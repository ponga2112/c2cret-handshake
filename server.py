# -*- coding: utf-8 -*-

"""
server.py

PoC To Smuggle Messages through an intercepting HTTPS proxy using only the TLS Handshake.

Client Max Bytes Per TLS Client Hello: 284
Server Max Bytes Per TLS Server Hello: 16k - TLS overhead [~15k]
Server Max Length of SAN record: 

TODO:
    1. Implement Reliable Packetization Protocol
    2. Implment server.py (using x509 SNA fields for smuggling)
    3. Test and investigate how detectable this is as a C2 channel
 
"""

# cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tlslite.messages import Message, ClientHello
from tlslite.tlsrecordlayer import TLSRecordLayer

import socketserver

import ipaddress
from datetime import datetime, timedelta
import typing
import random
import string
import threading
import socket
import argparse
import time
import math

MAX_SINGLE_MSG_LEN = 255
MAX_TOTAL_MSG_LEN = MAX_SINGLE_MSG_LEN * 62


def get_cert_from_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem, default_backend())


class TLSServerHandshake:
    key = None
    default_cert = None

    def __init__(self):
        if self.key is None:
            self.key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )
        self.default_cert = self.create_message

    def create_message(self, message: bytes) -> x509.Certificate:
        # Based on: https://gist.github.com/bloodearnest/9017111a313777b9cce5
        host, domain, tld = self._get_random_hostname()
        fqdn = host + "." + domain + "." + tld
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
        hex_msg = self._str_to_hex(str(message)) + "." + host + "." + tld
        if len(hex_msg) > MAX_SINGLE_MSG_LEN:
            print(
                f"ERROR: Encoded message length of {len(hex_msg)} (original length was {len(message)}) exceeds MAX_LEN of {MAX_SINGLE_MSG_LEN}"
            )
            raise NotImplementedError
        # Our smuggled payload goes into the SAN
        san = x509.SubjectAlternativeName([x509.DNSName(hex_msg)])
        # Now ready to create the crafter Certificate...
        basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=10 * 365))
            .add_extension(basic_contraints, False)
            .add_extension(san, False)
            .sign(self.key, hashes.SHA256(), default_backend())
        )
        # cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert

    def create_default_cert(self, common_name: str) -> x509.Certificate:
        cn = ""
        if not common_name:
            cn = ".".join(self._get_random_hostname())
        now_ts = datetime.utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .public_key(self.key.public_key())
            .serial_number(1000)
            .not_valid_before(now_ts)
            .not_valid_after(now_ts + timedelta(days=10 * 365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(x509.SubjectAlternativeName([x509.DNSName(cn)]))]), False
            )
            .sign(self.key, hashes.SHA256(), default_backend())
        )

    def _get_random_hostname(self) -> typing.Tuple[str, str, str]:
        tld = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, 4)))
        domain = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, 8)))
        host = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, 32)))
        return (host, domain, tld)

    def _str_to_hex(self, message: str) -> str:
        return bytes.hex(message.encode())

    def _hex_to_str(self, message: str) -> str:
        return bytes.fromhex(message.decode()).decode()

    def get_message_from_cert(cert: x509.Certificate) -> str:
        return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )[0]


TEST = None


class ThreadedTCPSocketServer(socketserver.StreamRequestHandler):
    def handle(self):
        # Receive and print the data received from client
        print("Recieved one request from {}".format(self.client_address[0]))
        # msg = self.rfile.read(self.rbufsize)
        #
        # Expect TLS Record; Reader header to confirm
        msg = self.rfile.read(9)
        print(f"Bytes Recieved from client: {len(msg)}")
        msg_hex_str = msg.hex()
        # print(msg_hex_str)
        if not self.validate_client_hello(msg_hex_str):
            return
        msg = self.rfile.read(int(msg_hex_str[12:], 16))
        print(msg.hex())
        sni = self._get_sni(msg.hex())
        print(f"___ {sni} ___")
        # with open("bin.out", "wb") as fh:
        #     fh.write(msg)
        # print(msg)
        self.decode_msg(msg)
        print("Thread Name:{}".format(threading.current_thread().name))

    def _get_sni(self, hex_str: str) -> str:
        # 2 + 32 + session_id_len[1 byte] + suites_len[2 bytes]
        # 1 + ciphers_len[2 bytes] {ciphers}
        # comp_len[1 byte] {comps}
        # ext_len[2 bytes]
        # EXT_TYPE[2 bytes]; if type == 00 00 == SNI
        # EXT_LEN[2 bytes]
        # offset = 66 + int()
        #
        hex_array = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]  # byte array (well, list but ya know)
        position = 35 + int(hex_array[35], 16)  # fixed tls fields
        position = position + int("".join(hex_array[position : position + 2]), 16) + 2  # ciphers suites
        position = position + int(hex_array[position], 16) + 1  # compression methods
        # extensions_len = int("".join(h[position : position + 2]), 16)
        position = position + 2
        sni = self._find_sni_extension(hex_array[position:])
        return sni

    def _find_sni_extension(self, exts: list) -> str:
        position = 0
        while position < len(exts):
            ext_type = "".join(exts[position : position + 2])
            ext_len = int("".join(exts[position + 2 : position + 4]), 16)
            # print("DEBUG_EXT_len: "+str(ext_len))
            # print("DEBUG_type: "+ext_type)
            if ext_type == "0000":
                position = position + 7
                # print("DEBUG_position: "+str(position))
                sni_len = int("".join(exts[position : position + 2]), 16)
                position = position + 2
                # print("DEBUG_sni_len: "+str(sni_len))
                # print("DEBUG_sni!: "+str(''.join(exts[position:position+sni_len])))
                return bytes.fromhex("".join(exts[position : position + sni_len])).decode()
            else:
                position = position + ext_len + 4
            return ""

    def validate_client_hello(self, hex_str: str) -> bool:
        # TLS client hello HEADER Ex: "16 0301 00d3 01 000024"
        try:
            if hex_str[0:2] != "16":
                return False
            if hex_str[2:4] != "03":
                return False
            if (int(hex_str[4:6], 16) < 1) or (int(hex_str[4:6], 16) > 4):
                return False
            max_len = int(math.pow(2, 14))
            if (int(hex_str[6:10], 16) < 1) or (int(hex_str[6:10], 16) > max_len):
                return False
            if hex_str[10:12] != "01":
                return False
            if (int(hex_str[12:], 16) < 1) or (int(hex_str[12:], 16) > max_len):
                return False
        except:
            return False
        return True

    def decode_msg(self, msg: bytes):
        try:
            c = ClientHello(msg)
        except:
            print("[!] Could not parse message!")
        print(str(c.server_name))
        print(str(c))

    def tls_server_hello(self, cert: x509.Certificate):
        return


if __name__ == "__main__":
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # proxy_send("_HOST_",443)

    # is_connected = proxy_connect
    # send_raw.proxy_connect(socket.socket(socket.AF_INET, socket.SOCK_STREAM),'_HOST_')

    # new shiz
    arg_parse = argparse.ArgumentParser(
        description="Send and Receive messages via TLS Handshakes through an interception proxy"
    )
    arg_parse.add_argument(
        "-p",
        "--port",
        metavar="bind_port",
        required=False,
        help="Bind to Listening TCP Port number",
    )
    args = arg_parse.parse_args()
    port = 8443
    if args.port:
        port = args.port
    server = None
    # try:
    #     thread = ThreadedServer("", port)
    #     thread.daemon = True
    #     thread.listen()
    #     while True:
    #         time.sleep(100)
    # except KeyboardInterrupt:
    #     exit(0)
    TCPServerInstance = socketserver.ThreadingTCPServer(("0.0.0.0", int(port)), ThreadedTCPSocketServer)
    print(f"[+] Listening on 0.0.0.0:{port}")
    try:
        TCPServerInstance.serve_forever()
    except KeyboardInterrupt:
        TCPServerInstance.shutdown()
        print("[+] Exiting.")
        exit(0)
