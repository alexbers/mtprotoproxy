#!/usr/bin/env python3

import asyncio
import socket
import urllib.parse
import urllib.request
import collections
import time
import datetime
import hmac
import base64
import hashlib
import random
import binascii
import sys
import re
import runpy
import signal


TG_DATACENTER_PORT = 443

TG_DATACENTERS_V4 = [
    "149.154.175.50", "149.154.167.51", "149.154.175.100",
    "149.154.167.91", "149.154.171.5"
]

TG_DATACENTERS_V6 = [
    "2001:b28:f23d:f001::a", "2001:67c:04e8:f002::a", "2001:b28:f23d:f003::a",
    "2001:67c:04e8:f004::a", "2001:b28:f23f:f005::a"
]

# This list will be updated in the runtime
TG_MIDDLE_PROXIES_V4 = {
    1: [("149.154.175.50", 8888)], -1: [("149.154.175.50", 8888)],
    2: [("149.154.162.38", 80)], -2: [("149.154.162.38", 80)],
    3: [("149.154.175.100", 8888)], -3: [("149.154.175.100", 8888)],
    4: [("91.108.4.136", 8888)], -4: [("149.154.165.109", 8888)],
    5: [("91.108.56.181", 8888)], -5: [("91.108.56.181", 8888)]
}

TG_MIDDLE_PROXIES_V6 = {
    1: [("2001:b28:f23d:f001::d", 8888)], -1: [("2001:b28:f23d:f001::d", 8888)],
    2: [("2001:67c:04e8:f002::d", 80)], -2: [("2001:67c:04e8:f002::d", 80)],
    3: [("2001:b28:f23d:f003::d", 8888)], -3: [("2001:b28:f23d:f003::d", 8888)],
    4: [("2001:67c:04e8:f004::d", 8888)], -4: [("2001:67c:04e8:f004::d", 8888)],
    5: [("2001:b28:f23f:f005::d", 8888)], -5: [("2001:67c:04e8:f004::d", 8888)]
}

PROXY_SECRET = bytes.fromhex(
    "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721" +
    "d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698" +
    "6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c" +
    "54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212"
)

SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
HANDSHAKE_LEN = 64
TLS_HANDSHAKE_LEN = 1 + 2 + 2 + 512
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_SECURE = b"\xdd\xdd\xdd\xdd"

CBC_PADDING = 16
PADDING_FILLER = b"\x04\x00\x00\x00"

MIN_MSG_LEN = 12
MAX_MSG_LEN = 2 ** 24


my_ip_info = {"ipv4": None, "ipv6": None}
used_handshakes = collections.OrderedDict()
disable_middle_proxy = False

config = {}


def init_config():
    global config
    # we use conf_dict to protect the original config from exceptions when reloading
    if len(sys.argv) < 2:
        conf_dict = runpy.run_module("config")
    elif len(sys.argv) == 2:
        # launch with own config
        conf_dict = runpy.run_path(sys.argv[1])
    else:
        # undocumented way of launching
        conf_dict = {}
        conf_dict["PORT"] = int(sys.argv[1])
        secrets = sys.argv[2].split(",")
        conf_dict["USERS"] = {"user%d" % i: secrets[i].zfill(32) for i in range(len(secrets))}
        if len(sys.argv) > 3:
            conf_dict["AD_TAG"] = sys.argv[3]

    conf_dict = {k: v for k, v in conf_dict.items() if k.isupper()}

    conf_dict.setdefault("PORT", 3255)
    conf_dict.setdefault("USERS", {"tg":  "00000000000000000000000000000000"})
    conf_dict["AD_TAG"] = bytes.fromhex(conf_dict.get("AD_TAG", ""))

    # load advanced settings

    # use middle proxy, necessary to show ad
    conf_dict.setdefault("USE_MIDDLE_PROXY", len(conf_dict["AD_TAG"]) == 16)

    # if IPv6 avaliable, use it by default
    conf_dict.setdefault("PREFER_IPV6", socket.has_ipv6)

    # disables tg->client trafic reencryption, faster but less secure
    conf_dict.setdefault("FAST_MODE", True)

    # doesn't allow to connect in not-secure mode
    conf_dict.setdefault("SECURE_ONLY", True)
    
    # doesn't allow to connect in not-tls mode
    conf_dict.setdefault("TLS_ONLY", True)

    # set the tls domain for the proxy, has an influence only on starting message
    conf_dict.setdefault("TLS_DOMAIN", "google.com")

    # disables the tls mode, actually there are no reasons for this
    conf_dict.setdefault("DISABLE_TLS", False)

    # user tcp connection limits, the mapping from name to the integer limit
    # one client can create many tcp connections, up to 8
    conf_dict.setdefault("USER_MAX_TCP_CONNS", {})

    # expiration date for users in format of day/month/year
    conf_dict.setdefault("USER_EXPIRATIONS", {})
    for user in conf_dict["USER_EXPIRATIONS"]:
        expiration = datetime.datetime.strptime(conf_dict["USER_EXPIRATIONS"][user], "%d/%m/%Y")
        conf_dict["USER_EXPIRATIONS"][user] = expiration

    # the data quota for user
    conf_dict.setdefault("USER_DATA_QUOTA", {})

    # length of used handshake randoms for active fingerprinting protection
    conf_dict.setdefault("REPLAY_CHECK_LEN", 32768)

    # block bad first packets to even more protect against replay-based fingerprinting
    conf_dict.setdefault("BLOCK_IF_FIRST_PKT_BAD", True)

    # delay in seconds between stats printing
    conf_dict.setdefault("STATS_PRINT_PERIOD", 600)

    # delay in seconds between middle proxy info updates
    conf_dict.setdefault("PROXY_INFO_UPDATE_PERIOD", 24*60*60)

    # delay in seconds between time getting, zero means disabled
    conf_dict.setdefault("GET_TIME_PERIOD", 10*60)

    # max socket buffer size to the client direction, the more the faster, but more RAM hungry
    # can be the tuple (low, users_margin, high) for the adaptive case. If no much users, use high
    conf_dict.setdefault("TO_CLT_BUFSIZE", (16384, 100, 131072))

    # max socket buffer size to the telegram servers direction, also can be the tuple
    conf_dict.setdefault("TO_TG_BUFSIZE", 65536)

    # keepalive period for clients in secs
    conf_dict.setdefault("CLIENT_KEEPALIVE", 10*60)

    # drop client after this timeout if the handshake fail
    conf_dict.setdefault("CLIENT_HANDSHAKE_TIMEOUT", 10)

    # if client doesn't confirm data for this number of seconds, it is dropped
    conf_dict.setdefault("CLIENT_ACK_TIMEOUT", 5*60)

    # telegram servers connect timeout in seconds
    conf_dict.setdefault("TG_CONNECT_TIMEOUT", 10)

    # listen address for IPv4
    conf_dict.setdefault("LISTEN_ADDR_IPV4", "0.0.0.0")

    # listen address for IPv6
    conf_dict.setdefault("LISTEN_ADDR_IPV6", "::")

    # allow access to config by attributes
    config = type("config", (dict,), conf_dict)(conf_dict)


def try_use_cryptography_module():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    def create_aes_ctr(key, iv):
        class EncryptorAdapter:
            def __init__(self, cipher):
                self.encryptor = cipher.encryptor()
                self.decryptor = cipher.decryptor()

            def encrypt(self, data):
                return self.encryptor.update(data)

            def decrypt(self, data):
                return self.decryptor.update(data)

        iv_bytes = int.to_bytes(iv, 16, "big")
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv_bytes), default_backend())
        return EncryptorAdapter(cipher)

    def create_aes_cbc(key, iv):
        class EncryptorAdapter:
            def __init__(self, cipher):
                self.encryptor = cipher.encryptor()
                self.decryptor = cipher.decryptor()

            def encrypt(self, data):
                return self.encryptor.update(data)

            def decrypt(self, data):
                return self.decryptor.update(data)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        return EncryptorAdapter(cipher)

    return create_aes_ctr, create_aes_cbc


def try_use_pycrypto_or_pycryptodome_module():
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    def create_aes_ctr(key, iv):
        ctr = Counter.new(128, initial_value=iv)
        return AES.new(key, AES.MODE_CTR, counter=ctr)

    def create_aes_cbc(key, iv):
        return AES.new(key, AES.MODE_CBC, iv)

    return create_aes_ctr, create_aes_cbc


def use_slow_bundled_cryptography_module():
    import pyaes

    msg = "To make the program a *lot* faster, please install cryptography module: "
    msg += "pip install cryptography\n"
    print(msg, flush=True, file=sys.stderr)

    def create_aes_ctr(key, iv):
        ctr = pyaes.Counter(iv)
        return pyaes.AESModeOfOperationCTR(key, ctr)

    def create_aes_cbc(key, iv):
        class EncryptorAdapter:
            def __init__(self, mode):
                self.mode = mode

            def encrypt(self, data):
                encrypter = pyaes.Encrypter(self.mode, pyaes.PADDING_NONE)
                return encrypter.feed(data) + encrypter.feed()

            def decrypt(self, data):
                decrypter = pyaes.Decrypter(self.mode, pyaes.PADDING_NONE)
                return decrypter.feed(data) + decrypter.feed()

        mode = pyaes.AESModeOfOperationCBC(key, iv)
        return EncryptorAdapter(mode)
    return create_aes_ctr, create_aes_cbc


try:
    create_aes_ctr, create_aes_cbc = try_use_cryptography_module()
except ImportError:
    try:
        create_aes_ctr, create_aes_cbc = try_use_pycrypto_or_pycryptodome_module()
    except ImportError:
        create_aes_ctr, create_aes_cbc = use_slow_bundled_cryptography_module()


def print_err(*params):
    print(*params, file=sys.stderr, flush=True)


def init_stats():
    global stats
    stats = {user: collections.Counter() for user in config.USERS}


def update_stats(user, connects=0, curr_connects=0, octets=0, msgs=0):
    global stats

    if user not in stats:
        stats[user] = collections.Counter()

    stats[user].update(connects=connects, curr_connects=curr_connects,
                       octets=octets, msgs=msgs)


def get_curr_connects_count():
    global stats

    all_connects = 0
    for user, stat in stats.items():
        all_connects += stat["curr_connects"]
    return all_connects


def get_to_tg_bufsize():
    if isinstance(config.TO_TG_BUFSIZE, int):
        return config.TO_TG_BUFSIZE

    low, margin, high = config.TO_TG_BUFSIZE
    return high if get_curr_connects_count() < margin else low


def get_to_clt_bufsize():
    if isinstance(config.TO_CLT_BUFSIZE, int):
        return config.TO_CLT_BUFSIZE

    low, margin, high = config.TO_CLT_BUFSIZE
    return high if get_curr_connects_count() < margin else low


class LayeredStreamReaderBase:
    def __init__(self, upstream):
        self.upstream = upstream

    async def read(self, n):
        return await self.upstream.read(n)

    async def readexactly(self, n):
        return await self.upstream.readexactly(n)


class LayeredStreamWriterBase:
    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        return self.upstream.write(data)

    def write_eof(self):
        return self.upstream.write_eof()

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def abort(self):
        return self.upstream.transport.abort()

    def get_extra_info(self, name):
        return self.upstream.get_extra_info(name)

    @property
    def transport(self):
        return self.upstream.transport


class FakeTLSStreamReader(LayeredStreamReaderBase):
    def __init__(self, upstream):
        self.upstream = upstream
        self.buf = bytearray()

    async def read(self, n, ignore_buf=False):
        if self.buf and not ignore_buf:
            data = self.buf
            self.buf = bytearray()
            return data

        while True:
            tls_rec_type = await self.upstream.readexactly(1)
            if not tls_rec_type:
                return b""

            if tls_rec_type not in [b"\x14", b"\x17"]:
                print_err("BUG: bad tls type %s in FakeTLSStreamReader" % tls_rec_type)
                return b""

            version = await self.upstream.readexactly(2)
            if version != b"\x03\x03":
                print_err("BUG: unknown version %s in FakeTLSStreamReader" % version)
                return b""

            data_len = int.from_bytes(await self.upstream.readexactly(2), "big")
            data = await self.upstream.readexactly(data_len)
            if tls_rec_type == b"\x14":
                continue
            return data

    async def readexactly(self, n):
        while len(self.buf) < n:
            tls_data = await self.read(1, ignore_buf=True)
            if not tls_data:
                return b""
            self.buf += tls_data
        data, self.buf = self.buf[:n], self.buf[n:]
        return bytes(data)


class FakeTLSStreamWriter(LayeredStreamWriterBase):
    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data, extra={}):
        MAX_CHUNK_SIZE = 65535
        for start in range(0, len(data), MAX_CHUNK_SIZE):
            end = min(start+MAX_CHUNK_SIZE, len(data))
            self.upstream.write(b"\x17\x03\x03" + int.to_bytes(end-start, 2, "big"))
            self.upstream.write(data[start: end])
        return len(data)


class CryptoWrappedStreamReader(LayeredStreamReaderBase):
    def __init__(self, upstream, decryptor, block_size=1):
        self.upstream = upstream
        self.decryptor = decryptor
        self.block_size = block_size
        self.buf = bytearray()

    async def read(self, n):
        if self.buf:
            ret = bytes(self.buf)
            self.buf.clear()
            return ret
        else:
            data = await self.upstream.read(n)
            if not data:
                return b""

            needed_till_full_block = -len(data) % self.block_size
            if needed_till_full_block > 0:
                data += self.upstream.readexactly(needed_till_full_block)
            return self.decryptor.decrypt(data)

    async def readexactly(self, n):
        if n > len(self.buf):
            to_read = n - len(self.buf)
            needed_till_full_block = -to_read % self.block_size

            to_read_block_aligned = to_read + needed_till_full_block
            data = await self.upstream.readexactly(to_read_block_aligned)
            self.buf += self.decryptor.decrypt(data)

        ret = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return ret


class CryptoWrappedStreamWriter(LayeredStreamWriterBase):
    def __init__(self, upstream, encryptor, block_size=1):
        self.upstream = upstream
        self.encryptor = encryptor
        self.block_size = block_size

    def write(self, data, extra={}):
        if len(data) % self.block_size != 0:
            print_err("BUG: writing %d bytes not aligned to block size %d" % (
                      len(data), self.block_size))
            return 0
        q = self.encryptor.encrypt(data)
        return self.upstream.write(q)


class MTProtoFrameStreamReader(LayeredStreamReaderBase):
    def __init__(self, upstream, seq_no=0):
        self.upstream = upstream
        self.seq_no = seq_no

    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")
        # skip paddings
        while msg_len == 4:
            msg_len_bytes = await self.upstream.readexactly(4)
            msg_len = int.from_bytes(msg_len_bytes, "little")

        len_is_bad = (msg_len % len(PADDING_FILLER) != 0)
        if not MIN_MSG_LEN <= msg_len <= MAX_MSG_LEN or len_is_bad:
            print_err("msg_len is bad, closing connection", msg_len)
            return b""

        msg_seq_bytes = await self.upstream.readexactly(4)
        msg_seq = int.from_bytes(msg_seq_bytes, "little", signed=True)
        if msg_seq != self.seq_no:
            print_err("unexpected seq_no")
            return b""

        self.seq_no += 1

        data = await self.upstream.readexactly(msg_len - 4 - 4 - 4)
        checksum_bytes = await self.upstream.readexactly(4)
        checksum = int.from_bytes(checksum_bytes, "little")

        computed_checksum = binascii.crc32(msg_len_bytes + msg_seq_bytes + data)
        if computed_checksum != checksum:
            return b""
        return data


class MTProtoFrameStreamWriter(LayeredStreamWriterBase):
    def __init__(self, upstream, seq_no=0):
        self.upstream = upstream
        self.seq_no = seq_no

    def write(self, msg, extra={}):
        len_bytes = int.to_bytes(len(msg) + 4 + 4 + 4, 4, "little")
        seq_bytes = int.to_bytes(self.seq_no, 4, "little", signed=True)
        self.seq_no += 1

        msg_without_checksum = len_bytes + seq_bytes + msg
        checksum = int.to_bytes(binascii.crc32(msg_without_checksum), 4, "little")

        full_msg = msg_without_checksum + checksum
        padding = PADDING_FILLER * ((-len(full_msg) % CBC_PADDING) // len(PADDING_FILLER))

        return self.upstream.write(full_msg + padding)


class MTProtoCompactFrameStreamReader(LayeredStreamReaderBase):
    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(1)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        extra = {"QUICKACK_FLAG": False}
        if msg_len >= 0x80:
            extra["QUICKACK_FLAG"] = True
            msg_len -= 0x80

        if msg_len == 0x7f:
            msg_len_bytes = await self.upstream.readexactly(3)
            msg_len = int.from_bytes(msg_len_bytes, "little")

        msg_len *= 4

        data = await self.upstream.readexactly(msg_len)

        return data, extra


class MTProtoCompactFrameStreamWriter(LayeredStreamWriterBase):
    def write(self, data, extra={}):
        SMALL_PKT_BORDER = 0x7f
        LARGE_PKT_BORGER = 256 ** 3

        if len(data) % 4 != 0:
            print_err("BUG: MTProtoFrameStreamWriter attempted to send msg with len", len(data))
            return 0

        if extra.get("SIMPLE_ACK"):
            return self.upstream.write(data[::-1])

        len_div_four = len(data) // 4

        if len_div_four < SMALL_PKT_BORDER:
            return self.upstream.write(bytes([len_div_four]) + data)
        elif len_div_four < LARGE_PKT_BORGER:
            return self.upstream.write(b'\x7f' + int.to_bytes(len_div_four, 3, 'little') + data)
        else:
            print_err("Attempted to send too large pkt len =", len(data))
            return 0


class MTProtoIntermediateFrameStreamReader(LayeredStreamReaderBase):
    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        extra = {}
        if msg_len > 0x80000000:
            extra["QUICKACK_FLAG"] = True
            msg_len -= 0x80000000

        data = await self.upstream.readexactly(msg_len)
        return data, extra


class MTProtoIntermediateFrameStreamWriter(LayeredStreamWriterBase):
    def write(self, data, extra={}):
        if extra.get("SIMPLE_ACK"):
            return self.upstream.write(data)
        else:
            return self.upstream.write(int.to_bytes(len(data), 4, 'little') + data)


class MTProtoSecureIntermediateFrameStreamReader(LayeredStreamReaderBase):
    async def read(self, buf_size):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        extra = {}
        if msg_len > 0x80000000:
            extra["QUICKACK_FLAG"] = True
            msg_len -= 0x80000000

        data = await self.upstream.readexactly(msg_len)

        if msg_len % 4 != 0:
            cut_border = msg_len - (msg_len % 4)
            data = data[:cut_border]

        return data, extra


class MTProtoSecureIntermediateFrameStreamWriter(LayeredStreamWriterBase):
    def write(self, data, extra={}):
        MAX_PADDING_LEN = 4
        if extra.get("SIMPLE_ACK"):
            # TODO: make this unpredictable
            return self.upstream.write(data)
        else:
            padding_len = random.randrange(MAX_PADDING_LEN)
            padding = bytearray([random.randrange(256) for i in range(padding_len)])
            padded_data_len_bytes = int.to_bytes(len(data) + padding_len, 4, 'little')
            return self.upstream.write(padded_data_len_bytes + data + padding)


class ProxyReqStreamReader(LayeredStreamReaderBase):
    async def read(self, msg):
        RPC_PROXY_ANS = b"\x0d\xda\x03\x44"
        RPC_CLOSE_EXT = b"\xa2\x34\xb6\x5e"
        RPC_SIMPLE_ACK = b"\x9b\x40\xac\x3b"

        data = await self.upstream.read(1)

        if len(data) < 4:
            return b""

        ans_type = data[:4]
        if ans_type == RPC_CLOSE_EXT:
            return b""

        if ans_type == RPC_PROXY_ANS:
            ans_flags, conn_id, conn_data = data[4:8], data[8:16], data[16:]
            return conn_data

        if ans_type == RPC_SIMPLE_ACK:
            conn_id, confirm = data[4:12], data[12:16]
            return confirm, {"SIMPLE_ACK": True}

        print_err("unknown rpc ans type:", ans_type)
        return b""


class ProxyReqStreamWriter(LayeredStreamWriterBase):
    def __init__(self, upstream, cl_ip, cl_port, my_ip, my_port, proto_tag):
        self.upstream = upstream

        if ":" not in cl_ip:
            self.remote_ip_port = b"\x00" * 10 + b"\xff\xff"
            self.remote_ip_port += socket.inet_pton(socket.AF_INET, cl_ip)
        else:
            self.remote_ip_port = socket.inet_pton(socket.AF_INET6, cl_ip)
        self.remote_ip_port += int.to_bytes(cl_port, 4, "little")

        if ":" not in my_ip:
            self.our_ip_port = b"\x00" * 10 + b"\xff\xff"
            self.our_ip_port += socket.inet_pton(socket.AF_INET, my_ip)
        else:
            self.our_ip_port = socket.inet_pton(socket.AF_INET6, my_ip)
        self.our_ip_port += int.to_bytes(my_port, 4, "little")
        self.out_conn_id = bytearray([random.randrange(0, 256) for i in range(8)])

        self.proto_tag = proto_tag

    def write(self, msg, extra={}):
        RPC_PROXY_REQ = b"\xee\xf1\xce\x36"
        EXTRA_SIZE = b"\x18\x00\x00\x00"
        PROXY_TAG = b"\xae\x26\x1e\xdb"
        FOUR_BYTES_ALIGNER = b"\x00\x00\x00"

        FLAG_NOT_ENCRYPTED = 0x2
        FLAG_HAS_AD_TAG = 0x8
        FLAG_MAGIC = 0x1000
        FLAG_EXTMODE2 = 0x20000
        FLAG_PAD = 0x8000000
        FLAG_INTERMEDIATE = 0x20000000
        FLAG_ABRIDGED = 0x40000000
        FLAG_QUICKACK = 0x80000000

        if len(msg) % 4 != 0:
            print_err("BUG: attempted to send msg with len %d" % len(msg))
            return 0

        flags = FLAG_HAS_AD_TAG | FLAG_MAGIC | FLAG_EXTMODE2

        if self.proto_tag == PROTO_TAG_ABRIDGED:
            flags |= FLAG_ABRIDGED
        elif self.proto_tag == PROTO_TAG_INTERMEDIATE:
            flags |= FLAG_INTERMEDIATE
        elif self.proto_tag == PROTO_TAG_SECURE:
            flags |= FLAG_INTERMEDIATE | FLAG_PAD

        if extra.get("QUICKACK_FLAG"):
            flags |= FLAG_QUICKACK

        if msg.startswith(b"\x00" * 8):
            flags |= FLAG_NOT_ENCRYPTED

        full_msg = bytearray()
        full_msg += RPC_PROXY_REQ + int.to_bytes(flags, 4, "little") + self.out_conn_id
        full_msg += self.remote_ip_port + self.our_ip_port + EXTRA_SIZE + PROXY_TAG
        full_msg += bytes([len(config.AD_TAG)]) + config.AD_TAG + FOUR_BYTES_ALIGNER
        full_msg += msg

        self.first_flag_byte = b"\x08"
        return self.upstream.write(full_msg)


def try_setsockopt(sock, level, option, value):
    try:
        sock.setsockopt(level, option, value)
    except OSError as E:
        pass


def set_keepalive(sock, interval=40, attempts=5):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, interval)
    if hasattr(socket, "TCP_KEEPINTVL"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
    if hasattr(socket, "TCP_KEEPCNT"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_KEEPCNT, attempts)


def set_ack_timeout(sock, timeout):
    if hasattr(socket, "TCP_USER_TIMEOUT"):
        try_setsockopt(sock, socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, timeout*1000)


def set_bufsizes(sock, recv_buf, send_buf):
    try_setsockopt(sock, socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buf)
    try_setsockopt(sock, socket.SOL_SOCKET, socket.SO_SNDBUF, send_buf)


def set_instant_rst(sock):
    INSTANT_RST = b"\x01\x00\x00\x00\x00\x00\x00\x00"
    if hasattr(socket, "SO_LINGER"):
        try_setsockopt(sock, socket.SOL_SOCKET, socket.SO_LINGER, INSTANT_RST)


async def handle_pseudo_tls_handshake(handshake, reader, writer):
    global used_handshakes

    TLS_VERS = b"\x03\x03"
    TLS_CIPHERSUITE = b"\xc0\x2f"
    TLS_EXTENSIONS = b"\x00\x12" + b"\xff\x01\x00\x01\x00" + b"\x00\x05\x00\x00"
    TLS_EXTENSIONS += b"\x00\x10\x00\x05\x00\x03\x02\x68\x32"
    TLS_CHANGE_CIPHER = b"\x14" + TLS_VERS + b"\x00\x01\x01"
    TLS_APP_HTTP2_HDR = b"\x17" + TLS_VERS

    DIGEST_LEN = 32
    DIGEST_POS = 11

    SESSION_ID_LEN_POS = DIGEST_POS + DIGEST_LEN
    SESSION_ID_POS = SESSION_ID_LEN_POS + 1

    digest = handshake[DIGEST_POS: DIGEST_POS + DIGEST_LEN]

    if digest in used_handshakes:
        ip = writer.get_extra_info('peername')[0]
        print_err("Active TLS fingerprinting detected from %s, dropping it" % ip)
        return False

    sess_id_len = handshake[SESSION_ID_LEN_POS]
    sess_id = handshake[SESSION_ID_POS: SESSION_ID_POS + sess_id_len]

    for user in config.USERS:
        secret = bytes.fromhex(config.USERS[user])

        msg = handshake[:DIGEST_POS] + b"\x00"*DIGEST_LEN + handshake[DIGEST_POS+DIGEST_LEN:]
        computed_digest = hmac.new(secret, msg, digestmod=hashlib.sha256).digest()

        xored_digest = bytes(digest[i] ^ computed_digest[i] for i in range(DIGEST_LEN))
        digest_good = xored_digest.startswith(b"\x00" * (DIGEST_LEN-4))

        timestamp = int.from_bytes(xored_digest[-4:], "little")
        if not digest_good:
            continue

        http_data = bytearray([random.randrange(0, 256) for i in range(random.randrange(1, 256))])

        srv_hello = TLS_VERS + b"\x00"*DIGEST_LEN + bytes([sess_id_len]) + sess_id
        srv_hello += TLS_CIPHERSUITE + b"\x00" + TLS_EXTENSIONS

        hello_pkt = b"\x16" + TLS_VERS + int.to_bytes(len(srv_hello) + 4, 2, "big")
        hello_pkt += b"\x02" + int.to_bytes(len(srv_hello), 3, "big") + srv_hello
        hello_pkt += TLS_CHANGE_CIPHER + TLS_APP_HTTP2_HDR
        hello_pkt += int.to_bytes(len(http_data), 2, "big") + http_data

        computed_digest = hmac.new(secret, msg=digest+hello_pkt, digestmod=hashlib.sha256).digest()
        hello_pkt = hello_pkt[:DIGEST_POS] + computed_digest + hello_pkt[DIGEST_POS+DIGEST_LEN:]

        writer.write(hello_pkt)
        await writer.drain()

        used_handshakes[digest] = True

        reader = FakeTLSStreamReader(reader)
        writer = FakeTLSStreamWriter(writer)
        return reader, writer

    return False


async def handle_handshake(reader, writer):
    global used_handshakes

    TLS_START_BYTES = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"
    EMPTY_READ_BUF_SIZE = 4096

    handshake = await reader.readexactly(HANDSHAKE_LEN)
    
    if config.TLS_ONLY and not handshake.startswith(TLS_START_BYTES):
        return False

    if handshake.startswith(TLS_START_BYTES) and not config.DISABLE_TLS:
        handshake += await reader.readexactly(TLS_HANDSHAKE_LEN - HANDSHAKE_LEN)
        tls_handshake_result = await handle_pseudo_tls_handshake(handshake, reader, writer)

        if not tls_handshake_result:
            set_instant_rst(writer.get_extra_info("socket"))
            return False
        reader, writer = tls_handshake_result
        handshake = await reader.readexactly(HANDSHAKE_LEN)

    dec_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN]
    dec_prekey, dec_iv = dec_prekey_and_iv[:PREKEY_LEN], dec_prekey_and_iv[PREKEY_LEN:]
    enc_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN][::-1]
    enc_prekey, enc_iv = enc_prekey_and_iv[:PREKEY_LEN], enc_prekey_and_iv[PREKEY_LEN:]

    if dec_prekey_and_iv in used_handshakes:
        ip = writer.get_extra_info('peername')[0]
        print_err("Active fingerprinting detected from %s, freezing it" % ip)
        while await reader.read(EMPTY_READ_BUF_SIZE):
            # just consume all the data
            pass

        return False

    for user in config.USERS:
        secret = bytes.fromhex(config.USERS[user])

        dec_key = hashlib.sha256(dec_prekey + secret).digest()
        decryptor = create_aes_ctr(key=dec_key, iv=int.from_bytes(dec_iv, "big"))

        enc_key = hashlib.sha256(enc_prekey + secret).digest()
        encryptor = create_aes_ctr(key=enc_key, iv=int.from_bytes(enc_iv, "big"))

        decrypted = decryptor.decrypt(handshake)

        proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS+4]
        if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
            continue

        if config.SECURE_ONLY and proto_tag != PROTO_TAG_SECURE:
            continue

        dc_idx = int.from_bytes(decrypted[DC_IDX_POS:DC_IDX_POS+2], "little", signed=True)

        while len(used_handshakes) >= config.REPLAY_CHECK_LEN:
            used_handshakes.popitem(last=False)
        used_handshakes[dec_prekey_and_iv] = True

        reader = CryptoWrappedStreamReader(reader, decryptor)
        writer = CryptoWrappedStreamWriter(writer, encryptor)
        return reader, writer, proto_tag, user, dc_idx, enc_key + enc_iv

    while await reader.read(EMPTY_READ_BUF_SIZE):
        # just consume all the data
        pass

    return False


async def open_connection_tryer(addr, port, limit, timeout, max_attempts=3):
    for attempt in range(max_attempts-1):
        try:
            task = asyncio.open_connection(addr, port, limit=limit)
            reader_tgt, writer_tgt = await asyncio.wait_for(task, timeout=timeout)
            return reader_tgt, writer_tgt
        except (OSError, asyncio.TimeoutError):
            continue

    # the last attempt
    task = asyncio.open_connection(addr, port, limit=limit)
    reader_tgt, writer_tgt = await asyncio.wait_for(task, timeout=timeout)
    return reader_tgt, writer_tgt


async def do_direct_handshake(proto_tag, dc_idx, dec_key_and_iv=None):
    RESERVED_NONCE_FIRST_CHARS = [b"\xef"]
    RESERVED_NONCE_BEGININGS = [b"\x48\x45\x41\x44", b"\x50\x4F\x53\x54",
                                b"\x47\x45\x54\x20", b"\xee\xee\xee\xee",
                                b"\xdd\xdd\xdd\xdd"]
    RESERVED_NONCE_CONTINUES = [b"\x00\x00\x00\x00"]

    global my_ip_info

    dc_idx = abs(dc_idx) - 1

    if my_ip_info["ipv6"] and (config.PREFER_IPV6 or not my_ip_info["ipv4"]):
        if not 0 <= dc_idx < len(TG_DATACENTERS_V6):
            return False
        dc = TG_DATACENTERS_V6[dc_idx]
    else:
        if not 0 <= dc_idx < len(TG_DATACENTERS_V4):
            return False
        dc = TG_DATACENTERS_V4[dc_idx]

    try:
        reader_tgt, writer_tgt = await open_connection_tryer(
            dc, TG_DATACENTER_PORT, limit=get_to_clt_bufsize(), timeout=config.TG_CONNECT_TIMEOUT)
    except ConnectionRefusedError as E:
        print_err("Got connection refused while trying to connect to", dc, TG_DATACENTER_PORT)
        return False
    except (OSError, asyncio.TimeoutError) as E:
        print_err("Unable to connect to", dc, TG_DATACENTER_PORT)
        return False

    set_keepalive(writer_tgt.get_extra_info("socket"))
    set_bufsizes(writer_tgt.get_extra_info("socket"), get_to_clt_bufsize(), get_to_tg_bufsize())

    while True:
        rnd = bytearray([random.randrange(0, 256) for i in range(HANDSHAKE_LEN)])
        if rnd[:1] in RESERVED_NONCE_FIRST_CHARS:
            continue
        if rnd[:4] in RESERVED_NONCE_BEGININGS:
            continue
        if rnd[4:8] in RESERVED_NONCE_CONTINUES:
            continue
        break

    rnd[PROTO_TAG_POS:PROTO_TAG_POS+4] = proto_tag

    if dec_key_and_iv:
        rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN] = dec_key_and_iv[::-1]

    rnd = bytes(rnd)

    dec_key_and_iv = rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN][::-1]
    dec_key, dec_iv = dec_key_and_iv[:KEY_LEN], dec_key_and_iv[KEY_LEN:]
    decryptor = create_aes_ctr(key=dec_key, iv=int.from_bytes(dec_iv, "big"))

    enc_key_and_iv = rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN]
    enc_key, enc_iv = enc_key_and_iv[:KEY_LEN], enc_key_and_iv[KEY_LEN:]
    encryptor = create_aes_ctr(key=enc_key, iv=int.from_bytes(enc_iv, "big"))

    rnd_enc = rnd[:PROTO_TAG_POS] + encryptor.encrypt(rnd)[PROTO_TAG_POS:]

    writer_tgt.write(rnd_enc)
    await writer_tgt.drain()

    reader_tgt = CryptoWrappedStreamReader(reader_tgt, decryptor)
    writer_tgt = CryptoWrappedStreamWriter(writer_tgt, encryptor)

    return reader_tgt, writer_tgt


def get_middleproxy_aes_key_and_iv(nonce_srv, nonce_clt, clt_ts, srv_ip, clt_port, purpose,
                                   clt_ip, srv_port, middleproxy_secret, clt_ipv6=None,
                                   srv_ipv6=None):
    EMPTY_IP = b"\x00\x00\x00\x00"

    if not clt_ip or not srv_ip:
        clt_ip = EMPTY_IP
        srv_ip = EMPTY_IP

    s = bytearray()
    s += nonce_srv + nonce_clt + clt_ts + srv_ip + clt_port + purpose + clt_ip + srv_port
    s += middleproxy_secret + nonce_srv

    if clt_ipv6 and srv_ipv6:
        s += clt_ipv6 + srv_ipv6

    s += nonce_clt

    md5_sum = hashlib.md5(s[1:]).digest()
    sha1_sum = hashlib.sha1(s).digest()

    key = md5_sum[:12] + sha1_sum
    iv = hashlib.md5(s[2:]).digest()
    return key, iv


async def do_middleproxy_handshake(proto_tag, dc_idx, cl_ip, cl_port):
    START_SEQ_NO = -2
    NONCE_LEN = 16

    RPC_NONCE = b"\xaa\x87\xcb\x7a"
    RPC_HANDSHAKE = b"\xf5\xee\x82\x76"
    CRYPTO_AES = b"\x01\x00\x00\x00"

    RPC_NONCE_ANS_LEN = 32
    RPC_HANDSHAKE_ANS_LEN = 32

    # pass as consts to simplify code
    RPC_FLAGS = b"\x00\x00\x00\x00"

    global my_ip_info

    use_ipv6_tg = (my_ip_info["ipv6"] and (config.PREFER_IPV6 or not my_ip_info["ipv4"]))
    use_ipv6_clt = (":" in cl_ip)

    if use_ipv6_tg:
        if dc_idx not in TG_MIDDLE_PROXIES_V6:
            return False
        addr, port = random.choice(TG_MIDDLE_PROXIES_V6[dc_idx])
    else:
        if dc_idx not in TG_MIDDLE_PROXIES_V4:
            return False
        addr, port = random.choice(TG_MIDDLE_PROXIES_V4[dc_idx])

    try:
        reader_tgt, writer_tgt = await open_connection_tryer(addr, port, limit=get_to_clt_bufsize(),
                                                             timeout=config.TG_CONNECT_TIMEOUT)
    except ConnectionRefusedError as E:
        print_err("Got connection refused while trying to connect to", addr, port)
        return False
    except (OSError, asyncio.TimeoutError) as E:
        print_err("Unable to connect to", addr, port)
        return False

    set_keepalive(writer_tgt.get_extra_info("socket"))
    set_bufsizes(writer_tgt.get_extra_info("socket"), get_to_clt_bufsize(), get_to_tg_bufsize())

    writer_tgt = MTProtoFrameStreamWriter(writer_tgt, START_SEQ_NO)

    key_selector = PROXY_SECRET[:4]
    crypto_ts = int.to_bytes(int(time.time()) % (256**4), 4, "little")

    nonce = bytes([random.randrange(0, 256) for i in range(NONCE_LEN)])

    msg = RPC_NONCE + key_selector + CRYPTO_AES + crypto_ts + nonce

    writer_tgt.write(msg)
    await writer_tgt.drain()

    old_reader = reader_tgt
    reader_tgt = MTProtoFrameStreamReader(reader_tgt, START_SEQ_NO)
    ans = await reader_tgt.read(get_to_clt_bufsize())

    if len(ans) != RPC_NONCE_ANS_LEN:
        return False

    rpc_type, rpc_key_selector, rpc_schema, rpc_crypto_ts, rpc_nonce = (
        ans[:4], ans[4:8], ans[8:12], ans[12:16], ans[16:32]
    )

    if rpc_type != RPC_NONCE or rpc_key_selector != key_selector or rpc_schema != CRYPTO_AES:
        return False

    # get keys
    tg_ip, tg_port = writer_tgt.upstream.get_extra_info('peername')[:2]
    my_ip, my_port = writer_tgt.upstream.get_extra_info('sockname')[:2]

    if not use_ipv6_tg:
        if my_ip_info["ipv4"]:
            # prefer global ip settings to work behind NAT
            my_ip = my_ip_info["ipv4"]

        tg_ip_bytes = socket.inet_pton(socket.AF_INET, tg_ip)[::-1]
        my_ip_bytes = socket.inet_pton(socket.AF_INET, my_ip)[::-1]

        tg_ipv6_bytes = None
        my_ipv6_bytes = None
    else:
        if my_ip_info["ipv6"]:
            my_ip = my_ip_info["ipv6"]

        tg_ip_bytes = None
        my_ip_bytes = None

        tg_ipv6_bytes = socket.inet_pton(socket.AF_INET6, tg_ip)
        my_ipv6_bytes = socket.inet_pton(socket.AF_INET6, my_ip)

    tg_port_bytes = int.to_bytes(tg_port, 2, "little")
    my_port_bytes = int.to_bytes(my_port, 2, "little")

    enc_key, enc_iv = get_middleproxy_aes_key_and_iv(
        nonce_srv=rpc_nonce, nonce_clt=nonce, clt_ts=crypto_ts, srv_ip=tg_ip_bytes,
        clt_port=my_port_bytes, purpose=b"CLIENT", clt_ip=my_ip_bytes, srv_port=tg_port_bytes,
        middleproxy_secret=PROXY_SECRET, clt_ipv6=my_ipv6_bytes, srv_ipv6=tg_ipv6_bytes)

    dec_key, dec_iv = get_middleproxy_aes_key_and_iv(
        nonce_srv=rpc_nonce, nonce_clt=nonce, clt_ts=crypto_ts, srv_ip=tg_ip_bytes,
        clt_port=my_port_bytes, purpose=b"SERVER", clt_ip=my_ip_bytes, srv_port=tg_port_bytes,
        middleproxy_secret=PROXY_SECRET, clt_ipv6=my_ipv6_bytes, srv_ipv6=tg_ipv6_bytes)

    encryptor = create_aes_cbc(key=enc_key, iv=enc_iv)
    decryptor = create_aes_cbc(key=dec_key, iv=dec_iv)

    SENDER_PID = b"IPIPPRPDTIME"
    PEER_PID = b"IPIPPRPDTIME"

    # TODO: pass client ip and port here for statistics
    handshake = RPC_HANDSHAKE + RPC_FLAGS + SENDER_PID + PEER_PID

    writer_tgt.upstream = CryptoWrappedStreamWriter(writer_tgt.upstream, encryptor, block_size=16)
    writer_tgt.write(handshake)
    await writer_tgt.drain()

    reader_tgt.upstream = CryptoWrappedStreamReader(reader_tgt.upstream, decryptor, block_size=16)

    handshake_ans = await reader_tgt.read(1)
    if len(handshake_ans) != RPC_HANDSHAKE_ANS_LEN:
        return False

    handshake_type, handshake_flags, handshake_sender_pid, handshake_peer_pid = (
        handshake_ans[:4], handshake_ans[4:8], handshake_ans[8:20], handshake_ans[20:32])
    if handshake_type != RPC_HANDSHAKE or handshake_peer_pid != SENDER_PID:
        return False

    writer_tgt = ProxyReqStreamWriter(writer_tgt, cl_ip, cl_port, my_ip, my_port, proto_tag)
    reader_tgt = ProxyReqStreamReader(reader_tgt)

    return reader_tgt, writer_tgt


async def handle_client(reader_clt, writer_clt):
    set_keepalive(writer_clt.get_extra_info("socket"), config.CLIENT_KEEPALIVE, attempts=3)
    set_ack_timeout(writer_clt.get_extra_info("socket"), config.CLIENT_ACK_TIMEOUT)
    set_bufsizes(writer_clt.get_extra_info("socket"), get_to_tg_bufsize(), get_to_clt_bufsize())

    cl_ip, cl_port = writer_clt.get_extra_info('peername')[:2]
    try:
        clt_data = await asyncio.wait_for(handle_handshake(reader_clt, writer_clt),
                                          timeout=config.CLIENT_HANDSHAKE_TIMEOUT)
    except asyncio.TimeoutError:
        return

    if not clt_data:
        return

    reader_clt, writer_clt, proto_tag, user, dc_idx, enc_key_and_iv = clt_data

    update_stats(user, connects=1)

    connect_directly = (not config.USE_MIDDLE_PROXY or disable_middle_proxy)

    if connect_directly:
        if config.FAST_MODE:
            tg_data = await do_direct_handshake(proto_tag, dc_idx, dec_key_and_iv=enc_key_and_iv)
        else:
            tg_data = await do_direct_handshake(proto_tag, dc_idx)
    else:
        tg_data = await do_middleproxy_handshake(proto_tag, dc_idx, cl_ip, cl_port)

    if not tg_data:
        return

    reader_tg, writer_tg = tg_data

    if connect_directly and config.FAST_MODE:
        class FakeEncryptor:
            def encrypt(self, data):
                return data

        class FakeDecryptor:
            def decrypt(self, data):
                return data

        reader_tg.decryptor = FakeDecryptor()
        writer_clt.encryptor = FakeEncryptor()

    if not connect_directly:
        if proto_tag == PROTO_TAG_ABRIDGED:
            reader_clt = MTProtoCompactFrameStreamReader(reader_clt)
            writer_clt = MTProtoCompactFrameStreamWriter(writer_clt)
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            reader_clt = MTProtoIntermediateFrameStreamReader(reader_clt)
            writer_clt = MTProtoIntermediateFrameStreamWriter(writer_clt)
        elif proto_tag == PROTO_TAG_SECURE:
            reader_clt = MTProtoSecureIntermediateFrameStreamReader(reader_clt)
            writer_clt = MTProtoSecureIntermediateFrameStreamWriter(writer_clt)
        else:
            return

    async def connect_reader_to_writer(rd, wr, user, rd_buf_size, block_if_first_pkt_bad=False):
        is_first_pkt = True
        try:
            while True:
                data = await rd.read(rd_buf_size)
                if isinstance(data, tuple):
                    data, extra = data
                else:
                    extra = {}

                # protection against replay-based fingerprinting
                if is_first_pkt:
                    is_first_pkt = False

                    ERR_PKT_DATA = b'l\xfe\xff\xff'
                    if block_if_first_pkt_bad and data == ERR_PKT_DATA:
                        print_err("Active fingerprinting detected from %s, dropping it" % cl_ip)

                        wr.write_eof()
                        await wr.drain()
                        return

                if not data:
                    wr.write_eof()
                    await wr.drain()
                    return
                else:
                    update_stats(user, octets=len(data), msgs=1)
                    wr.write(data, extra)
                    await wr.drain()
        except (OSError, asyncio.streams.IncompleteReadError) as e:
            # print_err(e)
            pass

    tg_to_clt = connect_reader_to_writer(reader_tg, writer_clt, user, get_to_clt_bufsize(),
                                         block_if_first_pkt_bad=config.BLOCK_IF_FIRST_PKT_BAD)
    clt_to_tg = connect_reader_to_writer(reader_clt, writer_tg, user, get_to_tg_bufsize())
    task_tg_to_clt = asyncio.ensure_future(tg_to_clt)
    task_clt_to_tg = asyncio.ensure_future(clt_to_tg)

    update_stats(user, curr_connects=1)

    tcp_limit_hit = (
        user in config.USER_MAX_TCP_CONNS and
        stats[user]["curr_connects"] > config.USER_MAX_TCP_CONNS[user]
    )

    user_expired = (
        user in config.USER_EXPIRATIONS and
        datetime.datetime.now() > config.USER_EXPIRATIONS[user]
    )

    user_data_quota_hit = (
        user in config.USER_DATA_QUOTA and
        stats[user]["octets"] > config.USER_DATA_QUOTA[user]
    )

    if (not tcp_limit_hit) and (not user_expired) and (not user_data_quota_hit):
        await asyncio.wait([task_tg_to_clt, task_clt_to_tg], return_when=asyncio.FIRST_COMPLETED)

    update_stats(user, curr_connects=-1)

    task_tg_to_clt.cancel()
    task_clt_to_tg.cancel()

    writer_tg.transport.abort()


async def handle_client_wrapper(reader, writer):
    try:
        await handle_client(reader, writer)
    except (asyncio.IncompleteReadError, ConnectionResetError, TimeoutError):
        pass
    finally:
        writer.transport.abort()


async def stats_printer():
    global stats
    while True:
        await asyncio.sleep(config.STATS_PRINT_PERIOD)

        print("Stats for", time.strftime("%d.%m.%Y %H:%M:%S"))
        for user, stat in stats.items():
            print("%s: %d connects (%d current), %.2f MB, %d msgs" % (
                user, stat["connects"], stat["curr_connects"],
                stat["octets"] / 1000000, stat["msgs"]))
        print(flush=True)


async def make_https_req(url, host="core.telegram.org"):
    """ Make request, return resp body and headers. """
    SSL_PORT = 443
    url_data = urllib.parse.urlparse(url)

    HTTP_REQ_TEMPLATE = "\r\n".join(["GET %s HTTP/1.1", "Host: %s",
                                     "Connection: close"]) + "\r\n\r\n"
    reader, writer = await asyncio.open_connection(url_data.netloc, SSL_PORT, ssl=True)
    req = HTTP_REQ_TEMPLATE % (urllib.parse.quote(url_data.path), host)
    writer.write(req.encode("utf8"))
    data = await reader.read()
    writer.close()

    headers, body = data.split(b"\r\n\r\n", 1)
    return headers, body


async def get_srv_time():
    TIME_SYNC_ADDR = "https://core.telegram.org/getProxySecret"
    MAX_TIME_SKEW = 30

    global disable_middle_proxy

    want_to_reenable_advertising = False
    while True:
        try:
            headers, secret = await make_https_req(TIME_SYNC_ADDR)

            for line in headers.split(b"\r\n"):
                if not line.startswith(b"Date: "):
                    continue
                line = line[len("Date: "):].decode()
                srv_time = datetime.datetime.strptime(line, "%a, %d %b %Y %H:%M:%S %Z")
                now_time = datetime.datetime.utcnow()
                time_skew = (now_time-srv_time).total_seconds() > MAX_TIME_SKEW
                if time_skew and config.USE_MIDDLE_PROXY and not disable_middle_proxy:
                    print_err("Time skew detected, please set the clock")
                    print_err("Server time:", srv_time, "your time:", now_time)
                    print_err("Disabling advertising to continue serving")

                    disable_middle_proxy = True
                    want_to_reenable_advertising = True
                elif not time_skew and want_to_reenable_advertising:
                    print_err("Time is ok, reenabling advertising")
                    disable_middle_proxy = False
                    want_to_reenable_advertising = False
        except Exception as E:
            print_err("Error getting server time", E)

        await asyncio.sleep(config.GET_TIME_PERIOD)


async def update_middle_proxy_info():
    async def get_new_proxies(url):
        PROXY_REGEXP = re.compile(r"proxy_for\s+(-?\d+)\s+(.+):(\d+)\s*;")
        ans = {}
        headers, body = await make_https_req(url)

        fields = PROXY_REGEXP.findall(body.decode("utf8"))
        if fields:
            for dc_idx, host, port in fields:
                if host.startswith("[") and host.endswith("]"):
                    host = host[1:-1]
                dc_idx, port = int(dc_idx), int(port)
                if dc_idx not in ans:
                    ans[dc_idx] = [(host, port)]
                else:
                    ans[dc_idx].append((host, port))
        return ans

    PROXY_INFO_ADDR = "https://core.telegram.org/getProxyConfig"
    PROXY_INFO_ADDR_V6 = "https://core.telegram.org/getProxyConfigV6"
    PROXY_SECRET_ADDR = "https://core.telegram.org/getProxySecret"

    global TG_MIDDLE_PROXIES_V4
    global TG_MIDDLE_PROXIES_V6
    global PROXY_SECRET

    while True:
        try:
            v4_proxies = await get_new_proxies(PROXY_INFO_ADDR)
            if not v4_proxies:
                raise Exception("no proxy data")
            TG_MIDDLE_PROXIES_V4 = v4_proxies
        except Exception as E:
            print_err("Error updating middle proxy list:", E)

        try:
            v6_proxies = await get_new_proxies(PROXY_INFO_ADDR_V6)
            if not v6_proxies:
                raise Exception("no proxy data (ipv6)")
            TG_MIDDLE_PROXIES_V6 = v6_proxies
        except Exception as E:
            print_err("Error updating middle proxy list for IPv6:", E)

        try:
            headers, secret = await make_https_req(PROXY_SECRET_ADDR)
            if not secret:
                raise Exception("no secret")
            if secret != PROXY_SECRET:
                PROXY_SECRET = secret
                print_err("Middle proxy secret updated")
        except Exception as E:
            print_err("Error updating middle proxy secret, using old", E)

        await asyncio.sleep(config.PROXY_INFO_UPDATE_PERIOD)


def init_ip_info():
    global my_ip_info
    global disable_middle_proxy

    def get_ip_from_url(url):
        TIMEOUT = 5
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as f:
                if f.status != 200:
                    raise Exception("Invalid status code")
                return f.read().decode().strip()
        except Exception:
            return None

    IPV4_URL1 = "http://v4.ident.me/"
    IPV4_URL2 = "http://ipv4.icanhazip.com/"

    IPV6_URL1 = "http://v6.ident.me/"
    IPV6_URL2 = "http://ipv6.icanhazip.com/"

    my_ip_info["ipv4"] = get_ip_from_url(IPV4_URL1) or get_ip_from_url(IPV4_URL2)
    my_ip_info["ipv6"] = get_ip_from_url(IPV6_URL1) or get_ip_from_url(IPV6_URL2)

    if my_ip_info["ipv6"] and (config.PREFER_IPV6 or not my_ip_info["ipv4"]):
        print_err("IPv6 found, using it for external communication")

    if config.USE_MIDDLE_PROXY:
        if not my_ip_info["ipv4"] and not my_ip_info["ipv6"]:
            print_err("Failed to determine your ip, advertising disabled")
            disable_middle_proxy = True


def print_tg_info():
    global my_ip_info

    ip_addrs = [ip for ip in my_ip_info.values() if ip]
    if not ip_addrs:
        ip_addrs = ["YOUR_IP"]

    for user, secret in sorted(config.USERS.items(), key=lambda x: x[0]):
        for ip in ip_addrs:
            if not config.SECURE_ONLY:
                params = {"server": ip, "port": config.PORT, "secret": secret}
                params_encodeded = urllib.parse.urlencode(params, safe=':')
                print("{}: tg://proxy?{}".format(user, params_encodeded), flush=True)

            params = {"server": ip, "port": config.PORT, "secret": "dd" + secret}
            params_encodeded = urllib.parse.urlencode(params, safe=':')
            print("{}: tg://proxy?{}".format(user, params_encodeded), flush=True)

            if not config.DISABLE_TLS:
                tls_secret = bytes.fromhex("ee" + secret) + config.TLS_DOMAIN.encode()
                tls_secret_base64 = base64.urlsafe_b64encode(tls_secret)
                params = {"server": ip, "port": config.PORT, "secret": tls_secret_base64}
                params_encodeded = urllib.parse.urlencode(params, safe=':')
                print("{}: tg://proxy?{} (experimental)".format(user, params_encodeded), flush=True)

        if secret in ["00000000000000000000000000000000", "0123456789abcdef0123456789abcdef"]:
            msg = "The default secret {} is used, this is not recommended".format(secret)
            print(msg, flush=True)


def setup_files_limit():
    try:
        import resource
        soft_fd_limit, hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_fd_limit, hard_fd_limit))
    except (ValueError, OSError):
        print("Failed to increase the limit of opened files", flush=True, file=sys.stderr)
    except ImportError:
        pass


def setup_signals():
    if hasattr(signal, 'SIGUSR1'):
        def debug_signal(signum, frame):
            import pdb
            pdb.set_trace()

        signal.signal(signal.SIGUSR1, debug_signal)

    if hasattr(signal, 'SIGUSR2'):
        def reload_signal(signum, frame):
            init_config()
            print("Config reloaded", flush=True, file=sys.stderr)
            print_tg_info()

        signal.signal(signal.SIGUSR2, reload_signal)


def try_setup_uvloop():
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass


def loop_exception_handler(loop, context):
    exception = context.get("exception")
    transport = context.get("transport")
    if exception:
        if isinstance(exception, TimeoutError):
            if transport:
                transport.abort()
                return
        if isinstance(exception, OSError):
            IGNORE_ERRNO = {
                10038,  # operation on non-socket on Windows, likely because fd == -1
                121,    # the semaphore timeout period has expired on Windows
            }

            FORCE_CLOSE_ERRNO = {
                113,    # no route to host

            }
            if exception.errno in IGNORE_ERRNO:
                return
            elif exception.errno in FORCE_CLOSE_ERRNO:
                if transport:
                    transport.abort()
                    return

    loop.default_exception_handler(context)


def main():
    setup_files_limit()
    setup_signals()
    try_setup_uvloop()

    init_stats()

    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(loop_exception_handler)

    stats_printer_task = asyncio.Task(stats_printer())
    asyncio.ensure_future(stats_printer_task)

    if config.USE_MIDDLE_PROXY:
        middle_proxy_updater_task = asyncio.Task(update_middle_proxy_info())
        asyncio.ensure_future(middle_proxy_updater_task)

        if config.GET_TIME_PERIOD:
            time_get_task = asyncio.Task(get_srv_time())
            asyncio.ensure_future(time_get_task)

    reuse_port = hasattr(socket, "SO_REUSEPORT")

    if config.LISTEN_ADDR_IPV4:
        task_v4 = asyncio.start_server(handle_client_wrapper, config.LISTEN_ADDR_IPV4, config.PORT,
                                       limit=get_to_tg_bufsize(), reuse_port=reuse_port, loop=loop)
        server_v4 = loop.run_until_complete(task_v4)

    if config.LISTEN_ADDR_IPV6 and socket.has_ipv6:
        task_v6 = asyncio.start_server(handle_client_wrapper, config.LISTEN_ADDR_IPV6, config.PORT,
                                       limit=get_to_tg_bufsize(), reuse_port=reuse_port, loop=loop)
        server_v6 = loop.run_until_complete(task_v6)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    for task in asyncio.Task.all_tasks():
        task.cancel()

    if config.LISTEN_ADDR_IPV4:
        server_v4.close()
        loop.run_until_complete(server_v4.wait_closed())

    if config.LISTEN_ADDR_IPV6 and socket.has_ipv6:
        server_v6.close()
        loop.run_until_complete(server_v6.wait_closed())

    loop.close()


if __name__ == "__main__":
    init_config()
    init_ip_info()
    print_tg_info()
    main()
