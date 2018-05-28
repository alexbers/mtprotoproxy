#!/usr/bin/env python3

import asyncio
import socket
import urllib.parse
import collections
import time
import hashlib
import random

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    def create_aes(key, iv):
        ctr = Counter.new(128, initial_value=iv)
        return AES.new(key, AES.MODE_CTR, counter=ctr)

except ModuleNotFoundError:
    print("Failed to find pycrypto, using slow AES version", flush=True)
    import pyaes

    def create_aes(key, iv):
        ctr = pyaes.Counter(iv)
        return pyaes.AESModeOfOperationCTR(key, ctr)


from config import PORT, USERS

TG_DATACENTERS = [
    "149.154.175.50", "149.154.167.51", "149.154.175.100",
    "149.154.167.91", "149.154.171.5"
]

TG_DATACENTER_PORT = 443

# disables tg->client trafic reencryption, faster but less secure
FAST_MODE = True

STATS_PRINT_PERIOD = 600
READ_BUF_SIZE = 4096

SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
HANDSHAKE_LEN = 64
MAGIC_VAL_POS = 56

MAGIC_VAL_TO_CHECK = b'\xef\xef\xef\xef'

def init_stats():
    global stats
    stats = {user: collections.Counter() for user in USERS}


def update_stats(user, connects=0, curr_connects_x2=0, octets=0):
    global stats

    if user not in stats:
        stats[user] = collections.Counter()

    stats[user].update(connects=connects, curr_connects_x2=curr_connects_x2,
                       octets=octets)


async def handle_handshake(reader, writer):
    handshake = await reader.readexactly(HANDSHAKE_LEN)

    for user in USERS:
        secret = bytes.fromhex(USERS[user])

        dec_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN]
        dec_prekey, dec_iv = dec_prekey_and_iv[:PREKEY_LEN], dec_prekey_and_iv[PREKEY_LEN:]
        dec_key = hashlib.sha256(dec_prekey + secret).digest()
        decryptor = create_aes(key=dec_key, iv=int.from_bytes(dec_iv, "big"))

        enc_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN+PREKEY_LEN+IV_LEN][::-1]
        enc_prekey, enc_iv = enc_prekey_and_iv[:PREKEY_LEN], enc_prekey_and_iv[PREKEY_LEN:]
        enc_key = hashlib.sha256(enc_prekey + secret).digest()
        encryptor = create_aes(key=enc_key, iv=int.from_bytes(enc_iv, "big"))

        decrypted = decryptor.decrypt(handshake)
        
        check_val = decrypted[MAGIC_VAL_POS:MAGIC_VAL_POS+4]
        if check_val != MAGIC_VAL_TO_CHECK:
            continue

        dc_idx = abs(int.from_bytes(decrypted[60:62], "little", signed=True)) - 1

        if dc_idx < 0 or dc_idx >= len(TG_DATACENTERS):
            continue

        dc = TG_DATACENTERS[dc_idx]

        return encryptor, decryptor, user, dc, enc_key + enc_iv
    return False


async def do_handshake(dc, dec_key_and_iv=None):
    RESERVED_NONCE_FIRST_CHARS = [b"\xef"]
    RESERVED_NONCE_BEGININGS = [b"\x48\x45\x41\x44", b"\x50\x4F\x53\x54",
                                b"\x47\x45\x54\x20", b"\xee\xee\xee\xee"]
    RESERVED_NONCE_CONTINUES = [b"\x00\x00\x00\x00"]

    try:
        reader_tgt, writer_tgt = await asyncio.open_connection(dc, TG_DATACENTER_PORT)
    except ConnectionRefusedError as E:
        return False
    except OSError as E:
        return False

    while True:
        rnd = bytearray([random.randrange(0, 256) for i in range(HANDSHAKE_LEN)])
        if rnd[:1] in RESERVED_NONCE_FIRST_CHARS:
            continue
        if rnd[:4] in RESERVED_NONCE_BEGININGS:
            continue
        if rnd[4:8] in RESERVED_NONCE_CONTINUES:
            continue
        break

    rnd[MAGIC_VAL_POS:MAGIC_VAL_POS+4] = MAGIC_VAL_TO_CHECK

    if dec_key_and_iv:
        rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN] = dec_key_and_iv[::-1]

    rnd = bytes(rnd)

    dec_key_and_iv = rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN][::-1]
    dec_key, dec_iv = dec_key_and_iv[:KEY_LEN], dec_key_and_iv[KEY_LEN:]
    decryptor = create_aes(key=dec_key, iv=int.from_bytes(dec_iv, "big"))

    enc_key_and_iv = rnd[SKIP_LEN:SKIP_LEN+KEY_LEN+IV_LEN]
    enc_key, enc_iv = enc_key_and_iv[:KEY_LEN], enc_key_and_iv[KEY_LEN:]
    encryptor = create_aes(key=enc_key, iv=int.from_bytes(enc_iv, "big"))
    
    rnd_enc = rnd[:MAGIC_VAL_POS] + encryptor.encrypt(rnd)[MAGIC_VAL_POS:]

    writer_tgt.write(rnd_enc)
    await writer_tgt.drain()

    return encryptor, decryptor, reader_tgt, writer_tgt


async def handle_client(reader, writer):
    clt_data = await handle_handshake(reader, writer)
    if not clt_data:
        writer.close()
        return

    clt_enc, clt_dec, user, dc, enc_key_and_iv = clt_data

    update_stats(user, connects=1)

    if FAST_MODE:
        tg_data = await do_handshake(dc, dec_key_and_iv=enc_key_and_iv)
    else:
        tg_data = await do_handshake(dc)
    if not tg_data:
        writer.close()
        return

    tg_enc, tg_dec, reader_tg, writer_tg = tg_data

    async def connect_reader_to_writer(rd, wr, rd_dec, wr_enc, user, fast=False):
        update_stats(user, curr_connects_x2=1)
        try:
            while True:
                data = await rd.read(READ_BUF_SIZE)
                if not data:
                    wr.write_eof()
                    await wr.drain()
                    wr.close()
                    return
                else:
                    update_stats(user, octets=len(data))

                    before_data = data
                    if not fast:
                        dec_data = rd_dec.decrypt(data)
                        data = wr_enc.encrypt(dec_data)

                    wr.write(data)
                    await wr.drain()
        except (ConnectionResetError, BrokenPipeError, OSError,
                AttributeError) as e:
            wr.close()
            # print(e)
        finally:
            update_stats(user, curr_connects_x2=-1)

    asyncio.ensure_future(connect_reader_to_writer(reader_tg, writer, tg_dec, clt_enc, user, fast=FAST_MODE))
    asyncio.ensure_future(connect_reader_to_writer(reader, writer_tg, clt_dec, tg_enc, user))


async def handle_client_wrapper(reader, writer):
    try:
        await handle_client(reader, writer)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        writer.close()


async def stats_printer():
    global stats
    while True:
        await asyncio.sleep(STATS_PRINT_PERIOD)

        print("Stats for", time.strftime("%d.%m.%Y %H:%M:%S"))
        for user, stat in stats.items():
            print("%s: %d connects (%d current), %.2f MB" % (
                user, stat["connects"], stat["curr_connects_x2"] // 2,
                stat["octets"] / 1000000))
        print(flush=True)


def print_tg_info():
    my_ip = socket.gethostbyname(socket.gethostname())

    octets = [int(o) for o in my_ip.split(".")]

    ip_is_local = (len(octets) == 4 and (
        octets[0] in [127, 10] or
        octets[0:2] == [192, 168] or
        (octets[0] == 172 and 16 <= octets[1] <= 31)))

    if ip_is_local:
        my_ip = "YOUR_IP"

    for user, secret in USERS.items():
        params = {
            "server": my_ip, "port": PORT, "secret": secret
        }
        print("tg://proxy?" + urllib.parse.urlencode(params), flush=True)


def main():
    init_stats()

    loop = asyncio.get_event_loop()
    stats_printer_task = asyncio.Task(stats_printer())
    asyncio.ensure_future(stats_printer_task)
    task = asyncio.start_server(handle_client_wrapper,
                                "0.0.0.0", PORT, loop=loop)
    server = loop.run_until_complete(task)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    stats_printer_task.cancel()

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == "__main__":
    print_tg_info()
    main()
