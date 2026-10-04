#!/usr/bin/env python3
"""Firmware byte formats vs independent models: the beacon header (PROTOCOL Q1 table), the DM
announcement countdown, the discovery advert, and the 0x11 PairingData payload against
tools/pulsar_host.py (both directions)."""
import os
import random
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import pulsar_host as H  # noqa: E402

exe = os.path.abspath(sys.argv[1])
rnd = random.Random(5)


def run(*args):
    return subprocess.run([exe, *map(str, args)], capture_output=True, text=True, check=True).stdout.strip()


def ref_beacon(chmap, unmapped, dm, session, ts, cl, ack):
    """PROTOCOL Q1 beacon table, written out independently of the C."""
    b = bytearray(16)
    b[0] = (chmap & 0x1F) << 3 | (dm & 3) << 1
    for i in range(4):
        b[1 + i] = chmap >> (5 + 8 * i) & 0xFF
    b[5] = unmapped
    struct.pack_into("<H", b, 6, session)
    b[8:14] = (ts & (1 << 48) - 1).to_bytes(6, "little")
    b[14], b[15] = cl, ack
    return bytes(b)


for _ in range(150):
    m = 0
    while bin(m).count("1") < 8:
        m = rnd.getrandbits(37)
    args = (m, rnd.randrange(37), rnd.randrange(4), rnd.getrandbits(16), rnd.getrandbits(52), 1 << rnd.randrange(5),
            rnd.getrandbits(5))
    got = bytes.fromhex(run("beacon", *args))
    assert got == ref_beacon(*args), (args, got.hex())
print("beacon: 150 headers match the PROTOCOL Q1 layout and round-trip through the parser")

# DM countdown: 'D' periods are 5..24 apart and announced 3, 2, 1 periods ahead
seq = run("dm", 0x5EED1234, 400).split()
d = [i for i, s in enumerate(seq) if s == "D"]
assert len(d) > 10
for a, b in zip(d, d[1:]):
    assert 5 <= b - a - 1 <= 24, (a, b)
    assert seq[b - 3:b] == ["3", "2", "1"], seq[b - 4:b + 1]
    assert all(s == "0" for s in seq[a + 1:b - 3])
print(f"dm: {len(d)} DM periods, gaps 5..24, each announced 3/2/1 periods ahead")

adv = bytes.fromhex(run("advert", 0x1122334455667788))
assert len(adv) == 32 and adv[0] == 2 and adv[1:3] == b"\x01\x17" and adv[5:13] == (0x1122334455667788).to_bytes(8, "little")
print("advert: type 2, version 01 17, device id at [5..12]")

# docs/re/AUDIT.md A2: legacy nonce = 00 00 00 00 00 || ts[0..5] LE || session_nonce LE;
# A3: steady = counter (u32 LE, 5th byte 0) || the controller's IV
for _ in range(50):
    sess, ts = rnd.getrandbits(16), rnd.getrandbits(52)
    want = bytes(5) + (ts & (1 << 48) - 1).to_bytes(6, "little") + sess.to_bytes(2, "little")
    assert bytes.fromhex(run("legacy", sess, ts)) == want
    ctr, iv = rnd.getrandbits(32), os.urandom(8)
    assert bytes.fromhex(run("steady", ctr, iv.hex())) == ctr.to_bytes(5, "little") + iv
print("nonces: legacy and steady-state layouts match AUDIT A2/A3")

for _ in range(50):
    shared, key, iv = os.urandom(32), os.urandom(16), os.urandom(8)
    netaddr = rnd.getrandbits(32)
    payload = bytes.fromhex(run("pairdata", shared.hex(), netaddr, key.hex(), iv.hex()))
    want, _ = H.build_pairing_payload(H.wrap_key_from_shared(shared), struct.pack("<I", netaddr), key, iv=iv)
    assert payload == want
    assert H.parse_pairing_data(H.wrap_key_from_shared(shared), payload) == (struct.pack("<I", netaddr), key)
    assert run("unpair", shared.hex(), want.hex()) == f"{netaddr:08x} {key.hex()}"
    bad = bytearray(want)
    bad[20] ^= 1
    assert run("unpair", shared.hex(), bytes(bad).hex()) == "fail"
print("pairing data: 50 payloads identical to pulsar_host.py both ways; tampering rejected")
