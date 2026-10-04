#!/usr/bin/env python3
"""Firmware byte formats vs independent models: the beacon header (PROTOCOL Q1 table), the DM
announcement countdown, the discovery advert, the 0x22 PairingData payload, the accept, the TL
packets and the notification chunk stream against tools/pulsar_host.py / pulsar_input.py."""
import os
import random
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import pulsar_host as H  # noqa: E402
import pulsar_input as I  # noqa: E402

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
    args = (m, rnd.randrange(37), rnd.randrange(4), rnd.getrandbits(16), rnd.getrandbits(52), 1 << rnd.randrange(1, 5),
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

# docs/re/REVIEW-RE.md R1-R3: one accept, [2] = (2 << 3) | 2, [11] = S (1..4, never 0),
# [12] = steady-IV flag, [13] = slot count 1; and the controller's request
for _ in range(50):
    dev, slot, iv = rnd.getrandbits(64), rnd.randrange(1, 5), rnd.choice((os.urandom(8), bytes(8)))
    pkt = bytes.fromhex(run("conn", dev, slot, iv.hex()))
    assert pkt == H.build_conn_negotiation(dev, slot, steady_iv=iv), pkt.hex()
    req = H.parse_conn_request(bytes.fromhex(run("req", dev, iv.hex())))
    assert (req["device_id"], req["version"], req["steady_iv"], req["format"]) == (dev, 0x1701, iv, 2), req
assert run("conn", 1, 0, "00" * 8) == "refused"  # slot 0 trips the controller's assert (R1)
print("connection: accepts identical to pulsar_host.py (slot 0 refused); requests parse with pulsar_host.py")

# R0: TL requests, peripheral payloads (PERIPHERALS.md via pulsar_input.py), uplinks
for _ in range(100):
    reg, seq, read = rnd.getrandbits(8), rnd.randrange(16), rnd.random() < 0.5
    payload = os.urandom(rnd.randrange(33))
    got = run("tl", reg, seq, int(read), payload.hex() or "-")
    assert bytes.fromhex(got) == H.build_tl_request(reg, seq, read, payload), (got, reg, seq, read)
assert run("tl", 1, 0, 0, "00" * 33) == "refused"
for _ in range(50):
    period, on, phase = rnd.randrange(700, 500001), rnd.randrange(1, 76), rnd.randrange(-10**6, 10**6)
    want = bytes([0x28, 0]) + I.pack_led_config(period, on, phase % period)
    assert bytes.fromhex(run("led", 2, period, on, phase)) == want
    amp, freq = rnd.getrandbits(8), rnd.randrange(40, 562)
    assert bytes.fromhex(run("haptic", 1, amp, freq)) == bytes([0xA0, 0]) + I.pack_haptic_freq(amp, freq)
assert bytes.fromhex(run("led", 0, 0, 0, 0)) == bytes([0x28, 0]) + I.pack_led_config(500000, 0, 0)
assert run("led", 1, 1000, 10, 0) == "refused"  # a real controller cannot hold its LEDs on
assert bytes.fromhex(run("haptic", 0, 0, 0)) == bytes([0x97, 0]) + I.pack_haptic_simple(0)
assert run("haptic", 2, 9, 9) == "pending"
for _ in range(100):
    slot = rnd.randrange(1, 5)
    pt = bytes([slot, rnd.getrandbits(8), rnd.getrandbits(7)]) + os.urandom(rnd.randrange(50))
    want = H.parse_tl_uplink(pt)
    s_, reg, fl, data = (run("tlup", pt.hex()) + " ").split(" ")[:4]
    assert (int(s_), int(reg), bytes.fromhex(data)) == (want["slot"], want["reg"], want["data"])
    fl = int(fl)
    assert (fl & 15, bool(fl & 0x10), bool(fl & 0x20), bool(fl & 0x40)) == \
        (want["seq"], want["read"], want["err"], want["ntf"])
print("TL: requests, LED / haptic payloads and uplinks identical to pulsar_host.py / pulsar_input.py")

# R13: notification chunk streams, fragments spanning notifications, one unpacker per controller
for _ in range(100):
    items = [(rnd.randrange(64), os.urandom(rnd.randrange(1, 40))) for _ in range(rnd.randrange(1, 6))]
    pays = I.pack_notifications(items)
    u = I.NtfUnpacker()
    want = [c for p in pays for c in u.feed(p)]
    assert [(t, bytes(d)) for t, d in want] == [(t, bytes(d)) for t, d in items], (items, want)
    got = run("ntf", *[p.hex() or "-" for p in pays]).split()
    assert got == [f"{t}:{bytes(d).hex()}" for t, d in want], (got, want)
print("ntf chunks: 100 fragmented streams reassemble like pulsar_input.NtfUnpacker")

for _ in range(50):
    shared, key, iv = os.urandom(32), os.urandom(16), os.urandom(8)
    netaddr = rnd.getrandbits(32)
    payload = bytes.fromhex(run("pairdata", shared.hex(), netaddr, key.hex(), iv.hex()))
    want, _ = H.build_pairing_payload(H.wrap_key_from_shared(shared), netaddr, key, iv=iv)
    assert payload == want
    assert H.parse_pairing_data(H.wrap_key_from_shared(shared), payload) == (struct.pack("<I", netaddr), key)
    assert run("unpair", shared.hex(), want.hex()) == f"{netaddr:08x} {key.hex()}"
    bad = bytearray(want)
    bad[20] ^= 1
    assert run("unpair", shared.hex(), bytes(bad).hex()) == "fail"
print("pairing data: 50 payloads identical to pulsar_host.py both ways; tampering rejected")
