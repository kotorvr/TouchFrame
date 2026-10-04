#!/usr/bin/env python3
"""Offline decode of a captured Pulsar connected-link packet, given the link's AES key.

The Pulsar link cipher is nRF hardware AES-128-CCM (docs/PROTOCOL.md Q3): L=2, 4-byte MIC,
1 byte of associated data (the CCM header byte, which Pulsar sets to 0). The 16-byte key is
provisioned at pairing and is held only on the headset and the controller; it never travels over
the air, so a sniffer cannot recover it and this tool cannot "crack" anything. It is for decoding
*your own* link once you supply that key — e.g. the headset default from
`/data/misc/pulsar_aes_key.bin`, or a key you dumped from your own device.

The 13-byte CCM nonce is the nRF hardware-CCM layout (docs/PROTOCOL.md Q3/Q4, docs/re/LINK.md §2),
confirmed from the firmware: a 5-byte little-endian packet counter (39-bit counter + direction in
bit 39) followed by the 8-byte IV. CCM is UPLINK ONLY (AUDIT A4): beacons and host downlink are
plaintext, so only device->host uplinks are decrypted here. There are two IV regimes (AUDIT A2/A3,
re-derived against the firmware — this supersedes the earlier "random per-session IV" reading,
which was the *pairing* wrap `FUN_00047604`, a different link):

  - **negotiation / "legacy" (A2):** counter 0, IV = session_nonce<<48 | beacon_ts48 (u64 LE), both
    read from the beacon (bytes 6..7 and 8..13). Nothing is random; a sniffer with the key derives
    it from the beacon alone. Decrypts the controller's first uplink (its connection request).
  - **steady state (A3):** IV = the 8 bytes the controller put in its connection request (bytes
    15..22, from elk record +0x68), with a per-slot counter that advances per packet.

Decode: for a negotiation uplink, pass `--session`/`--timestamp` (or let `scan` read them from the
preceding AP1 beacon). For steady-state uplinks, pass `--iv <the 8 request bytes>` and let `scan`
sweep the counter; a correct 4-byte MIC is a 1-in-4-billion coincidence, so one verifying packet
confirms IV + counter + key. AAD = S0 & 0xE3 (connected S0 0x04 -> 0x00).

  pulsar_crypto.py selftest
  pulsar_crypto.py decode --key <32 hex> --packet <hex payload incl. 4-byte MIC> \\
      [--counter N] [--dir 0|1] [--iv <16 hex>] [--session <4 hex>] [--timestamp N]
  pulsar_crypto.py scan  --key <32 hex> --capture cap.jsonl [--session ...] [--limit N]
      try every candidate layout against captured packets; report the first that verifies
"""
import argparse
import json
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ecb(key):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return lambda block: enc.update(block)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def ccm_decrypt(key, nonce, ct_with_mic, aad=b"\x00", mic_len=4, L=2):
    """RFC 3610 CCM. Returns (plaintext, mic_ok). nonce must be 15-L bytes."""
    if len(nonce) != 15 - L:
        raise ValueError(f"nonce must be {15 - L} bytes for L={L}")
    if len(ct_with_mic) < mic_len:
        return b"", False
    ct, mic = ct_with_mic[:-mic_len], ct_with_mic[-mic_len:]
    E = aes_ecb(key)
    m = len(ct)

    # Counter blocks A_i = flags(L-1) | nonce | i (L bytes)
    def A(i):
        return bytes([L - 1]) + nonce + i.to_bytes(L, "big")

    # Keystream for the payload, starting at A_1.
    ks = b""
    i = 1
    while len(ks) < m:
        ks += E(A(i))
        i += 1
    pt = xor(ct, ks[:m])

    # CBC-MAC over B_0, AAD, plaintext.
    flags = 64 * (1 if aad else 0) + 8 * ((mic_len - 2) // 2) + (L - 1)
    b0 = bytes([flags]) + nonce + m.to_bytes(L, "big")
    x = E(b0)
    if aad:
        a = struct.pack(">H", len(aad)) + aad  # <2^16 AAD: 2-byte length prefix
        a += b"\x00" * (-len(a) % 16)
        for off in range(0, len(a), 16):
            x = E(xor(x, a[off:off + 16]))
    p = pt + b"\x00" * (-m % 16)
    for off in range(0, len(p), 16):
        x = E(xor(x, p[off:off + 16]))
    mic_calc = xor(x, E(A(0)))[:mic_len]
    return pt, mic_calc == mic


# ---- Pulsar nonce candidates (13 bytes = 5-byte packet counter + 8-byte IV) ----

def nonce_from_fields(counter=0, direction=0, iv=b"\x00" * 8):
    """nRF BLE-CCM packing: 39-bit counter little-endian, direction = bit 39, then IV[8]."""
    if len(iv) != 8:
        raise ValueError("iv must be 8 bytes")
    pc = (counter & ((1 << 39) - 1)) | ((direction & 1) << 39)
    return pc.to_bytes(5, "little") + iv


def legacy_iv(session, beacon_ts48):
    """Negotiation ("legacy") IV = (session_nonce << 48 | beacon_ts48) as u64 little-endian
    (AUDIT A2, CONFIRMED: host FUN_0001aba8, elk 0x24092..0x240d6). Both come from the beacon
    (session = bytes 6..7, ts48 = bytes 8..13), so no IV is on air."""
    return ((((session or 0) & 0xFFFF) << 48) | ((beacon_ts48 or 0) & ((1 << 48) - 1))).to_bytes(8, "little")


def candidate_nonces(counter, direction, iv=None, session=None, beacon_ts=None):
    """Firmware-grounded nonce candidates (AUDIT A2/A3). Two regimes:

    - **steady state (A3):** `iv` = the 8 bytes the controller sent in its connection request
      (bytes 15..22), swept against a per-packet `counter`. This is the regime for all normal
      uplinks once the link is up.
    - **negotiation (A2):** `session` + `beacon_ts` from the beacon that opened the period; the
      nonce is counter 0, IV = legacy_iv(session, beacon_ts). This decrypts the controller's first
      uplink (its connection request), which itself carries the steady IV.

    Each is tried in the caller's direction and the flipped one (uplink is bit 39 = 1). The old
    `ctr=session<<48|ts` candidate is gone: `nonce_from_fields` masks the counter to 39 bits, so it
    silently dropped the session."""
    out = []
    if iv is not None:
        out.append(("steady iv-from-request", nonce_from_fields(counter, direction, iv)))
        out.append(("steady dir-flip", nonce_from_fields(counter, direction ^ 1, iv)))
    if session is not None and beacon_ts is not None:
        liv = legacy_iv(session, beacon_ts)
        out.append(("legacy session<<48|ts", nonce_from_fields(0, direction, liv)))
        out.append(("legacy dir-flip", nonce_from_fields(0, direction ^ 1, liv)))
    if not out:
        out.append(("ctr-only (pass --iv or --session+--timestamp)", nonce_from_fields(counter, direction, b"\x00" * 8)))
    return out


# ---- RFC 3610 self-test (validates the CCM implementation) ----

def selftest():
    # RFC 3610 packet vector #1: AES-CCM, L=2, M=8, 8-byte AAD.
    key = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
    nonce = bytes.fromhex("00000003020100a0a1a2a3a4a5")
    aad = bytes.fromhex("0001020304050607")
    enc = bytes.fromhex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
    pt, ok = ccm_decrypt(key, nonce, enc, aad=aad, mic_len=8, L=2)
    assert ok, "RFC 3610 #1 MIC failed"
    assert pt == bytes.fromhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e"), pt.hex()
    # Round-trip a Pulsar-shaped frame (1-byte AAD=0, M=4) to exercise that path.
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    n = nonce_from_fields(counter=0x1234, direction=1, iv=bytes(range(8)))
    msg = bytes(range(20))
    # encrypt = decrypt keystream is symmetric; forge a ct by decrypting then re-deriving is circular,
    # so just check decrypt of a self-encrypted frame:
    ct, _ = ccm_decrypt(k, n, msg + b"\x00" * 4, aad=b"\x00", mic_len=4)  # ct = msg xor ks
    # re-run: decrypting ct should give back msg, and MIC now recomputed over msg
    # build a valid frame: ciphertext = msg xor ks, mic = CBCMAC(msg) xor S0
    pt2, _ = ccm_decrypt(k, n, ct + b"\x00" * 4, aad=b"\x00", mic_len=4)
    assert pt2 == msg, "keystream round-trip failed"

    # AUDIT A8: an independent MIC check. Build a real Pulsar-shaped packet with the stdlib AES-CCM
    # under the A2 legacy nonce, wrap it as an on-air connected packet ([S0=0x04][LEN][ct+MIC]), and
    # confirm `scan`'s beacon-tracked legacy path finds it (so the nonce model, header stripping and
    # AAD are all correct, not just self-consistent).
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    import os, tempfile
    session, ts = 0xABCD, 0x1122334455
    nonce_a2 = nonce_from_fields(0, 1, legacy_iv(session, ts))      # uplink (dir 1), counter 0
    plain = bytes(range(20))
    ct_mic = AESCCM(k, tag_length=4).encrypt(nonce_a2, plain, b"\x00")  # AAD = S0 0x04 & 0xE3 = 0x00
    assert len(ct_mic) == 24
    beacon_payload = bytes(6) + session.to_bytes(2, "little") + ts.to_bytes(6, "little") + bytes(2)
    beacon = bytes([0x04, len(beacon_payload)]) + beacon_payload     # S0 + LEN + payload (AP1)
    uplink = bytes([0x04, len(ct_mic)]) + ct_mic                     # S0 + LEN + CCM(ct+MIC)
    with tempfile.TemporaryDirectory() as d:
        cap = os.path.join(d, "c.jsonl")
        with open(cap, "w") as f:
            f.write(json.dumps(dict(t_us=1, mhz=2404, addr=1, data=beacon.hex())) + "\n")
            f.write(json.dumps(dict(t_us=2, mhz=2404, addr=2, data=uplink.hex())) + "\n")
        args = argparse.Namespace(key=k.hex(), capture=cap, iv=None, session=None,
                                  s0len=1, max_counter=2, limit=0)
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            do_scan(args)
        assert "VERIFIED" in buf.getvalue() and plain.hex() in buf.getvalue(), buf.getvalue()
    print("selftest ok (RFC 3610 vector #1 + keystream round-trip + "
          "A2 legacy-nonce AES-CCM packet recovered by scan)")


def h(s):
    return bytes.fromhex(s.replace(" ", ""))


def do_decode(args):
    key = h(args.key)
    pkt = h(args.packet)
    iv = h(args.iv) if args.iv else None
    tried = candidate_nonces(args.counter, args.dir, iv, args.session, args.timestamp)
    for name, nonce in tried:
        pt, ok = ccm_decrypt(key, nonce, pkt)
        print(f"  {'VERIFIED' if ok else 'no      '} [{name}] nonce={nonce.hex()}" + (f"  pt={pt.hex()}" if ok else ""))
    if not any(ccm_decrypt(key, n, pkt)[1] for _, n in tried):
        print("no layout verified: wrong key, wrong counter/session/timestamp, or an unmodelled nonce layout")


def _ccm_body(data, s0len):
    """Strip [S0 (s0len bytes)][LENGTH] from a captured packet, returning the CCM ciphertext+MIC.

    Connected-link packets are captured with s0len=1 (S0=0x04); DM/pairing with s0len=0. The CCM
    payload is everything after S0+LENGTH; LENGTH counts the on-air payload so nothing extra trails
    it when crc_len=0 (--no-crc). AAD = S0 & 0xE3 (BLE-CCM; connected S0 0x04 -> 0x00; AUDIT A8)."""
    if len(data) < s0len + 1:
        return None, b"\x00"
    s0 = data[0] if s0len else 0
    length = data[s0len]
    body = data[s0len + 1: s0len + 1 + length]
    aad = bytes([s0 & 0xE3])
    return body, aad


def do_scan(args):
    key = h(args.key)
    iv = h(args.iv) if args.iv else None
    s0len = args.s0len
    rows = []
    with open(args.capture) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    rows = rows[: args.limit] if args.limit else rows
    # Track the most recent host beacon (AP1) so the A2 legacy nonce can use its session+ts (A8:
    # pull them from the preceding beacon rather than the dongle capture time).
    sess, bts = args.session, None
    print(f"{len(rows)} packets; s0len={s0len}; counters 0..{args.max_counter}; "
          f"{'steady IV given' if iv else 'legacy (beacon-tracked)'}")
    for r in rows:
        data = h(r["data"])
        addr = r.get("addr")
        if addr == 1 and len(data) >= s0len + 14:   # host beacon: refresh session nonce + ts48
            bp = data[s0len + 1:]
            if len(bp) >= 14:
                sess = int.from_bytes(bp[6:8], "little")
                bts = int.from_bytes(bp[8:14], "little")
            continue
        body, aad = _ccm_body(data, s0len)
        if not body or len(body) < 5:
            continue
        for direction in (0, 1):
            for counter in range(args.max_counter + 1):
                for name, nonce in candidate_nonces(counter, direction, iv, sess, bts):
                    pt, ok = ccm_decrypt(key, nonce, body, aad=aad)
                    if ok:
                        print(f"VERIFIED t={r.get('t_us')} mhz={r.get('mhz')} addr={addr} dir={direction} "
                              f"ctr={counter} [{name}] aad={aad.hex()}\n  pt={pt.hex()}")
                        return
    print("no packet verified with the given key and candidates "
          "(need the link key; for legacy, a preceding AP1 beacon; for steady, --iv from the request)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())
    d = sub.add_parser("decode")
    d.add_argument("--key", required=True)
    d.add_argument("--packet", required=True, help="CCM ciphertext incl. 4-byte MIC, hex")
    d.add_argument("--counter", type=int, default=0)
    d.add_argument("--dir", type=int, default=0, choices=(0, 1))
    d.add_argument("--iv", help="explicit 8-byte IV, hex (overrides session/timestamp)")
    d.add_argument("--session", type=lambda x: int(x, 16), help="16-bit session nonce, hex")
    d.add_argument("--timestamp", type=int, help="48-bit beacon timestamp")
    d.set_defaults(fn=do_decode)
    s = sub.add_parser("scan")
    s.add_argument("--key", required=True)
    s.add_argument("--capture", required=True)
    s.add_argument("--iv", help="8-byte STEADY IV from the controller's connection request "
                               "(bytes 15..22), hex — A3: sweeps the per-packet counter with this IV")
    s.add_argument("--session", type=lambda x: int(x, 16),
                   help="16-bit session nonce (fallback if no AP1 beacon is in the capture)")
    s.add_argument("--s0len", type=int, default=1, choices=(0, 1),
                   help="1 for connected captures ([S0][LEN][payload]), 0 for DM/pairing")
    s.add_argument("--max-counter", type=int, default=8)
    s.add_argument("--limit", type=int, default=0)
    s.set_defaults(fn=do_scan)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
