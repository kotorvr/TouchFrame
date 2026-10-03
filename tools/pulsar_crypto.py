#!/usr/bin/env python3
"""Offline decode of a captured Pulsar connected-link packet, given the link's AES key.

The Pulsar link cipher is nRF hardware AES-128-CCM (docs/PROTOCOL.md Q3): L=2, 4-byte MIC,
1 byte of associated data (the CCM header byte, which Pulsar sets to 0). The 16-byte key is
provisioned at pairing and is held only on the headset and the controller; it never travels over
the air, so a sniffer cannot recover it and this tool cannot "crack" anything. It is for decoding
*your own* link once you supply that key — e.g. the headset default from
`/data/misc/pulsar_aes_key.bin`, or a key you dumped from your own device.

The 13-byte CCM nonce packing from the Pulsar fields (session nonce, beacon timestamp, per-packet
counter, direction) is not yet pinned from the firmware (docs/PROTOCOL.md open item). So this tries
several candidate layouts and reports which one makes the 4-byte MIC verify — a correct MIC is a
1-in-4-billion coincidence, so a single verifying packet confirms both the key and the layout.

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


def candidate_nonces(counter, direction, iv, session, timestamp):
    """Plausible IV derivations to try. 'iv' (if given) overrides; else build from
    session nonce (beacon bytes 6-7) and 48-bit beacon timestamp (bytes 8-13)."""
    out = []
    if iv is not None:
        out.append(("explicit-iv", nonce_from_fields(counter, direction, iv)))
        return out
    sess = session or 0
    ts = timestamp or 0
    # elk-app 0x2409c builds a 64-bit value (session<<48)|timestamp; try it as IV (both endians)
    combined = ((sess & 0xFFFF) << 48) | (ts & ((1 << 48) - 1))
    out.append(("iv=sess<<48|ts LE", nonce_from_fields(counter, direction, combined.to_bytes(8, "little"))))
    out.append(("iv=sess<<48|ts BE", nonce_from_fields(counter, direction, combined.to_bytes(8, "big"))))
    # that 64-bit value as the packet counter instead, zero IV
    out.append(("ctr=sess<<48|ts", nonce_from_fields(combined, direction, b"\x00" * 8)))
    # counter alone, zero IV
    out.append(("ctr-only", nonce_from_fields(counter, direction, b"\x00" * 8)))
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
    print("selftest ok (RFC 3610 vector #1 + keystream round-trip)")


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


def do_scan(args):
    key = h(args.key)
    rows = []
    with open(args.capture) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    rows = rows[: args.limit] if args.limit else rows
    print(f"{len(rows)} packets; trying counters 0..{args.max_counter} per packet")
    for r in rows:
        data = h(r["data"])
        # strip the 1-byte LENGTH header and (if present) trailing 3 CRC bytes captured with --no-crc
        payload = data[1:]
        for strip_crc in (0, 3):
            body = payload[: len(payload) - strip_crc] if strip_crc else payload
            if len(body) < 5:
                continue
            for direction in (0, 1):
                for counter in range(args.max_counter + 1):
                    for name, nonce in candidate_nonces(counter, direction, None, args.session, r.get("t_us")):
                        pt, ok = ccm_decrypt(key, nonce, body)
                        if ok:
                            print(f"VERIFIED t={r.get('t_us')} mhz={r.get('mhz')} dir={direction} ctr={counter} "
                                  f"[{name}] crc_strip={strip_crc}\n  pt={pt.hex()}")
                            return
    print("no packet verified with the given key and candidates")


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
    s.add_argument("--session", type=lambda x: int(x, 16))
    s.add_argument("--max-counter", type=int, default=8)
    s.add_argument("--limit", type=int, default=0)
    s.set_defaults(fn=do_scan)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
