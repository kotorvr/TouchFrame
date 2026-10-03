#!/usr/bin/env python3
"""Host side of the Pulsar pairing exchange — OFFLINE packet construction + self-test.

This builds and parses the bytes the TouchFrame nRF dongle would send/receive to act as the
*host* of the Pulsar pairing handshake with the user's own Meta Touch Plus controllers, without
a Quest headset. It is pure byte builders/parsers plus crypto; it does NOT touch any radio.

  >>> TRANSMITTING these frames needs the dongle (hardware day). <<<
This module only constructs and verifies packets in memory. Nothing here keys up a radio; the
actual over-the-air TX/RX is deferred to hardware day and is intentionally not part of this tool.

Protocol source: docs/PROTOCOL.md (read-only here). Relevant sections:
  - Q1  : SPL/pairing radio params, the on-air packet layout (LENGTH, payload, 3-byte CRC) and the
          CRC-24 poly/init.  (Q2 pins the SPL command header: 2 bytes = cmd + seq, then payload.)
  - Q2  : pairing command IDs and the PairingData (0x11) layout + the ECDH->CCM key truncation.
  - Q3  : the AES-128-CCM parameters (L=2, M=4, 1-byte AAD=0) shared with tools/pulsar_crypto.py.

Pairing exchange (host = us):
  1. 0x12 SetupX25519Keys : we send our 32-byte X25519 public key; the controller replies with its
     32-byte public key. Both sides then have the shared secret (ECDH). No host auth (Q2 / Gate A).
  2. 0x11 PairingData     : we send [8-byte clear CCM IV][24-byte CCM(20)]. The 20-byte plaintext is
     [4-byte connected-link base address (our netaddr)][16-byte AES link key]. The CCM wrap key is
     the FIRST 16 bytes of the 32-byte shared secret (plain truncation, no hash). We choose the key.
  0x14 WriteAESKey is a no-op stub in the controller SPL (Q2) — we never send it. 0x15 = Reset.

  pulsar_host.py selftest     run all offline checks (X25519 RFC 7748 vector, pairing round-trip,
                              CRC/framing round-trip); prints "selftest ok ...".
"""
import argparse
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Reuse the vetted CCM + nonce helpers from the decode tool rather than reimplement them.
from pulsar_crypto import aes_ecb, xor, ccm_decrypt, nonce_from_fields

# ---- SPL command IDs (Q2, from SPL dispatcher FUN_0000822c) -------------------------------------
# Command byte = [bit0 read/write][bits1..6 cmd#][bit7 reserved]; these are the confirmed on-wire
# byte values.
CMD_SETUP_X25519 = 0x12  # SetupX25519Keys: the 32-byte public-key cross
CMD_PAIRING_DATA = 0x11  # PairingData (write): [IV][CCM(base||key)]
CMD_WRITE_AES_KEY = 0x14  # no-op stub in this SPL image — do NOT send
CMD_RESET = 0x15

# CCM parameters for the pairing wrap (Q2/Q3): single 0x00 AAD byte, 4-byte MIC, L=2.
PAIR_AAD = b"\x00"
PAIR_MIC_LEN = 4
PAIR_L = 2

# CRC-24 over the pairing/SPL link (Q1: "CRC-24, poly 0x00108421, init 0x00FFFFFF" — CONFIRMED
# literals syncboss 0x52034/0x520a8, elk-app 0x316fc/0x31770).
CRC24_POLY = 0x00108421
CRC24_INIT = 0x00FFFFFF


# ---- CRC-24 ------------------------------------------------------------------------------------

def crc24(data, poly=CRC24_POLY, init=CRC24_INIT):
    """nRF-style bit-serial CRC-24 (implicit x^24 term; poly bits = x^20,x^15,x^10,x^5,x^0).

    Processed MSB-first per byte, which is the common reference packing for nRF 2Mbit links. The
    confirmed facts from PROTOCOL.md are the POLY and INIT values only; the per-byte bit order and
    whether the 5-byte access address is folded in (CRCCNF SKIPADDR=0, Q1) are a hardware-day
    validation item — pass the address via `addr` to frame_spl/unframe_spl to include it.
    """
    crc = init & 0xFFFFFF
    for byte in data:
        for i in range(8):
            inbit = (byte >> (7 - i)) & 1
            topbit = (crc >> 23) & 1
            crc = (crc << 1) & 0xFFFFFF
            if inbit ^ topbit:
                crc ^= poly
    return crc & 0xFFFFFF


# ---- SPL command framing (Q1 packet layout + Q2 command header) --------------------------------

def frame_spl(cmd, payload, seq=0, addr=b""):
    """Build one SPL/pairing frame: [LENGTH][cmd][seq][payload...][CRC-24, 3 bytes LE].

    LENGTH (nRF LFLEN=8, S0LEN=0 for the pairing link, Q1) counts the on-air payload = the SPL
    body (cmd + seq + payload), not itself and not the CRC. CRC-24 is computed over LENGTH+body
    (and, on air, the preceding access address — SKIPADDR=0; pass it as `addr` to mirror that).
    """
    body = bytes([cmd & 0xFF, seq & 0xFF]) + bytes(payload)
    if len(body) > 0xFF:
        raise ValueError("SPL body exceeds 255-byte LENGTH field")
    hdr = bytes([len(body)]) + body
    crc = crc24(bytes(addr) + hdr)
    return hdr + crc.to_bytes(3, "little")


def unframe_spl(frame, addr=b""):
    """Inverse of frame_spl. Returns (cmd, seq, payload). Raises on short frame or CRC mismatch."""
    if len(frame) < 1 + 2 + 3:
        raise ValueError("frame too short")
    length = frame[0]
    body = frame[1:1 + length]
    if len(body) != length or len(frame) < 1 + length + 3:
        raise ValueError("truncated frame (LENGTH says more bytes than present)")
    crc_bytes = frame[1 + length:1 + length + 3]
    want = crc24(bytes(addr) + frame[:1 + length]).to_bytes(3, "little")
    if crc_bytes != want:
        raise ValueError(f"CRC mismatch: got {crc_bytes.hex()} want {want.hex()}")
    return body[0], body[1], body[2:]


# ---- X25519 (Q2: anonymous ECDH; wrap key = shared_secret[:16]) --------------------------------

def gen_host_keypair():
    """Generate an ephemeral host X25519 keypair. Returns (private_key_obj, public_bytes32)."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def derive_shared_secret(host_priv, controller_pub32):
    """32-byte X25519 shared secret from our private key and the controller's 32-byte public key."""
    if len(controller_pub32) != 32:
        raise ValueError("controller public key must be 32 bytes")
    return host_priv.exchange(X25519PublicKey.from_public_bytes(bytes(controller_pub32)))


def wrap_key_from_shared(shared32):
    """Pairing CCM wrap key = FIRST 16 bytes of the shared secret (plain truncation, Q2)."""
    if len(shared32) != 32:
        raise ValueError("shared secret must be 32 bytes")
    return shared32[:16]


def build_setup_x25519(host_pub32, seq=0, addr=b""):
    """0x12 SetupX25519Keys command carrying our 32-byte public key, framed per Q1."""
    if len(host_pub32) != 32:
        raise ValueError("host public key must be 32 bytes")
    return frame_spl(CMD_SETUP_X25519, host_pub32, seq=seq, addr=addr)


def parse_setup_x25519_response(frame, addr=b""):
    """Parse the controller's 0x12 reply; return its 32-byte public key."""
    cmd, _seq, payload = unframe_spl(frame, addr=addr)
    if cmd != CMD_SETUP_X25519:
        raise ValueError(f"not a SetupX25519Keys (0x12) frame: cmd=0x{cmd:02x}")
    if len(payload) != 32:
        raise ValueError(f"expected 32-byte controller pubkey, got {len(payload)}")
    return payload


# ---- CCM encrypt (mirror of pulsar_crypto.ccm_decrypt, built on the same primitives) -----------

def ccm_encrypt(key, nonce, pt, aad=PAIR_AAD, mic_len=PAIR_MIC_LEN, L=PAIR_L):
    """RFC 3610 CCM encrypt. Returns ciphertext || MIC. Inverse of pulsar_crypto.ccm_decrypt."""
    if len(nonce) != 15 - L:
        raise ValueError(f"nonce must be {15 - L} bytes for L={L}")
    E = aes_ecb(key)
    m = len(pt)

    def A(i):
        return bytes([L - 1]) + nonce + i.to_bytes(L, "big")

    ks = b""
    i = 1
    while len(ks) < m:
        ks += E(A(i))
        i += 1
    ct = xor(pt, ks[:m])

    flags = 64 * (1 if aad else 0) + 8 * ((mic_len - 2) // 2) + (L - 1)
    b0 = bytes([flags]) + nonce + m.to_bytes(L, "big")
    x = E(b0)
    if aad:
        a = struct.pack(">H", len(aad)) + aad
        a += b"\x00" * (-len(a) % 16)
        for off in range(0, len(a), 16):
            x = E(xor(x, a[off:off + 16]))
    p = pt + b"\x00" * (-m % 16)
    for off in range(0, len(p), 16):
        x = E(xor(x, p[off:off + 16]))
    mic = xor(x, E(A(0)))[:mic_len]
    return ct + mic


# ---- PairingData (0x11) ------------------------------------------------------------------------

def build_pairing_payload(wrap_key, base_addr_4b, link_key_16b, iv=None):
    """Build the 32-byte 0x11 on-wire payload: [8-byte clear IV][CCM(base||key) = 24 bytes].

    Plaintext (20 bytes) = [4-byte connected-link base address][16-byte AES link key] (Q2).
    CCM uses the legacy/pairing nonce = packet counter 0 with this random 8-byte IV (Q2/Q3).
    Returns (payload32, iv).
    """
    if len(wrap_key) != 16:
        raise ValueError("wrap key must be 16 bytes")
    if len(base_addr_4b) != 4:
        raise ValueError("base address must be 4 bytes")
    if len(link_key_16b) != 16:
        raise ValueError("link key must be 16 bytes")
    if iv is None:
        iv = os.urandom(8)
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes")
    plaintext = bytes(base_addr_4b) + bytes(link_key_16b)  # 20 bytes
    nonce = nonce_from_fields(counter=0, direction=0, iv=bytes(iv))  # legacy nonce, counter 0
    ct_mic = ccm_encrypt(wrap_key, nonce, plaintext)  # 24 bytes (20 + 4 MIC)
    return bytes(iv) + ct_mic, bytes(iv)


def build_pairing_data(wrap_key, base_addr_4b, link_key_16b, iv=None, seq=0, addr=b""):
    """0x11 PairingData write command: builds the 32-byte payload then frames it per Q1."""
    payload32, _iv = build_pairing_payload(wrap_key, base_addr_4b, link_key_16b, iv=iv)
    return frame_spl(CMD_PAIRING_DATA, payload32, seq=seq, addr=addr)


def parse_pairing_data(wrap_key, payload32):
    """Decrypt + verify a 32-byte 0x11 payload. Returns (base_addr_4b, link_key_16b).

    Raises on wrong payload length, bad MIC, or a decrypted length != 20 (the controller's own
    "incorrect decrypted length" check, Q2: FUN_00003abc requires len-4 == 0x14).
    """
    if len(payload32) != 32:
        raise ValueError(f"PairingData payload must be 32 bytes, got {len(payload32)}")
    iv, ct_mic = payload32[:8], payload32[8:]
    nonce = nonce_from_fields(counter=0, direction=0, iv=iv)
    pt, mic_ok = ccm_decrypt(wrap_key, nonce, ct_mic, aad=PAIR_AAD, mic_len=PAIR_MIC_LEN, L=PAIR_L)
    if not mic_ok:
        raise ValueError("PairingData MIC verification failed")
    if len(pt) != 20:
        raise ValueError(f"incorrect decrypted length: {len(pt)} (expected 20)")
    return pt[:4], pt[4:20]


# ---- selftest ----------------------------------------------------------------------------------

def _check_x25519_rfc7748():
    """RFC 7748 section 6.1 test vector: Alice/Bob known keys -> known shared secret."""
    alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    alice_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expect = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    a = X25519PrivateKey.from_private_bytes(alice_priv)
    b = X25519PrivateKey.from_private_bytes(bob_priv)
    # derived public keys match the vector
    assert a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == alice_pub
    assert b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == bob_pub
    # both directions agree and match the published shared secret
    assert a.exchange(X25519PublicKey.from_public_bytes(bob_pub)) == expect
    assert b.exchange(X25519PublicKey.from_public_bytes(alice_pub)) == expect
    # and our wrap-key truncation is the first 16 bytes
    assert wrap_key_from_shared(expect) == expect[:16]


def _check_pairing_roundtrip():
    """Full ECDH -> PairingData build -> parse recovers exactly base+key; tamper is rejected."""
    # Two ephemeral parties stand in for host + controller.
    host_priv, host_pub = gen_host_keypair()
    ctrl_priv, ctrl_pub = gen_host_keypair()
    shared_host = derive_shared_secret(host_priv, ctrl_pub)
    shared_ctrl = ctrl_priv.exchange(X25519PublicKey.from_public_bytes(host_pub))
    assert shared_host == shared_ctrl, "ECDH mismatch"
    wrap = wrap_key_from_shared(shared_host)

    base = bytes.fromhex("deadbeef")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    payload32, iv = build_pairing_payload(wrap, base, key, iv=bytes(range(8)))
    assert len(payload32) == 32 and payload32[:8] == iv

    got_base, got_key = parse_pairing_data(wrap, payload32)
    assert got_base == base, got_base.hex()
    assert got_key == key, got_key.hex()

    # The 0x11 command also frames + round-trips through the SPL framing.
    frame = build_pairing_data(wrap, base, key, iv=bytes(range(8)))
    cmd, _seq, fpayload = unframe_spl(frame)
    assert cmd == CMD_PAIRING_DATA
    assert parse_pairing_data(wrap, fpayload) == (base, key)

    # Corrupted MIC must be rejected.
    bad = bytearray(payload32)
    bad[-1] ^= 0x01
    try:
        parse_pairing_data(wrap, bytes(bad))
        raise AssertionError("corrupted MIC was accepted")
    except ValueError:
        pass
    # Short/long payload must be rejected (mirrors the controller length check).
    try:
        parse_pairing_data(wrap, payload32[:-1])
        raise AssertionError("short payload was accepted")
    except ValueError:
        pass


def _check_setup_x25519_frames():
    """0x12 request carries our pubkey; the response parser recovers the controller pubkey."""
    _ctrl_priv, ctrl_pub = gen_host_keypair()
    _host_priv, host_pub = gen_host_keypair()
    req = build_setup_x25519(host_pub)
    cmd, _seq, payload = unframe_spl(req)
    assert cmd == CMD_SETUP_X25519 and payload == host_pub
    # The controller's reply is an identically framed 0x12 with its own pubkey.
    resp = frame_spl(CMD_SETUP_X25519, ctrl_pub)
    assert parse_setup_x25519_response(resp) == ctrl_pub


def _check_crc_framing():
    """frame -> unframe returns the original payload; a single bit-flip fails CRC."""
    payload = bytes(range(32))
    frame = frame_spl(CMD_PAIRING_DATA, payload, seq=7)
    cmd, seq, got = unframe_spl(frame)
    assert cmd == CMD_PAIRING_DATA and seq == 7 and got == payload

    # Also exercise the SKIPADDR=0 path: CRC over a 5-byte access address + body (Q1).
    addr = bytes.fromhex("0cb0cefa aa".replace(" ", ""))
    framed_a = frame_spl(CMD_PAIRING_DATA, payload, seq=7, addr=addr)
    assert unframe_spl(framed_a, addr=addr)[2] == payload
    # Same bytes verified without the address must fail (address really is folded into the CRC).
    try:
        unframe_spl(framed_a, addr=b"")
        raise AssertionError("addr-covered CRC verified without the address")
    except ValueError:
        pass

    # Flip one payload bit -> CRC must reject.
    corrupt = bytearray(frame)
    corrupt[3] ^= 0x01
    try:
        unframe_spl(bytes(corrupt))
        raise AssertionError("bit-flip passed CRC")
    except ValueError:
        pass
    # Flip a CRC bit -> also rejected.
    corrupt2 = bytearray(frame)
    corrupt2[-1] ^= 0x80
    try:
        unframe_spl(bytes(corrupt2))
        raise AssertionError("corrupted CRC accepted")
    except ValueError:
        pass


def selftest():
    _check_x25519_rfc7748()
    _check_setup_x25519_frames()
    _check_pairing_roundtrip()
    _check_crc_framing()
    print("selftest ok (X25519 RFC 7748 6.1 vector + 0x12/0x11 build/parse + "
          "PairingData round-trip w/ MIC + length reject + CRC/framing round-trip)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
