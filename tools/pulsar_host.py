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
     [u32 LE connected-link base address (our netaddr)][16-byte AES link key]. The CCM wrap key is
     the FIRST 16 bytes of the 32-byte shared secret (plain truncation, no hash). We choose the key.
  3. 0x15 Reset (on-air 0x2a, empty) after a successful PairingData, then stop DM polling; the SPL
     jumps to the app ~500 ms later (REVIEW-RE R6).
  0x14 WriteAESKey is a no-op stub in the controller SPL (Q2) — we never send it.
  SPL reply on air = [LEN][status][seq][data]: match by seq only, status bit 7 = failed (R5).

Connected link (post-pairing), from docs/re/LINK.md as corrected by docs/re/REVIEW-RE.md:
  - build/parse_conn_negotiation : the single accept the host emits to bring a seeking controller
    onto slot S (1..4): [0]=1, [2]=(fmt<<3)|2, 64-bit device id, [11]=S, [12]=IV flag,
    [13]=slot count (REVIEW-RE R1-R3). Endpoint 3 = reject (EP_REJECT), never a "lock".
  - build/parse_beacon_header    : beacon payload bytes 0..15 (channel map, unmapped channel,
    session nonce, 48-bit timestamp, byte-14 downlink bit 1<<S, byte-15 ack bit 1<<S).
  - TL (transport layer, REVIEW-RE R0, CONFIRMED both sides): build_tl_request / build_beacon_tl
    (downlink, beacon byte 16 on) and parse_tl_uplink (decrypted uplink [S][reg][flags][data]).
  - CMD_REGS / describe_reg / check_{read,write}_request : the on-demand command-register namespace
    (reg-id -> operation map, CONFIRMED from symbol-named libsyncboss callers) and its limits.
  - legacy_nonce / steady_state_nonce : the CONFIRMED 13-byte connected-link CCM nonces
    (uplink direction 0, R8; steady counter = beacon periods since the accept, R7).

  pulsar_host.py selftest     run all offline checks (X25519 RFC 7748 vector, pairing round-trip,
                              CRC/framing, accept/beacon/TL literals, command-reg map/limits,
                              CCM nonces, and independent AESCCM vectors); prints "selftest ok ...".
"""
import argparse
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Reuse the vetted CCM + nonce helpers from the decode tool rather than reimplement them.
from pulsar_crypto import aes_ecb, xor, ccm_decrypt, nonce_from_fields

# ---- SPL command IDs (Q2 + AUDIT A5, from SPL dispatcher elk-spl FUN_0000822c) -----------------
# The dispatcher reads the first SPL byte, splits bit0 = read(1)/write(0), and switches on the
# command *number* = (byte >> 1) & 0x3f (elk-spl 0x8230 `ldrb r1,[r0],#2`, 0x823a `ands r7,r1,#1`,
# 0x824a `ubfx r1,r1,#1,#6`). So the NUMBERS below are identifiers; the ON-AIR byte is
# spl_cmd_byte(num, read) = (num << 1) | read_bit.  (AUDIT A5: the earlier tool put the raw number
# on air, which the controller decodes as the wrong command — pairing could not work.)
CMD_SETUP_X25519 = 0x12  # SetupX25519Keys (READ): request carries our 32B pubkey; reply = 32B ctrl pubkey
CMD_PAIRING_DATA = 0x11  # PairingData (WRITE): [IV][CCM(base||key)]
CMD_PAIRING_DATA_DERIVED = 0x1d  # 0x1d (WRITE): derived-key variant (what a real Quest sends first; A7)
CMD_WRITE_AES_KEY = 0x14  # no-op stub in this SPL image — do NOT send
CMD_RESET = 0x15  # Reset (WRITE, empty, on-air 0x2a): sent after a good PairingData (REVIEW-RE R6)

# Which commands are read(1) vs write(0) on air (elk-spl FUN_0000822c branches).
_CMD_IS_READ = {CMD_SETUP_X25519: 1}  # all others here are writes


def spl_cmd_byte(num, read=None):
    """On-air SPL command byte = (num << 1) | read_bit (AUDIT A5). `read` defaults to the known
    direction for `num`. Verified bytes: 0x12->0x25 (read), 0x11->0x22, 0x1d->0x3a, 0x15->0x2a."""
    if read is None:
        read = _CMD_IS_READ.get(num, 0)
    if not (0 <= num <= 0x3f):
        raise ValueError("command number must be 0..0x3f")
    return ((num & 0x3F) << 1) | (1 if read else 0)


def spl_decode_cmd_byte(b):
    """Inverse: return (num, read_bit) from an on-air SPL command byte (ignores bit7)."""
    return (b >> 1) & 0x3F, b & 1

# CCM parameters for the pairing wrap (Q2/Q3): single 0x00 AAD byte, 4-byte MIC, L=2.
PAIR_AAD = b"\x00"
PAIR_MIC_LEN = 4
PAIR_L = 2

# CRC-24 over the pairing/SPL link (Q1: "CRC-24, poly 0x00108421, init 0x00FFFFFF"). CONFIRMED by
# the register writes (AUDIT A9): host PHY init FUN_0001b61c writes CRCINIT = 0x00FFFFFF at 0x1b74a,
# CRCCNF = 3 (LEN 3, SKIPADDR 0) at 0x1b752 and CRCPOLY = 0x108421 (pool 0x1b958); the controller
# does the same at 0x25694..0x256a4. (The older "literal" citations syncboss 0x52034/0x520a8 and
# elk-app 0x316fc/0x31770 are entries T[1]/T[30] of the CRC lookup tables, not writes; AUDIT A11.)
CRC24_POLY = 0x00108421
CRC24_INIT = 0x00FFFFFF


# ---- CRC-24 ------------------------------------------------------------------------------------

def crc24(data, poly=CRC24_POLY, init=CRC24_INIT):
    """nRF-style bit-serial CRC-24 (implicit x^24 term; poly bits = x^20,x^15,x^10,x^5,x^0).

    MSB-first per byte, as the controller's software re-check does (elk-app FUN_00022ab8, an
    MSB-first table for poly 0x108421; AUDIT A9). This is the right feed for S0/LENGTH/payload. The
    access address (CRCCNF SKIPADDR=0) goes in bit-reversed: use crc24_air, which frame_spl /
    unframe_spl call when given `addr`. The on-air order of the 3 CRC bytes is still INFERRED.
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


def _bitrev8(b):
    return int(f"{b & 0xFF:08b}"[::-1], 2)


def crc24_air(base_le4, prefix, data):
    """On-air CRC-24 the way the nRF radio computes it over the access address (AUDIT A9).

    The controller's software re-check (elk-app FUN_00024164 → FUN_00022ab8, MSB-first table for
    poly 0x108421) feeds the address LSbit-first: bit-reverse each of the 4 base bytes (little-endian)
    and the prefix byte, then append S0/LENGTH/payload UNREVERSED (`data`). The earlier selftest fed
    the raw address bytes, which does not match the firmware; bit-reversing the five address bytes
    makes it match exactly. `data` = the on-air body (S0 if present, LENGTH, payload)."""
    if len(base_le4) != 4:
        raise ValueError("base must be 4 bytes (little-endian, as written to BASEn)")
    addr = bytes(_bitrev8(x) for x in bytes(base_le4)) + bytes([_bitrev8(prefix)])
    return crc24(addr + bytes(data))


# ---- SPL command framing (Q1 packet layout + Q2 command header) --------------------------------
# Seq rule (REVIEW-RE R5/R15): increment per new command, wrapping 255 -> 1 (never 0); a resend
# uses the same seq. The SPL keeps the last seq (initially 0) and treats a repeated seq as a
# retransmit: it re-sends its old reply and does NOT execute the command. So the first frame after
# link start must not use seq 0; every seq default below is 1.
SPL_SEQ_FIRST = 1


def spl_next_seq(seq):
    """Next SPL seq: +1, wrapping 255 -> 1 (0 is never used, R15)."""
    return seq + 1 if 0 < seq < 0xFF else 1


def _spl_crc(addr, hdr):
    """CRC-24 over LENGTH+body, with the 5-byte access address (base LE4 + prefix) folded in the
    on-air way (crc24_air, AUDIT A9) when given; empty `addr` = body only (offline framing)."""
    addr = bytes(addr)
    if not addr:
        return crc24(hdr)
    if len(addr) != 5:
        raise ValueError("addr must be 5 bytes: base (4, little-endian) + prefix")
    return crc24_air(addr[:4], addr[4], hdr)


def frame_spl(cmd_byte, payload, seq=SPL_SEQ_FIRST, addr=b""):
    """Build one SPL/pairing frame: [LENGTH][cmd_byte][seq][payload...][CRC-24, 3 bytes LE].

    `cmd_byte` is the ON-AIR command byte already encoded as (num<<1)|read (use spl_cmd_byte()).
    LENGTH (nRF LFLEN=8, S0LEN=0 for the pairing link, Q1) counts the on-air payload = the SPL
    body (cmd_byte + seq + payload), not itself and not the CRC. CRC-24 is computed over LENGTH+body
    and, on air, the preceding access address (SKIPADDR=0): pass `addr` = base LE4 + prefix and it
    is fed bit-reversed via crc24_air (AUDIT A9). See spl_next_seq for the seq rule (R15).
    """
    body = bytes([cmd_byte & 0xFF, seq & 0xFF]) + bytes(payload)
    if len(body) > 0xFF:
        raise ValueError("SPL body exceeds 255-byte LENGTH field")
    hdr = bytes([len(body)]) + body
    crc = _spl_crc(addr, hdr)
    return hdr + crc.to_bytes(3, "little")


def unframe_spl(frame, addr=b""):
    """Inverse of frame_spl. Returns (byte0, seq, payload): byte0 = the cmd byte of a request, or
    the status byte of a reply (see parse_spl_reply). Raises on short frame or CRC mismatch."""
    if len(frame) < 1 + 2 + 3:
        raise ValueError("frame too short")
    length = frame[0]
    body = frame[1:1 + length]
    if len(body) != length or len(frame) < 1 + length + 3:
        raise ValueError("truncated frame (LENGTH says more bytes than present)")
    crc_bytes = frame[1 + length:1 + length + 3]
    want = _spl_crc(addr, frame[:1 + length]).to_bytes(3, "little")
    if crc_bytes != want:
        raise ValueError(f"CRC mismatch: got {crc_bytes.hex()} want {want.hex()}")
    return body[0], body[1], body[2:]


SPL_STATUS_FAILED = 0x80  # reply status bit 7 = the handler returned failure (R5)


def parse_spl_reply(frame, addr=b"", seq=None):
    """Parse an SPL reply [LEN][status][seq][data] (REVIEW-RE R5, elk-spl FUN_0000822c tail).

    status bit 7 = command failed; bit 0 = 0 (1 only on the unsolicited-reply path 0x86f0); bits
    1..6 are stale (advert byte / earlier poll), NOT the command number, so they are never checked.
    Match replies by seq only: pass the request's `seq` to enforce it. Returns dict(status, failed,
    seq, data, unsolicited); the caller decides what a failure means."""
    status, rseq, data = unframe_spl(frame, addr=addr)
    if seq is not None and rseq != (seq & 0xFF):
        raise ValueError(f"reply seq {rseq} != request seq {seq & 0xFF}")
    return {"status": status, "failed": bool(status & SPL_STATUS_FAILED), "seq": rseq,
            "data": bytes(data), "unsolicited": bool(status & 1)}


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


def build_setup_x25519(host_pub32, seq=SPL_SEQ_FIRST, addr=b""):
    """SetupX25519Keys request carrying our 32-byte public key. On-air cmd byte = 0x25
    (num 0x12, read=1 — AUDIT A5: FUN_00003948 copies the 32B host pubkey from this read request)."""
    if len(host_pub32) != 32:
        raise ValueError("host public key must be 32 bytes")
    return frame_spl(spl_cmd_byte(CMD_SETUP_X25519), host_pub32, seq=seq, addr=addr)


def parse_setup_x25519_response(frame, addr=b"", seq=None):
    """Parse the controller's SetupX25519 reply; return its 32-byte public key.

    Reply = [LEN=0x22][status][seq][32-byte controller pubkey] (REVIEW-RE R5). Raises if status
    bit 7 (failed) is set or, when `seq` is given, if the reply seq differs. Status bits 1..6 are
    stale and are not checked."""
    r = parse_spl_reply(frame, addr=addr, seq=seq)
    if r["failed"]:
        raise ValueError(f"SetupX25519 failed (status {r['status']:#04x}, bit 7 set)")
    payload = r["data"]
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

def netaddr_bytes(netaddr):
    """PairingData base address = struct.pack("<I", netaddr) (AUDIT A16: the host stores a native
    u32, i.e. little-endian). 4 already-packed bytes pass through unchanged. R14: netaddr 0 trips
    the controller app's `init->address` assert and 0xFFFFFFFF reads as "no pairing info"."""
    if isinstance(netaddr, int):
        if not 0 <= netaddr <= 0xFFFFFFFF:
            raise ValueError("netaddr must be a u32")
        return struct.pack("<I", netaddr)
    if len(netaddr) != 4:
        raise ValueError("base address must be a u32 or 4 packed bytes")
    return bytes(netaddr)


def build_pairing_payload(wrap_key, netaddr, link_key_16b, iv=None):
    """Build the 32-byte 0x11 on-wire payload: [8-byte clear IV][CCM(base||key) = 24 bytes].

    Plaintext (20 bytes) = [u32 LE netaddr = connected-link base address][16-byte AES link key]
    (Q2, AUDIT A16). `netaddr` is an int, packed "<I"; 4 already-packed bytes are also accepted.
    CCM uses the pairing nonce = packet counter 0 with this random 8-byte IV (Q2/Q3).
    Returns (payload32, iv).
    """
    if len(wrap_key) != 16:
        raise ValueError("wrap key must be 16 bytes")
    base_addr_4b = netaddr_bytes(netaddr)
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


def build_pairing_data(wrap_key, netaddr, link_key_16b, iv=None, seq=SPL_SEQ_FIRST, addr=b"",
                       num=CMD_PAIRING_DATA):
    """PairingData write command: builds the 32-byte payload then frames it. On-air cmd byte = 0x22
    (num 0x11, write — AUDIT A5). Pass num=CMD_PAIRING_DATA_DERIVED (0x1d -> 0x3a) for the
    derived-key variant a real Quest uses first (A7); we use 0x11 so we choose the key.
    A failed PairingData (reply status bit 7) still wipes the SPL's keys (R15): redo 0x25 before
    retrying. On success, send build_spl_reset next (R6)."""
    payload32, _iv = build_pairing_payload(wrap_key, netaddr, link_key_16b, iv=iv)
    return frame_spl(spl_cmd_byte(num), payload32, seq=seq, addr=addr)


def build_spl_reset(seq, addr=b""):
    """Reset write (cmd 0x15, on-air 0x2a, empty payload): [2][0x2a][seq] + CRC (REVIEW-RE R6).

    The real host (sb input_pair 0x6663c) sends it after a successful PairingData reply (status
    bit 7 clear), waits for its reply (or polls ~10 ms), then stops DM polling and starts
    beaconing. The SPL validates the app image and jumps to it ~500 ms later; the app then seeks
    (R10). `seq` = spl_next_seq(the PairingData seq)."""
    return frame_spl(spl_cmd_byte(CMD_RESET), b"", seq=seq, addr=addr)


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


# ================================================================================================
# Connected link (post-pairing). See docs/re/LINK.md. Everything below is OFFLINE byte
# construction/parsing only — no radio. Tags CONFIRMED/INFERRED mirror LINK.md.
# ================================================================================================

# ---- Connected-link endpoints (CONFIRMED both sides, REVIEW-RE R1/R2) --------------------------
# Accept [2] & 7 (elk 0x23b18 / 0x23b64; host FUN_0001d038 writes (fmt<<3)|2 or |3):
EP_CONN_NEG = 2  # accept: the controller takes slot [11] and goes connected
EP_REJECT = 3    # reject: the controller goes back to idle (redraws its IV). NOT a "lock" (R2).
CONN_PKT_TYPE = 1  # accept handler requires connection packet [0] == 1
CONN_FMT_TOUCH_PLUS = 2  # the request's [1] >> 3 (0x11 >> 3) for a Touch Plus
# Protocol version 0x1701 (on-air 01 17) lives in the controller's REQUEST bytes 10..11 (AUDIT A14),
# never in the accept (R3).
PULSAR_VERSION = 0x1701

# ONE slot number S (REVIEW-RE R1/R4, CONFIRMED both sides; the old slot/endpoint split is gone):
#   accept [11] = S | controller TX prefix (host RX pipe) = S+1 | beacon byte 14 downlink bit and
#   byte 15 ack bit = 1 << S | uplink CL[0] = S.
# S is 1..4. Slot 0 is the negotiation slot only (seeking controllers TX on prefix 1 and send
# CL[0] = 0); an accept with [11] = 0 trips the controller's fatal
# `accept_pkt->endpoint != CONN_NEG_SLOT` assert (elk 0x23b22). FUN_00028ad0 bounds S <= 4.
CONN_NEG_SLOT = 0
SLOT_MIN = 1
SLOT_MAX = 4


def _check_slot(slot):
    if not (SLOT_MIN <= slot <= SLOT_MAX):
        raise ValueError(f"slot S must be {SLOT_MIN}..{SLOT_MAX} (0 = negotiation slot only, R1)")
    return slot


def slot_bit(slot):
    """Beacon byte-14 downlink bit / byte-15 ack bit for slot S = 1 << S (R4)."""
    return 1 << _check_slot(slot)


def device_tx_prefix(slot):
    """Uplink radio prefix a device in slot S transmits on = S + 1 (elk FUN_00028ad0 0x28afc,
    CONFIRMED). Connected slots 1..4 -> prefixes 2..5; CONN_NEG_SLOT (0) -> prefix 1 (seek)."""
    if not (CONN_NEG_SLOT <= slot <= SLOT_MAX):
        raise ValueError(f"slot must be {CONN_NEG_SLOT}..{SLOT_MAX}")
    return slot + 1


# ---- Command-register map (CONFIRMED from symbol-named libsyncboss callers; see LINK.md §3) -----
# The on-demand command-register namespace (request/response), DISTINCT from the streaming-input
# hreg space (buttons/analog/IMU) in PROTOCOL Q4. 'R'/'W'/'RW' is the access seen in libsyncboss.
CMD_REGS = {
    0x05: ("W", "shutdown"),
    0x06: ("W", "sleep/wake"),
    0x0B: ("R", "platform_attachment_info"),
    0x0C: ("RW", "platform_attachment_auth"),
    0x13: ("W", "unpair"),
    0x19: ("W", "console_cmd"),
    0x1A: ("W", "console_cmd"),
    0x1C: ("W", "set_carrier"),
    0x28: ("R", "get_led_config"),        # also written (12 B {p, ot, d}) to set it (REVIEW-RE R16)
    0x2B: ("R", "get_calibration_data"),  # request = {u32 offset, u32 len} (8 B), no 'type' (R16)
    0x2F: ("R", "get_battery_voltage"),
    0x33: ("R", "get_imu_temp"),
    0x34: ("R", "get_assert_info"),
    0x38: ("R", "get_backtrace"),
    0x3F: ("R", "get_build_hash"),
    0x4C: ("RW", "thumbstick_user_calibration"),
    0x4E: ("W", "clear_thumbstick_user_calibration"),
    0x4F: ("RW", "thumbstick_user_deadband_percentage"),
    0x50: ("RW", "adc_stream_enable"),
    0x53: ("RW", "battery_pack / set_battery_pack_pollrate"),
    0x9F: ("W", "imu_integration_uplink"),
    0xAB: ("R", "hid_report_descriptor"),
    0xAC: ("RW", "hid_feature_report"),
    0xB4: ("W", "stream_rf_perf"),
}

# Transport limits (CONFIRMED, libsyncboss pulsar_{read,write}_nolock asserts).
SPI_DATA_HDR_LEN = 0x14   # sizeof(spi_data_pulsar_data_t): 20-byte Android->MCU header
READ_REQ_MAX = 0xEB       # read: in_len <= 235 (sizeof(*pdata)+in_len <= WIRELESS_MAX_PAYLOAD_SIZE)
WRITE_LEN_MAX = 0xFF - SPI_DATA_HDR_LEN  # write: 0x14 + len <= 0xFF


def describe_reg(reg_id):
    """Return 'ACCESS name' for a command register id, or 'unknown' (CONFIRMED map)."""
    acc, name = CMD_REGS.get(reg_id, (None, None))
    return f"{acc} {name}" if name else "unknown"


def check_read_request(reg_id, in_len):
    """Validate a command-register READ request against the CONFIRMED transport limits.

    These are the Android->MCU (libsyncboss) limits; the on-air TL packet is smaller (payload
    <= 32 B per beacon, REVIEW-RE R0) and is built by build_tl_request."""
    if not (0 <= reg_id <= 0xFF):
        raise ValueError("reg_id out of range")
    if not (0 <= in_len <= READ_REQ_MAX):
        raise ValueError(f"read request in_len must be 0..{READ_REQ_MAX}")
    return True


def check_write_request(reg_id, length):
    """Validate a command-register WRITE request length (CONFIRMED transport limit)."""
    if not (0 <= reg_id <= 0xFF):
        raise ValueError("reg_id out of range")
    if not (0 <= length <= WRITE_LEN_MAX):
        raise ValueError(f"write length must be 0..{WRITE_LEN_MAX}")
    return True


# ---- Connection-negotiation accept (host -> device, REVIEW-RE R1-R3, CONFIRMED both sides) -----
# The host emits this in the beacon CL-data area to bring a seeking controller onto slot S. ONE
# packet; there is no follow-up "lock" (R2). Device reads (elk 0x23af8..0x23b3e): [0] type,
# [2]&7 endpoint, [3..10] device id vs its own, [11] S (must be != 0), [12] IV flag (0 = zero the
# steady IV, i.e. stay on the legacy nonce), [13] slot count (< 1 -> 1; sets the uplink budget
# 0x34 + 0x47*(n-1)). [1] is host +0x75, not read by the device. The rest of the 26-byte body
# is not read; we build the 14 bytes that matter.
CONN_NEG_PKT_LEN = 14  # [0..13]


def build_conn_negotiation(device_id_64, slot, fmt=CONN_FMT_TOUCH_PLUS, steady_iv=None,
                           slot_count=1, reject=False):
    """Build the connection accept (or, with reject=True, the refusal) the host transmits.

    device_id_64 : the controller's 64-bit device ID (from its connection request / advertisement).
    slot         : S, 1..4 (R1; 0 is the negotiation slot and is fatal in an accept).
    fmt          : the request's [1] >> 3 (parse_conn_request()["format"]; 2 for Touch Plus).
    steady_iv    : the 8-byte IV from the request (bytes 15..22), or None. [12] = 1 iff non-zero (R3).
    slot_count   : [13] (R3). The host honors only 1 or 2; Touch Plus uses 1.
    reject       : [2] = (fmt<<3)|EP_REJECT instead of |EP_CONN_NEG (sends the controller to idle).
    Returns 14 bytes: [1][0][(fmt<<3)|2][id:8 LE][S][iv flag][slot count]. No version (R3).
    """
    _check_slot(slot)
    if not 0 <= fmt <= 0x1F:
        raise ValueError("fmt must fit in bits 3..7")
    if slot_count not in (1, 2):
        raise ValueError("slot_count must be 1 or 2 (the host honors no other value)")
    pkt = bytearray(CONN_NEG_PKT_LEN)
    pkt[0] = CONN_PKT_TYPE
    pkt[1] = 0                                   # host +0x75, not read by the device
    pkt[2] = (fmt << 3) | (EP_REJECT if reject else EP_CONN_NEG)
    pkt[3:11] = int(device_id_64).to_bytes(8, "little")
    pkt[11] = slot
    pkt[12] = 1 if steady_iv is not None and any(bytes(steady_iv)) else 0
    pkt[13] = slot_count
    return bytes(pkt)


def build_conn_accept(request, slot):
    """The accept for a parsed connection request (parse_conn_request output) on slot S."""
    return build_conn_negotiation(request["device_id"], slot, fmt=request["format"],
                                  steady_iv=request["steady_iv"])


def parse_conn_negotiation(pkt):
    """Parse/validate an accept/reject by the CONFIRMED device rules.

    Returns dict(type, fmt, endpoint, reject, device_id, slot, iv_flag, slot_count). Raises if the
    controller would drop it (wrong type, endpoint not 2/3) or assert on it (an accept with S
    outside 1..4). slot_count is the value the device uses (< 1 -> 1)."""
    if len(pkt) < CONN_NEG_PKT_LEN:
        raise ValueError("connection packet too short")
    typ = pkt[0]
    endpoint = pkt[2] & 0x07
    device_id = int.from_bytes(pkt[3:11], "little")
    slot = pkt[11]
    if typ != CONN_PKT_TYPE:
        raise ValueError(f"connection packet type {typ} != {CONN_PKT_TYPE} (would be rejected)")
    if endpoint not in (EP_CONN_NEG, EP_REJECT):
        raise ValueError(f"endpoint {endpoint} not CONN_NEG(2)/REJECT(3) (ignored by the device)")
    if endpoint == EP_CONN_NEG and not (SLOT_MIN <= slot <= SLOT_MAX):
        raise ValueError(f"accept slot {slot} outside {SLOT_MIN}..{SLOT_MAX} (controller asserts)")
    return {"type": typ, "fmt": pkt[2] >> 3, "endpoint": endpoint,
            "reject": endpoint == EP_REJECT, "device_id": device_id, "slot": slot,
            "iv_flag": pkt[12], "slot_count": max(pkt[13], 1)}


# ---- Connection REQUEST (device -> host, uplink) — carries the steady IV (AUDIT A3) ------------
# The controller's connection request CL payload (elk-app 0x23bc4..0x23c22, LENGTH 0x19 = 25),
# as the host parses it in FUN_0001d038. It is a CCM UPLINK, so the host first decrypts it with the
# negotiation nonce (legacy_nonce(), A2) using the link key, THEN parses this plaintext. Byte 0 == 0
# (the host takes the request path only when [0]==0; this is NOT the host's [0]==1 response). The
# 8-byte steady-state IV at bytes 15..22 is the key output: the host stores it per slot and uses it
# with the per-slot counter (beacon periods since the accept, R7) for all later uplinks (A3/A4).
# The request is CL[0] == 0 on the negotiation slot; connected uplinks carry CL[0] = S (R4).
CONN_REQ_LEN = 25


def parse_conn_request(pt):
    """Parse the decrypted connection-request CL payload (device -> host). Returns dict with
    device_id (64-bit), version, slot_count, and steady_iv (8 bytes, bytes 15..22)."""
    if len(pt) < 23:
        raise ValueError("connection request too short (need >= 23 bytes for the IV)")
    if pt[0] != 0:
        raise ValueError("connection request byte 0 must be 0 (else it is not a request)")
    fmt = pt[1] >> 3  # non-zero => the extended fields (0x0e..0x18) are present
    return {
        "format": fmt,
        "device_id": int.from_bytes(pt[2:10], "little"),
        "version": int.from_bytes(pt[10:12], "little"),
        "slot_count": pt[14] if fmt else None,
        "steady_iv": bytes(pt[15:23]) if fmt else None,
    }


# ---- Notification wrapper (device -> host) — strip to the chunk stream (LINK.md §3) -------------
NTF_HEADER_LEN = 0x14  # host<->MCU wrapper, same size as spi_data_pulsar_data_t; byte 0x13 == 0


def split_notification(buf, sidechannel_len=0):
    """Strip the 0x14-byte notification wrapper (+ optional sidechannel chunk) and return
    (chunk_stream, sidechannel_bytes). The chunk stream is then fed to
    pulsar_input.unpack_chunks (RE-2). `sidechannel_len` is sidechannel_client_get_chunk_size()
    from the session (0 = no sidechannel). CONFIRMED gate: len >= 0x14 and byte 0x13 == 0
    (libsyncboss controller_process_notification @ 0x57324)."""
    if len(buf) < NTF_HEADER_LEN:
        raise ValueError("notification shorter than the 0x14-byte header")
    if buf[0x13] != 0:
        raise ValueError("notification header byte 0x13 must be 0")
    sc = bytes(buf[NTF_HEADER_LEN:NTF_HEADER_LEN + sidechannel_len])
    chunk_stream = bytes(buf[NTF_HEADER_LEN + sidechannel_len:])
    return chunk_stream, sc


# ---- Beacon header (host -> all; CONFIRMED layout, PROTOCOL Q1 + LINK.md §4 + REVIEW-RE R4) ----
def build_beacon_header(channel_map_37, unmapped, session_nonce, timestamp_us,
                        downlink_slot=None, ack_bitmap=0):
    """Build beacon payload bytes 0..15 (the CL header; the <=34-byte TL packet follows at 16).

    channel_map_37 : 37-bit active-channel bitmap (LSB = logical channel 0). Keep indices 0/17/36
                     in it: they are the controller's seek channels (REVIEW-RE R10).
    unmapped       : current unmapped-channel value 0..36 (byte 5).
    session_nonce  : 16-bit value (bytes 6..7).
    timestamp_us   : 48-bit beacon timestamp on the sync clock (bytes 8..13, little-endian).
    downlink_slot  : slot S (1..4) addressed by the TL packet in this beacon -> byte 14 = 1<<S,
                     else 0 (idle / broadcast). One number S for everything (R4).
    ack_bitmap     : byte 15 = ack bits 1<<S of the slots heard since the last beacon
                     (OR of slot_bit(S)).

    Byte 0 bits 1..2 (periods-until-DM-beacon) and bit 0 (reserved) are left 0 here. Returns the
    16-byte header; LENGTH on air = 14 + len(CL data) (the caller appends the TL packet, or use
    build_beacon)."""
    if not (0 <= channel_map_37 < (1 << 37)):
        raise ValueError("channel map must be a 37-bit value")
    if not (0 <= unmapped <= 36):
        raise ValueError("unmapped must be 0..36")
    if not (0 <= session_nonce <= 0xFFFF):
        raise ValueError("session_nonce must be 16-bit")
    if not (0 <= timestamp_us < (1 << 48)):
        raise ValueError("timestamp must be a 48-bit value")
    b = bytearray(14)
    # byte 0 bits3..7 = map bits 0..4; bytes 1..4 = map bits 5..36 (37-bit map, LSB first).
    b[0] = (channel_map_37 & 0x1F) << 3
    b[1] = (channel_map_37 >> 5) & 0xFF
    b[2] = (channel_map_37 >> 13) & 0xFF
    b[3] = (channel_map_37 >> 21) & 0xFF
    b[4] = (channel_map_37 >> 29) & 0xFF   # byte4 bits3..7 = map bits 32..36
    b[5] = unmapped
    b[6:8] = session_nonce.to_bytes(2, "little")
    b[8:14] = timestamp_us.to_bytes(6, "little")
    return bytes(b) + build_beacon_tl(downlink_slot, b"", ack_bitmap)


def parse_beacon_header(b):
    """Inverse of build_beacon_header. Returns dict of the 16-byte header fields, plus the TL
    packet at bytes 16.. (`tl_packet`, b"" if none)."""
    if len(b) < 16:
        raise ValueError("beacon header too short")
    channel_map = ((b[0] >> 3) & 0x1F) | (b[1] << 5) | (b[2] << 13) | (b[3] << 21) | (b[4] << 29)
    downlink = b[14]
    downlink_slot = (downlink.bit_length() - 1) if downlink else None
    return {
        "channel_map": channel_map & ((1 << 37) - 1),
        "dm_periods": (b[0] >> 1) & 0x3,
        "unmapped": b[5],
        "session_nonce": int.from_bytes(b[6:8], "little"),
        "timestamp_us": int.from_bytes(b[8:14], "little"),
        "downlink_slot": downlink_slot,
        "ack_bitmap": b[15],
        "ack_slots": [s for s in range(SLOT_MIN, SLOT_MAX + 1) if b[15] >> s & 1],
        "tl_packet": bytes(b[16:]),
    }


# ---- TL: register read / write / response / notification (REVIEW-RE R0, CONFIRMED both sides) --
# Host: syncboss pulsar_tl_host.c (0x19acc..0x1a220). Controller: elk TL state machine T=0x200051e8.
#
#   downlink (plaintext) : beacon payload [0..13 header][14 = 1<<S][15 = ack mask][16.. TL packet]
#   uplink (decrypted)   : [S][TL packet]          (CL[0] == 0 is a connection request, not TL)
#   TL packet            : [reg][flags][payload]   payload <= 32 B (TL packet <= 34 B)
#   flags                : bits 0..3 seq, bit 4 READ (1) / write (0), bit 5 error (responses),
#                          bit 6 notification (uplink only), bit 7 unused (0)
#
# Exchange rules:
#  - Host request [reg][seq | 0x10 if read][payload], addressed with byte 14 = 1<<S. The host bumps
#    seq per NEW command (+1, 15 wraps to 0; starts at 0) and repeats the SAME packet in every
#    beacon until it is answered or times out (timeout in beacon periods, >= 1). The controller
#    treats a packet with the same (seq, reg, read bit) as the last as a retransmit: it re-sends
#    its last response and does not execute again. So a repeat of the same command needs a new seq.
#  - Read: always answered with [reg][ack_seq | 0x10 | err<<5][data] (build_tl_read_response).
#  - Write: NO response on success. It is acked when ANY later uplink from that controller (e.g.
#    the next notification) carries its seq in bits 0..3. A failed write gets [reg][seq | 0x20].
#  - Response check (host): pkt[0] == the request reg and bits 0..3 == the current seq.
#  - Notifications: [0x00][ack_seq | 0x40][ntf chunk stream] (pulsar_input.NtfUnpacker), filled
#    up to the uplink budget 0x34 + 0x47*(slots-1) = 52 B for one slot (incl. the [S] byte).
#  - Reg 0x2a ('*') in either direction is the RF-performance stats channel: ignore it.
#  - Idle host beacon: TL [0x00][seq] with byte 14 = 0 (build_tl_idle). INFERRED optional for the
#    controller (a byte-14 = 0 packet goes to its broadcast handler, not the command path).
TL_SEQ_MASK = 0x0F
TL_READ = 0x10
TL_ERR = 0x20
TL_NTF = 0x40
TL_PAYLOAD_MAX = 32
TL_REG_NTF = 0x00       # notification register: chunk stream
TL_REG_RF_STATS = 0x2A  # RF-performance stats: ignore
UPLINK_BUDGET_1SLOT = 0x34  # 52 B uplink CL payload for slot count 1: [S] + TL packet


def tl_next_seq(seq):
    """Host TL seq: +1 per new command, 15 wraps to 0 (syncboss FUN_0001a708)."""
    return (seq + 1) & TL_SEQ_MASK


def build_tl_request(reg, seq, read, payload=b""):
    """Host -> controller TL packet [reg][(seq & 15) | 0x10 if read][payload <= 32] (R0)."""
    payload = bytes(payload)
    if not 0 <= reg <= 0xFF:
        raise ValueError("reg must be 0..255")
    if not 0 <= seq <= TL_SEQ_MASK:
        raise ValueError("TL seq must be 0..15")
    if len(payload) > TL_PAYLOAD_MAX:
        raise ValueError(f"TL payload must be <= {TL_PAYLOAD_MAX} bytes (syncboss asserts)")
    return bytes([reg, (seq & TL_SEQ_MASK) | (TL_READ if read else 0)]) + payload


def build_tl_idle(seq):
    """Idle host TL packet [0x00][seq] (sent with byte 14 = 0; INFERRED optional, R0 rule 2)."""
    return bytes([0x00, seq & TL_SEQ_MASK])


def build_beacon_tl(slot, tl_packet, ack_bitmap=0):
    """Beacon payload bytes 14.. : [1<<S (0 if slot is None)][ack mask][TL packet] (R0/R4).

    The controller hands CL+2 (beacon byte 16 on, length LEN-2) to its TL when bit S is set or
    byte 14 = 0 (only the first counts as addressed)."""
    tl_packet = bytes(tl_packet)
    if len(tl_packet) > 2 + TL_PAYLOAD_MAX:
        raise ValueError("TL packet must be <= 34 bytes")
    b14 = 0 if slot is None else slot_bit(slot)
    return bytes([b14, ack_bitmap & 0xFF]) + tl_packet


def build_beacon(channel_map_37, unmapped, session_nonce, timestamp_us, slot=None, tl_packet=b"",
                 ack_bitmap=0):
    """Whole beacon payload: header bytes 0..13 + build_beacon_tl(slot, tl_packet, ack_bitmap)."""
    hdr = build_beacon_header(channel_map_37, unmapped, session_nonce, timestamp_us)[:14]
    return hdr + build_beacon_tl(slot, tl_packet, ack_bitmap)


def parse_tl_uplink(plaintext):
    """Parse a decrypted connected uplink [S][reg][flags][data] (R0/R4).

    Returns dict(slot, reg, seq, read, err, ntf, data, rf_stats), or None when CL[0] == 0 (a
    connection request: use parse_conn_request). `rf_stats` marks reg 0x2a, which a host ignores.
    A notification is reg 0 with ntf=True; its data is the chunk stream."""
    p = bytes(plaintext)
    if not p or p[0] == CONN_NEG_SLOT:
        return None
    if len(p) < 3:
        raise ValueError("TL uplink too short: need [S][reg][flags]")
    flags = p[2]
    return {"slot": p[0], "reg": p[1], "seq": flags & TL_SEQ_MASK, "read": bool(flags & TL_READ),
            "err": bool(flags & TL_ERR), "ntf": bool(flags & TL_NTF), "data": p[3:],
            "rf_stats": p[1] == TL_REG_RF_STATS}


def build_tl_read_response(slot, reg, ack_seq, data, err=False):
    """Controller read response (uplink plaintext): [S][reg][ack_seq | 0x10 | err<<5][data]."""
    _check_slot(slot)
    return bytes([slot, reg, (ack_seq & TL_SEQ_MASK) | TL_READ | (TL_ERR if err else 0)]) + bytes(data)


def build_tl_notification(slot, ack_seq, chunks):
    """Controller notification (uplink plaintext): [S][0x00][0x40 | ack_seq][chunk stream]."""
    _check_slot(slot)
    out = bytes([slot, TL_REG_NTF, TL_NTF | (ack_seq & TL_SEQ_MASK)]) + bytes(chunks)
    if len(out) > UPLINK_BUDGET_1SLOT:
        raise ValueError(f"notification exceeds the {UPLINK_BUDGET_1SLOT}-byte one-slot uplink budget")
    return out


def build_tl_write_error(slot, reg, ack_seq):
    """Controller response to a FAILED write: [S][reg][ack_seq | 0x20]. A good write sends none."""
    _check_slot(slot)
    return bytes([slot, reg, (ack_seq & TL_SEQ_MASK) | TL_ERR])


def tl_completes(uplink, reg, seq, read):
    """Does parsed uplink `uplink` (parse_tl_uplink) complete the pending request (reg, seq, read)?

    Returns None (still pending) or dict(err, data). A read completes on its response (same reg,
    same seq, read bit, not a notification). A write completes on ANY uplink carrying its seq (an
    implicit ack, err = False), or on an explicit [reg][seq | 0x20] error response."""
    if uplink is None or uplink["rf_stats"] or uplink["seq"] != (seq & TL_SEQ_MASK):
        return None
    if read:
        if uplink["ntf"] or not uplink["read"] or uplink["reg"] != reg:
            return None
        return {"err": uplink["err"], "data": uplink["data"]}
    if not uplink["ntf"] and uplink["reg"] == reg and uplink["err"]:
        return {"err": True, "data": b""}
    return {"err": False, "data": b""}


# ---- CCM nonces (host as producer/consumer, LINK.md §2; AUDIT A2/A3/A4; REVIEW-RE R7/R8) --------
# CCM is UPLINK ONLY (A4): beacons and host downlink are plaintext, so the host only *decrypts*
# device uplinks. The direction bit (nonce bit 39) is never written in any image, so it is
# always 0 (AUDIT A17, REVIEW-RE R8). Two nonce regimes, both CONFIRMED:

def legacy_nonce(session_nonce, beacon_ts48):
    """Negotiation ("legacy") nonce (AUDIT A2, CONFIRMED both sides: host FUN_0001aba8, elk
    0x24092..0x240d6). counter = 0; IV(8) = (session_nonce << 48 | beacon_ts48) as u64 little-endian.
    13-byte nonce = 00 00 00 00 00 ‖ ts[0..5] LE ‖ session_nonce LE. Derived entirely from the
    beacon (session nonce = beacon bytes 6..7, ts48 = bytes 8..13), so no IV is on air. The host
    uses this to decrypt the controller's FIRST uplink (its connection request). After missed
    beacons the controller uses ts + missed*2000 (elk LL+0x280), so pass that ts."""
    if not (0 <= session_nonce <= 0xFFFF):
        raise ValueError("session_nonce must be 16-bit")
    if not (0 <= beacon_ts48 < (1 << 48)):
        raise ValueError("beacon_ts48 must be a 48-bit value")
    iv = ((session_nonce << 48) | beacon_ts48).to_bytes(8, "little")
    return nonce_from_fields(counter=0, direction=0, iv=iv)


def steady_state_nonce(counter, iv, direction=0):
    """Steady-state nonce (AUDIT A3): 13-byte = PACKETCOUNTER[5 LE, incl. direction bit 39] || IV[8].

    `iv` = the 8 bytes the controller sent at connection-request bytes 15..22 (parse_conn_request;
    elk record +0x68), CONFIRMED (A3). `counter` = the number of BEACON PERIODS since the accept
    (REVIEW-RE R7: elk LL+0x1b8 reset at the accept and bumped per period, plus skipped periods;
    the host bumps all five per-slot counters together each period). It advances whether or not a
    period carried an uplink; the exact start period (off-by-one at the accept) needs one live MIC.
    direction defaults to 0 (R8: nothing ever writes cfg+0x128). CCM field layout CONFIRMED
    (syncboss FUN_0001b1a4: counter@cfg+0x120 5B, direction@+0x128, IV@+0x129 8B)."""
    if len(iv) != 8:
        raise ValueError("iv must be 8 bytes")
    return nonce_from_fields(counter=counter, direction=direction, iv=bytes(iv))


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

    netaddr = 0xDEADBEEF
    base = bytes.fromhex("efbeadde")             # u32 LE on air (AUDIT A16)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    payload32, iv = build_pairing_payload(wrap, netaddr, key, iv=bytes(range(8)))
    assert len(payload32) == 32 and payload32[:8] == iv
    # the 4-byte packed fallback gives the same bytes
    assert build_pairing_payload(wrap, base, key, iv=bytes(range(8)))[0] == payload32

    got_base, got_key = parse_pairing_data(wrap, payload32)
    assert got_base == base, got_base.hex()
    assert got_key == key, got_key.hex()

    # The PairingData command also frames + round-trips through the SPL framing; on-air byte 0x22.
    frame = build_pairing_data(wrap, netaddr, key, iv=bytes(range(8)))
    cmd_byte, seq, fpayload = unframe_spl(frame)
    assert cmd_byte == 0x22 and spl_decode_cmd_byte(cmd_byte) == (CMD_PAIRING_DATA, 0)
    assert seq == 1                              # R15: default seq 1, never 0
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


def _check_cmd_byte_encoding():
    """On-air SPL command bytes match the dispatcher decode (AUDIT A5)."""
    assert spl_cmd_byte(CMD_SETUP_X25519) == 0x25        # read  (num 0x12)
    assert spl_cmd_byte(CMD_PAIRING_DATA) == 0x22        # write (num 0x11)
    assert spl_cmd_byte(CMD_PAIRING_DATA_DERIVED) == 0x3a  # write (num 0x1d)
    assert spl_cmd_byte(CMD_WRITE_AES_KEY) == 0x28
    assert spl_cmd_byte(CMD_RESET) == 0x2a
    for num in (CMD_SETUP_X25519, CMD_PAIRING_DATA, CMD_PAIRING_DATA_DERIVED, CMD_RESET):
        onair = spl_cmd_byte(num)
        dnum, drd = spl_decode_cmd_byte(onair)   # mirror FUN_0000822c: (b>>1)&0x3f, b&1
        assert dnum == num and drd == _CMD_IS_READ.get(num, 0)


def _check_setup_x25519_frames():
    """SetupX25519 request carries our pubkey on-air as 0x25; the reply parser follows R5."""
    _ctrl_priv, ctrl_pub = gen_host_keypair()
    _host_priv, host_pub = gen_host_keypair()
    req = build_setup_x25519(host_pub)
    cmd_byte, _seq, payload = unframe_spl(req)
    assert cmd_byte == 0x25                                # on-air byte, not the number
    assert spl_decode_cmd_byte(cmd_byte) == (CMD_SETUP_X25519, 1)
    assert payload == host_pub
    # R15 literal: [LEN=0x22][0x25][seq=1] — the first frame must not use seq 0 (the old default).
    assert req[:3] == bytes.fromhex("222501"), req[:3].hex()
    # R5: reply = [LEN][status][seq][data]; status bits 1..6 are stale, so 0x00, 0x04 (advert
    # byte 2 << 1) and 0x7e all pass; bit 7 = failed must raise (the old parser accepted it).
    for status in (0x00, 0x04, 0x7E):
        assert parse_setup_x25519_response(frame_spl(status, ctrl_pub, seq=1), seq=1) == ctrl_pub
    for status in (0x80, 0x84, 0xFE):
        try:
            parse_setup_x25519_response(frame_spl(status, ctrl_pub, seq=1))
            raise AssertionError(f"failed reply (status {status:#x}) accepted")
        except ValueError:
            pass
    try:                                                   # matched by seq only
        parse_setup_x25519_response(frame_spl(0x00, ctrl_pub, seq=2), seq=1)
        raise AssertionError("reply with the wrong seq accepted")
    except ValueError:
        pass
    r = parse_spl_reply(bytes.fromhex("02 80 05".replace(" ", "")) + crc24(bytes.fromhex("028005")).to_bytes(3, "little"))
    assert r == {"status": 0x80, "failed": True, "seq": 5, "data": b"", "unsolicited": False}


def _check_spl_seq_and_reset():
    """R15 seq rule and the R6 Reset frame, as literal bytes."""
    assert [spl_next_seq(s) for s in (0, 1, 2, 254, 255)] == [1, 2, 3, 255, 1]
    reset = build_spl_reset(2)
    assert reset[:3] == bytes.fromhex("022a02"), reset.hex()  # [LEN=2][0x2a][seq], no payload
    assert unframe_spl(reset) == (0x2A, 2, b"")
    assert spl_decode_cmd_byte(reset[1]) == (CMD_RESET, 0)


def _crc24_air_ref(base_le4, prefix, data):
    """Independent bit-serial CRC-24 the way the radio clocks bits on air: the access address
    LSbit-first (base LSByte first, then prefix), then S0/LENGTH/payload MSbit-first (ENDIAN=big).
    Written separately from crc24/crc24_air (no table, no byte reversal helper)."""
    reg = CRC24_INIT
    bits = [(b >> i) & 1 for b in list(base_le4) + [prefix] for i in range(8)]
    bits += [(b >> (7 - i)) & 1 for b in data for i in range(8)]
    for bit in bits:
        fb = ((reg >> 23) & 1) ^ bit
        reg = ((reg << 1) & 0xFFFFFF) ^ (CRC24_POLY if fb else 0)
    return reg


def _check_crc_framing():
    """frame -> unframe returns the original payload; a single bit-flip fails CRC."""
    payload = bytes(range(32))
    frame = frame_spl(spl_cmd_byte(CMD_PAIRING_DATA), payload, seq=7)
    cmd_byte, seq, got = unframe_spl(frame)
    assert cmd_byte == 0x22 and seq == 7 and got == payload

    # SKIPADDR=0 path: the 5-byte access address (base LE4 + prefix) is folded in the on-air way,
    # i.e. via crc24_air (AUDIT A9), not as raw bytes (the old selftest's bug path).
    addr = bytes.fromhex("0cb0cefaaa")
    framed_a = frame_spl(spl_cmd_byte(CMD_PAIRING_DATA), payload, seq=7, addr=addr)
    hdr = framed_a[:-3]
    assert framed_a[-3:] == _crc24_air_ref(addr[:4], addr[4], hdr).to_bytes(3, "little")
    assert framed_a[-3:] != crc24(addr + hdr).to_bytes(3, "little")     # raw-address CRC
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


def _check_conn_negotiation():
    """R1-R3 accept bytes as literal expectations, plus the device accept/reject rules."""
    dev_id = 0x1122334455667788
    iv = bytes(range(0x40, 0x48))
    # Full 14-byte accept, written out: [0]=1 [1]=0 [2]=(2<<3)|2 [3..10]=id LE [11]=S [12]=IV flag
    # [13]=slot count. The old tool built 01 00 02 .. <slot> 01 17 (EP 2 without fmt, version).
    assert build_conn_negotiation(dev_id, 1, steady_iv=iv) == \
        bytes.fromhex("01" "00" "12" "8877665544332211" "01" "01" "01")
    assert build_conn_negotiation(dev_id, 4, steady_iv=bytes(8)) == \
        bytes.fromhex("01" "00" "12" "8877665544332211" "04" "00" "01")       # zero IV -> flag 0
    assert build_conn_negotiation(dev_id, 2, steady_iv=None, reject=True) == \
        bytes.fromhex("01" "00" "13" "8877665544332211" "02" "00" "01")       # EP_REJECT = 3
    for slot in range(SLOT_MIN, SLOT_MAX + 1):
        got = parse_conn_negotiation(build_conn_negotiation(dev_id, slot, steady_iv=iv))
        assert got == {"type": 1, "fmt": 2, "endpoint": EP_CONN_NEG, "reject": False,
                       "device_id": dev_id, "slot": slot, "iv_flag": 1, "slot_count": 1}, got
    # R1: slot 0 (the negotiation slot) and 5+ are refused in the builder and flagged by the parser.
    for bad in (0, 5, 255):
        try:
            build_conn_negotiation(dev_id, bad)
            raise AssertionError(f"slot {bad} accepted")
        except ValueError:
            pass
    try:
        parse_conn_negotiation(bytes.fromhex("0100128877665544332211000101"))
        raise AssertionError("accept with slot 0 parsed as valid")
    except ValueError:
        pass
    try:
        parse_conn_negotiation(bytes([2, 0, EP_CONN_NEG]) + b"\x00" * 11)  # type!=1
        raise AssertionError("bad type accepted")
    except ValueError:
        pass
    # R4: one number S. Prefix S+1, beacon bit 1<<S; the negotiation slot transmits on prefix 1.
    assert [device_tx_prefix(s) for s in (0, 1, 4)] == [1, 2, 5]
    assert [slot_bit(s) for s in (1, 2, 3, 4)] == [0x02, 0x04, 0x08, 0x10]
    # accept built straight from a parsed request (fmt and IV flag come from it)
    req = bytearray(CONN_REQ_LEN)
    req[1], req[2:10], req[10:12], req[14], req[15:23] = 0x11, dev_id.to_bytes(8, "little"), b"\x01\x17", 1, iv
    assert build_conn_accept(parse_conn_request(bytes(req)), 3) == \
        bytes.fromhex("01" "00" "12" "8877665544332211" "03" "01" "01")


def _check_beacon_header():
    """Beacon header bytes 0..15 round-trip, incl. map packing, byte-14 slot, byte-15 ack."""
    cmap = 0x1555555555 & ((1 << 37) - 1)  # arbitrary 37-bit pattern
    hdr = build_beacon_header(cmap, unmapped=19, session_nonce=0xBEEF,
                              timestamp_us=0x0123456789AB, downlink_slot=3,
                              ack_bitmap=slot_bit(1) | slot_bit(3))
    assert len(hdr) == 16
    got = parse_beacon_header(hdr)
    assert got["channel_map"] == cmap, hex(got["channel_map"])
    assert got["unmapped"] == 19
    assert got["session_nonce"] == 0xBEEF
    assert got["timestamp_us"] == 0x0123456789AB
    assert got["downlink_slot"] == 3 and hdr[14] == 0x08         # byte 14 == 1<<S (R4)
    assert got["ack_bitmap"] == 0x0A and got["ack_slots"] == [1, 3]
    assert hdr[6:8] == b"\xef\xbe"              # session nonce little-endian
    assert hdr[8:14] == (0x0123456789AB).to_bytes(6, "little")
    # S is 1..4 (0 = negotiation slot, 5 out of range)
    for bad in (0, 5):
        try:
            build_beacon_header(cmap, 0, 0, 0, downlink_slot=bad)
            raise AssertionError("bad slot accepted")
        except ValueError:
            pass
    # no-downlink beacon has byte 14 == 0 and downlink_slot None
    hdr2 = build_beacon_header(cmap, 0, 0, 0)
    assert hdr2[14] == 0 and parse_beacon_header(hdr2)["downlink_slot"] is None


def _check_tl():
    """TL literals from REVIEW-RE R0's hand-built example, plus the exchange rules."""
    # Read cmd 0x32 with seq 3 for slot 1: beacon bytes 14..17 = 02 00 32 13 (ack mask 0 here).
    req = build_tl_request(0x32, 3, read=True)
    assert req == bytes.fromhex("3213")
    assert build_beacon_tl(1, req) == bytes.fromhex("02003213")
    cmap = (1 << 37) - 1
    bcn = build_beacon(cmap, 0, 0xBEEF, 1000, slot=1, tl_packet=req)
    assert bcn[14:] == bytes.fromhex("02003213") and len(bcn) == 18
    assert bcn[:14] == build_beacon_header(cmap, 0, 0xBEEF, 1000)[:14]
    assert parse_beacon_header(bcn)["tl_packet"] == req
    # Its response uplink plaintext = 01 32 13 + 16 bytes (cmd 0x32 IMU config).
    data16 = bytes(range(0xA0, 0xB0))
    resp = build_tl_read_response(1, 0x32, 3, data16)
    assert resp == bytes.fromhex("013213") + data16
    got = parse_tl_uplink(resp)
    assert got == {"slot": 1, "reg": 0x32, "seq": 3, "read": True, "err": False, "ntf": False,
                   "data": data16, "rf_stats": False}, got
    assert tl_completes(got, 0x32, 3, read=True) == {"err": False, "data": data16}
    assert tl_completes(got, 0x32, 4, read=True) is None                     # other seq
    # A write of 0x28 with seq 4 = 28 04 + 12 bytes; no response on success, acked by any later
    # uplink carrying seq 4 (here a notification).
    led = bytes(12)
    assert build_tl_request(0x28, 4, read=False, payload=led) == bytes.fromhex("2804") + led
    ntf = build_tl_notification(1, 4, bytes.fromhex("2480" "05"))            # ntf 4 (buttons) = 0x05
    assert ntf == bytes.fromhex("010044248005")
    pn = parse_tl_uplink(ntf)
    assert pn["reg"] == 0 and pn["ntf"] and pn["seq"] == 4 and pn["data"] == bytes.fromhex("248005")
    assert tl_completes(pn, 0x28, 4, read=False) == {"err": False, "data": b""}
    assert tl_completes(pn, 0x32, 4, read=True) is None                      # a ntf never answers a read
    # A failed write: [S][reg][seq | 0x20].
    werr = build_tl_write_error(1, 0x28, 4)
    assert werr == bytes.fromhex("012824")
    assert tl_completes(parse_tl_uplink(werr), 0x28, 4, read=False) == {"err": True, "data": b""}
    # CL[0] == 0 is a connection request, not TL; reg 0x2a is the RF stats channel.
    assert parse_tl_uplink(bytes.fromhex("0011") + bytes(23)) is None
    assert parse_tl_uplink(bytes.fromhex("012a40"))["rf_stats"]
    # seq wraps 15 -> 0; idle beacon TL = [00][seq] with byte 14 = 0
    assert [tl_next_seq(s) for s in (0, 14, 15)] == [1, 15, 0]
    assert build_beacon_tl(None, build_tl_idle(7)) == bytes.fromhex("00000007")
    # limits: payload <= 32, seq 0..15
    for bad in (lambda: build_tl_request(0x28, 16, False), lambda: build_tl_request(0x28, 0, False, bytes(33)),
                lambda: build_tl_notification(1, 0, bytes(50))):
        try:
            bad()
            raise AssertionError("TL limit not enforced")
        except ValueError:
            pass


def _check_reg_map_and_limits():
    """Command-register map matches LINK.md and transport limits are enforced."""
    assert describe_reg(0x2F).startswith("R ") and "battery" in describe_reg(0x2F)
    assert describe_reg(0x28) == "R get_led_config"
    assert describe_reg(0x13) == "W unpair"
    assert describe_reg(0x99) == "unknown"
    check_read_request(0x2F, 0)
    check_read_request(0x2B, 8)        # calibration read: {u32 offset, u32 len}
    check_write_request(0x13, 0)
    for bad in (READ_REQ_MAX + 1, 0x1000):
        try:
            check_read_request(0x2F, bad)
            raise AssertionError("over-long read accepted")
        except ValueError:
            pass
    try:
        check_write_request(0x13, WRITE_LEN_MAX + 1)
        raise AssertionError("over-long write accepted")
    except ValueError:
        pass


def _check_nonces():
    """Legacy (A2) and steady-state (A3) CCM nonces pack exactly as the firmware builds them."""
    # Legacy negotiation nonce: counter 0, IV = session<<48|ts48, as u64 LE.
    nonce = legacy_nonce(session_nonce=0xBEEF, beacon_ts48=0x0123456789AB)
    assert len(nonce) == 13
    assert nonce[:5] == b"\x00\x00\x00\x00\x00"                 # counter 0
    # 13-byte nonce = 00*5 ‖ ts[0..5] LE ‖ session LE  (AUDIT A2)
    assert nonce[5:11] == (0x0123456789AB).to_bytes(6, "little")
    assert nonce[11:13] == (0xBEEF).to_bytes(2, "little")

    # Steady-state nonce: per-slot counter + the IV from the connection request; direction 0 (R8).
    iv = bytes(range(0x10, 0x18))
    n = steady_state_nonce(counter=1, iv=iv)                   # direction defaults to 0
    assert len(n) == 13 and n[5:] == iv
    assert n[:5] == bytes.fromhex("0100000000")                # counter 1, bit 39 clear
    assert steady_state_nonce(counter=1, iv=iv, direction=1)[:5] == bytes.fromhex("0100000080")
    for bad in (b"\x00" * 7, b"\x00" * 9):
        try:
            steady_state_nonce(0, bad)
            raise AssertionError("bad IV length accepted")
        except ValueError:
            pass


def _check_independent_aesccm():
    """Vectors built with `cryptography`'s AESCCM (M=4, 1-byte AAD 00) and hand-packed nonces, NOT
    the tool's ccm_encrypt / nonce_from_fields (REVIEW-RE R17 "Add as selftests")."""
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    # (a) PairingData wrap: nonce = 00*5 ‖ IV, plaintext = u32 LE netaddr ‖ key.
    wrap = bytes(range(0x30, 0x40))
    iv = bytes.fromhex("0102030405060708")
    netaddr, key = 0x12345678, bytes(range(0x50, 0x60))
    pt = bytes.fromhex("78563412") + key
    want = iv + AESCCM(wrap, tag_length=4).encrypt(bytes(5) + iv, pt, b"\x00")
    assert build_pairing_payload(wrap, netaddr, key, iv=iv)[0] == want
    assert parse_pairing_data(wrap, want) == (bytes.fromhex("78563412"), key)
    # (b) A direction-0 steady uplink (R8): nonce = counter u40 LE (bit 39 clear) ‖ steady IV.
    #     The old default (direction=1) fails this MIC.
    link_key, siv, ctr = bytes(range(16)), bytes(range(0x40, 0x48)), 1000
    body = bytes.fromhex("010040") + bytes.fromhex("248005")                 # [S][0][0x40|0][chunk]
    ct = AESCCM(link_key, tag_length=4).encrypt(ctr.to_bytes(5, "little") + siv, body, b"\x00")
    got, ok = ccm_decrypt(link_key, steady_state_nonce(ctr, siv), ct, aad=b"\x00", mic_len=4)
    assert ok and got == body
    assert not ccm_decrypt(link_key, steady_state_nonce(ctr, siv, direction=1), ct)[1]
    assert parse_tl_uplink(got)["ntf"]


def _check_conn_request():
    """Connection-request parse recovers the device id, version and the 8-byte steady IV (A3)."""
    steady_iv = bytes(range(0x40, 0x48))
    dev_id = 0x1122334455667788
    pt = bytearray(CONN_REQ_LEN)
    pt[0] = 0
    pt[1] = 0x11                               # [1]>>3 = 2 (extended fields present)
    pt[2:10] = dev_id.to_bytes(8, "little")
    pt[10:12] = b"\x01\x17"                    # version 0x1701
    pt[14] = 1
    pt[15:23] = steady_iv
    got = parse_conn_request(bytes(pt))
    assert got["device_id"] == dev_id, hex(got["device_id"])
    assert got["version"] == PULSAR_VERSION
    assert got["steady_iv"] == steady_iv
    # byte 0 != 0 (a host response, not a request) is rejected
    pt[0] = 1
    try:
        parse_conn_request(bytes(pt))
        raise AssertionError("response accepted as request")
    except ValueError:
        pass
    # the IV recovered here feeds steady_state_nonce
    assert steady_state_nonce(0, got["steady_iv"])[5:] == steady_iv


def _check_notification_split():
    """split_notification strips the 0x14 wrapper (+ sidechannel) and enforces byte 0x13 == 0."""
    chunks = bytes([0x81, 0x40]) + bytes(2)    # a plausible unfragmented chunk header + payload
    sc = bytes(range(6))
    buf = bytes(0x14) + sc + chunks
    stream, got_sc = split_notification(buf, sidechannel_len=len(sc))
    assert stream == chunks and got_sc == sc
    # no sidechannel
    assert split_notification(bytes(0x14) + chunks)[0] == chunks
    # too short, and byte 0x13 != 0, both rejected
    try:
        split_notification(bytes(0x10))
        raise AssertionError("short notification accepted")
    except ValueError:
        pass
    bad = bytearray(0x14 + len(chunks))
    bad[0x13] = 1
    try:
        split_notification(bytes(bad))
        raise AssertionError("byte 0x13 != 0 accepted")
    except ValueError:
        pass


def _check_crc_air():
    """crc24_air bit-reverses the 5 address bytes before the body (AUDIT A9)."""
    base = bytes.fromhex("0cb0cefa")           # 0xFACEB00C written little-endian to BASEn
    prefix = 0xAA
    body = bytes([0x20]) + bytes(range(16))    # LENGTH + payload (DM link, no S0)
    air = crc24_air(base, prefix, body)
    # equals crc24 over the bit-reversed address followed by the unreversed body
    manual_addr = bytes(_bitrev8(x) for x in base) + bytes([_bitrev8(prefix)])
    assert air == crc24(manual_addr + body)
    # and the independent bit-serial reference (address LSbit-first) agrees
    assert air == _crc24_air_ref(base, prefix, body)
    # and it is NOT the raw-address CRC the old selftest used (the bug A9 flags)
    assert air != crc24(base + bytes([prefix]) + body)


def selftest():
    _check_x25519_rfc7748()
    _check_cmd_byte_encoding()
    _check_setup_x25519_frames()
    _check_spl_seq_and_reset()
    _check_pairing_roundtrip()
    _check_crc_framing()
    _check_crc_air()
    _check_conn_negotiation()
    _check_conn_request()
    _check_beacon_header()
    _check_tl()
    _check_notification_split()
    _check_reg_map_and_limits()
    _check_nonces()
    _check_independent_aesccm()
    print("selftest ok (X25519 RFC 7748 6.1 vector + SPL on-air cmd byte (num<<1)|read + "
          "0x25/0x22 build/parse + R5 reply status bit 7 / seq match + R15 seq 1 + R6 Reset 0x2a + "
          "PairingData round-trip w/ MIC + u32 LE netaddr + length reject + CRC/framing via "
          "crc24_air + independent air-CRC reference + R1-R3 accept literals + conn-request IV "
          "extract + beacon header 0..15 (1<<S) + R0 TL request/response/ntf/write-ack literals + "
          "notification wrapper split + command-reg map/limits + legacy & direction-0 steady "
          "nonces + independent AESCCM pairing-wrap and steady-uplink vectors)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
