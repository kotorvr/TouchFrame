#!/usr/bin/env python3
"""Offline decode of Touch Plus controller input, from the deerfly input-MCU sample.

There is NO HID report descriptor (docs/PROTOCOL.md Q4, CONFIRMED). The controller's elk-app
report assembler `FUN_000173bc @ 0x173bc` ("input_mcu_thread") reads the Renesas "deerfly"
input-MCU register 0x37 over SPI as a 61-byte sample (`FUN_00021fd4(0x37, buf, 0x3d)`), checks a
4-byte checksum (`FUN_00029f4c(buf, 0x39)` vs `buf[0x39..0x3c]`), then re-packs the fields into
individually-addressable elk host-facing registers ("hregs") the headset reads over Pulsar. So
there is no single packed on-air report: each field is a separate register value.

This tool reconstructs both halves offline, with NO hardware and NO radio:
  * `parse_deerfly(sample61)` extracts the fields from a raw 61-byte deerfly sample, applying the
    exact bit remaps the firmware uses when it builds the hregs.
  * `checksum_deerfly` / `verify` reproduce `FUN_00029f4c` exactly.
  * `decode_hreg(reg_id, value)` decodes a single already-packed host register, for when input
    arrives over the dongle as register reads rather than as the raw deerfly sample.

CHECKSUM (`FUN_00029f4c`, CONFIRMED by reading the function + its 16-entry table at flash
0x32b68): a standard reflected CRC-32 (polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR
0xFFFFFFFF) computed a nibble at a time (low nibble then high nibble per byte) over the first
0x39 (57) bytes. That nibble loop is bit-for-bit identical to `zlib.crc32`. The 4-byte result is
stored little-endian at buf[0x39:0x3d] and compared as a LE u32.

FIELD OFFSETS are CONFIRMED (cited to `FUN_000173bc`); SEMANTICS are INFERRED where noted. The
deerfly firmware is not in the dumps, so which analog is which axis, which button bit is which
label, and the flag/battery scales are NOT established here -- those are flagged INFERRED/UNKNOWN
and this tool only exposes the raw values under the Q4 field names. IMU (hregs 0xb/0x16) is a
SEPARATE elk-side path (imu_thread.c) and is deliberately NOT part of the deerfly sample, so it is
not parsed from `sample61`.

  pulsar_input.py selftest
  pulsar_input.py parse --sample <122 hex chars = 61 bytes>
  pulsar_input.py hreg  --reg <id> --value <hex>
"""
import argparse
import struct
import zlib

SAMPLE_LEN = 61            # deerfly reg 0x37 sample: 0x3d bytes
CRC_LEN = 0x39             # checksum covers buf[0x00:0x39] (57 bytes)
CRC_OFF = 0x39             # 4-byte LE checksum stored at buf[0x39:0x3d]


# ---- helpers -------------------------------------------------------------------------------

def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _bit(v, n):
    return (v >> n) & 1


# ---- checksum (FUN_00029f4c) ---------------------------------------------------------------

def checksum_deerfly(sample):
    """Checksum over buf[0x00:0x39], exactly as FUN_00029f4c computes it.

    FUN_00029f4c is a reflected CRC-32 (poly 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF)
    evaluated nibble-by-nibble against the 16-entry table at flash 0x32b68. That table equals the
    standard zlib CRC-32 nibble table (verified by reading the bytes out of the image), and the
    low-then-high nibble ordering makes the loop identical to a byte-wise CRC-32 -- so this is
    zlib.crc32 over the first CRC_LEN bytes. Returns a 32-bit int."""
    return zlib.crc32(bytes(sample[:CRC_LEN])) & 0xFFFFFFFF


def stored_checksum(sample):
    """The 4-byte checksum field the controller appended, read LE at buf[0x39] (as FUN_000173bc
    reads it: `*(int *)(buf + 0x39)`)."""
    return _u32(sample, CRC_OFF)


def verify(sample):
    """True iff the recomputed checksum equals the stored one -- the exact gate FUN_000173bc
    applies (`iVar16 == *(int *)(buf + 0x39)`) before it re-packs the hregs."""
    if len(sample) < SAMPLE_LEN:
        return False
    return checksum_deerfly(sample) == stored_checksum(sample)


# ---- bit remaps (CONFIRMED math, FUN_000173bc) ---------------------------------------------

def remap_buttons(b, c):
    """12-bit button word written to hreg 9, from deerfly b=buf[0x21], c=buf[0x22].

    CONFIRMED packing (FUN_000173bc): out0=b.0, out1=b.2, out2=b.4, out3=c.2, out4=b.6, out5=b.1,
    out6=b.3, out7=b.5, out8=b.7, out9=c.3, out10=c.0, out11=c.1. Which output bit is
    A/B/X/Y/menu/system/stick-click is decided in the (absent) deerfly firmware -> INFERRED."""
    return (
        _bit(b, 0) << 0 | _bit(b, 2) << 1 | _bit(b, 4) << 2 | _bit(c, 2) << 3
        | _bit(b, 6) << 4 | _bit(b, 1) << 5 | _bit(b, 3) << 6 | _bit(b, 5) << 7
        | _bit(b, 7) << 8 | _bit(c, 3) << 9 | _bit(c, 0) << 10 | _bit(c, 1) << 11
    )


def remap_flags_reg4(f):
    """Low nibble written to hreg 4, from deerfly f=buf[0x04].

    CONFIRMED math as literally decompiled at the `FUN_0001f464(4, ...)` call:
    out0=f.1, out1=f.2, out2=f.3, out3=f.0.

    NOTE (discrepancy, surfaced not resolved): docs/PROTOCOL.md Q4 prose lists reg4 as
    out2=f.0, out3=f.3 -- that ordering actually matches the *other* write in FUN_000173bc, the
    10-bit edge/bit variant `FUN_0001f748(value, 10)`, not the value written to hreg id 4. We
    implement the id-4 write faithfully and expose `flags_raw` so either reading can be checked
    against a live capture. Touch-vs-proximity meaning of each bit is INFERRED."""
    return _bit(f, 1) << 0 | _bit(f, 2) << 1 | _bit(f, 3) << 2 | _bit(f, 0) << 3


def remap_flags_edge10(f):
    """Low nibble of the 10-bit edge/bit value `FUN_0001f748(value, 10)` builds from f=buf[0x04]:
    out0=f.1, out1=f.2, out2=f.0, out3=f.3. (This is the ordering Q4 prose ascribes to reg4; the
    upper 6 of the 10 bits come from an unmodelled incoming register and are not reconstructable
    from the sample alone.) Exposed only for comparison -- INFERRED meaning."""
    return _bit(f, 1) << 0 | _bit(f, 2) << 1 | _bit(f, 0) << 2 | _bit(f, 3) << 3


# ---- parse the raw deerfly sample ----------------------------------------------------------

def parse_deerfly(sample61):
    """Decode a raw 61-byte deerfly sample (deerfly reg 0x37) into the Q4 hreg field names.

    Offsets CONFIRMED (FUN_000173bc); semantic labels INFERRED where commented. Raises ValueError
    on a short buffer."""
    s = bytes(sample61)
    if len(s) != SAMPLE_LEN:
        raise ValueError(f"deerfly sample must be {SAMPLE_LEN} bytes, got {len(s)}")

    b21, c22 = s[0x21], s[0x22]
    flag_byte = s[0x04]
    out = {
        # reg 2 (4B) -- sample counter / timestamp. INFERRED meaning.
        "sample_counter": _u32(s, 0x00),

        # reg 9 -- buttons. 12-bit remap CONFIRMED; bit labels INFERRED.
        "buttons": remap_buttons(b21, c22),
        "buttons_raw": (b21, c22),             # deerfly buf[0x21], buf[0x22] pre-remap

        # reg 3 / reg 0x17 -- four clean 12-bit ADC analogs. CONFIRMED these are the
        # {trigger, grip, stick-X, stick-Y} set; WHICH offset is WHICH axis is INFERRED/UNKNOWN.
        "analog_a": _u16(s, 0x23) & 0xFFF,     # -> hreg 3
        "analog_b": _u16(s, 0x25) & 0xFFF,     # -> hreg 3
        "analog_c": _u16(s, 0x31) & 0xFFF,     # -> hreg 0x17
        "analog_d": _u16(s, 0x33) & 0xFFF,     # -> hreg 0x17

        # reg 4 / reg 0x2b -- touch/proximity flags. Remap CONFIRMED (see remap_flags_reg4 note);
        # touch-vs-proximity meaning INFERRED.
        "touch_flags_reg4": remap_flags_reg4(flag_byte),
        "touch_flag_reg2b": _bit(flag_byte, 4),
        "flags_raw": flag_byte,                # deerfly buf[0x04] pre-remap
        "touch_flags_edge10": remap_flags_edge10(flag_byte),  # comparison only; see note

        # cap-touch / sensor channels -- raw slices, all INFERRED. Source ranges per Q4 table;
        # the per-byte repack into hregs 8/0x21/0x20 is in FUN_000173bc.
        "captouch_reg8_raw": s[0x05:0x0F],     # -> hreg 8  (10B)
        "captouch_reg21_raw": s[0x0F:0x1B],    # -> hreg 0x21 (12B)
        "sensor_reg20_raw": s[0x1B:0x21],      # -> hreg 0x20 (6B)
        "analog_aux_reg17_raw": s[0x2D:0x31] + s[0x35:0x37],  # aux bytes packed with C/D. INFERRED.

        # reg 0x15 (2B) -- battery. INFERRED unit/scale (Q4 says mV, unconfirmed).
        "battery_mv": _u16(s, 0x37),

        # checksum
        "checksum_stored": stored_checksum(s),
        "checksum_calc": checksum_deerfly(s),
        "checksum_ok": verify(s),
    }
    # IMU (hregs 0xb/0x16) is a SEPARATE elk-side path (Q4) and is NOT in this sample -> absent.
    return out


# ---- decode an individual already-packed host register -------------------------------------

def decode_hreg(reg_id, value):
    """Decode one elk host-facing register (as read over Pulsar) into its field(s).

    `value` is the register payload: an int for the small numeric regs, or bytes for the raw
    multi-byte regs. NOTE the hreg already holds the controller's *post-remap* value, so (unlike
    parse_deerfly, which starts from raw deerfly bytes) no remap is re-applied here -- buttons
    and flags are just unpacked bit-by-bit. Field semantics are INFERRED as in parse_deerfly."""
    def as_int(v, n):
        return v if isinstance(v, int) else int.from_bytes(bytes(v)[:n], "little")

    def as_bytes(v):
        return bytes(v) if not isinstance(v, int) else v.to_bytes((v.bit_length() + 7) // 8, "little")

    if reg_id == 2:
        return {"sample_counter": as_int(value, 4)}
    if reg_id == 9:
        v = as_int(value, 2) & 0xFFF
        return {"buttons": v, "button_bits": [(_bit(v, i)) for i in range(12)]}
    if reg_id == 3:
        v = as_int(value, 3)
        return {"analog_a": v & 0xFFF, "analog_b": (v >> 12) & 0xFFF}
    if reg_id == 0x17:
        v = as_bytes(value)
        # C and D are the two 12-bit ADCs packed into this 8-byte reg (see FUN_000173bc); the
        # remaining bytes are aux (INFERRED). We expose the two ADCs plus the raw block.
        word = int.from_bytes(v[:6].ljust(6, b"\x00"), "little")
        return {"analog_c": word & 0xFFF, "analog_d": (word >> 12) & 0xFFF, "reg17_raw": v}
    if reg_id == 4:
        v = as_int(value, 1) & 0xF
        return {"touch_flags_reg4": v}
    if reg_id == 0x2b:
        return {"touch_flag_reg2b": as_int(value, 1) & 1}
    if reg_id == 0x15:
        return {"battery_mv": as_int(value, 2)}            # INFERRED scale
    if reg_id in (8, 0x20, 0x21):
        return {f"captouch_reg{reg_id:#x}_raw": as_bytes(value)}   # INFERRED
    if reg_id in (0xB, 0x16):
        return {f"imu_reg{reg_id:#x}_raw": as_bytes(value)}        # separate path; INFERRED scale
    return {"unknown_reg": reg_id, "raw": as_bytes(value)}


# ---- packing (used by the selftest round-trip; also handy for building test vectors) --------

def pack_deerfly(counter=0, b21=0, c22=0, flags=0, analog_a=0, analog_b=0,
                 analog_c=0, analog_d=0, battery=0):
    """Build a valid 61-byte deerfly sample (with a correct checksum) from raw deerfly values.

    This places each field at its CONFIRMED offset and appends the CRC. It is the inverse of
    parse_deerfly for the losslessly-stored fields (counter, raw button bytes, raw flag byte, the
    four 12-bit ADCs, battery); the remapped button/flag *outputs* are then what parse derives."""
    s = bytearray(SAMPLE_LEN)
    struct.pack_into("<I", s, 0x00, counter & 0xFFFFFFFF)
    s[0x04] = flags & 0xFF
    s[0x21] = b21 & 0xFF
    s[0x22] = c22 & 0xFF
    struct.pack_into("<H", s, 0x23, analog_a & 0xFFF)
    struct.pack_into("<H", s, 0x25, analog_b & 0xFFF)
    struct.pack_into("<H", s, 0x31, analog_c & 0xFFF)
    struct.pack_into("<H", s, 0x33, analog_d & 0xFFF)
    struct.pack_into("<H", s, 0x37, battery & 0xFFFF)
    struct.pack_into("<I", s, CRC_OFF, checksum_deerfly(s))
    return bytes(s)


# ---- selftest (NO hardware) ----------------------------------------------------------------

def selftest():
    # 1. Round-trip: pack known raw field values, parse them back.
    fields = dict(counter=0x11223344, b21=0b10110101, c22=0b00001101, flags=0b10110,
                  analog_a=0x123, analog_b=0xABC, analog_c=0x4DE, analog_d=0xF05, battery=4123)
    s = pack_deerfly(**fields)
    assert len(s) == SAMPLE_LEN, len(s)
    p = parse_deerfly(s)
    assert p["sample_counter"] == fields["counter"]
    assert p["analog_a"] == 0x123 and p["analog_b"] == 0xABC
    assert p["analog_c"] == 0x4DE and p["analog_d"] == 0xF05
    assert p["battery_mv"] == 4123
    assert p["buttons_raw"] == (fields["b21"], fields["c22"])
    assert p["flags_raw"] == fields["flags"]
    assert p["checksum_ok"] is True

    # 2a. 12-bit ADC extraction: high bits of the 16-bit word must be masked off.
    sx = bytearray(pack_deerfly())
    struct.pack_into("<H", sx, 0x23, 0xF123)             # upper nibble set -> must be dropped
    struct.pack_into("<I", sx, CRC_OFF, checksum_deerfly(sx))
    assert parse_deerfly(bytes(sx))["analog_a"] == 0x123, "12-bit ADC mask failed"

    # 2b. Button remap on known single-bit inputs (CONFIRMED mapping).
    # b.0 -> out0 ; b.2 -> out1 ; c.1 -> out11 ; c.2 -> out3
    assert remap_buttons(0x01, 0x00) == (1 << 0)
    assert remap_buttons(0x04, 0x00) == (1 << 1)
    assert remap_buttons(0x00, 0x02) == (1 << 11)
    assert remap_buttons(0x00, 0x04) == (1 << 3)
    # full byte b=0xFF, c=0 -> every b-sourced output bit set, c-sourced clear.
    # b feeds outputs {0,1,2,4,5,6,7,8}; c feeds {3,9,10,11}.
    assert remap_buttons(0xFF, 0x00) == 0b000111110111
    assert remap_buttons(0x00, 0x0F) == 0b111000001000

    # 2c. Flag remap (decompiled id-4 math): f=0b1010 -> f.1=1,f.3=1 -> out0=1(f.1),out2=1(f.3)
    assert remap_flags_reg4(0b1010) == 0b0101
    assert remap_flags_reg4(0b0001) == 0b1000           # f.0 -> out3
    assert parse_deerfly(pack_deerfly(flags=0b10000))["touch_flag_reg2b"] == 1

    # 3. Checksum: hand-computed CRC-32 for a fixed all-zero-body sample, and corruption flips verify.
    body = bytes(CRC_LEN)                                # 57 zero bytes
    assert checksum_deerfly(body) == zlib.crc32(body) & 0xFFFFFFFF
    assert checksum_deerfly(body) == 0xDDD1DE1C, hex(checksum_deerfly(body))  # pinned value
    good = pack_deerfly(counter=0xDEADBEEF, analog_a=0x0AB, battery=4096)
    assert verify(good) is True
    bad = bytearray(good)
    bad[0x10] ^= 0x01                                    # flip one covered byte
    assert verify(bytes(bad)) is False, "single-byte corruption not detected"
    bad2 = bytearray(good)
    bad2[CRC_OFF] ^= 0x80                                # corrupt the stored checksum itself
    assert verify(bytes(bad2)) is False

    # 4. decode_hreg mirrors parse for the packed path (no re-remap): reg 3 unpacks two 12-bit ADCs.
    packed3 = (0x123 | (0xABC << 12)).to_bytes(3, "little")
    d = decode_hreg(3, packed3)
    assert d["analog_a"] == 0x123 and d["analog_b"] == 0xABC
    assert decode_hreg(9, 0x801)["button_bits"][0] == 1
    assert decode_hreg(0x15, b"\x00\x10")["battery_mv"] == 4096

    print("selftest ok -- CRC-32 (FUN_00029f4c) == zlib.crc32 over buf[0:0x39]; "
          "pack->parse round-trips counter/ADCs/battery; 12-bit ADC mask, button remap and "
          "flag remap match FUN_000173bc; 1-byte corruption fails verify().")


# ---- cli -----------------------------------------------------------------------------------

def _h(s):
    return bytes.fromhex(s.replace(" ", ""))


def do_parse(args):
    s = _h(args.sample)
    p = parse_deerfly(s)
    for k, v in p.items():
        if isinstance(v, (bytes, bytearray)):
            v = v.hex()
        elif k in ("analog_a", "analog_b", "analog_c", "analog_d",
                   "flags_raw", "checksum_stored", "checksum_calc"):
            v = hex(v)
        print(f"  {k} = {v}")


def do_hreg(args):
    reg = int(args.reg, 0)
    try:
        val = _h(args.value)          # prefer hex-bytes
    except ValueError:
        val = int(args.value, 0)      # fall back to an integer payload
    for k, v in decode_hreg(reg, val).items():
        if isinstance(v, (bytes, bytearray)):
            v = v.hex()
        print(f"  {k} = {v}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())
    p = sub.add_parser("parse")
    p.add_argument("--sample", required=True, help="61-byte deerfly sample, hex")
    p.set_defaults(fn=do_parse)
    g = sub.add_parser("hreg")
    g.add_argument("--reg", required=True, help="hreg id (e.g. 9, 0x17)")
    g.add_argument("--value", required=True, help="register payload: hex bytes, or an int")
    g.set_defaults(fn=do_hreg)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
