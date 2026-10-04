#!/usr/bin/env python3
"""Offline decode/encode of Touch Plus controller peripherals: input, IMU, IR LEDs, haptics.

Evidence: docs/re/PERIPHERALS.md (RE-2). Tags there: CONFIRMED / INFERRED / UNKNOWN.

Input does not go through a HID report descriptor: cmd 0xab does return one (LINK §3), but the
host decodes Touch Plus input from two register spaces (PERIPHERALS §1), and this tool models
both, with NO hardware and NO radio:

* Notification registers ("ntf"): the controller pushes them as a chunk stream (u16 header +
  payload, PERIPHERALS §1.1) in TL notifications [S][0x00][0x40|seq][chunks] (REVIEW-RE R0).
  Chunk type == ntf id. Buttons, stick, triggers, touch, IMU, battery, LED echo all arrive this way.
    NtfUnpacker().feed(payload) -> [(type, bytes)]  (host ntf_unpacker_next; fragments span
                                   notifications, so keep one unpacker per controller, R13)
    unpack_chunks(payload)      -> the same for one isolated notification (stateless)
    pack_notifications(items)   -> per-notification chunk streams within the 49-byte budget
    decode_ntf(type, payload)   -> labelled fields, SI units for the IMU
* Command registers: host pulsar_read/pulsar_write by id.
    pack_led_config / parse_led_config   cmd 0x28 {u32 period_us, u32 ontime_us, i32 delay_us}
    controller_apply_led                 the controller's clamp + validation (75 us, 500 ms)
    next_pulse_start                     the controller's pulse scheduler (FUN_0001873c)
    parse_imu_config                     cmd 0x32 (accel/gyro range, ODR, f32 scales)
    parse_battery_info                   cmd 0x2f
    pack_cal_read                        cmd 0x2b read params {u32 offset, u32 len<=32}
    pack_haptic_simple / _freq / _syncbuffer   cmds 0x97 / 0xa0 / 0x9b

It also keeps the deerfly (input MCU) layer that elk-app repacks into ntf registers:
    parse_deerfly(sample61)      raw 61-byte SPI sample (reg 0x37) -> labelled fields
    deerfly_to_ntf(sample61)     the exact ntf payloads elk FUN_000173bc builds from it
    checksum_deerfly / verify    CRC-32 (elk FUN_00029f4c == deerfly 0xba1c == zlib.crc32)

  pulsar_input.py selftest
  pulsar_input.py parse  --sample <122 hex chars = 61 bytes>
  pulsar_input.py ntf    --type <id> --value <hex>
  pulsar_input.py chunks --payload <hex> [--payload <hex> ...]
                         (notification bodies after the 0x14-byte header, in order; one unpacker)
  pulsar_input.py led    --period 11111 --ontime 75 --delay 0 [--now 123456]
"""
import argparse
import math
import struct
import warnings
import zlib

SAMPLE_LEN = 61            # deerfly reg 0x37 sample: 0x3d bytes
CRC_LEN = 0x39             # checksum covers buf[0x00:0x39] (57 bytes)
CRC_OFF = 0x39             # 4-byte LE checksum stored at buf[0x39:0x3d]

G = 9.80665                # host: accel * scale * 9.80665 (libsyncboss case type 1)
DEG2RAD = 0.017453292519943295

# ntf ids (== chunk types). CONFIRMED (elk table 0x2e7dc sizes + host handlers), PERIPHERALS §4.1.
NTF_BATTERY_PCT = 0x00     # u8 %
NTF_IMU = 0x01             # 18 B: u48 ts_us, i16 accel[3], i16 gyro[3]
NTF_STICK = 0x02           # 2 x i16
NTF_TRIGGERS = 0x03        # 24 bits: bits 0..11 index trigger ("fore"), 12..23 grip
NTF_BUTTONS = 0x04         # u8
NTF_STATE = 0x06           # u8 state flags
NTF_CAPTOUCH = 0x08        # 10 B raw
NTF_TOUCH = 0x09           # u32, 12 touch/prox bits
NTF_IRLED = 0x0B           # 12 B {p, ot, d} echo of the applied LED config
NTF_PRESSURE = 0x15        # u16 (deerfly u16@0x37), 12-bit index-trigger pressure, full scale 8.5 N
NTF_BATT_ALERTS = 0x16     # u16 alert bits
NTF_IDXCURL = 0x17         # 8 B: u8 curl1d, u8 idx_slider, 4 x s12 joint angles
NTF_SENSOR20 = 0x20        # 6 B (UNKNOWN meaning)
NTF_CAPTOUCH21 = 0x21      # 12 B raw
NTF_IMU_TEMP = 0x28        # i32 raw IMU temperature
NTF_AUX2B = 0x2B           # u16 = deerfly buf[4].4 (UNKNOWN meaning)

# ntf 4 bits -> label (CONFIRMED: host print_decoded_controller_input "button: {ax, by, sys, ts}").
BUTTON_BITS = {0: "a_x", 1: "b_y", 2: "thumbstick_click", 3: "system_menu"}
# ntf 9 bits -> label (CONFIRMED host labels; "thumbrest" for "tr" is INFERRED).
TOUCH_BITS = {0: "touch_a_x", 1: "touch_b_y", 2: "touch_thumbstick", 3: "touch_thumbrest",
              4: "touch_trigger", 5: "prox_a_x", 6: "prox_b_y", 7: "prox_thumbstick",
              8: "prox_trigger", 9: "prox_thumbrest", 10: "touch_trigger2", 11: "prox_trigger2"}
STATE_BITS = {0: "low_power", 1: "assert", 2: "cap_touch_err", 3: "imu_err", 4: "asleep",
              5: "attachment"}
BATT_ALERT_BITS = {0: "battery_pack_too_hot", 1: "battery_pack_too_cold", 2: "dead_battery",
                   3: "brownout_secondary", 4: "brownout"}

# cmd ids (pulsar_read / pulsar_write). CONFIRMED, PERIPHERALS §1.2/§2/§3/§7.
CMD_DEVICE_DESC = 0x01
CMD_PCB_SN = 0x02
CMD_ASSEMBLY_SN = 0x03
CMD_DATA_READY = 0x09      # write 1 byte 0x00: optional; the controller streams anyway after 100 ms (R12)
CMD_CAPABILITIES = 0x0A
CMD_SELECT_MCU = 0x20
CMD_APP_VERSION = 0x24
CMD_DM_VERSION = 0x25
CMD_LED_CONFIG = 0x28
CMD_CAL_BLOB = 0x2B        # ir_led_cal: 8 KB flash, read 32 B at a time
CMD_BATTERY_INFO = 0x2F
CMD_IMU_INFO = 0x31
CMD_IMU_CONFIG = 0x32
CMD_IMU_TEMP = 0x33
CMD_HAPTIC_SIMPLE = 0x97
CMD_HAPTIC_SYNCBUF = 0x9B
CMD_HAPTIC_MULTI = 0x9C    # NOT supported by Touch Plus elk (no case)
CMD_HAPTIC_PCM = 0x9D
CMD_HAPTIC_FREQ = 0xA0
CMD_A1 = 0xA1              # battery load test: pulses the motor at 3 amplitudes (REVIEW-RE R12). NEVER send.
CAL_BLOB_LEN = 0x1FE0      # bytes the host reads from CMD_CAL_BLOB

# IR LED limits (CONFIRMED elk FUN_00016e7c init + FUN_0001fbb8 validator + 0x27fe6 clamp).
LED_MAX_ONTIME_US = 75
LED_MAX_PERIOD_US = 500_000
LED_MIN_LEAD_US = 700      # FUN_0001873c floor
LED_DEFAULT = (33333, 19, -9)   # controller boot default (p, ot, d)
HOST_DEFAULT_ONTIME_US = 19     # libsyncboss when no on-time was set

# cmd 0x32 as reported by an ICM-42686 Touch Plus (CONFIRMED from elk tables, PERIPHERALS §3.2).
DEFAULT_IMU_CONFIG = {"accel_range_mg": 32000, "gyro_range_dps": 4000, "accel_odr_hz": 500,
                      "gyro_odr_hz": 500, "accel_g_per_lsb": 1 / 1024.0,
                      "gyro_dps_per_lsb": 1 / 8.192}


# ---- helpers -------------------------------------------------------------------------------

def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _bit(v, n):
    return (v >> n) & 1


def _s12(v):
    v &= 0xFFF
    return v - 0x1000 if v & 0x800 else v


def _f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def _bits(v, names):
    return {name: _bit(v, i) for i, name in names.items()}


# ---- checksum (elk FUN_00029f4c, deerfly 0xba1c) ---------------------------------------------

def checksum_deerfly(sample):
    """CRC-32/IEEE (reflected 0xEDB88320, init/final ~0) over buf[0:0x39], nibble-wise in both
    firmwares (elk table 0x32b68, deerfly table 0x16448) == zlib.crc32. CONFIRMED."""
    return zlib.crc32(bytes(sample[:CRC_LEN])) & 0xFFFFFFFF


def stored_checksum(sample):
    return _u32(sample, CRC_OFF)


def verify(sample):
    """The gate elk FUN_000173bc applies before repacking (`crc == *(int *)(buf + 0x39)`)."""
    if len(sample) < SAMPLE_LEN:
        return False
    return checksum_deerfly(sample) == stored_checksum(sample)


# ---- deerfly -> ntf bit remaps (CONFIRMED, elk FUN_000173bc) -------------------------------

def remap_touch(b, c):
    """ntf 9 (touch + proximity, 12 bits) from deerfly b=buf[0x21], c=buf[0x22].

    out0=b.0 out1=b.2 out2=b.4 out3=c.2 out4=b.6 out5=b.1 out6=b.3 out7=b.5 out8=b.7 out9=c.3
    out10=c.0 out11=c.1. Labels in TOUCH_BITS (host print_decoded_controller_input)."""
    return (
        _bit(b, 0) << 0 | _bit(b, 2) << 1 | _bit(b, 4) << 2 | _bit(c, 2) << 3
        | _bit(b, 6) << 4 | _bit(b, 1) << 5 | _bit(b, 3) << 6 | _bit(b, 5) << 7
        | _bit(b, 7) << 8 | _bit(c, 3) << 9 | _bit(c, 0) << 10 | _bit(c, 1) << 11
    )


def remap_buttons(f):
    """ntf 4 (buttons) from deerfly f=buf[0x04]: out = {f.1, f.2, f.3, f.0}.

    CONFIRMED at instruction level (elk 0x17a84..0x17ac6). So deerfly b0=system/menu, b1=A/X,
    b2=B/Y, b3=thumbstick click. (The other ordering {f.1, f.2, f.0, f.3} is the separate
    10-bit FUN_0001f748 write, see remap_edge10.)"""
    return _bit(f, 1) << 0 | _bit(f, 2) << 1 | _bit(f, 3) << 2 | _bit(f, 0) << 3


def remap_edge10(f):
    """Low nibble of FUN_0001f748(value, 10) (elk 0x17a86..0x17aac): {f.1, f.2, f.0, f.3}.
    Not an ntf register; meaning INFERRED (wake/edge bitmap). Kept for comparison only."""
    return _bit(f, 1) << 0 | _bit(f, 2) << 1 | _bit(f, 0) << 2 | _bit(f, 3) << 3


# ---- deerfly sample ------------------------------------------------------------------------

def deerfly_to_ntf(sample61):
    """The ntf payloads elk FUN_000173bc pushes for one deerfly sample (CONFIRMED byte moves)."""
    s = bytes(sample61)
    if len(s) != SAMPLE_LEN:
        raise ValueError(f"deerfly sample must be {SAMPLE_LEN} bytes, got {len(s)}")
    fore = _u16(s, 0x23) & 0xFFF
    grip = _u16(s, 0x25) & 0xFFF
    trig = fore | grip << 12
    curl = (s[0x2F] | (s[0x30] & 0xF) << 8) | (_u16(s, 0x31) & 0xFFF) << 12 \
        | (_u16(s, 0x33) & 0xFFF) << 24 | (_u16(s, 0x35) & 0xFFF) << 36
    return {
        NTF_STICK: s[0x00:0x04],
        NTF_TRIGGERS: trig.to_bytes(3, "little"),
        NTF_CAPTOUCH: s[0x07:0x0B] + s[0x0B:0x0D] + s[0x05:0x07] + s[0x0D:0x0F],
        NTF_TOUCH: remap_touch(s[0x21], s[0x22]).to_bytes(4, "little"),
        NTF_CAPTOUCH21: s[0x0F:0x11] + s[0x13:0x15] + s[0x11:0x13] + s[0x15:0x17] + s[0x17:0x1B],
        NTF_SENSOR20: bytes([s[0x1B], s[0x1D], s[0x1C], s[0x1E]]) + s[0x1F:0x21],
        NTF_IDXCURL: bytes([s[0x2D], s[0x2E]]) + curl.to_bytes(6, "little"),
        NTF_PRESSURE: s[0x37:0x39],
        NTF_BUTTONS: bytes([remap_buttons(s[0x04])]),
        NTF_AUX2B: struct.pack("<H", _bit(s[0x04], 4)),
    }


def parse_deerfly(sample61):
    """Decode a raw 61-byte deerfly sample into labelled fields, via the ntf payloads elk builds
    (so the result matches what arrives over the radio). Adds the checksum check."""
    s = bytes(sample61)
    out = {}
    for t, payload in deerfly_to_ntf(s).items():
        out.update(decode_ntf(t, payload))
    out.update({
        "buttons_raw": s[0x04],                 # deerfly buf[4] pre-remap
        "touch_raw": (s[0x21], s[0x22]),        # deerfly buf[0x21], buf[0x22] pre-remap
        "stick_raw_adc": (_u16(s, 0x0B), _u16(s, 0x05)),   # pre-calibration ADC (INFERRED order)
        "checksum_stored": stored_checksum(s),
        "checksum_calc": checksum_deerfly(s),
        "checksum_ok": verify(s),
    })
    return out


# ---- notification chunk stream (host ntf_unpacker_next, libsyncboss 0x12e74) ---------------

def chunk_header(ctype, length, seq=0, last=True):
    """u16 header: type bits 0..4, length bits 5..10, type bit 5 at bit 11, frag seq bits 12..14,
    bit 15 = last fragment. CONFIRMED."""
    if not 0 <= ctype < 0x40 or not 0 <= length < 0x40 or not 0 <= seq < 8:
        raise ValueError("chunk field out of range")
    return (ctype & 0x1F) | (length << 5) | ((ctype >> 5) & 1) << 11 | seq << 12 | (0x8000 if last else 0)


def pack_chunk(ctype, payload, seq=0, last=True):
    return struct.pack("<H", chunk_header(ctype, len(payload), seq, last)) + bytes(payload)


CHUNK_TOTAL_MAX = 0x3F     # host: a reassembled chunk must total <= 63 bytes
NTF_UPLINK_BUDGET = 52     # one-slot uplink CL payload 0x34 (elk 0x22714..0x2272e, REVIEW-RE R0)
NTF_STREAM_BUDGET = NTF_UPLINK_BUDGET - 3   # minus [S][reg 0][0x40|seq] = 49 B of chunk stream


def pack_chunks(items, frag=63):
    """[(type, payload)] -> ONE chunk stream, splitting payloads into <= `frag`-byte fragments.

    Low-level: the host stops parsing a notification at the first non-final fragment (R13), so a
    stream with a fragmented chunk is only fully read if that chunk's pieces each end a
    notification. Use pack_notifications to build what a controller actually sends; this stays for
    building test vectors. The host only reassembles fragments totalling <= 63 bytes."""
    out = b""
    for t, p in items:
        p = bytes(p)
        pieces = [p[i:i + frag] for i in range(0, len(p), frag)] or [b""]
        for i, piece in enumerate(pieces):
            out += pack_chunk(t, piece, seq=i, last=(i == len(pieces) - 1))
    return out


def pack_notifications(items, budget=NTF_STREAM_BUDGET):
    """[(type, payload)] -> [chunk stream per notification], each <= `budget` bytes (default 49 =
    the 52-byte one-slot uplink minus the [S][reg][flags] TL header).

    Whole chunks are packed greedily. A chunk too big for one notification is fragmented: each
    NON-FINAL piece goes at the END of a notification (the host stops parsing there, R13) and the
    final piece starts the next one, after which packing continues. Raises if a chunk exceeds the
    host's 63-byte reassembly limit or needs more than 8 fragments."""
    if budget < 3:
        raise ValueError("budget must fit a 2-byte header plus 1 byte")
    out, cur = [], b""
    for t, p in items:
        p = bytes(p)
        if len(p) > CHUNK_TOTAL_MAX:
            raise ValueError(f"chunk type {t:#x} is {len(p)} B; the host drops chunks > 63 B")
        if 2 + len(p) <= budget:                 # fits a notification whole
            if len(cur) + 2 + len(p) > budget:
                out.append(cur)
                cur = b""
            cur += pack_chunk(t, p)
            continue
        seq, rest = 0, p
        while rest:
            if seq > 7:
                raise ValueError("chunk needs more than 8 fragments (3-bit seq)")
            room = budget - len(cur) - 2
            if room < 1:
                out.append(cur)
                cur, room = b"", budget - 2
            if len(rest) <= room and seq > 0:    # final piece (seq >= 1, bit 15)
                cur += pack_chunk(t, rest, seq=seq, last=True)
                rest = b""
            else:                                # non-final piece: ends this notification
                piece, rest = rest[:room], rest[room:]
                cur += pack_chunk(t, piece, seq=seq, last=False)
                out.append(cur)
                cur = b""
            seq += 1
    if cur:
        out.append(cur)
    return out


class NtfUnpacker:
    """Per-controller notification unpacker (host ntf_unpacker_next, libsyncboss 0x12e74; state
    in the per-controller entry +0x158, REVIEW-RE R13). Reassembly state persists across feed()
    calls, so a chunk fragmented across notifications is delivered when its final piece arrives.

    Rules for each u16 header h in one notification's chunk stream:
      - (h & 0xf000) == 0x8000: a whole chunk, delivered (partial state left alone, INFERRED).
      - else a fragment. seq 0 starts a new chunk of that type; a continuation needs the same
        type and seq + 1; the total must stay <= 0x3f.
      - a NON-FINAL fragment ends parsing of this notification (the host's loop sees NULL); the
        rest of the payload is not parsed. State persists to the next feed().
      - a broken sequence (or an over-long total) drops the partial chunk and also stops parsing.
      - the final fragment (bit 15) delivers the reassembled chunk.
      - a chunk overrunning the payload ends parsing (is_chunk_overrun)."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.acc_type, self.acc, self.acc_seq = None, b"", -1

    def feed(self, payload):
        """One notification's chunk stream (after the 0x14-byte wrapper / TL header) ->
        [(type, bytes)] of the chunks completed by it."""
        buf = bytes(payload)
        pos, out = 0, []
        while pos + 2 <= len(buf):
            h = _u16(buf, pos)
            n = (h >> 5) & 0x3F
            if pos + 2 + n > len(buf):
                break                                    # is_chunk_overrun
            body = buf[pos + 2:pos + 2 + n]
            pos += 2 + n
            ctype = (h & 0x1F) | ((h >> 6) & 0x20)
            seq, last = (h >> 12) & 7, bool(h & 0x8000)
            if (h & 0xF000) == 0x8000:
                out.append((ctype, body))
                continue
            if seq == 0:
                self.acc_type, self.acc, self.acc_seq = ctype, b"", 0
            elif ctype != self.acc_type or seq != self.acc_seq + 1:
                self.reset()                             # broken sequence: drop and stop
                break
            else:
                self.acc_seq = seq
            if len(self.acc) + n > CHUNK_TOTAL_MAX:
                self.reset()
                break
            self.acc += body
            if not last:
                break                                    # non-final fragment ends this notification
            out.append((ctype, self.acc))
            self.reset()
        return out


def unpack_chunks(payload):
    """Stateless: one notification's chunk stream -> [(type, payload)], using a fresh NtfUnpacker
    (kept for old callers). A chunk fragmented across notifications is lost here; feed one
    NtfUnpacker per controller instead (R13)."""
    return NtfUnpacker().feed(payload)


# ---- decode one ntf payload ----------------------------------------------------------------

def decode_imu(payload, imu_config=None):
    """ntf 1 (18 B). Timestamp is µs in host (translator) time, 48 bits. SI conversion exactly
    as libsyncboss: accel * f32(cmd0x32@8) * 9.80665, gyro * f32(cmd0x32@12) * pi/180."""
    cfg = imu_config or DEFAULT_IMU_CONFIG
    p = bytes(payload)
    ts = int.from_bytes(p[0:6], "little")
    acc = struct.unpack_from("<3h", p, 6)
    gyr = struct.unpack_from("<3h", p, 12)
    fa, fg = _f32(cfg["accel_g_per_lsb"]), _f32(cfg["gyro_dps_per_lsb"])
    return {"imu_ts_us": ts, "accel_raw": acc, "gyro_raw": gyr,
            "accel_mps2": tuple(a * fa * G for a in acc),
            "gyro_radps": tuple(g * fg * DEG2RAD for g in gyr)}


def stick_axis(v):
    """Host: i16 / 32767 if positive, else / 32768."""
    return v / (32767.0 if v > 0 else 32768.0)


def decode_ntf(ntf_id, payload, imu_config=None):
    """Decode one notification register payload (one chunk) into labelled fields."""
    p = bytes(payload)
    if ntf_id == NTF_BATTERY_PCT:
        return {"battery_pct": p[0]}
    if ntf_id == NTF_IMU:
        return decode_imu(p, imu_config)
    if ntf_id == NTF_STICK:
        x, y = struct.unpack_from("<2h", p)
        return {"stick_x_raw": x, "stick_y_raw": y, "stick_x": stick_axis(x), "stick_y": stick_axis(y)}
    if ntf_id == NTF_TRIGGERS:
        v = int.from_bytes(p[:3], "little")
        fore, grip = v & 0xFFF, (v >> 12) & 0xFFF
        return {"trigger_raw": fore, "grip_raw": grip, "trigger": fore / 4095.0, "grip": grip / 4095.0}
    if ntf_id == NTF_BUTTONS:
        return {"buttons": p[0] & 0xF, **_bits(p[0], BUTTON_BITS)}
    if ntf_id == NTF_STATE:
        return {"state": p[0], **_bits(p[0], STATE_BITS)}
    if ntf_id == NTF_TOUCH:
        v = int.from_bytes(p[:4].ljust(4, b"\0"), "little") & 0xFFF
        return {"touch": v, **_bits(v, TOUCH_BITS)}
    if ntf_id == NTF_IRLED:
        return dict(zip(("led_period_us", "led_ontime_us", "led_delay_us"), parse_led_config(p)))
    if ntf_id == NTF_PRESSURE:
        # 12-bit field (R16/R17). The host caches the raw u16 and emits raw/4095 plus a separate
        # 8.5 N full-scale field; we mask so stray top bits cannot push it past full scale.
        v = _u16(p, 0) & 0xFFF
        return {"trigger_pressure_raw": v, "trigger_pressure": v / 4095.0,
                "trigger_pressure_n": v / 4095.0 * 8.5}
    if ntf_id == NTF_BATT_ALERTS:
        v = _u16(p, 0)
        return {"battery_alerts": v, **_bits(v, BATT_ALERT_BITS)}
    if ntf_id == NTF_IDXCURL:
        v = int.from_bytes(p[2:8], "little")
        # host: (s12 * 360) truncated toward zero / 4096 -> integer degrees
        ang = [int(_s12(v >> (12 * i)) * 360 / 4096) for i in range(4)]
        return {"idx_curl1d": p[0] / 255.0, "idx_slider": p[1] / 255.0,
                "idx_joint_deg": dict(zip(("0_z", "0_y", "1", "2"), ang))}
    if ntf_id == NTF_IMU_TEMP:
        return {"imu_temp_raw": struct.unpack_from("<i", p)[0],
                "imu_temp_c": struct.unpack_from("<i", p)[0] / 132.48 + 25.0}
    if ntf_id == NTF_AUX2B:
        return {"aux_2b": _u16(p, 0)}
    if ntf_id in (NTF_CAPTOUCH, NTF_CAPTOUCH21, NTF_SENSOR20):
        return {f"raw_ntf_{ntf_id:#x}": p}
    return {"unknown_ntf": ntf_id, "raw": p}


# ---- command registers -----------------------------------------------------------------------

def pack_led_config(period_us, ontime_us, delay_us):
    """cmd 0x28 payload (12 B). CONFIRMED (libsyncboss pulsar_write(dev, 0x28, &cfg, 0xc))."""
    return struct.pack("<IIi", period_us, ontime_us, delay_us)


def parse_led_config(b):
    return struct.unpack_from("<IIi", bytes(b))


def led_period_warning(period_us):
    """Warning text for a period the controller accepts but should never get, else None.

    The validator has no minimum period, but the scheduler's 700 µs lead floor adds at most one
    period (FUN_0001873c), so p < 700 µs schedules pulses closer than the lead (PERIPHERALS §2.2,
    REVIEW-RE R17)."""
    if 0 < period_us < LED_MIN_LEAD_US:
        return (f"LED period {period_us} us < {LED_MIN_LEAD_US} us: the controller accepts it but "
                f"cannot keep its {LED_MIN_LEAD_US} us scheduling lead; never send it")
    return None


def controller_apply_led(period_us, ontime_us, delay_us):
    """What the controller does with a cmd 0x28 write: clamp on-time to 75 µs (elk 0x27fe6),
    then reject if ot > 75, ot > p or p > 500 000 (FUN_0001fbb8). Returns (accepted, (p, ot, d)).
    Issues a warnings.warn (UserWarning) when p < 700 µs (led_period_warning)."""
    msg = led_period_warning(period_us)
    if msg:
        warnings.warn(msg, stacklevel=2)
    ot = min(ontime_us, LED_MAX_ONTIME_US)
    if ot > LED_MAX_ONTIME_US or ot > period_us or period_us > LED_MAX_PERIOD_US:
        return False, None
    return True, (period_us, ot, delay_us)


def next_pulse_start(now_us, period_us, delay_us, ontime_us, min_lead_us=0):
    """Controller pulse scheduler (elk FUN_000293ac -> FUN_0001873c), in host µs.

    offset = d - ot/2 (pulse centre at d), next t with t = offset (mod p) and lead >= 700 µs; the
    lead floor adds one period at most, so p < 700 µs can schedule closer than 700 µs. Returns
    (start_us, end_us). CONFIRMED arithmetic."""
    if period_us <= 0:
        raise ValueError("period_us > 0")
    min_lead = max(min_lead_us, LED_MIN_LEAD_US)
    off = delay_us - (ontime_us >> 1)
    if off < 0:
        off = period_us - ((-off) - period_us * ((-off) // period_us))
    else:
        off = off % period_us
    r = now_us % period_us
    delta = off - r if r < off else off + period_us - r
    if delta < min_lead:
        delta += period_us
    start = now_us + delta
    return start, start + ontime_us


def parse_imu_config(b):
    """cmd 0x32 (16 B): u16 accel range mg, u16 gyro range dps, u16 accel ODR, u16 gyro ODR,
    f32 accel g/LSB, f32 gyro dps/LSB. CONFIRMED (elk FUN_00025c98 case 0x32)."""
    ar, gr, ao, go, fa, fg = struct.unpack_from("<4H2f", bytes(b))
    return {"accel_range_mg": ar, "gyro_range_dps": gr, "accel_odr_hz": ao, "gyro_odr_hz": go,
            "accel_g_per_lsb": fa, "gyro_dps_per_lsb": fg}


def pack_imu_config(cfg=None):
    c = cfg or DEFAULT_IMU_CONFIG
    return struct.pack("<4H2f", c["accel_range_mg"], c["gyro_range_dps"], c["accel_odr_hz"],
                       c["gyro_odr_hz"], c["accel_g_per_lsb"], c["gyro_dps_per_lsb"])


def parse_battery_info(b):
    """cmd 0x2f (9 B): f32 battery % (INFERRED), u32 mV (host divides by 1000 -> V), u8 state."""
    pct, mv, st = struct.unpack_from("<fIB", bytes(b))
    return {"battery_pct": pct, "battery_mv": mv, "battery_v": mv / 1000.0, "battery_state": st}


def pack_cal_read(offset, length=32):
    """cmd 0x2b read params (8 B): u32 offset (low 16 bits used), u32 len <= 32."""
    if not 0 < length <= 32 or offset + length > 0x2000:
        raise ValueError("cal read: len 1..32 within the 8 KB blob")
    return struct.pack("<II", offset, length)


def cal_read_plan(total=CAL_BLOB_LEN):
    """The (offset, len) reads the host issues for the whole blob."""
    return [(o, min(32, total - o)) for o in range(0, total, 32)]


def pack_haptic_simple(amplitude):
    """cmd 0x97: 1 byte amplitude, 0 = stop. Controller auto-stops 2 s after the last write."""
    return bytes([max(0, min(255, int(amplitude)))])


def pack_haptic_freq(amplitude, freq_hz):
    """cmd 0xa0: {u8 amp, u16 freq}; elk accepts freq 40..561 (INFERRED Hz)."""
    f = int(freq_hz)
    if not 40 <= f <= 561:
        raise ValueError("freq 40..561")
    return struct.pack("<BH", max(0, min(255, int(amplitude))), f)


def pack_haptic_syncbuffer(samples):
    """cmd 0x9b: 32 B = {u8 n (<= 31), n amplitude bytes, zero pad}."""
    s = bytes(samples)
    if len(s) > 31:
        raise ValueError("<= 31 samples per write")
    return (bytes([len(s)]) + s).ljust(32, b"\0")


# ---- selftest (NO hardware) ----------------------------------------------------------------

def pack_deerfly(stick=(0, 0), buttons=0, touch=(0, 0), fore=0, grip=0, curl=(0, 0, 0, 0, 0, 0),
                 pressure=0, raw=None):
    """Build a valid 61-byte deerfly sample (correct CRC) with fields at their offsets."""
    s = bytearray(raw or bytes(SAMPLE_LEN))
    struct.pack_into("<2h", s, 0x00, *stick)
    s[0x04] = buttons & 0xFF
    s[0x21], s[0x22] = touch
    struct.pack_into("<H", s, 0x23, fore & 0xFFF)
    struct.pack_into("<H", s, 0x25, grip & 0xFFF)
    c1d, sl, a0, a1, a2, a3 = curl
    s[0x2D], s[0x2E] = c1d, sl
    struct.pack_into("<H", s, 0x2F, a0 & 0xFFF)
    struct.pack_into("<H", s, 0x31, a1 & 0xFFF)
    struct.pack_into("<H", s, 0x33, a2 & 0xFFF)
    struct.pack_into("<H", s, 0x35, a3 & 0xFFF)
    struct.pack_into("<H", s, 0x37, pressure & 0xFFFF)
    struct.pack_into("<I", s, CRC_OFF, checksum_deerfly(s))
    return bytes(s)


def selftest():
    # 1. checksum (unchanged, pinned)
    assert checksum_deerfly(bytes(CRC_LEN)) == 0xDDD1DE1C
    good = pack_deerfly(stick=(1000, -2000), fore=0x0AB)
    assert verify(good)
    bad = bytearray(good)
    bad[0x10] ^= 1
    assert not verify(bytes(bad))

    # 2. deerfly -> ntf -> labels
    s = pack_deerfly(stick=(32767, -32768), buttons=0b00011, touch=(0b01000001, 0b0100),
                     fore=4095, grip=0x800, curl=(255, 0, 0x7FF, 0x800, 0x001, 0xFFF), pressure=4095)
    p = parse_deerfly(s)
    assert p["stick_x"] == 1.0 and p["stick_y"] == -1.0
    assert p["trigger"] == 1.0 and p["grip_raw"] == 0x800
    # buf[4] b0 -> system/menu, b1 -> A/X (remap {f.1, f.2, f.3, f.0})
    assert p["system_menu"] == 1 and p["a_x"] == 1 and p["b_y"] == 0 and p["thumbstick_click"] == 0
    # touch b.0 -> touch_a_x, b.6 -> touch_trigger, c.2 -> touch_thumbrest
    assert p["touch_a_x"] == 1 and p["touch_trigger"] == 1 and p["touch_thumbrest"] == 1
    assert p["prox_a_x"] == 0 and p["touch"] == 0b11001
    assert p["idx_curl1d"] == 1.0 and p["idx_joint_deg"] == {"0_z": 179, "0_y": -180, "1": 0, "2": 0}
    assert abs(p["trigger_pressure_n"] - 8.5) < 1e-9
    assert p["checksum_ok"]
    # reg-3 packing exactly as elk: byte0 = fore lo, byte1 = fore hi nibble | grip lo nibble << 4
    t = deerfly_to_ntf(pack_deerfly(fore=0x123, grip=0xABC))[NTF_TRIGGERS]
    assert t == bytes([0x23, 0xC1, 0xAB]), t.hex()
    # touch remap on single bits (CONFIRMED mapping)
    assert remap_touch(0x04, 0) == 1 << 1 and remap_touch(0, 0x02) == 1 << 11
    assert remap_touch(0xFF, 0) == 0b000111110111 and remap_touch(0, 0x0F) == 0b111000001000
    assert remap_buttons(0b1010) == 0b0101 and remap_buttons(0b0001) == 0b1000
    assert remap_edge10(0b0001) == 0b0100
    assert decode_ntf(NTF_AUX2B, deerfly_to_ntf(pack_deerfly(buttons=0x10))[NTF_AUX2B])["aux_2b"] == 1

    # 2b. ntf 0x17 hand-packed per the AUDIT A6 bfi sequence (elk 0x179fe..0x17a68), not via
    #     pack_deerfly: [0]=buf[0x2d], [1]=buf[0x2e], bfi s12@0x2f #16, C@0x31 #28, D@0x33 #40,
    #     s12@0x35 #52 (each 12 bits wide).
    def bfi(dst, src, lsb, width):
        m = ((1 << width) - 1) << lsb
        return (dst & ~m) | ((src << lsb) & m)
    v = 0x80 | 0x40 << 8
    for lsb, field in ((16, 0x7FF), (28, 0x800), (40, 0x123), (52, 0xFFF)):
        v = bfi(v, field, lsb, 12)
    raw17 = v.to_bytes(8, "little")
    assert raw17 == bytes.fromhex("8040ff078023f1ff"), raw17.hex()
    d17 = decode_ntf(NTF_IDXCURL, raw17)
    # by hand: s12 0x7ff = 2047 -> 2047*360/4096 = 179.9 -> 179; 0x800 = -2048 -> -180;
    # 0x123 = 291 -> 25.58 -> 25; 0xfff = -1 -> -0.09 -> 0 (truncation toward zero)
    assert d17["idx_curl1d"] == 0x80 / 255.0 and d17["idx_slider"] == 0x40 / 255.0
    assert d17["idx_joint_deg"] == {"0_z": 179, "0_y": -180, "1": 25, "2": 0}, d17
    assert deerfly_to_ntf(pack_deerfly(curl=(0x80, 0x40, 0x7FF, 0x800, 0x123, 0xFFF)))[NTF_IDXCURL] == raw17

    # 2c. every ntf 9 bit vs TOUCH_BITS, and every deerfly touch input bit -> its label (table
    #     written out from the elk remap, REVIEW-RE "ntf 9 byte 0 = b0 b2 b4 c2 b6 b1 b3 b5,
    #     byte 1 = b7 c3 c0 c1")
    for bit, label in TOUCH_BITS.items():
        dt = decode_ntf(NTF_TOUCH, (1 << bit).to_bytes(4, "little"))
        assert dt["touch"] == 1 << bit and [k for k in TOUCH_BITS.values() if dt[k]] == [label]
    deerfly_touch = {("b", 0): "touch_a_x", ("b", 2): "touch_b_y", ("b", 4): "touch_thumbstick",
                     ("c", 2): "touch_thumbrest", ("b", 6): "touch_trigger", ("b", 1): "prox_a_x",
                     ("b", 3): "prox_b_y", ("b", 5): "prox_thumbstick", ("b", 7): "prox_trigger",
                     ("c", 3): "prox_thumbrest", ("c", 0): "touch_trigger2", ("c", 1): "prox_trigger2"}
    assert sorted(deerfly_touch.values()) == sorted(TOUCH_BITS.values())
    for (reg, bit), label in deerfly_touch.items():
        touch = (1 << bit, 0) if reg == "b" else (0, 1 << bit)
        pt = parse_deerfly(pack_deerfly(touch=touch))
        assert [k for k in TOUCH_BITS.values() if pt[k]] == [label], (reg, bit, label)

    # 2d. ntf 0x15 pressure is a 12-bit field (R16/R17)
    dp = decode_ntf(NTF_PRESSURE, b"\xff\xff")
    assert dp["trigger_pressure_raw"] == 0xFFF and dp["trigger_pressure"] == 1.0

    # 3. chunk stream round trip incl. a type with bit 5 set
    imu = struct.pack("<IH3h3h", 0x89ABCDEF, 0x0123, 1024, -1024, 0, 82, -82, 8192)
    items = [(NTF_IMU, imu), (NTF_BUTTONS, b"\x05"), (0x2B, b"\x01\x00"), (0x19, bytes(range(61)))]
    assert chunk_header(0x2B, 2) == (0x2B & 0x1F) | 2 << 5 | 1 << 11 | 0x8000
    assert unpack_chunks(pack_chunks(items)) == [(t, bytes(b)) for t, b in items]
    # A non-final fragment ends the notification (R13): fragments of 32 + 29 in ONE stream lose
    # 0x19, and so does a broken sequence (which also stops parsing).
    stream = pack_chunks(items, frag=32)
    assert unpack_chunks(stream) == [(t, bytes(b)) for t, b in items[:3]]
    broken = pack_chunks([(NTF_BUTTONS, b"\x05")]) + pack_chunk(0x19, bytes(29), seq=2, last=True) \
        + pack_chunks([(NTF_IMU, imu)])
    assert unpack_chunks(broken) == [(NTF_BUTTONS, b"\x05")]
    big = pack_chunks([(0x19, bytes(70))], frag=40)   # 40 + 30 > 63: the host drops it
    u = NtfUnpacker()
    assert u.feed(big[:42]) == [] and u.feed(big[42:]) == []

    # 3b. R13: a chunk split across two notifications. pack_notifications puts the non-final
    #     piece at the end of notification 1 and the final piece first in notification 2.
    split_items = [(NTF_IMU, imu), (0x19, bytes(range(61))), (NTF_BUTTONS, b"\x05")]
    ntfs = pack_notifications(split_items)
    assert [len(n) for n in ntfs] == [49, 39], [len(n) for n in ntfs]
    assert ntfs[0][20:22] == struct.pack("<H", chunk_header(0x19, 27, seq=0, last=False))
    assert ntfs[1][:2] == struct.pack("<H", chunk_header(0x19, 34, seq=1, last=True))
    u = NtfUnpacker()                                  # stateful, one per controller: reassembles
    assert u.feed(ntfs[0]) == [(NTF_IMU, imu)]
    assert u.feed(ntfs[1]) == [(0x19, bytes(range(61))), (NTF_BUTTONS, b"\x05")]
    # the old stateless call loses the chunk (and, as a broken sequence, the rest of ntf 2)
    assert unpack_chunks(ntfs[0]) == [(NTF_IMU, imu)] and unpack_chunks(ntfs[1]) == []
    # whole chunks only: everything fits, nothing fragments
    assert pack_notifications(items[:3]) == [pack_chunks(items[:3])]
    for n in pack_notifications([(t, bytes(40)) for t in (1, 2, 3)] + [(0x19, bytes(63))]):
        assert len(n) <= NTF_STREAM_BUDGET

    # 4. IMU SI conversion with the controller-reported scales
    d = decode_ntf(NTF_IMU, imu)
    assert d["imu_ts_us"] == 0x0123_89ABCDEF
    assert abs(d["accel_mps2"][0] - G) < 1e-4 and abs(d["accel_mps2"][1] + G) < 1e-4
    assert abs(d["gyro_radps"][2] - 1000 * DEG2RAD) < 1e-3       # 8192 LSB at 8.192 LSB/dps
    assert abs(d["gyro_radps"][0] - 10.009765625 * DEG2RAD) < 1e-5
    cfg = parse_imu_config(pack_imu_config())
    assert cfg["accel_range_mg"] == 32000 and cfg["gyro_odr_hz"] == 500
    assert cfg["accel_g_per_lsb"] == 1 / 1024.0
    assert abs(cfg["gyro_dps_per_lsb"] - 1 / 8.192) < 1e-7

    # 5. LED: payload, clamp, validation, scheduler
    assert pack_led_config(33333, 19, -9).hex() == "35820000" "13000000" "f7ffffff"
    assert parse_led_config(pack_led_config(*LED_DEFAULT)) == LED_DEFAULT
    assert controller_apply_led(11111, 200, 0) == (True, (11111, 75, 0))   # silently clamped
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert controller_apply_led(50, 75, 0) == (False, None)             # ot > p
        assert controller_apply_led(699, 19, 0) == (True, (699, 19, 0))     # accepted, but < 700 us
        assert controller_apply_led(700, 19, 0) == (True, (700, 19, 0))     # no warning
    assert len(caught) == 2 and all("700 us" in str(w.message) for w in caught)
    assert controller_apply_led(500_001, 19, 0) == (False, None)            # p > 500 ms
    assert controller_apply_led(500_000, 0, 0) == (True, (500_000, 0, 0))  # ot = 0: LEDs off
    st, en = next_pulse_start(1_000_000, 11111, 5000, 75)
    assert (st - (5000 - 37)) % 11111 == 0 and st - 1_000_000 >= 700 and en - st == 75
    st, _ = next_pulse_start(10_000 - 100, 10_000, 0, 0)       # 100 µs ahead < 700 -> next period
    assert st == 20_000
    st, _ = next_pulse_start(0, 300, 0, 0)                     # p < 700: floor applied once only,
    assert st == 600                                           # so the lead ends up < 700 µs
    st, _ = next_pulse_start(0, 1000, -9, 19)                  # negative offset wraps
    assert st % 1000 == (-9 - 9) % 1000

    # 6. command payload builders
    assert pack_cal_read(0x1FC0, 32) == struct.pack("<II", 0x1FC0, 32)
    plan = cal_read_plan()
    assert len(plan) == 255 and plan[-1] == (0x1FC0, 32) and sum(n for _, n in plan) == CAL_BLOB_LEN
    assert pack_haptic_simple(300) == b"\xff" and pack_haptic_simple(0) == b"\x00"
    assert pack_haptic_freq(128, 160) == b"\x80\xa0\x00"
    assert pack_haptic_syncbuffer(b"\x10\x20") == b"\x02\x10\x20" + bytes(29)
    bi = parse_battery_info(struct.pack("<fIB", 87.0, 3912, 1))
    assert bi["battery_v"] == 3.912 and bi["battery_pct"] == 87.0

    print("selftest ok -- deerfly CRC + ntf repack/labels (buttons ntf4, touch/prox ntf9, "
          "stick ntf2, trigger/grip ntf3, idxcurl, pressure); hand-packed A6 ntf 0x17 vector; "
          "every ntf 9 bit vs TOUCH_BITS; 12-bit ntf 0x15; chunk stream + R13 cross-notification "
          "fragments (NtfUnpacker, pack_notifications); IMU SI from cmd 0x32; LED clamp/validate/"
          "scheduler + p < 700 us warning; cal/haptics/battery payloads.")


# ---- cli -----------------------------------------------------------------------------------

def _h(s):
    return bytes.fromhex(s.replace(" ", ""))


def _show(d):
    for k, v in d.items():
        if isinstance(v, (bytes, bytearray)):
            v = v.hex()
        print(f"  {k} = {v}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())
    p = sub.add_parser("parse", help="decode a raw 61-byte deerfly sample")
    p.add_argument("--sample", required=True)
    p.set_defaults(fn=lambda a: _show(parse_deerfly(_h(a.sample))))
    n = sub.add_parser("ntf", help="decode one notification register payload")
    n.add_argument("--type", required=True)
    n.add_argument("--value", required=True)
    n.set_defaults(fn=lambda a: _show(decode_ntf(int(a.type, 0), _h(a.value))))
    c = sub.add_parser("chunks", help="decode notification chunk streams (one controller, in order)")
    c.add_argument("--payload", required=True, action="append",
                   help="one notification's chunk stream, hex; repeat for consecutive notifications")

    def do_chunks(a):
        u = NtfUnpacker()                    # fragments may span the given notifications (R13)
        for i, pl in enumerate(a.payload):
            for t, body in u.feed(_h(pl)):
                print(f"[{i}] ntf {t:#04x} ({len(body)} B)")
                _show(decode_ntf(t, body))
    c.set_defaults(fn=do_chunks)
    led = sub.add_parser("led", help="build cmd 0x28 and model what the controller does with it")
    led.add_argument("--period", type=int, required=True)
    led.add_argument("--ontime", type=int, required=True)
    led.add_argument("--delay", type=int, default=0)
    led.add_argument("--now", type=int, default=0, help="host us, to show the next pulse")

    def do_led(a):
        print("  cmd 0x28 payload =", pack_led_config(a.period, a.ontime, a.delay).hex())
        msg = led_period_warning(a.period)
        if msg:
            print("  WARNING:", msg)
        with warnings.catch_warnings():      # already printed above
            warnings.simplefilter("ignore")
            ok, applied = controller_apply_led(a.period, a.ontime, a.delay)
        print("  controller:", f"applied p/ot/d = {applied}" if ok else "REJECTED (old config kept)")
        if ok and applied[1]:
            st, en = next_pulse_start(a.now, applied[0], applied[2], applied[1])
            print(f"  next pulse {st}..{en} us host time; duty {applied[1] / applied[0]:.4%}")
    led.set_defaults(fn=do_led)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
