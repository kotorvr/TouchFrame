#!/usr/bin/env python3
"""PC side of the TouchFrame radio dongle (radio-fw/). Needs pyserial (and hidapi for --hid).

  radio.py ports                         list dongles (app and bootloader)
  radio.py dfu --package build/x.zip     reboot the dongle into its bootloader and flash it
  radio.py status
  radio.py sweep [--dwell-us 1000] [--rounds 20]
                                         peak RSSI per MHz, 2400-2500: where is traffic?
  radio.py sniff --preset discovery [--out cap.jsonl] [--seconds 30]
  radio.py sniff --freq 26 --prefix 0xAA --base 0xFACEB00C --no-crc --out pairing.jsonl

Host mode (link v3):
  radio.py hello                         link version, mode, capability bits (which formats are real)
  radio.py host [--pair any|ID] [--placeholder] [--compact] [--raw] [--seconds N]
                                         be the controllers' host: beacons, pairing, connections; prints
                                         events. The dongle keeps its identity and pairings in flash.
  radio.py host --identity f.json ...    driver-owned identity instead: netaddr, link key and the paired
                                         list live in f.json (created on first use), nothing in flash
  radio.py pairings                      the pairings stored on the dongle
  radio.py forget ID|all [--identity-too]
                                         remove stored pairings (--identity-too: new netaddr + key, so
                                         every controller must pair again)
  radio.py ping [--count 50]             time-sync quality (rtt, drift) between dongle and PC
  radio.py fake [--paired] [--slot 0] [--real-conn]
                                         loopback rig: this dongle plays a Touch Plus (second dongle)
  radio.py selftest                      on-dongle X25519 / AES / HW-CCM checks

--hid (any command) talks over the dongle's HID interface instead of the serial port (the Frame has
no cdc_acm; on Windows the serial port is the default).

Wire format: radio-fw/src/link.h (COBS frames, 0x00-terminated, type byte + body). The Python mirror
of every struct is FORMATS/SIZES below; radio-fw/test/test_link.py checks them against link.h.
tools/fake_dongle.py is a software dongle for testing PC code without hardware.
"""
import argparse
import glob
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial missing: python -m pip install pyserial")

APP_VIDPID = (0x1209, 0x0001)    # radio-fw/src/usb_descriptors.c
BOOT_VIDPID = (0x1915, 0x521F)   # Nordic open USB bootloader on the PCA10059

CMD_CONFIG, CMD_STOP, CMD_STATUS, CMD_SWEEP, CMD_DFU = 0x01, 0x02, 0x03, 0x04, 0x05
EVT_PACKET, EVT_STATUS, EVT_SWEEP, EVT_TEXT = 0x81, 0x82, 0x83, 0x84

CONFIG_FMT = "<BBII8sBBBBBBBBBBIIHB40sBB"  # link_config_t
STATUS_FMT = "<BBIIIIIB"                    # link_status_t header, then link_config_t
PACKET_FMT = "<IBbBBB"                      # link_packet_t
LINK_VERSION = 3

# ---------------------------------------------------------------- link v3 (radio-fw/src/link.h)
# Host-mode commands: body starts with a u8 tag; the dongle answers each with one EVT_RESULT.
CMD_HELLO = 0x06
CMD_HOST_START, CMD_HOST_STATUS, CMD_PAIR_START, CMD_PAIR_STOP = 0x10, 0x11, 0x12, 0x13
CMD_CONNECT, CMD_DISCONNECT, CMD_REG_READ, CMD_REG_WRITE, CMD_REG_SUBSCRIBE = 0x14, 0x15, 0x16, 0x17, 0x18
CMD_LED, CMD_HAPTIC, CMD_TIME_PING, CMD_FAKE_START, CMD_SELFTEST = 0x19, 0x1A, 0x1B, 0x1C, 0x1D
CMD_PAIR_LIST, CMD_PAIR_FORGET = 0x1E, 0x1F
EVT_RESULT, EVT_HELLO, EVT_HOST_STATUS, EVT_ADVERT, EVT_PAIR = 0x85, 0x86, 0x87, 0x88, 0x89
EVT_CONN, EVT_REG, EVT_INPUT, EVT_IMU, EVT_TIME, EVT_UPLINK = 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F
EVT_SAMPLE, EVT_SOF, EVT_PAIRINGS = 0x90, 0x91, 0x92

MODES = {0: "idle", 1: "sniffer", 2: "host", 3: "fake_ctrl"}
STATUS_CODES = {0: "ok", 1: "bad args", 2: "wrong state", 3: "busy", 4: "timeout",
                5: "pending RE (format not pinned)", 6: "no slot", 7: "crypto", 8: "rejected",
                9: "unknown command", 10: "not connected", 11: "queue full"}
SLOT_STATES = {0: "free", 1: "waiting", 2: "negotiating", 3: "connected", 4: "lost"}
PAIR_STATES = {0: "idle", 1: "scanning", 2: "linking", 3: "key_exchange", 4: "provision", 5: "done",
               6: "failed", 7: "stopped"}
CONN_REASONS = {0: "", 1: "requested", 2: "timeout", 3: "rejected", 4: "host restart"}
REG_KINDS = {0: "read", 1: "write_ack", 2: "notify"}
CAPS = {0: "sniffer", 1: "host", 2: "fake_ctrl", 3: "placeholder", 4: "store", 5: "hid", 8: "real_pairing",
        9: "real_conn_neg", 10: "real_nonce", 11: "real_hreg", 12: "real_input", 13: "real_imu", 14: "real_led",
        15: "real_haptic"}
HOST_AUTO_ACCEPT, HOST_DM_BEACONS, HOST_RAW_UPLINKS, HOST_PLACEHOLDER = 1, 2, 4, 8
HOST_COMPACT, HOST_STORED = 16, 32
PAIR_AUTO = 1
FORGET_ALL, FORGET_IDENTITY = 1, 2
HANDS = {0: "unknown", 1: "left", 2: "right"}
FAKE_PAIRED, FAKE_STREAM_INPUT, FAKE_STREAM_IMU, FAKE_REAL_CONN = 1, 2, 4, 8
LED_OFF, LED_ON, LED_STROBE = 0, 1, 2
HAPTIC_STOP, HAPTIC_SIMPLE, HAPTIC_PCM = 0, 1, 2
MAX_SLOTS, REG_MAX, PCM_MAX, MAX_PAIRINGS = 5, 32, 48, 8
LED_MIN_PERIOD_US, LED_MAX_ON_US = 700, 75
HID_OPEN_MS, HID_REPORT = 2000, 64

# struct name -> (format, field names). "name*N" = N consecutive values gathered into a list.
# Sizes are checked against the _Static_asserts in link.h at import (link_h_sizes below) and by
# radio-fw/test/test_link.py.
FORMATS = {
    "link_tag_t": ("<B", "tag"),
    "link_result_t": ("<BBBB", "tag cmd status detail"),
    "link_hello_t": ("<BBHIQQB3s", "version mode caps build dongle_id now_us max_slots reserved"),
    "link_host_start_t": ("<BBHI16s5sb", "tag flags session_nonce netaddr link_key chmap tx_power_dbm"),
    "link_slot_status_t": ("<BbHQIIQ", "state rssi pulsar_version device_id rx_packets rx_bad_mic last_rx_us"),
    "link_host_status_t": ("<BBBBQIIIIIIIB3s", "version mode host_flags pair_state now_us netaddr beacons "
                           "dm_beacons uplinks crc_errors late_beacons events_dropped channel_mhz reserved"),
    "link_pair_start_t": ("<BBHQ", "tag flags timeout_s device_id"),
    "link_advert_t": ("<QQbBHHB32s", "t_us device_id rssi type pulsar_version hw len raw"),
    "link_pair_event_t": ("<QBBBBQI", "t_us state status step hand device_id netaddr"),
    "link_pair_forget_t": ("<BBHQ", "tag flags reserved device_id"),
    "link_pairings_t": ("<IBBH", "netaddr count flags writes_left"),
    "link_pairing_t": ("<QBBH", "device_id slot hand reserved"),
    "link_connect_t": ("<BBBBQ", "tag slot flags reserved device_id"),
    "link_disconnect_t": ("<BBB", "tag slot flags"),
    "link_conn_event_t": ("<QBBBbQHH", "t_us slot state reason rssi device_id pulsar_version reserved"),
    "link_reg_cmd_t": ("<BBBB", "tag slot reg len"),
    "link_reg_sub_t": ("<BBBBH", "tag slot reg flags period_ms"),
    "link_reg_event_t": ("<QBBBBBB", "t_us tag slot reg kind status len"),
    "link_input_t": ("<QBBHBBH2hHHH", "t_us slot flags seq buttons battery_pct touch stick*2 trigger grip pressure"),
    "link_sample_t": ("<QBBHBBH2hHHH3h3h", "t_us slot flags seq buttons battery_pct touch stick*2 trigger grip "
                      "pressure accel*3 gyro*3"),
    "link_sof_t": ("<HHIQ", "usb_frame reserved sof_count t_us"),
    "link_imu_t": ("<QBBH3i3ihBBHH", "t_us slot flags seq accel*3 gyro*3 temp_raw bits accel_fs_g "
                   "gyro_fs_dps reserved"),
    "link_led_t": ("<BBBBIIiI", "tag slot mode intensity period_us on_us phase_us led_mask"),
    "link_haptic_t": ("<BBBBHHBB", "tag slot mode amplitude freq_hz duration_ms pcm_len reserved"),
    "link_time_ping_t": ("<B3sIQ", "tag reserved seq host_t"),
    "link_time_pong_t": ("<B3sIQQQ", "tag reserved seq host_t dongle_rx_us dongle_tx_us"),
    "link_fake_start_t": ("<BBBBQI16s", "tag flags slot reserved device_id netaddr link_key"),
    "link_uplink_t": ("<QBBbBB", "t_us slot channel_mhz rssi flags len"),
    "link_config_t": (CONFIG_FMT, None),
    "link_status_t": (STATUS_FMT + CONFIG_FMT[1:], None),
    "link_packet_t": (PACKET_FMT, None),
}
# The same sizes as link.h's _Static_asserts. A mismatch here means the two files drifted.
SIZES = {"link_tag_t": 1, "link_result_t": 4, "link_hello_t": 28, "link_host_start_t": 30,
         "link_slot_status_t": 28, "link_host_status_t": 44, "link_pair_start_t": 12, "link_advert_t": 55,
         "link_pair_event_t": 24, "link_connect_t": 12, "link_disconnect_t": 3, "link_conn_event_t": 24,
         "link_reg_cmd_t": 4, "link_reg_sub_t": 6, "link_reg_event_t": 14, "link_input_t": 26,
         "link_imu_t": 44, "link_led_t": 20, "link_haptic_t": 10, "link_time_ping_t": 16,
         "link_time_pong_t": 32, "link_fake_start_t": 32, "link_uplink_t": 13, "link_config_t": 81,
         "link_status_t": 104, "link_packet_t": 9, "link_sample_t": 38, "link_sof_t": 16,
         "link_pair_forget_t": 12, "link_pairings_t": 8, "link_pairing_t": 12}
for _n, (_f, _) in FORMATS.items():
    assert struct.calcsize(_f) == SIZES[_n], f"{_n}: radio.py {struct.calcsize(_f)} != link.h {SIZES[_n]}"
# link_host_status_t is followed by LINK_MAX_SLOTS link_slot_status_t (link.h asserts 44 + 5 * 28).
SLOT_STATUS_SIZE = SIZES["link_slot_status_t"]


def _fields(name):
    out = []
    for f in FORMATS[name][1].split():
        n, _, k = f.partition("*")
        out.append((n, int(k) if k else 1))
    return out


def layout(name):
    """[(field, count, struct code)] for a link.h struct ("5s" for byte arrays)."""
    codes = re.findall(r"\d*[a-zA-Z]", FORMATS[name][0][1:])
    codes = [c for c in codes for _ in range(1 if c.endswith("s") else int(c[:-1] or 1))]
    out, i = [], 0
    for n, k in _fields(name):
        out.append((n, k, codes[i][-1] if k > 1 else codes[i]))
        i += k
    return out


def sizeof(name):
    return SIZES[name]


def pack(name, **kw):
    """Pack a link.h struct; missing fields are zero (bytes fields: zero-filled)."""
    vals = []
    for n, k, code in layout(name):
        v = kw.pop(n, None)
        if code.endswith("s"):
            vals.append(bytes(v or b""))
        elif k > 1:
            vals += [int(x) for x in (v if v is not None else [0] * k)]
        else:
            vals.append(int(v or 0))
    if kw:
        raise TypeError(f"{name}: unknown fields {sorted(kw)}")
    return struct.pack(FORMATS[name][0], *vals)


def unpack(name, body, offset=0):
    """Unpack a link.h struct from body[offset:] into a dict ("name*N" fields become lists)."""
    v = struct.unpack_from(FORMATS[name][0], body, offset)
    out, i = {}, 0
    for n, k in _fields(name):
        out[n] = list(v[i:i + k]) if k > 1 else v[i]
        i += k
    return out


def decode_event(evt, body):
    """(name, dict) for any dongle -> PC frame. Unknown types give ("unknown", {"type", "body"})."""
    if evt == EVT_RESULT:
        r = unpack("link_result_t", body)
        r["status_name"] = STATUS_CODES.get(r["status"], str(r["status"]))
        return "result", r
    if evt == EVT_HELLO:
        h = unpack("link_hello_t", body)
        h["caps_names"] = [n for b, n in CAPS.items() if h["caps"] >> b & 1]
        return "hello", h
    if evt == EVT_HOST_STATUS:
        s = unpack("link_host_status_t", body)
        base = sizeof("link_host_status_t")
        s["slot"] = [unpack("link_slot_status_t", body, base + i * SLOT_STATUS_SIZE) for i in range(MAX_SLOTS)]
        return "host_status", s
    if evt == EVT_ADVERT:
        a = unpack("link_advert_t", body)
        a["raw"] = a["raw"][:a["len"]]
        return "advert", a
    if evt == EVT_PAIR:
        return "pair", unpack("link_pair_event_t", body)
    if evt == EVT_CONN:
        return "conn", unpack("link_conn_event_t", body)
    if evt == EVT_REG:
        r = unpack("link_reg_event_t", body)
        n = sizeof("link_reg_event_t")
        r["data"] = bytes(body[n:n + r["len"]])
        return "reg", r
    if evt == EVT_INPUT:
        return "input", unpack("link_input_t", body)
    if evt == EVT_IMU:
        return "imu", unpack("link_imu_t", body)
    if evt == EVT_SAMPLE:
        return "sample", unpack("link_sample_t", body)
    if evt == EVT_SOF:
        return "sof", unpack("link_sof_t", body)
    if evt == EVT_PAIRINGS:
        p = unpack("link_pairings_t", body)
        n = sizeof("link_pairings_t")
        p["pairings"] = [unpack("link_pairing_t", body, n + i * sizeof("link_pairing_t")) for i in range(p["count"])]
        return "pairings", p
    if evt == EVT_TIME:
        return "time", unpack("link_time_pong_t", body)
    if evt == EVT_UPLINK:
        u = unpack("link_uplink_t", body)
        n = sizeof("link_uplink_t")
        u["data"] = bytes(body[n:n + u["len"]])
        return "uplink", u
    if evt == EVT_TEXT:
        return "text", {"text": body.decode(errors="replace")}
    if evt == EVT_STATUS:
        return "status", parse_status(body)
    if evt == EVT_PACKET:
        ts, freq, rssi, crc_ok, rxmatch, length = struct.unpack_from(PACKET_FMT, body)
        return "packet", dict(t_us=ts, frequency=freq, rssi=rssi, crc_ok=crc_ok, rxmatch=rxmatch,
                              data=bytes(body[struct.calcsize(PACKET_FMT):][:length]))
    return "unknown", {"type": evt, "body": bytes(body)}


class LinkError(Exception):
    def __init__(self, cmd, status):
        super().__init__(f"command 0x{cmd:02x}: {STATUS_CODES.get(status, status)}")
        self.cmd, self.status = cmd, status


class TimeSync:
    """Dongle clock (us) -> PC clock, from CMD_TIME_PING samples (link.h link_time_pong_t).

    Keeps the lowest-RTT samples and fits offset + drift by least squares. pc_t and the result
    are in the same unit as host_t (pass ns from time.monotonic_ns / CLOCK_MONOTONIC_RAW)."""

    def __init__(self, window=64):
        self.samples, self.window = [], window  # (pc_mid, dongle_mid_us, rtt)

    def add(self, pong, t_recv):
        rtt = (t_recv - pong["host_t"]) - (pong["dongle_tx_us"] - pong["dongle_rx_us"]) * 1000
        pc_mid = (pong["host_t"] + t_recv) / 2
        d_mid = (pong["dongle_rx_us"] + pong["dongle_tx_us"]) / 2
        self.samples.append((pc_mid, d_mid, rtt))
        self.samples = self.samples[-self.window:]
        return rtt

    def fit(self):
        """(slope, intercept) with pc_ns = slope * dongle_us + intercept, from the best half."""
        best = sorted(self.samples, key=lambda s: s[2])[:max(2, len(self.samples) // 2)]
        if len(best) < 2:
            pc, d, _ = best[0]
            return 1000.0, pc - 1000.0 * d
        n = len(best)
        mx = sum(d for _, d, _ in best) / n
        my = sum(p for p, _, _ in best) / n
        sxx = sum((d - mx) ** 2 for _, d, _ in best)
        slope = sum((d - mx) * (p - my) for p, d, _ in best) / sxx if sxx else 1000.0
        return slope, my - slope * mx

    def to_pc(self, dongle_us):
        slope, icpt = self.fit()
        return slope * dongle_us + icpt


# docs/PROTOCOL.md Q1: Nrf_2Mbit, whitening off, CRC-24 0x108421 / 0xFFFFFF, BALEN 4, big-endian.
# Discovery/pairing/DM-beacon have no S0 byte; the connected link has a 1-byte S0 (0x04).
# base0/prefix[0] = logical address 0; base1/prefix[1..7] = logical addresses 1..7 (rx_mask selects).
def config(base0=0xFACEB00C, base1=0, prefix=(0xAA, 0, 0, 0, 0, 0, 0, 0), rx_mask=0x01, frequency=2,
           s0len=0, follow=0, follow_rx=1, **kw):
    c = dict(mode=1, frequency=frequency, base0=base0, base1=base1, prefix=tuple(prefix)[:8] + (0,) * 8,
             rx_mask=rx_mask, balen=4, big_endian=1, lflen=8, s0len=s0len, s1len=0, statlen=0, maxlen=255,
             crc_len=3, crc_skip_addr=0, crc_poly=0x108421, crc_init=0xFFFFFF, hop_dwell_ms=0, hop_count=0,
             hop_list=[], follow=follow, follow_rx=follow_rx)
    c.update(kw)
    c["prefix"] = tuple(c["prefix"])[:8]
    return c

DATA_CHANNELS = [4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46,
                 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78]
PRESETS = {
    "discovery": config(frequency=2),  # controller adverts + host DM beacons, logical addr 0
    # Pairing on 2426: base = the controller's device-id low word (advert bytes 5-8), prefix 0xAA.
    "pairing": config(frequency=26),
}


# ---------------------------------------------------------------- framing

def cobs_encode(data):
    out, block = bytearray(), bytearray()
    for b in data:
        if b == 0:
            out += bytes([len(block) + 1]) + block
            block = bytearray()
        else:
            block.append(b)
            if len(block) == 254:
                out += b"\xff" + block
                block = bytearray()
    out += bytes([len(block) + 1]) + block
    return bytes(out) + b"\x00"


def cobs_decode(data):
    out, i = bytearray(), 0
    while i < len(data):
        code = data[i]
        if code == 0 or i + code > len(data):
            raise ValueError("bad COBS frame")
        out += data[i + 1:i + code]
        i += code
        if code != 0xFF and i < len(data):
            out.append(0)
    return bytes(out)


# ---------------------------------------------------------------- HID transport (link.h "Framing")

def hid_reports(stream):
    """Split link bytes into 64-byte HID reports: [n][n bytes][zero pad]."""
    out = []
    for i in range(0, len(stream), HID_REPORT - 1):
        chunk = stream[i:i + HID_REPORT - 1]
        out.append(bytes([len(chunk)]) + chunk + bytes(HID_REPORT - 1 - len(chunk)))
    return out


def hid_payload(report):
    """The link bytes in one 64-byte report (n = 0: keepalive, nothing)."""
    n = report[0] if report else 0
    if n > HID_REPORT - 1:
        raise ValueError(f"bad HID report length byte {n}")
    return bytes(report[1:1 + n])


class HidTransport:
    """The dongle's HID interface (interface 2 of 1209:0001) as a byte stream with the serial
    port's write/read interface. Sends a keepalive report each second so the dongle keeps the
    interface "open" (link.h: an OUT report within LINK_HID_OPEN_MS)."""

    def __init__(self, path=None, device=None):
        if device is None:  # `device`: anything with hidapi's write(bytes) / read(size, timeout_ms) (tests)
            try:
                import hid
            except ImportError:
                sys.exit("hidapi missing: python -m pip install hidapi")
            if path is None:
                hits = [d for d in hid.enumerate(*APP_VIDPID) if d.get("interface_number") in (2, -1)]
                if not hits:
                    sys.exit("no TouchFrame radio dongle HID interface found")
                path = hits[0]["path"]
            device = hid.device()
            device.open_path(path)
        self.dev = device
        self.dtr = True  # accepted and ignored (serial-port compatibility)
        self.last_out = 0.0
        self.write(b"")  # open the interface now

    def write(self, data):
        for rep in hid_reports(bytes(data)) or [bytes(HID_REPORT)]:
            self.dev.write(b"\x00" + rep)  # report number 0, then the report
        self.last_out = time.monotonic()

    def read(self, n):
        if time.monotonic() - self.last_out > 1.0:
            self.write(b"")
        rep = self.dev.read(HID_REPORT, 50)
        return hid_payload(bytes(rep)) if rep else b""


class Dongle:
    """One dongle on a serial port (or `hid=True`: its HID interface). `transport` (anything with
    write/read and a dtr attribute, e.g. tools/fake_dongle.py's FakeDongle) replaces the port in tests."""

    def __init__(self, port=None, transport=None, hid=False):
        if transport is None:
            transport = HidTransport() if hid else serial.Serial(port, 115200, timeout=0.05)
        self.ser = transport
        self.ser.dtr = True  # the firmware only streams packets while DTR is set
        self.buf = bytearray()
        self.next_tag = 1
        self.pending = []  # events that arrived while request() waited for its result

    def send(self, cmd, body=b""):
        self.ser.write(cobs_encode(bytes([cmd]) + body))

    def request(self, cmd, struct_name=None, tail=b"", timeout=2.0, check=True, **fields):
        """Send a v3 command (tag filled in) and wait for its EVT_RESULT.

        Returns (result dict, [(name, event) ...] that arrived meanwhile, in order). Other async
        events are also queued on self.pending for the caller's event loop. Raises LinkError on a
        non-OK status when check is set."""
        tag = self.next_tag
        self.next_tag = self.next_tag % 255 + 1
        body = pack(struct_name or "link_tag_t", tag=tag, **fields) + bytes(tail)
        self.send(cmd, body)
        seen = []
        deadline = time.monotonic() + timeout  # absolute: streams keep frames() alive forever
        for t, b in self.frames(timeout):
            if time.monotonic() > deadline:
                break
            name, ev = decode_event(t, b)
            if name == "result" and ev["tag"] == tag and ev["cmd"] == cmd:
                if check and ev["status"]:
                    raise LinkError(cmd, ev["status"])
                return ev, seen
            seen.append((name, ev))
            self.pending.append((name, ev))
        raise TimeoutError(f"no EVT_RESULT for command 0x{cmd:02x}")

    def events(self, timeout):
        """Yield (name, event) for every frame (queued ones first) until `timeout` s of silence."""
        while self.pending:
            yield self.pending.pop(0)
        for t, b in self.frames(timeout):
            yield decode_event(t, b)

    # ---- v3 conveniences
    def hello(self):
        _, seen = self.request(CMD_HELLO)
        hello = [e for n, e in seen if n == "hello"]
        if not hello:
            raise LinkError(CMD_HELLO, 9)
        self.pending = [p for p in self.pending if p[0] != "hello"]
        return hello[-1]

    def host_start(self, netaddr, link_key, session_nonce, flags=HOST_DM_BEACONS, chmap=(1 << 37) - 1,
                   tx_power_dbm=8):
        return self.request(CMD_HOST_START, "link_host_start_t", flags=flags, session_nonce=session_nonce,
                            netaddr=netaddr, link_key=bytes(link_key), chmap=chmap.to_bytes(5, "little"),
                            tx_power_dbm=tx_power_dbm)[0]

    def pairings(self):
        """The dongle's stored identity and pairings (EVT_PAIRINGS), any mode."""
        _, seen = self.request(CMD_PAIR_LIST)
        self.pending = [p for p in self.pending if p[0] != "pairings"]
        return [e for n, e in seen if n == "pairings"][-1]

    def forget(self, device_id=0, all=False, identity=False):
        """Remove stored pairings; returns how many went."""
        flags = (FORGET_ALL if all else 0) | (FORGET_IDENTITY if identity else 0)
        return self.request(CMD_PAIR_FORGET, "link_pair_forget_t", flags=flags, device_id=device_id)[0]["detail"]

    def host_status(self):
        _, seen = self.request(CMD_HOST_STATUS)
        self.pending = [p for p in self.pending if p[0] != "host_status"]
        return [e for n, e in seen if n == "host_status"][-1]

    def time_ping(self, seq):
        """One ping; returns (pong, t_recv_ns) or None on timeout. Other events stay queued."""
        t0 = time.monotonic_ns()
        self.send(CMD_TIME_PING, pack("link_time_ping_t", tag=0, seq=seq, host_t=t0))
        deadline = time.monotonic() + 0.5
        for t, b in self.frames(0.5):
            if time.monotonic() > deadline:
                break
            name, ev = decode_event(t, b)
            if name == "time" and ev["seq"] == seq:
                return ev, time.monotonic_ns()
            self.pending.append((name, ev))
        return None

    def frames(self, timeout, idle=False):
        """Yield (type, body) until `timeout` seconds pass without a frame.
        With idle=True, also yield (None, b"") whenever a read times out."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            end = self.buf.find(b"\x00")
            if end >= 0:  # frames left over from an earlier read come first
                raw, self.buf = bytes(self.buf[:end]), self.buf[end + 1:]
                try:
                    frame = cobs_decode(raw) if raw else b""
                except ValueError:
                    continue
                if frame:
                    deadline = time.monotonic() + timeout
                    yield frame[0], frame[1:]
                continue
            chunk = self.ser.read(4096)
            if chunk:
                self.buf += chunk
            elif idle:
                yield None, b""

    def wait_for(self, evt, timeout=2.0):
        for t, body in self.frames(timeout):
            if t == EVT_TEXT:
                print("dongle:", body.decode(errors="replace"), file=sys.stderr)
            if t == evt:
                return body
        sys.exit(f"no reply (event 0x{evt:02x}) from the dongle")

    def status(self):
        self.send(CMD_STATUS)
        return parse_status(self.wait_for(EVT_STATUS))


CONFIG_SCALARS = ("mode frequency base0 base1").split()
CONFIG_TAIL = ("rx_mask balen big_endian lflen s0len s1len statlen maxlen crc_len crc_skip_addr "
               "crc_poly crc_init hop_dwell_ms hop_count").split()


def parse_status(body):
    n = struct.calcsize(STATUS_FMT)
    version, running, now_us, received, dropped, fbeacons, fblind, flocked = struct.unpack_from(STATUS_FMT, body)
    v = struct.unpack_from(CONFIG_FMT, body, n)
    cfg = dict(zip(CONFIG_SCALARS, v[:4]))
    cfg["prefix"] = list(v[4])
    cfg.update(zip(CONFIG_TAIL, v[5:19]))
    cfg["hop_list"] = list(v[19][: cfg["hop_count"]])
    cfg["follow"], cfg["follow_rx"] = v[20], v[21]
    if version != LINK_VERSION:
        print(f"warning: firmware link version {version}, tool expects {LINK_VERSION}", file=sys.stderr)
    return dict(running=bool(running), now_us=now_us, received=received, dropped=dropped,
                follow=dict(beacons=fbeacons, blind=fblind, locked=bool(flocked)), config=cfg)


def pack_config(c):
    hops = list(c.get("hop_list", []))
    prefix = bytes(tuple(c["prefix"])[:8]).ljust(8, b"\0")
    return struct.pack(CONFIG_FMT, c["mode"], c["frequency"], c["base0"], c["base1"], prefix,
                       c["rx_mask"], c["balen"], c["big_endian"], c["lflen"], c["s0len"], c["s1len"],
                       c["statlen"], c["maxlen"], c["crc_len"], c["crc_skip_addr"], c["crc_poly"],
                       c["crc_init"], c.get("hop_dwell_ms", 0), len(hops), bytes(hops).ljust(40, b"\0"),
                       c["follow"], c["follow_rx"])


# ---------------------------------------------------------------- ports

def find_ports(vidpid):
    return [p.device for p in serial.tools.list_ports.comports() if (p.vid, p.pid) == vidpid]


def open_dongle(args):
    return Dongle(hid=True) if getattr(args, "hid", False) else Dongle(app_port(args))


def app_port(args):
    if args.port:
        return args.port
    ports = find_ports(APP_VIDPID)
    if not ports:
        boot = find_ports(BOOT_VIDPID)
        hint = f" (a dongle is in its bootloader on {boot[0]}: flash it with `radio-fw/build.sh flash`)" if boot else ""
        sys.exit("no TouchFrame radio dongle found" + hint)
    return ports[0]


def cmd_ports(args):
    for p in serial.tools.list_ports.comports():
        kind = {APP_VIDPID: "TouchFrame radio", BOOT_VIDPID: "Nordic bootloader (DFU)"}.get((p.vid, p.pid))
        if kind:
            print(f"{p.device}\t{kind}\tserial {p.serial_number}")


def find_nrfutil():
    exe = shutil.which("nrfutil")
    if exe:
        return exe
    pattern = os.path.expanduser("~/AppData/Local/Microsoft/WinGet/Packages/NordicSemiconductor.nrfutil_*/nrfutil.exe")
    hits = glob.glob(pattern)
    if hits:
        return hits[0]
    sys.exit("nrfutil not found (winget install NordicSemiconductor.nrfutil; nrfutil install nrf5sdk-tools)")


def cmd_dfu(args):
    boot = find_ports(BOOT_VIDPID)
    if not boot:
        port = app_port(args)
        print(f"rebooting {port} into the bootloader")
        Dongle(port).send(CMD_DFU)
        deadline = time.monotonic() + 10
        while not boot and time.monotonic() < deadline:
            time.sleep(0.3)
            boot = find_ports(BOOT_VIDPID)
        if not boot:
            sys.exit("bootloader did not appear; press the dongle's side RESET button (red LED pulses) and retry")
    print(f"flashing {args.package} via {boot[0]}")
    subprocess.run([find_nrfutil(), "nrf5sdk-tools", "dfu", "usb-serial", "-pkg", args.package,
                    "-p", boot[0]], check=True)


def cmd_status(args):
    print(json.dumps(Dongle(app_port(args)).status(), indent=2))


def cmd_sweep(args):
    d = Dongle(app_port(args))
    peak = [127] * 101
    for _ in range(args.rounds):
        d.send(CMD_SWEEP, struct.pack("<H", args.dwell_us))
        body = d.wait_for(EVT_SWEEP, timeout=5)
        peak = [min(a, b) for a, b in zip(peak, body[2:103])]
    print(f"peak RSSI over {args.rounds} sweeps of {args.dwell_us} us per MHz")
    for mhz, v in enumerate(peak):
        bar = "#" * max(0, 100 - v)
        mark = " D" if mhz in DATA_CHANNELS else (" disc" if mhz == 2 else (" pair" if mhz == 26 else ""))
        print(f"{2400 + mhz} -{v:3d} dBm {bar}{mark}")


def sniff_config(args):
    if args.connected is not None:
        # Host on AP1=0xF0 (logical 1), controller slots on AP2..AP6 = 0x01..0x05 (logical 2..6),
        # AP0=0xAA on BASE0 for discovery/DM adverts. base1 = the host network address.
        c = config(base0=0xFACEB00C, base1=args.connected, frequency=4, s0len=1,
                   prefix=(0xAA, 0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00),
                   rx_mask=0x7F if args.with_adverts else 0x7E,  # bits 1..6, optionally +bit0
                   follow=0 if args.no_follow else 1, follow_rx=1)
    else:
        c = dict(PRESETS[args.preset] if args.preset else PRESETS["discovery"])
    if args.base0 is not None:
        c["base0"] = args.base0
    if args.base1 is not None:
        c["base1"] = args.base1
    if args.base is not None:  # single-address alias -> logical address 0
        c["base0"] = args.base
    if args.prefix is not None:
        pre = [int(x, 0) for x in str(args.prefix).split(",")]
        c["prefix"] = (pre + [0] * 8)[:8]
    if args.rx_mask is not None:
        c["rx_mask"] = args.rx_mask
    if args.s0:
        c["s0len"] = 1
    for key in ("frequency", "balen", "maxlen", "mode", "statlen", "follow_rx"):
        v = getattr(args, key)
        if v is not None:
            c[key] = v
    if args.follow:
        c["follow"] = 1
    if args.little_endian:
        c["big_endian"] = 0
    if args.crc_skip_addr:
        c["crc_skip_addr"] = 1
    if args.no_crc:
        c["crc_len"] = 0
        c["follow"] = 0  # follow needs CRC to tell beacons apart
        if args.statlen is None:
            c["statlen"] = 3  # keep the CRC bytes in the capture
    if args.hop:
        c["hop_list"] = DATA_CHANNELS if args.hop == "data" else [int(x, 0) for x in args.hop.split(",")]
        c["hop_dwell_ms"] = args.dwell_ms
    return c


def cmd_sniff(args):
    cfg = sniff_config(args)
    d = Dongle(app_port(args))
    d.send(CMD_CONFIG, pack_config(cfg))
    st = parse_status(d.wait_for(EVT_STATUS))
    if not st["running"]:
        sys.exit("dongle rejected the config")
    print("sniffing:", json.dumps(st["config"]), file=sys.stderr)

    out = open(args.out, "a") if args.out else None
    t_end = time.monotonic() + args.seconds if args.seconds else None
    count = good = 0
    t0 = None
    last_status = time.monotonic()
    try:
        for t, body in d.frames(timeout=1e9, idle=True):
            now = time.monotonic()
            if t == EVT_PACKET:
                ts, freq, rssi, crc_ok, rxmatch, length = struct.unpack_from(PACKET_FMT, body)
                data = body[struct.calcsize(PACKET_FMT):][:length]
                count += 1
                good += crc_ok
                if args.crc_only and cfg["crc_len"] and not crc_ok:
                    continue
                t0 = ts if t0 is None else t0
                rel_ms = ((ts - t0) & 0xFFFFFFFF) / 1000
                if not args.quiet:
                    flag = ("ok " if crc_ok else "BAD") if cfg["crc_len"] else "---"
                    print(f"{rel_ms:12.3f} ms {2400 + freq} a{rxmatch} {rssi:4d} dBm {flag} {length:3d} {data.hex()}")
                if out:
                    out.write(json.dumps(dict(t_us=ts, mhz=2400 + freq, rssi=rssi, crc_ok=crc_ok,
                                              addr=rxmatch, data=data.hex())) + "\n")
            elif t == EVT_TEXT:
                print("dongle:", body.decode(errors="replace"), file=sys.stderr)
            elif t == EVT_STATUS:
                st = parse_status(body)
                f = st["follow"]
                tail = f", follow: {f['beacons']} beacons, {f['blind']} blind, {'LOCKED' if f['locked'] else 'unlocked'}" if cfg.get("follow") else ""
                print(f"[{count} packets, {good} CRC ok, dropped {st['dropped']}{tail}]", file=sys.stderr)
            if now - last_status > 5:
                d.send(CMD_STATUS)
                last_status = now
            if t_end and now > t_end:
                break
    except KeyboardInterrupt:
        pass
    finally:
        d.send(CMD_STOP)
        if out:
            out.close()
    print(f"{count} packets, {good} with CRC ok", file=sys.stderr)


# ---------------------------------------------------------------- host mode (link v3)

def format_event(name, e):
    """One human-readable line per event."""
    t = f"{e['t_us'] / 1e6:12.6f}" if "t_us" in e else " " * 12
    if name == "advert":
        return f"{t} advert id={e['device_id']:016x} rssi={e['rssi']} ver=0x{e['pulsar_version']:04x} hw=0x{e['hw']:04x}"
    if name == "pair":
        st = PAIR_STATES.get(e["state"], e["state"])
        extra = f" status={STATUS_CODES.get(e['status'], e['status'])}" if e["status"] else ""
        hand = f" hand={HANDS[e['hand']]}" if e["hand"] else ""
        return f"{t} pair {st} id={e['device_id']:016x} step={e['step']}{hand}{extra}"
    if name == "conn":
        return (f"{t} slot{e['slot']} {SLOT_STATES.get(e['state'], e['state'])} id={e['device_id']:016x} "
                f"rssi={e['rssi']} {CONN_REASONS.get(e['reason'], e['reason'])}")
    if name in ("input", "sample"):
        s = (f"{t} slot{e['slot']} {name} #{e['seq']} buttons={e['buttons']:x} stick={e['stick']} "
             f"trigger={e['trigger']} grip={e['grip']} touch={e['touch']:03x} pressure={e['pressure']} "
             f"battery={e['battery_pct']}%")
        return s + (f" accel={e['accel']} gyro={e['gyro']}" if name == "sample" else "")
    if name == "pairings":
        rows = ", ".join(f"{p['device_id']:016x}(slot {p['slot']}, {HANDS.get(p['hand'], p['hand'])})"
                         for p in e["pairings"]) or "none"
        return f"stored identity netaddr 0x{e['netaddr']:08x}; pairings: {rows}"
    if name == "sof":
        return f"{t} usb sof frame {e['usb_frame']} (#{e['sof_count']})"
    if name == "imu":
        return f"{t} slot{e['slot']} imu #{e['seq']} accel={e['accel']} gyro={e['gyro']} temp={e['temp_raw']}"
    if name == "reg":
        return (f"{t} slot{e['slot']} reg 0x{e['reg']:02x} {REG_KINDS.get(e['kind'], e['kind'])} "
                f"{STATUS_CODES.get(e['status'], e['status'])} {e['data'].hex()}")
    if name == "uplink":
        return f"{t} uplink slot{e['slot']} {2400 + e['channel_mhz']} rssi={e['rssi']} flags={e['flags']} {e['data'].hex()}"
    if name == "text":
        return f"dongle: {e['text']}"
    if name == "result":
        return f"result cmd=0x{e['cmd']:02x} tag={e['tag']} {e['status_name']} detail={e['detail']}"
    return f"{name} {e}"


def load_identity(path):
    """Host identity (netaddr + link key + paired controllers) as JSON; created on first use.
    The dongle keeps nothing across resets: this file is the host's persistent state."""
    if os.path.exists(path):
        with open(path) as f:
            ident = json.load(f)
    else:
        ident = {"netaddr": int.from_bytes(os.urandom(4), "little") | 1, "link_key": os.urandom(16).hex(),
                 "paired": {}}
        save_identity(path, ident)
        print(f"new host identity in {path}", file=sys.stderr)
    return ident


def save_identity(path, ident):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(ident, f, indent=2)


def cmd_hello(args):
    print(json.dumps(open_dongle(args).hello(), indent=2, default=lambda b: b.hex()))


def cmd_pairings(args):
    print(format_event("pairings", open_dongle(args).pairings()))


def cmd_forget(args):
    d = open_dongle(args)
    n = d.forget(0 if args.id == "all" else int(args.id, 16), all=args.id == "all", identity=args.identity_too)
    print(f"forgot {n} pairing(s)" + ("; new identity at the next host start" if args.identity_too else ""))


def cmd_host(args):
    d = open_dongle(args)
    hello = d.hello()
    if hello["version"] != LINK_VERSION:
        sys.exit(f"firmware link version {hello['version']}, tool expects {LINK_VERSION}: reflash")
    ident = load_identity(args.identity) if args.identity else None
    flags = HOST_DM_BEACONS | (HOST_AUTO_ACCEPT if args.auto_accept else 0) | \
        (HOST_RAW_UPLINKS if args.raw else 0) | (HOST_PLACEHOLDER if args.placeholder else 0) | \
        (HOST_COMPACT if args.compact else 0) | (0 if ident else HOST_STORED)
    session = int.from_bytes(os.urandom(2), "little")
    if ident:
        r = d.host_start(ident["netaddr"], bytes.fromhex(ident["link_key"]), session, flags=flags,
                         tx_power_dbm=args.tx_power)
        netaddr = ident["netaddr"]
    else:
        r = d.host_start(0, bytes(16), session, flags=flags, tx_power_dbm=args.tx_power)
        netaddr = d.host_status()["netaddr"]
    print(f"host up: netaddr 0x{netaddr:08x} ({'file ' + args.identity if ident else 'stored on the dongle'}), "
          f"caps {hello['caps_names']}", file=sys.stderr)
    if not ident:
        print(f"{r['detail']} stored pairing(s) allowed in", file=sys.stderr)
    for dev, slot in (ident["paired"].items() if ident else ()):
        r, _ = d.request(CMD_CONNECT, "link_connect_t", slot=slot, device_id=int(dev, 16), check=False)
        print(f"connect {dev} -> slot {slot}: {STATUS_CODES[r['status']]}", file=sys.stderr)
    if args.pair:
        dev = 0 if args.pair == "any" else int(args.pair, 16)
        d.request(CMD_PAIR_START, "link_pair_start_t", flags=PAIR_AUTO if not args.scan_only else 0,
                  timeout_s=args.pair_timeout, device_id=dev)
    t_end = time.monotonic() + args.seconds if args.seconds else None
    last_status = time.monotonic()
    try:
        for name, e in d.events(timeout=1e9):
            if name in ("input", "imu", "sample") and args.quiet_streams:
                continue
            print(format_event(name, e))
            if name == "pair" and e["state"] == 5 and ident:  # DONE: remember it and let it connect
                dev = f"{e['device_id']:016x}"
                r, _ = d.request(CMD_CONNECT, "link_connect_t", slot=0xFF, device_id=e["device_id"], check=False)
                if r["status"] == 0:
                    ident["paired"][dev] = r["detail"]
                    save_identity(args.identity, ident)
                    print(f"paired {dev}, slot {r['detail']} (saved to {args.identity})", file=sys.stderr)
            now = time.monotonic()
            if now - last_status > 5:
                s = d.host_status()
                slots = " ".join(f"{i}:{SLOT_STATES[x['state']]}" for i, x in enumerate(s["slot"]))
                print(f"[beacons {s['beacons']} uplinks {s['uplinks']} crc_err {s['crc_errors']} "
                      f"late {s['late_beacons']} dropped {s['events_dropped']} | {slots}]", file=sys.stderr)
                last_status = now
            if t_end and now > t_end:
                break
    except KeyboardInterrupt:
        pass
    if args.stop:
        d.send(CMD_STOP)


def cmd_ping(args):
    d = open_dongle(args)
    ts = TimeSync()
    rtts = []
    for i in range(args.count):
        got = d.time_ping(i + 1)
        if got:
            rtts.append(ts.add(*got) / 1000)
        time.sleep(args.interval)
    if not rtts:
        sys.exit("no EVT_TIME replies")
    slope, icpt = ts.fit()
    rtts.sort()
    print(f"{len(rtts)}/{args.count} pongs, rtt us min {rtts[0]:.0f} median {rtts[len(rtts) // 2]:.0f} "
          f"max {rtts[-1]:.0f}; drift {(slope / 1000 - 1) * 1e6:+.1f} ppm")


def cmd_fake(args):
    d = open_dongle(args)
    flags = (FAKE_STREAM_INPUT if not args.no_input else 0) | (FAKE_STREAM_IMU if not args.no_imu else 0) |         (FAKE_REAL_CONN if args.real_conn else 0)
    kw = {}
    if args.paired:
        ident = load_identity(args.identity)
        flags |= FAKE_PAIRED
        kw = dict(netaddr=ident["netaddr"], link_key=bytes.fromhex(ident["link_key"]))
    d.request(CMD_FAKE_START, "link_fake_start_t", flags=flags, slot=args.slot,
              device_id=int(args.device_id, 16) if args.device_id else 0, **kw)
    print("fake controller running (CMD_STOP or Ctrl-C to end)", file=sys.stderr)
    try:
        for name, e in d.events(timeout=1e9):
            print(format_event(name, e))
    except KeyboardInterrupt:
        d.send(CMD_STOP)


def cmd_selftest(args):
    d = open_dongle(args)
    r, seen = d.request(CMD_SELFTEST, timeout=10, check=False)
    for name, e in seen:
        if name == "text":
            print(e["text"])
    print("selftest", "passed" if r["status"] == 0 else f"FAILED (bits 0x{r['detail']:02x})")
    sys.exit(1 if r["status"] else 0)


def int0(s):
    return int(s, 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", help="serial port (default: first TouchFrame dongle)")
    ap.add_argument("--hid", action="store_true", help="use the HID interface (link v3 commands only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ports").set_defaults(fn=cmd_ports)
    p = sub.add_parser("dfu")
    p.add_argument("--package", default=os.path.join(os.path.dirname(__file__), "..", "radio-fw", "build",
                                                     "touchframe-radio.zip"))
    p.set_defaults(fn=cmd_dfu)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    p = sub.add_parser("sweep")
    p.add_argument("--dwell-us", type=int, default=1000)
    p.add_argument("--rounds", type=int, default=20)
    p.set_defaults(fn=cmd_sweep)
    p = sub.add_parser("sniff")
    p.add_argument("--preset", choices=sorted(PRESETS))
    p.add_argument("--connected", type=int0, metavar="NETADDR",
                   help="follow the connected link with host network address NETADDR (hears host + "
                        "controllers, follows the channel hop). Get NETADDR from the Quest or by address search.")
    p.add_argument("--no-follow", action="store_true", help="with --connected, stay on one channel")
    p.add_argument("--with-adverts", action="store_true", help="with --connected, also receive logical address 0")
    p.add_argument("--frequency", "--freq", type=int, help="MHz above 2400")
    p.add_argument("--prefix", help="AP0[,AP1,...] access-address prefixes, e.g. 0xAA or 0xAA,0xF0,0x01")
    p.add_argument("--base", type=int0, help="base address for logical address 0 (alias for --base0)")
    p.add_argument("--base0", type=int0)
    p.add_argument("--base1", type=int0, help="base for logical addresses 1..7")
    p.add_argument("--rx-mask", type=int0, help="RXADDRESSES bitmask (bit n = logical address n)")
    p.add_argument("--s0", action="store_true", help="expect a 1-byte S0 (the connected link has one)")
    p.add_argument("--follow", action="store_true", help="follow the channel hop from beacons")
    p.add_argument("--follow-rx", type=int, help="logical address the beacons arrive on (default 1)")
    p.add_argument("--balen", type=int)
    p.add_argument("--maxlen", type=int)
    p.add_argument("--statlen", type=int)
    p.add_argument("--mode", type=int, help="0 Nrf_1Mbit, 1 Nrf_2Mbit (default), 3 Ble_1Mbit, 4 Ble_2Mbit")
    p.add_argument("--little-endian", action="store_true")
    p.add_argument("--no-crc", action="store_true", help="accept every address match; keeps 3 CRC bytes")
    p.add_argument("--crc-skip-addr", action="store_true")
    p.add_argument("--crc-only", action="store_true", help="hide packets whose CRC failed")
    p.add_argument("--hop", help="'data' (the 37 Pulsar data channels) or a list like 4,6,8")
    p.add_argument("--dwell-ms", type=int, default=50)
    p.add_argument("--seconds", type=float)
    p.add_argument("--out", help="append packets as JSON lines")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_sniff)

    default_ident = os.path.join(os.path.expanduser("~"), ".touchframe", "radio-host.json")
    sub.add_parser("hello", help="link version, mode and capabilities").set_defaults(fn=cmd_hello)
    p = sub.add_parser("host", help="run as the Pulsar host: beacons, pairing, connections, events")
    p.add_argument("--identity", metavar="FILE",
                   help="driver-owned identity: netaddr/key/paired list in FILE (created if missing; e.g. "
                        f"{default_ident}). Default: the dongle's flash identity")
    p.add_argument("--pair", metavar="ID|any", help="pair a controller in pairing mode (device id hex, or any)")
    p.add_argument("--scan-only", action="store_true", help="with --pair: only report adverts")
    p.add_argument("--pair-timeout", type=int, default=60)
    p.add_argument("--auto-accept", action="store_true", help="accept any controller holding our key")
    p.add_argument("--placeholder", action="store_true",
                   help="placeholder connected-link formats: loopback with a `fake` dongle ONLY")
    p.add_argument("--raw", action="store_true", help="report every uplink (EVT_UPLINK)")
    p.add_argument("--compact", action="store_true", help="EVT_SAMPLE (input + IMU in one event; use on HID)")
    p.add_argument("--tx-power", type=int, default=8, help="dBm, -40..8")
    p.add_argument("--quiet-streams", action="store_true", help="hide input/IMU/sample events")
    p.add_argument("--seconds", type=float)
    p.add_argument("--stop", action="store_true", help="stop host mode on exit (default: keep running)")
    p.set_defaults(fn=cmd_host)
    sub.add_parser("pairings", help="identity and pairings stored on the dongle").set_defaults(fn=cmd_pairings)
    p = sub.add_parser("forget", help="remove stored pairings")
    p.add_argument("id", metavar="ID|all")
    p.add_argument("--identity-too", action="store_true", help="also replace the netaddr + key (all re-pair)")
    p.set_defaults(fn=cmd_forget)
    p = sub.add_parser("ping", help="time-sync quality: rtt and drift vs this PC")
    p.add_argument("--count", type=int, default=50)
    p.add_argument("--interval", type=float, default=0.05)
    p.set_defaults(fn=cmd_ping)
    p = sub.add_parser("fake", help="loopback rig: this dongle plays a Touch Plus")
    p.add_argument("--paired", action="store_true", help="start paired to --identity (skip pairing)")
    p.add_argument("--identity", default=default_ident)
    p.add_argument("--slot", type=int, default=0)
    p.add_argument("--device-id", help="hex; default = the dongle's own FICR id")
    p.add_argument("--no-input", action="store_true")
    p.add_argument("--no-imu", action="store_true")
    p.add_argument("--real-conn", action="store_true",
                   help="connect with the real request/negotiation formats (host without --placeholder)")
    p.set_defaults(fn=cmd_fake)
    sub.add_parser("selftest", help="on-dongle crypto/radio self-tests (X25519, AES, HW CCM)").set_defaults(fn=cmd_selftest)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
