#!/usr/bin/env python3
"""A software TouchFrame radio dongle speaking link v3 (radio-fw/src/link.h) — no hardware.

It models what the firmware does *at the USB link*, with simulated Touch Plus controllers behind
it, so PC software (tools/radio.py, the driver's RadioSource) can be tested before a dongle or a
controller exists:

  * HELLO, HOST_START/STATUS, STOP, TIME_PING with a dongle clock that has its own offset and drift;
  * pairing: a simulated controller advertises, then the real 0x12/0x11 exchange runs in memory
    (tools/pulsar_host.py builds the host side, the simulated controller decrypts it);
  * CONNECT -> WAITING -> NEGOTIATING -> CONNECTED, then EVT_INPUT and EVT_IMU streams at the
    configured rates (EVT_SAMPLE with LINK_HOST_COMPACT); DISCONNECT; link loss on request (drop_slot);
  * LINK_HOST_STORED: a "flash" identity + pairings that survive CMD_STOP and reboot(), pairings
    saved and let in automatically, PAIR_LIST / PAIR_FORGET;
  * REG_READ / WRITE / SUBSCRIBE against a per-controller register table; LED and HAPTIC are
    recorded (last_led / last_haptic) for tests to inspect; EVT_SOF once a second;
  * hid=True: the HID interface instead of the serial port. write() takes hidraw writes (65 bytes:
    0x00 + a 64-byte report), read() returns one 64-byte IN report at a time, and the interface
    is "open" only while an OUT report arrived in the last 2 s (else output is discarded).

As the firmware since BUILD-1b (docs/re/REVIEW-RE.md): slots are 1..4 (slot 0 is the negotiation
slot and never assigned); without LINK_HOST_PLACEHOLDER (real formats) EVT_INPUT carries flags bit 1
(arrival time), PCM haptics answer LINK_ERR_PENDING_RE, SIMPLE haptics need 40..561 Hz. Each
simulated controller answers cmd 1 (device_desc, REVIEW-RE R11) with its hand in bytes 16..23:
"left", "right" or "unconf" (SimController(hand=...); by default from the id's lowest bit, like
radio-fw's fake controller). Once a controller connects, the dongle reads it like host_core.c
got_hand(): "left"/"right" is stored with the pairing and, for the controller paired in this host
run, sent as a second EVT_PAIR(DONE) that carries only the hand; "unconf" changes nothing.

`pending_re=True` mimics the firmware before BUILD-1b: without LINK_HOST_PLACEHOLDER, controllers
connect but send no input or IMU events, and registers, LED and haptics answer LINK_ERR_PENDING_RE.

Use it in-process (Dongle(transport=FakeDongle())) or serve it:
  fake_dongle.py --pty               Linux/macOS: prints a /dev/pts path to open like /dev/ttyACM0
  fake_dongle.py --tcp 5555          one client at a time on 127.0.0.1:5555 (raw COBS frames)
"""
import argparse
import math
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import radio as R  # noqa: E402  (link.h mirror: formats, constants, COBS)

ADVERT_TYPE = 2
PULSAR_VERSION = 0x1701


REG_DEVICE_DESC = 0x01
LINK_HANDS = {"left": 1, "right": 2}  # link_hand; anything else ("unconf") is LINK_HAND_UNKNOWN


def device_desc(hand):
    """cmd 1's 32 bytes: four NUL-padded 8-byte fields, as radio-fw/src/ctrl_core.c builds them."""
    d = bytearray(32)
    for i, field in enumerate((b"oculus", b"rubyprq", hand.encode(), b"0x0c")):
        d[8 * i:8 * i + len(field)] = field
    return bytes(d)


def desc_hand(d):
    """link_hand from a cmd 1 answer, like host_core.c got_hand(): bytes 16..23, NUL-terminated."""
    if len(d) < 24:
        return 0
    return LINK_HANDS.get(bytes(d[16:24]).split(b"\0")[0].decode("latin-1"), 0)


class SimController:
    def __init__(self, device_id, seed=0, hand=None):
        self.device_id = device_id
        self.rng = random.Random(seed or device_id)
        self.paired = None   # (netaddr, key) once provisioned
        self.regs = {9: b"\x00\x00", 3: b"\x00\x00\x00", 0x17: bytes(8), 4: b"\x00", 0x2b: b"\x00",
                     0x15: struct.pack("<H", 3900), 0x0B: bytes(12), 0x16: bytes(2), 0x02: bytes(4),
                     # imu_config (docs/re/PERIPHERALS.md): accel +-32 g, gyro +-4000 dps, 500 Hz each,
                     # g and dps per count
                     0x32: struct.pack("<HHHHff", 32000, 4000, 500, 500, 1 / 1024, 1 / 8.192)}
        self.set_hand(hand or ("right" if device_id & 1 else "left"))  # radio-fw's fake: odd ids are right

    def set_hand(self, hand):
        """What cmd 1 says from now on: "left", "right" or "unconf"."""
        self.regs[REG_DEVICE_DESC] = device_desc(hand)

    @property
    def hand(self):
        """link_hand as the dongle reads it from cmd 1 (0 = unconf)."""
        return desc_hand(self.regs.get(REG_DEVICE_DESC, b""))

    def advert(self):
        return bytes([ADVERT_TYPE]) + struct.pack("<HH", PULSAR_VERSION, 0x0301) + \
            struct.pack("<Q", self.device_id) + bytes(19)


class FakeDongle:
    """Transport-compatible fake: write() feeds it commands, read() returns event bytes."""

    def __init__(self, controllers=None, pending_re=False, clock_offset_us=None, drift_ppm=None,
                 input_hz=500, imu_hz=500, dongle_id=0xD0D0CAFE12345678, seed=1, hid=False):
        self.rng = random.Random(seed)
        self.dtr = True
        self.hid = hid
        self.hid_last_out = None  # time of the last OUT report (hid)
        self.flash = dict(netaddr=0, key=bytes(16), pairs=[])  # survives CMD_STOP and reboot()
        self.sof_count, self.next_sof = 0, 0
        self.timeout = 0.05
        self.out = bytearray()
        self.inbuf = bytearray()
        self.pending_re = pending_re
        self.input_hz, self.imu_hz = input_hz, imu_hz
        self.dongle_id = dongle_id
        self.offset_us = self.rng.randrange(10 ** 6, 10 ** 9) if clock_offset_us is None else clock_offset_us
        self.drift = (self.rng.uniform(-20, 20) if drift_ppm is None else drift_ppm) * 1e-6
        self.t0_ns = time.monotonic_ns()
        self.controllers = list(controllers if controllers is not None else
                                [SimController(0x1122334455667701), SimController(0x1122334455667702)])
        self.mode = 0
        self.host = None
        self.pair = None
        self.slots = [None] * R.MAX_SLOTS
        self.subs = {}  # (slot, reg) -> period_ms
        self.timers = []  # (due_us, fn)
        self.last_led, self.last_haptic = {}, {}
        self.last_paired, self.hand_sent = None, False  # the second EVT_PAIR(DONE), with the hand
        self.events_dropped = 0
        self.beacons = 0

    # ---- clock
    def now_us(self):
        pc_us = (time.monotonic_ns() - self.t0_ns) / 1000
        return int(self.offset_us + pc_us * (1 + self.drift))

    def at(self, delay_us, fn):
        self.timers.append((self.now_us() + delay_us, fn))

    def reboot(self):
        """Power cycle: everything but the flash store is lost."""
        flash = self.flash
        self.__init__(self.controllers, self.pending_re, self.offset_us, self.drift * 1e6, self.input_hz,
                      self.imu_hz, self.dongle_id, hid=self.hid)
        self.flash = flash

    # ---- transport
    def hid_open(self):
        return self.hid_last_out is not None and time.monotonic() - self.hid_last_out < R.HID_OPEN_MS / 1000

    def write(self, data):
        if self.hid:  # one hidraw write = report number 0 + one 64-byte report
            if len(data) != R.HID_REPORT + 1 or data[0] != 0:
                raise OSError("hidraw write must be 65 bytes starting with report number 0")
            self.hid_last_out = time.monotonic()
            self._feed(R.hid_payload(data[1:]))
            return len(data)
        return self._feed(data)

    def _feed(self, data):
        for b in data:
            if b:
                self.inbuf.append(b)
                continue
            raw, self.inbuf = bytes(self.inbuf), bytearray()
            try:
                frame = R.cobs_decode(raw) if raw else b""
            except ValueError:
                continue
            if frame:
                self.handle(frame[0], frame[1:], self.now_us())
        return len(data)

    def read(self, n=4096):
        self.tick()
        if not self.out:
            time.sleep(0.002)
            self.tick()
        if self.hid:  # one IN report, or nothing
            if not self.out:
                return b""
            chunk, self.out = bytes(self.out[:R.HID_REPORT - 1]), self.out[R.HID_REPORT - 1:]
            return R.hid_reports(chunk)[0]
        chunk, self.out = bytes(self.out[:n]), self.out[n:]
        return chunk

    def close(self):
        pass

    def emit(self, evt, body):
        if not (self.hid_open() if self.hid else self.dtr):
            self.events_dropped += 1
            self.out.clear()  # pending output is discarded while closed
            return
        self.out += R.cobs_encode(bytes([evt]) + body)

    def result(self, tag, cmd, status=0, detail=0):
        self.emit(R.EVT_RESULT, R.pack("link_result_t", tag=tag, cmd=cmd, status=status, detail=detail))

    # ---- simulation
    def tick(self):
        now = self.now_us()
        if now >= self.next_sof:  # one EVT_SOF a second (1 ms frames)
            self.sof_count += 1000
            self.emit(R.EVT_SOF, R.pack("link_sof_t", usb_frame=(now // 1000) & 0x7FF, sof_count=self.sof_count,
                                        t_us=now))
            self.next_sof = now + 1000000
        due = sorted([t for t in self.timers if t[0] <= now], key=lambda t: t[0])
        self.timers = [t for t in self.timers if t[0] > now]
        for _, fn in due:
            fn()
        if self.mode == 2:
            self.beacons = (now - self.host["t_start"]) // 2000
            streams = not (self.pending_re and not self.host["flags"] & R.HOST_PLACEHOLDER)  # no real input format yet
            for s, slot in enumerate(self.slots):
                if slot and slot["state"] == 3 and streams:
                    self.stream(s, slot, now)

    def stream(self, s, slot, now):
        """Emit the input/IMU samples due since the last tick (capped so a stall can't flood)."""
        compact = self.host["flags"] & R.HOST_COMPACT
        real = not self.host["flags"] & R.HOST_PLACEHOLDER
        for kind, hz in (("input", self.input_hz), ("imu", 0 if compact else self.imu_hz)):
            if not hz:
                continue
            period = 10 ** 6 // hz
            nxt = slot["next_" + kind]
            if now - nxt > 50 * period:
                nxt = now - 50 * period
            while nxt <= now:
                slot["seq_" + kind] = (slot["seq_" + kind] + 1) & 0xFFFF
                ph = nxt / 1e6
                a = int(2048 + 2000 * math.sin(ph))
                g = int(4096 * math.sin(ph * 2))
                inp = dict(t_us=nxt, slot=s, flags=2 if real else slot["fmt_flags"], seq=slot["seq_" + kind],
                           buttons=(int(ph) & 1) << 0, battery_pct=87, touch=0x001, stick=[a - 2048, 0],
                           trigger=a, grip=4095 - a, pressure=0)
                if kind == "input" and compact:
                    inp["flags"] = 0 if real else inp["flags"] | 4  # real: the IMU stamp, scale from cmd 0x32
                    self.emit(R.EVT_SAMPLE, R.pack("link_sample_t", **inp, accel=[0, 0, 1024], gyro=[g, 0, 0]))
                elif kind == "input":
                    self.emit(R.EVT_INPUT, R.pack("link_input_t", **inp))
                else:
                    self.emit(R.EVT_IMU, R.pack("link_imu_t", t_us=nxt, slot=s, flags=0 if real else 5,
                                                seq=slot["seq_imu"], accel=[0, 0, 1024], gyro=[g, 0, 0],
                                                temp_raw=2500, bits=16, accel_fs_g=32, gyro_fs_dps=4000))
                nxt += period
            slot["next_" + kind] = nxt
        for (ss, reg), period_ms in list(self.subs.items()):
            if ss != s:
                continue
            key = ("sub_next", reg)
            if slot.get(key, 0) <= now:
                ctrl = slot["ctrl"]
                self.emit_reg(s, reg, 2, 0, ctrl.regs.get(reg, b""), 0, now)
                slot[key] = now + max(period_ms, 2) * 1000

    def emit_reg(self, slot, reg, kind, status, data, tag, t_us):
        self.emit(R.EVT_REG, R.pack("link_reg_event_t", t_us=t_us, tag=tag, slot=slot, reg=reg, kind=kind,
                                    status=status, len=len(data)) + bytes(data))

    def conn_event(self, s, state, reason=0, device_id=None):
        slot = self.slots[s]
        if slot:
            slot["state"] = state
        self.emit(R.EVT_CONN, R.pack("link_conn_event_t", t_us=self.now_us(), slot=s, state=state, reason=reason,
                                     rssi=-48, device_id=device_id if device_id is not None else
                                     (slot["device_id"] if slot else 0),
                                     pulsar_version=PULSAR_VERSION if state == 3 else 0))

    def pair_event(self, state, status=0, step=0, device_id=0, hand=0):
        if self.pair:
            self.pair["state"] = state
        self.emit(R.EVT_PAIR, R.pack("link_pair_event_t", t_us=self.now_us(), state=state, status=status,
                                     step=step, hand=hand, device_id=device_id,
                                     netaddr=self.host["netaddr"] if state == 5 else 0))

    def drop_slot(self, s):
        """Test hook: the controller in slot s goes out of range (it will seek and reconnect)."""
        if self.slots[s] and self.slots[s]["state"] == 3:
            self.conn_event(s, 4, reason=2)
            self.at(200000, lambda: self._negotiate(s))

    def _controller(self, device_id):
        return next((c for c in self.controllers if c.device_id == device_id), None)

    def _negotiate(self, s):
        slot = self.slots[s]
        if not slot or self.mode != 2:
            return
        ctrl = self._controller(slot["device_id"])
        if not ctrl or ctrl.paired != (self.host["netaddr"], self.host["key"]):
            return  # never seeks us: not paired to this identity
        self.conn_event(s, 2)
        self.at(30000, lambda: self._lock(s, ctrl))

    def _lock(self, s, ctrl):
        slot = self.slots[s]
        if not slot or slot["state"] != 2:
            return
        now = self.now_us()
        slot.update(ctrl=ctrl, next_input=now, next_imu=now,
                    fmt_flags=1 if self.host["flags"] & R.HOST_PLACEHOLDER else 0)
        self.conn_event(s, 3)
        if not self.host["flags"] & R.HOST_PLACEHOLDER and not self.pending_re:
            self.at(4000, lambda: self._got_hand(s, ctrl))  # host_core enumerate(): cmd 1 first, one TL round trip

    def _got_hand(self, s, ctrl):
        """host_core.c got_hand(): the cmd 1 answer. "unconf" stores nothing and sends nothing."""
        slot = self.slots[s]
        if not slot or slot["state"] != 3 or slot.get("ctrl") is not ctrl:
            return
        hand = ctrl.hand
        if not hand:
            return
        if self._stored():
            for p in self.flash["pairs"]:
                if p["device_id"] == ctrl.device_id:
                    p["hand"] = hand
        if ctrl.device_id == self.last_paired and not self.hand_sent:  # the pairing's DONE, now with the hand
            self.hand_sent = True
            self.emit(R.EVT_PAIR, R.pack("link_pair_event_t", t_us=self.now_us(), state=5, status=0, step=3,
                                         hand=hand, device_id=ctrl.device_id, netaddr=self.host["netaddr"]))

    def _pair_step(self, step):
        p = self.pair
        if not p or p["state"] in (5, 6, 7):
            return
        if step == "advert":
            for c in self.controllers:
                if c.paired is None and (not p["filter"] or p["filter"] == c.device_id):
                    adv = c.advert()
                    self.emit(R.EVT_ADVERT, R.pack("link_advert_t", t_us=self.now_us(), device_id=c.device_id,
                                                   rssi=-40, type=ADVERT_TYPE, pulsar_version=PULSAR_VERSION,
                                                   hw=0x0301, len=len(adv), raw=adv))
                    if p["auto"] and not p.get("target"):
                        p["target"] = c
            if p.get("target"):
                self.pair_event(2, device_id=p["target"].device_id)
                self.at(20000, lambda: self._pair_step("exchange"))
            else:
                self.at(100000, lambda: self._pair_step("advert"))
        elif step == "exchange":
            c = p["target"]
            self.pair_event(3, step=1, device_id=c.device_id)
            try:  # run the real pairing crypto both ways (tools/pulsar_host.py)
                import pulsar_host as H
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                hpriv, hpub = H.gen_host_keypair()
                cpriv, cpub = H.gen_host_keypair()
                wrap = H.wrap_key_from_shared(H.derive_shared_secret(hpriv, cpub))
                payload, _ = H.build_pairing_payload(wrap, self.host["netaddr"], self.host["key"])
                cwrap = H.wrap_key_from_shared(cpriv.exchange(X25519PublicKey.from_public_bytes(hpub)))
                base, key = H.parse_pairing_data(cwrap, payload)
                c.paired = (struct.unpack("<I", base)[0], key)
            except ImportError:  # no `cryptography`: skip the crypto, keep the event flow
                c.paired = (self.host["netaddr"], self.host["key"])
            self.pair_event(4, step=2, device_id=c.device_id)
            self.at(20000, lambda: (self.pair_event(5, step=3, device_id=c.device_id), self._pair_end(),
                                    self._paired(c.device_id), self._stored_pair(c.device_id)))

    def _paired(self, device_id):
        self.last_paired, self.hand_sent = device_id, False

    def _pair_end(self):
        self.pair = None if self.pair is None else dict(self.pair, state=0)

    # ---- flash store (LINK_HOST_STORED)
    def _stored(self):
        return self.mode == 2 and self.host["flags"] & R.HOST_STORED

    def _free_slot(self):
        """The first free slot, 1..4: slot 0 is the negotiation slot (REVIEW-RE R1)."""
        return next((i for i in range(1, R.MAX_SLOTS) if not self.slots[i]), None)

    def _allow(self, device_id, want):
        """CMD_CONNECT's effect; returns the slot or None."""
        for s, sl in enumerate(self.slots):
            if sl and sl["device_id"] == device_id:
                return s
        if want is None or not 1 <= want < R.MAX_SLOTS or self.slots[want]:
            want = self._free_slot()
        if want is None:
            return None
        self.slots[want] = dict(state=1, device_id=device_id, seq_input=0, seq_imu=0, fmt_flags=0)
        self.conn_event(want, 1)
        self.at(50000, lambda: self._negotiate(want))
        return want

    def _stored_pair(self, device_id):
        if not self._stored():
            return
        pairs = self.flash["pairs"]
        old = next((p for p in pairs if p["device_id"] == device_id), None)
        s = self._allow(device_id, old["slot"] if old else None)
        pairs[:] = [p for p in pairs if p["device_id"] != device_id][-(R.MAX_PAIRINGS - 1):]
        pairs.append(dict(device_id=device_id, slot=s if s is not None else 0, hand=0))

    # ---- commands
    def handle(self, cmd, body, rx_us):
        tag = body[0] if body else 0
        bad = lambda: self.result(tag, cmd, 1)  # noqa: E731
        if cmd == R.CMD_STOP:
            self.mode, self.host, self.pair = 0, None, None
            self.slots = [None] * R.MAX_SLOTS
            self.emit(R.EVT_STATUS, struct.pack(R.STATUS_FMT, R.LINK_VERSION, 0, self.now_us() & 0xFFFFFFFF, 0, 0,
                                                0, 0, 0) + R.pack_config(R.config()))
        elif cmd == R.CMD_STATUS:
            self.emit(R.EVT_STATUS, struct.pack(R.STATUS_FMT, R.LINK_VERSION, 0, self.now_us() & 0xFFFFFFFF, 0, 0,
                                                0, 0, 0) + R.pack_config(R.config()))
        elif cmd == R.CMD_HELLO:
            caps = 0x3F | 0x700 | (0 if self.pending_re else 0xF800)  # incl. STORE (bit 4), HID (bit 5)
            self.emit(R.EVT_HELLO, R.pack("link_hello_t", version=R.LINK_VERSION, mode=self.mode, caps=caps,
                                          build=20261004, dongle_id=self.dongle_id, now_us=self.now_us(),
                                          max_slots=R.MAX_SLOTS))
            self.result(tag, cmd)
        elif cmd == R.CMD_TIME_PING:
            if len(body) != R.sizeof("link_time_ping_t"):
                return
            p = R.unpack("link_time_ping_t", body)
            self.emit(R.EVT_TIME, R.pack("link_time_pong_t", tag=p["tag"], seq=p["seq"], host_t=p["host_t"],
                                         dongle_rx_us=rx_us, dongle_tx_us=self.now_us()))
        elif cmd == R.CMD_HOST_START:
            if len(body) != R.sizeof("link_host_start_t"):
                return bad()
            h = R.unpack("link_host_start_t", body)
            chmap = int.from_bytes(h["chmap"], "little") & ((1 << 37) - 1) | 1 | 1 << 17 | 1 << 36  # seek (R10)
            if bin(chmap).count("1") < 8:
                return bad()
            for s in range(R.MAX_SLOTS):
                if self.slots[s] and self.slots[s]["state"] in (2, 3, 4):
                    self.conn_event(s, 1, reason=4)
            self.mode = 2
            netaddr, key = h["netaddr"], h["link_key"]
            if h["flags"] & R.HOST_STORED:
                if not self.flash["netaddr"]:
                    self.flash.update(netaddr=self.rng.randrange(1, 0xFFFFFFFF), key=os.urandom(16), pairs=[])
                netaddr, key = self.flash["netaddr"], self.flash["key"]
            self.host = dict(netaddr=netaddr, key=key, flags=h["flags"], t_start=self.now_us())
            for s, slot in enumerate(self.slots):  # slots allowed before this start seek us again
                if slot:
                    self.at(100000, lambda s=s: self._negotiate(s))
            loaded = 0  # (_allow schedules its own negotiation)
            if h["flags"] & R.HOST_STORED:
                for p in reversed(self.flash["pairs"]):
                    if self._allow(p["device_id"], p["slot"]) is None:
                        break
                    loaded += 1
            self.result(tag, cmd, 0, loaded)
        elif cmd == R.CMD_PAIR_LIST:
            f = self.flash
            self.emit(R.EVT_PAIRINGS, R.pack("link_pairings_t", netaddr=f["netaddr"], count=len(f["pairs"]), flags=1,
                                             writes_left=100) +
                      b"".join(R.pack("link_pairing_t", **p) for p in f["pairs"]))
            self.result(tag, cmd, 0, len(f["pairs"]))
        elif cmd == R.CMD_PAIR_FORGET:
            if len(body) != R.sizeof("link_pair_forget_t"):
                return bad()
            c = R.unpack("link_pair_forget_t", body)
            every = bool(c["flags"] & (R.FORGET_ALL | R.FORGET_IDENTITY))
            if not every and not c["device_id"]:
                return bad()
            gone = [p for p in self.flash["pairs"] if every or p["device_id"] == c["device_id"]]
            if self._stored():
                for s, sl in enumerate(self.slots):
                    if sl and any(p["device_id"] == sl["device_id"] for p in gone):
                        self.conn_event(s, 0, reason=1)
                        self.slots[s] = None
            self.flash["pairs"] = [p for p in self.flash["pairs"] if p not in gone]
            if c["flags"] & R.FORGET_IDENTITY:
                self.flash.update(netaddr=0, key=bytes(16))
            self.result(tag, cmd, 0, len(gone))
        elif cmd == R.CMD_HOST_STATUS:
            if self.mode != 2:
                return self.result(tag, cmd, 2)
            slots = b"".join(R.pack("link_slot_status_t", state=sl["state"] if sl else 0, rssi=-48 if sl else 0,
                                    pulsar_version=PULSAR_VERSION if sl and sl["state"] == 3 else 0,
                                    device_id=sl["device_id"] if sl else 0) for sl in self.slots)
            self.emit(R.EVT_HOST_STATUS, R.pack("link_host_status_t", version=R.LINK_VERSION, mode=self.mode,
                                                host_flags=self.host["flags"],
                                                pair_state=self.pair["state"] if self.pair else 0,
                                                now_us=self.now_us(), netaddr=self.host["netaddr"],
                                                beacons=self.beacons, events_dropped=self.events_dropped,
                                                channel_mhz=4) + slots)
            self.result(tag, cmd)
        elif cmd == R.CMD_PAIR_START:
            if len(body) != R.sizeof("link_pair_start_t"):
                return bad()
            if self.mode != 2:
                return self.result(tag, cmd, 2)
            if self.pair and self.pair["state"] in (1, 2, 3, 4):
                return self.result(tag, cmd, 3)
            p = R.unpack("link_pair_start_t", body)
            self.pair = dict(state=0, filter=p["device_id"], auto=bool(p["flags"] & R.PAIR_AUTO))
            self.result(tag, cmd)
            self.pair_event(1)
            self.at(50000, lambda: self._pair_step("advert"))
        elif cmd == R.CMD_PAIR_STOP:
            if self.pair:
                self.pair_event(7)
                self.pair = None
            self.result(tag, cmd)
        elif cmd == R.CMD_CONNECT:
            if len(body) != R.sizeof("link_connect_t"):
                return bad()
            if self.mode != 2:
                return self.result(tag, cmd, 2)
            c = R.unpack("link_connect_t", body)
            s = c["slot"]
            have = next((i for i, sl in enumerate(self.slots) if sl and sl["device_id"] == c["device_id"]), None)
            if have is not None:
                return self.result(tag, cmd, 0, have)  # already allowed there
            if s == 0xFF:
                s = self._free_slot()
                if s is None:
                    return self.result(tag, cmd, 6)
            elif s >= R.MAX_SLOTS:
                return bad()
            elif s == 0 or self.slots[s]:
                return self.result(tag, cmd, 6, s)
            self.slots[s] = dict(state=1, device_id=c["device_id"], seq_input=0, seq_imu=0, fmt_flags=0)
            self.result(tag, cmd, 0, s)
            self.conn_event(s, 1)
            self.at(50000, lambda: self._negotiate(s))
        elif cmd == R.CMD_DISCONNECT:
            if len(body) != R.sizeof("link_disconnect_t"):
                return bad()
            d = R.unpack("link_disconnect_t", body)
            if d["slot"] >= R.MAX_SLOTS:
                return bad()
            slot = self.slots[d["slot"]]
            if slot:
                self.conn_event(d["slot"], 0 if d["flags"] & 1 else 1, reason=1)
                if d["flags"] & 1:
                    self.slots[d["slot"]] = None
                self.subs = {k: v for k, v in self.subs.items() if k[0] != d["slot"]}
            self.result(tag, cmd)
        elif cmd in (R.CMD_REG_READ, R.CMD_REG_WRITE, R.CMD_REG_SUBSCRIBE, R.CMD_LED, R.CMD_HAPTIC):
            self.peripheral(cmd, tag, body)
        elif cmd == R.CMD_FAKE_START:
            self.result(tag, cmd, 2)  # a fake host can't also be a fake controller
        elif cmd == R.CMD_SELFTEST:
            self.emit(R.EVT_TEXT, b"selftest: fake dongle, nothing to test")
            self.result(tag, cmd)
        elif cmd in (R.CMD_CONFIG, R.CMD_SWEEP, R.CMD_DFU):
            self.emit(R.EVT_TEXT, b"fake dongle: sniffer commands not modelled")
        else:
            self.result(tag, cmd, 9)

    def peripheral(self, cmd, tag, body):
        names = {R.CMD_REG_READ: "link_reg_cmd_t", R.CMD_REG_WRITE: "link_reg_cmd_t",
                 R.CMD_REG_SUBSCRIBE: "link_reg_sub_t", R.CMD_LED: "link_led_t", R.CMD_HAPTIC: "link_haptic_t"}
        n = R.sizeof(names[cmd])
        if len(body) < n:
            return self.result(tag, cmd, 1)
        f = R.unpack(names[cmd], body)
        tail = body[n:]
        if self.mode != 2:
            return self.result(tag, cmd, 2)
        if f["slot"] >= R.MAX_SLOTS:
            return self.result(tag, cmd, 1)
        if self.pending_re and not self.host["flags"] & R.HOST_PLACEHOLDER:
            return self.result(tag, cmd, 5)
        slot = self.slots[f["slot"]]
        if not slot or slot["state"] != 3:
            return self.result(tag, cmd, 10)
        ctrl = slot["ctrl"]
        if cmd == R.CMD_REG_READ:
            self.result(tag, cmd)
            data = ctrl.regs.get(f["reg"], b"")
            if f["len"]:
                data = data[:f["len"]]
            self.at(4000, lambda: self.emit_reg(f["slot"], f["reg"], 0, 0 if f["reg"] in ctrl.regs else 8,
                                                data, tag, self.now_us()))
        elif cmd == R.CMD_REG_WRITE:
            if f["len"] > R.REG_MAX or len(tail) != f["len"]:
                return self.result(tag, cmd, 1)
            ctrl.regs[f["reg"]] = bytes(tail)
            self.result(tag, cmd)
            self.at(4000, lambda: self.emit_reg(f["slot"], f["reg"], 1, 0, b"", tag, self.now_us()))
        elif cmd == R.CMD_REG_SUBSCRIBE:
            key = (f["slot"], f["reg"])
            if f["flags"] & 1:
                self.subs.pop(key, None)
            else:
                self.subs[key] = f["period_ms"]
            self.result(tag, cmd)
        elif cmd == R.CMD_LED:
            real = not self.host["flags"] & R.HOST_PLACEHOLDER
            if f["mode"] > 2 or (f["mode"] == 2 and (f["period_us"] < R.LED_MIN_PERIOD_US or not f["on_us"])) or \
                    (f["mode"] == R.LED_ON and real):  # real controllers cannot hold the LEDs on
                return self.result(tag, cmd, 1)
            f["on_us"] = min(f["on_us"], R.LED_MAX_ON_US)
            self.last_led[f["slot"]] = f
            self.result(tag, cmd)
        elif cmd == R.CMD_HAPTIC:
            real = not self.host["flags"] & R.HOST_PLACEHOLDER
            if f["mode"] > 2 or f["pcm_len"] > R.PCM_MAX or len(tail) != f["pcm_len"] or \
                    (real and f["mode"] == R.HAPTIC_SIMPLE and not 40 <= f["freq_hz"] <= 561):
                return self.result(tag, cmd, 1)
            if real and f["mode"] == R.HAPTIC_PCM:
                return self.result(tag, cmd, 5)  # 0x9d (3-bit ADPCM) is not implemented
            self.last_haptic[f["slot"]] = dict(f, pcm=bytes(tail))
            self.result(tag, cmd)


def serve_pty(fake):
    import pty
    import select
    master, slave = pty.openpty()
    import tty
    tty.setraw(slave)
    print(os.ttyname(slave), flush=True)
    while True:
        r, _, _ = select.select([master], [], [], 0.002)
        if r:
            fake.write(os.read(master, 4096))
        data = fake.read()
        if data:
            os.write(master, data)


def serve_tcp(fake, port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print(f"fake dongle on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        conn.settimeout(0.002)
        fake.dtr = True
        pending = b""  # --hid: TCP does not keep the 65-byte hidraw writes apart
        try:
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    if fake.hid:
                        pending += data
                        while len(pending) >= R.HID_REPORT + 1:
                            fake.write(pending[:R.HID_REPORT + 1])
                            pending = pending[R.HID_REPORT + 1:]
                    else:
                        fake.write(data)
                except socket.timeout:
                    pass
                out = fake.read()
                if out:
                    conn.sendall(out)
        except OSError:
            pass
        fake.dtr = False  # port closed: host mode keeps running, events are dropped
        conn.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pty", action="store_true")
    g.add_argument("--tcp", type=int, metavar="PORT")
    ap.add_argument("--pending-re", action="store_true", help="behave like today's firmware (RE-pending stubs)")
    ap.add_argument("--input-hz", type=int, default=500)
    ap.add_argument("--imu-hz", type=int, default=500)
    ap.add_argument("--hid", action="store_true",
                    help="model the HID interface: 65-byte writes, 64-byte reads (with --tcp: raw reports)")
    ap.add_argument("--paired", action="store_true",
                    help="simulated controllers start paired (to whatever identity HOST_START gives)")
    args = ap.parse_args()
    fake = FakeDongle(pending_re=args.pending_re, input_hz=args.input_hz, imu_hz=args.imu_hz, hid=args.hid)
    if args.paired:
        orig = fake.handle

        def handle(cmd, body, rx_us):
            orig(cmd, body, rx_us)
            if cmd == R.CMD_HOST_START and fake.host:
                for c in fake.controllers:
                    c.paired = (fake.host["netaddr"], fake.host["key"])
        fake.handle = handle
    if args.pty:
        serve_pty(fake)
    else:
        serve_tcp(fake, args.tcp)


if __name__ == "__main__":
    main()
