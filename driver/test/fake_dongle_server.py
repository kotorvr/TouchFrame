#!/usr/bin/env python3
"""tools/fake_dongle.py served over TCP for driver/test/radio_fake_test.cpp.

Like `fake_dongle.py --tcp`, plus what the driver test needs:
  --framing hid   the stream as hidraw sees it: the client writes 65-byte OUT writes (0x00 + report)
                  and reads 64-byte IN reports. TCP may merge or split them; this server re-chunks.
  --caps-store    advertise LINK_CAP_STORE | LINK_CAP_HID in HELLO (the flash store is modelled
                  either way).
  --drift-ppm / --offset-us   a known dongle clock, so the test can check the time sync.
  --reboot-at S   power-cycle the dongle S seconds after the first host start (clock restarts,
                  flash survives).
  --hands H,H,..  one simulated controller per entry, ids 0x1122334455667701, ...02, ...: what each
                  answers to cmd 1 (left | right | unconf). Default: right,left (the fake's default).
  --stored I,I,.. those controllers (1-based) start paired in the dongle's flash (hand unknown), as
                  if paired in an earlier run. The flash identity is made up front.
  --control       also listen for test commands, one per line on a second port, each answered with
                  "ok ..." or "err ...":
                    drop ID        the controller goes out of range (it seeks and reconnects)
                    slot ID        the slot it is in (0 = none)
                    hand ID H      what it answers to cmd 1 from now on
                    pairs          the flash pairings: ID:SLOT:HAND ...
                  (ID = hex device id.)
Prints "control PORT" (with --control), then "ready PORT", when listening.
"""
import argparse
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import fake_dongle as F  # noqa: E402
import radio as R  # noqa: E402


class Control:
    """--control: line commands from the test on their own port (see the module doc)."""

    def __init__(self, fake):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.srv.setblocking(False)
        self.port = self.srv.getsockname()[1]
        self.conn, self.buf = None, b""

    def poll(self, fake):
        if self.conn is None:
            try:
                self.conn, _ = self.srv.accept()
                self.conn.setblocking(False)
            except BlockingIOError:
                return
        try:
            data = self.conn.recv(4096)
            if not data:
                self.conn.close()
                self.conn = None
                return
            self.buf += data
        except BlockingIOError:
            pass
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            reply = self.run(fake, line.decode().split())
            print(f"fake: control {line.decode()!r} -> {reply}", flush=True)
            self.conn.sendall((reply + "\n").encode())

    @staticmethod
    def run(fake, words):
        slot_of = lambda dev: next((s for s, sl in enumerate(fake.slots) if sl and sl["device_id"] == dev), 0)  # noqa: E731
        try:
            if words[0] == "pairs":
                return "ok " + " ".join(f"{p['device_id']:016x}:{p['slot']}:{p['hand']}" for p in fake.flash["pairs"])
            dev = int(words[1], 16)
            ctrl = fake._controller(dev)
            if words[0] == "slot":
                return f"ok {slot_of(dev)}"
            if words[0] == "drop":
                s = slot_of(dev)
                if not s or fake.slots[s]["state"] != 3:
                    return "err not connected"
                fake.drop_slot(s)
                return f"ok {s}"
            if words[0] == "hand":
                if not ctrl:
                    return "err no such controller"
                ctrl.set_hand(words[2])
                return "ok"
        except (IndexError, ValueError) as e:
            return f"err {e}"
        return "err unknown command"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--framing", choices=("raw", "hid"), default="raw")
    ap.add_argument("--caps-store", action="store_true")
    ap.add_argument("--drift-ppm", type=float, default=12.5)
    ap.add_argument("--offset-us", type=int, default=123456789)
    ap.add_argument("--reboot-at", type=float, default=0)
    ap.add_argument("--hands", default="right,left")
    ap.add_argument("--stored", default="")
    ap.add_argument("--control", action="store_true")
    ap.add_argument("--seconds", type=float, default=120, help="exit after this long")
    args = ap.parse_args()

    hid = args.framing == "hid"
    ctrls = [F.SimController(0x1122334455667700 + i + 1, hand=h) for i, h in enumerate(args.hands.split(","))]
    fake = F.FakeDongle(controllers=ctrls, clock_offset_us=args.offset_us, drift_ppm=args.drift_ppm, hid=hid)
    if args.stored:
        fake.flash.update(netaddr=0x5EED0001, key=bytes(range(16)), pairs=[])
        for i in args.stored.split(","):
            c = ctrls[int(i) - 1]
            c.paired = (fake.flash["netaddr"], fake.flash["key"])
            fake.flash["pairs"].append(dict(device_id=c.device_id, slot=0, hand=0))
    events = {"host_t": None}

    def patch(fk):
        orig = fk.handle

        def handle(cmd, body, rx_us):
            if cmd == R.CMD_HELLO and args.caps_store:
                saved = fk.emit

                def emit(evt, b):
                    if evt == R.EVT_HELLO:
                        h = R.unpack("link_hello_t", b)
                        h["caps"] |= 0x30  # LINK_CAP_STORE | LINK_CAP_HID
                        b = R.pack("link_hello_t", **h)
                    saved(evt, b)
                fk.emit = emit
                try:
                    orig(cmd, body, rx_us)
                finally:
                    fk.emit = saved
                return
            orig(cmd, body, rx_us)
            if cmd == R.CMD_HOST_START and events["host_t"] is None:
                events["host_t"] = time.monotonic()
        fk.handle = handle

    patch(fake)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(1)
    ctl = Control(fake) if args.control else None
    if ctl:
        print(f"control {ctl.port}", flush=True)  # before "ready": run.sh reads both once it sees ready
    print(f"ready {srv.getsockname()[1]}", flush=True)
    srv.settimeout(0.5)
    t_end = time.monotonic() + args.seconds
    rebooted = False
    while time.monotonic() < t_end:
        if ctl:
            ctl.poll(fake)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        conn.settimeout(0.001)
        fake.dtr = True
        inbuf = b""
        try:
            while time.monotonic() < t_end:
                try:
                    data = conn.recv(65536)
                    if not data:
                        break
                    if hid:
                        inbuf += data
                        while len(inbuf) >= R.HID_REPORT + 1:
                            fake.write(inbuf[:R.HID_REPORT + 1])
                            inbuf = inbuf[R.HID_REPORT + 1:]
                    else:
                        fake.write(data)
                except socket.timeout:
                    pass
                ht = events["host_t"]
                if ht and args.reboot_at and not rebooted and time.monotonic() - ht > args.reboot_at:
                    rebooted = True
                    print("fake: reboot", flush=True)
                    fake.reboot()
                    patch(fake)
                if ctl:
                    ctl.poll(fake)
                # Drain everything due (HID: one report per read()).
                for _ in range(64):
                    out = fake.read()
                    if not out:
                        break
                    conn.sendall(out)
        except OSError as e:
            print(f"fake: connection ended: {e}", flush=True)
        fake.dtr = False
        conn.close()
        print("fake: client gone", flush=True)


if __name__ == "__main__":
    main()
