#!/usr/bin/env python3
"""Link v3 tests, no hardware: link.h <-> tools/radio.py agreement, framing, and a full host-mode
session through radio.Dongle against tools/fake_dongle.py."""
import os
import random
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import radio as R  # noqa: E402
from fake_dongle import FakeDongle, SimController  # noqa: E402

LINK_H = open(os.path.join(ROOT, "radio-fw", "src", "link.h"), encoding="utf-8").read()


def c_constants():
    """NAME = value pairs from link.h enums and #defines."""
    out = {}
    nocomments = re.sub(r"//[^\n]*", "", LINK_H)
    for body in re.findall(r"enum[^{]*\{([^}]*)\}", nocomments):
        for item in body.split(","):
            if "=" in item:
                name, expr = (x.strip() for x in item.split("=", 1))
                out[name] = eval(expr.replace("1u", "1"), {}, dict(out))
    for m in re.finditer(r"^#define\s+([A-Z][A-Z0-9_]+)\s+(\d+)", LINK_H, re.M):
        out[m.group(1)] = int(m.group(2))
    return out


def test_link_h_matches_radio_py():
    sizes = {m.group(1): eval(m.group(2)) for m in
             re.finditer(r"_Static_assert\(sizeof\((\w+)\) == ([\d +*]+),", LINK_H)}
    assert set(sizes) == set(R.SIZES), set(sizes) ^ set(R.SIZES)
    for name, n in sizes.items():
        want = R.SIZES[name]
        if name == "link_host_status_t":  # radio.py keeps the header and the slot array apart
            want += R.MAX_SLOTS * R.SIZES["link_slot_status_t"]
        assert n == want, (name, n, want)
    c = c_constants()
    assert c["LINK_VERSION"] == R.LINK_VERSION
    assert (c["LINK_MAX_SLOTS"], c["LINK_REG_MAX"], c["LINK_PCM_MAX"]) == (R.MAX_SLOTS, R.REG_MAX, R.PCM_MAX)
    assert (c["LINK_MAX_PAIRINGS"], c["LINK_HID_OPEN_MS"]) == (R.MAX_PAIRINGS, R.HID_OPEN_MS)
    assert (c["LINK_LED_MIN_PERIOD_US"], c["LINK_LED_MAX_ON_US"]) == (R.LED_MIN_PERIOD_US, R.LED_MAX_ON_US)
    assert {c["LINK_HAND_" + v.upper()]: v for v in R.HANDS.values()} == R.HANDS
    for k, v in c.items():
        if k.startswith(("CMD_", "EVT_")):
            assert getattr(R, k) == v, (k, v)
    for prefix, table in (("LINK_ERR_", R.STATUS_CODES), ("LINK_MODE_", R.MODES)):
        for k, v in c.items():
            if k.startswith(prefix):
                assert v in table, k
    caps = {k: v for k, v in c.items() if k.startswith("LINK_CAP_")}
    assert sorted(v.bit_length() - 1 for v in caps.values()) == sorted(R.CAPS), caps
    for pyname in ("HOST_AUTO_ACCEPT", "HOST_DM_BEACONS", "HOST_RAW_UPLINKS", "HOST_PLACEHOLDER", "HOST_COMPACT",
                   "HOST_STORED", "FORGET_ALL", "FORGET_IDENTITY", "PAIR_AUTO", "FAKE_REAL_CONN",
                   "FAKE_PAIRED", "FAKE_STREAM_INPUT", "FAKE_STREAM_IMU", "LED_OFF", "LED_ON", "LED_STROBE",
                   "HAPTIC_STOP", "HAPTIC_SIMPLE", "HAPTIC_PCM"):
        assert getattr(R, pyname) == c["LINK_" + pyname], pyname
    print(f"link.h vs radio.py: {len(sizes)} struct sizes, {sum(k.startswith(('CMD_', 'EVT_')) for k in c)} ids agree")


def test_cobs_and_pack():
    rnd = random.Random(3)
    cases = [b"", b"\0", b"\0" * 300, bytes(range(1, 256)) * 2, bytes([1] * 254), bytes([1] * 255)]
    cases += [bytes(rnd.randrange(3) and rnd.randrange(256) for _ in range(rnd.randrange(400))) for _ in range(300)]
    for c in cases:
        enc = R.cobs_encode(c)
        assert enc.count(0) == 1 and enc[-1] == 0
        assert R.cobs_decode(enc[:-1]) == c
    for name, (fmt, fields) in R.FORMATS.items():
        if not fields:
            continue
        kw = {}
        for n, k, code in R.layout(name):
            if code.endswith("s"):
                kw[n] = bytes(range(1, 1 + int(code[:-1])))
            else:
                kw[n] = [5] * k if k > 1 else 7
        try:
            b = R.pack(name, **kw)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"{name}: {e}")
        assert len(b) == R.sizeof(name), name
        back = R.unpack(name, b)
        for n, v in kw.items():
            if isinstance(v, bytes):
                assert back[n].rstrip(b"\0") == v.rstrip(b"\0"), (name, n)
            else:
                assert back[n] == v, (name, n, back[n], v)
    print(f"COBS: {len(cases)} round-trips; pack/unpack: every struct round-trips")


def wait(d, pred, timeout=3.0):
    """Drain events until pred(name, ev) is true; return (that event, everything seen)."""
    seen, end = [], time.monotonic() + timeout
    while time.monotonic() < end:
        for name, ev in d.events(0.05):
            seen.append((name, ev))
            if pred(name, ev):
                return ev, seen
            if time.monotonic() > end:
                break
    raise AssertionError(f"timed out; saw {[n for n, _ in seen][-20:]}")


def test_host_session():
    fake = FakeDongle(clock_offset_us=123_456_789, drift_ppm=15, input_hz=500, imu_hz=250)
    d = R.Dongle(transport=fake)
    h = d.hello()
    assert h["version"] == R.LINK_VERSION and "host" in h["caps_names"]

    # host commands need host mode
    r, _ = d.request(R.CMD_CONNECT, "link_connect_t", slot=1, device_id=1, check=False)
    assert r["status"] == 2
    netaddr, key = 0x5EED1234, bytes(range(16))
    d.host_start(netaddr, key, 0xBEEF)
    try:
        d.host_start(netaddr, key, 1, chmap=0x1F)  # 5 channels + seek 17, 36 = 7: rejected like the firmware
        raise AssertionError("7-channel map accepted")
    except R.LinkError as e:
        assert e.status == 1

    # pairing: advert, then linking -> key exchange -> provision -> done
    d.request(R.CMD_PAIR_START, "link_pair_start_t", flags=R.PAIR_AUTO, timeout_s=10)
    done, seen = wait(d, lambda n, e: n == "pair" and e["state"] in (5, 6))
    assert done["state"] == 5 and done["netaddr"] == netaddr, done
    adverts = [e for n, e in seen if n == "advert"]
    assert adverts and adverts[0]["pulsar_version"] == 0x1701
    states = [e["state"] for n, e in seen if n == "pair"]
    assert states == [1, 2, 3, 4, 5], states
    dev = done["device_id"]
    assert fake.controllers[0].paired == (netaddr, key)  # real 0x11 wrap decrypted by the sim controller

    # connect it (any free slot: 1..4, never the negotiation slot 0) -> waiting, negotiating,
    # connected, then a second DONE with the hand; then streams
    r, _ = d.request(R.CMD_CONNECT, "link_connect_t", slot=0, device_id=dev, check=False)
    assert r["status"] == 6
    r, _ = d.request(R.CMD_CONNECT, "link_connect_t", slot=0xFF, device_id=dev)
    slot = r["detail"]
    assert slot == 1
    conn, seen = wait(d, lambda n, e: n == "conn" and e["state"] == 3)
    assert conn["slot"] == slot and conn["device_id"] == dev and conn["pulsar_version"] == 0x1701
    assert [e["state"] for n, e in seen if n == "conn"] == [1, 2, 3]
    hand, _ = wait(d, lambda n, e: n == "pair" and e["state"] == 5)
    assert hand["device_id"] == dev and hand["hand"] == fake.controllers[0].hand != 0
    inputs, imus = [], []
    end = time.monotonic() + 0.3
    for name, e in d.events(0.05):
        if name == "input":
            inputs.append(e)
        elif name == "imu":
            imus.append(e)
        if time.monotonic() > end:
            break
    assert len(inputs) > 50 and len(imus) > 25, (len(inputs), len(imus))
    seqs = [e["seq"] for e in inputs]
    assert all(b == (a + 1) & 0xFFFF for a, b in zip(seqs, seqs[1:])), "input seq gaps"
    assert all(b["t_us"] > a["t_us"] for a, b in zip(inputs, inputs[1:]))
    assert imus[0]["bits"] == 16 and imus[0]["accel_fs_g"] == 32 and imus[0]["gyro_fs_dps"] == 4000
    assert 0 <= inputs[0]["trigger"] < 4096 and inputs[0]["battery_pct"] == 87 and inputs[0]["flags"] == 2

    # registers
    d.request(R.CMD_REG_READ, "link_reg_cmd_t", slot=slot, reg=0x15)
    reg, _ = wait(d, lambda n, e: n == "reg" and e["reg"] == 0x15)
    assert reg["kind"] == 0 and reg["status"] == 0 and reg["data"] == (3900).to_bytes(2, "little")
    d.request(R.CMD_REG_WRITE, "link_reg_cmd_t", tail=b"\x07\x00", slot=slot, reg=0x40, len=2)
    ack, _ = wait(d, lambda n, e: n == "reg" and e["reg"] == 0x40)
    assert ack["kind"] == 1
    r, _ = d.request(R.CMD_REG_WRITE, "link_reg_cmd_t", tail=b"\x07", slot=slot, reg=0x40, len=2, check=False)
    assert r["status"] == 1  # len vs data mismatch
    d.request(R.CMD_REG_SUBSCRIBE, "link_reg_sub_t", slot=slot, reg=9, period_ms=10)
    wait(d, lambda n, e: n == "reg" and e["kind"] == 2 and e["reg"] == 9)
    d.request(R.CMD_REG_SUBSCRIBE, "link_reg_sub_t", slot=slot, reg=9, flags=1)

    # LED and haptics
    d.request(R.CMD_LED, "link_led_t", slot=slot, mode=R.LED_STROBE, intensity=200, period_us=11111,
              on_us=80, phase_us=-500)
    assert fake.last_led[slot]["phase_us"] == -500 and fake.last_led[slot]["on_us"] == R.LED_MAX_ON_US
    r, _ = d.request(R.CMD_LED, "link_led_t", slot=slot, mode=R.LED_STROBE, period_us=699, on_us=50, check=False)
    assert r["status"] == 1  # faster than LINK_LED_MIN_PERIOD_US
    r, _ = d.request(R.CMD_LED, "link_led_t", slot=slot, mode=R.LED_ON, check=False)
    assert r["status"] == 1  # real controllers cannot hold the LEDs on
    d.request(R.CMD_HAPTIC, "link_haptic_t", slot=slot, mode=R.HAPTIC_SIMPLE, amplitude=200, freq_hz=160,
              duration_ms=100)
    assert fake.last_haptic[slot]["freq_hz"] == 160
    r, _ = d.request(R.CMD_HAPTIC, "link_haptic_t", tail=bytes(range(10)), slot=slot, mode=R.HAPTIC_PCM,
                     amplitude=255, freq_hz=2000, pcm_len=10, check=False)
    assert r["status"] == 5  # PCM (0x9d) is not implemented for real controllers
    r, _ = d.request(R.CMD_HAPTIC, "link_haptic_t", slot=4, mode=R.HAPTIC_SIMPLE, check=False)
    assert r["status"] == 10  # nobody in slot 4

    # time sync: the fit must recover the fake's offset/drift to well under a USB frame
    ts = R.TimeSync()
    for i in range(30):
        got = d.time_ping(i + 1)
        assert got, "no pong"
        ts.add(*got)
    pc_now = time.monotonic_ns()
    d_now = fake.now_us()
    err_us = abs(ts.to_pc(d_now) - pc_now) / 1000
    assert err_us < 500, f"time sync error {err_us:.0f} us"

    # link loss and recovery, then status and disconnect
    fake.drop_slot(slot)
    wait(d, lambda n, e: n == "conn" and e["state"] == 4)
    wait(d, lambda n, e: n == "conn" and e["state"] == 3)
    st = d.host_status()
    assert st["netaddr"] == netaddr and st["slot"][slot]["state"] == 3 and st["slot"][slot]["device_id"] == dev
    d.request(R.CMD_DISCONNECT, "link_disconnect_t", slot=slot, flags=1)
    wait(d, lambda n, e: n == "conn" and e["state"] == 0)
    d.send(R.CMD_STOP)
    assert d.wait_for(R.EVT_STATUS)
    print(f"host session: pair, connect, {len(inputs)} input + {len(imus)} IMU events, regs, LED, haptics, "
          f"time sync ({err_us:.0f} us), loss/recovery, disconnect ok")


def test_pending_re_behaviour():
    """Today's firmware: real negotiation connects, but no input formats and PENDING_RE peripherals."""
    fake = FakeDongle(pending_re=True, controllers=[SimController(0xAB)])
    fake.controllers[0].paired = (0x1234, bytes(16))
    d = R.Dongle(transport=fake)
    h = d.hello()
    assert "real_conn_neg" in h["caps_names"] and "real_hreg" not in h["caps_names"]
    d.host_start(0x1234, bytes(16), 1)
    d.request(R.CMD_CONNECT, "link_connect_t", slot=0xFF, device_id=0xAB)
    wait(d, lambda n, e: n == "conn" and e["state"] == 3)
    r, _ = d.request(R.CMD_REG_READ, "link_reg_cmd_t", slot=1, reg=9, check=False)
    assert r["status"] == 5
    t_end = time.monotonic() + 0.3
    for name, e in d.events(0.05):
        assert name not in ("input", "imu", "sample"), "input from a real controller without a pinned format"
        if time.monotonic() > t_end:
            break
    # ... and with the placeholder formats (loopback) it does connect
    d.host_start(0x1234, bytes(16), 1, flags=R.HOST_DM_BEACONS | R.HOST_PLACEHOLDER)
    conn, _ = wait(d, lambda n, e: n == "conn" and e["state"] == 3)
    ev, _ = wait(d, lambda n, e: n == "input")
    assert ev["flags"] & 1, "placeholder flag not set on input"
    print("pending-RE behaviour: real connect, no input, PENDING_RE peripherals; placeholder streams")


def test_stored_and_compact():
    """LINK_HOST_STORED: the dongle's flash identity, pairings saved + let in, kept across a reboot,
    listed and forgotten; LINK_HOST_COMPACT: EVT_SAMPLE instead of EVT_INPUT + EVT_IMU."""
    fake = FakeDongle(controllers=[SimController(0xC0FFEE)])
    d = R.Dongle(transport=fake)
    flags = R.HOST_DM_BEACONS | R.HOST_STORED | R.HOST_COMPACT
    r = d.host_start(0, bytes(16), 7, flags=flags)
    assert r["detail"] == 0
    netaddr = d.host_status()["netaddr"]
    assert netaddr and d.pairings() == dict(netaddr=netaddr, count=0, flags=1, writes_left=100, pairings=[])
    d.request(R.CMD_PAIR_START, "link_pair_start_t", flags=R.PAIR_AUTO, timeout_s=10)
    done, _ = wait(d, lambda n, e: n == "pair" and e["state"] == 5)
    assert done["netaddr"] == netaddr and done["hand"] == 0
    wait(d, lambda n, e: n == "conn" and e["state"] == 3)  # no CMD_CONNECT needed
    smp, seen = wait(d, lambda n, e: n == "sample")
    assert smp["accel"] == [0, 0, 1024] and smp["flags"] == 0 and not any(n in ("input", "imu") for n, _ in seen)
    p = d.pairings()
    assert p["count"] == 1 and p["pairings"][0]["device_id"] == 0xC0FFEE
    assert p["pairings"][0]["slot"] == 1 and p["pairings"][0]["hand"] == 1  # even id: left

    fake.reboot()  # power cycle: the identity and the pairing survive
    d = R.Dongle(transport=fake)
    r = d.host_start(0, bytes(16), 8, flags=flags)
    assert r["detail"] == 1 and d.host_status()["netaddr"] == netaddr
    wait(d, lambda n, e: n == "conn" and e["state"] == 3)

    assert d.forget(0xC0FFEE) == 1
    wait(d, lambda n, e: n == "conn" and e["state"] == 0)
    assert d.pairings()["count"] == 0
    r, _ = d.request(R.CMD_PAIR_FORGET, "link_pair_forget_t", check=False)
    assert r["status"] == 1  # neither an id nor ALL
    d.forget(identity=True)
    d.host_start(0, bytes(16), 9, flags=flags)
    assert d.host_status()["netaddr"] not in (0, netaddr)
    print("stored identity: pair -> saved + auto-connected, reboot -> reconnects, list / forget ok; compact samples ok")


class _HidShim:
    """hidapi's device interface over a FakeDongle(hid=True), for radio.HidTransport."""

    def __init__(self, fake):
        self.fake = fake

    def write(self, data):
        return self.fake.write(bytes(data))

    def read(self, size, timeout_ms=0):
        return list(self.fake.read())


def test_hid_transport():
    for stream in (b"", b"\x01", bytes(range(256)) * 3):
        reps = R.hid_reports(stream)
        assert all(len(x) == R.HID_REPORT for x in reps)
        assert b"".join(R.hid_payload(x) for x in reps) == stream
    fake = FakeDongle(hid=True, input_hz=500, imu_hz=500)
    try:
        fake.write(bytes(64))
        raise AssertionError("64-byte hidraw write accepted")
    except OSError:
        pass
    d = R.Dongle(transport=R.HidTransport(device=_HidShim(fake)))
    assert d.hello()["version"] == R.LINK_VERSION  # a 28-byte event spans an IN report boundary
    d.host_start(0x1234, bytes(16), 1, flags=R.HOST_DM_BEACONS | R.HOST_COMPACT)
    fake.controllers[0].paired = (0x1234, bytes(16))
    d.request(R.CMD_CONNECT, "link_connect_t", slot=0xFF, device_id=fake.controllers[0].device_id)
    wait(d, lambda n, e: n == "sample")
    # nobody writes for longer than LINK_HID_OPEN_MS: the dongle discards its output
    fake.hid_last_out -= R.HID_OPEN_MS / 1000 + 0.1
    time.sleep(0.02)
    fake.tick()
    assert not fake.out and fake.events_dropped > 0
    d.hello()  # the next OUT report reopens it
    print("HID: report framing round-trips, hidraw 65-byte writes, events over 64-byte reports, 2 s open window ok")


if __name__ == "__main__":
    test_link_h_matches_radio_py()
    test_cobs_and_pack()
    test_host_session()
    test_pending_re_behaviour()
    test_stored_and_compact()
    test_hid_transport()
    print("link tests passed")
