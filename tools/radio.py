#!/usr/bin/env python3
"""PC side of the TouchFrame radio dongle (radio-fw/). Needs pyserial.

  radio.py ports                         list dongles (app and bootloader)
  radio.py dfu --package build/x.zip     reboot the dongle into its bootloader and flash it
  radio.py status
  radio.py sweep [--dwell-us 1000] [--rounds 20]
                                         peak RSSI per MHz, 2400-2500: where is traffic?
  radio.py sniff --preset discovery [--out cap.jsonl] [--seconds 30]
  radio.py sniff --freq 26 --prefix 0xAA --base 0xFACEB00C --no-crc --out pairing.jsonl

Wire format: radio-fw/src/link.h (COBS frames, 0x00-terminated, type byte + body).
"""
import argparse
import glob
import json
import os
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
LINK_VERSION = 2

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


class Dongle:
    def __init__(self, port):
        self.ser = serial.Serial(port, 115200, timeout=0.05)
        self.ser.dtr = True  # the firmware only streams packets while DTR is set
        self.buf = bytearray()

    def send(self, cmd, body=b""):
        self.ser.write(cobs_encode(bytes([cmd]) + body))

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


def int0(s):
    return int(s, 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", help="serial port (default: first TouchFrame dongle)")
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
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
