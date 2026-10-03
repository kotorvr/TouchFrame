#!/usr/bin/env python3
"""Build XRService (Steam Frame camera tracker) controller configs for Touch Plus.

Source: Meta's own controller calibration JSON ("Device"/"TrackedObject" with ModelPoints,
ImuPosition, AccCalibration, GyroCalibration), the format Monado's Rift S driver parses. Meta
ships factory calibrations of "Ruby" (= Touch Plus) units inside the Quest 3 OTA
(odm/lib64/libtrackingengines.so). This tool reads them from YOUR extracted OTA at run time; nothing
Meta-made is stored in the repo. Later the controller's own calibration (read over the radio) can
be fed in with --cal instead.

Output, per hand: an XRService config (docs/FRAME-TRACKER.md §1) with
  lighthouse_config  = the LED positions and normals (meters, Meta model frame),
  imu                = model axes at ImuPosition (IMU samples must be rectified into model axes:
                       model = M (raw - offset), M/offset from Acc/GyroCalibration),
  head               = the frame SteamVR reports. Default identity: the guess is that Meta's model
                       frame is the "raw" Touch pose SteamVR's render models use. Measure it with the
                       Gate B clone run (cvclone logs head_from_clone) and pass --head.

  python tools/touchplus_config.py                       # -> artifacts/touchplus/
  python tools/touchplus_config.py --list
  python tools/touchplus_config.py --head 0,0,0,0,0,0 --model-number TouchFrame_TouchPlus
"""
import argparse
import json
import math
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEFAULT_LIB = os.path.join(ROOT, "artifacts", "quest", "odm", "lib64", "libtrackingengines.so")
DEFAULT_OUT = os.path.join(ROOT, "artifacts", "touchplus")


def embedded_calibrations(path):
    """Every complete calibration JSON object (with TrackedObject.ModelPoints) in a binary."""
    data = open(path, "rb").read()
    out = []
    for m in re.finditer(rb'"ModelPoints":\{', data):
        start = data.rfind(b"\x00", 0, m.start()) + 1
        end = data.find(b"\x00", m.start())
        try:
            out.append(json.loads(data[start:end].decode("latin1")))
        except ValueError:
            pass
    return out


def hand_of(cal):
    build = cal.get("Device", {}).get("BuildType", "").lower()
    if build.endswith("_left"):
        return 0
    if build.endswith("_right"):
        return 1
    return None


def is_touch_plus(cal):
    return cal.get("Device", {}).get("DeviceType", "").lower() == "ruby"


def points(cal):
    mp = cal["TrackedObject"]["ModelPoints"]
    keys = sorted(mp, key=lambda k: int(re.sub(r"\D", "", k) or 0))
    return [mp[k] for k in keys]


def average(cals):
    """Mean LED model / IMU position of several units of the same hand (same LED order)."""
    pts = [points(c) for c in cals]
    n = len(pts[0])
    if any(len(p) != n for p in pts):
        raise ValueError("units disagree on LED count")
    led_pos = [[sum(p[i][k] for p in pts) / len(pts) for k in range(3)] for i in range(n)]
    led_nrm = []
    for i in range(n):
        v = [sum(p[i][3 + k] for p in pts) for k in range(3)]
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        led_nrm.append([x / norm for x in v])
    imu = [sum(c["TrackedObject"]["ImuPosition"][k] for c in cals) / len(cals) for k in range(3)]
    return led_pos, led_nrm, imu


def euler_xyz_deg_to_axes(rx, ry, rz):
    """plus_x / plus_z columns of R = Rx * Ry * Rz (degrees)."""
    a, b, c = (math.radians(v) for v in (rx, ry, rz))
    ca, sa, cb, sb, cc, sc = math.cos(a), math.sin(a), math.cos(b), math.sin(b), math.cos(c), math.sin(c)
    R = [[cb * cc, -cb * sc, sb],
         [sa * sb * cc + ca * sc, -sa * sb * sc + ca * cc, -sa * cb],
         [-ca * sb * cc + sa * sc, ca * sb * sc + sa * cc, ca * cb]]
    return [R[0][0], R[1][0], R[2][0]], [R[0][2], R[1][2], R[2][2]]


def build_config(led_pos, led_nrm, imu_pos, hand, serial, model_number, head):
    hx, hz = euler_xyz_deg_to_axes(*head[:3])
    return {
        "device_class": "controller",
        "device_serial_number": serial,
        "head": {"plus_x": hx, "plus_z": hz, "position": list(head[3:])},
        "imu": {"plus_x": [1.0, 0.0, 0.0], "plus_z": [0.0, 0.0, 1.0], "position": imu_pos},
        "lighthouse_config": {"modelNormals": led_nrm, "modelPoints": led_pos},
        "manufacturer": "Meta",
        "model_number": model_number,
        "revision": 1,
        "tracked_controller_role": "left_hand" if hand == 0 else "right_hand",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lib", default=DEFAULT_LIB, help="libtrackingengines.so from your Quest 3 OTA")
    ap.add_argument("--cal", action="append", default=[],
                    help="Meta calibration JSON file(s) instead of the OTA library (e.g. read from your controller)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--list", action="store_true", help="list calibrations found and exit")
    ap.add_argument("--model-number", default="",
                    help="default: Steam_Frame_Controller_<Hand> (the model XRService is known to accept)")
    ap.add_argument("--serial-prefix", default="tftouchplus")
    ap.add_argument("--head", default="0,0,0,0,0,0",
                    help="model_from_head: rx,ry,rz (deg, XYZ) and x,y,z (m)")
    args = ap.parse_args()

    if args.cal:
        cals = [json.load(open(p)) for p in args.cal]
    else:
        if not os.path.exists(args.lib):
            sys.exit(f"{args.lib} not found: extract your Quest 3 OTA first (docs/PROTOCOL.md 'Reproduce')")
        cals = embedded_calibrations(args.lib)
    if args.list:
        for c in cals:
            d = c.get("Device", {})
            print(d.get("DeviceType", "?"), d.get("BuildType", "?"), d.get("SerialNumber") or
                  c.get("TrackedObject", {}).get("SerialNumber", "?"), len(points(c)), "LEDs")
        return

    head = [float(x) for x in args.head.split(",")]
    if len(head) != 6:
        sys.exit("--head needs 6 numbers")
    os.makedirs(args.out, exist_ok=True)
    for hand, name in ((0, "left"), (1, "right")):
        mine = [c for c in cals if is_touch_plus(c) and hand_of(c) == hand]
        if not mine:
            print(f"no Touch Plus ({name}) calibration found", file=sys.stderr)
            continue
        led_pos, led_nrm, imu = average(mine)
        model = args.model_number or f"Steam_Frame_Controller_{name.capitalize()}"
        cfg = build_config(led_pos, led_nrm, imu, hand, f"{args.serial_prefix}_{name}", model, head)
        path = os.path.join(args.out, f"touchplus_{name}.json")
        with open(path, "w") as f:
            json.dump(cfg, f, separators=(",", ":"))
        # The unit calibrations themselves, for IMU rectification (M, offset) later.
        with open(os.path.join(args.out, f"touchplus_{name}_meta_cal.json"), "w") as f:
            json.dump(mine, f, indent=1)
        print(f"{path}: {len(led_pos)} LEDs from {len(mine)} unit(s), imu at "
              f"({imu[0]*1e3:.1f}, {imu[1]*1e3:.1f}, {imu[2]*1e3:.1f}) mm, model_number {model}")


if __name__ == "__main__":
    main()
