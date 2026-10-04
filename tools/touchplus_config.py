#!/usr/bin/env python3
"""Build XRService (Steam Frame camera tracker) controller configs for Touch Plus.

Source: Meta's own controller calibration JSON ("Device"/"TrackedObject" with ModelPoints,
ImuPosition, AccCalibration, GyroCalibration), the format Monado's Rift S driver parses. Meta
ships factory calibrations of "Ruby" (= Touch Plus) units inside the Quest 3 OTA
(odm/lib64/libtrackingengines.so). This tool reads them from YOUR extracted OTA at run time; nothing
Meta-made is stored in the repo. Later the controller's own calibration (read over the radio) can
be fed in with --cal instead: a JSON file, or a raw dump of controller command 0x2b (the 8 KB
`ir_led_cal` flash blob, 0x1fe0 bytes read 32 at a time; docs/re/PERIPHERALS.md §6). That the
blob holds this same JSON is INFERRED until one live read; load_cal() accepts NUL/0xFF padding.

Output, per hand: an XRService config (docs/FRAME-TRACKER.md §1) with
  lighthouse_config  = the LED positions and normals (meters, Meta model frame),
  imu                = model axes at ImuPosition (IMU samples must be rectified into model axes:
                       model = M (raw - offset), M/offset from Acc/GyroCalibration),
  head               = the frame SteamVR reports. Default identity: the guess is that Meta's model
                       frame is the "raw" Touch pose SteamVR's render models use. Measure it with the
                       Gate B clone run (cvclone logs head_from_clone) and pass --head.
  model_number       = TouchFrame_TouchPlus_<Hand>_Roy_EV1.5. XRService picks a controller "type"
                       from substrings of model_number, and types EV1 and default (which covers
                       Steam_Frame_Controller_* and any unknown name) load hard-coded 18-LED
                       neighbour-likelihood tables. With 8 LEDs those tables are indexed wrongly and
                       XRService logs ~300 "Couldn't find any neighbor" errors/s. "Roy" + "EV1.5"
                       selects the type with no tables, so bootstrapping uses neighbours computed from
                       our own LED geometry (docs/re/FRAME-MODEL.md §1).
  cv                 = {"led_nominal_brightness": 0.75}, the value the default type would use (the
                       EV1.5 type defaults to 0.4).

  python tools/touchplus_config.py                       # -> artifacts/touchplus/
  python tools/touchplus_config.py --list
  python tools/touchplus_config.py --check some_config.json   # XRService type / table / neighbour check
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

# XRService's controller types, as chosen from model_number by XRService FUN_025af580
# (docs/re/FRAME-MODEL.md §1.3). Types EV1 and DEFAULT memcpy fixed 18x18 / 18x18x18 neighbour
# tables into the model; the others leave them empty and fall back to geometric neighbours.
XR_TYPE_NAMES = {1: "K2V3", 2: "ibex_ev1", 3: "EV1", 4: "EV1.5", 5: "default"}
XR_TABLE_TYPES = (3, 5)
XR_TABLE_LEDS = 18
DEFAULT_MODEL_SUFFIX = "_Roy_EV1.5"
NOMINAL_BRIGHTNESS = 0.75  # what the default type gets for its default led_type (everlight)
NORMAL_MAX_DEG = 130.0     # XRService neighbour rule: normals within this angle (model +0x1a0)


def xrservice_model_type(model_number):
    """XRService's controller type for a model_number (substring tests, case-sensitive)."""
    m = model_number or ""
    if len(m) > 2 and ("Roy" in m or (len(m) > 0x15 and "Steam_Frame_Controller" in m)):
        if len(m) != 3:
            if "K2V3" in m:
                return 1
            if len(m) > 4 and "EV1.5" in m:
                return 4
        if "EV1" in m:
            return 3
        return 5  # EV2, DV1, plain Steam_Frame_Controller_*: all the default type
    if len(m) > 7 and "ibex_ev1" in m:
        return 2
    return 5


def check_config(cfg):
    """Problems XRService would have with a controller config (default object), as strings."""
    problems = []
    lc = cfg.get("lighthouse_config", {})
    pts, nrm = lc.get("modelPoints", []), lc.get("modelNormals", [])
    n = len(pts)
    t = xrservice_model_type(cfg.get("model_number", ""))
    if t in XR_TABLE_TYPES and n != XR_TABLE_LEDS:
        problems.append(f"model_number {cfg.get('model_number')!r} is XRService type {XR_TYPE_NAMES[t]}, "
                        f"which loads {XR_TABLE_LEDS}-LED neighbour tables, but the model has {n} LEDs: "
                        f"expect a 'Couldn't find any neighbor' flood. Use a name containing "
                        f"'Roy' and 'EV1.5'.")
    for i in range(n):
        near = 0
        for j in range(n):
            if i == j:
                continue
            dot = sum(a * b for a, b in zip(nrm[i], nrm[j]))
            if math.degrees(math.acos(max(-1.0, min(1.0, dot)))) <= NORMAL_MAX_DEG:
                near += 1
        if near < 2:
            problems.append(f"LED {i} has {near} geometric neighbours (normals within {NORMAL_MAX_DEG:g} deg); "
                            f"P3P bootstrap needs 2")
    return problems


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


def load_cal(path):
    """A calibration from a JSON file or a raw cmd-0x2b dump: the first complete JSON object in
    the bytes, ignoring any leading binary and the NUL/0xFF padding of an erased flash tail."""
    data = open(path, "rb").read()
    start = data.find(b"{")
    if start < 0:
        raise ValueError(f"{path}: no JSON object (blank or non-JSON calibration blob)")
    text = data[start:].split(b"\x00", 1)[0].split(b"\xff", 1)[0].decode("latin1")
    obj, _ = json.JSONDecoder().raw_decode(text)
    return obj


def selftest():
    import tempfile
    cal = {"Device": {"DeviceType": "Ruby", "BuildType": "x_left"},
           "TrackedObject": {"ModelPoints": {"Point0": [0.01, 0, 0, 1, 0, 0],
                                             "Point1": [0, 0.02, 0, 0, 1, 0]},
                             "ImuPosition": [0.001, 0.002, 0.003]}}
    blob = json.dumps(cal).encode().ljust(0x1fe0, b"\x00")
    with tempfile.TemporaryDirectory() as d:
        for name, body in (("a.json", json.dumps(cal).encode()), ("b.bin", blob),
                           ("c.bin", b"\x01\x02" + json.dumps(cal).encode() + b"\xff" * 64)):
            path = os.path.join(d, name)
            open(path, "wb").write(body)
            got = load_cal(path)
            assert got == cal and is_touch_plus(got) and hand_of(got) == 0, name
        empty = os.path.join(d, "e.bin")
        open(empty, "wb").write(b"\xff" * 0x1fe0)
        try:
            load_cal(empty)
            raise AssertionError("erased blob must not parse")
        except ValueError:
            pass
    led_pos, led_nrm, imu = average([cal])
    assert led_pos[1] == [0, 0.02, 0] and led_nrm[0] == [1.0, 0.0, 0.0] and imu == [0.001, 0.002, 0.003]

    # XRService type classifier: the model_numbers of the configs shipped with SteamVR's cv driver
    # (18 LEDs except K2V3 with 17), plus ours. Tables are loaded only for EV1 and default.
    for name, want in (("Steam_Frame_Controller_Left", 5), ("Roy_DV1_Left", 5), ("Roy_EV2_Left", 5),
                       ("Roy_EV2_Playtest_Ergo_Right_CV", 5), ("Roy_EV1_Left_CV", 3),
                       ("Roy_EV1.5_Right_CV", 4), ("Roy_K2V3_Left_CV", 1), ("Roy_K2C_Left_CV", 5),
                       ("ibex_ev1", 2), ("", 5), ("Roy", 5), ("TouchFrame_TouchPlus_Left", 5),
                       ("Steam_Frame_Controller_EV1.5", 4), (default_model_number(0), 4),
                       (default_model_number(1), 4)):
        got = xrservice_model_type(name)
        assert got == want, (name, got, want)
    # An 8-LED ring: geometric neighbours fine, tables only with a table type.
    ring = [[math.cos(k * math.pi / 4), math.sin(k * math.pi / 4), 0.0] for k in range(8)]
    pts8 = [[0.03 * x, 0.03 * y, 0.0] for x, y, _ in ring]
    good = build_config(pts8, ring, [0, 0, 0], 0, "s", default_model_number(0), [0] * 6,
                        {"led_nominal_brightness": NOMINAL_BRIGHTNESS})
    assert check_config(good) == [] and good["cv"] == {"led_nominal_brightness": 0.75}
    assert json.loads(json.dumps(good))["model_number"] == "TouchFrame_TouchPlus_Left_Roy_EV1.5"
    bad = dict(good, model_number="Steam_Frame_Controller_Left")
    assert len(check_config(bad)) == 1 and "neighbour tables" in check_config(bad)[0]
    lonely = dict(good, lighthouse_config={"modelPoints": pts8[:3],
                                           "modelNormals": [[0, 0, 1], [0, 0, -1], [1, 0, 0]]})
    # LEDs 0 and 1 face apart (180 deg > 130), so each has only LED 2 as a neighbour.
    assert [p.split()[1] for p in check_config(lonely)] == ["0", "1"]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.txt")
        open(path, "w").write("log line {\"default\": " + json.dumps(bad) + ", \"onboard\": {}} tail")
        assert load_any_config(path)["model_number"] == "Steam_Frame_Controller_Left"
    assert build_config(pts8, ring, [0, 0, 0], 1, "s", "m", [0] * 6).get("cv") is None
    print("selftest ok -- load_cal reads JSON files and padded cmd-0x2b blobs; average() unchanged; "
          "XRService type classifier, cv block and --check agree with FRAME-MODEL.md")


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


def default_model_number(hand):
    return f"TouchFrame_TouchPlus_{'Left' if hand == 0 else 'Right'}{DEFAULT_MODEL_SUFFIX}"


def build_config(led_pos, led_nrm, imu_pos, hand, serial, model_number, head, cv=None):
    hx, hz = euler_xyz_deg_to_axes(*head[:3])
    cfg = {
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
    if cv:
        cfg["cv"] = dict(cv)
    return cfg


def load_any_config(path):
    """The controller config (default object) in a file: our own output, a {"default":...,
    "onboard":...} pair, or a log excerpt holding one."""
    text = open(path, "rb").read().decode("latin1")
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text[m.start():])
        except ValueError:
            continue
        if isinstance(obj, dict):
            if "lighthouse_config" in obj:
                return obj
            if isinstance(obj.get("default"), dict) and "lighthouse_config" in obj["default"]:
                return obj["default"]
    raise ValueError(f"{path}: no controller config with lighthouse_config found")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lib", default=DEFAULT_LIB, help="libtrackingengines.so from your Quest 3 OTA")
    ap.add_argument("--cal", action="append", default=[],
                    help="Meta calibration JSON file(s) or raw cmd-0x2b dumps instead of the OTA library")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--list", action="store_true", help="list calibrations found and exit")
    ap.add_argument("--model-number", default="",
                    help="default: TouchFrame_TouchPlus_<Hand>_Roy_EV1.5 (XRService type EV1.5: no "
                         "18-LED neighbour tables). The same value is used for both hands.")
    ap.add_argument("--led-nominal-brightness", type=float, default=NOMINAL_BRIGHTNESS,
                    help="cv.led_nominal_brightness (default %(default)s; 0 leaves the cv block out)")
    ap.add_argument("--retro-reflectors", action="store_true",
                    help="EXPERIMENT ONLY: cv.has_retro_reflectors=true (blob threshold 60 instead of "
                         "170, retroreflector adaptive threshold); see FRAME-MODEL.md test T5")
    ap.add_argument("--serial-prefix", default="tftouchplus")
    ap.add_argument("--head", default="0,0,0,0,0,0",
                    help="model_from_head: rx,ry,rz (deg, XYZ) and x,y,z (m)")
    ap.add_argument("--check", metavar="FILE", action="append", default=[],
                    help="report XRService's view of an existing config (type, tables, neighbours) and exit")
    ap.add_argument("--selftest", action="store_true", help="offline self-check and exit")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.check:
        bad = 0
        for path in args.check:
            cfg = load_any_config(path)
            t = xrservice_model_type(cfg.get("model_number", ""))
            n = len(cfg.get("lighthouse_config", {}).get("modelPoints", []))
            problems = check_config(cfg)
            print(f"{path}: model_number {cfg.get('model_number')!r} -> XRService type "
                  f"{XR_TYPE_NAMES[t]} ({t}), {n} LEDs, neighbour tables "
                  f"{'yes' if t in XR_TABLE_TYPES else 'no'}: {'OK' if not problems else 'PROBLEMS'}")
            for p in problems:
                print("  -", p)
            bad += bool(problems)
        sys.exit(1 if bad else 0)

    if args.cal:
        cals = [load_cal(p) for p in args.cal]
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
    cv = {}
    if args.led_nominal_brightness > 0:
        cv["led_nominal_brightness"] = args.led_nominal_brightness
    if args.retro_reflectors:
        cv["has_retro_reflectors"] = True
    os.makedirs(args.out, exist_ok=True)
    for hand, name in ((0, "left"), (1, "right")):
        mine = [c for c in cals if is_touch_plus(c) and hand_of(c) == hand]
        if not mine:
            print(f"no Touch Plus ({name}) calibration found", file=sys.stderr)
            continue
        led_pos, led_nrm, imu = average(mine)
        model = args.model_number or default_model_number(hand)
        cfg = build_config(led_pos, led_nrm, imu, hand, f"{args.serial_prefix}_{name}", model, head, cv)
        for p in check_config(cfg):
            print(f"WARNING ({name}): {p}", file=sys.stderr)
        path = os.path.join(args.out, f"touchplus_{name}.json")
        with open(path, "w") as f:
            json.dump(cfg, f, separators=(",", ":"))
        # The unit calibrations themselves, for IMU rectification (M, offset) later.
        with open(os.path.join(args.out, f"touchplus_{name}_meta_cal.json"), "w") as f:
            json.dump(mine, f, indent=1)
        print(f"{path}: {len(led_pos)} LEDs from {len(mine)} unit(s), imu at "
              f"({imu[0]*1e3:.1f}, {imu[1]*1e3:.1f}, {imu[2]*1e3:.1f}) mm, model_number {model} "
              f"(XRService type {XR_TYPE_NAMES[xrservice_model_type(model)]})")


if __name__ == "__main__":
    main()
