#!/usr/bin/env python3
"""Fake Touch Plus source for testing the Frame driver without a Quest.

Sends StatePackets (driver/src/protocol.h) to the Frame: both hands circle in front of
the play-space origin, the trigger ramps, and buttons cycle. Prints haptics it receives.

    python tools/sim_sender.py 192.168.0.195 [--seconds 30] [--hz 90]
"""
import argparse
import math
import socket
import struct
import time

STATE_MAGIC = 0x31524654
HAPTIC_MAGIC = 0x31484654
HAND = struct.Struct("<BBH4f3f4f3f3f")
HEADER = struct.Struct("<IIQ")
assert HAND.size == 72 and HEADER.size + 2 * HAND.size == 160

CONNECTED, ORI_VALID, POS_VALID, ORI_TRACKED, POS_TRACKED = 1, 2, 4, 8, 16


def hand_state(h, t):
    side = -1 if h == 0 else 1
    a = t * 1.5
    pos = (side * 0.2 + 0.05 * math.cos(a), 1.1 + 0.05 * math.sin(a), -0.4)
    yaw = 0.3 * math.sin(a)
    rot = (0.0, math.sin(yaw / 2), 0.0, math.cos(yaw / 2))
    vel = (-0.075 * math.sin(a), 0.075 * math.cos(a), 0.0)
    ang = (0.0, 0.45 * math.cos(a), 0.0)
    phase = int(t) % 6
    buttons = (1 << phase) if phase < 4 else 0
    trig = (math.sin(t) + 1) / 2
    flags = CONNECTED | ORI_VALID | POS_VALID | ORI_TRACKED | POS_TRACKED
    return HAND.pack(flags, 80, buttons, trig, 1 - trig, math.cos(a), math.sin(a), *pos, *rot, *vel, *ang)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=28430)
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--hz", type=float, default=90)
    a = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    t0 = time.monotonic()
    seq = 0
    while (t := time.monotonic() - t0) < a.seconds:
        seq += 1
        pkt = HEADER.pack(STATE_MAGIC, seq, time.monotonic_ns()) + hand_state(0, t) + hand_state(1, t)
        s.sendto(pkt, (a.host, a.port))
        try:
            while True:
                d, _ = s.recvfrom(64)
                if len(d) == 20 and struct.unpack_from("<I", d)[0] == HAPTIC_MAGIC:
                    _, hand, amp, freq, dur = struct.unpack("<IB3xfff", d)
                    print(f"haptic hand={hand} amp={amp:.2f} freq={freq:.0f} dur={dur:.3f}")
        except BlockingIOError:
            pass
        time.sleep(1 / a.hz)
    print(f"sent {seq} packets")


if __name__ == "__main__":
    main()
