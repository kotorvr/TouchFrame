#!/usr/bin/env python3
"""Analyse radio.py captures (JSON lines: t_us, mhz, rssi, crc_ok, data hex).

  pulsar_analyze.py cap.jsonl [more.jsonl] [--crc-only] [--mhz 2402] [--min-len 2]
  pulsar_analyze.py cap.jsonl --dump 20          first 20 packets, decoded LENGTH + payload

Prints:
  - per-channel counts, RSSI and CRC pass rate;
  - packet timing: inter-arrival histogram and the dominant period (beacon/slot candidates);
  - payload lengths;
  - per-byte-offset field classes for the most common length (const / counter / few values / varies),
    the first thing to look at when reading an unknown format;
  - the most common payload prefixes (message types).
`data` is what the radio stored: [S0][LENGTH][S1][payload][CRC if captured with --no-crc]. With
the Pulsar defaults (LFLEN 8, no S0/S1) byte 0 is LENGTH. Use --hdr to change how many header
bytes precede the payload.
"""
import argparse
import collections
import json
import statistics
import sys


def load(paths, crc_only, mhz):
    pkts = []
    for p in paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                if crc_only and not r.get("crc_ok"):
                    continue
                if mhz and r["mhz"] != mhz:
                    continue
                r["data"] = bytes.fromhex(r["data"])
                pkts.append(r)
    # Timestamps are the dongle's 32-bit µs counter: unwrap.
    off, prev = 0, None
    for r in pkts:
        if prev is not None and r["t_us"] < prev - (1 << 31):
            off += 1 << 32
        prev = r["t_us"]
        r["t"] = r["t_us"] + off
    return pkts


def hist(values, width=50, bins=None):
    c = collections.Counter(values)
    if not c:
        return
    top = c.most_common(bins) if bins else sorted(c.items())
    peak = max(n for _, n in top)
    for k, n in top:
        print(f"  {k!s:>12} {n:7d} {'#' * max(1, n * width // peak)}")


def period_candidates(deltas, resolution_us):
    """Most common inter-arrival times, bucketed to `resolution_us`."""
    buckets = collections.Counter(round(d / resolution_us) * resolution_us for d in deltas if d > 0)
    return buckets.most_common(8)


def field_classes(payloads):
    """Per byte offset: const / counter / few values / varies."""
    n = min(len(p) for p in payloads)
    out = []
    for i in range(n):
        col = [p[i] for p in payloads]
        vals = collections.Counter(col)
        diffs = collections.Counter((b - a) & 0xFF for a, b in zip(col, col[1:]))
        if len(vals) == 1:
            out.append(("const", f"{col[0]:02x}"))
        elif diffs and diffs.most_common(1)[0][1] > 0.8 * (len(col) - 1) and diffs.most_common(1)[0][0] != 0:
            out.append(("counter", f"+{diffs.most_common(1)[0][0]}"))
        elif len(vals) <= 4:
            out.append(("few", " ".join(f"{v:02x}" for v, _ in vals.most_common(4))))
        else:
            out.append(("varies", f"{len(vals)} values"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--crc-only", action="store_true")
    ap.add_argument("--mhz", type=int)
    ap.add_argument("--hdr", type=int, default=1, help="header bytes before the payload (default 1: LENGTH)")
    ap.add_argument("--min-len", type=int, default=0)
    ap.add_argument("--resolution-us", type=int, default=10)
    ap.add_argument("--dump", type=int, default=0)
    args = ap.parse_args()

    pkts = [p for p in load(args.files, args.crc_only, args.mhz) if len(p["data"]) >= args.min_len]
    if not pkts:
        sys.exit("no packets")
    dur = (pkts[-1]["t"] - pkts[0]["t"]) / 1e6
    print(f"{len(pkts)} packets over {dur:.2f} s ({len(pkts) / max(dur, 1e-9):.1f}/s)")

    print("\nper channel: count, RSSI median, CRC ok")
    by_ch = collections.defaultdict(list)
    for p in pkts:
        by_ch[p["mhz"]].append(p)
    for mhz in sorted(by_ch):
        ps = by_ch[mhz]
        print(f"  {mhz} MHz {len(ps):7d}  {statistics.median(p['rssi'] for p in ps):5.0f} dBm  "
              f"{100 * sum(p['crc_ok'] for p in ps) / len(ps):5.1f}%")

    deltas = [b["t"] - a["t"] for a, b in zip(pkts, pkts[1:])]
    if deltas:
        print(f"\ninter-arrival (µs, {args.resolution_us} µs buckets), most common:")
        for d, n in period_candidates(deltas, args.resolution_us):
            print(f"  {d:10d} µs  {n:7d}  ({1e6 / d if d else 0:.1f} Hz)")
        for mhz in sorted(by_ch):
            ps = by_ch[mhz]
            if len(ps) > 10 and len(by_ch) > 1:
                dd = [b["t"] - a["t"] for a, b in zip(ps, ps[1:])]
                top = period_candidates(dd, args.resolution_us)[:3]
                print(f"  {mhz} MHz only: " + ", ".join(f"{d} µs×{n}" for d, n in top))

    pay = [p["data"][args.hdr:] for p in pkts]
    print("\npayload lengths (bytes after the header):")
    hist([len(x) for x in pay], bins=12)

    common_len = collections.Counter(len(x) for x in pay).most_common(1)[0][0]
    same = [x for x in pay if len(x) == common_len]
    if common_len and len(same) > 2:
        print(f"\nfield classes at length {common_len} ({len(same)} packets):")
        for i, (kind, info) in enumerate(field_classes(same)):
            print(f"  [{i:3d}] {kind:8s} {info}")

    print("\nmost common 4-byte payload prefixes:")
    hist([x[:4].hex() for x in pay], bins=10)

    if args.dump:
        print()
        t0 = pkts[0]["t"]
        for p in pkts[:args.dump]:
            d = p["data"]
            print(f"{(p['t'] - t0) / 1e3:11.3f} ms {p['mhz']} {p['rssi']:4d} {'ok ' if p['crc_ok'] else '-- '}"
                  f"hdr {d[:args.hdr].hex()} | {d[args.hdr:].hex()}")


if __name__ == "__main__":
    main()
