#!/usr/bin/env python3
"""Extract partitions from a full Android A/B OTA payload.bin (no protobuf dependency).

    python tools/payload_extract.py payload.bin --list
    python tools/payload_extract.py payload.bin odm vendor -o out/

Only full-OTA operations (REPLACE, REPLACE_BZ, REPLACE_XZ, REPLACE_ZSTD, ZERO, DISCARD)
are supported; incremental (diff) payloads are rejected.
"""
import argparse
import bz2
import lzma
import os
import struct
import sys


def varint(buf, i):
    v = shift = 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, i
        shift += 7


def fields(buf):
    """Yield (field_number, wire_type, value) for one protobuf message."""
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(buf, i)
        elif wt == 1:
            v = buf[i:i + 8]
            i += 8
        elif wt == 2:
            n, i = varint(buf, i)
            v = buf[i:i + n]
            i += n
        elif wt == 5:
            v = buf[i:i + 4]
            i += 4
        else:
            raise ValueError(f"wire type {wt}")
        yield fn, wt, v


def parse_extent(buf):
    start = num = 0
    for fn, _, v in fields(buf):
        if fn == 1:
            start = v
        elif fn == 2:
            num = v
    return start, num


def parse_op(buf):
    op = {"type": 0, "offset": 0, "length": 0, "dst": []}
    for fn, _, v in fields(buf):
        if fn == 1:
            op["type"] = v
        elif fn == 2:
            op["offset"] = v
        elif fn == 3:
            op["length"] = v
        elif fn == 6:
            op["dst"].append(parse_extent(v))
    return op


def parse_partition(buf):
    p = {"name": "", "ops": [], "size": 0}
    for fn, _, v in fields(buf):
        if fn == 1:
            p["name"] = v.decode()
        elif fn == 8:
            p["ops"].append(parse_op(v))
        elif fn == 7:  # new_partition_info
            for f2, _, v2 in fields(v):
                if f2 == 1:
                    p["size"] = v2
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("payload")
    ap.add_argument("partitions", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-o", "--out", default=".")
    a = ap.parse_args()

    f = open(a.payload, "rb")
    magic, ver, msize = struct.unpack(">4sQQ", f.read(20))
    if magic != b"CrAU":
        sys.exit("not a payload.bin")
    sigsize = struct.unpack(">I", f.read(4))[0] if ver >= 2 else 0
    manifest = f.read(msize)
    data_start = 20 + (4 if ver >= 2 else 0) + msize + sigsize

    block = 4096
    parts = []
    for fn, _, v in fields(manifest):
        if fn == 3:
            block = v
        elif fn == 13:
            parts.append(parse_partition(v))

    if a.list or not a.partitions:
        for p in parts:
            print(f"{p['name']:24} {p['size'] / 1e6:10.1f} MB  {len(p['ops'])} ops")
        return

    os.makedirs(a.out, exist_ok=True)
    for p in parts:
        if p["name"] not in a.partitions:
            continue
        path = os.path.join(a.out, p["name"] + ".img")
        with open(path, "wb") as o:
            for op in p["ops"]:
                t = op["type"]
                if t in (6, 7):  # ZERO, DISCARD
                    for s, n in op["dst"]:
                        o.seek(s * block)
                        o.write(b"\0" * (n * block))
                    continue
                f.seek(data_start + op["offset"])
                raw = f.read(op["length"])
                if t == 0:
                    data = raw
                elif t == 1:
                    data = bz2.decompress(raw)
                elif t == 8:
                    data = lzma.decompress(raw)
                elif t == 14:
                    import zstandard  # pip install zstandard
                    data = zstandard.ZstdDecompressor().decompress(raw, max_output_size=1 << 31)
                else:
                    sys.exit(f"{p['name']}: unsupported op type {t} (incremental payload?)")
                pos = 0
                for s, n in op["dst"]:
                    o.seek(s * block)
                    o.write(data[pos:pos + n * block])
                    pos += n * block
            if p["size"]:
                o.truncate(p["size"])
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
