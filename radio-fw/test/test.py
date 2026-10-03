#!/usr/bin/env python3
"""radio-fw host tests: hop rule (C vs an independent Python model) and beacon parsing."""
import os, random, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
exe = os.path.abspath(sys.argv[1])  # Windows subprocess needs an absolute path
TABLE = [4,6,8,10,12,14,16,18,20,22,24,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78]

def ref(netaddr, chmap, start, n):
    hop = (netaddr & 0xFF) % 11 + 5
    used = [i for i in range(37) if chmap >> i & 1]
    u, out = start, []
    for _ in range(n):
        u = (u + hop) % 37
        idx = u if chmap >> u & 1 else used[u % len(used)]
        out.append(TABLE[idx])
    return out

random.seed(7)
full = (1 << 37) - 1
cases = [(0x12345678, full, 0), (0xFF, full, 36), (0x0, full, 5)]
for _ in range(300):
    m = 0
    while bin(m).count("1") < 8:
        m = random.getrandbits(37)
    cases.append((random.getrandbits(32), m, random.randrange(37)))
for net, m, s in cases:
    got = list(map(int, subprocess.check_output([exe, hex(net), hex(m), str(s), "60"], text=True).split()))
    assert got == ref(net, m, s, 60), (hex(net), hex(m), s)
print(f"hop: {len(cases)} cases match the Python model")

def beacon(chmap, unmapped, dm=0):
    b0 = (chmap & 0x1F) << 3 | (dm & 3) << 1
    return bytes([b0, chmap >> 5 & 0xFF, chmap >> 13 & 0xFF, chmap >> 21 & 0xFF, chmap >> 29 & 0xFF, unmapped]) + bytes(10)

def parse(b):
    return subprocess.run([exe, "parse"], input=b.hex(), capture_output=True, text=True).stdout.split()

for _ in range(200):
    m = 0
    while bin(m).count("1") < 8:
        m = random.getrandbits(37)
    u = random.randrange(37)
    assert parse(beacon(m, u, random.randrange(4))) == [format(m, "x"), str(u)]
assert parse(beacon(0b1111111, 3)) == ["reject"]          # fewer than 8 channels
assert parse(beacon(full, 37)) == ["reject"]              # unmapped out of range
assert parse(bytes(5)) == ["reject"]                      # too short
print("beacon parse: 200 round-trips + 3 rejects ok")
