#!/usr/bin/env python3
"""Find which functions of a stripped AArch64 ELF reference given strings, without full analysis.

Function boundaries come from .eh_frame FDEs; references are ADRP+ADD / ADRP+LDR pairs found by
a linear scan of the executable segment. Prints "func_start func_size string" lines and writes the
function starts to <elf>.xref_funcs (one hex address per line) for DecompileAt.java.

usage: xref_scan.py <elf> <needle> [<needle> ...]     (needles are substrings)
Used on the user's own Steam Frame binaries copied to artifacts/frame/ (gitignored).
"""
import re, sys, bisect, struct
from elftools.elf.elffile import ELFFile

elf_path = sys.argv[1]
needles = [n.encode() for n in sys.argv[2:]]
data = open(elf_path, 'rb').read()
f = ELFFile(open(elf_path, 'rb'))
loads = [s for s in f.iter_segments() if s['p_type'] == 'PT_LOAD']

def o2v(o):
    for s in loads:
        if s['p_offset'] <= o < s['p_offset'] + s['p_filesz']:
            return o - s['p_offset'] + s['p_vaddr']

# 1. target string addresses
targets = {}
for m in re.finditer(rb'[\x20-\x7e\t\n]{4,}\x00', data):
    s = m.group()[:-1]
    for n in needles:
        if n in s:
            v = o2v(m.start())
            if v is not None:
                # also allow references into the middle of merged strings
                targets[v] = s.decode(errors='replace')
            break
tset = set(targets)

# 2. function ranges from .eh_frame
starts = []
for e in f.get_dwarf_info().EH_CFI_entries():
    h = getattr(e, "header", None)
    if h is None: continue
    if 'initial_location' in h:
        starts.append((h['initial_location'], h['address_range']))
starts.sort()
sv = [s for s, _ in starts]

def func_of(a):
    i = bisect.bisect_right(sv, a) - 1
    if i >= 0 and starts[i][0] <= a < starts[i][0] + starts[i][1]:
        return starts[i]
    return None

# 3. scan executable segments for ADRP + ADD/LDR
hits = {}
for s in loads:
    if not (s['p_flags'] & 1):
        continue
    base, off, size = s['p_vaddr'], s['p_offset'], s['p_filesz']
    words = struct.unpack_from('<%dI' % (size // 4), data, off)
    last_adrp = {}
    for i, w in enumerate(words):
        pc = base + i * 4
        if (w & 0x9f000000) == 0x90000000:  # ADRP
            rd = w & 31
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7ffff
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= 1 << 33
            last_adrp[rd] = ((pc & ~0xfff) + imm, i)
            continue
        if (w & 0xff800000) == 0x91000000:  # ADD imm (64-bit)
            rn = (w >> 5) & 31
            if rn in last_adrp and i - last_adrp[rn][1] < 8:
                imm12 = (w >> 10) & 0xfff
                sh = (w >> 22) & 1
                t = last_adrp[rn][0] + (imm12 << (12 * sh))
                if t in tset:
                    hits.setdefault(t, []).append(pc)
for t in sorted(hits):
    for pc in hits[t]:
        fn = func_of(pc)
        print('%x %x %x %s' % (fn[0] if fn else 0, fn[1] if fn else 0, pc, targets[t][:120].replace('\n', '\\n')))
with open(elf_path + '.xref_funcs', 'w') as o:
    seen = set()
    for t in hits:
        for pc in hits[t]:
            fn = func_of(pc)
            if fn and fn[0] not in seen:
                seen.add(fn[0]); o.write('0x%x\n' % fn[0])
missing = [targets[t][:80] for t in tset if t not in hits]
if missing:
    print('# no xrefs found for: %s' % missing, file=sys.stderr)
