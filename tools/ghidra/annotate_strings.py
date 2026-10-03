#!/usr/bin/env python3
"""Annotate a Ghidra decompile (made without analysis) with the C strings its constants point at.

usage: annotate_strings.py <elf> <in.c> <out.c>
Every DAT_xxxxxxxx / PTR_xxxxxxxx / 0xNNNNNN token that lands on a printable NUL-terminated string
gets a trailing /* "..." */ comment.
"""
import re, sys
from elftools.elf.elffile import ELFFile

elf, src, dst = sys.argv[1:4]
data = open(elf, 'rb').read()
f = ELFFile(open(elf, 'rb'))
loads = [s for s in f.iter_segments() if s['p_type'] == 'PT_LOAD']

def v2o(v):
    for s in loads:
        if s['p_vaddr'] <= v < s['p_vaddr'] + s['p_filesz']:
            return v - s['p_vaddr'] + s['p_offset']

def cstr(v):
    o = v2o(v)
    if o is None:
        return None
    e = data.find(b'\0', o, o + 400)
    if e <= o:
        return None
    s = data[o:e]
    if len(s) < 3 or any(c < 0x09 or c > 0x7e for c in s):
        return None
    return s.decode().replace('\n', '\\n')[:160]

tok = re.compile(r'(?:DAT_|PTR_|UNK_|s_\w*_|LAB_)([0-9a-f]{6,10})\b|0x([0-9a-f]{6,9})\b')
with open(src) as i, open(dst, 'w') as o:
    for line in i:
        notes = []
        for m in tok.finditer(line):
            v = int(m.group(1) or m.group(2), 16)
            s = cstr(v)
            if s:
                notes.append('"%s"' % s)
        o.write(line.rstrip('\n') + ('   /* ' + ' | '.join(notes) + ' */' if notes else '') + '\n')
