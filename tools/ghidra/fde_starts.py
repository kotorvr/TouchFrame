#!/usr/bin/env python3
"""Turn the .debug_frame in Meta's *-unwind.bin ELFs into function start/size lists.

The OTA ships unwind tables (no symbols) for some images; each FDE gives a function's
start address and length, which seeds Ghidra with exact function boundaries.
  odm/firmware/syncboss-unwind.bin   -> syncboss.bin
  odm/firmware/unwind-elk-app.bin    -> fw/ruby/elk-app.bin (reset 0x2ba39 matches; not ruby_prq)
Writes artifacts/work/<name>.funcs (one "0xADDR 0xSIZE" per line).
"""
import os, sys
from elftools.elf.elffile import ELFFile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
Q = os.path.join(ROOT, 'artifacts', 'quest', 'odm', 'firmware')
OUT = os.path.join(ROOT, 'artifacts', 'work')

for src, name in (('syncboss-unwind.bin', 'syncboss'), ('unwind-elk-app.bin', 'elk-app-ruby')):
    f = ELFFile(open(os.path.join(Q, src), 'rb'))
    starts = {}
    for e in f.get_dwarf_info().CFI_entries():
        if 'initial_location' in e.header:
            starts[e.header['initial_location']] = e.header['address_range']
    with open(os.path.join(OUT, name + '.funcs'), 'w') as o:
        for a in sorted(starts):
            o.write('0x%x 0x%x\n' % (a, starts[a]))
    print(name, len(starts), 'functions')
