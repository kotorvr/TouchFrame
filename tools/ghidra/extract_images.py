#!/usr/bin/env python3
"""Parse Meta "dAeH" firmware images and lay them out as flat flash images for Ghidra.

Reads only from artifacts/quest/ (gitignored, the user's own OTA) and writes to
artifacts/work/. Nothing produced here may be committed.

dAeH header (0x2e bytes, little endian), as observed:
  0x00 'dAeH' magic
  0x04 u32   checksum (unverified)
  0x08 u32   header length (0x2e)
  0x0c u32   image kind: 0x01020304 app, 0x11223344 SPL, 0xeeddccbb SPL-updater
  0x10 u32   payload length
  0x14 u32   2 (format version?)
  0x18 u32   flash address of the vector table (file offset 0x100)
  0x1c u32   firmware version
  0x20 char[12] git hash
The vector table sits at file offset 0x100, so load base = hdr[0x18] - 0x100.
"""
import os, struct, sys, json

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
Q = os.path.join(ROOT, 'artifacts', 'quest')
OUT = os.path.join(ROOT, 'artifacts', 'work')


def parse(d, off=0):
    magic, csum, hlen, kind, plen, fmt, vec, ver = struct.unpack_from('<4sIIIIIII', d, off)
    assert magic == b'dAeH', magic
    return dict(off=off, csum=csum, hlen=hlen, kind=kind, plen=plen, fmt=fmt, vec=vec,
                ver=ver, git=d[off + 0x20:off + 0x2c].decode(), base=vec - 0x100,
                end=off + plen + hlen)


def main():
    os.makedirs(OUT, exist_ok=True)
    jobs = []
    for variant in ('ruby_prq', 'ruby'):
        app = open(os.path.join(Q, 'fw', variant, 'elk-app.bin'), 'rb').read()
        h = parse(app)
        jobs.append(('elk-app-%s' % variant, app, h))
        upd = open(os.path.join(Q, 'fw', variant, 'elk-spl-updater.bin'), 'rb').read()
        # the SPL ("DM" = device management mode, which does pairing) is embedded in the updater
        i = upd.find(b'dAeH', 4)
        hs = parse(upd, i)
        jobs.append(('elk-spl-%s' % variant, upd[i:hs['end']], parse(upd[i:hs['end']])))
    sb = open(os.path.join(Q, 'odm', 'firmware', 'syncboss.bin'), 'rb').read()
    jobs.append(('syncboss', sb, dict(base=0, vec=0x1100, git='raw', kind=0, ver=0)))
    manifest = {}
    for name, data, h in jobs:
        p = os.path.join(OUT, name + '.bin')
        open(p, 'wb').write(data)
        sp, rst = struct.unpack_from('<II', data, h['vec'] - h['base'])
        manifest[name] = dict(path=p, base=h['base'], vec=h['vec'], sp=sp, reset=rst, git=h['git'],
                              kind=h['kind'], ver=h['ver'])
        print('%-18s base=0x%05x vec=0x%05x sp=0x%08x reset=0x%05x git=%s kind=0x%08x' % (
            name, h['base'], h['vec'], sp, rst, h['git'], h['kind']))
    json.dump(manifest, open(os.path.join(OUT, 'images.json'), 'w'), indent=1)


if __name__ == '__main__':
    main()
