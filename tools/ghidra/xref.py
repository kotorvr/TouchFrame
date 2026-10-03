import os as _os
_WORK=_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),"..","..","artifacts","work")
import struct, json, sys, re
imgs=json.load(open(_os.path.join(_WORK,'images.json')))
name=sys.argv[1]; needle=sys.argv[2].encode()
m=imgs[name]; d=open(m['path'],'rb').read(); base=m['base']
# find string
soff=d.find(needle)
if soff<0: print('string not found'); sys.exit()
saddr=base+soff
print('string "%s" @ 0x%x'%(sys.argv[2],saddr))
# scan all words for any pointer into the string (literal pool entries)
for off in range(0,len(d)-3,2):
    w=struct.unpack_from('<I',d,off)[0]
    if saddr-0<=w<=saddr+2:
        print('  literal 0x%x -> 0x%x (near code)'%(base+off,w))
