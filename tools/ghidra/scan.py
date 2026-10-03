import os as _os
_WORK=_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),"..","..","artifacts","work")
import struct, json, sys
imgs=json.load(open(_os.path.join(_WORK,'images.json')))
TARGETS={
 0x40001000:'RADIO',0x40001504:'RADIO_PACKETPTR',0x40001508:'RADIO_FREQUENCY',
 0x4000150c:'RADIO_TXPOWER',0x40001510:'RADIO_MODE',0x40001514:'RADIO_PCNF0',
 0x40001518:'RADIO_PCNF1',0x4000151c:'RADIO_BASE0',0x40001520:'RADIO_BASE1',
 0x40001524:'RADIO_PREFIX0',0x40001528:'RADIO_PREFIX1',0x4000152c:'RADIO_TXADDRESS',
 0x40001530:'RADIO_RXADDRESSES',0x40001534:'RADIO_CRCCNF',0x40001538:'RADIO_CRCPOLY',
 0x4000153c:'RADIO_CRCINIT',0x40001550:'RADIO_DATAWHITEIV',0x40001560:'RADIO_MODECNF0',
 0x4000f000:'CCM',0x4000f504:'CCM_MODE',0x4000f508:'CCM_CNFPTR',0x4000f50c:'CCM_INPTR',
 0x4000f510:'CCM_OUTPTR',0x4000f514:'CCM_SCRATCHPTR',
 0x4000e000:'AAR_or_ECB',0x4000e508:'ECB_ECBDATAPTR',0x4000e510:'AAR_ADDRPTR',
 0x4000b000:'RNG',0x10000060:'FICR_DEVICEID0',0x100000a4:'FICR_DEVICEADDR0',
}
CONSTS={0x108421:'CRC24_POLY',0xffffff:'CRC24_INIT',0xfaceb00c:'DISCOVERY_AA_LOW',0xaa:'DISCOVERY_AA_PREFIX'}
for name,m in imgs.items():
    d=open(m['path'],'rb').read(); base=m['base']
    # literal pools: scan every word
    hits={}
    consthits={}
    for off in range(0,len(d)-3,2):
        w=struct.unpack_from('<I',d,off)[0]
        if w in TARGETS: hits.setdefault(TARGETS[w],[]).append(base+off)
        if w in CONSTS: consthits.setdefault(CONSTS[w],[]).append(base+off)
    print('===',name,'base',hex(base),'len',len(d))
    for k in sorted(hits):
        v=hits[k]; print('  %-20s %d  %s'%(k,len(v),' '.join(hex(x) for x in v[:8])))
    for k in sorted(consthits):
        v=consthits[k]; print('  CONST %-16s %d  %s'%(k,len(v),' '.join(hex(x) for x in v[:8])))
