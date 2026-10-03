import os as _os
_WORK=_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),"..","..","artifacts","work")
import struct, json, sys
from capstone import *
from capstone.arm import *
imgs=json.load(open(_os.path.join(_WORK,'images.json')))
LBL={0x40001504:'PACKETPTR',0x40001508:'FREQUENCY',0x4000150c:'TXPOWER',0x40001510:'MODE',
 0x40001514:'PCNF0',0x40001518:'PCNF1',0x4000151c:'BASE0',0x40001520:'BASE1',
 0x40001524:'PREFIX0',0x40001528:'PREFIX1',0x4000152c:'TXADDRESS',0x40001530:'RXADDRESSES',
 0x40001534:'CRCCNF',0x40001538:'CRCPOLY',0x4000153c:'CRCINIT',0x40001550:'DATAWHITEIV',
 0x40001560:'MODECNF0',0x40001000:'RADIO',0x4000f000:'CCM',0x4000f504:'CCM_MODE',
 0x4000f508:'CCM_CNFPTR',0x4000f50c:'CCM_INPTR',0x4000f510:'CCM_OUTPTR',0x4000f514:'CCM_SCRATCH',
 0x4000e508:'ECB_DATAPTR',0x4000e510:'AAR_ADDRPTR',0x4000e000:'ECB/AAR',0x4000b000:'RNG',
 0x108421:'#CRC24POLY',0xffffff:'#CRC24INIT',0xfaceb00c:'#DISC_AA'}
def run(name,start,length):
    m=imgs[name]; d=open(m['path'],'rb').read(); base=m['base']
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB); md.detail=True
    o=start-base
    code=d[o:o+length]
    for ins in md.disasm(code,start):
        ann=''
        if ins.id==ARM_INS_LDR and len(ins.operands)>=2 and ins.operands[1].type==ARM_OP_MEM and ins.operands[1].mem.base==ARM_REG_PC:
            pc=(ins.address+4)&~3; addr=pc+ins.operands[1].mem.disp
            try:
                val=struct.unpack_from('<I',d,addr-base)[0]
                ann='; =0x%x'%val
                if val in LBL: ann+=' '+LBL[val]
            except: pass
        print('%06x  %-8s %-24s%s'%(ins.address,ins.mnemonic,ins.op_str,ann))
if __name__=='__main__':
    run(sys.argv[1],int(sys.argv[2],16),int(sys.argv[3],16))
