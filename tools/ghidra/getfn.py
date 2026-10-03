import os as _os
_WORK=_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),"..","..","artifacts","work")
import sys,re
# getfn.py <decomp.c> <addr> ...  -> prints enclosing function bodies
f=open(sys.argv[1],encoding='utf8',errors='replace').read()
# split into (entryaddr, name, body)
parts=re.split(r'// ==== (\S+) @ ([0-9a-fA-F]+) ====\n',f)
funcs=[]
for i in range(1,len(parts),3):
    funcs.append((int(parts[i+1],16),parts[i],parts[i+2]))
funcs.sort()
targets=[int(x,16) for x in sys.argv[2:]]
import bisect
entries=[a for a,_,_ in funcs]
for t in targets:
    j=bisect.bisect_right(entries,t)-1
    if j<0: print('// no fn for 0x%x'%t); continue
    a,n,b=funcs[j]
    print('// target 0x%x in %s @ 0x%x'%(t,n,a))
    print(b)
