#!/usr/bin/env python3
# Writes the tiny arm64 Mach-O executable used inside samples/mobile/ipa/Wikipedia-fixture.ipa.
# It is then ad-hoc signed with rcodesign 0.29.0 (see samples/mobile/SOURCES.md).
import sys
import struct
# minimal arm64 MH_EXECUTE: __PAGEZERO, __TEXT (one page with code), __LINKEDIT, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLINKER, LC_MAIN, LC_LOAD_DYLIB libSystem
PAGE=0x4000
cmds=[]
def seg(name,vmaddr,vmsize,fileoff,filesize,maxprot,initprot,sects=[]):
    body=struct.pack('<16sQQQQiiII',name.encode(),vmaddr,vmsize,fileoff,filesize,maxprot,initprot,len(sects),0)
    for s in sects: body+=s
    return struct.pack('<II',0x19,8+len(body))+body
def sect(name,segname,addr,size,offset):
    return struct.pack('<16s16sQQIIIIIIII',name.encode(),segname.encode(),addr,size,offset,2,0,0,0x80000400,0,0,0)
code=bytes.fromhex('000080d2c0035fd6')  # mov x0,#0 ; ret
textoff=PAGE-len(code)
cmds.append(seg('__PAGEZERO',0,0x100000000,0,0,0,0))
cmds.append(seg('__TEXT',0x100000000,PAGE,0,PAGE,5,5,[sect('__text','__TEXT',0x100000000+textoff,len(code),textoff)]))
linkoff=PAGE
cmds.append(seg('__LINKEDIT',0x100000000+PAGE,PAGE,linkoff,16,1,1))
cmds.append(struct.pack('<IIIIII',0x2,24,linkoff,0,linkoff,16))  # symtab: no syms, 16 byte strtab
cmds.append(struct.pack('<II18I',0xb,80,*([0]*18)))
dyld=b'/usr/lib/dyld\0'; dyld+=b'\0'*((8-(12+len(dyld))%8)%8)
cmds.append(struct.pack('<III',0xe,12+len(dyld),12)+dyld)
cmds.append(struct.pack('<IIQQ',0x80000028,24,textoff,0))
lib=b'/usr/lib/libSystem.B.dylib\0'; lib+=b'\0'*((8-(24+len(lib))%8)%8)
cmds.append(struct.pack('<IIIIII',0xc,24+len(lib),24,2,0x05276403,0x00010000)+lib)
lib2=b'@rpath/WMF.framework/WMF\0'; lib2+=b'\0'*((8-(24+len(lib2))%8)%8)
cmds.append(struct.pack('<IIIIII',0xc,24+len(lib2),24,2,0x10000,0x10000)+lib2)
blob=b''.join(cmds)
hdr=struct.pack('<IiiIIIII',0xfeedfacf,0x0100000c,0,2,len(cmds),len(blob),0x00200085,0)
out=hdr+blob
out+=b'\0'*(textoff-len(out))+code
out+=b'\0'*16
open(sys.argv[1] if len(sys.argv) > 1 else 'Wikipedia','wb').write(out)
print(len(out))
