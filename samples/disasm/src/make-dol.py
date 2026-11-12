#!/usr/bin/env python3
"""Packs a big endian PowerPC ELF into a GameCube DOL: executable sections become text sections,
other loaded sections data sections, .bss/.sbss the bss range. Usage: make-dol.py in.elf out.dol"""
import struct, sys
from elftools.elf.elffile import ELFFile

elf = ELFFile(open(sys.argv[1], 'rb'))
texts, datas, bss = [], [], []
for s in elf.iter_sections():
    if not (s['sh_flags'] & 2) or s['sh_size'] == 0 or s.name.startswith('.eh_frame'): continue
    if s['sh_type'] == 'SHT_NOBITS': bss.append((s['sh_addr'], s['sh_size'])); continue
    (texts if s['sh_flags'] & 4 else datas).append((s['sh_addr'], s.data()))
assert len(texts) <= 7 and len(datas) <= 11
hdr = bytearray(0x100)
body = bytearray()
off = 0x100
def place(i, addr, data):
    global off, body
    struct.pack_into('>I', hdr, i * 4, off); struct.pack_into('>I', hdr, 0x48 + i * 4, addr); struct.pack_into('>I', hdr, 0x90 + i * 4, len(data))
    body += data + b'\0' * ((-len(data)) % 32); off = 0x100 + len(body)
for i, (a, d) in enumerate(texts): place(i, a, d)
for i, (a, d) in enumerate(datas): place(7 + i, a, d)
if bss:
    lo = min(a for a, _ in bss); hi = max(a + n for a, n in bss)
    struct.pack_into('>II', hdr, 0xd8, lo, hi - lo)
struct.pack_into('>I', hdr, 0xe0, elf['e_entry'])
open(sys.argv[2], 'wb').write(hdr + body)
print('wrote', sys.argv[2], len(hdr + body), 'bytes')
