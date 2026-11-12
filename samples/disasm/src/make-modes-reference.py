#!/usr/bin/env python3
"""Reference values for the load mode fixtures from radare2 (independent of RevLens): instruction
addresses, sizes, text and branch targets of hello16.com (x86 16 bit at 0x100) and of the functions
in demo-ppc.dol (PowerPC 32 big endian; addresses from the ELF symbol table via pyelftools).
Usage: make-modes-reference.py out.json"""
import json, subprocess, sys
from elftools.elf.elffile import ELFFile

def r2(args, cmd):
    out = subprocess.run(['r2', '-q', '-2', '-c', cmd] + args, capture_output=True, text=True, check=True).stdout
    return json.loads(out)

def insns(lst):
    return [{'addr': hex(x['addr']), 'size': x['size'], 'text': x.get('opcode', x['disasm']), 'type': x['type'], **({'jump': hex(x['jump'])} if 'jump' in x else {})} for x in lst]

ref = {}
ref['hello16.com'] = {'insns': insns(r2(['-a', 'x86', '-b', '16', '-m', '0x100', 'hello16.com'], 'pdj 11 @ 0x100'))}
syms = {s.name: s['st_value'] for s in ELFFile(open('src/dolmain.elf', 'rb')).get_section_by_name('.symtab').iter_symbols() if s['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT')}
ref['demo-ppc.dol'] = {'symbols': {k: hex(v) for k, v in syms.items()}, 'functions': {},
    'sections': [{'name': x['name'], 'vaddr': hex(x['vaddr']), 'size': x['vsize'], 'paddr': x['paddr'], 'perm': x['perm']} for x in r2(['demo-ppc.dol'], 'iSj')],
    'entry': hex(r2(['demo-ppc.dol'], 'iej')[0]['vaddr'])}
for name in ('mix', 'spin', '__start'):
    a = syms[name]
    lst = r2(['-e', 'asm.sub.names=false', 'demo-ppc.dol'], f'af @ {hex(a)}; pdfj @ {hex(a)}')
    ref['demo-ppc.dol']['functions'][name] = {'addr': hex(a), 'insns': insns(lst['ops'])}
json.dump(ref, open(sys.argv[1], 'w'), indent=1)
print('wrote', sys.argv[1])
