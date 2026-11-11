# Writes gaps-reference.json with values read by pyelftools 0.33:
# - lua-x64-stripped.elf: the function symbols of the build it was stripped from (same addresses).
#   The stripped file has no symbols, so this is the ground truth for stripped vs unstripped matching.
# - lua-x64.elf: address and size of luaV_execute.disptab and luaV_execute (jump table checks).
# - virt-x64.elf / virt-arm64.elf: vtable symbols (_ZTV*) with addresses and sizes.
# Usage: python3 make-gaps-reference.py lua-x64-reordered.unstripped > gaps-reference.json  (run in samples/disasm)
import json, sys
from elftools.elf.elffile import ELFFile

def syms(path):
    f = ELFFile(open(path, 'rb'))
    for s in f.get_section_by_name('.symtab').iter_symbols():
        if s['st_value'] and s['st_shndx'] != 'SHN_UNDEF':
            yield s

out = {}
funcs = {}
for s in syms(sys.argv[1]):
    if s['st_info']['type'] == 'STT_FUNC':
        funcs.setdefault(s.name, {'addr': s['st_value'], 'size': s['st_size']})
out['lua-x64-stripped.elf'] = {'source': 'pyelftools 0.33 on the unstripped twin', 'functions': funcs}
lua = {s.name: {'addr': s['st_value'], 'size': s['st_size']} for s in syms('lua-x64.elf') if s.name in ('luaV_execute.disptab', 'luaV_execute')}
out['lua-x64.elf'] = {'disptab': lua['luaV_execute.disptab'], 'luaV_execute': lua['luaV_execute']}
for v in ('virt-x64.elf', 'virt-arm64.elf'):
    out[v] = {'vtables': {s.name: {'addr': s['st_value'], 'size': s['st_size']} for s in syms(v) if s.name.startswith('_ZTV')}}
json.dump(out, sys.stdout, indent=0, sort_keys=True)
