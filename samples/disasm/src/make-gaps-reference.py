# Writes gaps-reference.json: the function symbols of the Lua build that lua-x64-stripped.elf was
# stripped from (same addresses), read with pyelftools. The stripped file has no symbols, so this
# is the ground truth for stripped vs unstripped function matching.
# Usage: python3 make-gaps-reference.py lua-x64-reordered.unstripped > ../gaps-reference.json
import json, sys
from elftools.elf.elffile import ELFFile
f = ELFFile(open(sys.argv[1], 'rb'))
out = {}
for s in f.get_section_by_name('.symtab').iter_symbols():
    if s['st_info']['type'] == 'STT_FUNC' and s['st_value'] and s['st_shndx'] != 'SHN_UNDEF':
        out.setdefault(s.name, {'addr': s['st_value'], 'size': s['st_size']})
json.dump({'lua-x64-stripped.elf': {'source': 'pyelftools 0.33 on the unstripped twin', 'functions': out}}, sys.stdout, indent=0, sort_keys=True)
