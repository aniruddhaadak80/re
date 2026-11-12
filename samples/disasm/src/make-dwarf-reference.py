#!/usr/bin/env python3
"""Reference values for the DWARF type fixtures, from two independent readers:
pyelftools 0.33 (structure: sizes, member offsets, bit fields, enumerators, function ranges,
parameter and local names, global addresses) and llvm-dwarfdump 19 (the C type names it prints
in quotes after DW_AT_type). Usage: make-dwarf-reference.py out.json fixture.elf...
"""
import json, re, subprocess, sys
from elftools.elf.elffile import ELFFile

def llvm_types(path):
    out = subprocess.run(['llvm-dwarfdump', '--debug-info', path], capture_output=True, text=True, check=True).stdout
    cur = None; m = {}
    for line in out.splitlines():
        h = re.match(r'^(0x[0-9a-f]+):\s+DW_TAG_', line)
        if h: cur = int(h.group(1), 16); continue
        t = re.search(r'DW_AT_type\s+\(0x[0-9a-f]+ "(.*)"\)$', line)
        if t and cur is not None: m[cur] = t.group(1)
    return m

def attr(die, name, default=None):
    a = die.attributes.get(name)
    return a.value if a is not None else default

def sname(die):
    v = attr(die, 'DW_AT_name')
    return v.decode() if isinstance(v, bytes) else v

def cxx(path):
    """C++ units: every class/struct/enum DIE (by .debug_info offset) with members and llvm type names."""
    tnames = llvm_types(path)
    res = {'classes': {}, 'functions': {}}
    with open(path, 'rb') as f:
        dw = ELFFile(f).get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type') and sname(die) and 'DW_AT_declaration' not in die.attributes:
                    mem = []
                    for c in die.iter_children():
                        if c.tag == 'DW_TAG_member':
                            mem.append({'name': sname(c), 'offset': attr(c, 'DW_AT_data_member_location'), 'type': tnames.get(c.offset)})
                        elif c.tag == 'DW_TAG_inheritance':
                            mem.append({'name': '<base>', 'offset': attr(c, 'DW_AT_data_member_location'), 'type': tnames.get(c.offset)})
                    res['classes'][hex(die.offset)] = {'name': sname(die), 'size': attr(die, 'DW_AT_byte_size'), 'members': mem}
                elif die.tag == 'DW_TAG_enumeration_type' and sname(die):
                    res['classes'][hex(die.offset)] = {'name': sname(die), 'enumerators': {sname(c): c.attributes['DW_AT_const_value'].value for c in die.iter_children() if c.tag == 'DW_TAG_enumerator'}}
                elif die.tag == 'DW_TAG_subprogram' and 'DW_AT_low_pc' in die.attributes:
                    res['functions'][hex(die.attributes['DW_AT_low_pc'].value)] = {'name': sname(die), 'params': [tnames.get(c.offset) for c in die.iter_children() if c.tag == 'DW_TAG_formal_parameter']}
    return res

def one(path):
    if path.endswith('.cpp.elf') or 'shapes' in path: return cxx(path)
    tnames = llvm_types(path)
    res = {'structs': {}, 'enums': {}, 'typedefs': {}, 'functions': {}, 'globals': {}}
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            top = cu.get_top_DIE()
            if sname(top) != 'types.c': continue
            res['version'] = cu['version']
            for die in top.iter_children():
                tag = die.tag; n = sname(die)
                if tag in ('DW_TAG_structure_type', 'DW_TAG_union_type') and n:
                    mem = []
                    for c in die.iter_children():
                        if c.tag != 'DW_TAG_member': continue
                        e = {'name': sname(c), 'type': tnames.get(c.offset)}
                        dml = attr(c, 'DW_AT_data_member_location')
                        if isinstance(dml, int): e['offset'] = dml
                        if attr(c, 'DW_AT_bit_size') is not None: e['bitSize'] = attr(c, 'DW_AT_bit_size')
                        if attr(c, 'DW_AT_data_bit_offset') is not None: e['bitOffset'] = attr(c, 'DW_AT_data_bit_offset')
                        mem.append(e)
                    res['structs'][('union ' if tag == 'DW_TAG_union_type' else 'struct ') + n] = {'size': attr(die, 'DW_AT_byte_size'), 'members': mem}
                elif tag == 'DW_TAG_enumeration_type' and n:
                    res['enums'][n] = {c.attributes['DW_AT_name'].value.decode(): c.attributes['DW_AT_const_value'].value for c in die.iter_children() if c.tag == 'DW_TAG_enumerator'}
                elif tag == 'DW_TAG_typedef':
                    res['typedefs'][n] = tnames.get(die.offset)
                elif tag == 'DW_TAG_subprogram' and n and 'DW_AT_low_pc' in die.attributes:
                    lo = die.attributes['DW_AT_low_pc']
                    low = lo.value
                    hi = die.attributes['DW_AT_high_pc']
                    high = low + hi.value if hi.form.startswith('DW_FORM_data') else hi.value
                    params = [{'name': sname(c), 'type': tnames.get(c.offset)} for c in die.iter_children() if c.tag == 'DW_TAG_formal_parameter']
                    def locals_of(d):
                        out = []
                        for c in d.iter_children():
                            if c.tag == 'DW_TAG_variable': out.append(sname(c))
                            elif c.tag == 'DW_TAG_lexical_block': out += locals_of(c)
                        return out
                    res['functions'][n] = {'low': hex(low), 'high': hex(high), 'returns': tnames.get(die.offset, 'void'), 'params': params, 'locals': locals_of(die)}
                elif tag == 'DW_TAG_variable' and n:
                    loc = attr(die, 'DW_AT_location')
                    addr = None
                    if isinstance(loc, list) and loc and loc[0] == 0x03:
                        addr = int.from_bytes(bytes(loc[1:]), 'little')
                    elif isinstance(loc, list) and loc and loc[0] == 0xa1:
                        addr = dw.get_addr(cu, loc[1])
                    res['globals'][n] = {'type': tnames.get(die.offset), 'addr': hex(addr) if addr is not None else None}
    return res

out = {p.split('/')[-1]: one(p) for p in sys.argv[2:]}
json.dump(out, open(sys.argv[1], 'w'), indent=1, sort_keys=True)
print('wrote', sys.argv[1])
