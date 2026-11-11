#!/usr/bin/env python3
"""Reference member lists for managed_compare_members and managed_pinvoke_map, using dnfile 0.18.0 (MIT).
Usage: ref-members.py <out.json> <assembly.dll>...  Writes per assembly: types (full name with / for nesting)
with method keys name/paramCount and field names, plus ImplMap rows (module, entry, flags, member name)."""
import sys, json, dnfile

def comp(b, i):
    x = b[i]
    if x & 0x80 == 0: return x, i + 1
    if x & 0xc0 == 0x80: return ((x & 0x3f) << 8) | b[i + 1], i + 2
    return ((x & 0x1f) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3], i + 4

def nparams(blob):
    b = blob.value if isinstance(blob.value, (bytes, bytearray)) else bytes(blob.raw_data); i = 1
    if b[0] & 0x10: _, i = comp(b, i)
    n, _ = comp(b, i)
    return n

def dump(path):
    pe = dnfile.dnPE(path)
    t = pe.net.mdtables
    tds = list(t.TypeDef)
    enclosing = {}
    if t.NestedClass:
        for nc in t.NestedClass: enclosing[nc.NestedClass.row_index] = nc.EnclosingClass.row_index
    def name(rid, d=0):
        td = tds[rid - 1]
        n = (str(td.TypeNamespace) + '.' if str(td.TypeNamespace) else '') + str(td.TypeName)
        return name(enclosing[rid], d + 1) + '/' + str(td.TypeName) if rid in enclosing and d < 32 else n
    types = {}
    for rid, td in enumerate(tds, 1):
        ms = sorted(f'{m.row.Name}/{nparams(m.row.Signature)}' for m in td.MethodList)
        fs = sorted(str(f.row.Name) for f in td.FieldList)
        types[name(rid)] = {'methods': ms, 'fields': fs}
    impl = []
    if t.ImplMap:
        for im in t.ImplMap:
            f = im.MappingFlags
            cs = next(k for k in ['Ansi', 'Auto', 'NotSpec', 'Unicode'] if getattr(f, 'pmCharSet' + k))
            cc = next((k for k in ['Cdecl', 'Fastcall', 'Stdcall', 'Thiscall', 'Winapi'] if getattr(f, 'pmCallConv' + k)), 'default')
            impl.append({'module': str(im.ImportScope.row.Name), 'entry': str(im.ImportName), 'charset': cs, 'exactSpelling': bool(f.pmNoMangle), 'setLastError': bool(f.pmSupportsLastError), 'callConv': cc, 'member': str(im.MemberForwarded.row.Name)})
    return {'types': types, 'implMap': impl}

out = {p.split('/')[-1]: dump(p) for p in sys.argv[2:]}
json.dump(out, open(sys.argv[1], 'w'), indent=None, sort_keys=True, separators=(',', ':'))
