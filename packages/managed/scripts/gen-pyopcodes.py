# Dump the opcode table of the running CPython as JSON (dev only, used to generate src/python/opcodes.ts).
import dis, opcode, sys, json, importlib.util
v = f"{sys.version_info.major}.{sys.version_info.minor}"
names = {}
for i, n in enumerate(dis.opname):
    if not n.startswith('<'):
        names[i] = n
# 3.13 has pseudo / instrumented opcodes above 255 in opmap; keep only real bytes.
names = {i: n for i, n in names.items() if i < 256}
def lst(attr):
    return sorted(x for x in getattr(dis, attr, []) if x < 256)
cache = {}
ice = getattr(opcode, '_inline_cache_entries', None)
if isinstance(ice, dict):
    for n, c in ice.items():
        if c and n in opcode.opmap: cache[opcode.opmap[n]] = c
elif isinstance(ice, list):
    for i, c in enumerate(ice):
        if c and i < 256: cache[i] = c
out = {
    'version': v,
    'magic': int.from_bytes(importlib.util.MAGIC_NUMBER[:2], 'little'),
    'names': names,
    'hasconst': lst('hasconst'), 'hasname': lst('hasname'), 'hasjrel': lst('hasjrel'), 'hasjabs': lst('hasjabs'),
    'haslocal': lst('haslocal'), 'hasfree': lst('hasfree'), 'hascompare': lst('hascompare'),
    'hasarg': lst('hasarg') if hasattr(dis, 'hasarg') else [i for i in names if i >= dis.HAVE_ARGUMENT] if hasattr(dis, 'HAVE_ARGUMENT') else [],
    'haveArgument': getattr(dis, 'HAVE_ARGUMENT', None),
    'extendedArg': dis.opmap.get('EXTENDED_ARG'),
    'cache': cache,
    'cmpOp': list(dis.cmp_op),
    'nbOps': [s for _, s in getattr(opcode, '_nb_ops', [])],
}
print(json.dumps(out))
