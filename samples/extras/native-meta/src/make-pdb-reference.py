#!/usr/bin/env python3
"""Reference values for the PDB fixtures from llvm-pdbutil 19 (`pdb2yaml`): PDB info (GUID, age),
TPI records (struct, class, union and enum definitions with their members, offsets and sizes,
procedure argument counts), IPI LF_FUNC_ID names, and module procedure symbols with their
parameters and locals. Usage: make-pdb-reference.py out.json file.pdb..."""
import json, re, subprocess, sys, yaml

class Loader(yaml.SafeLoader):
    pass
# YAML 1.1 reads On/Off/Yes/No as booleans; enumerator names like `On` must stay strings
Loader.yaml_implicit_resolvers = {k: [(t, r) for t, r in v if t != 'tag:yaml.org,2002:bool'] for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
Loader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$'), list('tf'))

def one(path):
    y = yaml.load(subprocess.run(['llvm-pdbutil', 'pdb2yaml', '-tpi-stream', '-ipi-stream', '-pdb-stream', '-dbi-stream', '-module-syms', path], capture_output=True, text=True, check=True).stdout, Loader=Loader)
    recs = y['TpiStream']['Records']
    ti = {0x1000 + i: r for i, r in enumerate(recs)}
    out = {'guid': y['PdbStream']['Guid'].strip('{}').upper(), 'age': y['PdbStream']['Age'], 'types': {}, 'procedures': {}, 'funcIds': [], 'procs': []}
    for i, r in ti.items():
        k = r['Kind']
        if k in ('LF_STRUCTURE', 'LF_CLASS', 'LF_UNION', 'LF_ENUM'):
            body = r.get('Class') or r.get('Union') or r.get('Enum')
            if 'ForwardReference' in body.get('Options', []): continue
            fl = ti.get(body.get('FieldList'))
            members = []
            for m in (fl or {}).get('FieldList', []):
                mk = m['Kind']
                if mk == 'LF_MEMBER': members.append({'kind': 'member', 'name': m['DataMember']['Name'], 'offset': m['DataMember']['FieldOffset'], 'typeIndex': m['DataMember']['Type']})
                elif mk == 'LF_ENUMERATE': members.append({'kind': 'enumerate', 'name': m['Enumerator']['Name'], 'value': int(m['Enumerator']['Value'])})
                elif mk == 'LF_STMEMBER': members.append({'kind': 'static', 'name': m['StaticDataMember']['Name']})
                elif mk == 'LF_BCLASS': members.append({'kind': 'base', 'offset': m['BaseClass']['Offset'], 'typeIndex': m['BaseClass']['Type']})
                elif mk == 'LF_ONEMETHOD': members.append({'kind': 'method', 'name': m['OneMethod']['Name']})
                elif mk == 'LF_METHOD': members.append({'kind': 'method', 'name': m['OverloadedMethod']['Name']})
                elif mk == 'LF_VFUNCTAB': members.append({'kind': 'vfptr'})
            out['types'][body['Name']] = {'index': i, 'leaf': k, 'size': body.get('Size'), 'underlying': body.get('UnderlyingType'), 'members': members}
        elif k == 'LF_PROCEDURE':
            out['procedures'][hex(i)] = {'returnType': r['Procedure']['ReturnType'], 'params': r['Procedure']['ParameterCount']}
    for r in y.get('IpiStream', {}).get('Records', []):
        if r['Kind'] == 'LF_FUNC_ID': out['funcIds'].append({'name': r['FuncId']['Name'], 'typeIndex': r['FuncId']['FunctionType']})
    for mod in y['DbiStream']['Modules']:
        cur = None
        for s in mod.get('Modi', {}).get('Records', []):
            if s['Kind'] in ('S_GPROC32', 'S_LPROC32'):
                p = s['ProcSym']
                cur = {'kind': s['Kind'], 'name': p['DisplayName'], 'segment': p['Segment'], 'offset': p['Offset'], 'size': p['CodeSize'], 'typeIndex': p['FunctionType'], 'locals': []}
                out['procs'].append(cur)
            elif s['Kind'] == 'S_LOCAL' and cur is not None:
                l = s['LocalSym']
                cur['locals'].append({'name': l['VarName'], 'param': 'IsParameter' in l.get('Flags', [])})
            elif s['Kind'] == 'S_END': cur = None
    return out

res = {p.split('/')[-1]: one(p) for p in sys.argv[2:]}
json.dump(res, open(sys.argv[1], 'w'), indent=1, sort_keys=True)
print('wrote', sys.argv[1])
