#!/usr/bin/env python3
"""Reference values for the round 3 native metadata tests, from independent tools.

  * samples/extras/native-meta/objc-*-macos: llvm-objdump --macho --objc-meta-data (LLVM 19) and
    llvm-nm for method implementation addresses, radare2 rabin2 -cj for ivar offsets.
  * Maccy 2.8.0 (samples/.cache/extras/maccy-Maccy.macho, both slices): radare2 rabin2 -cj
    (classes, methods, ivars, Swift types and fields), plus the binary's own nominal type
    descriptor symbols demangled by swift-demangle are not needed: the test checks those itself.
  * samples/extras/dart/main-aot.so: the V8 snapshot profile and instruction sizes that Dart's
    gen_snapshot 3.5.4 wrote while building the snapshot (--write-v8-snapshot-profile-to and
    --print-instructions-sizes-to), reduced to the read only strings and the function names.

Run with the tools on PATH (. /workspace/work/tools/env.sh):
  python3 packages/extras/scripts/gen_reference_r3.py <dart profile.json> <dart sizes.json>
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..', '..', '..'))
NM = os.path.join(ROOT, 'samples', 'extras', 'native-meta')


def run(*a):
    return subprocess.run(a, check=True, capture_output=True, text=True, timeout=300).stdout


def parse_objdump(text, syms):
    classes, cats, protos = [], [], []
    cur = None; meta = False; sect = None; pending = {}; in_cls_dump = False; where = None
    def mlist(target, kind):
        return target.setdefault(kind, [])
    for line in text.split('\n'):
        if line.startswith('Contents of'):
            where = re.search(r',(\w+)\)', line).group(1); cur = None; continue
        m = re.match(r'^[0-9a-f]{16} 0x[0-9a-f]+ (\S+)$', line)
        if m and where == '__objc_classlist':
            cur = {'symbol': m.group(1), 'methods': [], 'classMethods': [], 'ivars': [], 'properties': [], 'protocols': []}
            classes.append(cur); meta = False; sect = None; continue
        if m and where == '__objc_catlist':
            cur = {'symbol': m.group(1), 'instanceMethods': [], 'classMethods': [], 'properties': []}
            cats.append(cur); sect = None; in_cls_dump = False; continue
        if m and where == '__objc_protolist':
            protos.append(m.group(1).replace('__OBJC_PROTOCOL_$_', '')); continue
        if cur is None:
            continue
        if where == '__objc_catlist':
            if line.startswith('              name ') and 'name' not in cur:
                cur['name'] = line.split()[-1]; continue
            if line.startswith('               cls '):
                in_cls_dump = True; continue
            if line.startswith('   instanceMethods '): in_cls_dump = False; sect = 'instanceMethods'; continue
            if line.startswith('      classMethods '): sect = 'classMethods'; continue
            if line.startswith('         protocols '): sect = None; continue
            if line.startswith('instanceProperties '): sect = 'properties'; continue
            if in_cls_dump: continue
        else:
            if line.startswith('Meta Class'): meta = True; sect = None; continue
            if line.startswith('                    flags ') and not meta: cur['flags'] = int(line.split()[1], 16); continue
            if line.startswith('            instanceStart ') and not meta: cur['instanceStart'] = int(line.split()[1]); continue
            if line.startswith('             instanceSize ') and not meta: cur['instanceSize'] = int(line.split()[1]); continue
            if line.startswith('                     name ') and not meta: cur['name'] = line.split()[-1]; continue
            if line.startswith('    superclass ') and not meta: cur['superclass'] = line.split()[-1].replace('_OBJC_CLASS_$_', '') if len(line.split()) > 2 else None; continue
            if line.startswith('              baseMethods '): sect = 'classMethods' if meta else 'methods'; continue
            if line.startswith('            baseProtocols '): sect = 'protocols'; continue
            if line.startswith('                    ivars '): sect = 'ivars'; continue
            if line.startswith('           weakIvarLayout'): sect = None; continue
            if line.startswith('           baseProperties '): sect = None if meta else 'properties'; continue
            if sect == 'protocols' and line.startswith('\t\t\t     name ') and not meta:
                cur['protocols'].append(line.split()[-1]); continue
        if sect in ('methods', 'classMethods', 'instanceMethods'):
            if line.startswith('\t\t      name '): pending = {'name': line.split()[-1]}
            elif line.startswith('\t\t     types '): pending['types'] = line.split(None, 2)[2] if len(line.split()) > 2 else ''
            elif line.startswith('\t\t       imp '):
                imp = line.split(None, 1)[1]
                pending['impSymbol'] = imp
                pending['imp'] = syms.get(imp)
                cur[sect].append(pending); pending = {}
        elif sect == 'ivars':
            if line.startswith('\t\t\t     name '): pending = {'name': line.split()[-1]}
            elif line.startswith('\t\t\t     type '): pending['type'] = line.split()[-1]
            elif line.startswith('\t\t\talignment '): pending['alignment'] = int(line.split()[-1])
            elif line.startswith('\t\t\t     size '): pending['size'] = int(line.split()[-1]); cur['ivars'].append(pending); pending = {}
        elif sect == 'properties':
            if line.startswith('\t\t\t     name '): pending = {'name': line.split()[-1]}
            elif line.startswith('\t\t\tattributes '): pending['attributes'] = line.split()[-1]; cur['properties'].append(pending); pending = {}
    return {'classes': classes, 'categories': cats, 'protocols': protos}


def nm_syms(path):
    out = {}
    for line in run('llvm-nm', path).split('\n'):
        m = re.match(r'^([0-9a-f]+) \w (.+)$', line)
        if m: out[m.group(2)] = '0x' + m.group(1).lstrip('0')
    return out


def r2_classes(path, arch=None):
    args = ['rabin2', '-cj'] + (['-a', arch] if arch else []) + [path]
    return json.loads(run(*args))['classes']


def compact_r2(classes):
    objc, swift = {}, {}
    for c in classes:
        key = hex(c['addr'])
        if c['lang'] == 'objc':
            objc[key] = {'name': c['classname'], 'super': (c.get('super') or [None])[0],
                         'methods': [[m['name'], hex(m['addr']), 'class' in m.get('flags', [])] for m in c.get('methods', [])],
                         'ivars': [[f['name'], f.get('offset')] for f in c.get('fields', []) if f.get('kind') == 'var' and f['name'] != 'isa']}
        else:
            swift[key] = {'name': c['classname'], 'kind': (c.get('attr') or ['class'])[0],
                          'fields': [[f['name'], f.get('type')] for f in c.get('fields', [])]}
    return {'objc': objc, 'swift': swift}


def main():
    ref = {'objcFixture': {}, 'maccy': {}, 'dart': {}}
    for arch in ('aarch64', 'x86_64'):
        p = os.path.join(NM, f'objc-{arch}-macos')
        text = run('llvm-objdump', '--macho', '--objc-meta-data', p)
        d = parse_objdump(text, nm_syms(p))
        offs = {}
        for c in r2_classes(p):
            for f in c.get('fields', []):
                if f.get('kind') == 'var' and 'offset' in f: offs[c['classname'] + '.' + f['name']] = f['offset']
        d['ivarOffsets'] = offs
        ref['objcFixture'][arch] = d
    maccy = os.path.join(ROOT, 'samples', '.cache', 'extras', 'maccy-Maccy.macho')
    if os.path.exists(maccy):
        for arch, r2arch in (('x86_64', 'x86_64'), ('arm64', 'arm_64')):
            ref['maccy'][arch] = compact_r2(r2_classes(maccy, r2arch))
    if len(sys.argv) > 2:
        prof = json.load(open(sys.argv[1]))
        meta = prof['snapshot']['meta']; types = meta['node_types'][0]; nf = len(meta['node_fields'])
        nodes = prof['nodes']; strs = prof['strings']
        ro = sorted({strs[nodes[i + 1]] for i in range(0, len(nodes), nf) if types[nodes[i]] == '(RO) String'})
        sizes = json.load(open(sys.argv[2]))
        ref['dart'] = {'sdk': '3.5.4 (stable) linux_arm64', 'roStrings': ro, 'instructionsEntries': len(sizes),
                       'functions': sorted({(s.get('c', '') + '.' if s.get('c') else '') + re.sub(r'^\[\w+\] ', '', s['n']) for s in sizes})}
    with open(os.path.join(NM, 'reference.json'), 'w') as f:
        json.dump(ref, f, indent=0, sort_keys=True)
    print('wrote', os.path.join(NM, 'reference.json'))


if __name__ == '__main__':
    main()
