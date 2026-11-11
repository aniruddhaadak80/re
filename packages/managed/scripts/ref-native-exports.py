#!/usr/bin/env python3
"""Reference export lists for samples/managed/native with LLVM 19 tools (dev only):
llvm-nm -D --defined-only (ELF), llvm-readobj --coff-exports (PE), llvm-objdump --macho --exports-trie (Mach-O)."""
import json, os, re, subprocess, sys
L = os.environ.get('LLVM_BIN', '/workspace/work/tools/sysroot/usr/lib/llvm-19/bin')
root = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'samples', 'managed', 'native')
def run(*a): return subprocess.run([os.path.join(L, a[0]), *a[1:]], capture_output=True, text=True, check=True).stdout
out = {}
for rid, f, kind in [('linux-x64', 'libSystem.IO.Compression.Native.so', 'elf'), ('win-x64', 'System.IO.Compression.Native.dll', 'pe'), ('osx-arm64', 'libSystem.IO.Compression.Native.dylib', 'macho')]:
    p = os.path.join(root, rid, f)
    ex = {}
    if kind == 'elf':
        for line in run('llvm-nm', '-D', '--defined-only', p).splitlines():
            a, t, n = line.split()
            if t in 'TDBRW': ex[n.split('@')[0]] = hex(int(a, 16))
    elif kind == 'pe':
        txt = run('llvm-readobj', '--coff-exports', p)
        for o, n, r in re.findall(r'Ordinal: (\d+)\s+Name: (\S+)\s+RVA: (0x[0-9A-Fa-f]+)', txt): ex[n] = {'ordinal': int(o), 'address': hex(int(r, 16))}
    else:
        for line in run('llvm-objdump', '--macho', '--exports-trie', p).splitlines():
            m = re.match(r'(0x[0-9A-Fa-f]+)\s+_(\S+)', line.strip())
            if m: ex[m.group(2)] = hex(int(m.group(1), 16))
    out[f'{rid}/{f}'] = ex
json.dump(out, open(os.path.join(root, 'exports.ref.json'), 'w'), indent=1, sort_keys=True)
