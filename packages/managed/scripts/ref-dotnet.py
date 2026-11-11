# Reference dump for .NET fixtures using dnfile (MIT) and dncil (Apache-2.0).
# Dev only. Usage: python3 ref-dotnet.py <assembly.dll> <out.json> [--summary]
# --summary keeps a compact record: an aggregate sha1 over every method's instruction stream plus samples.
import sys, json, hashlib, dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.error import MethodBodyFormatError

class R(CilMethodBodyReaderBase):
    def __init__(self, pe, rva):
        self.pe = pe; self.off = pe.get_offset_from_rva(rva)
    def read(self, n):
        d = self.pe.get_data(self.pe.get_rva_from_offset(self.off), n); self.off += n; return d
    def tell(self): return self.off
    def seek(self, off): self.off = off; return off

path, out = sys.argv[1], sys.argv[2]
pe = dnfile.dnPE(path)
t = pe.net.mdtables
rowcounts = {}
for tbl in t.tables_list:
    rowcounts[tbl.name] = tbl.num_rows
asm = t.Assembly[0]
methods = {}
for i, m in enumerate(t.MethodDef):
    rid = i + 1
    if not m.Rva or (m.ImplFlags.miNative if hasattr(m.ImplFlags, 'miNative') else False): continue
    try:
        body = CilMethodBody(R(pe, m.Rva))
    except MethodBodyFormatError:
        continue
    seq = [(ins.offset - body.offset - body.header_size, ins.opcode.name.lower(), ins.size) for ins in body.instructions]
    s = ';'.join(f'{o}:{n}' for o, n, _ in seq)
    methods[f'{0x06000000 | rid:08x}'] = {'n': len(seq), 'sha1': hashlib.sha1(s.encode()).hexdigest(), 'first': [n for _, n, _ in seq[:6]], 'codeSize': body.code_size, 'maxStack': body.max_stack}
us = pe.net.user_strings
summary = '--summary' in sys.argv
if summary:
    agg = hashlib.sha1('\n'.join(f'{k}:{v["sha1"]}' for k, v in sorted(methods.items())).encode()).hexdigest()
    sample = {k: methods[k] for k in sorted(methods)[:: max(1, len(methods) // 40)]}
    methods_out = {'count': len(methods), 'instructions': sum(v['n'] for v in methods.values()), 'aggregateSha1': agg, 'sample': sample}
else:
    methods_out = methods
json.dump({
    'assembly': {'name': str(asm.Name), 'version': f'{asm.MajorVersion}.{asm.MinorVersion}.{asm.BuildNumber}.{asm.RevisionNumber}'},
    'assemblyRefs': [str(r.Name) for r in (t.AssemblyRef or [])],
    'moduleRefs': [str(r.Name) for r in (t.ModuleRef or [])],
    'implMap': [str(r.ImportName) for r in (t.ImplMap or [])],
    'resources': [str(r.Name) for r in (t.ManifestResource or [])],
    'typeNames': [f'{r.TypeNamespace}.{r.TypeName}' if str(r.TypeNamespace) else str(r.TypeName) for r in t.TypeDef][: (60 if summary else None)],
    'rowCounts': rowcounts,
    'methods': methods_out,
}, open(out, 'w'), indent=0 if not summary else None)
print(path, len(methods), 'methods with bodies')
