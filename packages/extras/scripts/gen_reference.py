#!/usr/bin/env python3
"""Produce samples/extras/reference.json and src/eval/tasks.ts from INDEPENDENT reference tools.

Run once after rebuilding fixtures (needs network for the rustc-demangle vectors):
  source /workspace/work/tools/extras-env.sh   # llvm-19 tools, GNU binutils, binwalk
  python3 packages/extras/scripts/gen_reference.py

Reference tools: llvm-nm, llvm-cxxfilt, llvm-undname, llvm-readobj (LLVM 19), GNU c++filt and
readelf 2.44, binwalk 2.4.3, pefile, lief, pyelftools, gguf-py, safetensors, pylnk3, fdt,
intelhex, uboot (PyPI), rust-demangler (PyPI), go tool nm (Go 1.23.4), node vm.Script.
"""
import json, os, re, subprocess, sys, hashlib, struct, urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
S = os.path.join(ROOT, 'samples', 'extras')
CACHE = os.path.join(ROOT, 'samples', '.cache', 'extras')
def p(*a): return os.path.join(S, *a)
def sh(*cmd, inp=None):
    return subprocess.run(cmd, input=inp, capture_output=True, text=True, check=True).stdout

ref = {}

# ---- demangling ----
nm = sh('llvm-nm', '--defined-only', p('demo-x64.elf'))
itan_all = sorted({l.split()[-1] for l in nm.splitlines() if l.split() and l.split()[-1].startswith('_Z')})
itan = sorted(set([x for x in itan_all if 'revlens' in x] + itan_all[::max(1, len(itan_all) // 1200)]))
outs = sh('llvm-cxxfilt', inp='\n'.join(itan) + '\n').splitlines()
gnu = sh('c++filt', inp='\n'.join(itan) + '\n').splitlines()
ref['itanium'] = [{'mangled': m, 'llvm': o, 'gnu': g} for m, o, g in zip(itan, outs, gnu)]

msvc_syms = sorted({l.split()[-1] for l in sh('llvm-nm', p('demo-msvc.obj')).splitlines() if l.split() and l.split()[-1].startswith('?')})
ref['msvc'] = [{'mangled': m, 'undname': sh('llvm-undname', m).strip().splitlines()[-1]} for m in msvc_syms]

import rust_demangler
jnm = sh('llvm-nm', '-D', '--defined-only', p('jiter-0.5.0.so')) + sh('llvm-nm', '--defined-only', p('jiter-0.5.0.so'))
rleg_all = sorted({l.split()[-1] for l in jnm.splitlines() if l.split() and re.match(r'^_ZN.*17h[0-9a-f]{16}E$', l.split()[-1])})
rleg = rleg_all[::max(1, len(rleg_all) // 300)]
ref['rust_legacy'] = [{'mangled': m, 'demangled': rust_demangler.demangle(m)} for m in rleg]
src = urllib.request.urlopen('https://raw.githubusercontent.com/rust-lang/rustc-demangle/main/src/v0.rs').read().decode()
v0 = sorted({m for m in re.findall(r'"(_R[0-9A-Za-z_$.]+)"', src)})
v0out = sh('llvm-cxxfilt', inp='\n'.join(v0) + '\n').splitlines()
ref['rust_v0'] = [{'mangled': m, 'llvm': o} for m, o in zip(v0, v0out) if o != m]

# ---- ELF ----
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
with open(p('demo-x64.elf'), 'rb') as f:
    e = ELFFile(f)
    segs = [s for s in e.iter_segments()]
    relro = any(s['p_type'] == 'PT_GNU_RELRO' for s in segs)
    stack = [s for s in segs if s['p_type'] == 'PT_GNU_STACK']
    dyn = e.get_section_by_name('.dynamic')
    needed, flags1, bindnow = [], 0, False
    for t in dyn.iter_tags():
        if t.entry.d_tag == 'DT_NEEDED': needed.append(t.needed)
        if t.entry.d_tag == 'DT_FLAGS_1': flags1 = t.entry.d_val
        if t.entry.d_tag == 'DT_FLAGS' and t.entry.d_val & 8: bindnow = True
        if t.entry.d_tag == 'DT_BIND_NOW': bindnow = True
    dynsym = [s.name for s in e.get_section_by_name('.dynsym').iter_symbols()]
    ia = e.get_section_by_name('.init_array')
    init = list(struct.unpack('<%dQ' % (ia['sh_size'] // 8), ia.data())) if ia else []
    symtab = {s['st_value']: s.name for s in e.get_section_by_name('.symtab').iter_symbols() if s['st_info']['type'] == 'STT_FUNC'}
    # unwind ranges from .eh_frame via pyelftools
    fdes = []
    if e.has_ehabi_info() is False or True:
        cfi = e.get_dwarf_info().EH_CFI_entries() if e.get_dwarf_info().has_EH_CFI() else []
        for ent in cfi:
            if type(ent).__name__ == 'FDE':
                fdes.append((ent.header['initial_location'], ent.header['address_range']))
    ref['elf_x64'] = {
        'type': e['e_type'], 'needed': needed, 'relro': relro, 'bindNow': bindnow, 'nx': bool(stack and not (stack[0]['p_flags'] & 1)),
        'stackChk': '__stack_chk_fail' in dynsym, 'flags1': flags1,
        'initArray': [{'target': hex(t), 'symbol': symtab.get(t)} for t in init],
        'fdeCount': len(fdes), 'fdes': sorted([{'start': hex(a), 'size': s} for a, s in fdes], key=lambda x: int(x['start'], 16))[:50],
        'entry': hex(e['e_entry']),
    }
notes = sh('readelf', '-n', p('demo-x64.elf'))
ref['elf_x64']['readelfNotes'] = notes
ref['elf_arm64_stripped'] = {'fdeCount': len([l for l in sh('readelf', '--debug-dump=frames', p('demo-arm64-stripped.elf')).splitlines() if ' FDE cie=' in l])}

# ---- PE ----
import pefile
pe = pefile.PE(p('hello-res.exe'))
vi = {}
for fi in pe.FileInfo or []:
    for e2 in fi:
        if e2.Key == b'StringFileInfo':
            for st in e2.StringTable:
                for k, v in st.entries.items(): vi[k.decode()] = v.decode()
ffi = pe.VS_FIXEDFILEINFO[0]
res_types = []
for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for n in t.directory.entries:
        for l in n.directory.entries:
            res_types.append({'type': t.id, 'name': n.id if n.id is not None else str(n.name), 'lang': l.id, 'size': l.data.struct.Size, 'offset': pe.get_offset_from_rva(l.data.struct.OffsetToData)})
man = [r for r in res_types if r['type'] == 24][0]
mxml = pe.get_data(pe.DIRECTORY_ENTRY_RESOURCE.entries[[t.id for t in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(24)].directory.entries[0].directory.entries[0].data.struct.OffsetToData, man['size']).decode()
ref['pe_hello'] = {
    'machine': hex(pe.FILE_HEADER.Machine), 'imageBase': hex(pe.OPTIONAL_HEADER.ImageBase), 'entry': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
    'sections': [s.Name.rstrip(b'\0').decode() for s in pe.sections], 'checksumHeader': pe.OPTIONAL_HEADER.CheckSum, 'checksumComputed': pe.generate_checksum(),
    'fileVersion': '%d.%d.%d.%d' % (ffi.FileVersionMS >> 16, ffi.FileVersionMS & 0xffff, ffi.FileVersionLS >> 16, ffi.FileVersionLS & 0xffff),
    'productVersion': '%d.%d.%d.%d' % (ffi.ProductVersionMS >> 16, ffi.ProductVersionMS & 0xffff, ffi.ProductVersionLS >> 16, ffi.ProductVersionLS & 0xffff),
    'strings': vi, 'resources': res_types, 'manifestHasAsInvoker': 'asInvoker' in mxml,
    'exports': [x.name.decode() for x in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],
    'imports': sorted({d.dll.decode() for d in pe.DIRECTORY_ENTRY_IMPORT}),
    'rich': pe.parse_rich_header() is not None,
    'dllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
}
import lief
lief.logging.disable()
hb = lief.PE.parse(p('hello-res.exe'))
ref['pe_hello']['authentihashSha256'] = hb.authentihash(lief.PE.ALGORITHMS.SHA_256).hex()
sx = os.path.join(CACHE, 'strings64.exe')
if os.path.exists(sx):
    sb = lief.PE.parse(sx)
    sig = sb.signatures[0]
    ref['pe_strings64'] = {'sha256': hashlib.sha256(open(sx, 'rb').read()).hexdigest(), 'authentihashSha256': sb.authentihash(lief.PE.ALGORITHMS.SHA_256).hex(), 'signedDigest': bytes(sig.content_info.digest).hex(), 'verify': str(sb.verify_signature()), 'signerSerial': bytes(sig.signers[0].serial_number).hex(), 'signerIssuer': str(sig.signers[0].issuer)}

# ---- Mach-O ----
mb = lief.MachO.parse(p('hello-arm64.macho')).at(0)
cs = mb.code_signature
blob = open(p('hello-arm64.macho'), 'rb').read()[cs.data_offset: cs.data_offset + cs.data_size]
magic, length, count = struct.unpack('>III', blob[:12])
cds = []
for i in range(count):
    typ, off = struct.unpack('>II', blob[12 + 8 * i: 20 + 8 * i])
    m2, l2 = struct.unpack('>II', blob[off: off + 8])
    if m2 == 0xfade0c02:
        hash_type = blob[off + 37]
        h = hashlib.sha256 if hash_type == 2 else hashlib.sha1
        ident_off = struct.unpack('>I', blob[off + 20: off + 24])[0]
        ident = blob[off + ident_off: blob.index(b'\0', off + ident_off)].decode()
        cds.append({'slot': typ, 'cdhash': h(blob[off: off + l2]).hexdigest()[:40], 'identifier': ident, 'hashType': hash_type})
ref['macho_hello'] = {
    'uuid': str(mb.uuid.uuid if hasattr(mb.uuid, 'uuid') else '').replace(' ', ''), 'cpu': str(mb.header.cpu_type),
    'dylibs': [l.name for l in mb.libraries], 'codeSignature': {'offset': cs.data_offset, 'size': cs.data_size}, 'codeDirectories': cds,
    'buildPlatform': str(mb.build_version.platform) if mb.has_build_version else None,
    'minos': '.'.join(map(str, mb.build_version.minos)) if mb.has_build_version else None,
}
ref['macho_hello']['uuidBytes'] = bytes(mb.uuid.uuid).hex() if hasattr(mb, 'uuid') and mb.has_uuid else None

# ---- Go ----
gofull = '/tmp/go-full'
if os.path.exists(gofull):
    gn = sh('/workspace/work/tools/go/bin/go', 'tool', 'nm', gofull)
    tf = {}
    for l in gn.splitlines():
        parts = l.split()
        if len(parts) >= 3 and parts[1] in ('T', 't'): tf[' '.join(parts[2:])] = parts[0]
    ref['go_hello'] = {'mainMain': '0x' + tf.get('main.main', '0'), 'textSymbols': len(tf), 'sample': {k: '0x' + v for k, v in sorted(tf.items())[:: max(1, len(tf) // 40)]}, 'goVersion': 'go1.23.4'}

# ---- Rust ----
cm = sh('readelf', '-p', '.comment', p('jiter-0.5.0.so'))
ref['rust_jiter'] = {'rustc': re.search(r'rustc version ([^\n]+?)\s*$', cm, re.M).group(1).strip(),
    'crates': sorted(set(re.findall(r'index\.crates\.io-[0-9a-f]{16}/([A-Za-z0-9_-]+?)-(\d+\.\d+\.\d+)/', open(p('jiter-0.5.0.so'), 'rb').read().decode('latin1'))))}
cm2 = sh('readelf', '-p', '.comment', p('orjson-3.10.7.so'))
ref['rust_orjson'] = {'rustc': re.search(r'rustc version ([^\n]+?)\s*$', cm2, re.M).group(1).strip()}

# ---- data formats ----
from gguf import GGUFReader
gr = GGUFReader(p('tiny.gguf'))
ref['gguf'] = {'tensors': [{'name': t.name, 'shape': [int(x) for x in t.shape], 'type': t.tensor_type.name, 'fileOffset': int(t.data_offset), 'bytes': int(t.n_bytes)} for t in gr.tensors],
    'arch': bytes(gr.fields['general.architecture'].parts[-1]).decode(), 'kvCount': len([k for k in gr.fields if not k.startswith('GGUF.')])}
from safetensors import safe_open
with safe_open(p('tiny.safetensors'), 'np') as f:
    ref['safetensors'] = {'tensors': {k: {'shape': list(f.get_slice(k).get_shape()), 'dtype': f.get_slice(k).get_dtype()} for k in f.keys()}, 'metadata': f.metadata(), 'headerSize': struct.unpack('<Q', open(p('tiny.safetensors'), 'rb').read(8))[0]}
import pylnk3
lk = pylnk3.parse(p('notepad.lnk'))
ref['lnk'] = {'path': lk.path, 'arguments': lk.arguments, 'workDir': lk.work_dir, 'description': lk.description, 'icon': lk.icon}
import fdt
dt = fdt.parse_dtb(open(p('board.dtb'), 'rb').read())
ref['dtb'] = {'model': dt.get_property('model').data[0], 'compatible': list(dt.get_property('compatible').data), 'nodes': sorted(n.path.rstrip('/') + '/' + n.name if n.name != '/' else '/' for n in dt.walk_nodes()) if hasattr(dt, 'walk_nodes') else None,
    'memoryReg': list(dt.get_property('reg', '/memory@80000000').data), 'version': dt.header.version, 'totalSize': len(open(p('board.dtb'), 'rb').read())}
import intelhex
ih = intelhex.IntelHex(p('fw.hex'))
ref['ihex'] = {'min': ih.minaddr(), 'max': ih.maxaddr(), 'segments': [list(x) for x in ih.segments()], 'start': ih.start_addr, 'bytes': len(ih)}
bw = sh('binwalk', p('fw-blob.bin'))
ref['binwalk'] = [{'offset': int(l.split()[0]), 'desc': ' '.join(l.split()[2:])} for l in bw.splitlines() if re.match(r'^\d+\s+0x', l)]
import uboot
ui = uboot.parse_img(open(p('uimage.bin'), 'rb').read())
h = ui.header
ref['uimage'] = {'name': h.name, 'size': h.data_size, 'arch': str(h.arch_type), 'os': str(h.os_type), 'headerCrc': h.header_crc, 'dataCrc': h.data_crc, 'loadAddress': h.load_address}
ref['v8'] = json.load(open(p('add.jsc.json')))
ro = sh('llvm-readobj', '--file-headers', '--symbols', p('kernels-gfx906.o'))
ref['amdgpu'] = {'mach': 'gfx906' if 'GFX906' in ro else None, 'abiVersion': int(re.search(r'ABIVersion: (\d+)', ro).group(1)), 'xnackOff': 'XNACK_OFF' in ro, 'srameccOff': 'SRAMECC_OFF' in ro, 'kernels': sorted(re.findall(r'Name: (\w+)\.kd ', ro))}
ptx = open(p('kernels.ptx')).read()
ref['ptx'] = {'version': re.search(r'\.version ([\d.]+)', ptx).group(1), 'target': re.search(r'\.target (\w+)', ptx).group(1), 'entries': re.findall(r'\.entry (\w+)\(', ptx)}
ref['spirv'] = {}
for n, stage, model in [('triangle.vert', 'vert', 'Vertex'), ('triangle.frag', 'frag', 'Fragment'), ('emboss.comp', 'comp', 'GLCompute')]:
    d = open(p(n + '.spv'), 'rb').read()
    magic, ver, gen, bound = struct.unpack('<IIII', d[:16])
    srcg = open(p('src', n)).read()
    ls = re.search(r'local_size_x\s*=\s*(\d+),\s*local_size_y\s*=\s*(\d+)', srcg)
    ref['spirv'][n] = {'version': '%d.%d' % ((ver >> 16) & 0xff, (ver >> 8) & 0xff), 'generator': gen, 'bound': bound, 'model': model, 'glsl': int(re.search(r'#version (\d+)', srcg).group(1)), 'localSize': [int(ls.group(1)), int(ls.group(2)), 1] if ls else None}
ips = os.path.join(CACHE, 'WindowServer.ips')
if os.path.exists(ips):
    t = open(ips).read(); h, b = t.split('\n', 1); b, end = json.JSONDecoder().raw_decode(b)
    ft = b['threads'][b['faultingThread']]; fr = ft['frames'][0]; im = b['usedImages'][fr['imageIndex']]
    ref['ips'] = {'proc': b['procName'], 'exception': b['exception']['type'], 'signal': b['exception']['signal'], 'threads': len(b['threads']), 'images': len(b['usedImages']), 'frame0': {'symbol': fr['symbol'], 'image': im['name'], 'address': hex(im['base'] + fr['imageOffset'])}}

json.dump(ref, open(p('reference.json'), 'w'), indent=1, sort_keys=True)
print('reference.json written,', len(ref), 'groups')

# ---- eval tasks: answers come from the reference values above ----
E = 'samples/extras/'
T = []
def task(id, q, f, tags, typ, ans, refn, hint):
    T.append({'id': id, 'question': q, 'file': E + f, 'tags': tags, 'answerType': typ, 'answer': ans, 'reference': refn, 'hint': hint})
pe_ = ref['pe_hello']; el = ref['elf_x64']
task('pe-file-version', 'What FileVersion does the VS_FIXEDFILEINFO of this PE declare (dotted, four parts)?', 'hello-res.exe', ['pe'], 'exact', pe_['fileVersion'], 'pefile VS_FIXEDFILEINFO', ['x_pe_resources'])
task('pe-company', 'What CompanyName is in the version resource?', 'hello-res.exe', ['pe'], 'exact', pe_['strings']['CompanyName'], 'pefile StringFileInfo', ['x_pe_resources'])
task('pe-exports', 'Which functions does this PE export by name?', 'hello-res.exe', ['pe'], 'set', pe_['exports'], 'pefile DIRECTORY_ENTRY_EXPORT', ['x_pe_inspect'])
task('pe-imports', 'Which DLLs does this PE import from?', 'hello-res.exe', ['pe'], 'set', pe_['imports'], 'pefile DIRECTORY_ENTRY_IMPORT', ['x_pe_inspect'])
task('pe-authentihash', 'What is the SHA-256 Authenticode digest (authentihash) of this PE, as hex?', 'hello-res.exe', ['pe', 'signature'], 'exact', pe_['authentihashSha256'], 'lief authentihash', ['x_pe_authenticode'])
task('pe-manifest-level', 'Which requestedExecutionLevel does the embedded manifest ask for?', 'hello-res.exe', ['pe'], 'exact', 'asInvoker', 'pefile resource type 24', ['x_pe_resources'])
task('elf-needed', 'Which shared libraries does this ELF list as DT_NEEDED?', 'demo-x64.elf', ['elf'], 'set', el['needed'], 'pyelftools dynamic section', ['x_elf_inspect'])
task('elf-entry', 'What is the ELF entry point address?', 'demo-x64.elf', ['elf'], 'hex', el['entry'], 'pyelftools e_entry', ['x_container'])
task('elf-fde-count', 'How many FDEs (unwind ranges) does .eh_frame describe?', 'demo-x64.elf', ['elf', 'unwind'], 'int', el['fdeCount'], 'pyelftools EH_CFI_entries', ['x_elf_unwind'])
task('elf-relro', 'Is the binary built with RELRO and is the stack non-executable? Answer like "relro=yes nx=yes".', 'demo-x64.elf', ['elf', 'hardening'], 'exact', 'relro=%s nx=%s' % ('yes' if el['relro'] else 'no', 'yes' if el['nx'] else 'no'), 'pyelftools program headers', ['x_checksec'])
it = [x for x in ref['itanium'] if 'revlens::demo::sum' in x['llvm']]
if it: task('cxx-demangle-sum', 'What is the demangled C++ signature of the function in namespace revlens::demo named sum?', 'demo-x64.elf', ['demangle'], 'exact', it[0]['llvm'], 'llvm-cxxfilt', ['x_demangle'])
ms = [x for x in ref['msvc'] if x['mangled'].startswith('?scale@')]
if ms: task('msvc-demangle-scale', 'Demangle the MSVC symbol for revlens::demo::scale found in this object file.', 'demo-msvc.obj', ['demangle'], 'exact', ms[0]['undname'], 'llvm-undname', ['x_demangle'])
if 'go_hello' in ref: task('go-main-addr', 'At what address does main.main start in this stripped Go binary?', 'go-hello-stripped.elf', ['go'], 'hex', ref['go_hello']['mainMain'], 'go tool nm on the unstripped build', ['x_go_symbols'])
task('rust-version', 'Which rustc version built this library?', 'jiter-0.5.0.so', ['rust'], 'contains', [ref['rust_jiter']['rustc'].split(' ')[0]], 'readelf -p .comment', ['x_rust_info'])
task('rust-crates', 'Which crates.io crates (name only) are referenced by registry paths in this library?', 'jiter-0.5.0.so', ['rust'], 'set', sorted({c[0] for c in ref['rust_jiter']['crates']}), 'grep of registry paths', ['x_rust_info'])
task('macho-cdhash', 'What is the cdhash (first 20 bytes, hex) of the code directory in this Mach-O?', 'hello-arm64.macho', ['macho', 'signature'], 'exact', ref['macho_hello']['codeDirectories'][0]['cdhash'], 'lief plus sha256 of the CodeDirectory blob', ['x_macho_inspect'])
task('macho-dylibs', 'Which dylibs does this Mach-O load?', 'hello-arm64.macho', ['macho'], 'set', ref['macho_hello']['dylibs'], 'lief libraries', ['x_macho_inspect'])
task('fw-dtb-offset', 'At what file offset does the flattened device tree start in this blob?', 'fw-blob.bin', ['firmware'], 'int', [x for x in ref['binwalk'] if 'device tree' in x['desc']][0]['offset'], 'binwalk 2.4.3 signature scan', ['x_firmware_scan'])
task('fw-uimage-name', 'What image name does the uImage header carry?', 'fw-blob.bin', ['firmware'], 'exact', ref['uimage']['name'], 'uboot parse_img', ['x_firmware_scan', 'x_firmware_parse'])
task('dtb-model', 'What is the model property of the device tree root node?', 'board.dtb', ['firmware'], 'exact', ref['dtb']['model'], 'fdt parse_dtb', ['x_firmware_parse'])
task('ihex-start', 'What is the lowest address with data in this Intel HEX file?', 'fw.hex', ['firmware'], 'hex', hex(ref['ihex']['min']), 'intelhex minaddr', ['x_firmware_parse'])
task('gguf-arch', 'What architecture does this GGUF model declare?', 'tiny.gguf', ['model'], 'exact', ref['gguf']['arch'], 'gguf-py GGUFReader', ['x_model_inspect'])
task('gguf-tensors', 'List the tensor names in this GGUF file.', 'tiny.gguf', ['model'], 'set', [t['name'] for t in ref['gguf']['tensors']], 'gguf-py GGUFReader', ['x_model_inspect'])
task('lnk-target', 'Which program does this shortcut launch (full path)?', 'notepad.lnk', ['windows'], 'exact', ref['lnk']['path'], 'pylnk3 parse', ['x_lnk_inspect'])
task('lnk-args', 'What command line arguments does this shortcut pass?', 'notepad.lnk', ['windows'], 'exact', ref['lnk']['arguments'], 'pylnk3 parse', ['x_lnk_inspect'])
task('v8-source-length', 'How long (in characters) was the JavaScript source this V8 code cache was made from?', 'add.jsc', ['javascript'], 'int', ref['v8']['sourceLength'], 'node vm.Script source length', ['x_v8_inspect'])
task('ptx-kernels', 'Which kernels (.entry) does this PTX module define?', 'kernels.ptx', ['gpu'], 'set', ref['ptx']['entries'], 'PTX text', ['x_gpu_inspect'])
task('amdgpu-target', 'Which AMD GPU target (gfx name) is this code object built for?', 'kernels-gfx906.o', ['gpu'], 'exact', ref['amdgpu']['mach'], 'llvm-readobj e_flags', ['x_gpu_inspect'])
task('spirv-stage', 'What execution model does the entry point of this SPIR-V module use?', 'emboss.comp.spv', ['gpu'], 'exact', 'GLCompute', 'GLSL source stage', ['x_gpu_inspect'])
task('spirv-localsize', 'What workgroup local size does this compute shader declare? Answer like 8,8,1.', 'emboss.comp.spv', ['gpu'], 'exact', ','.join(map(str, ref['spirv']['emboss.comp']['localSize'])), 'GLSL source layout', ['x_gpu_inspect'])

ts = '// Generated by packages/extras/scripts/gen_reference.py from reference tool output. Do not edit by hand.\n'
ts += "import type { EvalTask } from './harness.js';\n"
ts += 'export const TASKS: EvalTask[] = ' + json.dumps(T, indent=1) + ';\n'
open(os.path.join(ROOT, 'packages', 'extras', 'src', 'eval', 'tasks.ts'), 'w').write(ts)
print(len(T), 'eval tasks written')
