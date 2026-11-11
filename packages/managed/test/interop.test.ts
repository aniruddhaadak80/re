// P/Invoke to native export matching and .NET member diff on real files.
// References: dnfile 0.18.0 (ImplMap rows, TypeDef/MethodDef/Field lists), llvm-nm, llvm-readobj and
// llvm-objdump 19 (exports of the .NET 8.0.11 System.IO.Compression.Native builds).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { gunzipSync } from 'node:zlib';
import fc from 'fast-check';
import { sample, cached, bytes, json, has } from './helpers.js';
import { loadAssembly, nativeExports, mapPInvokes, compareAssemblies, snapshotAssembly, pinvokeMapTool, compareMembersTool, TOOLS, CLI_COMMANDS, ParseError } from '../src/index.js';

const NATIVE = ['linux-x64/libSystem.IO.Compression.Native.so', 'win-x64/System.IO.Compression.Native.dll', 'osx-arm64/libSystem.IO.Compression.Native.dylib'];
const dir = mkdtempSync(join(tmpdir(), 'rl-native-'));
// the runtime probes by file name, so keep the real names in a per-rid folder
const libPaths = NATIVE.map((n) => { mkdirSync(join(dir, n.split('/')[0]!), { recursive: true }); const p = join(dir, n); writeFileSync(p, gunzipSync(readFileSync(sample('native', n + '.gz')))); return p; });
const libs = NATIVE.map((n, i) => ({ name: n, bytes: new Uint8Array(readFileSync(libPaths[i]!)) }));
const EXPORTS = json(sample('native', 'exports.ref.json'));

test('native exports of ELF, PE and Mach-O builds match llvm-nm, llvm-readobj and llvm-objdump', () => {
  for (const l of libs) {
    const r = nativeExports(l.bytes);
    const ref = EXPORTS[l.name];
    const ours: Record<string, unknown> = {};
    for (const e of r.exports) ours[e.name] = r.format === 'pe' ? { ordinal: e.ordinal, address: e.address } : e.address;
    assert.deepEqual(ours, ref, l.name);
  }
  assert.equal(nativeExports(libs[0]!.bytes).arch, 'x86_64');
  assert.equal(nativeExports(libs[2]!.bytes).arch, 'arm64');
});

test('managed_pinvoke_map: every Brotli DllImport (dnfile ImplMap) resolves on linux, windows and macOS', async () => {
  const ref = json(sample('dotnet', 'brotli.ref.json'));
  const r = mapPInvokes(loadAssembly(bytes(sample('dotnet', 'System.IO.Compression.Brotli.dll'))), libs);
  assert.deepEqual(r.bindings.map((b) => b.entry).sort(), [...ref.implMap].sort());
  assert.deepEqual(r.summary, { total: 11, resolved: 11, 'missing-export': 0, 'library-not-shipped': 0 });
  for (const b of r.bindings) {
    assert.equal(b.library, 'libSystem.IO.Compression.Native');
    assert.deepEqual(b.matches.map((m) => m.platform), ['linux-x86_64', 'windows-x86_64', 'macos-arm64']);
    assert.equal(b.matches[0]!.address, EXPORTS[NATIVE[0]!][b.entry]);
    assert.equal(b.matches[1]!.ordinal, EXPORTS[NATIVE[1]!][b.entry].ordinal);
    assert.equal(b.matches[2]!.address, EXPORTS[NATIVE[2]!][b.entry]);
  }
  assert.deepEqual(r.libraries.map((l) => [l.exports, l.referenced]), [[18, 11], [18, 11], [18, 11]]);
});

test('managed_pinvoke_map: resolved, missing export and library not shipped in RevDemoLib, flags as dnfile reads them', async () => {
  const ref = json(sample('dotnet', 'revdemolib.members.ref.json'))['RevDemoLib-1.0.0.dll'];
  const r = await pinvokeMapTool({ path: sample('dotnet', 'RevDemoLib-1.0.0.dll'), librariesBase64: libs.map((l) => ({ name: l.name, base64: Buffer.from(l.bytes).toString('base64') })) }) as any;
  const by = (m: string) => r.bindings.items.find((b: any) => b.member.endsWith('::' + m) || b.member.includes('::' + m + '('));
  for (const im of ref.implMap) {
    const b = by(im.member);
    assert.ok(b, im.member);
    assert.equal(b.library, im.module); assert.equal(b.entry, im.entry); assert.equal(b.charset, im.charset);
    assert.equal(b.exactSpelling, im.exactSpelling); assert.equal(b.setLastError, im.setLastError); assert.equal(b.callConv, im.callConv);
  }
  assert.equal(by('BrotliEncoderCreateInstance').status, 'resolved');
  assert.equal(by('DecoderVersion').status, 'missing-export', 'BrotliDecoderVersion is not exported by the .NET shim');
  assert.equal(by('Missing').status, 'missing-export');
  assert.equal(by('MessageBox').status, 'library-not-shipped');
  assert.equal(by('getpid').status, 'library-not-shipped');
  assert.deepEqual(r.summary, { total: 5, resolved: 1, 'missing-export': 2, 'library-not-shipped': 2 });
  const only = await pinvokeMapTool({ path: sample('dotnet', 'RevDemoLib-1.0.0.dll'), libraries: [], status: 'library-not-shipped' }) as any;
  assert.equal(only.bindings.total, 5);
});

function projected(s: ReturnType<typeof snapshotAssembly>): Record<string, { methods: string[]; fields: string[] }> {
  const out: Record<string, { methods: string[]; fields: string[] }> = {};
  for (const [n, t] of s.types) out[n] = {
    methods: [...t.methods.values()].map((m) => `${m.name}/${m.paramCount}`).sort(),
    fields: [...t.fields.keys()].sort(),
  };
  return out;
}

test('managed_compare_members: RevDemoLib 1.0.0 vs 2.0.0 member lists match dnfile and the diff is exact', async () => {
  const ref = json(sample('dotnet', 'revdemolib.members.ref.json'));
  const a = loadAssembly(bytes(sample('dotnet', 'RevDemoLib-1.0.0.dll'))), b = loadAssembly(bytes(sample('dotnet', 'RevDemoLib-2.0.0.dll')));
  assert.deepEqual(projected(snapshotAssembly(a)), ref['RevDemoLib-1.0.0.dll'].types);
  assert.deepEqual(projected(snapshotAssembly(b)), ref['RevDemoLib-2.0.0.dll'].types);
  const d = compareAssemblies(a, b, { bodies: true });
  assert.deepEqual(d.types.added, ['RevDemo.Index']);
  assert.deepEqual(d.types.removed, ['RevDemo.Legacy']);
  const store = d.changes.find((c) => c.type === 'RevDemo.Store')!;
  assert.deepEqual(store.interfaces, { added: ['System.IDisposable'], removed: [] });
  assert.deepEqual(store.methods.removed, ['public void Clear()']);
  assert.deepEqual(store.methods.added.sort(), [
    'public !!0 Find``1(System.Func<string, !!0>)', 'public bool Remove(string)', 'public void Add(string, int)', 'public void Dispose()',
    'public void add_Changed(System.EventHandler)', 'public void remove_Changed(System.EventHandler)',
  ].sort());
  assert.deepEqual(store.methods.bodyChanged, ['Describe()']);
  assert.deepEqual(store.fields.added.sort(), ['private System.EventHandler Changed', 'public static int Capacity']);
  const same = compareAssemblies(a, a, { bodies: true });
  assert.equal(same.types.changed + same.types.added.length + same.types.removed.length, 0);
});

const NJ = [cached('Newtonsoft.Json-12.0.3.dll'), cached('Newtonsoft.Json.dll')];
test('managed_compare_members: Newtonsoft.Json 12.0.3 vs 13.0.3 member lists match dnfile', { skip: !NJ.every(has) && 'run packages/managed/scripts/fetch-fixtures.mjs' }, async () => {
  const ref = JSON.parse(gunzipSync(readFileSync(sample('dotnet', 'newtonsoft-12.0.3-13.0.3.members.ref.json.gz'))).toString('utf8'));
  const a = loadAssembly(bytes(NJ[0]!)), b = loadAssembly(bytes(NJ[1]!));
  assert.deepEqual(projected(snapshotAssembly(a)), ref['Newtonsoft.Json-12.0.3.dll'].types);
  assert.deepEqual(projected(snapshotAssembly(b)), ref['Newtonsoft.Json.dll'].types);
  const d = await compareMembersTool({ path: NJ[0]!, otherPath: NJ[1]!, publicOnly: true, limit: 2000 }) as any;
  const refAdded = Object.keys(ref['Newtonsoft.Json.dll'].types).filter((t) => !(t in ref['Newtonsoft.Json-12.0.3.dll'].types));
  for (const t of d.types.added) assert.ok(refAdded.includes(t), t);
  assert.ok(d.types.added.includes('Newtonsoft.Json.Linq.JsonCloneSettings'));
  assert.ok(d.types.added.includes('Newtonsoft.Json.Linq.JsonSelectSettings'));
});

test('tools and CLI commands', async () => {
  for (const n of ['managed_pinvoke_map', 'managed_compare_members']) assert.ok(TOOLS.some((t) => t.name === n));
  const logs: string[] = [];
  const orig = console.log;
  console.log = (s: string) => { logs.push(s); };
  try {
    assert.equal(await CLI_COMMANDS.find((c) => c.name === 'compare-members')!.run([sample('dotnet', 'RevDemoLib-1.0.0.dll'), sample('dotnet', 'RevDemoLib-2.0.0.dll')]), 0);
    assert.match(logs.join('\n'), /\+ type RevDemo\.Index/);
    logs.length = 0;
    assert.equal(await CLI_COMMANDS.find((c) => c.name === 'pinvoke-map')!.run([sample('dotnet', 'System.IO.Compression.Brotli.dll'), ...libPaths, '--json']), 0);
    assert.equal(JSON.parse(logs.join('\n')).summary.total, 11);
  } finally { console.log = orig; }
  await assert.rejects(() => compareMembersTool({ path: sample('dotnet', 'RevDemoLib-1.0.0.dll') }), ParseError);
});

test('hostile: mutated native libraries and assemblies end in a result or ParseError', () => {
  const asm = bytes(sample('dotnet', 'RevDemoLib-2.0.0.dll'));
  const ok = (e: unknown) => { if (!(e instanceof ParseError) && !(e instanceof RangeError)) throw e; };
  fc.assert(fc.property(fc.integer({ min: 0, max: 3 }), fc.nat(), fc.integer({ min: 0, max: 255 }), fc.nat({ max: 50 }), (w, pos, val, cut) => {
    const src = w < 3 ? libs[w]!.bytes.subarray(0, 65536) : asm;
    const m = src.slice(0, Math.max(1, src.length - cut * 13));
    m[pos % m.length] = val;
    const t0 = Date.now();
    try { if (w < 3) nativeExports(m); else compareAssemblies(loadAssembly(asm), loadAssembly(m), { bodies: true }); } catch (e) { ok(e); }
    assert.ok(Date.now() - t0 < 3000);
  }), { numRuns: 300 });
  fc.assert(fc.property(fc.uint8Array({ minLength: 64, maxLength: 4096 }), fc.integer({ min: 0, max: 2 }), (b, k) => {
    b.set([[0x7f, 0x45, 0x4c, 0x46, 2, 1], [0x4d, 0x5a], [0xcf, 0xfa, 0xed, 0xfe]][k]!, 0);
    try { nativeExports(b); } catch (e) { ok(e); }
  }), { numRuns: 300 });
});
