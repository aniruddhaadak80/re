// .NET metadata and CIL checked against dnfile (metadata) and dncil (IL) reference dumps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { sample, cached, bytes, json, has } from './helpers.js';
import { loadAssembly, dotnetInfo, listTypes, methodIl, findMethods, xrefs, getUserString, singleFileBundle } from '../src/index.js';

const BROTLI = sample('dotnet', 'System.IO.Compression.Brotli.dll');
const NJ = cached('Newtonsoft.Json.dll');

// dnfile spells FieldRVA as FieldRva.
const rowCount = (rc: Record<string, number>, name: string) => Object.entries(rc).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

function ilSha(asm: ReturnType<typeof loadAssembly>, tok: string) {
  const m = methodIl(asm, parseInt(tok, 16) & 0xffffff);
  return { m, sha1: createHash('sha1').update(m.instructions.map((i) => `${i.offset}:${i.opcode}`).join(';')).digest('hex') };
}

test('dotnet: Brotli identity, references, P/Invoke and resources match dnfile', () => {
  const ref = json(sample('dotnet', 'brotli.ref.json'));
  const asm = loadAssembly(bytes(BROTLI));
  const info = dotnetInfo(asm);
  assert.equal(info.assembly?.name, ref.assembly.name);
  assert.equal(info.assembly?.version, ref.assembly.version);
  assert.deepEqual(info.assemblyRefs.map((r) => r.name), ref.assemblyRefs);
  assert.equal(info.assemblyRefs[0]?.publicKeyToken, 'b03f5f7f11d50a3a');
  assert.deepEqual(info.moduleRefs, ref.moduleRefs);
  assert.deepEqual(info.pinvoke.map((p) => p.entry), ref.implMap);
  assert.ok(info.pinvoke.every((p) => p.library === 'libSystem.IO.Compression.Native'));
  assert.deepEqual(info.resources.map((r) => r.name), ref.resources);
  assert.equal(info.resources[0]?.kind, 'resources');
  for (const [name, n] of Object.entries<number>(ref.rowCounts)) if (n > 0) assert.equal(rowCount(info.metadata.rowCounts, name), n, name);
  assert.deepEqual(listTypes(asm).map((t) => (t.namespace ? `${t.namespace}.${t.name}` : t.name)), ref.typeNames);
  assert.equal(info.targetFramework, '.NETCoreApp,Version=v8.0');
  assert.equal(info.runtimeVersion, 'v4.0.30319');
  assert.equal(info.machine, 'amd64 (linux r2r)');
  assert.ok(info.readyToRun, 'runtime pack assemblies are ReadyToRun');
  assert.match(info.readyToRun!.compositeOrComponent ?? '', /^Crossgen2 8\./);
  assert.deepEqual(info.obfuscators, []);
});

test('dotnet: every Brotli method body decodes to the same CIL as dncil', () => {
  const ref = json(sample('dotnet', 'brotli.ref.json'));
  const asm = loadAssembly(bytes(BROTLI));
  let n = 0;
  for (const [tok, r] of Object.entries<any>(ref.methods)) {
    const { m, sha1 } = ilSha(asm, tok);
    assert.equal(sha1, r.sha1, `${tok} ${m.name}`);
    assert.equal(m.body?.codeSize, r.codeSize);
    assert.equal(m.body?.maxStack, r.maxStack);
    assert.deepEqual(m.instructions.slice(0, 6).map((i) => i.opcode), r.first);
    n++;
  }
  assert.equal(n, 112);
});

test('dotnet: tokens resolve and xrefs find P/Invoke callers', () => {
  const asm = loadAssembly(bytes(BROTLI));
  const pinv = methodIl(asm, findMethods(asm, 'Interop/Brotli::BrotliDecoderDecompress')[0]!);
  assert.match(pinv.error ?? '', /P\/Invoke/);
  const res = xrefs(asm, (_t, text) => text.includes('::BrotliDecoderDecompress('));
  assert.ok(res.xrefs.length >= 1);
  assert.ok(res.xrefs.every((x) => x.opcode === 'call'));
  const ldstr = xrefs(asm, (tok) => tok >>> 24 === 0x70);
  assert.ok(ldstr.xrefs.length > 0);
  assert.equal(JSON.stringify(getUserString(asm.md, parseInt(ldstr.xrefs[0]!.toToken, 16) & 0xffffff)), ldstr.xrefs[0]!.to);
});

test('dotnet: Newtonsoft.Json netstandard2.0 matches dnfile and dncil (needs fetch-fixtures)', { skip: !has(NJ) }, () => {
  const ref = json(sample('dotnet', 'newtonsoft.ref.json'));
  const asm = loadAssembly(bytes(NJ));
  const info = dotnetInfo(asm);
  assert.equal(info.assembly?.name, 'Newtonsoft.Json');
  assert.equal(info.assembly?.version, '13.0.0.0');
  assert.equal(info.targetFramework, '.NETStandard,Version=v2.0');
  assert.deepEqual(info.assemblyRefs.map((r) => r.name), ['netstandard']);
  for (const [name, n] of Object.entries<number>(ref.rowCounts)) if (n > 0) assert.equal(rowCount(info.metadata.rowCounts, name), n, name);
  assert.equal(info.counts.types, 496);
  assert.equal(info.counts.methods, 4185);
  assert.equal(info.readyToRun, undefined);
  assert.deepEqual(info.obfuscators, []);
  const lines: string[] = [];
  let instructions = 0;
  for (const tok of Object.keys(ref.methods.sample)) assert.equal(ilSha(asm, tok).sha1, ref.methods.sample[tok].sha1);
  // Aggregate over all 4064 bodies, computed the same way as the dncil reference.
  const toks: string[] = [];
  for (let rid = 1; rid <= info.counts.methods; rid++) {
    const m = methodIl(asm, rid);
    if (!m.body) continue;
    toks.push((0x06000000 | rid).toString(16).padStart(8, '0'));
  }
  for (const tok of toks.sort()) { const { m, sha1 } = ilSha(asm, tok); lines.push(`${tok}:${sha1}`); instructions += m.instructions.length; }
  assert.equal(toks.length, ref.methods.count);
  assert.equal(instructions, ref.methods.instructions);
  assert.equal(createHash('sha1').update(lines.join('\n')).digest('hex'), ref.methods.aggregateSha1);
  const ser = methodIl(asm, findMethods(asm, 'Newtonsoft.Json.JsonConvert::SerializeObject')[0]!);
  assert.deepEqual(ser.instructions.map((i) => i.opcode), ['ldarg.0', 'ldnull', 'ldnull', 'call', 'ret']);
  assert.equal(ser.instructions[3]!.text, 'Newtonsoft.Json.JsonConvert::SerializeObject(object, System.Type, Newtonsoft.Json.JsonSerializerSettings)');
});

test('dotnet: obfuscator markers are found (real assembly with a patched attribute name)', () => {
  // Rename the CompilerGeneratedAttribute TypeRef in place, the way ConfuserEx and Dotfuscator add their marker types.
  for (const [marker, expect] of [['ConfusedByAttribute', 'ConfuserEx'], ['DotfuscatorAttribute', 'Dotfuscator']] as const) {
    const b = bytes(BROTLI).slice();
    const asm0 = loadAssembly(b);
    const needle = new TextEncoder().encode('CompilerGeneratedAttribute\0');
    const s = asm0.md.strings;
    let at = -1;
    for (let i = 0; i + needle.length <= s.length && at < 0; i++) if (needle.every((x, k) => s[i + k] === x)) at = i;
    assert.ok(at > 0);
    b.set(new TextEncoder().encode(marker + '\0'), asm0.md.stringsOffset + at);
    const hits = dotnetInfo(loadAssembly(b)).obfuscators;
    assert.deepEqual(hits.map((h) => h.name), [expect]);
    assert.match(hits[0]!.evidence, new RegExp(`TypeRef .*${marker}`));
  }
});

test('dotnet: single-file bundle manifest (synthetic, built from the documented v6 layout)', () => {
  const enc = new TextEncoder();
  const str = (s: string) => { const b = enc.encode(s); return [b.length, ...b]; };
  const i64 = (n: number) => { const a = new Uint8Array(8); new DataView(a.buffer).setBigInt64(0, BigInt(n), true); return [...a]; };
  const u32 = (n: number) => { const a = new Uint8Array(4); new DataView(a.buffer).setUint32(0, n, true); return [...a]; };
  const sig = [0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, 0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae];
  const headerOffset = 200;
  const header = [...u32(6), ...u32(0), ...u32(2), ...str('abc123'), ...i64(100), ...i64(10), ...i64(110), ...i64(5), ...i64(0),
    ...i64(64), ...i64(30), ...i64(0), 1, ...str('App.dll'), ...i64(100), ...i64(10), ...i64(0), 3, ...str('App.deps.json')];
  const file = new Uint8Array(headerOffset + header.length);
  file.set([...i64(headerOffset), ...sig], 16);
  file.set(header, headerOffset);
  const info = singleFileBundle(file)!;
  assert.equal(info.version, '6.0');
  assert.equal(info.bundleId, 'abc123');
  assert.deepEqual(info.files.map((f) => [f.path, f.type, f.offset, f.size]), [['App.dll', 'assembly', 64, 30], ['App.deps.json', 'depsjson', 100, 10]]);
});
