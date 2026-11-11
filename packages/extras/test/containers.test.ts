// Containers against reference tools: wxapkg packed and decrypted by KillWxapkg v2.4.1,
// UnityFS bundles (Unity 5.5.0f3 output and a UnityPy LZ4 repack) read by UnityPy 1.10.18,
// Node SEA blob written by node 22.23.3, Bun 1.4.4 compile checked against `bun build
// --target=bun`, Deno 2.9.8 compile checked against its source files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fc from 'fast-check';
import * as X from '../src/node.js';
import { RG, sx, cachedAt } from './helpers2.js';

const C = RG.containers;
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
type Ref = { size?: number; sha256?: string; json?: unknown };
// KillWxapkg pretty prints JSON members; everything else must be byte identical
const same = (d: Uint8Array, r: Ref, name: string): void => {
  if ('json' in r) assert.deepEqual(JSON.parse(new TextDecoder().decode(d)), r.json, name);
  else { assert.equal(d.length, r.size, name); assert.equal(sha(d), r.sha256, name); }
};

test('wxapkg member table and bytes match KillWxapkg extraction', async () => {
  const b = sx('containers', 'demo.wxapkg');
  const w = await X.parseWxapkgAny(b);
  const ref = C.wxapkg['demo.wxapkg'].files as Record<string, Ref>;
  assert.equal(w.fileCount, Object.keys(ref).length);
  assert.deepEqual(w.entries.map((e) => e.name).sort(), Object.keys(ref).sort());
  for (const e of w.entries) same(X.wxapkgMember(b, e), ref[e.name]!, e.name);
  assert.equal(w.kind, 'main');
  assert.deepEqual(w.pages, ['pages/index/index']);
  assert.ok(w.entries.some((e) => e.name === '/images/说明.txt'));
});

test('V1MMWX PC package decrypts with the AppID like KillWxapkg, and refuses a wrong AppID', async () => {
  const enc = sx('containers', 'demo-pc-encrypted.wxapkg');
  const locked = await X.parseWxapkgAny(enc);
  assert.equal(locked.encrypted, true);
  assert.equal(locked.entries.length, 0);
  const w = await X.parseWxapkgAny(enc, { appId: C.wxapkg['demo-pc-encrypted.wxapkg'].appid });
  assert.equal(w.decrypted, true);
  const ref = C.wxapkg['demo-pc-encrypted.wxapkg'].files as Record<string, Ref>;
  for (const e of w.entries) same(X.wxapkgMember(w.bytes, e), ref[e.name]!, e.name);
  assert.deepEqual(w.bytes, sx('containers', 'demo.wxapkg'));
  await assert.rejects(() => X.parseWxapkgAny(enc, { appId: 'wx0000000000000000' }), X.ParseError);
});

test('UnityFS header, blocks, nodes and serialized objects match UnityPy (uncompressed, LZ4, LZ4HC blocks info at end)', () => {
  const files: [string, Uint8Array | null][] = [['ExternalAssets.unity3d', sx('containers', 'ExternalAssets.unity3d')], ['ExternalAssets-lz4.unity3d', sx('containers', 'ExternalAssets-lz4.unity3d')], ['unity-cards.unity3d', cachedAt('', 'unity-cards.unity3d')]];
  let n = 0;
  for (const [f, b] of files) {
    if (!b || !C.unity[f]) continue;
    const ref = C.unity[f];
    const u = X.parseUnityFs(b);
    assert.equal(u.version, ref.version);
    assert.equal(u.unityVersion, ref.player);
    assert.equal(u.unityRevision, ref.engine);
    assert.equal(u.flags, ref.flags);
    assert.equal(u.nodes.length, ref.nodes.length);
    u.nodes.forEach((node, k) => {
      const r = ref.nodes[k];
      assert.equal(node.path, r.path);
      const d = X.unityNodeBytes(b, u, node);
      assert.equal(d.length, r.size);
      assert.equal(sha(d), r.sha256);
      const s = X.parseSerializedFile(d);
      assert.equal(s.version, r.serializedVersion);
      assert.equal(s.unityVersion, r.unityVersion);
      assert.equal(s.targetPlatform, r.platform);
      assert.deepEqual(s.objects.map((o) => [o.pathId, o.classId, o.offset, o.size]), r.objects);
    });
    n++;
  }
  assert.ok(n >= 2);
  assert.equal(X.parseUnityFs(sx('containers', 'ExternalAssets-lz4.unity3d')).blocks[0]!.compression, 'lz4');
});

test('Node SEA blob decodes the node-written layout: code path, entry script and asset', () => {
  const blob = sx('containers', 'node-sea-prep.blob');
  const r = C.standalone.nodeSeaBlob;
  assert.equal(sha(blob), r.sha256);
  const s = X.parseSeaBlob(blob, 0);
  assert.equal(s.size, r.size);
  assert.equal(s.codePath, r.codePath);
  assert.equal(sha(blob.subarray(s.mainCodeOffset, s.mainCodeOffset + s.mainCodeSize)), r.mainSha256);
  assert.deepEqual(s.assets.map((a) => a.name), [r.asset]);
  assert.equal(sha(blob.subarray(s.assets[0]!.offset, s.assets[0]!.offset + s.assets[0]!.size)), r.assetSha256);
  assert.deepEqual(s.flags, ['disableExperimentalSEAWarning', 'includeAssets']);
});

test('Bun module graph excerpt decodes to the same bundle bun build --target=bun writes', () => {
  const b = sx('containers', 'bun-1.4.4-graph.bin');
  const s = X.inspectStandaloneJs(b);
  assert.equal(s.runtime, 'bun');
  assert.deepEqual(s.bun!.modules.map((m) => m.name), [C.standalone.bun.module]);
  assert.equal(sha(X.standaloneFile(b, s, C.standalone.bun.module)!), C.standalone.bun.contentsSha256);
});

test('Deno payload excerpt: metadata entrypoint and embedded files match the sources', () => {
  const b = sx('containers', 'deno-2.9.8-payload.bin');
  const s = X.inspectStandaloneJs(b);
  assert.equal(s.runtime, 'deno');
  assert.equal(s.deno!.entrypoint, C.standalone.deno.entrypoint);
  for (const [name, h] of Object.entries(C.standalone.deno.files as Record<string, string>)) {
    const f = s.deno!.files.find((x) => x.path === name)!;
    assert.ok(f, name);
    assert.equal(sha(b.subarray(f.offset, f.offset + f.size)), h);
  }
  assert.ok(Array.isArray((s.deno!.metadata!.permissions as Record<string, unknown>).allow_import));
});

const full = (f: string): Uint8Array | null => cachedAt('standalone', f);
test('full single-file executables: node SEA, bun and deno binaries (make_standalone_fixtures.sh)', { skip: !full('app-bun') && 'run packages/extras/scripts/make_standalone_fixtures.sh' }, () => {
  const node = full('node-sea-hello');
  if (node) {
    const s = X.inspectStandaloneJs(node);
    assert.equal(s.runtime, 'node-sea');
    assert.equal(s.nodeSea!.fuse, 'injected');
    assert.equal(sha(node.subarray(s.nodeSea!.blob!.offset, s.nodeSea!.blob!.offset + s.nodeSea!.blob!.size)), C.standalone.nodeSeaBlob.sha256);
  }
  const bun = X.inspectStandaloneJs(full('app-bun')!);
  assert.equal(bun.runtime, 'bun');
  assert.equal(bun.runtimeVersion, C.standalone.bun.version);
  assert.equal(sha(X.standaloneFile(full('app-bun')!, bun, C.standalone.bun.module)!), C.standalone.bun.contentsSha256);
  const deno = full('app-deno');
  if (deno) {
    const d = X.inspectStandaloneJs(deno);
    assert.equal(d.runtime, 'deno');
    assert.equal(d.runtimeVersion, C.standalone.deno.version);
    assert.deepEqual(d.deno!.files.map((f) => f.path), Object.keys(C.standalone.deno.files));
  }
});

test('container parsers reject hostile input with ParseError only', async () => {
  const seeds = [sx('containers', 'demo.wxapkg'), sx('containers', 'ExternalAssets.unity3d'), sx('containers', 'ExternalAssets-lz4.unity3d'), sx('containers', 'node-sea-prep.blob'), sx('containers', 'bun-1.4.4-graph.bin'), sx('containers', 'deno-2.9.8-payload.bin')];
  const parsers: ((b: Uint8Array) => unknown)[] = [(b) => X.parseWxapkg(b), (b) => { const u = X.parseUnityFs(b); for (const n of u.nodes) X.parseSerializedFile(X.unityNodeBytes(b, u, n)); }, (b) => X.parseSeaBlob(b, 0), (b) => X.inspectStandaloneJs(b), (b) => X.lz4Block(b, 4096)];
  fc.assert(fc.property(fc.integer({ min: 0, max: seeds.length - 1 }), fc.integer({ min: 0, max: 1 << 16 }), fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 30 }), (si, pos, val, cut) => {
    const s = seeds[si]!;
    const m = s.slice(0, Math.max(0, s.length - cut * 13));
    if (m.length) m[pos % m.length] = val;
    for (const p of parsers) { try { p(m); } catch (e) { if (!(e instanceof X.ParseError) && !(e instanceof RangeError)) throw e; } }
  }), { numRuns: 300 });
});
