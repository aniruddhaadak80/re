// Game packages and ROMs: Godot .pck exported by the real Godot 3.6, 4.3, 4.4.1 and 4.5.1 editors
// and read back by the real engines (scripts/gen-godot-fixtures.py), iNES / NES 2.0 ROMs built
// with ca65/ld65 (samples/extras/src/nes/build.sh, CRCs from Python zlib), and a UnityFS bundle
// with LZMA blocks written and read back by UnityPy 1.10.18 (scripts/gen-unity-lzma.py).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import fc from 'fast-check';
import { inspectGodotPck, godotPckFile, findGodotPck, parseInes, parseUnityFs, unityNodeBytes, parseSerializedFile, TOOLS, ParseError } from '../src/index.js';
import { S } from './helpers.js';

const G = join(S, 'containers', 'godot');
const N = join(S, 'containers', 'nes');
const gref = JSON.parse(readFileSync(join(G, 'reference.json'), 'utf8')) as { encryptionKey: string; sourceMd5: Record<string, string>; packs: Record<string, { engine: string; formatVersion: number; files: string[]; mainPackRun?: string; embeddedRun?: string; embeddedStart?: number }> };
const nref = JSON.parse(readFileSync(join(N, 'reference.json'), 'utf8'));
const load = (d: string, f: string) => new Uint8Array(readFileSync(join(d, f)));
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const FIRST_LINE = 'RevLens Godot pack fixture line one';

for (const [name, ref] of Object.entries(gref.packs)) {
  test(`godot: ${name} (Godot ${ref.engine}) lists the files the exporter stored`, () => {
    const b = load(G, name);
    const p = inspectGodotPck(b);
    assert.equal(p.formatVersion, ref.formatVersion);
    assert.equal(p.engineVersion.split('.').slice(0, ref.engine.split('.').length).join('.'), ref.engine);
    assert.equal(p.fileCount, ref.files.length);
    if (name.includes('encdir')) {
      assert.equal(p.flags.encryptedDirectory, true);
      assert.equal(p.files.length, 0);
      return;
    }
    assert.deepEqual(p.files.map((f) => f.path).sort(), ref.files);
    for (const [path, md5] of Object.entries(gref.sourceMd5)) {
      const e = p.files.find((f) => f.path === path)!;
      if (name.includes('-enc')) { assert.equal(e.encrypted, path.endsWith('.txt'), path); if (e.encrypted) { assert.equal(e.encryption!.plainMd5, md5, 'FileAccessEncrypted header holds the MD5 of the plain file'); continue; } }
      assert.equal(e.md5, md5, `${path} MD5 in the directory equals the source file`);
      const r = godotPckFile(b, p, path);
      assert.equal(r.md5Matches, true);
    }
    if (!name.includes('-enc')) {
      const d = godotPckFile(b, p, 'data.txt');
      assert.equal(new TextDecoder().decode(d.data).split('\n')[0], FIRST_LINE);
      assert.equal(ref.mainPackRun, FIRST_LINE, 'the real engine read the same line with --main-pack');
    }
  });
}

for (const [name, ref] of Object.entries(gref.packs).filter(([, r]) => r.embeddedStart)) {
  const exe = name.replace('.pck', '-embedded.elf');
  test(`godot: ${exe} finds the pack after an ELF, laid out as the engine accepted it`, () => {
    const b = load(G, exe);
    assert.equal(ref.embeddedRun, FIRST_LINE, 'the real engine with this pack appended read res://data.txt');
    const loc = findGodotPck(b)!;
    assert.deepEqual(loc, { start: ref.embeddedStart, embedded: 'trailer' });
    const p = inspectGodotPck(b);
    assert.equal(p.packStart, ref.embeddedStart);
    assert.deepEqual(p.files.map((f) => f.path).sort(), ref.files);
    for (const f of p.files) assert.equal(godotPckFile(b, p, f.path).md5Matches, true, f.path);
    assert.equal(new TextDecoder().decode(godotPckFile(b, p, 'res://data.txt').data).split('\n')[0], FIRST_LINE);
    // the ELF header is still at the start: the pack is an addition, not a replacement
    assert.deepEqual([...b.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46]);
  });
}

test('godot: x_godot_pck tool and a pack found by scanning when the trailer is gone', async () => {
  const r = (await tool('x_godot_pck').run({ path: join(G, 'godot451-embedded.elf') })) as { formatVersion: number; files: { total: number } };
  assert.equal(r.formatVersion, 3);
  assert.equal(r.files.total, 8);
  const one = (await tool('x_godot_pck').run({ path: join(G, 'godot43.pck'), file: 'res://config.json', preview: 8 })) as { md5Matches: boolean; previewHex: string };
  assert.equal(one.md5Matches, true);
  assert.equal(one.previewHex, Buffer.from('{"name":').toString('hex'));
  const b = load(G, 'godot43-embedded.elf');
  const cut = b.subarray(0, b.length - 12);
  assert.equal(findGodotPck(cut)!.embedded, 'scan');
  assert.equal(inspectGodotPck(cut).files.length, 7);
});

test('nes: iNES 1.0 and NES 2.0 headers and data hashes', async () => {
  for (const f of ['ines-mmc1.nes', 'nes2-268.nes']) {
    const r = parseInes(load(N, f));
    const w = nref[f];
    for (const k of Object.keys(w)) if (k !== 'size') assert.deepEqual((r as unknown as Record<string, unknown>)[k], w[k], `${f} ${k}`);
    assert.equal(r.trailingBytes, 0);
    assert.deepEqual(r.warnings, []);
  }
  const t = (await tool('x_nes_rom').run({ path: join(N, 'nes2-268.nes') })) as { mapper: number; prgOffset: number };
  assert.equal(t.mapper, 268);
  assert.equal(t.prgOffset, 16 + 512);
  assert.throws(() => parseInes(new Uint8Array(32)), ParseError);
});

test('unity: LZMA UnityFS bundle decodes to the node bytes UnityPy reads', () => {
  const ref = JSON.parse(readFileSync(join(S, 'containers', 'ExternalAssets-lzma.reference.json'), 'utf8'));
  const b = load(join(S, 'containers'), 'ExternalAssets-lzma.unity3d');
  const u = parseUnityFs(b);
  assert.ok(u.blocks.every((x) => x.compression === 'lzma'), JSON.stringify(u.blocks));
  assert.equal(u.nodes.length, ref.nodes.length);
  for (const n of ref.nodes) {
    const node = u.nodes.find((x) => x.path === n.path)!;
    const data = unityNodeBytes(b, u, node);
    assert.equal(data.length, n.size);
    assert.equal(sha(data), n.sha256);
    const sf = parseSerializedFile(data);
    assert.deepEqual(sf.objects.map((o) => ({ pathId: o.pathId, class: o.class })).sort((x, y) => Number(x.pathId) - Number(y.pathId)), ref.objects);
  }
  // the same objects as the uncompressed original (UnityPy re-serializes, so bytes may differ)
  const orig = load(join(S, 'containers'), 'ExternalAssets.unity3d');
  const uo = parseUnityFs(orig);
  assert.deepEqual(parseSerializedFile(unityNodeBytes(orig, uo, uo.nodes[0]!)).objects.map((o) => o.pathId).sort(), ref.objects.map((o: { pathId: string }) => o.pathId).sort());
});

test('hostile: Godot, NES and Unity parsers end in a result or a ParseError', () => {
  const seeds = [load(G, 'godot43.pck'), load(G, 'godot451.pck'), load(G, 'godot36.pck'), load(N, 'ines-mmc1.nes').subarray(0, 64), load(join(S, 'containers'), 'ExternalAssets-lzma.unity3d')];
  const run = (b: Uint8Array) => {
    const t = Date.now();
    for (const fn of [() => inspectGodotPck(b), () => parseInes(b), () => { const u = parseUnityFs(b); for (const n of u.nodes) unityNodeBytes(b, u, n, 1 << 20); }]) {
      try { fn(); } catch (e) { assert.ok(e instanceof ParseError || /limit|range|truncat|bad|invalid|past|exceed/i.test((e as Error).message), String(e)); }
    }
    assert.ok(Date.now() - t < 2000);
  };
  fc.assert(fc.property(fc.uint8Array({ maxLength: 2048 }), (b) => run(b)), { numRuns: 200 });
  for (const s of seeds) {
    fc.assert(fc.property(fc.nat(s.length), fc.array(fc.tuple(fc.nat(s.length - 1), fc.integer({ min: 1, max: 255 })), { maxLength: 6 }), (n, flips) => {
      const x = s.slice(0, n);
      for (const [o, v] of flips) if (o < x.length) x[o] = (x[o] as number) ^ v;
      run(x);
    }), { numRuns: 60 });
  }
  // huge counts: a pack header claiming 2^32-1 files
  const big = load(G, 'godot43.pck').slice();
  new DataView(big.buffer).setUint32(20 + 12 + 64, 0xffffffff, true);
  assert.throws(() => inspectGodotPck(big), ParseError);
});
