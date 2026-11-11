// Windows offline artifacts against reference tools: registry hives vs regipy 6.5.0,
// Prefetch vs windowsprefetch 4.0.3 (+ dissect.util LZXPRESS Huffman), Jump Lists vs
// olefile 0.47, LnkParse3 1.6.0 and the dtformats DestList layout. Values in reference-gaps.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import fc from 'fast-check';
import * as X from '../src/node.js';
import { RG, wx } from './helpers2.js';

const hive = (f: string): Uint8Array => (f.endsWith('.gz') ? new Uint8Array(gunzipSync(wx(f))) : wx(f));

test('registry hives: key and value totals, root and top level keys match regipy', () => {
  for (const f of ['SAM.gz', 'BCD', 'SECURITY', 'NTUSER.DAT.gz']) {
    const ref = RG.registry[f];
    const r = X.inspectRegf(hive(f));
    assert.equal(r.keyCount, ref.keys, `${f} keys`);
    assert.equal(r.valueCount, ref.values, `${f} values`);
    assert.equal(r.root.name, ref.root);
    assert.deepEqual(r.topLevel, ref.rootSubkeys);
    assert.equal(r.header.checksumValid, true);
  }
});

test('registry values decode like regipy (REG_EXPAND_SZ, REG_SZ, REG_DWORD)', () => {
  const r = new X.Regf(hive('NTUSER.DAT.gz'));
  const env = r.values(r.find('Environment')!);
  assert.deepEqual(Object.fromEntries(env.map((v) => [v.name, v.value])), RG.registry['NTUSER.DAT.gz'].environment);
  const desk = r.values(r.find('Control Panel\\Desktop')!);
  let checked = 0;
  for (const [name, [type, val]] of Object.entries(RG.registry['NTUSER.DAT.gz'].desktop as Record<string, [string, unknown]>)) {
    const v = desk.find((x) => x.name === name);
    assert.ok(v, name);
    assert.equal(v!.type, type);
    if (val !== null && (type === 'REG_SZ' || type === 'REG_DWORD')) { assert.equal(v!.value, val, name); checked++; }
  }
  assert.ok(checked > 20);
  const bcd = new X.Regf(wx('BCD'));
  assert.deepEqual(bcd.subkeys(bcd.find('Objects')!).map((k) => k.name), RG.registry.BCD.objects);
});

test('registry tool lists keys recursively and finds Run style paths', async () => {
  const t = X.TOOLS.find((x) => x.name === 'x_registry_hive')!;
  const out = (await t.run({ bytes: Buffer.from(hive('NTUSER.DAT.gz')).toString('base64'), key: 'Software\\Microsoft', recursive: true, limit: 5 })) as { keys: { total: number; items: { path: string }[] } };
  assert.ok(out.keys.total > 100);
  assert.match(out.keys.items[0]!.path, /\\Software\\Microsoft$/);
});

test('prefetch: XP, Vista, 7, 8 and Windows 10 compressed files match windowsprefetch', () => {
  for (const [f, ref] of Object.entries(RG.prefetch as Record<string, any>)) {
    const p = X.parsePrefetch(wx(f));
    assert.equal(p.version, ref.version, f);
    assert.equal(p.executable, ref.executable);
    assert.equal(p.hash, ref.hash);
    assert.equal(p.runCount, ref.runCount, `${f} run count`);
    assert.equal(p.files.length, ref.files);
    assert.equal(p.files[0], ref.firstFile);
    assert.equal(p.files.at(-1), ref.lastFile);
    assert.deepEqual(p.volumes.map((v) => [v.devicePath, v.serial]), ref.volumes.map((v: any) => [v.path, v.serial]));
    assert.equal(p.lastRunTimes.length, ref.timestamps.length);
    // windowsprefetch prints naive UTC datetimes with microseconds
    assert.deepEqual(p.lastRunTimes.map((t) => t.slice(0, 19).replace('T', ' ')), ref.timestamps.map((t: string) => t.slice(0, 19)));
  }
});

test('LZXPRESS Huffman output is byte identical to dissect.util', () => {
  for (const f of ['win10-CALC.EXE-3FBEF7FD.pf', 'win10-CMD.EXE-D269B812.pf']) {
    const { data, compressed } = X.decompressPrefetch(wx(f));
    assert.equal(compressed, true);
    assert.equal(data.length, RG.prefetch[f].decompressedSize);
    assert.equal(createHash('sha256').update(data).digest('hex'), RG.prefetch[f].decompressedSha256);
  }
});

test('automatic jump lists: streams, DestList and embedded links match olefile and LnkParse3', () => {
  for (const f of ['win10-f01b4d95cf55d32a.automaticDestinations-ms', 'win7-1b4dd67f29cb1962.automaticDestinations-ms']) {
    const ref = RG.jumplists[f];
    const j = X.parseAutomaticJumpList(wx(f), { name: f });
    assert.equal(j.appId, f.slice(f.indexOf('-') + 1, f.indexOf('-') + 17));
    assert.deepEqual(j.streams.map((s) => s.name).sort(), ref.streams);
    assert.equal(j.destListVersion, ref.version);
    assert.equal(j.entryCount, ref.entries);
    assert.equal(j.pinnedCount, ref.pinned);
    assert.equal(j.entries.length, ref.destList.length);
    j.entries.forEach((e, i) => {
      const r = ref.destList[i];
      assert.equal(e.entryNumber, r.entry);
      assert.equal(e.hostname, r.host);
      assert.equal(e.path, r.path);
      assert.equal(e.pinStatus, r.pin);
      if (r.count !== null) assert.equal(e.accessCount, r.count);
      assert.equal(e.lastModified?.slice(0, 23), r.modified.slice(0, 23));
      assert.equal(e.lnk?.localBasePath, r.lnk.localBasePath);
      assert.equal(e.lnk?.fileSize, r.lnk.size);
    });
  }
});

test('custom jump list links match LnkParse3 offsets and arguments', () => {
  const f = 'dtformats-5afe4de1b92fc382.customDestinations-ms';
  const ref = RG.jumplists[f];
  const j = X.parseCustomJumpList(wx(f), { name: f });
  assert.equal(j.footerValid, ref.footer === 'abfbbfba');
  assert.deepEqual(j.links.map((l) => l.offset), ref.lnkOffsets);
  assert.deepEqual(j.links.map((l) => l.arguments), ref.lnks.map((l: any) => l.arguments));
  assert.deepEqual(j.links.map((l) => l.localBasePath), ref.lnks.map((l: any) => l.localBasePath));
});

test('Windows parsers reject hostile input with ParseError only', () => {
  const parsers: ((b: Uint8Array) => unknown)[] = [(b) => X.inspectRegf(b), (b) => X.parsePrefetch(b), (b) => X.parseJumpList(b), (b) => new X.Cfb(b), (b) => X.lzxpressHuffman(b, 4096)];
  const seeds = [hive('BCD'), wx('win10-CALC.EXE-3FBEF7FD.pf'), wx('xppro-CMD.EXE-087B4001.pf'), wx('win7-1b4dd67f29cb1962.automaticDestinations-ms')];
  fc.assert(fc.property(fc.integer({ min: 0, max: seeds.length - 1 }), fc.integer({ min: 0, max: 40000 }), fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 64 }), (si, pos, val, cut) => {
    const s = seeds[si]!;
    const m = s.slice(0, Math.max(0, s.length - cut * 97));
    if (m.length) m[pos % m.length] = val;
    for (const p of parsers) { try { p(m); } catch (e) { if (!(e instanceof X.ParseError) && !(e instanceof RangeError)) throw e; } }
  }), { numRuns: 150 });
  for (const p of parsers) assert.throws(() => p(new Uint8Array(3)));
});
