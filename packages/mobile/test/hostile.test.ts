// Hostile input: random bytes, truncation, bit flips of real files, and absurd counts.
// Every parser must either return or throw an Error quickly; never hang or crash the process.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import {
  openZip, readEntry, parseAxml, parseResourceTable, DexFile, openDex, renderClass, parseClass, javap, parseElfDynamic,
  parsePlist, parseMachoSlices, parseIl2cppMetadata, apkSigning, analyzeApk, analyzeIpa, ParseError, mobileDexClasses,
} from '../src/node.js';
import { APKS, bytes } from './helpers.js';

async function safe(fn: () => unknown | Promise<unknown>, ms = 5000): Promise<void> {
  const t0 = Date.now();
  try { await fn(); } catch (err) { assert.ok(err instanceof Error, `threw a non-Error: ${String(err)}`); }
  assert.ok(Date.now() - t0 < ms, `took ${Date.now() - t0} ms`);
}

function dexAll(b: Uint8Array): void {
  for (const d of openDex(b)) for (const c of d.classes.slice(0, 200)) renderClass(d, c);
}

const PARSERS: [string, (b: Uint8Array) => unknown | Promise<unknown>][] = [
  ['zip', (b) => openZip(b)],
  ['axml', (b) => parseAxml(b)],
  ['arsc', (b) => parseResourceTable(b)],
  ['dex', (b) => dexAll(b)],
  ['class', (b) => javap(parseClass(b))],
  ['elf', (b) => parseElfDynamic(b)],
  ['plist', (b) => parsePlist(b)],
  ['macho', (b) => parseMachoSlices(b)],
  ['il2cpp', (b) => { const m = parseIl2cppMetadata(b); m.types(0, 50); m.methods(0, 50); m.literals(0, 50); }],
  ['apk', (b) => analyzeApk(b)],
  ['ipa', (b) => analyzeIpa(b)],
];

const MAGIC: Record<string, number[]> = {
  axml: [0x03, 0x00, 0x08, 0x00], arsc: [0x02, 0x00, 0x0c, 0x00], dex: [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00],
  class: [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52], elf: [0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], plist: [...new TextEncoder().encode('bplist00')],
  macho: [0xcf, 0xfa, 0xed, 0xfe], il2cpp: [0xaf, 0x1b, 0xb1, 0xfa, 29, 0, 0, 0], zip: [0x50, 0x4b, 0x03, 0x04], apk: [0x50, 0x4b, 0x03, 0x04], ipa: [0x50, 0x4b, 0x03, 0x04],
};

test('random bytes with valid magic never crash any parser', async () => {
  for (const [name, fn] of PARSERS) {
    await fc.assert(fc.asyncProperty(fc.uint8Array({ minLength: 0, maxLength: 4096 }), async (rand) => {
      const m = MAGIC[name] ?? [];
      const b = new Uint8Array(Math.max(rand.length, m.length));
      b.set(rand);
      b.set(m);
      await safe(() => fn(b));
    }), { numRuns: 150 });
  }
});

async function realSamples(): Promise<Record<string, Uint8Array>> {
  const apk = bytes('apk', APKS.alarm);
  const zip = openZip(apk);
  return {
    axml: await readEntry(zip, 'AndroidManifest.xml'),
    arsc: await readEntry(zip, 'resources.arsc'),
    dex: bytes('java', 'hello-035.dex'),
    class: bytes('java', 'Hello.class'),
    elf: await readEntry(openZip(bytes('apk', APKS.streak)), 'lib/arm64-v8a/libStreak.so'),
    plist: await readEntry(openZip(bytes('ipa', 'Wikipedia-fixture.ipa')), 'Payload/Wikipedia.app/Info.plist'),
    macho: await readEntry(openZip(bytes('ipa', 'Wikipedia-fixture.ipa')), 'Payload/Wikipedia.app/Wikipedia'),
    apk: bytes('apk', APKS.stopwatch),
    ipa: bytes('ipa', 'Wikipedia-fixture.ipa'),
  };
}

test('bit flips and truncation of real files never crash', async () => {
  const s = await realSamples();
  for (const [name, fn] of PARSERS) {
    const orig = s[name];
    if (!orig) continue;
    await fc.assert(fc.asyncProperty(
      fc.array(fc.tuple(fc.nat(orig.length - 1), fc.integer({ min: 0, max: 255 })), { minLength: 1, maxLength: 24 }),
      fc.nat(orig.length),
      async (flips, cut) => {
        const b = orig.slice(0, Math.max(8, cut));
        for (const [i, v] of flips) if (i < b.length) b[i] = v;
        await safe(() => fn(b), 15_000);
      },
    ), { numRuns: name === 'apk' || name === 'ipa' ? 25 : 120 });
  }
});

test('absurd counts are rejected with ParseError', async () => {
  const dex = bytes('java', 'hello-035.dex').slice();
  new DataView(dex.buffer).setUint32(56, 0xffffffff, true); // string_ids_size
  assert.throws(() => new DexFile(dex), ParseError);

  const dex2 = bytes('java', 'hello-035.dex').slice();
  new DataView(dex2.buffer).setUint32(96, 50_000, true); // class_defs_size far beyond the file
  assert.throws(() => new DexFile(dex2), ParseError);

  const plist = (await realSamples()).plist.slice();
  const t = plist.length - 32;
  new DataView(plist.buffer).setBigUint64(t + 8, 0xffffffffffn); // numObjects
  assert.throws(() => parsePlist(plist), ParseError);

  // a binary plist whose array contains itself
  const cyc = new Uint8Array([...new TextEncoder().encode('bplist00'), 0xa1, 0x00, 0x08, ...new Array(6).fill(0), 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
  assert.throws(() => parsePlist(cyc), /cycle/);

  const zip = bytes('apk', APKS.stopwatch).slice();
  const z = openZip(zip);
  new DataView(zip.buffer).setUint16(z.eocdOffset + 10, 0xffff, true);
  const big = openZip(zip); // count is clamped by the central directory itself
  assert.ok(big.entries.length <= z.entries.length);

  const axml = (await realSamples()).axml.slice();
  new DataView(axml.buffer).setUint32(8 + 8, 0x7fffffff, true); // string pool count
  assert.throws(() => parseAxml(axml), ParseError);
});

test('deflate bombs are capped by the declared size', async () => {
  const apk = bytes('apk', APKS.stopwatch).slice();
  const zip = openZip(apk);
  const e = zip.byName.get('classes.dex');
  assert.ok(e);
  e.size = 1000; // lie about the size: inflating must stop near 2x the claim
  await assert.rejects(() => readEntry(zip, e), /limit/);
});

test('signing block with lying lengths reports warnings, not crashes', async () => {
  const apk = bytes('apk', APKS.alarm).slice();
  const z = openZip(apk);
  const view = new DataView(apk.buffer);
  const blockStart = z.centralDirOffset - Number(view.getBigUint64(z.centralDirOffset - 24, true)) - 8;
  view.setBigUint64(blockStart + 8, 0xffffffn, true); // first pair length
  const s = await apkSigning(apk);
  assert.ok(s.warnings.length > 0);
  assert.equal(s.v1.present, true);
});

test('tools reject non-mobile input cleanly', async () => {
  await assert.rejects(() => mobileDexClasses({ base64: Buffer.from('hello world').toString('base64') }), ParseError);
});
