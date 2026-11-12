// Compression decoders and squashfs against independent reference decoders. The SHA-256 values in
// samples/extras/compress/reference.json and samples/extras/firmware/squashfs.reference.json come
// from scripts/gen-compress-reference.py: Python's lzma (liblzma) for .xz/.lzma, lzop 1.04 -d,
// zstd -d, gzip -d, bzip2 1.0.8 -d, and unsquashfs 4.6.1 for every file in the squashfs images.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import fc from 'fast-check';
import { decompressAuto, detectCompression, bzip2Decode, extractSquashfs, lzmaAloneDecode, xzDecode, lzopDecode, lzo1xDecompress, zstdDecodeFrame, TOOLS, CLI_COMMANDS, ParseError } from '../src/index.js';
import { gunzipMember, inflateRaw } from '../src/compress/inflate.js';
import { lz4Block } from '../src/containers/lz4.js';
import { S } from './helpers.js';

const C = join(S, 'compress');
const F = join(S, 'firmware');
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const ref = JSON.parse(readFileSync(join(C, 'reference.json'), 'utf8')) as Record<string, { size: number; sha256: string; tool: string }>;
const sqRef = JSON.parse(readFileSync(join(F, 'squashfs.reference.json'), 'utf8')) as Record<string, { files: Record<string, { type: string; size?: number; sha256?: string; target?: string }> }>;
const load = (d: string, f: string) => new Uint8Array(readFileSync(join(d, f)));
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;

for (const [file, want] of Object.entries(ref)) {
  test(`compress: ${file} decodes to the same bytes as ${want.tool}`, () => {
    const b = load(C, file);
    const r = decompressAuto(b);
    assert.equal(r.data.length, want.size);
    assert.equal(sha(r.data), want.sha256);
    // multi stream bzip2 and single streams: the decoder reports the end of the input it used
    assert.equal(r.inputEnd, b.length, 'the whole file is one stream (or concatenated streams)');
    if (r.format === 'xz') assert.ok((r.details.blocks as { checkValid: boolean | null }[]).every((x) => x.checkValid !== false));
    if (r.format === 'bzip2') assert.equal(r.details.crcValid, true);
    if (r.format === 'lzop') assert.notEqual(r.details.checksumsValid, false);
  });
}

test('compress: format detection by magic bytes', () => {
  const want: Record<string, string> = { 'plain.gz': 'gzip', 'plain-crc64.xz': 'xz', 'plain.lzma': 'lzma', 'plain-9.lzo': 'lzop', 'plain.zst': 'zstd', 'plain.bz2': 'bzip2' };
  for (const [f, fmt] of Object.entries(want)) assert.equal(detectCompression(load(C, f)), fmt, f);
  assert.equal(detectCompression(load(C, 'plain.bin')), undefined);
});

test('compress: bzip2 reports blocks, streams and a bad CRC', () => {
  const b = load(C, 'plain-multi.bz2');
  const r = bzip2Decode(b);
  assert.equal(r.streams, 2);
  assert.equal(r.blockSize, 100000);
  assert.equal(r.crcValid, true);
  assert.ok(new TextDecoder().decode(r.data.subarray(r.data.length - 14)) === 'second stream\n');
  // flip one bit of the stored block CRC (bytes 10..13 follow the 6 byte block magic)
  const bad = load(C, 'plain.bz2');
  bad[12] = (bad[12] as number) ^ 1;
  assert.equal(bzip2Decode(bad).crcValid, false);
});

test('compress: output caps stop decoders early', () => {
  for (const f of ['plain.gz', 'plain-crc64.xz', 'plain.lzma', 'plain-9.lzo', 'plain.bz2', 'plain.zst']) {
    assert.throws(() => decompressAuto(load(C, f), { maxOut: 1000 }), /limit|exceeds|larger|too/i, f);
  }
});

for (const [img, want] of Object.entries(sqRef)) {
  test(`squashfs: ${img} matches unsquashfs 4.6.1 file by file (SHA-256)`, () => {
    const r = extractSquashfs(load(F, img), 0, { withData: true });
    assert.deepEqual(r.errors, []);
    const got = new Map(r.entries.map((e) => [e.path.replace(/^\/+/, ''), e]));
    for (const [path, w] of Object.entries(want.files)) {
      const e = got.get(path);
      assert.ok(e, `${path} present`);
      assert.equal(e.type, w.type, path);
      if (w.type === 'file') { assert.equal(e.data!.length, w.size, path); assert.equal(sha(e.data!), w.sha256, path); }
      if (w.type === 'symlink') assert.equal(e.target, w.target, path);
    }
    assert.equal([...got.keys()].filter((k) => k !== '').length, Object.keys(want.files).length, 'same entry count');
  });
}

test('tools: x_decompress, x_squashfs and the signal tools run on fixtures', async () => {
  const d = (await tool('x_decompress').run({ path: join(C, 'plain-x86.xz'), preview: 8 })) as { format: string; sha256: string; previewHex: string; inputEnd: number };
  assert.equal(d.format, 'xz');
  assert.equal(d.sha256, ref['plain-x86.xz']!.sha256);
  assert.equal(d.previewHex.length, 16);
  const s = (await tool('x_squashfs').run({ path: join(F, 'rootfs-zstd.squashfs') })) as { super: { compression: string }; entries: { items: { path: string; sha256?: string }[] } };
  assert.equal(s.super.compression, 'zstd');
  const hello = s.entries.items.find((e) => e.path.endsWith('bin/hello'))!;
  assert.equal(hello.sha256, sqRef['rootfs-zstd.squashfs']!.files['bin/hello']!.sha256);
  const one = (await tool('x_squashfs').run({ path: join(F, 'rootfs-lzo.squashfs'), file: '/lib/libdata.so', preview: 4 })) as { sha256: string; previewHex: string };
  assert.equal(one.sha256, sqRef['rootfs-lzo.squashfs']!.files['lib/libdata.so']!.sha256);
  const cat = (await tool('x_signal_decoders').run({})) as { modulations: unknown[]; logicDecoders: unknown[] };
  assert.ok(cat.modulations.length >= 8 && cat.logicDecoders.length === 3);
  const sig = (await tool('x_signal_decode').run({ path: join(S, 'signals', 'pwm_433.92M_250k.cu8'), spectrum: false })) as { kind: string; recording: { sampleRate: number; centerFreq: number }; pulses: { packageCount: number } };
  assert.equal(sig.kind, 'rf');
  assert.equal(sig.recording.sampleRate, 250000);
  assert.equal(sig.recording.centerFreq, 433.92e6);
  assert.ok(sig.pulses.packageCount > 0);
  const lg = (await tool('x_signal_decode').run({ path: join(S, 'logic', 'mixed_1MHz.sr'), decoder: 'uart', options: { rx: '0', baudrate: 115200 } })) as { kind: string; annotations: { total: number } };
  assert.equal(lg.kind, 'logic');
  assert.ok(lg.annotations.total > 0);
  for (const c of ['x-signal-decoders', 'x-signal', 'x-decompress', 'x-squashfs', 'x-firmware-extract', 'x-godot', 'x-nes']) assert.ok(CLI_COMMANDS.some((x) => x.name === c), c);
});

// Hostile input: every decoder must end in a result or a ParseError (including OutputLimitError),
// never hang, crash with a RangeError from a typed array, or allocate without bound.
const decoders: [string, (b: Uint8Array) => unknown][] = [
  ['gzip', (b) => gunzipMember(b, { maxOut: 1 << 20 })],
  ['deflate', (b) => inflateRaw(b, { maxOut: 1 << 20 })],
  ['lzma', (b) => lzmaAloneDecode(b, { maxOut: 1 << 20 })],
  ['xz', (b) => xzDecode(b, { maxOut: 1 << 20 })],
  ['lzop', (b) => lzopDecode(b, { maxOut: 1 << 20 })],
  ['lzo1x', (b) => lzo1xDecompress(b, { maxOut: 1 << 20 })],
  ['zstd', (b) => zstdDecodeFrame(b, { maxOut: 1 << 20 })],
  ['bzip2', (b) => bzip2Decode(b, { maxOut: 1 << 20 })],
  ['lz4', (b) => lz4Block(b, 4096, 1 << 20)],
  ['squashfs', (b) => extractSquashfs(b, 0, { withData: true, maxTotal: 1 << 20, deadline: Date.now() + 2000 })],
];
const seeds: Record<string, string> = { gzip: 'plain.gz', deflate: 'plain.gz', lzma: 'plain.lzma', xz: 'plain-arm.xz', lzop: 'plain-1.lzo', lzo1x: 'plain-1.lzo', zstd: 'plain.zst', bzip2: 'plain.bz2', lz4: 'plain.bin', squashfs: '' };
const okError = (e: unknown) => e instanceof ParseError || (e instanceof Error && /limit|truncat|corrupt|invalid|bad|unexpected|out of range|past the end|exceed/i.test(e.message));

for (const [name, fn] of decoders) {
  test(`hostile: ${name} decoder on random bytes, truncation and bit flips`, () => {
    const seed = name === 'squashfs' ? load(F, 'rootfs-gzip.squashfs').subarray(0, 8192) : load(C, seeds[name]!).subarray(0, 6000);
    const check = (b: Uint8Array) => {
      const t = Date.now();
      try { fn(b); } catch (e) { assert.ok(okError(e), `${name}: unexpected ${(e as Error).name}: ${(e as Error).message}`); }
      assert.ok(Date.now() - t < 3000, `${name} took ${Date.now() - t} ms`);
    };
    fc.assert(fc.property(fc.uint8Array({ maxLength: 4096 }), (b) => check(b)), { numRuns: 150 });
    fc.assert(fc.property(fc.nat(seed.length), (n) => check(seed.slice(0, n))), { numRuns: 60 });
    fc.assert(fc.property(fc.array(fc.tuple(fc.nat(seed.length - 1), fc.integer({ min: 0, max: 7 })), { minLength: 1, maxLength: 8 }), (flips) => {
      const b = seed.slice();
      for (const [o, bit] of flips) b[o] = (b[o] as number) ^ (1 << bit);
      check(b);
    }), { numRuns: 100 });
  });
}
