// Firmware extraction checked against independent tools: unsquashfs 4.6.1 file hashes
// (squashfs.reference.json), binwalk 2.4.3 offsets and EDK2 compressors plus the uefi_firmware 1.16
// parser (uefi-trx.reference.json, scripts/gen-uefi-trx-fixtures.py), and the mkimage, mkbootimg
// and cpio fixtures from scripts/gen-firmware-fixtures.sh. The Node writer is tested against path
// traversal, absolute names, symlink escapes and planted symlinks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, readdirSync, lstatSync, existsSync, symlinkSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import fc from 'fast-check';
import { extractFirmware, sanitizeMemberPath, TOOLS, ParseError, writeExtraction } from '../src/node.js';
import { efiDecompress } from '../src/compress/efi.js';
import { S } from './helpers.js';
import { cachedAt } from './helpers2.js';

const F = join(S, 'firmware');
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const load = (f: string) => new Uint8Array(readFileSync(join(F, f)));
const sq = JSON.parse(readFileSync(join(F, 'squashfs.reference.json'), 'utf8')) as Record<string, { files: Record<string, { type: string; sha256?: string; target?: string }> }>;
const UR = JSON.parse(readFileSync(join(F, 'uefi-trx.reference.json'), 'utf8'));
const rootRef = sq['rootfs-xz.squashfs']!.files;
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const tmp = () => mkdtempSync(join(tmpdir(), 'revlens-fw-'));

/** Every regular file of the reference root must appear under `prefix` with the same hash. */
function sameTree(files: { path: string; sha256?: string; kind: string; target?: string }[], prefix: string) {
  for (const [p, w] of Object.entries(rootRef)) {
    const f = files.find((x) => x.path === `${prefix}/${p}`);
    assert.ok(f, `${prefix}/${p} extracted`);
    if (w.type === 'file') assert.equal(f.sha256, w.sha256, p);
    if (w.type === 'symlink') { assert.equal(f.kind, 'symlink'); assert.equal(f.target, w.target); }
  }
}

test('firmware: initramfs.cpio.gz unpacks to the same files unsquashfs gives for the same tree', () => {
  const r = extractFirmware(load('initramfs.cpio.gz'));
  assert.deepEqual(r.chunks.map((c) => c.type), ['gzip', 'cpio']);
  sameTree(r.files, '00000000-gzip/gzip.uncompressed.extract/00000000-cpio');
  assert.ok(!r.files.some((f) => f.path.endsWith('/unnamed')), 'the archive root entry is not emitted');
});

test('firmware: FIT image, uImage and Android boot images v0 to v4', () => {
  const fit = extractFirmware(load('fit.itb'));
  assert.equal(fit.chunks[0]!.type, 'fdt');
  assert.match(fit.chunks[0]!.description, /FIT image "RevLens FIT", 2 images/);
  sameTree(fit.files, '00000000-fdt/ramdisk-1.extract/00000000-gzip/gzip.uncompressed.extract/00000000-cpio');
  const kernel = fit.files.find((f) => f.path === '00000000-fdt/kernel-1')!;
  assert.equal(kernel.size, 50000, 'gzip kernel decompressed per the FIT compression property');
  const lib = rootRef['lib/libdata.so']!;
  void lib;
  const u = extractFirmware(load('uImage-gzip.bin'));
  assert.equal(u.files[0]!.path, '00000000-uimage/RevLens kernel');
  assert.equal(u.files[0]!.sha256, kernel.sha256, 'same kernel bytes as the FIT kernel');
  for (const v of [0, 1, 2, 3, 4]) {
    const r = extractFirmware(load(`boot-v${v}.img`));
    assert.equal(r.chunks[0]!.type, 'android-boot');
    assert.match(r.chunks[0]!.description, new RegExp(`v${v}`));
    assert.match(r.chunks[0]!.description, /kernel 50028 bytes, ramdisk 72104 bytes/);
    sameTree(r.files, '00000000-android-boot/ramdisk.extract/00000000-gzip/gzip.uncompressed.extract/00000000-cpio');
    assert.equal(r.files.find((f) => f.path === '00000000-android-boot/kernel.extract/00000000-gzip/gzip.uncompressed')!.sha256, kernel.sha256);
  }
});

test('firmware: TRX offsets match binwalk, kernel matches the source, rootfs matches unsquashfs', () => {
  const r = extractFirmware(load('revlens.trx'));
  const t = UR.trx;
  assert.equal(r.chunks[0]!.type, 'trx');
  assert.match(r.chunks[0]!.description, /TRX v1, 77824 bytes, CRC ok/);
  const flat = [0, ...r.chunks.slice(1).map((c) => (c.path.includes('partition0') ? t.kernelOffset : t.rootfsOffset) + c.offset)];
  assert.deepEqual(flat, t.binwalk.map((x: { offset: number }) => x.offset), 'TRX header, LZMA and squashfs where binwalk sees them');
  assert.equal(r.files.find((f) => f.path.endsWith('lzma.uncompressed'))!.sha256, t.kernelSha256);
  sameTree(r.files, '00000000-trx/partition1.extract/00000000-squashfs');
  // a flipped byte in the body makes the TRX CRC fail, and it is reported
  const bad = load('revlens.trx'); bad[5000] = (bad[5000] as number) ^ 0xff;
  assert.match(extractFirmware(bad).chunks[0]!.description, /CRC bad/);
});

test('firmware: router image (vendor header, uImage LZMA kernel, squashfs) matches binwalk offsets', () => {
  const r = extractFirmware(load('router.bin'));
  const ref = UR.router;
  assert.deepEqual(r.chunks.map((c) => c.offset), [ref.uimageOffset, ref.squashfsOffset]);
  assert.ok(ref.binwalk.some((x: { offset: number; description: string }) => x.offset === ref.uimageOffset && /uImage/.test(x.description)));
  assert.ok(ref.binwalk.some((x: { offset: number; description: string }) => x.offset === ref.squashfsOffset && /Squashfs/.test(x.description)));
  assert.equal(r.files.find((f) => f.path === '00000040-uimage/RevLens router kernel')!.sha256, ref.kernelSha256);
  sameTree(r.files, '00010000-squashfs');
  assert.deepEqual(r.unknown.map((u) => [u.offset, u.end]), [[0, 64]], 'the vendor header is the only unknown gap');
});

test('firmware: EFI and Tiano decompression match the EDK2 decompressors', () => {
  const want = UR['plain.bin'].sha256;
  const e = efiDecompress(load('uefi/plain.efi'), { variant: 'efi' });
  const t = efiDecompress(load('uefi/plain.tiano'), { variant: 'tiano' });
  assert.equal(sha(e.data), want); assert.equal(UR.efi.sha256, want);
  assert.equal(sha(t.data), want); assert.equal(UR.tiano.sha256, want);
  assert.equal(efiDecompress(load('uefi/plain.tiano')).variant, 'tiano', 'auto falls back to Tiano');
});

test('firmware: UEFI volume sections match the uefi_firmware parser (EFI, LZMA and Tiano sections, nested FV)', () => {
  const r = extractFirmware(load('uefi/revlens-fv.bin'));
  assert.equal(r.chunks[0]!.offset, UR.fv.offset);
  assert.equal(r.chunks[0]!.end - r.chunks[0]!.offset, UR.fv.length);
  assert.match(r.chunks[0]!.description, /4 files, 16384 bytes, header checksum ok/);
  const hashes = new Map(r.files.map((f) => [f.sha256, f.path]));
  for (const leaf of UR.fv.leafSections as { file: string; type: number | string; sha256: string; size: number }[]) {
    if (leaf.type === 21) continue; // UI sections are written as UTF-8 text and used in the folder name
    const p = hashes.get(leaf.sha256);
    assert.ok(p, `section type ${leaf.type} of ${leaf.file} (${leaf.size} bytes) found`);
    assert.ok(p.toUpperCase().includes(leaf.file), `${p} sits under file ${leaf.file}`);
  }
  for (const n of ['RevLensDxe', 'RevLensConfig', 'RevLensApp']) assert.ok(r.files.some((f) => f.path.includes(`-${n}/`)), n);
  for (const k of ['pe1', 'pe2', 'raw1', 'nestedRaw']) assert.ok(hashes.has(UR.fv.expect[k]), k);
});

// ---------------- writer ----------------
function newc(entries: { name: string; mode: number; data?: string; target?: string }[]): Uint8Array {
  const parts: number[] = [];
  const hex = (n: number) => n.toString(16).padStart(8, '0');
  const add = (name: string, mode: number, body: Uint8Array) => {
    const nb = new TextEncoder().encode(name + '\0');
    const h = '070701' + [1, mode, 0, 0, 1, 0, body.length, 0, 0, 0, 0, nb.length, 0].map(hex).join('');
    for (const c of new TextEncoder().encode(h)) parts.push(c);
    for (const c of nb) parts.push(c);
    while (parts.length % 4) parts.push(0);
    for (const c of body) parts.push(c);
    while (parts.length % 4) parts.push(0);
  };
  for (const e of entries) add(e.name, e.mode, new TextEncoder().encode(e.target ?? e.data ?? ''));
  add('TRAILER!!!', 0, new Uint8Array(0));
  return new Uint8Array(parts);
}

test('writer: traversal, absolute names and symlink escapes stay inside outDir', async () => {
  const evil = newc([
    { name: '../../escape.txt', mode: 0o100644, data: 'x' },
    { name: '/etc/abs.txt', mode: 0o100644, data: 'abs' },
    { name: 'link', mode: 0o120777, target: '/tmp' },
    { name: 'rel', mode: 0o120777, target: '../../..' },
    { name: 'inner', mode: 0o120777, target: 'sub' },
    { name: 'sub', mode: 0o040755 },
    { name: 'link/pwned.txt', mode: 0o100644, data: 'through a symlink' },
    { name: 'ok.txt', mode: 0o100644, data: 'fine' },
  ]);
  const base = tmp();
  const out = join(base, 'out');
  const r = extractFirmware(evil);
  assert.ok(r.warnings.some((w) => /traversal/.test(w)));
  const w = await writeExtraction(r, out, { symlinks: 'inside' });
  const all: string[] = [];
  const walk = (d: string) => { for (const n of readdirSync(d)) { const p = join(d, n); all.push(p); if (lstatSync(p).isDirectory()) walk(p); } };
  walk(base);
  assert.ok(all.every((p) => p.startsWith(out)), 'nothing written outside outDir');
  assert.ok(!existsSync(join(base, 'escape.txt')));
  const cpioDir = join(out, '00000000-cpio');
  assert.equal(readFileSync(join(cpioDir, 'escape.txt'), 'utf8'), 'x', 'the .. segments were dropped');
  assert.equal(readFileSync(join(cpioDir, 'etc', 'abs.txt'), 'utf8'), 'abs');
  assert.ok(!existsSync(join(cpioDir, 'link')) || !lstatSync(join(cpioDir, 'link')).isSymbolicLink(), 'absolute symlink not created');
  assert.ok(!existsSync(join(cpioDir, 'rel')), 'escaping relative symlink not created');
  assert.ok(lstatSync(join(cpioDir, 'inner')).isSymbolicLink(), 'a link that stays inside is created with symlinks=inside');
  assert.equal(readFileSync(join(cpioDir, 'link', 'pwned.txt'), 'utf8'), 'through a symlink', 'written into a real directory, not through /tmp');
  assert.ok(w.manifest.endsWith('revlens-extract.json'));
  const man = JSON.parse(readFileSync(w.manifest, 'utf8'));
  assert.ok(man.symlinks.some((s: { path: string; created: boolean }) => s.path.endsWith('/link') && !s.created));
  rmSync(base, { recursive: true, force: true });
});

test('writer: refuses a non-empty outDir and never follows a planted symlink', async () => {
  const base = tmp();
  const out = join(base, 'out'), victim = join(base, 'victim');
  mkdirSync(out); mkdirSync(victim);
  writeFileSync(join(out, 'keep'), 'k');
  const r = extractFirmware(load('initramfs.cpio.gz'));
  await assert.rejects(writeExtraction(r, out), /not empty/);
  rmSync(join(out, 'keep'));
  symlinkSync(victim, join(out, '00000000-gzip'));
  const w = await writeExtraction(r, out, { overwrite: true });
  assert.equal(readdirSync(victim).length, 0, 'nothing written through the planted link');
  assert.ok(w.skipped.some((s) => /symlink/.test(s.reason)));
  rmSync(base, { recursive: true, force: true });
});

test('writer: x_firmware_extract writes the TRX tree and the files hash like unsquashfs', async () => {
  const base = tmp();
  const res = (await tool('x_firmware_extract').run({ path: join(F, 'revlens.trx'), outDir: join(base, 'o') })) as { written: { written: number; skipped: unknown[] }; stats: { files: number } };
  assert.equal(res.written.written, 9, 'two TRX partitions, the LZMA kernel and six squashfs files');
  const hello = readFileSync(join(base, 'o', '00000000-trx', 'partition1.extract', '00000000-squashfs', 'bin', 'hello'));
  assert.equal(sha(hello), rootRef['bin/hello']!.sha256);
  rmSync(base, { recursive: true, force: true });
});

test('firmware: limits on depth, files and bytes are honoured and reported', () => {
  const shallow = extractFirmware(load('fit.itb'), { maxDepth: 1 });
  assert.ok(shallow.stats.maxDepthReached <= 1);
  assert.ok(!shallow.files.some((f) => f.path.includes('cpio')));
  const few = extractFirmware(load('router.bin'), { maxFiles: 3 });
  assert.ok(few.files.length <= 3 && few.truncated);
  const small = extractFirmware(load('router.bin'), { maxTotalBytes: 30000 });
  assert.ok(small.stats.bytes <= 30000 && small.truncated);
  assert.ok(small.warnings.some((w) => /not unpacked/.test(w)));
  const skip = extractFirmware(load('router.bin'), { skip: ['squashfs'] });
  assert.equal(skip.chunks[0]!.type, 'uimage');
  assert.ok(!skip.chunks.some((c) => c.type === 'squashfs'), 'squashfs skipped (its xz blocks are still carved, as binwalk does)');
});

test('firmware: sanitizeMemberPath', () => {
  assert.equal(sanitizeMemberPath('../../a/./b//c'), 'a/b/c');
  assert.equal(sanitizeMemberPath('/abs/x'), 'abs/x');
  assert.equal(sanitizeMemberPath('a\\..\\..\\b'), 'a/b');
  assert.equal(sanitizeMemberPath('a\u0000b\u001b'), 'a_b_');
  assert.equal(sanitizeMemberPath('..'), 'unnamed');
  assert.ok(sanitizeMemberPath('x'.repeat(1000)).length <= 201);
});

test('hostile: extractFirmware on random bytes with planted magic ends quickly with a result', () => {
  const magics = [[0x1f, 0x8b, 8, 0], [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0], [0x68, 0x73, 0x71, 0x73], [0x27, 0x05, 0x19, 0x56], [0xd0, 0x0d, 0xfe, 0xed], [0x48, 0x44, 0x52, 0x30], [0x5f, 0x46, 0x56, 0x48], [0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59], [0x30, 0x37, 0x30, 0x37, 0x30, 0x31], [0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21], [0x02, 0x21, 0x4c, 0x18], [0x50, 0x4b, 3, 4]];
  fc.assert(fc.property(fc.uint8Array({ minLength: 64, maxLength: 8192 }), fc.array(fc.tuple(fc.nat(8000), fc.nat(magics.length - 1)), { maxLength: 6 }), (b, plants) => {
    const x = b.slice();
    for (const [o, m] of plants) { const sig = magics[m]!; if (o + sig.length + 64 <= x.length) x.set(sig, o + 64 > x.length ? 0 : o); }
    const t = Date.now();
    try { const r = extractFirmware(x, { timeBudgetMs: 3000 }); assert.ok(r.stats.files >= 0); } catch (e) { assert.ok(e instanceof ParseError, String(e)); }
    assert.ok(Date.now() - t < 4000);
  }), { numRuns: 120 });
  // truncations and bit flips of real images
  for (const f of ['revlens.trx', 'router.bin', 'uefi/revlens-fv.bin', 'fit.itb']) {
    const seed = load(f);
    fc.assert(fc.property(fc.nat(seed.length), fc.array(fc.nat(seed.length - 1), { maxLength: 6 }), (n, flips) => {
      const x = seed.slice(0, n);
      for (const o of flips) if (o < x.length) x[o] = (x[o] as number) ^ 0x5a;
      const t = Date.now();
      extractFirmware(x, { timeBudgetMs: 3000 });
      assert.ok(Date.now() - t < 4000, f);
    }), { numRuns: 25 });
  }
});

// Real OpenWrt 23.05.5 images (GPL-2.0, fetched by scripts/fetch-openwrt.mjs, not committed).
// References from scripts/gen-openwrt-reference.py: binwalk 2.4.3 offsets, liblzma kernels,
// unsquashfs 4.6.1 file hashes.
const OW = join(S, 'firmware', 'openwrt');
for (const refFile of existsSync(OW) ? readdirSync(OW).filter((f) => f.endsWith('.reference.json')) : []) {
  const ref = JSON.parse(readFileSync(join(OW, refFile), 'utf8')) as { image: string; sha256: string; binwalk: { offset: number; description: string }[]; lzma: { offset: number; sha256: string; size: number }[]; squashfs: { offset: number; entries: number; files: Record<string, string> }[] };
  const img = cachedAt('openwrt', ref.image);
  test(`openwrt: ${ref.image} matches binwalk, liblzma and unsquashfs`, { skip: img ? false : 'run node packages/extras/scripts/fetch-openwrt.mjs', timeout: 120000 }, () => {
    assert.equal(sha(img!), ref.sha256);
    const r = extractFirmware(img!, { timeBudgetMs: 110000 });
    assert.equal(r.truncated, false);
    // where binwalk sees the kernel and the root filesystem
    const sqAt = ref.binwalk.find((x) => x.description.startsWith('Squashfs'))!.offset;
    const top = r.chunks.filter((c) => c.depth === 0);
    if (top[0]!.type === 'trx') {
      const parts = /partitions at (.*)$/.exec(top[0]!.description)![1]!.split(', ').map((x) => parseInt(x, 16));
      assert.ok(parts.includes(sqAt), `TRX partition at the squashfs offset ${sqAt}`);
      for (const x of ref.binwalk.slice(1)) assert.ok(parts.includes(x.offset), `TRX partition at ${x.offset} (${x.description.slice(0, 30)})`);
    } else assert.ok(top.some((c) => c.type === 'squashfs' && c.offset === sqAt) || top.some((c) => c.type === 'uimage' && c.end === sqAt), 'squashfs found where binwalk sees it');
    for (const lz of ref.lzma) assert.ok(r.files.some((f) => f.path.endsWith('lzma.uncompressed') && f.sha256 === lz.sha256 && f.size === lz.size), `kernel LZMA at ${lz.offset} decodes like liblzma`);
    // every file and symlink unsquashfs creates, with the same bytes
    const sqDir = r.chunks.find((c) => c.type === 'squashfs')!.path;
    const got = new Map(r.files.filter((f) => f.path.startsWith(sqDir + '/')).map((f) => [f.path.slice(sqDir.length + 1), f]));
    let n = 0;
    for (const [p, w] of Object.entries(ref.squashfs[0]!.files)) {
      const f = got.get(p);
      assert.ok(f, `${p} extracted`);
      if (w === 'dir') assert.equal(f.kind, 'dir', p);
      else if (w.startsWith('->')) assert.equal(f.target, w.slice(2), p);
      else { assert.equal(f.sha256, w, p); n++; }
    }
    assert.ok(n > 300, `${n} regular files compared`);
  });
}
