// Hostile input: truncation, random bytes behind real headers, absurd counts. Nothing may throw
// past the loader's own format error, hang, or allocate without bound.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { Program, loadImage, liftFunction, parseAddrForTest } from './helpers.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
const FILES = ['hello-x64.elf', 'hello-arm64.elf', 'hello-x86.elf', 'hello-arm32.elf', 'hello-x64.exe', 'hello-arm64.macho', 'hello-fat.macho'];
const load = (n: string) => new Uint8Array(readFileSync(join(dir, n)));

async function exercise(bytes: Uint8Array, opts: Record<string, unknown> = {}): Promise<void> {
  let p: Program;
  try {
    p = await Program.open(bytes, { discoveryMs: 300, maxFunctionInsns: 2000, ...opts });
  } catch (e) {
    assert.match((e as Error).message, /not an ELF|fat Mach-O/);
    return;
  }
  const fns = [...p.discover().keys()].slice(0, 40);
  for (const a of fns) {
    const af = p.analyze(a);
    if (af) liftFunction(p, af, 50);
  }
  p.xrefs(300);
  p.decodeAt(p.img.entry ?? 0, 16);
}

test('truncated real binaries never crash', async () => {
  for (const f of FILES) {
    const b = load(f);
    for (const cut of [16, 52, 64, 200, 512, 1024, 4096, Math.floor(b.length / 2), b.length - 1]) {
      if (cut < b.length) await exercise(b.slice(0, cut));
    }
  }
});

test('random bytes after real headers (fast-check)', async () => {
  const heads = FILES.map((f) => load(f).slice(0, 4096));
  await fc.assert(fc.asyncProperty(fc.integer({ min: 0, max: heads.length - 1 }), fc.uint8Array({ minLength: 0, maxLength: 8192 }), fc.integer({ min: 0, max: 4095 }), async (hi, tail, cut) => {
    const h = heads[hi]!;
    const b = new Uint8Array(cut + tail.length);
    b.set(h.subarray(0, cut));
    b.set(tail, cut);
    await exercise(b);
  }), { numRuns: 120 });
});

test('mutated headers (random byte flips in the first 1 KB)', async () => {
  const bases = FILES.map(load);
  await fc.assert(fc.asyncProperty(fc.integer({ min: 0, max: bases.length - 1 }), fc.array(fc.tuple(fc.integer({ min: 0, max: 1023 }), fc.integer({ min: 0, max: 255 })), { minLength: 1, maxLength: 24 }), async (bi, flips) => {
    const b = bases[bi]!.slice();
    for (const [o, v] of flips) if (o < b.length) b[o] = v;
    await exercise(b);
  }), { numRuns: 120 });
});

test('huge counts in headers stay bounded', async () => {
  // ELF: e_shnum and e_phnum to 0xffff
  const e = load('hello-x64.elf');
  e[60] = 0xff; e[61] = 0xff; e[56] = 0xff; e[57] = 0xff;
  const t0 = Date.now();
  await exercise(e);
  // Mach-O: ncmds to 0xffffffff
  const m = load('hello-arm64.macho');
  m[16] = 0xff; m[17] = 0xff; m[18] = 0xff; m[19] = 0xff;
  await exercise(m);
  // PE: NumberOfSections and NumberOfSymbols maxed
  const p = load('hello-x64.exe');
  const pe = p[0x3c]! | (p[0x3d]! << 8);
  p[pe + 6] = 0xff; p[pe + 7] = 0xff;
  p[pe + 16] = 0xff; p[pe + 17] = 0xff; p[pe + 18] = 0xff; p[pe + 19] = 0x7f;
  await exercise(p);
  // fat with an absurd slice count is rejected as non fat
  const fat = load('hello-fat.macho');
  fat[4] = 0x7f;
  assert.throws(() => loadImage(fat), /not an ELF/);
  assert.ok(Date.now() - t0 < 30000);
});

test('raw random code decodes for every architecture without throwing', async () => {
  await fc.assert(fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 2048 }), fc.constantFrom('x86', 'x86_64', 'arm64', 'arm'), async (code, arch) => {
    const p = await Program.open(code, { rawArch: arch as never, rawBase: 0x1000, discoveryMs: 200 });
    const ins = p.decodeAt(0x1000, 300);
    for (const i of ins) { assert.ok(i.size > 0); assert.ok(i.address >= 0x1000); }
    const af = p.analyze(0x1000);
    if (af) liftFunction(p, af, 40);
  }), { numRuns: 80 });
});

test('address parsing rejects junk', () => {
  for (const v of ['', 'zz', '0x', '-1', '0x' + 'f'.repeat(40), {}, null, NaN]) assert.equal(parseAddrForTest(v), undefined);
  assert.equal(parseAddrForTest('0x401000'), 0x401000);
  assert.equal(parseAddrForTest('401000h'), 0x401000);
});
