// Load modes: DOS COM (x86 16 bit at 0x100), raw binaries at a base address and GameCube DOL
// (big endian PowerPC). Fixtures: samples/disasm/hello16.com (llvm-mc 19 from src/hello.s) and
// samples/disasm/demo-ppc.dol (zig cc 0.17.1 powerpc-freestanding-eabi from src/dolmain.c, packed by
// src/make-dol.py). Expected values in modes-reference.json come from radare2 6 (its own DOL loader
// and disassembler) through src/make-modes-reference.py.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { disasmAt, disasmInfo, disasmFunction, disasmListFunctions, loadImage } from '../src/node.ts';
import { isDol, loadDol } from '../src/loader/rawmodes.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
const P = (n: string) => join(dir, n);
const REF = JSON.parse(readFileSync(P('modes-reference.json'), 'utf8'));
const norm = (s: string) => s.replace(/\s+/g, ' ').trim();

test('DOS COM: 16 bit decode at 0x100 matches radare2 addresses, sizes, text and branch targets', async () => {
  const r: any = await disasmAt({ path: P('hello16.com'), loadMode: 'dos-com', address: '0x100', count: REF['hello16.com'].insns.length } as never);
  REF['hello16.com'].insns.forEach((x: any, i: number) => {
    const y = r.instructions[i];
    assert.equal(y.addr, x.addr);
    assert.equal(y.bytes.length / 2, x.size, x.addr);
    assert.equal(norm(y.text), norm(x.text), x.addr);
  });
  const info: any = await disasmInfo({ path: P('hello16.com'), loadMode: 'dos-com' } as never);
  assert.equal(info.format, 'dos-com');
  assert.equal(info.arch, 'x86_16');
  assert.equal(info.entry, '0x100');
  const fns: any = await disasmListFunctions({ path: P('hello16.com'), loadMode: 'dos-com' } as never);
  assert.deepEqual(fns.functions.map((f: any) => f.addr), ['0x100', '0x119'], 'start and the call target');
  const f: any = await disasmFunction({ path: P('hello16.com'), loadMode: 'dos-com', function: '0x119' } as never);
  assert.equal(f.summary.instructions, 3);
});

test('raw load mode: bytes at a base address, entry and arch as given', async () => {
  const b = readFileSync(P('hello16.com'));
  const img = loadImage(new Uint8Array(b), { loadMode: 'raw', rawArch: 'x86_16', rawBase: 0x7c00, rawEntry: 0x7c00 });
  assert.equal(img.format, 'raw');
  assert.equal(img.segments[0]!.vaddr, 0x7c00);
  const r: any = await disasmAt({ bytes: new Uint8Array(b), loadMode: 'raw', rawArch: 'x86_16', rawBase: 0x7c00, address: '0x7c07', count: 1 } as never);
  assert.equal(r.instructions[0].text, 'call 0x7c19');
  assert.throws(() => loadImage(new Uint8Array(b), { loadMode: 'raw' }), /rawArch/);
});

test('GameCube DOL: sections, entry and function bodies match radare2', async () => {
  const ref = REF['demo-ppc.dol'];
  const info: any = await disasmInfo({ path: P('demo-ppc.dol') });
  assert.equal(info.format, 'gamecube-dol');
  assert.equal(info.arch, 'ppc');
  assert.equal(info.endian, 'be');
  assert.equal(info.entry, ref.entry);
  const mine = info.sections.map((s: any) => [s.vaddr, s.size, s.exec]);
  assert.deepEqual(mine, ref.sections.map((s: any) => [s.vaddr, s.size, s.perm.includes('x')]));
  for (const [name, fn] of Object.entries<any>(ref.functions)) {
    const f: any = await disasmFunction({ path: P('demo-ppc.dol'), function: fn.addr, limit: 1000 });
    const addrs = f.blocks.flatMap((b: any) => b.insns.map((i: any) => i.addr)).sort();
    assert.deepEqual(addrs, fn.insns.map((x: any) => x.addr).sort(), name);
    const texts = new Map(f.blocks.flatMap((b: any) => b.insns.map((i: any) => [i.addr, norm(i.text)])));
    for (const x of fn.insns) assert.equal(texts.get(x.addr), norm(x.text), `${name} ${x.addr}`);
  }
  const spin: any = await disasmFunction({ path: P('demo-ppc.dol'), function: ref.symbols.spin });
  assert.deepEqual(spin.calls.map((c: any) => c.target), [ref.symbols.mix]);
  assert.equal(spin.summary.loops, 1);
});

test('hostile DOL and COM input', () => {
  const dol = new Uint8Array(readFileSync(P('demo-ppc.dol')));
  assert.ok(isDol(dol));
  fc.assert(fc.property(fc.integer({ min: 0, max: 0xff }), fc.uint8Array({ minLength: 4, maxLength: 4 }), (pos, junk) => {
    const b = dol.slice();
    b.set(junk, pos & ~3);
    try { const img = loadDol(b); assert.ok(img.segments.length > 0); } catch (e) { assert.match((e as Error).message, /DOL/); }
  }), { numRuns: 300 });
  assert.equal(isDol(dol.subarray(0, 0x80)), false);
  const big = new Uint8Array(0x10000).fill(0x90);
  const img = loadImage(big, { loadMode: 'dos-com' });
  assert.equal(img.bytes.length, 0xff00);
  assert.match(img.warnings[0]!, /65280/);
});
