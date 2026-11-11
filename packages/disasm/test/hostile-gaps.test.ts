// Hostile input for the jump table resolver, the value tracker and the function matcher. Real fixtures
// get random bytes written over their jump tables, code and headers (fast-check). The tools must not
// throw past a clean format error, must stay inside their caps, and must keep their answers well formed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { disasmIndirectTargets, disasmTraceValues } from '../src/flowapi.ts';
import { disasmMatchFunctions, disasmCompareFunctions } from '../src/matchapi.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
const load = (n: string) => new Uint8Array(readFileSync(join(dir, n)));
const SWITCH = load('switch-x64.elf');
const SWITCH_ARM = load('switch-arm64.elf');
const VIRT = load('virt-x64.elf');
const HELLO = load('hello-x64.elf');
const FORMAT_ERROR = /not an ELF|not a PE|Mach-O|unsupported|unknown format|no executable|not found|cannot|invalid|truncated|out of range|not mapped|no call |no referenced string|no register parameters|pass path or bytes/i;

/** Run fn; a thrown error is fine only when it is a clean input or format error. */
async function clean<T>(fn: () => Promise<T>): Promise<T | undefined> {
  try { return await fn(); } catch (e) {
    assert.ok(e instanceof Error, 'throws an Error');
    assert.match(e.message, FORMAT_ERROR, `unexpected error: ${e.message}`);
    return undefined;
  }
}

function overwrite(base: Uint8Array, at: number, junk: Uint8Array): Uint8Array {
  const b = base.slice();
  for (let i = 0; i < junk.length && at + i < b.length; i++) b[at + i] = junk[i]!;
  return b;
}

test('jump table resolver: random table contents and random code around the dispatch (x86-64, AArch64)', async () => {
  await fc.assert(fc.asyncProperty(
    fc.boolean(), fc.integer({ min: 0x400, max: 0x2000 }), fc.uint8Array({ minLength: 1, maxLength: 512 }),
    async (arm, at, junk) => {
      const b = overwrite(arm ? SWITCH_ARM : SWITCH, at, junk);
      const t0 = Date.now();
      const r: any = await clean(() => disasmIndirectTargets({ bytes: b, limit: 50, budgetMs: 3000 }));
      assert.ok(Date.now() - t0 < 20_000, 'stays near its budget');
      if (!r) return;
      assert.ok(r.resolved + r.unresolved === r.total);
      assert.ok(r.sites.length <= 50);
      for (const s of r.sites) {
        assert.ok((s.targets ?? []).length <= 1024, 'table entries are capped');
        if (s.entries !== undefined) assert.ok(s.entries >= 0 && s.entries <= 1024);
      }
    }), { numRuns: 60 });
});

test('jump table resolver: tables filled with huge offsets and self references never loop', async () => {
  // the dense_switch table in switch-x64.elf sits at 0x530; fill it with patterns that point everywhere
  for (const fill of [0x00, 0xff, 0x7f, 0x80]) {
    const r: any = await clean(() => disasmIndirectTargets({ bytes: overwrite(SWITCH, 0x530, new Uint8Array(512).fill(fill)), budgetMs: 3000 }));
    if (r) for (const s of r.sites) assert.ok((s.targets ?? []).length <= 1024);
  }
});

test('value tracker: backward and forward traces on corrupted code stay bounded', async () => {
  await fc.assert(fc.asyncProperty(
    fc.integer({ min: 0x1000, max: Math.max(0x1001, HELLO.length - 64) }), fc.uint8Array({ minLength: 1, maxLength: 256 }),
    fc.constantFrom('printf', 'puts', '0x0', 'hello'), fc.integer({ min: 0, max: 3 }),
    async (at, junk, what, depth) => {
      const b = overwrite(HELLO, at, junk);
      const back: any = await clean(() => disasmTraceValues({ bytes: b, function: 'main', call: what, depth, limit: 20, budgetMs: 2000 }));
      if (back) {
        assert.equal(back.mode, 'backward');
        for (const c of back.calls ?? []) for (const a of c.args ?? []) assert.equal(typeof a.value?.text, 'string');
      }
      const fwd: any = await clean(() => disasmTraceValues({ bytes: b, value: what, depth, limit: 20, budgetMs: 2000 }));
      if (fwd) {
        assert.equal(fwd.mode, 'forward');
        for (const x of fwd.results ?? []) assert.ok(x.sinks.length <= 20);
      }
    }), { numRuns: 50 });
});

test('value tracker: absurd parameters are clamped, not trusted', async () => {
  const r: any = await clean(() => disasmTraceValues({ path: undefined, bytes: HELLO, function: 'main', call: 'printf', arg: 1e9, depth: 1e9, limit: 1e9, budgetMs: 1e12 }));
  if (r) assert.ok(r.calls.every((c: any) => c.args.length <= 16));
  const f: any = await clean(() => disasmTraceValues({ bytes: HELLO, function: 'main', param: -5, depth: -1 }));
  if (f) assert.ok(f.depth >= 0 && f.depth <= 3);
});

test('matcher: a binary against a randomly corrupted copy gives one to one, well formed matches', async () => {
  await fc.assert(fc.asyncProperty(
    fc.integer({ min: 0, max: VIRT.length - 1 }), fc.uint8Array({ minLength: 1, maxLength: 1024 }), fc.boolean(),
    async (at, junk, useNames) => {
      const b = overwrite(VIRT, at, junk);
      const r: any = await clean(() => disasmMatchFunctions({ bytes: VIRT, bytes2: b, useNames, limit: 500, budgetMs: 5000 }));
      if (!r) return;
      assert.ok(r.matched <= Math.min(r.a.functions, r.b.functions));
      const bs = new Set<string>();
      for (const m of r.matches) {
        assert.ok(m.confidence >= 0 && m.confidence <= 1);
        assert.ok(m.similarity === undefined || (m.similarity >= 0 && m.similarity <= 1));
        assert.ok(!bs.has(m.b.addr), 'each function on the second side is matched at most once');
        bs.add(m.b.addr);
      }
      assert.equal(r.identical + r.changed, r.matched);
    }), { numRuns: 40 });
});

test('matcher and compare: random bytes on either side are refused or matched without throwing', async () => {
  await fc.assert(fc.asyncProperty(fc.uint8Array({ minLength: 0, maxLength: 4096 }), async (junk) => {
    await clean(() => disasmMatchFunctions({ bytes: junk, bytes2: VIRT, budgetMs: 2000 }));
    await clean(() => disasmMatchFunctions({ bytes: VIRT, bytes2: junk, budgetMs: 2000 }));
    await clean(() => disasmCompareFunctions({ bytes: VIRT, function: 'main', bytes2: junk, function2: 'main' }));
  }), { numRuns: 40 });
});
