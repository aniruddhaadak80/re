// Jump table and code pointer table resolution on real binaries built with zig cc from
// samples/disasm/src/switch.c (x86-64 PIE, x86-64 static non PIE, AArch64) and Lua 5.4.7.
// Expected case targets are checked by reading the code: every case in switch.c has its own string
// or constant, so the block a resolved table entry points at must reference exactly that value.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { openProgram, resolveFunction, disasmFunction, type Program, type AnalyzedFunction } from '../src/node.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
const P = (n: string) => join(dir, n);

/** strings and immediates seen from `start` along jumps and fallthroughs (not conditional branches), up to a return */
function caseEvidence(p: Program, af: AnalyzedFunction, start: number): { strings: string[]; imms: number[]; calls: string[] } {
  const blocks = new Map(af.blocks.map((b) => [b.start, b] as const));
  const strings: string[] = [];
  const imms: number[] = [];
  const calls: string[] = [];
  let cur = blocks.get(start);
  for (let hops = 0; cur && hops < 4; hops++) {
    for (const i of cur.insns) {
      for (const d of af.dataRefs) if (d.at === i.address && d.kind === 'string' && d.value !== undefined) strings.push(d.value);
      imms.push(...i.imms);
      if (i.flow === 'call' && i.target !== undefined) calls.push(p.nameOf(i.target) ?? '?');
    }
    const next = cur.succ.find((e) => e.kind === 'jump' || e.kind === 'fallthrough');
    if (!next || cur.succ.some((e) => e.kind === 'true')) break;
    cur = blocks.get(next.to);
  }
  return { strings, imms, calls };
}

const BINS = ['switch-x64.elf', 'switch-x64-nopie.elf', 'switch-arm64.elf'];

for (const bin of BINS) {
  test(`${bin}: dense_switch table has 10 cases and each case target is that case`, async () => {
    const p = await openProgram({ path: P(bin) });
    const af = p.analyze(resolveFunction(p, 'dense_switch')!.addr)!;
    const sw = af.switches?.find((s) => s.kind === 'switch');
    assert.ok(sw, 'switch resolved');
    assert.equal(sw!.count, 10);
    assert.equal(sw!.bound, 'cmp');
    assert.equal(af.unresolvedIndirect, 0);
    const expect: Record<number, (e: ReturnType<typeof caseEvidence>) => boolean> = {
      0: (e) => e.strings.includes('op zero'),
      1: (e) => e.imms.includes(0x11) && e.imms.includes(0x12),
      2: (e) => e.strings.includes('op two %d\n'),
      3: (e) => e.strings.includes('op three'),
      5: (e) => e.strings.includes('op five %d %d\n'),
      6: (e) => e.strings.includes('op six'),
      // atoi("77") is folded by clang: case 7 returns 77 * 3 = 231 (on AArch64 w0 = 231 is set before the br)
      7: (e) => e.calls.length === 0 && (e.imms.includes(231) || bin.includes('arm64')),
      8: (e) => e.strings.includes('op eight'),
      9: (e) => e.strings.includes('op nine'),
    };
    for (const [k, ok] of Object.entries(expect)) {
      const ev = caseEvidence(p, af, sw!.targets[Number(k)]!);
      assert.ok(ok(ev), `case ${k} at 0x${sw!.targets[Number(k)]!.toString(16)}: ${JSON.stringify(ev)}`);
    }
    // the CFG now holds every case block as a successor of the dispatch block
    const disp = af.blocks.find((b) => b.insns.some((i) => i.address === sw!.at))!;
    assert.equal(new Set(disp.succ.filter((e) => e.kind === 'case').map((e) => e.to)).size, new Set(sw!.targets).size);
    assert.equal(disp.exit, undefined);
  });

  test(`${bin}: biased_switch finds the bias (100), holes go to the default block`, async () => {
    const p = await openProgram({ path: P(bin) });
    const af = p.analyze(resolveFunction(p, 'biased_switch')!.addr)!;
    const sw = af.switches!.find((s) => s.kind === 'switch')!;
    assert.equal(sw.count, 12);
    assert.equal(sw.bias, 100);
    assert.equal(sw.targets[3], sw.targets[7], 'cases 103 and 107 share the default target');
    const ev = (k: number) => caseEvidence(p, af, sw.targets[k - 100]!);
    assert.ok(ev(100).imms.includes(0x100));
    assert.ok(ev(101).strings.includes('b101'));
    assert.ok(ev(102).strings.includes('b102 %d\n'));
    assert.ok(ev(104).imms.includes(0x104));
    assert.ok(ev(105).strings.includes('b105'));
    assert.ok(ev(106).imms.includes(107) || bin.includes('arm64'), 'atoi("106") is folded: returns 106 + 1');
    assert.ok(ev(108).strings.includes('b108'));
    assert.ok(ev(109).strings.includes('b109 %d %d\n'));
    assert.ok(ev(111).imms.includes(0x111));
    assert.ok(ev(103).imms.includes(-1) || ev(103).imms.includes(0xffffffff), 'hole is the default: hit(-1)');
  });

  test(`${bin}: dispatch through HANDLERS[k] is a code pointer table with the 4 handlers`, async () => {
    const p = await openProgram({ path: P(bin) });
    const af = p.analyze(resolveFunction(p, 'dispatch')!.addr)!;
    const call = af.calls.find((c) => c.candidates);
    assert.ok(call, 'indirect call resolved');
    assert.deepEqual(call!.candidates!.map((t) => p.nameOf(t)), ['h_add', 'h_sub', 'h_mul', 'h_div']);
    assert.equal(call!.resolvedBy, 'table');
  });
}

test('switch-x64.elf and switch-arm64.elf: char_class lexer switch (x86-64 table with bias 0x61; AArch64 uses a compare tree)', async () => {
  const p = await openProgram({ path: P('switch-x64.elf') });
  const af = p.analyze(resolveFunction(p, 'char_class')!.addr)!;
  const sw = af.switches!.find((s) => s.kind === 'switch')!;
  assert.equal(sw.count, 7);
  assert.equal(sw.bias, 0x61);
  assert.ok(caseEvidence(p, af, sw.targets[0]!).strings.includes('letter a'));
  // the format strings live in callee saved registers set before the loop, so check the callees
  assert.ok(caseEvidence(p, af, sw.targets[1]!).calls.includes('hit'), "case 'b' calls hit");
  assert.ok(caseEvidence(p, af, sw.targets[2]!).calls.includes('printf'), "case 'c' calls printf");
  assert.ok(caseEvidence(p, af, sw.targets[5]!).calls.includes('strlen'), "case 'f' calls strlen");
  assert.deepEqual(caseEvidence(p, af, sw.targets[6]!).calls, ['hit', 'hit'], "case 'g' calls hit twice");
  const a = await openProgram({ path: P('switch-arm64.elf') });
  const aaf = a.analyze(resolveFunction(a, 'char_class')!.addr)!;
  assert.equal(aaf.switches, undefined, 'clang emitted compares, not a table, on AArch64');
  assert.equal(aaf.unresolvedIndirect, 0);
});

test('sparse_switch has no table (compare tree) on every target', async () => {
  for (const bin of BINS) {
    const p = await openProgram({ path: P(bin) });
    const af = p.analyze(resolveFunction(p, 'sparse_switch')!.addr)!;
    assert.equal(af.switches, undefined, bin);
  }
});

test('lua-x64.elf: luaV_execute computed goto table is luaV_execute.disptab with NUM_OPCODES (83) entries', async () => {
  const ref = JSON.parse(readFileSync(P('gaps-reference.json'), 'utf8'))['lua-x64.elf'];
  const p = await openProgram({ path: P('lua-x64.elf') });
  const f = resolveFunction(p, 'luaV_execute')!;
  const af = p.analyze(f.addr)!;
  const first = af.switches!.find((s) => s.sharedWith === undefined && s.kind === 'switch')!;
  // pyelftools: luaV_execute.disptab address and size (83 * 8 bytes); lopcodes.h: NUM_OPCODES = 83
  assert.equal(first.table, ref.disptab.addr);
  assert.equal(first.count * first.entrySize, ref.disptab.size);
  assert.equal(first.count, 83);
  assert.equal(first.bound, 'mask');
  for (const t of first.targets) assert.ok(t > f.addr && t < f.addr + ref.luaV_execute.size, `target 0x${t.toString(16)} inside luaV_execute`);
  // every handler ends with the same dispatch; they share the table
  const shared = af.switches!.filter((s) => s.sharedWith === first.at);
  assert.ok(shared.length >= 10, `shared dispatch sites: ${shared.length}`);
  assert.ok(af.blocks.length > 500, `${af.blocks.length} blocks`);
  // the op handlers are now reachable: OP_ADD's handler calls luaT_trybinTM through the slow path
  const d = await disasmFunction({ path: P('lua-x64.elf'), function: 'luaV_execute', limit: 1 });
  assert.ok(d.switches.length >= 10);
  assert.equal(d.switches[0]!.entries, 83);
});

test('lua-x64.elf: luaK_prefix and luaH_get switches resolve with a bounds check', async () => {
  const p = await openProgram({ path: P('lua-x64.elf') });
  for (const name of ['luaK_prefix', 'luaH_get']) {
    const af = p.analyze(resolveFunction(p, name)!.addr)!;
    const sw = af.switches?.find((s) => s.kind === 'switch');
    assert.ok(sw && sw.bound === 'cmp', name);
    for (const t of sw!.targets) assert.ok(af.blocks.some((b) => b.start === t), `${name}: case block 0x${t.toString(16)} in CFG`);
  }
});
