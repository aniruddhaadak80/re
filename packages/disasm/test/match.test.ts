// Function matching across binaries. Ground truth:
// - lua-x64.elf vs lua-x64-stripped.elf: the stripped build links the Lua 5.4.7 sources in reverse
//   order, so every function moved; samples/disasm/gaps-reference.json holds the symbols of its
//   unstripped twin (pyelftools). A match is correct when the stripped address is that symbol's.
// - esbuild 0.23.1 vs 0.24.0 (Go, fetched by scripts/fetch-fixtures.mjs): both carry pclntab names;
//   matching runs with useNames:false and a match is correct when the names agree.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { disasmMatchFunctions, disasmCompareFunctions, TOOLS } from '../src/node.ts';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', '..', '..', 'samples', 'disasm');
const cache = join(here, '..', '..', '..', 'samples', '.cache', 'disasm');
const P = (n: string) => join(dir, n);
const ref = JSON.parse(readFileSync(P('gaps-reference.json'), 'utf8'));

test('lua: stripped vs unstripped build, >= 95% of matches correct against symbols and >= 95% of functions matched', async () => {
  const truth = ref['lua-x64-stripped.elf'].functions as Record<string, { addr: number }>;
  const r = await disasmMatchFunctions({ path: P('lua-x64.elf'), path2: P('lua-x64-stripped.elf'), limit: 20000 });
  let ok = 0, bad = 0;
  for (const m of r.matches) {
    const t = truth[m.a.name];
    if (!t) continue;
    if (t.addr === parseInt(m.b.addr, 16)) ok++; else bad++;
  }
  const total = Object.keys(truth).length;
  assert.ok(ok / (ok + bad) >= 0.95, `precision ${ok}/${ok + bad}`);
  assert.ok(ok / total >= 0.95, `recall ${ok}/${total}`);
  assert.ok(r.matches.every((m) => m.confidence > 0 && m.confidence <= 1));
  // the stripped side has no names: everything was matched by code
  assert.equal(r.byMethod.name, undefined);
});

for (const [older, newer] of [['esbuild-linux-x64-0.23.1', 'esbuild-linux-x64'], ['esbuild-darwin-arm64-0.23.1', 'esbuild-darwin-arm64']] as const) {
  const a = join(cache, older), b = join(cache, newer);
  test(`Go ${older} vs 0.24.0: code only matching agrees with pclntab names for >= 95% of matches`, { skip: !(existsSync(a) && existsSync(b)) && 'run fetch-fixtures.mjs' }, async () => {
    const r = await disasmMatchFunctions({ path: a, path2: b, useNames: false, limit: 20000, budgetMs: 120000 });
    let ok = 0;
    for (const m of r.matches) if (m.a.name === m.b.name) ok++;
    assert.ok(ok / r.matches.length >= 0.95, `precision ${ok}/${r.matches.length}`);
    assert.ok(r.matched / r.a.functions >= 0.9, `coverage ${r.matched}/${r.a.functions}`);
    assert.ok(r.identical > 1000 && r.changed > 100, `identical ${r.identical}, changed ${r.changed}`);
    // high confidence matches are almost always right
    const hi = r.matches.filter((m) => m.confidence >= 0.95);
    assert.ok(hi.filter((m) => m.a.name === m.b.name).length / hi.length >= 0.98);
    // with names on, main.main pairs up by name
    const n = await disasmMatchFunctions({ path: a, path2: b, filter: 'main.main', limit: 10 });
    assert.ok(n.matches.some((m) => m.a.name === 'main.main' && m.b.name === 'main.main' && m.method === 'name'));
  });
}

test('compare: h_add vs h_sub in one binary differ in the arithmetic and the string only', async () => {
  const r = await disasmCompareFunctions({ path: P('switch-x64.elf'), function: 'h_add', function2: 'h_sub' });
  assert.equal(r.identical, false);
  assert.deepEqual(r.dimensions.strings.onlyA, ['handler add']);
  assert.deepEqual(r.dimensions.strings.onlyB, ['handler sub']);
  assert.ok(r.dimensions.cfg.sameShape);
  assert.ok(r.diff.some((l) => l.op === '-' && /^(add|lea)/.test(l.text)));
  assert.ok(r.diff.some((l) => l.op === '+' && /^sub/.test(l.text)));
});

test('compare: a function in the unstripped and the stripped Lua build is identical after address normalization', async () => {
  const addr = ref['lua-x64-stripped.elf'].functions.luaH_get.addr as number;
  const r = await disasmCompareFunctions({ path: P('lua-x64.elf'), function: 'luaH_get', path2: P('lua-x64-stripped.elf'), function2: '0x' + addr.toString(16) });
  assert.equal(r.identical, true);
  assert.equal(r.similarity, 1);
  assert.equal(r.blocks.onlyB.length, 0);
  assert.equal(r.diff.length, 0);
});

test('match and compare tools are registered', () => {
  for (const n of ['disasm_match_functions', 'disasm_compare_functions']) assert.ok(TOOLS.some((t) => t.name === n), n);
});
