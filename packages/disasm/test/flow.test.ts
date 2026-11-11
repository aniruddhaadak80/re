// Value flow, stack variables and pseudo code structure on real binaries built from
// samples/disasm/src/switch.c (-O2 and -O0, x86-64 and AArch64). Expected values come from reading
// the C source: load_settings calls open_config("/etc/revlens/settings.conf", 0x241, 0644), and so on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { disasmTraceValues, disasmPseudocode, disasmIndirectTargets, openProgram, resolveFunction, TOOLS } from '../src/node.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
const P = (n: string) => join(dir, n);
const ALL = ['switch-x64.elf', 'switch-arm64.elf', 'switch-x64-O0.elf', 'switch-arm64-O0.elf'];

for (const bin of ALL) {
  test(`${bin}: the constants reaching open_config's arguments (through stack slots at -O0)`, async () => {
    const r = await disasmTraceValues({ path: P(bin), function: 'load_settings', call: 'open_config' });
    assert.equal(r.mode, 'backward');
    const c = (r as { calls: { args: { value: { kind: string; value?: string } }[] }[] }).calls[0]!;
    assert.equal(c.args.length, 3, 'open_config takes 3 register parameters');
    assert.equal(c.args[0]!.value.kind, 'string');
    assert.equal(c.args[0]!.value.value, '/etc/revlens/settings.conf');
    assert.equal(Number(c.args[1]!.value.value), 0x241);
    assert.equal(Number(c.args[2]!.value.value), 0o644);
  });

  test(`${bin}: forward_secret compares its first argument with "revlens-gap-key"`, async () => {
    const r = await disasmTraceValues({ path: P(bin), function: 'forward_secret', call: 'strcmp', depth: 1 }) as { calls: { args: { value: { kind: string; index?: number; value?: string }; fromCallers?: { function: string; value: { kind: string; values?: { kind: string; value?: string }[] } }[] }[] }[] };
    const a = r.calls[0]!.args;
    assert.equal(a[0]!.value.kind, 'argument');
    assert.equal(a[0]!.value.index, 0);
    assert.equal(a[1]!.value.value, 'revlens-gap-key');
    // one hop up: main passes argc > 2 ? argv[2] : "none"
    const from = a[0]!.fromCallers ?? [];
    assert.ok(from.some((x) => x.function === 'main'), 'caller main found');
    const m = from.find((x) => x.function === 'main')!;
    if (!bin.includes('O0')) {
      assert.equal(m.value.kind, 'one-of');
      assert.ok(m.value.values!.some((v) => v.kind === 'string' && v.value === 'none'));
    }
  });

  test(`${bin}: the settings path flows into open_config, then into printf as its second argument`, async () => {
    const r = await disasmTraceValues({ path: P(bin), value: '/etc/revlens/settings.conf', depth: 2 }) as { results: { sinks: { kind: string; callee?: string; argIndex?: number; into?: { function: string; sinks: { kind: string; callee?: string; argIndex?: number }[] } }[] }[] };
    const sinks = r.results[0]!.sinks.filter((s) => s.kind === 'call-arg');
    const oc = sinks.find((s) => s.callee === 'open_config');
    assert.ok(oc, JSON.stringify(r.results[0]!.sinks));
    assert.equal(oc!.argIndex, 0);
    assert.equal(oc!.into?.function, 'open_config');
    const pf = oc!.into!.sinks.find((s) => s.kind === 'call-arg' && /printf/.test(s.callee ?? ''));
    assert.ok(pf, 'reaches printf');
    assert.equal(pf!.argIndex, 1);
  });

  test(`${bin}: parameter 0 of forward_secret flows to strcmp and puts`, async () => {
    const r = await disasmTraceValues({ path: P(bin), function: 'forward_secret', param: 0 }) as { results: { sinks: { kind: string; callee?: string; argIndex?: number }[] }[] };
    const callees = r.results[0]!.sinks.filter((s) => s.kind === 'call-arg' && s.argIndex === 0).map((s) => s.callee);
    assert.ok(callees.includes('strcmp'), JSON.stringify(callees));
    assert.ok(callees.includes('puts'), JSON.stringify(callees));
  });

  test(`${bin}: call through the writable global "chosen" resolves to its initial value h_mul`, async () => {
    const r = await disasmIndirectTargets({ path: P(bin), function: 'call_through_global' });
    const s = r.sites.find((x) => x.resolved && x.kind !== 'switch') as { resolvedBy: string; targets: { name?: string }[] } | undefined;
    assert.ok(s, JSON.stringify(r.sites));
    assert.equal(s!.resolvedBy, 'initial-value');
    assert.deepEqual(s!.targets.map((t) => t.name), ['h_mul']);
  });
}

for (const bin of ['switch-x64-O0.elf', 'switch-arm64-O0.elf']) {
  test(`${bin}: sum_array has 2 parameters, its locals, and lifts to a for loop with a break`, async () => {
    const r = await disasmPseudocode({ path: P(bin), function: 'sum_array' });
    assert.deepEqual(r.params!.map((x) => x.name), ['a1', 'a2']);
    const locals = r.stackVars!.filter((v) => v.kind === 'local');
    // int *a, int n, int total, int i
    assert.equal(locals.length, 4, JSON.stringify(locals));
    assert.deepEqual(locals.map((v) => v.width).sort(), [4, 4, 4, 8]);
    const text = r.pseudocode;
    assert.match(text, /int64_t sum_array\(int64_t a1, int64_t a2\)/);
    assert.match(text, /for \((local_[0-9a-f]+) = 0; \1 < (local_[0-9a-f]+); \1\+\+\) \{/);
    assert.match(text, /break;/);
    assert.doesNotMatch(text, /goto /);
    assert.ok(r.structured);
  });

  test(`${bin}: locals_demo has two counted loops over the 8 element buffer`, async () => {
    const r = await disasmPseudocode({ path: P(bin), function: 'locals_demo' });
    const loops = r.pseudocode.match(/for \((local_[0-9a-f]+) = 0; \1 < 8; \1\+\+\)/g) ?? [];
    assert.equal(loops.length, 2, r.pseudocode);
    assert.match(r.pseudocode, /__stack_chk_fail/);
  });
}

test('switch-x64.elf (-O2): the jump table renders as a switch statement with case labels', async () => {
  const r = await disasmPseudocode({ path: P('switch-x64.elf'), function: 'biased_switch' });
  // the table index is (op - 100); the switch shows the original value so the labels match the source
  assert.match(r.pseudocode, /switch \(rdi \+ 0x64\) \{ \/\/ jump table at 0x[0-9a-f]+, 12 entries/);
  assert.match(r.pseudocode, /edi -= 0x64;/);
  assert.match(r.pseudocode, /case 0x64:/);
  assert.match(r.pseudocode, /case 0x67: case 0x6b: goto L_/, 'holes 103 and 107 share the default target');
  assert.doesNotMatch(r.pseudocode, /goto \*/);
});

test('switch-x64.elf: dispatch lists its 4 candidate handlers in pseudo code', async () => {
  const r = await disasmPseudocode({ path: P('switch-x64.elf'), function: 'dispatch' });
  assert.match(r.pseudocode, /one of: h_add, h_sub, h_mul, h_div \(table\)/);
});

test('value tracker tools are registered', () => {
  for (const n of ['disasm_trace_values', 'disasm_indirect_targets']) assert.ok(TOOLS.some((t) => t.name === n), n);
});

test('main at -O0 passes &local array to sum_array (stack address argument)', async () => {
  const p = await openProgram({ path: P('switch-x64-O0.elf') });
  const r = await disasmTraceValues({ path: P('switch-x64-O0.elf'), function: 'main', call: 'sum_array' }) as { calls: { args: { value: { kind: string; offset?: number } }[] }[] };
  assert.equal(r.calls[0]!.args[0]!.value.kind, 'stack-address');
  assert.equal(r.calls[0]!.args[1]!.value.kind, 'constant');
  assert.ok(resolveFunction(p, 'sum_array'));
});
