// Indirect call resolution: C++ virtual calls (samples/disasm/src/virt.cpp built with zig c++ for
// x86-64 and AArch64, plus a stripped copy) and Go dispatch stubs (esbuild, when fetched).
// Expected targets come from the source: make_noise calls Animal::speak (slot 4 after the two
// destructors, name and legs), count_legs calls legs, which Dog inherits from Animal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { disasmIndirectTargets, disasmPseudocode, openProgram, resolveFunction } from '../src/node.ts';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', '..', '..', 'samples', 'disasm');
const P = (n: string) => join(dir, n);
const ref = JSON.parse(readFileSync(P('gaps-reference.json'), 'utf8'));

type Site = { at: string; function: string; kind: string; resolved: boolean; resolvedBy?: string; targets: { addr: string; name?: string }[] };

for (const bin of ['virt-x64.elf', 'virt-arm64.elf']) {
  test(`${bin}: vtables match the _ZTV symbols (pyelftools) and virtual calls get their slot candidates`, async () => {
    const p = await openProgram({ path: P(bin) });
    const vt = p.vtables();
    for (const [name, v] of Object.entries<{ addr: number; size: number }>(ref[bin].vtables)) {
      const t = vt.find((x) => x.name === name);
      assert.ok(t, name);
      assert.equal(t!.addr, v.addr + 16, `${name}: slots start after offset-to-top and RTTI`);
      assert.equal(t!.slots.length, (v.size - 16) / 8, `${name}: 5 virtual functions`);
    }
    const r = await disasmIndirectTargets({ path: P(bin) });
    const sites = r.sites as Site[];
    const noise = sites.find((s) => s.function === '_Z10make_noisePK6Animal')!;
    assert.equal(noise.resolvedBy, 'vtable');
    assert.deepEqual(noise.targets.map((t) => t.name).sort(), ['_ZNK3Dog5speakEv', '_ZNK4Bird5speakEv', '_ZNK5Snake5speakEv']);
    const legs = sites.find((s) => s.function === '_Z10count_legsPP6Animali')!;
    assert.deepEqual(legs.targets.map((t) => t.name).sort(), ['_ZNK4Bird4legsEv', '_ZNK5Snake4legsEv', '_ZNK6Animal4legsEv']);
    const mainCalls = sites.filter((s) => s.function === 'main' && s.resolvedBy === 'vtable');
    assert.ok(mainCalls.some((s) => s.targets.every((t) => /4nameEv$/.test(t.name ?? ''))), 'g_pet->name()');
    assert.ok(mainCalls.some((s) => s.targets.every((t) => /D0Ev$/.test(t.name ?? ''))), 'delete zoo[i] (deleting destructor)');
    const pc = await disasmPseudocode({ path: P(bin), function: '_Z10make_noisePK6Animal' });
    assert.match(pc.pseudocode, /one of: _ZNK3Dog5speakEv, _ZNK4Bird5speakEv, _ZNK5Snake5speakEv \(vtable\)/);
  });
}

test('virt-x64-stripped.elf: without symbols the vtables are found by their Itanium shape and give the same targets', async () => {
  const full = await openProgram({ path: P('virt-x64.elf') });
  const names = new Map([...full.functions.values()].map((f) => [f.addr, f.name] as const));
  const r = await disasmIndirectTargets({ path: P('virt-x64-stripped.elf') });
  const sites = r.sites as Site[];
  const noise = sites.find((s) => s.function === 'sub_' + resolveFunction(full, '_Z10make_noisePK6Animal')!.addr.toString(16))!;
  assert.ok(noise, JSON.stringify(sites.map((s) => s.function)));
  assert.deepEqual(noise.targets.map((t) => names.get(parseInt(t.addr, 16))).sort(), ['_ZNK3Dog5speakEv', '_ZNK4Bird5speakEv', '_ZNK5Snake5speakEv']);
  assert.equal(r.resolved, 6);
});

const go = join(here, '..', '..', '..', 'samples', '.cache', 'disasm', 'esbuild-linux-x64');
test('Go esbuild: runtime.reflectcall dispatches to runtime.call16 ... call1073741824 (asm_amd64.s DISPATCH)', { skip: !existsSync(go) && 'run fetch-fixtures.mjs' }, async () => {
  const r = await disasmIndirectTargets({ path: go, function: 'runtime.reflectcall' });
  const names = (r.sites as Site[]).filter((s) => s.resolved).flatMap((s) => s.targets.map((t) => t.name));
  // DISPATCH(runtime·call16, 16) through DISPATCH(runtime·call1073741824, 1073741824): 27 sizes
  for (const n of ['runtime.call16', 'runtime.call32', 'runtime.call65536', 'runtime.call1073741824']) assert.ok(names.includes(n), n);
  assert.equal(new Set(names.filter((n) => /^runtime\.call\d+$/.test(n ?? ''))).size, 27);
});
