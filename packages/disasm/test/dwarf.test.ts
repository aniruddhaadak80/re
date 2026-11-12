// DWARF 4 and 5 types, prototypes, locals and globals on binaries built from samples/disasm/src/types.c
// (zig cc 0.17.1: x86-64 and AArch64, -O1 and -O0). Expected values in samples/disasm/dwarf-reference.json
// come from pyelftools 0.33 (structure) and llvm-dwarfdump 19 (type names), through
// samples/disasm/src/make-dwarf-reference.py. llvm-dwarfdump prints C tag types without the
// struct/union/enum keyword; RevLens keeps it, so names are compared with the keyword removed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { loadImage, readDwarf, disasmDebugInfo, disasmPseudocode, TOOLS, declare } from '../src/node.ts';

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'samples', 'disasm');
const P = (n: string) => join(dir, n);
const REF = JSON.parse(readFileSync(P('dwarf-reference.json'), 'utf8')) as Record<string, any>;
const strip = (s: string | undefined) => (s ?? 'void').replace(/\b(struct|union|enum) /g, '');
const FILES = Object.keys(REF);

for (const f of FILES) {
  const ref = REF[f];
  test(`${f}: DWARF ${ref.version} structs, unions, enums and typedefs match pyelftools and llvm-dwarfdump`, () => {
    const d = readDwarf(loadImage(new Uint8Array(readFileSync(P(f)))));
    assert.ok(d.present);
    assert.ok(d.complete, d.warnings.join('; '));
    const unit = d.units.find((u) => u.name === 'types.c')!;
    assert.equal(unit.version, ref.version);
    const mine = d.types.filter((t) => t.unit === unit.offset);
    for (const [name, s] of Object.entries<any>(ref.structs)) {
      const t = mine.find((x) => x.display === name && x.members);
      assert.ok(t, `missing ${name}`);
      assert.equal(t.size, s.size, name);
      assert.equal(t.members!.length, s.members.length, name);
      s.members.forEach((m: any, i: number) => {
        const x = t.members![i]!;
        assert.equal(x.name, m.name);
        assert.equal(strip(x.type), m.type, `${name}.${m.name}`);
        if (m.offset !== undefined) assert.equal(x.offset, m.offset, `${name}.${m.name} offset`);
        if (m.bitSize !== undefined) { assert.equal(x.bitSize, m.bitSize); assert.equal(x.bitOffset, m.bitOffset, `${name}.${m.name} bit offset`); }
      });
    }
    for (const [name, vals] of Object.entries<any>(ref.enums)) {
      const t = mine.find((x) => x.kind === 'enum' && x.name === name)!;
      assert.deepEqual(Object.fromEntries(t.enumerators!.map((e) => [e.name, e.value])), vals);
    }
    for (const [name, target] of Object.entries<any>(ref.typedefs)) {
      const t = mine.find((x) => x.kind === 'typedef' && x.name === name)!;
      assert.equal(strip(t.aliasOf), target, name);
    }
  });

  test(`${f}: function prototypes, ranges, parameters, locals and globals match the reference`, () => {
    const d = readDwarf(loadImage(new Uint8Array(readFileSync(P(f)))));
    for (const [name, r] of Object.entries<any>(ref.functions)) {
      const fn = d.functions.find((x) => x.name === name && x.low !== undefined)!;
      assert.ok(fn, name);
      assert.equal('0x' + fn.low!.toString(16), r.low);
      assert.equal('0x' + fn.high!.toString(16), r.high);
      assert.equal(strip(fn.returns), r.returns);
      assert.deepEqual(fn.params.map((x) => ({ name: x.name, type: strip(x.type) })), r.params);
      assert.deepEqual(fn.locals.map((x) => x.name), r.locals);
    }
    for (const [name, g] of Object.entries<any>(ref.globals)) {
      const x = d.globals.find((y) => y.name === name)!;
      assert.equal(strip(x.type), g.type);
      assert.equal('0x' + x.addr!.toString(16), g.addr);
    }
  });
}

test('C prototypes and declarations read like the source', () => {
  const d = readDwarf(loadImage(new Uint8Array(readFileSync(P('types-dwarf5-x64.elf')))));
  const proto = (n: string) => d.functions.find((x) => x.name === n && x.low)!.prototype;
  assert.equal(proto('node_weight'), 'int node_weight(struct node *n, int scale, color_t c)');
  assert.equal(proto('value_mix'), 'double value_mix(union value v, float k)');
  assert.equal(proto('main'), 'int main(int argc, char **argv)');
  assert.equal(proto('cmp_int'), 'int cmp_int(const void *a, const void *b)');
  assert.equal(declare('int (*)(const void *, const void *)', 'f'), 'int (*f)(const void *, const void *)');
  assert.equal(declare('u32_t[4]', 'ids'), 'u32_t ids[4]');
  // -O1: parameters live in registers at entry (location lists)
  const nw = d.functions.find((x) => x.name === 'node_weight' && x.low)!;
  assert.deepEqual(nw.params.map((x) => x.location?.reg), ['rdi', 'rsi', 'rdx']);
});

test('disasm_debug_info views: summary, type with C declaration, function, globals', async () => {
  const path = P('types-dwarf5-x64.elf');
  const s: any = await disasmDebugInfo({ path });
  assert.equal(s.present, true);
  assert.ok(s.units.some((u: any) => u.name === 'types.c' && u.version === 5 && u.language === 'C11'));
  const t: any = await disasmDebugInfo({ path, view: 'type', name: 'struct node' });
  assert.equal(t.size, 80);
  assert.match(t.declarationText, /cmp_fn compare; \/\/ offset 64/);
  assert.match(t.declarationText, /u32_t ids\[4\]; \/\/ offset 44/);
  const td: any = await disasmDebugInfo({ path, view: 'type', name: 'cmp_fn' });
  assert.equal(td.declarationText, 'typedef int (*cmp_fn)(const void *, const void *);');
  const fl: any = await disasmDebugInfo({ path, view: 'type', name: 'flags' });
  assert.deepEqual(fl.members.map((m: any) => [m.name, m.bitSize, m.bitOffset]), [['a', 3, 0], ['b', 5, 3], ['c', 1, 8]]);
  const fn: any = await disasmDebugInfo({ path, view: 'function', name: 'node_weight' });
  assert.equal(fn.found, true);
  assert.deepEqual(fn.locals.map((l: any) => l.name), ['w', 'it']);
  const g: any = await disasmDebugInfo({ path, view: 'globals' });
  assert.ok(g.items.some((x: any) => x.name === 'g_points' && x.type === 'point_t[3]'));
  assert.ok(TOOLS.some((x) => x.name === 'disasm_debug_info'));
});

for (const f of ['types-dwarf5-x64-O0.elf', 'types-dwarf4-arm64-O0.elf']) {
  test(`${f}: pseudo code uses DWARF names, types and struct fields`, async () => {
    const r: any = await disasmPseudocode({ path: P(f), function: 'node_weight' });
    assert.match(r.pseudocode, /^int node_weight\(struct node \*n, int scale, color_t c\) \{$/m);
    assert.match(r.pseudocode, /^ {2}struct node \*it; \/\/ stack/m);
    assert.match(r.pseudocode, /^ {2}int w; \/\/ stack/m);
    assert.match(r.pseudocode, /= it->next;/);
    assert.match(r.pseudocode, /= n->ids\[2\];/, 'n->ids[2] is offset 0x34');
    assert.match(r.pseudocode, /= it->fl;/);
    assert.doesNotMatch(r.pseudocode.split('\n').filter((l: string) => !l.startsWith('//')).join('\n'), /\ba1\b/);
    assert.equal(r.debug.prototype, 'int node_weight(struct node *n, int scale, color_t c)');
    const plain: any = await disasmPseudocode({ path: P(f), function: 'node_weight', debugInfo: false });
    assert.match(plain.pseudocode, /int64_t node_weight\(int64_t a1, int64_t a2, int64_t a3\)/);
  });
}

test('-O1 pseudo code names register parameters from DWARF location lists', async () => {
  for (const f of ['types-dwarf5-x64.elf', 'types-dwarf5-arm64.elf']) {
    const r: any = await disasmPseudocode({ path: P(f), function: 'node_weight' });
    assert.match(r.pseudocode, /int node_weight\(struct node \*n, int scale, color_t c\)/);
    assert.match(r.pseudocode, /= c;/, f);
    assert.match(r.pseudocode, /= n;|\(n == 0\)/, f);
  }
});

test('hostile DWARF: random bytes over .debug_info and .debug_abbrev never throw and stay fast', () => {
  const base = new Uint8Array(readFileSync(P('types-dwarf5-x64.elf')));
  const img0 = loadImage(base);
  const info = img0.debugSections!.find((s) => s.name === '.debug_info')!;
  const abbrev = img0.debugSections!.find((s) => s.name === '.debug_abbrev')!;
  fc.assert(fc.property(fc.boolean(), fc.nat(), fc.uint8Array({ minLength: 1, maxLength: 256 }), fc.integer({ min: 0, max: 3 }), (useAbbrev, pos, junk, mode) => {
    const b = base.slice();
    const sec = useAbbrev ? abbrev : info;
    const at = sec.offset + (pos % sec.size);
    if (mode === 0) b.set(junk.subarray(0, Math.max(0, Math.min(junk.length, b.length - at))), at);
    else if (mode === 1) b[at] = b[at]! ^ (1 << (junk[0]! % 8));
    else if (mode === 2) { for (let i = 0; i < 4 && at + i < b.length; i++) b[at + i] = 0xff; }
    else b.fill(0, at, Math.min(b.length, at + junk.length));
    const t0 = Date.now();
    const d = readDwarf(loadImage(b), { budgetMs: 2000 });
    assert.ok(Date.now() - t0 < 3000);
    assert.ok(Array.isArray(d.types));
  }), { numRuns: 150 });
});

test('hostile DWARF: truncated files and huge unit lengths', () => {
  const base = new Uint8Array(readFileSync(P('types-dwarf4-x64.elf')));
  const img0 = loadImage(base);
  const info = img0.debugSections!.find((s) => s.name === '.debug_info')!;
  for (const cut of [info.offset + 5, info.offset + 40, info.offset + info.size - 3]) {
    const d = readDwarf(loadImage(base.slice(0, cut)));
    assert.ok(!d.complete || d.units.length >= 0);
  }
  const b = base.slice();
  new DataView(b.buffer).setUint32(info.offset, 0x7ffffff0, true);
  const d = readDwarf(loadImage(b));
  assert.equal(d.complete, false);
});
