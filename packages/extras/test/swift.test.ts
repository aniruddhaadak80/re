// Swift demangler against the real swift-demangle from the Swift 6.0.3 toolchain:
// samples/extras/swift/manglings-ref.json (470 vectors from swift's test/Demangle/Inputs/manglings.txt, old and new
// mangling, default and -simplified output) and samples/extras/swift/maccy-symbols-ref.json (every Swift symbol of the
// Maccy 2.8.0 Mach-O). Hostile inputs (deep nesting, huge counts, exponential substitutions, random strings) must end
// fast in text or null, never a throw.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import fc from 'fast-check';
import { demangle, demangleSwift, demangleSwiftTree, swiftDemangleCompat, manglingScheme, TOOLS, CLI_COMMANDS } from '../src/node.js';
import { S, CACHE } from './helpers.js';
import { existsSync } from 'node:fs';

interface Row { m: string; ref: string; simplified: string }
const VECTORS: Row[] = JSON.parse(readFileSync(join(S, 'swift', 'manglings-ref.json'), 'utf8'));
const MACCY: { items: Row[] } = JSON.parse(readFileSync(join(S, 'swift', 'maccy-symbols-ref.json'), 'utf8'));

// Measured pass counts. The test fails if a change makes any of them drop.
const MEASURED = { vectors: 470, vectorsSimplified: 470, maccy: 1947, maccySimplified: 1947 };

function score(rows: Row[], key: 'ref' | 'simplified'): { ok: number; bad: string[] } {
  let ok = 0; const bad: string[] = [];
  for (const r of rows) {
    const got = swiftDemangleCompat(r.m, { simplified: key === 'simplified' });
    if (got === r[key]) ok++; else bad.push(`${r.m}\n  want ${r[key]}\n  got  ${got}`);
  }
  return { ok, bad };
}

test('swift test vectors: default output matches swift-demangle 6.0.3 -compact', () => {
  assert.equal(VECTORS.length, 470);
  const { ok, bad } = score(VECTORS, 'ref');
  assert.ok(ok >= MEASURED.vectors, `${ok}/470 (measured ${MEASURED.vectors}):\n${bad.slice(0, 5).join('\n')}`);
  // Both manglings are in the set: old Swift 1 to 3 (_T but not _T0) and new.
  assert.ok(VECTORS.filter((r) => r.m.startsWith('_T') && !r.m.startsWith('_T0')).length > 200);
  assert.ok(VECTORS.filter((r) => /^(\$s|\$S|_T0|_\$s)/.test(r.m)).length > 150);
});

test('swift test vectors: simplified output matches swift-demangle -compact -simplified', () => {
  const { ok, bad } = score(VECTORS, 'simplified');
  assert.ok(ok >= MEASURED.vectorsSimplified, `${ok}/470:\n${bad.slice(0, 5).join('\n')}`);
});

test('Maccy 2.8.0: every Swift symbol of a real Mach-O matches swift-demangle, default and simplified', () => {
  assert.equal(MACCY.items.length, 1947);
  assert.ok(score(MACCY.items, 'ref').ok >= MEASURED.maccy);
  assert.ok(score(MACCY.items, 'simplified').ok >= MEASURED.maccySimplified);
  for (const r of MACCY.items) {
    const d = demangle(r.m);
    assert.equal(d.scheme, 'swift', r.m);
    assert.equal(d.output, r.ref, r.m);
  }
});

test('specific values', () => {
  assert.equal(demangleSwift('$s10AppIntents020CustomIntentMigratedaD0P15intentClassNameSSvgZTq'), 'method descriptor for static AppIntents.CustomIntentMigratedAppIntent.intentClassName.getter : Swift.String');
  assert.equal(demangleSwift('$s10AppIntents020CustomIntentMigratedaD0P15intentClassNameSSvgZTq', { simplified: true }), 'method descriptor for static CustomIntentMigratedAppIntent.intentClassName.getter');
  assert.equal(demangleSwift('_TtBf32_'), 'Builtin.FPIEEE32');
  assert.equal(demangleSwift('_TFC3foo3bar3basfT3zimCS_3zim_T_'), 'foo.bar.bas(zim: foo.zim) -> ()');
  assert.equal(demangleSwift('_TFC3foo3bar3basfT3zimCS_3zim_T_', { simplified: true }), 'bar.bas(zim:)');
  assert.equal(demangleSwift('$sSaySiGSgD', { simplified: true }), '[Int]?');
  assert.equal(demangleSwift('not a symbol'), null);
  assert.equal(swiftDemangleCompat('not a symbol'), 'not a symbol');
  const tree = demangleSwiftTree('$sSiD')!;
  assert.equal(tree.kind, 'Global');
});

test('scheme detection: Swift prefixes, Mach-O underscores, and C names that only look like old Swift', () => {
  assert.equal(manglingScheme('$sSiD'), 'swift');
  assert.equal(manglingScheme('_$s10AppIntents020CustomIntentMigratedaD0Mp'), 'swift');
  assert.equal(manglingScheme('$S3foo3barSiyF'), 'swift');
  assert.equal(manglingScheme('_T0s5print_9separator10terminatoryypfC'), 'swift');
  assert.equal(manglingScheme('_TFC3foo3bar3basfT3zimCS_3zim_T_'), 'swift');
  assert.equal(manglingScheme('__TFC3foo3bar3basfT3zimCS_3zim_T_'), 'swift');
  assert.equal(demangle('__TFC3foo3bar3basfT3zimCS_3zim_T_').output, 'foo.bar.bas(zim: foo.zim) -> ()');
  assert.equal(manglingScheme('_Test'), 'none');
  assert.equal(manglingScheme('_TIFFReadDirectory'), 'none');
  assert.equal(manglingScheme('main'), 'none');
  assert.equal(manglingScheme('_ZN3foo3barEv'), 'itanium');
});

test('x_swift_demangle tool: symbols with simplified form and node tree', async () => {
  const t = TOOLS.find((x) => x.name === 'x_swift_demangle')!;
  const r = await t.run({ symbols: ['$sSaySiGSgD', 'junk'], simplified: true, tree: true }) as { items: { input: string; output: string | null; tree?: { kind: string; children?: unknown[] } | null }[] };
  assert.equal(r.items[0]!.output, '[Int]?');
  assert.equal(r.items[0]!.tree!.kind, 'Global');
  assert.equal(r.items[1]!.output, null);
  assert.equal(r.items[1]!.tree, null);
  const x = TOOLS.find((y) => y.name === 'x_demangle')!;
  const d = await x.run({ symbols: ['$sSiD'] }) as { items: { scheme: string; output: string }[] };
  assert.deepEqual(d.items[0], { input: '$sSiD', scheme: 'swift', output: 'Swift.Int' });
});

const MACCY_BIN = join(CACHE, 'maccy-Maccy.macho');
test('x_swift_demangle on the real Maccy Mach-O lists every Swift symbol with addresses', { skip: !existsSync(MACCY_BIN) && 'run packages/extras/scripts/fetch-fixtures.mjs' }, async () => {
  const t = TOOLS.find((x) => x.name === 'x_swift_demangle')!;
  const r = await t.run({ path: MACCY_BIN, limit: 5000 }) as { total: number; items: { mangled: string; demangled: string; address: string }[] };
  assert.equal(r.total, 1947);
  const want = new Map(MACCY.items.map((i) => [i.m, i.ref]));
  for (const i of r.items) { assert.equal(i.demangled, want.get(i.mangled), i.mangled); assert.match(i.address, /^0x/); }
});

test('x-swift-demangle CLI prints text and JSON', async () => {
  const c = CLI_COMMANDS.find((x) => x.name === 'x-swift-demangle')!;
  const orig = console.log; let out = '';
  console.log = (...a: unknown[]) => { out += a.join(' ') + '\n'; };
  try {
    assert.equal(await c.run(['$sSaySiGSgD', '--simplified', '--json']), 0);
    assert.equal(JSON.parse(out).items[0].output, '[Int]?');
    out = '';
    assert.equal(await c.run(['_TtBf32_']), 0);
    assert.match(out, /Builtin\.FPIEEE32/);
  } finally { console.log = orig; }
});

function quick(s: string, budgetMs = 2000): string | null {
  const t0 = Date.now();
  const r = demangleSwift(s);
  demangleSwift(s, { simplified: true });
  demangle(s);
  assert.ok(Date.now() - t0 < budgetMs, `${JSON.stringify(s.slice(0, 60))} took ${Date.now() - t0} ms`);
  assert.ok(r === null || typeof r === 'string');
  return r;
}

test('hostile: deep nesting in both manglings ends fast in text or null', () => {
  for (const n of [10, 100, 1000, 5000, 20000]) {
    quick('$s' + 'Say'.repeat(n) + 'Si' + 'G'.repeat(n) + 'D');
    quick('_Tt' + 'GSq'.repeat(n) + 'Si' + '_'.repeat(n));
    quick('$s' + 'yyc'.repeat(n) + 'D');
    quick('$s' + 'Si_'.repeat(n) + 'tD');
    quick('$s1a1bV' + 'AC'.repeat(n) + 'D');
    quick('_TF' + 'C3foo'.repeat(n) + '3barfT_T_');
  }
  assert.equal(demangleSwift('$s' + 'Say'.repeat(20000) + 'Si' + 'G'.repeat(20000) + 'D'), null);
});

test('hostile: huge counts and lengths', () => {
  // A 25-digit generic parameter count wraps like the 64-bit C++ and prints the first 128 names, as swift-demangle does.
  assert.match(quick('_Ttu4222222222222222222222222_rW_2T_2TJ_')!, /^<A, B, C, .*, XE, \.\.\.> B\.T_\.TJ$/);
  quick('_Ttu' + '9'.repeat(3000) + '_rW_2T_2TJ_');
  assert.equal(quick('$s' + '9'.repeat(30) + 'aD'), null);
  assert.equal(quick('$s99999999999999999SiD'), null);
  quick('_TtBv' + '9'.repeat(40) + 'Bi32_');
  assert.equal(quick('$s' + 'a'.repeat(20000)), null);
});

test('hostile: substitutions that double the output are capped, not exponential', () => {
  const L = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let s = '$s1a1SVySiSiG';
  for (let k = 3; k < 26; k++) s += `ACyA2${L[k]}G`;
  quick(s + 'D', 3000);
});

test('hostile: random strings with Swift prefixes and mangling characters (fast-check)', () => {
  const alphabet = fc.constantFrom(...'0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$'.split(''));
  const prefix = fc.constantFrom('$s', '_$s', '$S', '_T0', '_T', '_Tt', '_TF', '_TTS', '@__swiftmacro_', '');
  fc.assert(fc.property(prefix, fc.array(alphabet, { maxLength: 300 }), (p, cs) => { quick(p + cs.join('')); }), { numRuns: 3000 });
});

test('hostile: random bytes as a symbol (fast-check)', () => {
  fc.assert(fc.property(fc.uint8Array({ maxLength: 512 }), fc.constantFrom('$s', '_T', ''), (b, p) => {
    quick(p + new TextDecoder().decode(b));
    quick(p + String.fromCharCode(...b));
  }), { numRuns: 1500 });
});

test('hostile: mutations of real vectors never throw', () => {
  fc.assert(fc.property(fc.integer({ min: 0, max: VECTORS.length - 1 }), fc.nat(), fc.constantFrom('', '0', '9', '_', 'S', 'A', 'G', 'y', 'T', '99999'), (i, pos, ins) => {
    const m = VECTORS[i]!.m;
    const p = pos % (m.length + 1);
    quick(m.slice(0, p) + ins + m.slice(p + 1));
    quick(m.slice(0, p));
  }), { numRuns: 3000 });
});
