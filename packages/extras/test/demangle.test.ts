// Demanglers against reference tools: GNU c++filt 2.44 and llvm-cxxfilt 19 (Itanium),
// llvm-undname 19 (MSVC), rust-demangler (Rust legacy), llvm-cxxfilt (Rust v0 vectors from rustc-demangle).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { demangle, demangleItanium, demangleMsvc, demangleRustLegacy, demangleRustV0, manglingScheme, TOOLS } from '../src/node.js';
import { REF, S } from './helpers.js';
import { join } from 'node:path';

test('Itanium: every symbol of demo-x64.elf matches GNU c++filt exactly', () => {
  assert.ok(REF.itanium.length > 500);
  for (const x of REF.itanium) assert.equal(demangleItanium(x.mangled), x.gnu, x.mangled);
});

test('Itanium: matches llvm-cxxfilt on at least 99 percent once LLVM spelling is applied', () => {
  // GNU style differs from LLVM style only in spelling: "> >" versus ">>" and decltype(nullptr) versus std::nullptr_t, {lambda()#1} versus 'lambda'()
  const llvmStyle = (s: string) => s.replace(/> >/g, '>>').replace(/> >/g, '>>').replace(/decltype\(nullptr\)/g, 'std::nullptr_t')
    .replace(/\{lambda\(([^{}]*)\)#(\d+)\}/g, (_m, a: string, n: string) => `'lambda${n === '1' ? '' : Number(n) - 2}'(${a})`);
  // LLVM also prints the return type of a template function that encloses a local name; GNU does not.
  const diff = REF.itanium.filter((x: { mangled: string; llvm: string }) => llvmStyle(demangleItanium(x.mangled)!) !== x.llvm);
  assert.ok(diff.length <= REF.itanium.length / 100, `${diff.length} style differences: ${diff.slice(0, 3).map((d: { mangled: string }) => d.mangled).join(' ')}`);
});

test('Itanium: the fixture own functions', () => {
  const sum = REF.itanium.find((x: { gnu: string }) => x.gnu.startsWith('revlens::demo::sum('));
  assert.equal(sum.gnu, 'revlens::demo::sum(std::__1::vector<int, std::__1::allocator<int> > const&)');
  assert.equal(demangle(sum.mangled).output, sum.gnu);
});

test('MSVC: every ? symbol of demo-msvc.obj matches llvm-undname', () => {
  assert.ok(REF.msvc.length >= 10);
  for (const x of REF.msvc) assert.equal(demangleMsvc(x.mangled), x.undname, x.mangled);
  assert.equal(demangleMsvc('?scale@demo@revlens@@YANNM_J@Z'), 'double __cdecl revlens::demo::scale(double, float, __int64)');
});

test('Rust legacy: jiter symbols match rust-demangler', () => {
  assert.ok(REF.rust_legacy.length > 200);
  for (const x of REF.rust_legacy) assert.equal(demangleRustLegacy(x.mangled), x.demangled, x.mangled);
});

test('Rust v0: rustc-demangle test vectors match llvm-cxxfilt (suffix shown without parentheses)', () => {
  assert.ok(REF.rust_v0.length >= 5);
  for (const x of REF.rust_v0) assert.equal(demangleRustV0(x.mangled, false), x.llvm.replace(/ \(\.[^)]*\)$/, ''), x.mangled);
});

test('scheme detection', () => {
  assert.equal(manglingScheme('_ZN3foo3barEv'), 'itanium');
  assert.equal(manglingScheme('_RNvC6_123foo3bar'), 'rust-v0');
  assert.equal(manglingScheme('_ZN3foo3bar17h0123456789abcdefE'), 'rust-legacy');
  assert.equal(manglingScheme('?f@@YAXXZ'), 'msvc');
  assert.equal(manglingScheme('main'), 'none');
});

test('x_demangle tool demangles a binary symbol table with paging and filter', async () => {
  const t = TOOLS.find((x) => x.name === 'x_demangle')!;
  const r = await t.run({ path: join(S, 'demo-x64.elf'), filter: 'revlens::demo', limit: 50 }) as { total: number; items: { demangled: string; address: string }[] };
  assert.ok(r.total >= 2);
  assert.ok(r.items.some((i) => i.demangled.startsWith('revlens::demo::sum(')));
  assert.ok(r.items.every((i) => i.address.startsWith('0x')));
});
