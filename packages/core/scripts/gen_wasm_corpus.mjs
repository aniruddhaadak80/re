// Builds the WebAssembly validation corpus and records wabt's verdict for each module.
//  1. hand written WAT modules (valid and invalid), assembled with wabt's wat2wasm without validation
//  2. one probe module per SIMD and 0xFC opcode, typed from RevLens's own opcode table, which wabt
//     must accept: this checks the table against wabt instruction by instruction
//  3. seeded byte mutations of two valid modules
// wabt verdicts come from the wabt npm package (Apache-2.0, the WebAssembly binary toolkit compiled
// to wasm), the same validator as the wasm-validate command line tool.
// Run: WABT_NPM=/path/to/node_modules/wabt node packages/core/scripts/gen_wasm_corpus.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', '..', '..', 'samples', 'core', 'wasm');
mkdirSync(out, { recursive: true });
const require = createRequire(import.meta.url);
const wabt = await require(process.env.WABT_NPM ?? '/workspace/work/r4c-scratch/node_modules/wabt')();

const FEATURES = { mutable_globals: true, sat_float_to_int: true, sign_extension: true, simd: true, multi_value: true, bulk_memory: true, reference_types: true };
function assemble(name, wat) {
  let mod;
  try { mod = wabt.parseWat(`${name}.wat`, wat, FEATURES); } catch (e) { throw new Error(`${name}: ${String(e.message).slice(0, 400)}`); }
  mod.resolveNames();
  const { buffer } = mod.toBinary({ log: false, write_debug_names: false });
  mod.destroy();
  return new Uint8Array(buffer);
}
function verdict(bytes) {
  try {
    const m = wabt.readWasm(bytes, { readDebugNames: false, ...FEATURES });
    try { m.validate(); return { valid: true }; } catch (e) { return { valid: false, error: String(e.message).split('\n').filter(Boolean).slice(-1)[0]?.trim() }; } finally { m.destroy(); }
  } catch (e) { return { valid: false, error: String(e.message).split('\n').filter(Boolean).slice(-1)[0]?.trim(), read: true }; }
}

const CASES = {
  'ok-add': '(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))',
  'case-blocks': '(module (func (param i32) (result i32) (block (result i32) (loop (result i32) local.get 0 br_if 1 i32.const 2)) (if (result i32) (then i32.const 1) (else i32.const 3)) i32.add))',
  'ok-multivalue': '(module (type $t (func (param i32) (result i32 i32))) (func (param i32) (result i32 i32) local.get 0 (block (type $t) (param i32) (result i32 i32) local.get 0)))',
  'ok-memory': '(module (memory 1 2) (data (i32.const 8) "hi") (func (result i32) i32.const 0 i32.load offset=4 align=4 i32.const 0 i64.load8_u i32.wrap_i64 i32.add) (func i32.const 0 i32.const 0 i32.const 4 memory.copy))',
  'ok-bulk': '(module (memory 1) (data $d "abc") (func i32.const 0 i32.const 0 i32.const 3 memory.init $d data.drop $d))',
  'ok-reftypes': '(module (table 2 funcref) (table 1 externref) (elem declare func $f) (func $f (result funcref) ref.func $f) (func (param externref) i32.const 0 local.get 0 table.set 1) (func (result i32) ref.null func ref.is_null))',
  'ok-brtable': '(module (func (param i32) (result i32) (block (result i32) (block (result i32) i32.const 1 local.get 0 br_table 0 1 0) drop i32.const 2)))',
  'case-unreachable': '(module (func (result i32) unreachable i32.add) (func (result f64) (block (result f64) br 0 i32.eqz)))',
  'ok-select': '(module (func (param i32) (result f32) f32.const 1 f32.const 2 local.get 0 select) (func (result externref) ref.null extern ref.null extern i32.const 0 select (result externref)))',
  'ok-globals': '(module (import "env" "g" (global $g i32)) (global $h (mut i32) (global.get $g)) (func global.get $h i32.const 1 i32.add global.set $h) (export "h" (global $h)))',
  'ok-simd': '(module (memory 1) (func (param v128) (result i32) local.get 0 local.get 0 i32x4.add i8x16.extract_lane_u 15 i32.const 0 v128.load align=16 i32x4.all_true i32.add) (func (result v128) v128.const i32x4 1 2 3 4 v128.const i32x4 0 0 0 0 i8x16.shuffle 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 31))',
  'ok-sat-signext': '(module (func (param f32 i64) (result i64) local.get 0 i32.trunc_sat_f32_u i32.extend8_s drop local.get 1 i64.extend32_s))',
  'ok-start': '(module (func $s) (start $s))',
  'ok-callindirect': '(module (type $t (func (param i32) (result i32))) (table 1 funcref) (func (param i32) (result i32) local.get 0 i32.const 0 call_indirect (type $t)))',
  'bad-type-mismatch': '(module (func (result i32) i64.const 1))',
  'bad-stack-underflow': '(module (func (result i32) i32.add))',
  'bad-extra-value': '(module (func i32.const 1))',
  'bad-local-index': '(module (func local.get 3 drop))',
  'bad-global-index': '(module (func global.get 0 drop))',
  'bad-global-immutable': '(module (global i32 (i32.const 0)) (func i32.const 1 global.set 0))',
  'bad-br-depth': '(module (func br 2))',
  'bad-call-args': '(module (func $f (param i64)) (func i32.const 1 call $f))',
  'bad-call-index': '(module (func call 9))',
  'bad-if-no-else': '(module (func (result i32) i32.const 1 (if (result i32) (then i32.const 2))))',
  'bad-if-cond': '(module (func f32.const 1 (if (then))))',
  'bad-select-mismatch': '(module (func (result i32) i32.const 1 i64.const 2 i32.const 0 select))',
  'bad-select-ref': '(module (func (result funcref) ref.null func ref.null func i32.const 0 select))',
  'bad-no-memory': '(module (func (result i32) i32.const 0 i32.load))',
  'bad-alignment': '(module (memory 1) (func (result i32) i32.const 0 i32.load align=8))',
  'bad-dup-export': '(module (func) (export "a" (func 0)) (export "a" (func 0)))',
  'bad-export-index': '(module (export "a" (func 3)))',
  'bad-start-params': '(module (func $s (param i32)) (start $s))',
  'bad-two-memories': '(module (memory 1) (memory 1))',
  'bad-memory-limits': '(module (memory 2 1))',
  'bad-memory-too-big': '(module (memory 65537))',
  'bad-ref-func-undeclared': '(module (func $f (result funcref) ref.func $f))',
  'bad-memory-init-no-datacount': '(module (memory 1) (func i32.const 0 i32.const 0 i32.const 0 memory.init 0))',
  'case-simd-lanes': '(module (func (param v128) (result i32) local.get 0 i32x4.extract_lane 3 drop local.get 0 i8x16.extract_lane_s 15))',
  'bad-simd-type': '(module (func (param i32) (result v128) local.get 0 local.get 0 i32x4.add))',
  'bad-global-init': '(module (global i32 (i64.const 1)))',
  'bad-global-init-ref': '(module (global $a i32 (i32.const 1)) (global i32 (global.get $a)))',
  'bad-brtable-arity': '(module (func (param i32) (result i32) (block (result i32) (block i32.const 1 local.get 0 br_table 0 1)) ))',
  'bad-callindirect-notable': '(module (type $t (func)) (func i32.const 0 call_indirect (type $t)))',
  'bad-elem-func': '(module (table 1 funcref) (elem (i32.const 0) func 5))',
  'bad-data-memory': '(module (data (i32.const 0) "x"))',
  'bad-tableset-type': '(module (table 1 funcref) (func (param externref) i32.const 0 local.get 0 table.set 0))',
  'bad-return-type': '(module (func (result i32) f32.const 0 return))',
  'case-loop-label': '(module (func (result i32) (loop (result i32) i32.const 1 br 0)))',
};

const expected = {};
for (const [name, wat] of Object.entries(CASES)) {
  const bytes = assemble(name, wat);
  if (name.startsWith('ok-')) writeFileSync(join(out, `${name}.wasm`), bytes);
  expected[`${name}.wasm`] = { ...verdict(bytes), hex: Buffer.from(bytes).toString('hex') };
}

// Opcode probes: one function per opcode, operands typed from the RevLens table (kept in step with
// src/wasm/validate.ts by the test that loads this corpus).
const enc = (n) => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
const T = { i32: 0x7f, i64: 0x7e, f32: 0x7d, f64: 0x7c, v128: 0x7b };
const CONST = { i32: [0x41, 0], i64: [0x42, 0], f32: [0x43, 0, 0, 0, 0], f64: [0x44, 0, 0, 0, 0, 0, 0, 0, 0], v128: [0xfd, 12, ...new Array(16).fill(0)] };
function moduleWith(body, results) {
  const type = [0x60, 0, results.length, ...results.map((r) => T[r])];
  const sec = (id, b) => [id, ...enc(b.length), ...b];
  const code = [0, ...body, 0x0b];
  return new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...sec(1, [1, ...type]), ...sec(3, [1, 0]), ...sec(5, [1, 0, 1]), ...sec(10, [1, ...enc(code.length), ...code])]);
}
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const simdKinds = {};
const put = (ops, k) => { for (const o of ops) simdKinds[o] = k; };
put(range(0x00, 0x0a), 'load'); put([0x0b], 'store'); put([0x0d], 'shuffle'); put([0x0e], 'b');
put([0x0f, 0x10, 0x11], 'splat:i32'); put([0x12], 'splat:i64'); put([0x13], 'splat:f32'); put([0x14], 'splat:f64');
put([0x15, 0x16], 'extract:i32'); put([0x17], 'replace:i32'); put([0x18, 0x19], 'extract:i32'); put([0x1a], 'replace:i32'); put([0x1b], 'extract:i32'); put([0x1c], 'replace:i32');
put([0x1d], 'extract:i64'); put([0x1e], 'replace:i64'); put([0x1f], 'extract:f32'); put([0x20], 'replace:f32'); put([0x21], 'extract:f64'); put([0x22], 'replace:f64');
put(range(0x23, 0x4c), 'b'); put([0x4d], 'u'); put(range(0x4e, 0x51), 'b'); put([0x52], 't'); put([0x53], 'r'); put(range(0x54, 0x57), 'loadlane'); put(range(0x58, 0x5b), 'storelane'); put([0x5c, 0x5d], 'load');
put([0x5e, 0x5f, 0x60, 0x61, 0x62], 'u'); put([0x63, 0x64], 'r'); put([0x65, 0x66], 'b'); put(range(0x67, 0x6a), 'u'); put(range(0x6b, 0x6d), 's'); put(range(0x6e, 0x73), 'b'); put([0x74, 0x75], 'u'); put(range(0x76, 0x79), 'b'); put([0x7a], 'u'); put([0x7b], 'b');
put(range(0x7c, 0x7f), 'u'); put([0x80, 0x81], 'u'); put([0x82], 'b'); put([0x83, 0x84], 'r'); put([0x85, 0x86], 'b'); put(range(0x87, 0x8a), 'u'); put(range(0x8b, 0x8d), 's'); put(range(0x8e, 0x93), 'b'); put([0x94], 'u'); put(range(0x95, 0x99), 'b'); put([0x9b], 'b'); put(range(0x9c, 0x9f), 'b');
put([0xa0, 0xa1], 'u'); put([0xa3, 0xa4], 'r'); put(range(0xa7, 0xaa), 'u'); put(range(0xab, 0xad), 's'); put([0xae, 0xb1], 'b'); put(range(0xb5, 0xba), 'b'); put(range(0xbc, 0xbf), 'b');
put([0xc0, 0xc1], 'u'); put([0xc3, 0xc4], 'r'); put(range(0xc7, 0xca), 'u'); put(range(0xcb, 0xcd), 's'); put([0xce, 0xd1], 'b'); put(range(0xd5, 0xdf), 'b');
put([0xe0, 0xe1, 0xe3], 'u'); put(range(0xe4, 0xeb), 'b'); put([0xec, 0xed, 0xef], 'u'); put(range(0xf0, 0xf7), 'b'); put(range(0xf8, 0xff), 'u');
const probes = {};
for (let op = 0; op <= 0xff; op++) {
  const k = simdKinds[op];
  const pre = [0xfd, ...enc(op)];
  let body, res = [];
  const v = CONST.v128, i = CONST.i32;
  if (!k) { body = [...pre]; res = []; }
  else if (k === 'load') { body = [...i, ...pre, 0, 0]; res = ['v128']; }
  else if (k === 'store') { body = [...i, ...v, ...pre, 0, 0]; }
  else if (k === 'loadlane') { body = [...i, ...v, ...pre, 0, 0, 0]; res = ['v128']; }
  else if (k === 'storelane') { body = [...i, ...v, ...pre, 0, 0, 0]; }
  else if (k === 'shuffle') { body = [...v, ...v, ...pre, ...new Array(16).fill(0)]; res = ['v128']; }
  else if (k === 'u') { body = [...v, ...pre]; res = ['v128']; }
  else if (k === 'b') { body = [...v, ...v, ...pre]; res = ['v128']; }
  else if (k === 't') { body = [...v, ...v, ...v, ...pre]; res = ['v128']; }
  else if (k === 's') { body = [...v, ...i, ...pre]; res = ['v128']; }
  else if (k === 'r') { body = [...v, ...pre]; res = ['i32']; }
  else if (k.startsWith('splat:')) { body = [...CONST[k.slice(6)], ...pre]; res = ['v128']; }
  else if (k.startsWith('extract:')) { body = [...v, ...pre, 0]; res = [k.slice(8)]; }
  else if (k.startsWith('replace:')) { body = [...v, ...CONST[k.slice(8)], ...pre, 0]; res = ['v128']; }
  const bytes = moduleWith(body, res);
  const name = `probe-simd-${op.toString(16).padStart(2, '0')}.wasm`;
  const vv = verdict(bytes);
  probes[name] = { ...vv, kind: k ?? 'undefined', hex: Buffer.from(bytes).toString('hex') };
  if (!!k !== vv.valid) console.log('table disagrees with wabt at SIMD opcode', op.toString(16), k, vv.error);
}

// Seeded mutations of two valid modules.
let seed = 1234567;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
const mutations = {};
for (const base of ['ok-memory', 'ok-simd', 'ok-brtable', 'ok-reftypes']) {
  const src = assemble(base, CASES[base]);
  for (let n = 0; n < 40; n++) {
    const b = src.slice();
    const flips = 1 + (rnd() % 3);
    for (let k = 0; k < flips; k++) { const pos = 8 + (rnd() % (b.length - 8)); b[pos] = rnd() & 0xff; }
    const name = `mut-${base}-${n}.wasm`;
    mutations[name] = { ...verdict(b), hex: Buffer.from(b).toString('hex') };
  }
}
writeFileSync(join(out, 'corpus.json'), JSON.stringify({ generator: 'packages/core/scripts/gen_wasm_corpus.mjs', wabt: 'wabt npm 1.0.37 (readWasm + validate, wasm-validate default features)', cases: expected, probes, mutations }, null, 1));
console.log('cases', Object.keys(expected).length, 'probes', Object.keys(probes).length, 'mutations', Object.keys(mutations).length);
console.log('valid cases', Object.entries(expected).filter(([, v]) => v.valid).map(([k]) => k).join(' '));
