// WebAssembly validation: module level rules and a full type check of every function body with the
// operand and control stacks of the specification's validation algorithm. Feature set matches the
// default of wabt's wasm-validate: MVP plus mutable globals, saturating float to int, sign extension,
// multi-value, bulk memory, reference types and fixed width SIMD.

import { readWasmModule, WasmReader, WasmError, funcTypeOf, globalTypeOf, tableTypeOf, memoryCount, tableCount, funcCount, globalCount, type ValType, type FuncType, type WasmModule, type ConstExpr } from './module.js';

export interface WasmValidation {
  valid: boolean;
  /** first error, as offset and reason */
  error?: { offset: number; message: string; functionIndex?: number };
  stage: 'read' | 'module' | 'code' | 'ok';
  module?: WasmModule;
  functionsChecked: number;
  instructions: number;
}

type T = ValType | 'unknown';
const isNum = (t: T): boolean => t === 'i32' || t === 'i64' || t === 'f32' || t === 'f64' || t === 'v128' || t === 'unknown';
const isRef = (t: T): boolean => t === 'funcref' || t === 'externref' || t === 'unknown';

class V extends Error { constructor(msg: string, readonly offset: number) { super(msg); } }

interface Frame { op: number; start: ValType[]; end: ValType[]; height: number; unreachable: boolean }

// opcode -> [params, results] for plain numeric instructions
const SIMPLE: Record<number, [ValType[], ValType[]]> = {};
const def = (ops: number[], p: ValType[], r: ValType[]): void => { for (const o of ops) SIMPLE[o] = [p, r]; };
const range = (a: number, b: number): number[] => { const o: number[] = []; for (let i = a; i <= b; i++) o.push(i); return o; };
def([0x45], ['i32'], ['i32']); def(range(0x46, 0x4f), ['i32', 'i32'], ['i32']);
def([0x50], ['i64'], ['i32']); def(range(0x51, 0x5a), ['i64', 'i64'], ['i32']);
def(range(0x5b, 0x60), ['f32', 'f32'], ['i32']); def(range(0x61, 0x66), ['f64', 'f64'], ['i32']);
def(range(0x67, 0x69), ['i32'], ['i32']); def(range(0x6a, 0x78), ['i32', 'i32'], ['i32']);
def(range(0x79, 0x7b), ['i64'], ['i64']); def(range(0x7c, 0x8a), ['i64', 'i64'], ['i64']);
def(range(0x8b, 0x91), ['f32'], ['f32']); def(range(0x92, 0x98), ['f32', 'f32'], ['f32']);
def(range(0x99, 0x9f), ['f64'], ['f64']); def(range(0xa0, 0xa6), ['f64', 'f64'], ['f64']);
def([0xa7], ['i64'], ['i32']); def([0xa8, 0xa9], ['f32'], ['i32']); def([0xaa, 0xab], ['f64'], ['i32']);
def([0xac, 0xad], ['i32'], ['i64']); def([0xae, 0xaf], ['f32'], ['i64']); def([0xb0, 0xb1], ['f64'], ['i64']);
def([0xb2, 0xb3], ['i32'], ['f32']); def([0xb4, 0xb5], ['i64'], ['f32']); def([0xb6], ['f64'], ['f32']);
def([0xb7, 0xb8], ['i32'], ['f64']); def([0xb9, 0xba], ['i64'], ['f64']); def([0xbb], ['f32'], ['f64']);
def([0xbc], ['f32'], ['i32']); def([0xbd], ['f64'], ['i64']); def([0xbe], ['i32'], ['f32']); def([0xbf], ['i64'], ['f64']);
def([0xc0, 0xc1], ['i32'], ['i32']); def([0xc2, 0xc3, 0xc4], ['i64'], ['i64']);

// loads and stores: opcode -> [value type, natural alignment log2]
const LOADS: Record<number, [ValType, number]> = { 0x28: ['i32', 2], 0x29: ['i64', 3], 0x2a: ['f32', 2], 0x2b: ['f64', 3], 0x2c: ['i32', 0], 0x2d: ['i32', 0], 0x2e: ['i32', 1], 0x2f: ['i32', 1], 0x30: ['i64', 0], 0x31: ['i64', 0], 0x32: ['i64', 1], 0x33: ['i64', 1], 0x34: ['i64', 2], 0x35: ['i64', 2] };
const STORES: Record<number, [ValType, number]> = { 0x36: ['i32', 2], 0x37: ['i64', 3], 0x38: ['f32', 2], 0x39: ['f64', 3], 0x3a: ['i32', 0], 0x3b: ['i32', 1], 0x3c: ['i64', 0], 0x3d: ['i64', 1], 0x3e: ['i64', 2] };
const SAT: [ValType, ValType][] = [['f32', 'i32'], ['f32', 'i32'], ['f64', 'i32'], ['f64', 'i32'], ['f32', 'i64'], ['f32', 'i64'], ['f64', 'i64'], ['f64', 'i64']];

// SIMD (0xFD prefix). kind: u unary v128->v128, b binary, t ternary, s shift [v128 i32]->v128,
// c compare (binary), r v128->i32 reduction, plus special entries handled in code.
const SIMD: Record<number, string> = {};
const simd = (ops: number[], kind: string): void => { for (const o of ops) SIMD[o] = kind; };
simd(range(0x00, 0x0a), 'load'); simd([0x0b], 'store'); simd([0x0c], 'const'); simd([0x0d], 'shuffle'); simd([0x0e], 'b');
simd([0x0f, 0x10, 0x11], 'splat:i32'); simd([0x12], 'splat:i64'); simd([0x13], 'splat:f32'); simd([0x14], 'splat:f64');
simd([0x15, 0x16], 'extract:i32:16'); simd([0x17], 'replace:i32:16'); simd([0x18, 0x19], 'extract:i32:8'); simd([0x1a], 'replace:i32:8');
simd([0x1b], 'extract:i32:4'); simd([0x1c], 'replace:i32:4'); simd([0x1d], 'extract:i64:2'); simd([0x1e], 'replace:i64:2');
simd([0x1f], 'extract:f32:4'); simd([0x20], 'replace:f32:4'); simd([0x21], 'extract:f64:2'); simd([0x22], 'replace:f64:2');
simd(range(0x23, 0x4c), 'b'); simd([0x4d], 'u'); simd(range(0x4e, 0x51), 'b'); simd([0x52], 't'); simd([0x53], 'r');
simd(range(0x54, 0x57), 'loadlane'); simd(range(0x58, 0x5b), 'storelane'); simd([0x5c, 0x5d], 'load');
simd([0x5e, 0x5f], 'u'); simd([0x60, 0x61, 0x62], 'u'); simd([0x63, 0x64], 'r'); simd([0x65, 0x66], 'b'); simd(range(0x67, 0x6a), 'u');
simd(range(0x6b, 0x6d), 's'); simd(range(0x6e, 0x73), 'b'); simd([0x74, 0x75], 'u'); simd(range(0x76, 0x79), 'b'); simd([0x7a], 'u'); simd([0x7b], 'b');
simd(range(0x7c, 0x7f), 'u'); simd([0x80, 0x81], 'u'); simd([0x82], 'b'); simd([0x83, 0x84], 'r'); simd([0x85, 0x86], 'b'); simd(range(0x87, 0x8a), 'u');
simd(range(0x8b, 0x8d), 's'); simd(range(0x8e, 0x93), 'b'); simd([0x94], 'u'); simd(range(0x95, 0x99), 'b'); simd([0x9b], 'b'); simd(range(0x9c, 0x9f), 'b');
simd([0xa0, 0xa1], 'u'); simd([0xa3, 0xa4], 'r'); simd(range(0xa7, 0xaa), 'u'); simd(range(0xab, 0xad), 's'); simd([0xae, 0xb1], 'b'); simd(range(0xb5, 0xba), 'b'); simd(range(0xbc, 0xbf), 'b');
simd([0xc0, 0xc1], 'u'); simd([0xc3, 0xc4], 'r'); simd(range(0xc7, 0xca), 'u'); simd(range(0xcb, 0xcd), 's'); simd([0xce, 0xd1], 'b'); simd(range(0xd5, 0xdf), 'b');
simd([0xe0, 0xe1, 0xe3], 'u'); simd(range(0xe4, 0xeb), 'b'); simd([0xec, 0xed, 0xef], 'u'); simd(range(0xf0, 0xf7), 'b'); simd(range(0xf8, 0xff), 'u');
/** natural alignment log2 of SIMD memory instructions */
const SIMD_ALIGN: Record<number, number> = { 0x00: 4, 0x01: 3, 0x02: 3, 0x03: 3, 0x04: 3, 0x05: 3, 0x06: 3, 0x07: 0, 0x08: 1, 0x09: 2, 0x0a: 3, 0x0b: 4, 0x5c: 2, 0x5d: 3, 0x54: 0, 0x55: 1, 0x56: 2, 0x57: 3, 0x58: 0, 0x59: 1, 0x5a: 2, 0x5b: 3 };
const LANE_COUNT: Record<number, number> = { 0x54: 16, 0x55: 8, 0x56: 4, 0x57: 2, 0x58: 16, 0x59: 8, 0x5a: 4, 0x5b: 2 };

export interface ValidateOptions { maxFunctions?: number; maxInstructions?: number; simd?: boolean }

function checkConst(m: WasmModule, bytes: Uint8Array, e: ConstExpr, want: ValType, refs: Set<number>): void {
  const r = new WasmReader(bytes, e.start, e.end);
  const stack: ValType[] = [];
  while (!r.eof()) {
    const at = r.pos;
    const op = r.u8();
    if (op === 0x0b) break;
    if (op === 0x41) { r.sleb(32); stack.push('i32'); }
    else if (op === 0x42) { r.sleb(64); stack.push('i64'); }
    else if (op === 0x43) { r.bytes(4); stack.push('f32'); }
    else if (op === 0x44) { r.bytes(8); stack.push('f64'); }
    else if (op === 0xfd) { r.u32(); r.bytes(16); stack.push('v128'); }
    else if (op === 0xd0) stack.push(r.reftype());
    else if (op === 0xd2) { const f = r.u32(); if (f >= funcCount(m)) throw new V(`invalid function index ${f} in constant expression`, at); refs.add(f); stack.push('funcref'); }
    else if (op === 0x23) {
      const g = r.u32();
      if (g >= m.importCounts.global) throw new V('initializer expression can only reference an imported global', at);
      const gt = globalTypeOf(m, g);
      if (!gt) throw new V(`invalid global index ${g}`, at);
      if (gt.mutable) throw new V('initializer expression cannot reference a mutable global', at);
      stack.push(gt.type);
    } else throw new V(`invalid instruction in constant expression: 0x${op.toString(16)}`, at);
  }
  if (stack.length !== 1 || stack[0] !== want) throw new V(`type mismatch in constant expression, expected [${want}] but got [${stack.join(', ')}]`, e.start);
}

function validateModule(m: WasmModule, bytes: Uint8Array, refs: Set<number>): void {
  for (const imp of m.imports) {
    if (imp.desc.kind === 'func' && !m.types[imp.desc.type]) throw new V(`invalid import function type index ${imp.desc.type}`, imp.offset);
    if (imp.desc.kind === 'tag') throw new V('tags are not enabled', imp.offset);
    if (imp.desc.kind === 'memory') checkMemLimits(imp.desc.memory, imp.offset);
    if (imp.desc.kind === 'table') checkLimits(imp.desc.table.limits, 0xffffffff, imp.offset);
  }
  for (let i = 0; i < m.functions.length; i++) if (!m.types[m.functions[i] as number]) throw new V(`invalid function type index ${m.functions[i]}`, m.sections.find((s) => s.id === 3)?.offset ?? 0);
  for (const t of m.tables) checkLimits(t.limits, 0xffffffff, m.sections.find((s) => s.id === 4)?.offset ?? 0);
  if (memoryCount(m) > 1) throw new V('only one memory block allowed', m.sections.find((s) => s.id === 5)?.offset ?? 0);
  for (const mm of m.memories) checkMemLimits(mm, m.sections.find((s) => s.id === 5)?.offset ?? 0);
  for (const g of m.globals) checkConst(m, bytes, g.init, g.type.type, refs);
  const names = new Set<string>();
  for (const e of m.exports) {
    if (names.has(e.name)) throw new V(`duplicate export "${e.name}"`, e.offset);
    names.add(e.name);
    const ok = e.kind === 'func' ? e.index < funcCount(m) : e.kind === 'table' ? e.index < tableCount(m) : e.kind === 'memory' ? e.index < memoryCount(m) : e.kind === 'global' ? e.index < globalCount(m) : false;
    if (!ok) throw new V(`invalid export ${e.kind} index ${e.index}`, e.offset);
    if (e.kind === 'func') refs.add(e.index);
  }
  if (m.start !== undefined) {
    const t = funcTypeOf(m, m.start);
    const at = m.sections.find((s) => s.id === 8)?.offset ?? 0;
    if (!t) throw new V(`invalid start function index ${m.start}`, at);
    if (t.params.length || t.results.length) throw new V('start function must not have parameters or results', at);
  }
  for (const e of m.elements) {
    if (e.mode === 'active') {
      const tt = tableTypeOf(m, e.table);
      if (!tt) throw new V(`invalid table index ${e.table} in element segment`, e.at);
      if (e.offset) checkConst(m, bytes, e.offset, 'i32', refs);
      if (tt.elem !== e.type) throw new V(`type mismatch in element segment, expected ${tt.elem} but got ${e.type}`, e.at);
    }
    for (const f of e.funcs ?? []) { if (f >= funcCount(m)) throw new V(`invalid function index ${f} in element segment`, e.at); refs.add(f); }
    for (const x of e.exprs ?? []) checkConst(m, bytes, x, e.type, refs);
  }
  for (const d of m.datas) {
    if (d.mode === 'active') {
      if (d.memory >= memoryCount(m)) throw new V(`invalid memory index ${d.memory} in data segment`, d.at);
      if (d.offset) checkConst(m, bytes, d.offset, 'i32', refs);
    }
  }
}

function checkLimits(l: { min: number; max?: number }, cap: number, at: number): void {
  if (l.min > cap) throw new V(`initial size ${l.min} is too large`, at);
  if (l.max !== undefined && (l.max > cap || l.max < l.min)) throw new V(l.max < l.min ? 'max size must be greater than or equal to initial size' : `max size ${l.max} is too large`, at);
}
function checkMemLimits(l: { min: number; max?: number; shared?: boolean; is64?: boolean }, at: number): void {
  if (l.is64) throw new V('memory64 is not enabled', at);
  if (l.shared) throw new V('memory may not be shared: threads not allowed', at);
  checkLimits(l, 65536, at);
}

/** Validate one function body. */
function validateFunction(m: WasmModule, bytes: Uint8Array, fi: number, refs: Set<number>, budget: { n: number }, opts: ValidateOptions): void {
  const code = m.codes[fi]!;
  const ft = m.types[m.functions[fi] as number] as FuncType;
  const locals: ValType[] = [...ft.params];
  for (const g of code.locals) for (let k = 0; k < g.count; k++) locals.push(g.type);
  const r = new WasmReader(bytes, code.bodyStart, code.bodyEnd);
  const vals: T[] = [];
  const ctrls: Frame[] = [];
  let at = r.pos;
  const err = (msg: string): never => { throw new V(msg, at); };
  const push = (t: T): void => { vals.push(t); };
  const pop = (): T => {
    const f = ctrls[ctrls.length - 1] as Frame;
    if (vals.length === f.height) { if (f.unreachable) return 'unknown'; return err('type mismatch: not enough values on the stack'); }
    return vals.pop() as T;
  };
  const popT = (want: T): T => {
    const got = pop();
    if (got !== want && got !== 'unknown' && want !== 'unknown') err(`type mismatch: expected ${want} but got ${got}`);
    return got === 'unknown' ? want : got;
  };
  const popAll = (ts: ValType[]): void => { for (let i = ts.length - 1; i >= 0; i--) popT(ts[i] as ValType); };
  const pushAll = (ts: ValType[]): void => { for (const t of ts) push(t); };
  const labelTypes = (f: Frame): ValType[] => (f.op === 0x03 ? f.start : f.end);
  const pushCtrl = (op: number, start: ValType[], end: ValType[]): void => { ctrls.push({ op, start, end, height: vals.length, unreachable: false }); pushAll(start); };
  const popCtrl = (): Frame => {
    const f = ctrls[ctrls.length - 1];
    if (!f) return err('unexpected end');
    popAll(f.end);
    if (vals.length !== f.height) err(`type mismatch: ${vals.length - f.height} extra values on the stack at the end of the block`);
    ctrls.pop();
    return f;
  };
  const unreachable = (): void => { const f = ctrls[ctrls.length - 1] as Frame; vals.length = f.height; f.unreachable = true; };
  const label = (): Frame => { const l = r.u32(); const f = ctrls[ctrls.length - 1 - l]; if (!f) err(`invalid depth: ${l} (max ${ctrls.length - 1})`); return f as Frame; };
  const blockType = (): FuncType => {
    const bat = r.pos;
    const b = r.b[r.pos] as number;
    if (b === 0x40) { r.pos++; return { params: [], results: [] }; }
    if (b === 0x7f || b === 0x7e || b === 0x7d || b === 0x7c || b === 0x7b || b === 0x70 || b === 0x6f) return { params: [], results: [r.valtype()] };
    const idx = r.sleb(33);
    if (idx < 0) throw new WasmError('invalid block type', bat);
    const t = m.types[idx];
    if (!t) { at = bat; return err(`invalid block type index ${idx}`); }
    return t;
  };
  const memarg = (natural: number): void => {
    const aat = r.pos;
    const align = r.u32();
    r.u32();
    if (memoryCount(m) === 0) { at = aat; err('memory instruction requires a memory'); }
    if (align > natural) { at = aat; err(`alignment must not be larger than natural alignment (${2 ** natural})`); }
  };
  const needMem = (): void => { if (memoryCount(m) === 0) err('memory instruction requires a memory'); };
  const zeroByte = (): void => { const z = r.u8(); if (z !== 0) throw new WasmError('memory index must be zero', r.pos - 1); };
  const tableOf = (idx: number): ValType => { const t = tableTypeOf(m, idx); if (!t) return err(`invalid table index ${idx}`); return t.elem; };
  ctrls.push({ op: 0x02, start: [], end: ft.results, height: 0, unreachable: false });
  while (ctrls.length) {
    if (r.eof()) { at = r.pos; err('function body must end with an end opcode'); }
    if (++budget.n > (opts.maxInstructions ?? 50_000_000)) err('instruction budget used up');
    at = r.pos;
    const op = r.u8();
    const simple = SIMPLE[op];
    if (simple) { popAll(simple[0]); pushAll(simple[1]); continue; }
    const ld = LOADS[op];
    if (ld) { memarg(ld[1]); popT('i32'); push(ld[0]); continue; }
    const st = STORES[op];
    if (st) { memarg(st[1]); popT(st[0]); popT('i32'); continue; }
    switch (op) {
      case 0x00: unreachable(); break;
      case 0x01: break;
      case 0x02: case 0x03: { const bt = blockType(); popAll(bt.params); pushCtrl(op, bt.params, bt.results); break; }
      case 0x04: { const bt = blockType(); popT('i32'); popAll(bt.params); pushCtrl(op, bt.params, bt.results); break; }
      case 0x05: { const f = popCtrl(); if (f.op !== 0x04) err('else without matching if'); pushCtrl(0x05, f.start, f.end); break; }
      case 0x0b: {
        const f = popCtrl();
        if (f.op === 0x04 && (f.start.length !== f.end.length || f.start.some((t, i) => t !== f.end[i]))) err(`type mismatch: if without else must have matching param and result types`);
        pushAll(f.end);
        break;
      }
      case 0x0c: { const f = label(); popAll(labelTypes(f)); unreachable(); break; }
      case 0x0d: { const f = label(); popT('i32'); const lt = labelTypes(f); popAll(lt); pushAll(lt); break; }
      case 0x0e: {
        const n = r.u32();
        if (n > code.bodyEnd - r.pos) throw new WasmError('br_table target count is too large', at);
        const targets: Frame[] = [];
        for (let i = 0; i < n; i++) targets.push(label());
        const dflt = label();
        popT('i32');
        const arity = labelTypes(dflt).length;
        for (const t of targets) {
          const lt = labelTypes(t);
          if (lt.length !== arity) err('br_table labels have inconsistent types');
          // check the stack against each label without consuming it
          const saved = vals.slice();
          popAll(lt);
          vals.length = 0; vals.push(...saved);
        }
        popAll(labelTypes(dflt));
        unreachable();
        break;
      }
      case 0x0f: popAll(ft.results); unreachable(); break;
      case 0x10: { const f = r.u32(); const t = funcTypeOf(m, f); if (!t) err(`invalid call function index ${f}`); popAll(t!.params); pushAll(t!.results); break; }
      case 0x11: {
        const ti = r.u32(); const tab = r.u32();
        if (tableCount(m) === 0) err('call_indirect requires a table');
        if (tableOf(tab) !== 'funcref') err('type mismatch: call_indirect must reference table of funcref type');
        const t = m.types[ti]; if (!t) err(`invalid call_indirect type index ${ti}`);
        popT('i32'); popAll(t!.params); pushAll(t!.results); break;
      }
      case 0x1a: pop(); break;
      case 0x1b: {
        popT('i32');
        const t1 = pop(), t2 = pop();
        if (!isNum(t1) || !isNum(t2)) err('type mismatch: select without a type immediate needs numeric operands');
        if (t1 !== t2 && t1 !== 'unknown' && t2 !== 'unknown') err(`type mismatch in select: ${t1} and ${t2}`);
        push(t1 === 'unknown' ? t2 : t1);
        break;
      }
      case 0x1c: {
        const n = r.u32();
        if (n !== 1) throw new WasmError('invalid select arity', at);
        const t = r.valtype();
        popT('i32'); popT(t); popT(t); push(t);
        break;
      }
      case 0x20: { const i = r.u32(); const t = locals[i]; if (!t) err(`invalid local index ${i}`); push(t!); break; }
      case 0x21: { const i = r.u32(); const t = locals[i]; if (!t) err(`invalid local index ${i}`); popT(t!); break; }
      case 0x22: { const i = r.u32(); const t = locals[i]; if (!t) err(`invalid local index ${i}`); popT(t!); push(t!); break; }
      case 0x23: { const g = r.u32(); const t = globalTypeOf(m, g); if (!t) err(`invalid global index ${g}`); push(t!.type); break; }
      case 0x24: { const g = r.u32(); const t = globalTypeOf(m, g); if (!t) err(`invalid global index ${g}`); if (!t!.mutable) err(`can't global.set on immutable global ${g}`); popT(t!.type); break; }
      case 0x25: { const t = tableOf(r.u32()); popT('i32'); push(t); break; }
      case 0x26: { const t = tableOf(r.u32()); popT(t); popT('i32'); break; }
      case 0x3f: zeroByte(); needMem(); push('i32'); break;
      case 0x40: zeroByte(); needMem(); popT('i32'); push('i32'); break;
      case 0x41: r.sleb(32); push('i32'); break;
      case 0x42: r.sleb(64); push('i64'); break;
      case 0x43: r.bytes(4); push('f32'); break;
      case 0x44: r.bytes(8); push('f64'); break;
      case 0xd0: push(r.reftype()); break;
      case 0xd1: { const t = pop(); if (!isRef(t)) err(`type mismatch: ref.is_null expects a reference, got ${t}`); push('i32'); break; }
      case 0xd2: { const f = r.u32(); if (f >= funcCount(m)) err(`invalid function index ${f}`); if (!refs.has(f)) err(`function ${f} is not declared in any elem sections`); push('funcref'); break; }
      case 0xfc: {
        const sub = r.u32();
        if (sub <= 7) { const [p, res] = SAT[sub] as [ValType, ValType]; popT(p); push(res); break; }
        switch (sub) {
          case 8: { const d = r.u32(); zeroByte(); needMem(); if (m.dataCount === undefined) err('memory.init requires data count section'); if (d >= (m.dataCount ?? 0)) err(`invalid data segment index ${d}`); popAll(['i32', 'i32', 'i32']); break; }
          case 9: { const d = r.u32(); if (m.dataCount === undefined) err('data.drop requires data count section'); if (d >= (m.dataCount ?? 0)) err(`invalid data segment index ${d}`); break; }
          case 10: zeroByte(); zeroByte(); needMem(); popAll(['i32', 'i32', 'i32']); break;
          case 11: zeroByte(); needMem(); popAll(['i32', 'i32', 'i32']); break;
          case 12: { const e = r.u32(); const t = tableOf(r.u32()); const seg = m.elements[e]; if (!seg) err(`invalid elem segment index ${e}`); if (seg!.type !== t) err('type mismatch in table.init'); popAll(['i32', 'i32', 'i32']); break; }
          case 13: { const e = r.u32(); if (!m.elements[e]) err(`invalid elem segment index ${e}`); break; }
          case 14: { const d = tableOf(r.u32()); const s = tableOf(r.u32()); if (d !== s) err('type mismatch in table.copy'); popAll(['i32', 'i32', 'i32']); break; }
          case 15: { const t = tableOf(r.u32()); popT('i32'); popT(t); push('i32'); break; }
          case 16: { tableOf(r.u32()); push('i32'); break; }
          case 17: { const t = tableOf(r.u32()); popT('i32'); popT(t); popT('i32'); break; }
          default: throw new WasmError(`unexpected opcode: 0xfc 0x${sub.toString(16)}`, at);
        }
        break;
      }
      case 0xfd: {
        if (opts.simd === false) err('SIMD is not enabled');
        const sub = r.u32();
        const kind = SIMD[sub];
        if (!kind) throw new WasmError(`unexpected opcode: 0xfd 0x${sub.toString(16)}`, at);
        if (kind === 'load') { memarg(SIMD_ALIGN[sub] as number); popT('i32'); push('v128'); }
        else if (kind === 'store') { memarg(4); popT('v128'); popT('i32'); }
        else if (kind === 'loadlane' || kind === 'storelane') {
          memarg(SIMD_ALIGN[sub] as number);
          const lane = r.u8();
          if (lane >= (LANE_COUNT[sub] as number)) err(`lane index must be less than ${LANE_COUNT[sub]}`);
          popT('v128'); popT('i32');
          if (kind === 'loadlane') push('v128');
        } else if (kind === 'const') { r.bytes(16); push('v128'); }
        else if (kind === 'shuffle') { const lanes = r.bytes(16); for (const l of lanes) if (l >= 32) err('shuffle lane index must be less than 32'); popT('v128'); popT('v128'); push('v128'); }
        else if (kind === 'u') { popT('v128'); push('v128'); }
        else if (kind === 'b') { popT('v128'); popT('v128'); push('v128'); }
        else if (kind === 't') { popT('v128'); popT('v128'); popT('v128'); push('v128'); }
        else if (kind === 's') { popT('i32'); popT('v128'); push('v128'); }
        else if (kind === 'r') { popT('v128'); push('i32'); }
        else if (kind.startsWith('splat:')) { popT(kind.slice(6) as ValType); push('v128'); }
        else if (kind.startsWith('extract:') || kind.startsWith('replace:')) {
          const [k, t, n] = kind.split(':') as [string, ValType, string];
          const lane = r.u8();
          if (lane >= Number(n)) err(`lane index must be less than ${n}`);
          if (k === 'extract') { popT('v128'); push(t); } else { popT(t); popT('v128'); push('v128'); }
        }
        break;
      }
      default: throw new WasmError(`unexpected opcode: 0x${op.toString(16)}`, at);
    }
  }
  if (!r.eof()) { at = r.pos; err('function body has bytes after the final end'); }
}

/** Validate a module. Returns the first error with its offset, like wasm-validate. */
export function validateWasm(bytes: Uint8Array, opts: ValidateOptions = {}): WasmValidation {
  let m: WasmModule;
  try { m = readWasmModule(bytes); } catch (e) {
    const off = e instanceof WasmError ? e.offset : 0;
    return { valid: false, stage: 'read', error: { offset: off, message: e instanceof WasmError ? e.reason : (e as Error).message }, functionsChecked: 0, instructions: 0 };
  }
  const refs = new Set<number>();
  try { validateModule(m, bytes, refs); } catch (e) {
    if (e instanceof V || e instanceof WasmError) return { valid: false, stage: 'module', module: m, error: { offset: e.offset, message: e instanceof WasmError ? e.reason : e.message }, functionsChecked: 0, instructions: 0 };
    throw e;
  }
  const budget = { n: 0 };
  const max = Math.min(m.codes.length, opts.maxFunctions ?? Infinity);
  for (let i = 0; i < max; i++) {
    try { validateFunction(m, bytes, i, refs, budget, opts); } catch (e) {
      if (e instanceof V || e instanceof WasmError) return { valid: false, stage: e instanceof WasmError ? 'read' : 'code', module: m, error: { offset: e.offset, message: e instanceof WasmError ? e.reason : e.message, functionIndex: m.importCounts.func + i }, functionsChecked: i, instructions: budget.n };
      throw e;
    }
  }
  return { valid: true, stage: 'ok', module: m, functionsChecked: max, instructions: budget.n };
}
