// WebAssembly binary module reader: every standard section with full types, the name section and
// code bodies located (not yet validated). Malformed input raises WasmError with the byte offset,
// matching what wabt calls a read error.

export type ValType = 'i32' | 'i64' | 'f32' | 'f64' | 'v128' | 'funcref' | 'externref';
export interface FuncType { params: ValType[]; results: ValType[] }
export interface Limits { min: number; max?: number; shared?: boolean; is64?: boolean }
export interface TableType { elem: ValType; limits: Limits }
export interface GlobalType { type: ValType; mutable: boolean }
export interface ConstExpr { start: number; end: number }
export type ImportDesc =
  | { kind: 'func'; type: number }
  | { kind: 'table'; table: TableType }
  | { kind: 'memory'; memory: Limits }
  | { kind: 'global'; global: GlobalType }
  | { kind: 'tag'; type: number };
export interface WasmImport { module: string; name: string; desc: ImportDesc; offset: number }
export interface WasmExport { name: string; kind: 'func' | 'table' | 'memory' | 'global' | 'tag'; index: number; offset: number }
export interface WasmElem { mode: 'active' | 'passive' | 'declarative'; table: number; offset?: ConstExpr; type: ValType; funcs?: number[]; exprs?: ConstExpr[]; at: number }
export interface WasmData { mode: 'active' | 'passive'; memory: number; offset?: ConstExpr; size: number; at: number }
export interface WasmCode { offset: number; size: number; locals: { count: number; type: ValType }[]; bodyStart: number; bodyEnd: number }
export interface WasmSection { id: number; name: string; offset: number; size: number; customName?: string }
export interface WasmNames { module?: string; functions: Record<number, string>; locals: Record<number, Record<number, string>>; other: string[] }
export interface WasmModule {
  version: number;
  sections: WasmSection[];
  types: FuncType[];
  imports: WasmImport[];
  functions: number[];
  tables: TableType[];
  memories: Limits[];
  globals: { type: GlobalType; init: ConstExpr }[];
  exports: WasmExport[];
  start?: number;
  elements: WasmElem[];
  dataCount?: number;
  codes: WasmCode[];
  datas: WasmData[];
  names?: WasmNames;
  producers?: Record<string, string[]>;
  /** imported counts, for index spaces */
  importCounts: { func: number; table: number; memory: number; global: number; tag: number };
}

export class WasmError extends Error {
  constructor(message: string, readonly offset: number) { super(`${message} (at offset 0x${offset.toString(16)})`); }
  get reason(): string { return this.message.replace(/ \(at offset 0x[0-9a-f]+\)$/, ''); }
}

export const SECTION_NAMES = ['custom', 'type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'code', 'data', 'datacount', 'tag'];
/** Required order of the non-custom sections. */
const ORDER: Record<number, number> = { 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 13: 6, 6: 7, 7: 8, 8: 9, 9: 10, 12: 11, 10: 12, 11: 13 };

export class WasmReader {
  pos: number;
  constructor(readonly b: Uint8Array, pos = 0, readonly end = b.length) { this.pos = pos; }
  eof(): boolean { return this.pos >= this.end; }
  u8(): number { if (this.pos >= this.end) throw new WasmError('unexpected end', this.pos); return this.b[this.pos++] as number; }
  u32(): number {
    const start = this.pos;
    let result = 0, shift = 0;
    for (let i = 0; i < 5; i++) {
      const byte = this.u8();
      if (i === 4 && (byte & 0x70) !== 0) throw new WasmError('invalid LEB128 u32: unused bits set', start);
      result += (byte & 0x7f) * 2 ** shift;
      if (!(byte & 0x80)) return result;
      shift += 7;
    }
    throw new WasmError('invalid LEB128 u32: too long', start);
  }
  /** signed LEB of up to `bits` bits, returned as a number (i64 values beyond 2^53 lose precision, which validation never needs) */
  sleb(bits: 32 | 33 | 64): number {
    const start = this.pos;
    const maxBytes = Math.ceil(bits / 7);
    let result = 0, shift = 0, byte = 0;
    for (let i = 0; i < maxBytes; i++) {
      byte = this.u8();
      if (i === maxBytes - 1) {
        // the unused high bits of the last byte must all equal the sign bit
        const used = bits - 7 * (maxBytes - 1);
        const rest = (byte & 0x7f) >> (used - 1);
        const ok = (byte & 0x80) === 0 && (rest === 0 || rest === (0x7f >> (used - 1)));
        if (!ok) throw new WasmError(`invalid LEB128 s${bits}`, start);
      }
      result += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) {
        if (byte & 0x40) result -= 2 ** shift;
        return result;
      }
    }
    throw new WasmError(`invalid LEB128 s${bits}: too long`, start);
  }
  bytes(n: number): Uint8Array { if (this.pos + n > this.end || n < 0) throw new WasmError('unexpected end', this.pos); const s = this.b.subarray(this.pos, this.pos + n); this.pos += n; return s; }
  name(): string {
    const n = this.u32();
    const at = this.pos;
    const raw = this.bytes(n);
    try { return new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { throw new WasmError('invalid utf-8 encoding', at); }
  }
  valtype(): ValType {
    const at = this.pos;
    const t = this.u8();
    switch (t) {
      case 0x7f: return 'i32'; case 0x7e: return 'i64'; case 0x7d: return 'f32'; case 0x7c: return 'f64';
      case 0x7b: return 'v128'; case 0x70: return 'funcref'; case 0x6f: return 'externref';
      default: throw new WasmError(`malformed value type 0x${t.toString(16)}`, at);
    }
  }
  reftype(): ValType { const at = this.pos; const t = this.valtype(); if (t !== 'funcref' && t !== 'externref') throw new WasmError('malformed reference type', at); return t; }
  limits(memory: boolean): Limits {
    const at = this.pos;
    const flags = this.u8();
    const allowed = memory ? 0x07 : 0x01;
    if (flags & ~allowed) throw new WasmError(`malformed limits flags 0x${flags.toString(16)}`, at);
    const is64 = (flags & 4) !== 0;
    const min = is64 ? this.u64num() : this.u32();
    const l: Limits = { min };
    if (flags & 1) l.max = is64 ? this.u64num() : this.u32();
    if (flags & 2) l.shared = true;
    if (is64) l.is64 = true;
    return l;
  }
  u64num(): number {
    const start = this.pos;
    let result = 0, shift = 0;
    for (let i = 0; i < 10; i++) {
      const byte = this.u8();
      result += (byte & 0x7f) * 2 ** shift;
      if (!(byte & 0x80)) return result;
      shift += 7;
    }
    throw new WasmError('invalid LEB128 u64', start);
  }
}

/** Skip one constant expression up to and including its end opcode; returns its byte range. */
function constExpr(r: WasmReader): ConstExpr {
  const start = r.pos;
  for (let guard = 0; guard < 1 << 20; guard++) {
    const op = r.u8();
    if (op === 0x0b) return { start, end: r.pos };
    switch (op) {
      case 0x41: r.sleb(32); break;
      case 0x42: r.sleb(64); break;
      case 0x43: r.bytes(4); break;
      case 0x44: r.bytes(8); break;
      case 0x23: case 0xd2: r.u32(); break;
      case 0xd0: r.reftype(); break;
      case 0xfd: { const sub = r.u32(); if (sub !== 12) throw new WasmError('illegal opcode in constant expression', r.pos); r.bytes(16); break; }
      case 0x6a: case 0x6b: case 0x6c: case 0x7c: case 0x7d: case 0x7e: break; // extended-const arithmetic, checked by the validator
      default: throw new WasmError(`illegal opcode in constant expression: 0x${op.toString(16)}`, r.pos - 1);
    }
  }
  throw new WasmError('constant expression is too long', start);
}

const MAX_COUNT = 1_000_000;
function count(r: WasmReader, what: string): number {
  const at = r.pos;
  const n = r.u32();
  if (n > MAX_COUNT || n > r.end - r.pos) throw new WasmError(`${what} count ${n} is larger than the section`, at);
  return n;
}

/** Parse a module. Throws WasmError on any malformed encoding. */
export function readWasmModule(bytes: Uint8Array): WasmModule {
  if (bytes.length < 8) throw new WasmError('unable to read magic and version', 0);
  if (bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) throw new WasmError('bad magic value', 0);
  const version = (bytes[4] as number) | ((bytes[5] as number) << 8) | ((bytes[6] as number) << 16) | ((bytes[7] as number) << 24);
  if (version !== 1) throw new WasmError(`bad wasm file version: 0x${version.toString(16)}`, 4);
  const m: WasmModule = { version, sections: [], types: [], imports: [], functions: [], tables: [], memories: [], globals: [], exports: [], elements: [], codes: [], datas: [], importCounts: { func: 0, table: 0, memory: 0, global: 0, tag: 0 } };
  const r = new WasmReader(bytes, 8);
  let last = 0;
  let sawFunction = false, sawCode = false;
  while (!r.eof()) {
    const at = r.pos;
    const id = r.u8();
    const size = r.u32();
    const start = r.pos;
    if (start + size > bytes.length) throw new WasmError(`section ${SECTION_NAMES[id] ?? id} extends past the end of the module`, at);
    const s = new WasmReader(bytes, start, start + size);
    const sec: WasmSection = { id, name: SECTION_NAMES[id] ?? `section${id}`, offset: at, size };
    m.sections.push(sec);
    if (id !== 0) {
      const ord = ORDER[id];
      if (ord === undefined) throw new WasmError(`invalid section code: ${id}`, at);
      if (ord <= last) throw new WasmError(`section ${sec.name} out of order`, at);
      last = ord;
    }
    switch (id) {
      case 0: {
        const nm = s.name();
        sec.customName = nm;
        try { if (nm === 'name') m.names = readNames(s); else if (nm === 'producers') m.producers = readProducers(s); } catch { /* a broken name section is not a validation error */ }
        s.pos = s.end;
        break;
      }
      case 1: {
        const n = count(s, 'type');
        for (let i = 0; i < n; i++) {
          const fat = s.pos;
          const form = s.u8();
          if (form !== 0x60) throw new WasmError(`unexpected type form 0x${form.toString(16)}`, fat);
          const np = count(s, 'param'); const params: ValType[] = []; for (let k = 0; k < np; k++) params.push(s.valtype());
          const nr = count(s, 'result'); const results: ValType[] = []; for (let k = 0; k < nr; k++) results.push(s.valtype());
          m.types.push({ params, results });
        }
        break;
      }
      case 2: {
        const n = count(s, 'import');
        for (let i = 0; i < n; i++) {
          const iat = s.pos;
          const module = s.name(), name = s.name();
          const kat = s.pos;
          const kind = s.u8();
          let desc: ImportDesc;
          if (kind === 0) { desc = { kind: 'func', type: s.u32() }; m.importCounts.func++; }
          else if (kind === 1) { desc = { kind: 'table', table: { elem: s.reftype(), limits: s.limits(false) } }; m.importCounts.table++; }
          else if (kind === 2) { desc = { kind: 'memory', memory: s.limits(true) }; m.importCounts.memory++; }
          else if (kind === 3) { const type = s.valtype(); const mat = s.pos; const mu = s.u8(); if (mu > 1) throw new WasmError('malformed mutability', mat); desc = { kind: 'global', global: { type, mutable: mu === 1 } }; m.importCounts.global++; }
          else if (kind === 4) { s.u8(); desc = { kind: 'tag', type: s.u32() }; m.importCounts.tag++; }
          else throw new WasmError(`malformed import kind ${kind}`, kat);
          m.imports.push({ module, name, desc, offset: iat });
        }
        break;
      }
      case 3: { sawFunction = true; const n = count(s, 'function'); for (let i = 0; i < n; i++) m.functions.push(s.u32()); break; }
      case 4: { const n = count(s, 'table'); for (let i = 0; i < n; i++) m.tables.push({ elem: s.reftype(), limits: s.limits(false) }); break; }
      case 5: { const n = count(s, 'memory'); for (let i = 0; i < n; i++) m.memories.push(s.limits(true)); break; }
      case 6: {
        const n = count(s, 'global');
        for (let i = 0; i < n; i++) { const type = s.valtype(); const mat = s.pos; const mu = s.u8(); if (mu > 1) throw new WasmError('malformed mutability', mat); m.globals.push({ type: { type, mutable: mu === 1 }, init: constExpr(s) }); }
        break;
      }
      case 7: {
        const n = count(s, 'export');
        for (let i = 0; i < n; i++) {
          const eat = s.pos;
          const name = s.name();
          const kat = s.pos;
          const k = s.u8();
          const kind = (['func', 'table', 'memory', 'global', 'tag'] as const)[k];
          if (!kind) throw new WasmError(`malformed export kind ${k}`, kat);
          m.exports.push({ name, kind, index: s.u32(), offset: eat });
        }
        break;
      }
      case 8: m.start = s.u32(); break;
      case 9: {
        const n = count(s, 'element');
        for (let i = 0; i < n; i++) {
          const eat = s.pos;
          const flags = s.u32();
          if (flags > 7) throw new WasmError(`malformed element segment flags ${flags}`, eat);
          const passiveOrDecl = (flags & 1) !== 0, explicitTable = (flags & 2) !== 0, usesExprs = (flags & 4) !== 0;
          const e: WasmElem = { mode: passiveOrDecl ? (explicitTable ? 'declarative' : 'passive') : 'active', table: 0, type: 'funcref', at: eat };
          if (!passiveOrDecl) { if (explicitTable) e.table = s.u32(); e.offset = constExpr(s); }
          if (passiveOrDecl || explicitTable) {
            if (usesExprs) e.type = s.reftype();
            else { const kat = s.pos; const ek = s.u8(); if (ek !== 0) throw new WasmError('malformed element kind', kat); }
          }
          const c = count(s, 'element item');
          if (usesExprs) { e.exprs = []; for (let k = 0; k < c; k++) e.exprs.push(constExpr(s)); }
          else { e.funcs = []; for (let k = 0; k < c; k++) e.funcs.push(s.u32()); }
          m.elements.push(e);
        }
        break;
      }
      case 10: {
        sawCode = true;
        const n = count(s, 'function body');
        for (let i = 0; i < n; i++) {
          const bat = s.pos;
          const bsize = s.u32();
          const bstart = s.pos;
          if (bstart + bsize > s.end) throw new WasmError('function body extends past the end of the code section', bat);
          const b = new WasmReader(bytes, bstart, bstart + bsize);
          const groups = count(b, 'local group');
          const locals: { count: number; type: ValType }[] = [];
          let total = 0;
          for (let k = 0; k < groups; k++) {
            const cat = b.pos;
            const c = b.u32();
            total += c;
            if (total > 50000) throw new WasmError('local count too large', cat);
            locals.push({ count: c, type: b.valtype() });
          }
          m.codes.push({ offset: bat, size: bsize, locals, bodyStart: b.pos, bodyEnd: bstart + bsize });
          s.pos = bstart + bsize;
        }
        break;
      }
      case 11: {
        const n = count(s, 'data segment');
        for (let i = 0; i < n; i++) {
          const dat = s.pos;
          const flags = s.u32();
          let d: WasmData;
          if (flags === 0) { const offset = constExpr(s); d = { mode: 'active', memory: 0, offset, size: 0, at: dat }; }
          else if (flags === 1) d = { mode: 'passive', memory: 0, size: 0, at: dat };
          else if (flags === 2) { const memory = s.u32(); d = { mode: 'active', memory, offset: constExpr(s), size: 0, at: dat }; }
          else throw new WasmError(`malformed data segment flags ${flags}`, dat);
          d.size = s.u32();
          s.bytes(d.size);
          m.datas.push(d);
        }
        if (m.dataCount !== undefined && m.dataCount !== m.datas.length) throw new WasmError('data segment count does not equal data count section', at);
        break;
      }
      case 12: m.dataCount = s.u32(); break;
      case 13: { const n = count(s, 'tag'); for (let i = 0; i < n; i++) { s.u8(); s.u32(); } break; }
    }
    if (id !== 0 && s.pos !== s.end) throw new WasmError(`section ${sec.name} size mismatch: ${s.end - s.pos} bytes left`, s.pos);
    r.pos = start + size;
  }
  if (m.functions.length !== m.codes.length && (sawFunction || sawCode)) throw new WasmError('function and code section have inconsistent lengths', bytes.length);
  if (m.dataCount !== undefined && !m.sections.some((x) => x.id === 11) && m.dataCount !== 0) throw new WasmError('data count section without data section', bytes.length);
  return m;
}

function readNameMap(s: WasmReader): Record<number, string> {
  const out: Record<number, string> = {};
  const n = s.u32();
  for (let i = 0; i < n && i < MAX_COUNT; i++) { const idx = s.u32(); out[idx] = s.name(); }
  return out;
}
function readNames(s: WasmReader): WasmNames {
  const names: WasmNames = { functions: {}, locals: {}, other: [] };
  while (!s.eof()) {
    const id = s.u8(); const size = s.u32(); const end = s.pos + size;
    const sub = new WasmReader(s.b, s.pos, end);
    if (id === 0) names.module = sub.name();
    else if (id === 1) names.functions = readNameMap(sub);
    else if (id === 2) { const n = sub.u32(); for (let i = 0; i < n && i < MAX_COUNT; i++) { const f = sub.u32(); names.locals[f] = readNameMap(sub); } }
    else names.other.push(['module', 'functions', 'locals', 'labels', 'types', 'tables', 'memories', 'globals', 'elems', 'datas', 'fields', 'tags'][id] ?? `subsection ${id}`);
    s.pos = end;
  }
  return names;
}
function readProducers(s: WasmReader): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  const n = s.u32();
  for (let i = 0; i < n && i < 64; i++) {
    const field = s.name(); const c = s.u32(); const vals: string[] = [];
    for (let k = 0; k < c && k < 64; k++) { const nm = s.name(); const ver = s.name(); vals.push(ver ? `${nm} ${ver}` : nm); }
    out[field] = vals;
  }
  return out;
}

/** Function type of a function index (imports first). */
export function funcTypeOf(m: WasmModule, idx: number): FuncType | undefined {
  let i = 0;
  for (const imp of m.imports) if (imp.desc.kind === 'func') { if (i === idx) return m.types[imp.desc.type]; i++; }
  const t = m.functions[idx - m.importCounts.func];
  return t === undefined ? undefined : m.types[t];
}
export function globalTypeOf(m: WasmModule, idx: number): GlobalType | undefined {
  let i = 0;
  for (const imp of m.imports) if (imp.desc.kind === 'global') { if (i === idx) return imp.desc.global; i++; }
  return m.globals[idx - m.importCounts.global]?.type;
}
export function tableTypeOf(m: WasmModule, idx: number): TableType | undefined {
  let i = 0;
  for (const imp of m.imports) if (imp.desc.kind === 'table') { if (i === idx) return imp.desc.table; i++; }
  return m.tables[idx - m.importCounts.table];
}
export function memoryCount(m: WasmModule): number { return m.importCounts.memory + m.memories.length; }
export function tableCount(m: WasmModule): number { return m.importCounts.table + m.tables.length; }
export function funcCount(m: WasmModule): number { return m.importCounts.func + m.functions.length; }
export function globalCount(m: WasmModule): number { return m.importCounts.global + m.globals.length; }
