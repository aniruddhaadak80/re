// CPython marshal decoder (format versions used by 3.7 to 3.13) producing plain JS values.
import { ByteReader, ParseError, LIMITS, utf8, latin1, hex } from '../util.js';

export type PyValue =
  | null | boolean | number | string
  | { kind: 'int'; value: string }
  | { kind: 'float'; value: number }
  | { kind: 'complex'; real: number; imag: number }
  | { kind: 'bytes'; bytes: Uint8Array }
  | { kind: 'tuple'; items: PyValue[] }
  | { kind: 'list'; items: PyValue[] }
  | { kind: 'set'; items: PyValue[]; frozen: boolean }
  | { kind: 'dict'; entries: [PyValue, PyValue][] }
  | { kind: 'ellipsis' } | { kind: 'stopiteration' } | { kind: 'null' }
  | PyCode;

export interface PyCode {
  kind: 'code';
  argcount: number; posonlyargcount: number; kwonlyargcount: number; nlocals: number; stacksize: number; flags: number;
  code: Uint8Array;
  consts: PyValue[];
  names: string[];
  varnames: string[];
  freevars: string[];
  cellvars: string[];
  /** 3.11+: all local, cell and free names in frame order */
  localsplusnames?: string[];
  localspluskinds?: Uint8Array;
  filename: string;
  name: string;
  qualname: string;
  firstlineno: number;
  linetable: Uint8Array;
  exceptiontable?: Uint8Array;
}

export interface MarshalOptions { /** CPython minor version, for example 12 for 3.12 */ minor: number; maxObjects?: number; maxDepth?: number }

class Unmarshaller {
  refs: PyValue[] = [];
  count = 0;
  constructor(readonly r: ByteReader, readonly opt: Required<MarshalOptions>) {}

  read(depth: number): PyValue {
    if (depth > this.opt.maxDepth) throw new ParseError('marshal nesting too deep', this.r.pos);
    if (++this.count > this.opt.maxObjects) throw new ParseError('too many marshal objects', this.r.pos);
    const r = this.r;
    const at = r.pos;
    const code = r.u8();
    const flag = (code & 0x80) !== 0;
    const t = String.fromCharCode(code & 0x7f);
    let slot = -1;
    const reserve = () => { if (flag) { slot = this.refs.length; this.refs.push(null); } };
    const done = (v: PyValue): PyValue => {
      if (flag) { if (slot < 0) this.refs.push(v); else this.refs[slot] = v; }
      return v;
    };
    switch (t) {
      case '0': return { kind: 'null' };
      case 'N': return null;
      case 'F': return false;
      case 'T': return true;
      case 'S': return { kind: 'stopiteration' };
      case '.': return { kind: 'ellipsis' };
      case 'i': return done(r.i32());
      case 'I': { const v = r.i64(); return done(safeInt(v)); }
      case 'l': {
        const n = r.i32();
        const size = Math.abs(n);
        if (size > 1 << 20) throw new ParseError('long too large', at);
        let v = 0n;
        const digits: number[] = [];
        for (let i = 0; i < size; i++) digits.push(r.u16());
        for (let i = size - 1; i >= 0; i--) v = (v << 15n) | BigInt(digits[i] as number);
        if (n < 0) v = -v;
        return done(safeInt(v));
      }
      case 'f': { const n = r.u8(); return done({ kind: 'float', value: Number(latin1(r.take(n))) }); }
      case 'g': return done({ kind: 'float', value: r.f64() });
      case 'x': { const a = r.u8(); const re = Number(latin1(r.take(a))); const b = r.u8(); return done({ kind: 'complex', real: re, imag: Number(latin1(r.take(b))) }); }
      case 'y': return done({ kind: 'complex', real: r.f64(), imag: r.f64() });
      case 's': { const n = this.len(); return done({ kind: 'bytes', bytes: r.take(n) }); }
      case 't': case 'u': { const n = this.len(); return done(utf8(r.take(n))); }
      case 'a': case 'A': { const n = this.len(); return done(latin1(r.take(n))); }
      case 'z': case 'Z': { const n = r.u8(); return done(latin1(r.take(n))); }
      case 'r': {
        const i = r.u32();
        if (i >= this.refs.length) throw new ParseError(`bad marshal ref ${i}`, at);
        return this.refs[i] as PyValue;
      }
      case '(': case ')': case '[': case '<': case '>': {
        const n = t === ')' ? r.u8() : this.len();
        reserve();
        const items: PyValue[] = [];
        for (let i = 0; i < n; i++) items.push(this.read(depth + 1));
        if (t === '[') return done({ kind: 'list', items });
        if (t === '<' || t === '>') return done({ kind: 'set', items, frozen: t === '>' });
        return done({ kind: 'tuple', items });
      }
      case '{': {
        reserve();
        const entries: [PyValue, PyValue][] = [];
        for (let guard = 0; guard < LIMITS.maxEntries * 10; guard++) {
          if (r.bytes[r.pos] === 0x30) { r.pos++; break; }
          const k = this.read(depth + 1);
          const v = this.read(depth + 1);
          entries.push([k, v]);
        }
        return done({ kind: 'dict', entries });
      }
      case 'c': {
        reserve();
        const c = this.code(depth);
        return done(c);
      }
      default:
        throw new ParseError(`unknown marshal type ${JSON.stringify(t)} (0x${code.toString(16)})`, at);
    }
  }

  len(): number {
    const n = this.r.u32();
    if (n > this.r.remaining() * 64 + 16) throw new ParseError(`marshal length ${n} larger than input`, this.r.pos - 4);
    return n;
  }

  str(depth: number): string {
    const v = this.read(depth + 1);
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object' && v.kind === 'bytes') return latin1(v.bytes);
    return v === null ? '' : String(v);
  }
  bytes(depth: number): Uint8Array {
    const v = this.read(depth + 1);
    if (v && typeof v === 'object' && v.kind === 'bytes') return v.bytes;
    if (typeof v === 'string') return new TextEncoder().encode(v);
    return new Uint8Array(0);
  }
  tuple(depth: number): PyValue[] {
    const v = this.read(depth + 1);
    if (v && typeof v === 'object' && (v.kind === 'tuple' || v.kind === 'list')) return v.items;
    return [];
  }
  strTuple(depth: number): string[] { return this.tuple(depth).map((x) => (typeof x === 'string' ? x : x && typeof x === 'object' && x.kind === 'bytes' ? latin1(x.bytes) : String(x))); }

  code(depth: number): PyCode {
    const r = this.r;
    const m = this.opt.minor;
    const argcount = r.i32();
    const posonlyargcount = m >= 8 ? r.i32() : 0;
    const kwonlyargcount = r.i32();
    const nlocalsRaw = m < 11 ? r.i32() : -1;
    const stacksize = r.i32();
    const flags = r.i32();
    const code = this.bytes(depth);
    const consts = this.tuple(depth);
    const names = this.strTuple(depth);
    if (m >= 11) {
      const localsplusnames = this.strTuple(depth);
      const localspluskinds = this.bytes(depth);
      const filename = this.str(depth);
      const name = this.str(depth);
      const qualname = this.str(depth);
      const firstlineno = r.i32();
      const linetable = this.bytes(depth);
      const exceptiontable = this.bytes(depth);
      const varnames: string[] = [], cellvars: string[] = [], freevars: string[] = [];
      localsplusnames.forEach((n, i) => {
        const k = localspluskinds[i] ?? 0;
        if (k & 0x20) varnames.push(n);
        if (k & 0x40) cellvars.push(n);
        if (k & 0x80) freevars.push(n);
      });
      return { kind: 'code', argcount, posonlyargcount, kwonlyargcount, nlocals: varnames.length, stacksize, flags, code, consts, names, varnames, freevars, cellvars, localsplusnames, localspluskinds, filename, name, qualname, firstlineno, linetable, exceptiontable };
    }
    const varnames = this.strTuple(depth);
    const freevars = this.strTuple(depth);
    const cellvars = this.strTuple(depth);
    const filename = this.str(depth);
    const name = this.str(depth);
    const firstlineno = r.i32();
    const linetable = this.bytes(depth);
    return { kind: 'code', argcount, posonlyargcount, kwonlyargcount, nlocals: nlocalsRaw, stacksize, flags, code, consts, names, varnames, freevars, cellvars, filename, name, qualname: name, firstlineno, linetable };
  }
}

function safeInt(v: bigint): PyValue {
  return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : { kind: 'int', value: v.toString() };
}

/** Decode one marshalled object starting at `offset`. */
export function unmarshal(bytes: Uint8Array, opt: MarshalOptions, offset = 0): { value: PyValue; end: number } {
  const r = new ByteReader(bytes, offset);
  const u = new Unmarshaller(r, { maxObjects: LIMITS.maxMarshalObjects, maxDepth: LIMITS.maxDepth * 2, ...opt });
  const value = u.read(0);
  return { value, end: r.pos };
}

export function isCode(v: PyValue): v is PyCode { return !!v && typeof v === 'object' && (v as { kind: string }).kind === 'code'; }

/** Python like repr for constants, used in disassembly text and to compare with dis. */
export function pyRepr(v: PyValue, depth = 0): string {
  if (depth > 16) return '...';
  if (v === null) return 'None';
  if (v === true) return 'True';
  if (v === false) return 'False';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return reprStr(v);
  switch (v.kind) {
    case 'int': return v.value;
    case 'float': return floatRepr(v.value);
    case 'complex': {
      const c = (x: number) => floatRepr(x).replace(/\.0$/, '');
      return v.real === 0 && !Object.is(v.real, -0) ? `${c(v.imag)}j` : `(${c(v.real)}${v.imag < 0 || Number.isNaN(v.imag) ? '' : '+'}${c(v.imag)}j)`;
    }
    case 'bytes': return 'b' + reprStr(latin1(v.bytes), true);
    case 'tuple': return v.items.length === 1 ? `(${pyRepr(v.items[0] as PyValue, depth + 1)},)` : `(${v.items.map((x) => pyRepr(x, depth + 1)).join(', ')})`;
    case 'list': return `[${v.items.map((x) => pyRepr(x, depth + 1)).join(', ')}]`;
    case 'set': return v.frozen ? `frozenset({${v.items.map((x) => pyRepr(x, depth + 1)).join(', ')}})` : `{${v.items.map((x) => pyRepr(x, depth + 1)).join(', ')}}`;
    case 'dict': return `{${v.entries.map(([k, x]) => `${pyRepr(k, depth + 1)}: ${pyRepr(x, depth + 1)}`).join(', ')}}`;
    case 'ellipsis': return 'Ellipsis';
    case 'stopiteration': return 'StopIteration';
    case 'null': return 'NULL';
    case 'code': return `<code object ${v.name} at 0x0, file "${v.filename}", line ${v.firstlineno}>`;
  }
}

function floatRepr(x: number): string {
  if (Number.isNaN(x)) return 'nan';
  if (!Number.isFinite(x)) return x > 0 ? 'inf' : '-inf';
  if (Number.isInteger(x) && Math.abs(x) < 1e16) return x.toFixed(1);
  const s = String(x);
  return s.replace(/e\+?(-?)(\d)$/, 'e$10$2');
}

function reprStr(s: string, bytes = false): string {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = q;
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (ch === q || ch === '\\') out += '\\' + ch;
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20 || c === 0x7f || (bytes && c > 0x7e) || (!bytes && c >= 0x80 && c < 0xa0)) out += '\\x' + c.toString(16).padStart(2, '0');
    else out += ch;
  }
  return out + q;
}

/** JSON friendly view of a value with caps on size. */
export function toJsonValue(v: PyValue, depth = 0, maxItems = 200): unknown {
  if (depth > 24) return '<depth>';
  if (v === null || typeof v !== 'object') return v;
  switch (v.kind) {
    case 'bytes': return { bytes: hex(v.bytes, 0, 512), length: v.bytes.length };
    case 'tuple': case 'list': case 'set': return { [v.kind]: v.items.slice(0, maxItems).map((x) => toJsonValue(x, depth + 1, maxItems)), ...(v.items.length > maxItems ? { truncated: v.items.length } : {}) };
    case 'dict': return { dict: v.entries.slice(0, maxItems).map(([k, x]) => [toJsonValue(k, depth + 1, maxItems), toJsonValue(x, depth + 1, maxItems)]) };
    case 'code': return { code: v.qualname || v.name, firstlineno: v.firstlineno };
    case 'float': return { float: Number.isFinite(v.value) ? v.value : String(v.value) };
    default: return { ...v };
  }
}
