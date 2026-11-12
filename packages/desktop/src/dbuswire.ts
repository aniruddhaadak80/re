// D-Bus wire format (marshalling and unmarshalling) written from the D-Bus specification.
// No Node imports, so it also runs in a browser worker (for example to decode a captured
// message). Every read is bounds checked; nesting, array sizes and message sizes are capped.
import { InputError } from './proc.js';

/** A value with an explicit D-Bus signature, used to encode variants and to force a type. */
export class Variant { constructor(public sig: string, public value: DValue) {} }
export type DValue = string | number | bigint | boolean | null | Variant | Uint8Array | DValue[] | { [k: string]: DValue };

export const MSG = { call: 1, return: 2, error: 3, signal: 4 } as const;
export const FLAG = { noReply: 1, noAutoStart: 2 } as const;
export interface DMessage {
  type: number; flags: number; serial: number;
  path?: string; interface?: string; member?: string; errorName?: string; replySerial?: number;
  destination?: string; sender?: string; signature?: string; unixFds?: number;
  body: DValue[];
}

const MAX_MESSAGE = 128 * 1024 * 1024; // spec limit
const MAX_ARRAY = 64 * 1024 * 1024;
const MAX_DEPTH = 64;

/** Split a signature into single complete types ("a{sv}ia(ii)" -> ["a{sv}", "i", "a(ii)"]). */
export function splitSignature(sig: string): string[] {
  if (sig.length > 255) throw new InputError('signature longer than 255');
  const out: string[] = [];
  let i = 0;
  while (i < sig.length) { const end = completeType(sig, i, 0); out.push(sig.slice(i, end)); i = end; }
  return out;
}
function completeType(sig: string, i: number, depth: number): number {
  if (depth > MAX_DEPTH) throw new InputError('signature nested too deep');
  const c = sig[i];
  if (c === undefined) throw new InputError('truncated signature');
  if ('ybnqiuxtdsoghv'.includes(c)) return i + 1;
  if (c === 'a') return completeType(sig, i + 1, depth + 1);
  if (c === '(' || c === '{') {
    const close = c === '(' ? ')' : '}';
    let j = i + 1, n = 0;
    while (sig[j] !== close) { if (sig[j] === undefined) throw new InputError('unclosed container in signature'); j = completeType(sig, j, depth + 1); n++; }
    if (n === 0 || (c === '{' && n !== 2)) throw new InputError('bad struct or dict entry in signature');
    return j + 1;
  }
  throw new InputError(`bad signature character ${JSON.stringify(c)}`);
}
function alignOf(c: string): number {
  switch (c) { case 'y': case 'g': case 'v': return 1; case 'n': case 'q': return 2; case 'x': case 't': case 'd': case '(': case '{': return 8; default: return 4; }
}

// ---------------- writer ----------------

class Writer {
  buf = new Uint8Array(256); len = 0;
  private dv = new DataView(this.buf.buffer);
  private grow(n: number) {
    if (this.len + n <= this.buf.length) return;
    if (this.len + n > MAX_MESSAGE) throw new InputError('message too large');
    let size = this.buf.length * 2; while (size < this.len + n) size *= 2;
    const b = new Uint8Array(size); b.set(this.buf.subarray(0, this.len)); this.buf = b; this.dv = new DataView(b.buffer);
  }
  pad(a: number) { const p = (a - (this.len % a)) % a; this.grow(p); this.buf.fill(0, this.len, this.len + p); this.len += p; }
  u8(v: number) { this.grow(1); this.buf[this.len++] = v & 0xff; }
  u16(v: number, signed = false) { this.pad(2); this.grow(2); signed ? this.dv.setInt16(this.len, v, true) : this.dv.setUint16(this.len, v, true); this.len += 2; }
  u32(v: number, signed = false) { this.pad(4); this.grow(4); signed ? this.dv.setInt32(this.len, v, true) : this.dv.setUint32(this.len, v >>> 0, true); this.len += 4; }
  u64(v: bigint, signed = false) { this.pad(8); this.grow(8); signed ? this.dv.setBigInt64(this.len, v, true) : this.dv.setBigUint64(this.len, v, true); this.len += 8; }
  f64(v: number) { this.pad(8); this.grow(8); this.dv.setFloat64(this.len, v, true); this.len += 8; }
  bytes(b: Uint8Array) { this.grow(b.length); this.buf.set(b, this.len); this.len += b.length; }
  setU32(at: number, v: number) { this.dv.setUint32(at, v, true); }
  out() { return this.buf.slice(0, this.len); }
}

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

function num(v: DValue, what: string): number {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'boolean') return v ? 1 : 0;
  throw new InputError(`expected a number for ${what}`);
}

function writeValue(w: Writer, sig: string, v: DValue, depth: number): void {
  if (depth > MAX_DEPTH) throw new InputError('value nested too deep');
  const c = sig[0]!;
  switch (c) {
    case 'y': w.u8(num(v, 'byte')); return;
    case 'b': w.u32(v ? 1 : 0); return;
    case 'n': w.u16(num(v, 'int16'), true); return;
    case 'q': w.u16(num(v, 'uint16')); return;
    case 'i': w.u32(num(v, 'int32'), true); return;
    case 'u': case 'h': w.u32(num(v, 'uint32')); return;
    case 'x': w.u64(BigInt(typeof v === 'bigint' ? v : Math.trunc(num(v, 'int64'))), true); return;
    case 't': w.u64(BigInt(typeof v === 'bigint' ? v : Math.trunc(num(v, 'uint64')))); return;
    case 'd': w.f64(num(v, 'double')); return;
    case 's': case 'o': { const b = enc.encode(String(v)); w.u32(b.length); w.bytes(b); w.u8(0); return; }
    case 'g': { const b = enc.encode(String(v)); if (b.length > 255) throw new InputError('signature too long'); w.u8(b.length); w.bytes(b); w.u8(0); return; }
    case 'v': {
      const vv = v instanceof Variant ? v : guessVariant(v);
      writeValue(w, 'g', vv.sig, depth + 1);
      if (splitSignature(vv.sig).length !== 1) throw new InputError('variant needs one complete type');
      writeValue(w, vv.sig, vv.value, depth + 1); return;
    }
    case 'a': {
      const elem = sig.slice(1);
      w.u32(0); const lenAt = w.len - 4;
      w.pad(alignOf(elem[0]!));
      const start = w.len;
      if (elem[0] === 'y' && v instanceof Uint8Array) w.bytes(v);
      else if (elem[0] === '{') {
        const [ks, vs] = splitSignature(elem.slice(1, -1)) as [string, string];
        const entries: [DValue, DValue][] = v instanceof Map ? [...(v as Map<DValue, DValue>).entries()] : Array.isArray(v) ? (v as DValue[]).map((e) => e as unknown as [DValue, DValue]) : Object.entries(v as Record<string, DValue>);
        for (const [k, val] of entries) { w.pad(8); writeValue(w, ks, ks === 's' || ks === 'o' || ks === 'g' ? k : Number(k), depth + 1); writeValue(w, vs, val, depth + 1); }
      } else {
        if (!Array.isArray(v)) throw new InputError('expected an array');
        for (const x of v) writeValue(w, elem, x, depth + 1);
      }
      const n = w.len - start;
      if (n > MAX_ARRAY) throw new InputError('array too large');
      w.setU32(lenAt, n); return;
    }
    case '(': {
      const parts = splitSignature(sig.slice(1, -1));
      if (!Array.isArray(v) || v.length !== parts.length) throw new InputError(`struct ${sig} needs ${parts.length} members`);
      w.pad(8); parts.forEach((p, i) => writeValue(w, p, v[i]!, depth + 1)); return;
    }
    default: throw new InputError(`cannot write type ${c}`);
  }
}

function guessVariant(v: DValue): Variant {
  if (typeof v === 'string') return new Variant('s', v);
  if (typeof v === 'boolean') return new Variant('b', v);
  if (typeof v === 'number') return Number.isInteger(v) ? new Variant('i', v) : new Variant('d', v);
  if (typeof v === 'bigint') return new Variant('x', v);
  if (v instanceof Uint8Array) return new Variant('ay', v);
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return new Variant('as', v);
  if (v && typeof v === 'object' && !Array.isArray(v)) return new Variant('a{sv}', v);
  throw new InputError('cannot guess a variant type; wrap the value in Variant');
}

const FIELD = { path: [1, 'o'], interface: [2, 's'], member: [3, 's'], errorName: [4, 's'], replySerial: [5, 'u'], destination: [6, 's'], sender: [7, 's'], signature: [8, 'g'], unixFds: [9, 'u'] } as const;

/** Encode one message (little endian). */
export function encodeMessage(m: Omit<DMessage, 'body'> & { body?: DValue[] }): Uint8Array {
  const body = new Writer();
  const sigs = m.signature ? splitSignature(m.signature) : [];
  const vals = m.body ?? [];
  if (sigs.length !== vals.length) throw new InputError(`signature ${m.signature ?? ''} has ${sigs.length} values, got ${vals.length}`);
  sigs.forEach((s, i) => writeValue(body, s, vals[i]!, 0));
  const w = new Writer();
  w.u8(0x6c); w.u8(m.type); w.u8(m.flags); w.u8(1); w.u32(body.len); w.u32(m.serial);
  const fields: [number, Variant][] = [];
  for (const [k, [code, sig]] of Object.entries(FIELD)) { const val = (m as unknown as Record<string, unknown>)[k]; if (val !== undefined && val !== '') fields.push([code, new Variant(sig, val as DValue)]); }
  writeValue(w, 'a(yv)', fields as unknown as DValue, 0);
  w.pad(8); w.bytes(body.out());
  return w.out();
}

// ---------------- reader ----------------

class Reader {
  dv: DataView; pos = 0;
  constructor(public b: Uint8Array, public little: boolean, public base = 0) { this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength); }
  need(n: number) { if (this.pos + n > this.b.length) throw new InputError('message truncated'); }
  align(a: number) { const p = (a - ((this.pos - this.base) % a)) % a; this.need(p); this.pos += p; }
  u8() { this.need(1); return this.b[this.pos++]!; }
  u16(s = false) { this.align(2); this.need(2); const v = s ? this.dv.getInt16(this.pos, this.little) : this.dv.getUint16(this.pos, this.little); this.pos += 2; return v; }
  u32(s = false) { this.align(4); this.need(4); const v = s ? this.dv.getInt32(this.pos, this.little) : this.dv.getUint32(this.pos, this.little); this.pos += 4; return v; }
  u64(s = false) { this.align(8); this.need(8); const v = s ? this.dv.getBigInt64(this.pos, this.little) : this.dv.getBigUint64(this.pos, this.little); this.pos += 8; return v; }
  f64() { this.align(8); this.need(8); const v = this.dv.getFloat64(this.pos, this.little); this.pos += 8; return v; }
  str(n: number) { this.need(n + 1); const s = dec.decode(this.b.subarray(this.pos, this.pos + n)); this.pos += n + 1; return s; }
}

const big = (v: bigint): number | string => (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString());

function readValue(r: Reader, sig: string, depth: number, budget: { n: number }): DValue {
  if (depth > MAX_DEPTH) throw new InputError('value nested too deep');
  if (--budget.n < 0) throw new InputError('too many values in message');
  const c = sig[0]!;
  switch (c) {
    case 'y': return r.u8();
    case 'b': return r.u32() !== 0;
    case 'n': return r.u16(true);
    case 'q': return r.u16();
    case 'i': return r.u32(true);
    case 'u': case 'h': return r.u32();
    case 'x': return big(r.u64(true));
    case 't': return big(r.u64());
    case 'd': return r.f64();
    case 's': case 'o': { const n = r.u32(); return r.str(n); }
    case 'g': { const n = r.u8(); return r.str(n); }
    case 'v': { const s = r.str(r.u8()); if (splitSignature(s).length !== 1) throw new InputError('variant signature is not one type'); return readValue(r, s, depth + 1, budget); }
    case 'a': {
      const n = r.u32();
      if (n > MAX_ARRAY) throw new InputError('array too large');
      const elem = sig.slice(1);
      r.align(alignOf(elem[0]!));
      const end = r.pos + n;
      if (end > r.b.length) throw new InputError('array runs past the message');
      if (elem === 'y') { const b = r.b.slice(r.pos, end); r.pos = end; return b; }
      if (elem[0] === '{') {
        const [ks, vs] = splitSignature(elem.slice(1, -1)) as [string, string];
        const o: Record<string, DValue> = Object.create(null);
        while (r.pos < end) { r.align(8); const k = readValue(r, ks, depth + 1, budget); o[String(k)] = readValue(r, vs, depth + 1, budget); }
        if (r.pos !== end) throw new InputError('dict entries overrun the array');
        return o;
      }
      const out: DValue[] = [];
      while (r.pos < end) out.push(readValue(r, elem, depth + 1, budget));
      if (r.pos !== end) throw new InputError('array elements overrun the array');
      return out;
    }
    case '(': { r.align(8); return splitSignature(sig.slice(1, -1)).map((p) => readValue(r, p, depth + 1, budget)); }
    default: throw new InputError(`cannot read type ${c}`);
  }
}

/** Bytes needed for the complete message starting at buf[0], or 0 when the fixed header is not in yet. */
export function messageLength(buf: Uint8Array): number {
  if (buf.length < 16) return 0;
  const little = buf[0] === 0x6c;
  if (!little && buf[0] !== 0x42) throw new InputError('bad endianness byte');
  const dv = new DataView(buf.buffer, buf.byteOffset, 16);
  const bodyLen = dv.getUint32(4, little), fieldsLen = dv.getUint32(12, little);
  const headerEnd = 16 + fieldsLen + ((8 - ((16 + fieldsLen) % 8)) % 8);
  const total = headerEnd + bodyLen;
  if (total > MAX_MESSAGE) throw new InputError('message too large');
  return total;
}

/** Decode one complete message. */
export function decodeMessage(buf: Uint8Array): DMessage {
  const total = messageLength(buf);
  if (!total || total > buf.length) throw new InputError('message truncated');
  const little = buf[0] === 0x6c;
  const r = new Reader(buf.subarray(0, total), little);
  r.pos = 1;
  const type = r.u8(), flags = r.u8(), version = r.u8();
  if (version !== 1) throw new InputError(`unsupported protocol version ${version}`);
  const bodyLen = r.u32(), serial = r.u32();
  const budget = { n: 4_000_000 };
  const fields = readValue(r, 'a(yv)', 0, budget) as [number, DValue][];
  r.align(8);
  const m: DMessage = { type, flags, serial, body: [] };
  const names: Record<number, keyof DMessage> = { 1: 'path', 2: 'interface', 3: 'member', 4: 'errorName', 5: 'replySerial', 6: 'destination', 7: 'sender', 8: 'signature', 9: 'unixFds' };
  for (const [code, val] of fields) { const k = names[code]; if (k) (m as unknown as Record<string, unknown>)[k] = val; }
  if (r.pos + bodyLen !== total) throw new InputError('body length does not match');
  if (m.signature) {
    const br = new Reader(buf.subarray(r.pos, total), little);
    m.body = splitSignature(m.signature).map((s) => readValue(br, s, 0, budget));
    if (br.pos !== bodyLen) throw new InputError('body has trailing bytes');
  }
  return m;
}
