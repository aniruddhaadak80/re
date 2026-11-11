// Shared helpers: a bounds checked byte reader, limits and paging. Pure, no Node built-ins.

/** Raised for malformed or truncated input. Every parser in this package throws only this. */
export class ParseError extends Error {
  constructor(message: string, readonly offset?: number) {
    super(offset === undefined ? message : `${message} (at 0x${offset.toString(16)})`);
    this.name = 'ParseError';
  }
}

/** Bounds checked little or big endian reader over a Uint8Array. */
export class ByteReader {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  pos: number;
  little: boolean;

  constructor(bytes: Uint8Array, pos = 0, little = true) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = pos;
    this.little = little;
  }

  get length(): number { return this.bytes.length; }
  remaining(): number { return this.bytes.length - this.pos; }
  eof(): boolean { return this.pos >= this.bytes.length; }

  need(n: number, at = this.pos): void {
    if (!Number.isFinite(n) || n < 0 || at < 0 || at + n > this.bytes.length) {
      throw new ParseError(`read of ${n} bytes past end`, at);
    }
  }
  seek(p: number): this {
    if (p < 0 || p > this.bytes.length) throw new ParseError('seek out of range', p);
    this.pos = p; return this;
  }
  skip(n: number): this { this.need(n); this.pos += n; return this; }

  u8(): number { this.need(1); return this.bytes[this.pos++] as number; }
  i8(): number { this.need(1); return this.view.getInt8(this.pos++); }
  u16(): number { this.need(2); const v = this.view.getUint16(this.pos, this.little); this.pos += 2; return v; }
  i16(): number { this.need(2); const v = this.view.getInt16(this.pos, this.little); this.pos += 2; return v; }
  u32(): number { this.need(4); const v = this.view.getUint32(this.pos, this.little); this.pos += 4; return v; }
  i32(): number { this.need(4); const v = this.view.getInt32(this.pos, this.little); this.pos += 4; return v; }
  u64(): bigint { this.need(8); const v = this.view.getBigUint64(this.pos, this.little); this.pos += 8; return v; }
  i64(): bigint { this.need(8); const v = this.view.getBigInt64(this.pos, this.little); this.pos += 8; return v; }
  f32(): number { this.need(4); const v = this.view.getFloat32(this.pos, this.little); this.pos += 4; return v; }
  f64(): number { this.need(8); const v = this.view.getFloat64(this.pos, this.little); this.pos += 8; return v; }
  take(n: number): Uint8Array { this.need(n); const s = this.bytes.subarray(this.pos, this.pos + n); this.pos += n; return s; }

  /** Read an unsigned value of 1, 2 or 4 bytes. */
  uN(size: number): number { return size === 1 ? this.u8() : size === 2 ? this.u16() : this.u32(); }

  /** NUL terminated string, at most maxLen bytes scanned. */
  cstr(maxLen = 4096): string {
    const start = this.pos;
    const end = Math.min(this.bytes.length, start + maxLen);
    let i = start;
    while (i < end && this.bytes[i] !== 0) i++;
    const s = utf8(this.bytes.subarray(start, i));
    this.pos = i < this.bytes.length ? i + 1 : i;
    return s;
  }
}

const dec = new TextDecoder('utf-8', { fatal: false });
const decLatin1 = new TextDecoder('latin1');
export function utf8(b: Uint8Array): string { return dec.decode(b); }
export function latin1(b: Uint8Array): string { return decLatin1.decode(b); }
export function utf16le(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] as number) | ((b[i + 1] as number) << 8));
  return s;
}

export function hex(b: Uint8Array, start = 0, end = b.length): string {
  let s = '';
  for (let i = Math.max(0, start); i < Math.min(end, b.length); i++) s += (b[i] as number).toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(h: string): Uint8Array {
  let clean = h.trim();
  if (clean.startsWith('0x') || clean.startsWith('0X')) clean = clean.slice(2);
  clean = clean.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) clean = clean.slice(0, -1);
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function hex32(n: number): string { return '0x' + (n >>> 0).toString(16).padStart(8, '0'); }

export function indexOfBytes(hay: Uint8Array, needle: Uint8Array, from = 0, to = hay.length): number {
  const n = needle.length;
  if (n === 0) return from;
  const first = needle[0] as number;
  const last = Math.min(to, hay.length) - n;
  let i = hay.indexOf(first, from);
  while (i >= 0 && i <= last) {
    let j = 1;
    while (j < n && hay[i + j] === needle[j]) j++;
    if (j === n) return i;
    i = hay.indexOf(first, i + 1);
  }
  return -1;
}

export function lastIndexOfBytes(hay: Uint8Array, needle: Uint8Array, from = hay.length - needle.length): number {
  const n = needle.length;
  for (let i = Math.min(from, hay.length - n); i >= 0; i--) {
    let j = 0;
    while (j < n && hay[i + j] === needle[j]) j++;
    if (j === n) return i;
  }
  return -1;
}

export function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export interface Page<T> { total: number; offset: number; limit: number; items: T[]; truncated: boolean }

/** Slice an array for paged tool output. */
export function page<T>(items: T[], offset = 0, limit = 200, max = 5000): Page<T> {
  const o = Math.max(0, Math.floor(Number(offset) || 0));
  const l = Math.min(max, Math.max(1, Math.floor(Number(limit) || 200)));
  const slice = items.slice(o, o + l);
  return { total: items.length, offset: o, limit: l, items: slice, truncated: o + slice.length < items.length };
}

/** Hard caps shared by every parser. Kept generous for real files and small enough to stop hostile counts. */
export const LIMITS = {
  maxRowsPerTable: 1 << 22,
  maxDepth: 64,
  maxMarshalObjects: 2_000_000,
  maxInstructions: 200_000,
  maxEntries: 100_000,
  maxOutputBytes: 512 * 1024 * 1024,
  maxStringLen: 1 << 20,
};

export function errMsg(e: unknown): string { return e instanceof Error ? e.message : String(e); }

/** Accept Uint8Array, ArrayBuffer, number[] or base64 / hex string. */
export function toBytes(input: unknown): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (Array.isArray(input)) return Uint8Array.from(input as number[]);
  throw new ParseError('expected bytes');
}
