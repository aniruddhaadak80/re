// Bounds-checked byte helpers shared by every parser in this package.
// Pure TypeScript, no Node built-ins, safe to run in a browser Web Worker.

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

/** Random-access little or big endian reader that throws ParseError on any out of range read. */
export class Buf {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  readonly little: boolean;

  constructor(bytes: Uint8Array, little = true) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.little = little;
  }

  get length(): number { return this.bytes.length; }

  check(off: number, n: number): void {
    if (!Number.isInteger(off) || off < 0 || n < 0 || off + n > this.bytes.length) {
      throw new ParseError(`read of ${n} bytes at offset ${off} is outside the ${this.bytes.length} byte buffer`);
    }
  }

  has(off: number, n: number): boolean {
    return Number.isInteger(off) && off >= 0 && n >= 0 && off + n <= this.bytes.length;
  }

  u8(off: number): number { this.check(off, 1); return this.bytes[off] as number; }
  i8(off: number): number { this.check(off, 1); return this.view.getInt8(off); }
  u16(off: number): number { this.check(off, 2); return this.view.getUint16(off, this.little); }
  i16(off: number): number { this.check(off, 2); return this.view.getInt16(off, this.little); }
  u32(off: number): number { this.check(off, 4); return this.view.getUint32(off, this.little); }
  i32(off: number): number { this.check(off, 4); return this.view.getInt32(off, this.little); }
  u64(off: number): bigint { this.check(off, 8); return this.view.getBigUint64(off, this.little); }
  i64(off: number): bigint { this.check(off, 8); return this.view.getBigInt64(off, this.little); }
  f32(off: number): number { this.check(off, 4); return this.view.getFloat32(off, this.little); }
  f64(off: number): number { this.check(off, 8); return this.view.getFloat64(off, this.little); }

  slice(off: number, n: number): Uint8Array { this.check(off, n); return this.bytes.subarray(off, off + n); }

  /** Unsigned LEB128. Returns value and the number of bytes consumed. */
  uleb(off: number): [number, number] {
    let result = 0;
    let shift = 0;
    let i = 0;
    for (;;) {
      const b = this.u8(off + i);
      i++;
      result += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (i >= 5) break;
    }
    return [result >>> 0, i];
  }

  /** Signed LEB128 (32-bit). */
  sleb(off: number): [number, number] {
    let result = 0;
    let shift = 0;
    let i = 0;
    let b = 0;
    for (;;) {
      b = this.u8(off + i);
      i++;
      result |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0 || i >= 5) break;
    }
    if (shift < 32 && (b & 0x40)) result |= -1 << shift;
    return [result | 0, i];
  }

  /** NUL-terminated ASCII or UTF-8 string, capped at `max` bytes. */
  cstr(off: number, max = 4096): string {
    this.check(off, 0);
    let end = off;
    const lim = Math.min(this.bytes.length, off + max);
    while (end < lim && this.bytes[end] !== 0) end++;
    return utf8(this.bytes.subarray(off, end));
  }
}

const utf8Dec = new TextDecoder('utf-8', { fatal: false });
const utf16Dec = new TextDecoder('utf-16le', { fatal: false });

export function utf8(b: Uint8Array): string { return utf8Dec.decode(b); }
export function utf16le(b: Uint8Array): string { return utf16Dec.decode(b); }

export function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function hex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += (b[i] as number).toString(16).padStart(2, '0');
  return s;
}

export function startsWith(b: Uint8Array, prefix: ArrayLike<number>, at = 0): boolean {
  if (at + prefix.length > b.length) return false;
  for (let i = 0; i < prefix.length; i++) if (b[at + i] !== prefix[i]) return false;
  return true;
}

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

/** SHA-256 / SHA-1 through WebCrypto, available in browsers, workers and Node 20+. */
export async function digest(alg: 'SHA-256' | 'SHA-1', data: Uint8Array): Promise<string> {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto is not available in this runtime');
  const buf = await subtle.digest(alg, data as unknown as BufferSource);
  return hex(new Uint8Array(buf));
}

/**
 * Decode Modified UTF-8 (used by DEX string_data and Java class files).
 * Handles 1, 2 and 3 byte forms including surrogate pairs encoded as two 3-byte units and 0xC0 0x80 for NUL.
 */
export function mutf8(b: Uint8Array, start = 0, end = b.length, maxChars = 1 << 20): string {
  let out = '';
  const parts: string[] = [];
  let i = start;
  let count = 0;
  while (i < end && count < maxChars) {
    const a = b[i] as number;
    let c: number;
    if (a < 0x80) { c = a; i += 1; }
    else if ((a & 0xe0) === 0xc0 && i + 1 < end) { c = ((a & 0x1f) << 6) | ((b[i + 1] as number) & 0x3f); i += 2; }
    else if ((a & 0xf0) === 0xe0 && i + 2 < end) { c = ((a & 0x0f) << 12) | (((b[i + 1] as number) & 0x3f) << 6) | ((b[i + 2] as number) & 0x3f); i += 3; }
    else { c = 0xfffd; i += 1; }
    out += String.fromCharCode(c);
    count++;
    if (out.length >= 4096) { parts.push(out); out = ''; }
  }
  parts.push(out);
  return parts.join('');
}

/** Small time and count budget used to stop runaway loops on hostile input. */
export class Budget {
  private readonly deadline: number;
  constructor(ms = 20_000) { this.deadline = Date.now() + ms; }
  check(what = 'operation'): void {
    if (Date.now() > this.deadline) throw new ParseError(`${what} passed its time budget`);
  }
}

export function clampInt(v: unknown, def: number, min: number, max: number): number {
  const n = typeof v === 'number' && Number.isFinite(v) ? Math.floor(v) : def;
  return Math.max(min, Math.min(max, n));
}
