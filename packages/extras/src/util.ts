// Shared, browser safe helpers for @revlens/extras. Every read is bounds checked.

export class ParseError extends Error {
  constructor(message: string, readonly offset?: number) {
    super(offset === undefined ? message : `${message} at 0x${offset.toString(16)}`);
    this.name = 'ParseError';
  }
}

/** Bounds checked little or big endian view over a byte array. */
export class View {
  readonly dv: DataView;
  constructor(readonly bytes: Uint8Array, public le = true) {
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  get length(): number { return this.bytes.length; }
  has(off: number, n: number): boolean { return Number.isInteger(off) && off >= 0 && n >= 0 && off + n <= this.bytes.length; }
  need(off: number, n: number): void { if (!this.has(off, n)) throw new ParseError(`read of ${n} bytes out of range`, off); }
  u8(o: number): number { this.need(o, 1); return this.bytes[o] as number; }
  u16(o: number, le = this.le): number { this.need(o, 2); return this.dv.getUint16(o, le); }
  i16(o: number, le = this.le): number { this.need(o, 2); return this.dv.getInt16(o, le); }
  u32(o: number, le = this.le): number { this.need(o, 4); return this.dv.getUint32(o, le); }
  i32(o: number, le = this.le): number { this.need(o, 4); return this.dv.getInt32(o, le); }
  u64(o: number, le = this.le): bigint { this.need(o, 8); return this.dv.getBigUint64(o, le); }
  /** 64 bit value as a JS number; throws when it does not fit safely. */
  u64n(o: number, le = this.le): number {
    const v = this.u64(o, le);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ParseError('64 bit value too large', o);
    return Number(v);
  }
  uN(o: number, size: number, le = this.le): number { return size === 8 ? this.u64n(o, le) : size === 4 ? this.u32(o, le) : size === 2 ? this.u16(o, le) : this.u8(o); }
  sub(o: number, n: number): Uint8Array { this.need(o, n); return this.bytes.subarray(o, o + n); }
  /** NUL terminated string, latin1, capped. */
  cstr(o: number, max = 4096): string {
    if (o < 0 || o >= this.bytes.length) throw new ParseError('string offset out of range', o);
    let s = '';
    const end = Math.min(this.bytes.length, o + max);
    for (let i = o; i < end; i++) {
      const c = this.bytes[i] as number;
      if (c === 0) return s;
      s += String.fromCharCode(c);
    }
    return s;
  }
  /** NUL terminated UTF-8 string, capped. */
  utf8z(o: number, max = 4096): string {
    if (o < 0 || o >= this.bytes.length) throw new ParseError('string offset out of range', o);
    const end = Math.min(this.bytes.length, o + max);
    let i = o;
    while (i < end && this.bytes[i] !== 0) i++;
    return utf8(this.bytes.subarray(o, i));
  }
  utf16(o: number, chars: number, le = true): string {
    this.need(o, chars * 2);
    let s = '';
    for (let i = 0; i < chars; i++) s += String.fromCharCode(this.dv.getUint16(o + i * 2, le));
    return s;
  }
  /** NUL terminated UTF-16LE string, capped in characters. */
  utf16z(o: number, max = 4096): string {
    let s = '';
    for (let i = 0; i < max; i++) {
      if (!this.has(o + i * 2, 2)) break;
      const c = this.dv.getUint16(o + i * 2, true);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }
}

const dec = new TextDecoder('utf-8', { fatal: false });
export function utf8(b: Uint8Array): string { return dec.decode(b); }
export function latin1(b: Uint8Array): string { let s = ''; for (const c of b) s += String.fromCharCode(c); return s; }
export function hexs(n: number | bigint, pad = 0): string { return '0x' + n.toString(16).padStart(pad, '0'); }
export function toHex(b: Uint8Array): string { let s = ''; for (const c of b) s += c.toString(16).padStart(2, '0'); return s; }
export function fromHex(h: string): Uint8Array {
  const clean = h.replace(/\s+/g, '');
  if (clean.length % 2 || /[^0-9a-fA-F]/.test(clean)) throw new ParseError('invalid hex string');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function ascii(s: string): Uint8Array { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff; return o; }
export function startsWithBytes(b: Uint8Array, sig: ArrayLike<number>, at = 0): boolean {
  if (at < 0 || at + sig.length > b.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig[i]) return false;
  return true;
}
export function indexOfBytes(h: Uint8Array, n: Uint8Array, from = 0, to = h.length): number {
  if (n.length === 0) return -1;
  const first = n[0] as number;
  const last = Math.min(to, h.length) - n.length;
  outer: for (let i = Math.max(0, from); i <= last; i++) {
    if (h[i] !== first) continue;
    for (let j = 1; j < n.length; j++) if (h[i + j] !== n[j]) continue outer;
    return i;
  }
  return -1;
}
/** Microsoft style GUID text from 16 bytes (first three fields little endian). */
export function guid(b: Uint8Array, o = 0): string {
  const v = new View(b);
  const d1 = v.u32(o).toString(16).padStart(8, '0');
  const d2 = v.u16(o + 4).toString(16).padStart(4, '0');
  const d3 = v.u16(o + 6).toString(16).padStart(4, '0');
  const r = toHex(v.sub(o + 8, 8));
  return `${d1}-${d2}-${d3}-${r.slice(0, 4)}-${r.slice(4)}`.toUpperCase();
}
export function align(n: number, a: number): number { return Math.ceil(n / a) * a; }

/** Windows FILETIME (100ns since 1601) to ISO string, or null when zero or out of range. */
export function filetime(lo: number, hi: number): string | null {
  const t = (BigInt(hi) << 32n) | BigInt(lo);
  if (t === 0n) return null;
  const ms = Number(t / 10000n) - 11644473600000;
  if (!Number.isFinite(ms) || ms < -8.64e15 || ms > 8.64e15) return null;
  return new Date(ms).toISOString();
}
export function unixTime(sec: number): string | null {
  if (!Number.isFinite(sec) || sec <= 0 || sec > 8.64e12) return null;
  return new Date(sec * 1000).toISOString();
}

/** CRC-32 (IEEE), as used by uImage, zip, UEFI and many others. */
let crcTable: Uint32Array | undefined;
export function crc32(b: Uint8Array, start = 0, end = b.length): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[i] = c >>> 0; }
  }
  let c = 0xffffffff;
  for (let i = start; i < end; i++) c = (crcTable[(c ^ (b[i] as number)) & 0xff] as number) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Decompress zlib, gzip or raw deflate with the platform DecompressionStream, capped. */
export async function inflate(data: Uint8Array, kind: 'gzip' | 'deflate' | 'deflate-raw', maxOut = 64 << 20): Promise<Uint8Array> {
  const DS = (globalThis as { DecompressionStream?: new (f: string) => TransformStream<Uint8Array, Uint8Array> }).DecompressionStream;
  if (!DS) throw new ParseError('DecompressionStream is not available in this runtime');
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DS(kind));
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxOut) { await reader.cancel(); throw new ParseError(`decompressed size over ${maxOut} bytes`); }
      parts.push(value);
    }
  } catch (e) {
    if (e instanceof ParseError) throw e;
    // keep what was decoded before a trailing error (common with appended garbage)
    if (!parts.length) throw new ParseError(`decompression failed: ${(e as Error).message}`);
  }
  const out = new Uint8Array(total);
  let p = 0;
  for (const part of parts) { out.set(part, p); p += part.length; }
  return out;
}

/** Page a list for agent tools. */
export function page<T>(items: T[], offset = 0, limit = 200): { total: number; offset: number; limit: number; items: T[] } {
  const o = Math.max(0, Math.floor(offset || 0));
  const l = Math.max(1, Math.min(5000, Math.floor(limit || 200)));
  return { total: items.length, offset: o, limit: l, items: items.slice(o, o + l) };
}

export type InputSpec = { type: 'string' | 'number' | 'boolean' | 'array' | 'object'; description: string; optional?: boolean };
export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, InputSpec>;
  run: (input: any) => Promise<unknown>;
}
export interface CliCommand {
  name: string;
  usage: string;
  summary: string;
  run(argv: string[]): Promise<number>;
}

/** Bytes from a tool input: base64 `bytes`, hex `hex`, or a `path` read through the injected loader. */
export type FileLoader = (path: string) => Promise<Uint8Array>;
let loader: FileLoader | undefined;
export function setFileLoader(fn: FileLoader): void { loader = fn; }
export async function inputBytes(input: { path?: string; bytes?: string; hex?: string }): Promise<Uint8Array> {
  if (typeof input?.bytes === 'string') {
    const bin = atob(input.bytes);
    const o = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i);
    return o;
  }
  if (typeof input?.hex === 'string') return fromHex(input.hex);
  if (typeof input?.path === 'string') {
    if (loader) return loader(input.path);
    const fs = await import(/* @vite-ignore */ 'node:fs/promises' as string).catch(() => undefined) as { readFile?: (p: string) => Promise<Uint8Array> } | undefined;
    if (fs?.readFile) return new Uint8Array(await fs.readFile(input.path));
    throw new ParseError('no file loader in this runtime; pass bytes (base64) instead of path');
  }
  throw new ParseError('pass path, bytes (base64) or hex');
}
export const PATH_INPUT: Record<string, InputSpec> = {
  path: { type: 'string', description: 'Local file path to read', optional: true },
  bytes: { type: 'string', description: 'File content as base64, instead of path', optional: true },
};

/** Shannon entropy in bits per byte. */
export function entropyOf(b: Uint8Array): number {
  if (!b.length) return 0;
  const f = new Uint32Array(256);
  for (const c of b) f[c]!++;
  let e = 0;
  for (const n of f) { if (n) { const p = n / b.length; e -= p * Math.log2(p); } }
  return e;
}
