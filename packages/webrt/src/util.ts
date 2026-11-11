// Small shared helpers. No Node imports here: this file must load in a browser worker.

export const LIMITS = {
  /** largest input any parser in this package will look at */
  maxInputBytes: 256 * 1024 * 1024,
  /** largest JavaScript source we parse into an AST */
  maxJsBytes: 16 * 1024 * 1024,
  /** recursion cap for AST walks */
  maxAstDepth: 2000,
  /** visit cap for AST walks */
  maxAstNodes: 5_000_000,
  /** default page size for list outputs */
  defaultLimit: 200,
  maxLimit: 10_000,
};

export class InputError extends Error {}

export function clampLimit(limit: unknown, def = LIMITS.defaultLimit): number {
  const n = typeof limit === 'number' && Number.isFinite(limit) ? Math.floor(limit) : def;
  return Math.max(0, Math.min(n, LIMITS.maxLimit));
}

export function clampOffset(offset: unknown): number {
  const n = typeof offset === 'number' && Number.isFinite(offset) ? Math.floor(offset) : 0;
  return Math.max(0, n);
}

/** Return one page of a list plus paging info. */
export function page<T>(items: T[], offset?: unknown, limit?: unknown): { total: number; offset: number; limit: number; items: T[] } {
  const o = clampOffset(offset);
  const l = clampLimit(limit);
  return { total: items.length, offset: o, limit: l, items: items.slice(o, o + l) };
}

const utf8 = new TextDecoder('utf-8', { fatal: false });
const latin1 = new TextDecoder('latin1');

export function decodeUtf8(b: Uint8Array): string {
  return utf8.decode(b);
}
export function decodeLatin1(b: Uint8Array): string {
  return latin1.decode(b);
}
export function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function toBytes(x: Uint8Array | ArrayBuffer | string): Uint8Array {
  if (typeof x === 'string') return encodeUtf8(x);
  if (x instanceof Uint8Array) return x;
  return new Uint8Array(x);
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/=_-]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(b: Uint8Array): string {
  let s = '';
  const CH = 0x8000;
  for (let i = 0; i < b.length; i += CH) s += String.fromCharCode(...b.subarray(i, i + CH));
  return btoa(s);
}

export function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

/** Bounds-checked little/big endian reader over a byte array. Throws InputError when out of range. */
export class Reader {
  readonly dv: DataView;
  constructor(readonly b: Uint8Array) {
    this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  get length(): number { return this.b.length; }
  need(off: number, n: number): void {
    if (!(off >= 0 && n >= 0 && off + n <= this.b.length)) throw new InputError(`read past end (offset ${off}, length ${n}, size ${this.b.length})`);
  }
  u8(off: number): number { this.need(off, 1); return this.b[off] as number; }
  u16(off: number, le: boolean): number { this.need(off, 2); return this.dv.getUint16(off, le); }
  u32(off: number, le: boolean): number { this.need(off, 4); return this.dv.getUint32(off, le); }
  i32(off: number, le: boolean): number { this.need(off, 4); return this.dv.getInt32(off, le); }
  u64n(off: number, le: boolean): bigint { this.need(off, 8); return this.dv.getBigUint64(off, le); }
  f64(off: number, le: boolean): number { this.need(off, 8); return this.dv.getFloat64(off, le); }
  slice(off: number, n: number): Uint8Array { this.need(off, n); return this.b.subarray(off, off + n); }
}

// ---- MD5 (RFC 1321), used for JA3. Small self-contained implementation. ----
const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

export function md5Hex(input: Uint8Array | string): string {
  const msg = typeof input === 'string' ? encodeUtf8(input) : input;
  const len = msg.length;
  const padLen = (((len + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, (len * 8) >>> 0, true);
  dv.setUint32(padLen - 4, Math.floor(len / 0x20000000), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + (K[i] as number) + (M[g] as number)) >>> 0;
      A = D; D = C; C = B;
      const s = S[i] as number;
      B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, a0, true); ov.setUint32(4, b0, true); ov.setUint32(8, c0, true); ov.setUint32(12, d0, true);
  return hex(out);
}

/**
 * Normalize an archive or source-map path into a safe relative path.
 * Drops scheme prefixes like webpack://, removes drive letters, "..", "." and empty parts.
 * Returns '' when nothing safe is left.
 */
export function safeRelPath(p: string): string {
  let s = String(p).replace(/\\/g, '/');
  s = s.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/+/, '');
  s = s.replace(/^[a-zA-Z]:/, '');
  s = s.replace(/[\u0000-\u001f]/g, '_');
  const parts: string[] = [];
  for (const part of s.split('/')) {
    if (!part || part === '.' || part === '..' || part === '~') continue;
    parts.push(part.replace(/[<>:"|?*]/g, '_').slice(0, 200));
  }
  return parts.slice(0, 64).join('/');
}

export function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '...' : s;
}

/** Map a 0-based offset in text to 1-based line and column. Keeps a lazy index. */
export function lineIndex(text: string): (offset: number) => { line: number; column: number } {
  const starts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (offset: number) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((starts[mid] as number) <= offset) lo = mid; else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - (starts[lo] as number) };
  };
}
