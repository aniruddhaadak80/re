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

// ---- SHA-256 (FIPS 180-4), synchronous so it works in a worker without WebCrypto promises. ----
const K256 = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

/** SHA-256 of bytes or of a string's UTF-8 encoding, as lowercase hex. */
export function sha256Hex(input: Uint8Array | string): string {
  const msg = typeof input === 'string' ? encodeUtf8(input) : input;
  const len = msg.length;
  const padLen = (((len + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, Math.floor(len / 0x20000000), false);
  dv.setUint32(padLen - 4, (len * 8) >>> 0, false);
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const w15 = W[i - 15] as number, w2 = W[i - 2] as number;
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
      W[i] = ((W[i - 16] as number) + s0 + (W[i - 7] as number) + s1) >>> 0;
    }
    let a = H[0] as number, b = H[1] as number, c = H[2] as number, d = H[3] as number, e = H[4] as number, f = H[5] as number, g = H[6] as number, h = H[7] as number;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + (K256[i] as number) + (W[i] as number)) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = ((H[0] as number) + a) >>> 0; H[1] = ((H[1] as number) + b) >>> 0; H[2] = ((H[2] as number) + c) >>> 0; H[3] = ((H[3] as number) + d) >>> 0;
    H[4] = ((H[4] as number) + e) >>> 0; H[5] = ((H[5] as number) + f) >>> 0; H[6] = ((H[6] as number) + g) >>> 0; H[7] = ((H[7] as number) + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i] as number, false);
  return hex(out);
}
