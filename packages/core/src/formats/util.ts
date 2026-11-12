// Shared helpers for the container format readers: bounds checked big and little endian reads,
// base64, CRC-32 and a hard error type that carries the file offset.

export class FormatError extends Error {
  constructor(message: string, readonly offset?: number) { super(offset === undefined ? message : `${message} (at offset ${offset})`); }
}

/** Bounds checked reads over a byte array. Every read throws FormatError instead of returning garbage. */
export class BinView {
  readonly dv: DataView;
  constructor(readonly bytes: Uint8Array) { this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }
  get length(): number { return this.bytes.length; }
  has(off: number, len: number): boolean { return off >= 0 && len >= 0 && off + len <= this.bytes.length; }
  need(off: number, len: number): void { if (!this.has(off, len)) throw new FormatError(`read of ${len} bytes past the end`, off); }
  u8(o: number): number { this.need(o, 1); return this.bytes[o] as number; }
  u16be(o: number): number { this.need(o, 2); return this.dv.getUint16(o, false); }
  u32be(o: number): number { this.need(o, 4); return this.dv.getUint32(o, false); }
  u64be(o: number): number { this.need(o, 8); return this.dv.getUint32(o, false) * 4294967296 + this.dv.getUint32(o + 4, false); }
  u16le(o: number): number { this.need(o, 2); return this.dv.getUint16(o, true); }
  u32le(o: number): number { this.need(o, 4); return this.dv.getUint32(o, true); }
  u64le(o: number): number { this.need(o, 8); return this.dv.getUint32(o + 4, true) * 4294967296 + this.dv.getUint32(o, true); }
  sub(o: number, len: number): Uint8Array { this.need(o, len); return this.bytes.subarray(o, o + len); }
  ascii(o: number, len: number): string { const b = this.sub(o, len); let s = ''; for (let i = 0; i < b.length; i++) { const c = b[i] as number; if (c === 0) break; s += String.fromCharCode(c); } return s; }
  hex(o: number, len: number): string { return toHex(this.sub(o, len)); }
}

export function toHex(b: Uint8Array): string {
  const H = '0123456789abcdef';
  const out: string[] = new Array(b.length);
  for (let i = 0; i < b.length; i++) { const v = b[i] as number; out[i] = (H[v >> 4] as string) + (H[v & 15] as string); }
  return out.join('');
}

const B64 = new Int16Array(256).fill(-1);
for (let i = 0; i < 64; i++) B64['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.charCodeAt(i)] = i;
B64['-'.charCodeAt(0)] = 62; B64['_'.charCodeAt(0)] = 63;

/** Decode base64 (standard or URL alphabet), skipping whitespace and stopping at padding. */
export function base64Decode(s: string, maxOut = 256 * 1024 * 1024): Uint8Array {
  const out = new Uint8Array(Math.min(maxOut, Math.floor((s.length * 3) / 4) + 3));
  let acc = 0, bits = 0, o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x3d) break;
    const v = c < 256 ? (B64[c] as number) : -1;
    if (v < 0) continue;
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) { bits -= 8; if (o >= out.length) break; out[o++] = (acc >> bits) & 0xff; }
  }
  return out.subarray(0, o);
}

let CRC_TABLE: Uint32Array | undefined;
/** CRC-32 (IEEE 802.3, the zlib and UDIF checksum). */
export function crc32(b: Uint8Array, seed = 0): number {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n] = c >>> 0; }
  }
  const t = CRC_TABLE;
  let c = (seed ^ 0xffffffff) >>> 0;
  for (let i = 0; i < b.length; i++) c = (t[(c ^ (b[i] as number)) & 0xff] as number) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** UTF-16 big endian text. */
export function utf16be(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(((b[i] as number) << 8) | (b[i + 1] as number));
  return s;
}

/** Join byte chunks into one array. */
export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Normalize a member path: forward slashes, no leading slash, no empty or dot segments. Keeps ".." so callers can flag it. */
export function normPath(p: string): string {
  return p.replace(/\\/g, '/').split('/').filter((s) => s && s !== '.').join('/');
}

/** ISO 8601 UTC text from epoch milliseconds, built by hand so the result never depends on the runtime's Date formatting. */
export function isoUtc(ms: number): string {
  const d = new Date(ms);
  if (!Number.isFinite(d.getTime())) return '';
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return `${p(d.getUTCFullYear(), 4)}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}Z`;
}
