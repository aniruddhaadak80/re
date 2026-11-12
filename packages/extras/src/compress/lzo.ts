// LZO1X decompression (the format squashfs, UBIFS, lzop and many routers use), written from the
// stream description in the Linux kernel documentation (Documentation/staging/lzo.rst), plus the
// lzop container. Bounds checked and capped.

import { ParseError, crc32 } from '../util.js';
import { OutputLimitError } from './inflate.js';

/** Decompress a raw LZO1X stream. Returns the output and the input offset after the end marker. */
export function lzo1xDecompress(src: Uint8Array, opts: { start?: number; end?: number; maxOut?: number; expectedSize?: number } = {}): { data: Uint8Array; end: number } {
  const end = Math.min(src.length, opts.end ?? src.length);
  const maxOut = opts.maxOut ?? 64 << 20;
  let out = new Uint8Array(Math.min(maxOut, opts.expectedSize ?? Math.max(1024, (end - (opts.start ?? 0)) * 4)));
  let op = 0;
  let ip = opts.start ?? 0;
  const need = (n: number) => {
    if (op + n <= out.length) return;
    if (op + n > maxOut) throw new OutputLimitError(maxOut);
    let cap = out.length * 2;
    while (cap < op + n) cap *= 2;
    const nb = new Uint8Array(Math.min(maxOut, cap));
    nb.set(out.subarray(0, op));
    out = nb;
  };
  const byte = (): number => { if (ip >= end) throw new ParseError('LZO stream is truncated'); return src[ip++] as number; };
  const lit = (n: number) => {
    if (ip + n > end) throw new ParseError('LZO literal run past the input');
    need(n);
    out.set(src.subarray(ip, ip + n), op);
    op += n; ip += n;
  };
  const copy = (dist: number, n: number) => {
    if (dist < 1 || dist > op) throw new ParseError('LZO match distance before the start of the output');
    need(n);
    let s = op - dist;
    for (let k = 0; k < n; k++) out[op++] = out[s++] as number;
  };
  const ext = (base: number): number => {
    let n = 0, b: number;
    while ((b = byte()) === 0) { n += 255; if (n > 0x7fffffff) throw new ParseError('LZO length overflow'); }
    return base + n + b;
  };
  let state = 0;
  // first byte
  if (ip < end && (src[ip] as number) > 17) {
    const t = byte() - 17;
    lit(t);
    state = t < 4 ? t : 4;
  }
  for (let guard = 0; ; guard++) {
    if (guard > 0x7fffffff) throw new ParseError('LZO loop guard');
    const op0 = byte();
    if (op0 < 16) {
      if (state === 0) {
        const len = (op0 === 0 ? ext(15) : op0) + 3;
        lit(len);
        state = 4;
        continue;
      }
      const h = byte();
      const s = op0 & 3;
      if (state < 4) copy((h << 2) + ((op0 >> 2) & 3) + 1, 2);
      else copy((h << 2) + ((op0 >> 2) & 3) + 2049, 3);
      lit(s);
      state = s;
      continue;
    }
    let len: number, dist: number, s: number;
    if (op0 < 32) {
      len = ((op0 & 7) === 0 ? ext(7) : op0 & 7) + 2;
      const v = byte() | (byte() << 8);
      s = v & 3;
      dist = 16384 + ((op0 & 8) << 11) + (v >> 2);
      if (dist === 16384) {
        if (len !== 3) throw new ParseError('bad LZO end marker');
        break;
      }
    } else if (op0 < 64) {
      len = ((op0 & 31) === 0 ? ext(31) : op0 & 31) + 2;
      const v = byte() | (byte() << 8);
      s = v & 3;
      dist = (v >> 2) + 1;
    } else if (op0 < 128) {
      len = 3 + ((op0 >> 5) & 1);
      s = op0 & 3;
      dist = (byte() << 3) + ((op0 >> 2) & 7) + 1;
    } else {
      len = 5 + ((op0 >> 5) & 3);
      s = op0 & 3;
      dist = (byte() << 3) + ((op0 >> 2) & 7) + 1;
    }
    copy(dist, len);
    lit(s);
    state = s;
  }
  if (opts.expectedSize !== undefined && op !== opts.expectedSize) throw new ParseError(`LZO output is ${op} bytes, expected ${opts.expectedSize}`);
  return { data: out.slice(0, op), end: ip };
}

const adler32 = (d: Uint8Array): number => {
  let a = 1, b = 0;
  for (let k = 0; k < d.length;) {
    const stop = Math.min(d.length, k + 3800);
    for (; k < stop; k++) { a += d[k] as number; b += a; }
    a %= 65521; b %= 65521;
  }
  return ((b << 16) | a) >>> 0;
};

export const LZOP_MAGIC = [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

export interface LzopFile { name: string; mtime: number; method: number; level: number; flags: number; blocks: number; data: Uint8Array; end: number; checksumsValid: boolean | null }

/** Decode an lzop file (methods 1-3 are LZO1X). */
export function lzopDecode(b: Uint8Array, opts: { start?: number; maxOut?: number } = {}): LzopFile {
  const s = opts.start ?? 0;
  if (LZOP_MAGIC.some((m, k) => b[s + k] !== m)) throw new ParseError('not an lzop file', s);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const has = (o: number, n: number) => { if (o + n > b.length) throw new ParseError('lzop header truncated', o); };
  let p = s + 9;
  has(p, 16);
  const version = dv.getUint16(p);
  p += 2; // version
  p += 2; // lib version
  if (version >= 0x0940) p += 2; // version needed
  const method = b[p++] as number;
  const level = version >= 0x0940 ? (b[p++] as number) : 0;
  const flags = dv.getUint32(p); p += 4;
  if (flags & 0x800) p += 4; // filter
  p += 4; // mode
  const mtime = dv.getUint32(p); p += 4;
  if (version >= 0x0940) p += 4; // mtime high
  has(p, 1);
  const nl = b[p++] as number;
  has(p, nl + 4);
  const name = new TextDecoder().decode(b.subarray(p, p + nl));
  p += nl + 4; // header checksum
  if (flags & 0x40) { has(p, 4); p += 4 + dv.getUint32(p) + 4; } // extra field
  if (method < 1 || method > 3) throw new ParseError(`lzop method ${method} is not LZO1X`);
  const parts: Uint8Array[] = [];
  let total = 0, blocks = 0;
  let ok: boolean | null = null;
  const maxOut = opts.maxOut ?? 256 << 20;
  for (;;) {
    has(p, 4);
    const usize = dv.getUint32(p); p += 4;
    if (usize === 0) break;
    if (usize > 64 << 20) throw new ParseError('lzop block too large');
    if (total + usize > maxOut) throw new OutputLimitError(maxOut);
    has(p, 4);
    const csize = dv.getUint32(p); p += 4;
    let ucheck: number | undefined, ccheck: number | undefined;
    if (flags & 0x1 || flags & 0x100) { has(p, 4); ucheck = dv.getUint32(p); p += 4; }
    if ((flags & 0x2 || flags & 0x200) && csize < usize) { has(p, 4); ccheck = dv.getUint32(p); p += 4; }
    has(p, csize);
    const data = csize < usize ? lzo1xDecompress(b, { start: p, end: p + csize, expectedSize: usize, maxOut: usize }).data : b.slice(p, p + csize);
    if (ucheck !== undefined) {
      const v = flags & 0x100 ? crc32(data) >>> 0 : adler32(data);
      ok = (ok ?? true) && v === ucheck;
    }
    void ccheck;
    p += csize;
    parts.push(data);
    total += data.length;
    blocks++;
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const d of parts) { out.set(d, o); o += d.length; }
  return { name, mtime, method, level, flags, blocks, data: out, end: p, checksumsValid: ok };
}
