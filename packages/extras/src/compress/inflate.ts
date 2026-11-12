// Synchronous DEFLATE (RFC 1951) decoder with zlib (RFC 1950) and gzip (RFC 1952) wrappers.
// Unlike DecompressionStream it reports how many input bytes the stream used, which carving
// needs, and it never reads past a caller supplied output cap. Pure TypeScript.

import { ParseError, crc32 } from '../util.js';

export class OutputLimitError extends ParseError {
  constructor(limit: number) { super(`decompressed size exceeds the limit of ${limit} bytes`); this.name = 'OutputLimitError'; }
}

/** Growable output buffer with a hard cap. */
export class OutBuf {
  buf: Uint8Array;
  len = 0;
  constructor(readonly limit: number, initial = 1 << 16) { this.buf = new Uint8Array(Math.max(16, Math.min(initial, limit || 16))); }
  ensure(n: number): void {
    const need = this.len + n;
    if (need > this.limit) throw new OutputLimitError(this.limit);
    if (need <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < need) cap *= 2;
    const nb = new Uint8Array(Math.min(cap, Math.max(need, this.limit)));
    nb.set(this.buf.subarray(0, this.len));
    this.buf = nb;
  }
  push(b: number): void { if (this.len >= this.buf.length) this.ensure(1); else if (this.len >= this.limit) throw new OutputLimitError(this.limit); this.buf[this.len++] = b; }
  copy(dist: number, n: number): void {
    if (dist <= 0 || dist > this.len) throw new ParseError('back reference before the start of the output');
    this.ensure(n);
    const b = this.buf;
    let s = this.len - dist;
    for (let k = 0; k < n; k++) b[this.len++] = b[s++] as number;
  }
  result(): Uint8Array { return this.buf.slice(0, this.len); }
}

const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

interface Huff { counts: Uint16Array; symbols: Uint16Array }
function buildHuff(lengths: ArrayLike<number>, n: number): Huff {
  const counts = new Uint16Array(16);
  for (let k = 0; k < n; k++) counts[lengths[k] as number]!++;
  counts[0] = 0;
  const offs = new Uint16Array(16);
  for (let k = 1; k < 16; k++) offs[k] = (offs[k - 1] as number) + (counts[k - 1] as number);
  const symbols = new Uint16Array(n);
  for (let k = 0; k < n; k++) { const l = lengths[k] as number; if (l) symbols[offs[l]!++] = k; }
  return { counts, symbols };
}

class Bits {
  pos: number; bit = 0; cnt = 0;
  constructor(readonly b: Uint8Array, start: number, readonly end: number) { this.pos = start; }
  need(n: number): number {
    while (this.cnt < n) {
      if (this.pos >= this.end) throw new ParseError('deflate stream is truncated');
      this.bit |= (this.b[this.pos++] as number) << this.cnt;
      this.cnt += 8;
    }
    const v = this.bit & ((1 << n) - 1);
    this.bit >>>= n;
    this.cnt -= n;
    return v;
  }
  decode(h: Huff): number {
    let code = 0, first = 0, index = 0;
    for (let len = 1; len < 16; len++) {
      code |= this.need(1);
      const c = h.counts[len] as number;
      if (code - c < first) return h.symbols[index + (code - first)] as number;
      index += c;
      first = (first + c) << 1;
      code <<= 1;
    }
    throw new ParseError('bad Huffman code in deflate stream');
  }
  align(): void { this.bit = 0; this.cnt = 0; }
}

let FIXED: { l: Huff; d: Huff } | undefined;
function fixed(): { l: Huff; d: Huff } {
  if (FIXED) return FIXED;
  const l = new Uint8Array(288);
  for (let k = 0; k < 144; k++) l[k] = 8;
  for (let k = 144; k < 256; k++) l[k] = 9;
  for (let k = 256; k < 280; k++) l[k] = 7;
  for (let k = 280; k < 288; k++) l[k] = 8;
  const d = new Uint8Array(30).fill(5);
  FIXED = { l: buildHuff(l, 288), d: buildHuff(d, 30) };
  return FIXED;
}

/** Inflate a raw DEFLATE stream starting at `start`. Returns the output and the offset just after the stream. */
export function inflateRaw(b: Uint8Array, opts: { start?: number; end?: number; maxOut?: number; out?: OutBuf } = {}): { data: Uint8Array; end: number } {
  const bits = new Bits(b, opts.start ?? 0, Math.min(b.length, opts.end ?? b.length));
  const out = opts.out ?? new OutBuf(opts.maxOut ?? 256 << 20);
  let last = 0;
  let guard = 0;
  while (!last) {
    if (++guard > 1_000_000) throw new ParseError('too many deflate blocks');
    last = bits.need(1);
    const type = bits.need(2);
    if (type === 0) {
      bits.align();
      if (bits.pos + 4 > bits.end) throw new ParseError('deflate stored block is truncated');
      const len = (b[bits.pos] as number) | ((b[bits.pos + 1] as number) << 8);
      const nlen = (b[bits.pos + 2] as number) | ((b[bits.pos + 3] as number) << 8);
      if ((len ^ 0xffff) !== nlen) throw new ParseError('deflate stored block length check failed');
      bits.pos += 4;
      if (bits.pos + len > bits.end) throw new ParseError('deflate stored block is truncated');
      out.ensure(len);
      out.buf.set(b.subarray(bits.pos, bits.pos + len), out.len);
      out.len += len;
      bits.pos += len;
      continue;
    }
    let lh: Huff, dh: Huff;
    if (type === 1) ({ l: lh, d: dh } = fixed());
    else if (type === 2) {
      const hlit = bits.need(5) + 257, hdist = bits.need(5) + 1, hclen = bits.need(4) + 4;
      if (hlit > 286 || hdist > 30) throw new ParseError('bad dynamic deflate header');
      const cl = new Uint8Array(19);
      for (let k = 0; k < hclen; k++) cl[CLORDER[k] as number] = bits.need(3);
      const ch = buildHuff(cl, 19);
      const lens = new Uint8Array(hlit + hdist);
      for (let k = 0; k < hlit + hdist;) {
        const sym = bits.decode(ch);
        if (sym < 16) lens[k++] = sym;
        else {
          let rep = 0, val = 0;
          if (sym === 16) { if (!k) throw new ParseError('repeat with no previous length'); val = lens[k - 1] as number; rep = 3 + bits.need(2); }
          else if (sym === 17) rep = 3 + bits.need(3);
          else rep = 11 + bits.need(7);
          if (k + rep > hlit + hdist) throw new ParseError('too many code lengths');
          while (rep--) lens[k++] = val;
        }
      }
      lh = buildHuff(lens.subarray(0, hlit), hlit);
      dh = buildHuff(lens.subarray(hlit), hdist);
    } else throw new ParseError('invalid deflate block type 3');
    for (;;) {
      const sym = bits.decode(lh);
      if (sym < 256) { out.push(sym); continue; }
      if (sym === 256) break;
      const li = sym - 257;
      if (li >= 29) throw new ParseError('bad deflate length symbol');
      const len = (LBASE[li] as number) + bits.need(LEXT[li] as number);
      const di = bits.decode(dh);
      if (di >= 30) throw new ParseError('bad deflate distance symbol');
      const dist = (DBASE[di] as number) + bits.need(DEXT[di] as number);
      out.copy(dist, len);
    }
  }
  return { data: out.result(), end: bits.pos };
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

/** Inflate a zlib stream; verifies the Adler-32 when present. */
export function inflateZlib(b: Uint8Array, opts: { start?: number; maxOut?: number } = {}): { data: Uint8Array; end: number; checksumValid: boolean | null } {
  const s = opts.start ?? 0;
  if (s + 2 > b.length) throw new ParseError('zlib header truncated');
  const cmf = b[s] as number, flg = b[s + 1] as number;
  if ((cmf & 15) !== 8 || ((cmf << 8) | flg) % 31 !== 0) throw new ParseError('not a zlib stream', s);
  if (flg & 0x20) throw new ParseError('zlib preset dictionary is not supported');
  const r = inflateRaw(b, { start: s + 2, maxOut: opts.maxOut });
  let ok: boolean | null = null;
  if (r.end + 4 <= b.length) {
    const want = (((b[r.end] as number) << 24) | ((b[r.end + 1] as number) << 16) | ((b[r.end + 2] as number) << 8) | (b[r.end + 3] as number)) >>> 0;
    ok = want === adler32(r.data);
  }
  return { data: r.data, end: Math.min(b.length, r.end + 4), checksumValid: ok };
}

export interface GzipMember { name?: string; comment?: string; mtime: number; os: number; data: Uint8Array; start: number; end: number; crcValid: boolean; sizeValid: boolean }

/** Inflate one gzip member starting at `start`. */
export function gunzipMember(b: Uint8Array, opts: { start?: number; maxOut?: number } = {}): GzipMember {
  const s = opts.start ?? 0;
  if (s + 18 > b.length || b[s] !== 0x1f || b[s + 1] !== 0x8b || b[s + 2] !== 8) throw new ParseError('not a gzip member', s);
  const flg = b[s + 3] as number;
  if (flg & 0xe0) throw new ParseError('gzip reserved flags set', s);
  const mtime = ((b[s + 4] as number) | ((b[s + 5] as number) << 8) | ((b[s + 6] as number) << 16) | ((b[s + 7] as number) << 24)) >>> 0;
  let p = s + 10;
  const cstr = (): string => { let t = ''; while (p < b.length && b[p] !== 0 && t.length < 4096) t += String.fromCharCode(b[p++] as number); p++; return t; };
  if (flg & 4) { if (p + 2 > b.length) throw new ParseError('gzip extra truncated'); p += 2 + ((b[p] as number) | ((b[p + 1] as number) << 8)); }
  const name = flg & 8 ? cstr() : undefined;
  const comment = flg & 16 ? cstr() : undefined;
  if (flg & 2) p += 2;
  if (p > b.length) throw new ParseError('gzip header truncated');
  const r = inflateRaw(b, { start: p, maxOut: opts.maxOut });
  if (r.end + 8 > b.length) throw new ParseError('gzip trailer truncated');
  const v = (o: number) => ((b[o] as number) | ((b[o + 1] as number) << 8) | ((b[o + 2] as number) << 16) | ((b[o + 3] as number) << 24)) >>> 0;
  return { ...(name !== undefined ? { name } : {}), ...(comment !== undefined ? { comment } : {}), mtime, os: b[s + 9] as number, data: r.data, start: s, end: r.end + 8, crcValid: v(r.end) === crc32(r.data), sizeValid: v(r.end + 4) === (r.data.length >>> 0) };
}
