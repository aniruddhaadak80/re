// LZMA, LZMA2 and XZ decoders in TypeScript, written from the LZMA specification (the public
// domain LzmaSpec reference by Igor Pavlov describes the format). Used for UnityFS LZMA blocks,
// .lzma and .xz streams in firmware, and squashfs xz/lzma. Output is always capped.

import { ParseError, crc32 } from '../util.js';
import { OutputLimitError } from './inflate.js';

class RangeDecoder {
  range = 0xffffffff;
  code = 0;
  pos: number;
  constructor(readonly b: Uint8Array, start: number, readonly end: number) {
    this.pos = start;
    if (this.byte() !== 0) throw new ParseError('LZMA range coder first byte is not zero', start);
    for (let k = 0; k < 4; k++) this.code = ((this.code << 8) | this.byte()) >>> 0;
    if (this.code === this.range) throw new ParseError('LZMA range coder start is invalid');
  }
  byte(): number {
    if (this.pos >= this.end) throw new ParseError('LZMA stream is truncated');
    return this.b[this.pos++] as number;
  }
  normalize(): void {
    if (this.range < 0x1000000) { this.range = (this.range << 8) >>> 0; this.code = ((this.code << 8) | this.byte()) >>> 0; }
  }
  direct(n: number): number {
    let res = 0;
    for (let k = 0; k < n; k++) {
      this.range >>>= 1;
      let t = 0;
      if (this.code >= this.range) { this.code = (this.code - this.range) >>> 0; t = 1; }
      res = ((res << 1) | t) >>> 0;
      this.normalize();
    }
    return res;
  }
  bit(p: Uint16Array, i: number): number {
    const v = p[i] as number;
    const bound = ((this.range >>> 11) * v) >>> 0;
    let sym: number;
    if (this.code < bound) { p[i] = v + ((2048 - v) >>> 5); this.range = bound; sym = 0; }
    else { p[i] = v - (v >>> 5); this.code = (this.code - bound) >>> 0; this.range = (this.range - bound) >>> 0; sym = 1; }
    this.normalize();
    return sym;
  }
  get finishedOk(): boolean { return this.code === 0; }
}

const bitTree = (rc: RangeDecoder, p: Uint16Array, base: number, bits: number): number => {
  let m = 1;
  for (let k = 0; k < bits; k++) m = (m << 1) + rc.bit(p, base + m);
  return m - (1 << bits);
};
const bitTreeReverse = (rc: RangeDecoder, p: Uint16Array, base: number, bits: number): number => {
  let m = 1, sym = 0;
  for (let k = 0; k < bits; k++) { const b = rc.bit(p, base + m); m = (m << 1) + b; sym |= b << k; }
  return sym;
};

const PROB_INIT = 1024;
const N_STATES = 12;
const POS_BITS_MAX = 4;

class LenDecoder {
  choice = new Uint16Array(2).fill(PROB_INIT);
  low = new Uint16Array(16 << 3).fill(PROB_INIT);
  mid = new Uint16Array(16 << 3).fill(PROB_INIT);
  high = new Uint16Array(256).fill(PROB_INIT);
  reset(): void { this.choice.fill(PROB_INIT); this.low.fill(PROB_INIT); this.mid.fill(PROB_INIT); this.high.fill(PROB_INIT); }
  decode(rc: RangeDecoder, posState: number): number {
    if (rc.bit(this.choice, 0) === 0) return bitTree(rc, this.low, posState << 3, 3);
    if (rc.bit(this.choice, 1) === 0) return 8 + bitTree(rc, this.mid, posState << 3, 3);
    return 16 + bitTree(rc, this.high, 0, 8);
  }
}

/** Sliding window over the output buffer (the whole output is kept, so the window is the output). */
class Window {
  buf: Uint8Array;
  len = 0;
  constructor(readonly limit: number, initial: number) { this.buf = new Uint8Array(Math.max(64, Math.min(initial, limit))); }
  grow(n: number): void {
    const need = this.len + n;
    if (need > this.limit) throw new OutputLimitError(this.limit);
    if (need <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < need) cap *= 2;
    const nb = new Uint8Array(Math.min(Math.max(cap, need), this.limit));
    nb.set(this.buf.subarray(0, this.len));
    this.buf = nb;
  }
  put(b: number): void { if (this.len >= this.buf.length) this.grow(1); this.buf[this.len++] = b; }
  get(dist: number): number { return this.buf[this.len - dist] as number; }
  copy(dist: number, n: number): void {
    this.grow(n);
    const b = this.buf;
    let s = this.len - dist;
    for (let k = 0; k < n; k++) b[this.len++] = b[s++] as number;
  }
}

export interface LzmaProps { lc: number; lp: number; pb: number; dictSize: number }

export function decodeProps(byte: number, dictSize: number): LzmaProps {
  if (byte >= 9 * 5 * 5) throw new ParseError('bad LZMA properties byte');
  const lc = byte % 9, r = Math.floor(byte / 9);
  return { lc, lp: r % 5, pb: Math.floor(r / 5), dictSize };
}

/** One LZMA decoder state; reused across LZMA2 chunks. */
class LzmaDecoder {
  lc = 0; lp = 0; pb = 0; dictSize = 0;
  literal!: Uint16Array;
  posSlot = new Uint16Array(4 << 6);
  posDecoders = new Uint16Array(1 + 128 - 14);
  align = new Uint16Array(16);
  isMatch = new Uint16Array(N_STATES << POS_BITS_MAX);
  isRep = new Uint16Array(N_STATES);
  isRepG0 = new Uint16Array(N_STATES);
  isRepG1 = new Uint16Array(N_STATES);
  isRepG2 = new Uint16Array(N_STATES);
  isRep0Long = new Uint16Array(N_STATES << POS_BITS_MAX);
  lenDec = new LenDecoder();
  repLenDec = new LenDecoder();
  state = 0; rep0 = 0; rep1 = 0; rep2 = 0; rep3 = 0;
  // the dictionary start for this decoder: distances may not reach before it
  dictStart = 0;
  constructor(readonly win: Window) {}
  setProps(p: LzmaProps): void {
    if (p.lc + p.lp > 12 && !this.literal) { /* LZMA1 allows lc up to 8; the table below handles it */ }
    this.lc = p.lc; this.lp = p.lp; this.pb = p.pb; this.dictSize = p.dictSize;
    const size = 0x300 << (p.lc + p.lp);
    if (size > 0x300 << 12) throw new ParseError('LZMA lc + lp too large');
    this.literal = new Uint16Array(size);
  }
  resetState(): void {
    this.literal.fill(PROB_INIT); this.posSlot.fill(PROB_INIT); this.posDecoders.fill(PROB_INIT); this.align.fill(PROB_INIT);
    this.isMatch.fill(PROB_INIT); this.isRep.fill(PROB_INIT); this.isRepG0.fill(PROB_INIT); this.isRepG1.fill(PROB_INIT); this.isRepG2.fill(PROB_INIT); this.isRep0Long.fill(PROB_INIT);
    this.lenDec.reset(); this.repLenDec.reset();
    this.state = 0; this.rep0 = this.rep1 = this.rep2 = this.rep3 = 0;
  }
  private decodeDistance(rc: RangeDecoder, len: number): number {
    let lenState = len;
    if (lenState > 3) lenState = 3;
    const slot = bitTree(rc, this.posSlot, lenState << 6, 6);
    if (slot < 4) return slot;
    const numDirect = (slot >>> 1) - 1;
    let dist = ((2 | (slot & 1)) << numDirect) >>> 0;
    if (slot < 14) dist = (dist + bitTreeReverse(rc, this.posDecoders, dist - slot, numDirect)) >>> 0;
    else {
      dist = (dist + ((rc.direct(numDirect - 4) << 4) >>> 0)) >>> 0;
      dist = (dist + bitTreeReverse(rc, this.align, 0, 4)) >>> 0;
    }
    return dist;
  }
  /**
   * Decode until `outLimit` bytes are produced in this call (when known) or an end marker.
   * Returns true when the end marker was seen.
   */
  decode(rc: RangeDecoder, outLimit: number | undefined, allowEndMarker: boolean): boolean {
    const win = this.win;
    const pbMask = (1 << this.pb) - 1, lpMask = (1 << this.lp) - 1;
    const start = win.len;
    for (;;) {
      if (outLimit !== undefined && win.len - start >= outLimit) return false;
      const posState = win.len & pbMask;
      const st = this.state;
      if (rc.bit(this.isMatch, (st << POS_BITS_MAX) + posState) === 0) {
        const prev = win.len > this.dictStart ? win.get(1) : 0;
        const litState = ((win.len & lpMask) << this.lc) + (prev >>> (8 - this.lc));
        const base = 0x300 * litState;
        let sym = 1;
        if (st >= 7) {
          let match = win.get(this.rep0 + 1);
          do {
            const mb = (match >>> 7) & 1;
            match <<= 1;
            const bit = rc.bit(this.literal, base + ((1 + mb) << 8) + sym);
            sym = (sym << 1) | bit;
            if (mb !== bit) break;
          } while (sym < 0x100);
        }
        while (sym < 0x100) sym = (sym << 1) | rc.bit(this.literal, base + sym);
        win.put(sym & 0xff);
        this.state = st < 4 ? 0 : st < 10 ? st - 3 : st - 6;
        continue;
      }
      let len: number;
      if (rc.bit(this.isRep, st) !== 0) {
        if (win.len === this.dictStart) throw new ParseError('LZMA repeat match with an empty dictionary');
        if (rc.bit(this.isRepG0, st) === 0) {
          if (rc.bit(this.isRep0Long, (st << POS_BITS_MAX) + posState) === 0) {
            this.state = st < 7 ? 9 : 11;
            win.put(win.get(this.rep0 + 1));
            continue;
          }
        } else {
          let dist: number;
          if (rc.bit(this.isRepG1, st) === 0) dist = this.rep1;
          else {
            if (rc.bit(this.isRepG2, st) === 0) dist = this.rep2;
            else { dist = this.rep3; this.rep3 = this.rep2; }
            this.rep2 = this.rep1;
          }
          this.rep1 = this.rep0;
          this.rep0 = dist;
        }
        len = this.repLenDec.decode(rc, posState);
        this.state = st < 7 ? 8 : 11;
      } else {
        this.rep3 = this.rep2; this.rep2 = this.rep1; this.rep1 = this.rep0;
        len = this.lenDec.decode(rc, posState);
        this.state = st < 7 ? 7 : 10;
        this.rep0 = this.decodeDistance(rc, len);
        if (this.rep0 === 0xffffffff) {
          if (!allowEndMarker) throw new ParseError('unexpected LZMA end marker');
          return true;
        }
        if (this.rep0 >= this.dictSize || this.rep0 >= win.len - this.dictStart) throw new ParseError('LZMA match distance is outside the dictionary');
      }
      len += 2;
      if (outLimit !== undefined) len = Math.min(len, outLimit - (win.len - start));
      win.copy(this.rep0 + 1, len);
    }
  }
}

/** Decode a raw LZMA1 stream with known properties. `size` may be undefined (end marker required). */
export function lzmaDecodeRaw(b: Uint8Array, props: LzmaProps, opts: { start?: number; end?: number; size?: number; maxOut?: number } = {}): { data: Uint8Array; end: number } {
  const maxOut = opts.maxOut ?? 256 << 20;
  if (opts.size !== undefined && opts.size > maxOut) throw new OutputLimitError(maxOut);
  const win = new Window(maxOut, opts.size !== undefined ? opts.size : Math.min(maxOut, 1 << 20));
  const dec = new LzmaDecoder(win);
  dec.setProps(props);
  dec.resetState();
  const rc = new RangeDecoder(b, opts.start ?? 0, Math.min(b.length, opts.end ?? b.length));
  dec.decode(rc, opts.size, true);
  return { data: win.buf.slice(0, win.len), end: rc.pos };
}

/** Decode a .lzma (LZMA alone) stream: 13 byte header (props, dictionary size, size or -1). */
export function lzmaAloneDecode(b: Uint8Array, opts: { start?: number; maxOut?: number } = {}): { data: Uint8Array; end: number; props: LzmaProps; declaredSize: number | null } {
  const s = opts.start ?? 0;
  if (s + 13 > b.length) throw new ParseError('LZMA header truncated');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const props = decodeProps(b[s] as number, dv.getUint32(s + 1, true));
  const lo = dv.getUint32(s + 5, true), hi = dv.getUint32(s + 9, true);
  const unknown = lo === 0xffffffff && hi === 0xffffffff;
  if (!unknown && hi > 0x1fffff) throw new ParseError('LZMA declared size too large');
  const size = unknown ? undefined : hi * 2 ** 32 + lo;
  const r = lzmaDecodeRaw(b, props, { start: s + 13, size, maxOut: opts.maxOut });
  return { ...r, props, declaredSize: size ?? null };
}

/** Plausibility check for a .lzma header at an offset (used by carving). */
export function looksLikeLzmaAlone(b: Uint8Array, o: number): boolean {
  if (o + 14 > b.length) return false;
  const p = b[o] as number;
  if (p >= 225) return false;
  const dict = ((b[o + 1] as number) | ((b[o + 2] as number) << 8) | ((b[o + 3] as number) << 16) | ((b[o + 4] as number) << 24)) >>> 0;
  // dictionary is a power of two or 2^n + 2^(n-1), between 4 KiB and 1.5 GiB
  if (dict < 4096 || dict > 0x60000000) return false;
  const pow = (x: number) => x > 0 && (x & (x - 1)) === 0;
  if (!pow(dict) && !pow(dict - (dict & -dict))) return false;
  const hi = ((b[o + 9] as number) | ((b[o + 10] as number) << 8) | ((b[o + 11] as number) << 16) | ((b[o + 12] as number) << 24)) >>> 0;
  const lo = ((b[o + 5] as number) | ((b[o + 6] as number) << 8) | ((b[o + 7] as number) << 16) | ((b[o + 8] as number) << 24)) >>> 0;
  if (!(lo === 0xffffffff && hi === 0xffffffff) && hi > 0x10) return false;
  return b[o + 13] === 0;
}

/** Decode LZMA2 chunks from `start` until the end marker. */
export function lzma2Decode(b: Uint8Array, dictSize: number, opts: { start?: number; end?: number; maxOut?: number } = {}): { data: Uint8Array; end: number } {
  const maxOut = opts.maxOut ?? 256 << 20;
  const end = Math.min(b.length, opts.end ?? b.length);
  const win = new Window(maxOut, Math.min(maxOut, 1 << 20));
  const dec = new LzmaDecoder(win);
  let p = opts.start ?? 0;
  let needProps = true, needDictReset = true;
  for (let guard = 0; ; guard++) {
    if (guard > 10_000_000) throw new ParseError('too many LZMA2 chunks');
    if (p >= end) throw new ParseError('LZMA2 stream is truncated');
    const ctrl = b[p++] as number;
    if (ctrl === 0) break;
    if (ctrl === 1 || ctrl === 2) {
      if (ctrl === 1) { needDictReset = false; dec.dictStart = win.len; }
      else if (needDictReset) throw new ParseError('LZMA2 uncompressed chunk without a dictionary reset');
      if (p + 2 > end) throw new ParseError('LZMA2 chunk header truncated');
      const size = (((b[p] as number) << 8) | (b[p + 1] as number)) + 1;
      p += 2;
      if (p + size > end) throw new ParseError('LZMA2 uncompressed chunk truncated');
      win.grow(size);
      win.buf.set(b.subarray(p, p + size), win.len);
      win.len += size;
      p += size;
      continue;
    }
    if (ctrl < 0x80) throw new ParseError(`bad LZMA2 control byte 0x${ctrl.toString(16)}`);
    if (p + 4 > end) throw new ParseError('LZMA2 chunk header truncated');
    const usize = (((ctrl & 0x1f) << 16) | ((b[p] as number) << 8) | (b[p + 1] as number)) + 1;
    const csize = (((b[p + 2] as number) << 8) | (b[p + 3] as number)) + 1;
    p += 4;
    const reset = (ctrl >>> 5) & 3;
    if (reset === 3) { needDictReset = false; dec.dictStart = win.len; }
    else if (needDictReset) throw new ParseError('LZMA2 first chunk does not reset the dictionary');
    if (reset >= 2) {
      if (p >= end) throw new ParseError('LZMA2 properties truncated');
      const pr = decodeProps(b[p++] as number, dictSize);
      if (pr.lc + pr.lp > 4) throw new ParseError('LZMA2 lc + lp must be at most 4');
      dec.setProps(pr);
      needProps = false;
    } else if (needProps) throw new ParseError('LZMA2 chunk without properties');
    if (reset >= 1) dec.resetState();
    if (p + csize > end) throw new ParseError('LZMA2 compressed chunk truncated');
    const rc = new RangeDecoder(b, p, p + csize);
    const before = win.len;
    dec.decode(rc, usize, false);
    if (win.len - before !== usize) throw new ParseError('LZMA2 chunk decoded to the wrong size');
    p += csize;
  }
  return { data: win.buf.slice(0, win.len), end: p };
}

// ---------------- XZ ----------------

let CRC64: BigUint64Array | undefined;
export function crc64(d: Uint8Array): bigint {
  if (!CRC64) {
    CRC64 = new BigUint64Array(256);
    const poly = 0xc96c5795d7870f42n;
    for (let k = 0; k < 256; k++) { let c = BigInt(k); for (let j = 0; j < 8; j++) c = c & 1n ? (c >> 1n) ^ poly : c >> 1n; CRC64[k] = c; }
  }
  // process with two 32 bit halves to keep BigInt work per byte small
  let c = 0xffffffffffffffffn;
  for (let k = 0; k < d.length; k++) c = (CRC64[Number((c ^ BigInt(d[k] as number)) & 0xffn)] as bigint) ^ (c >> 8n);
  return c ^ 0xffffffffffffffffn;
}

const readVli = (b: Uint8Array, p: number, end: number): [number, number] => {
  let v = 0, mul = 1;
  for (let k = 0; k < 9; k++) {
    if (p >= end) throw new ParseError('XZ variable length integer truncated');
    const x = b[p++] as number;
    v += (x & 0x7f) * mul;
    mul *= 128;
    if (!(x & 0x80)) return [v, p];
  }
  throw new ParseError('XZ variable length integer too long');
};

export interface XzInfo { check: 'none' | 'crc32' | 'crc64' | 'sha256' | string; blocks: { compressedSize: number; uncompressedSize: number; filters: string[]; checkValid: boolean | null }[]; end: number; data: Uint8Array }

const FILTER_NAMES: Record<number, string> = { 0x21: 'lzma2', 0x03: 'delta', 0x04: 'x86', 0x05: 'powerpc', 0x06: 'ia64', 0x07: 'arm', 0x08: 'armthumb', 0x09: 'sparc', 0x0a: 'arm64', 0x0b: 'riscv' };

/** Decode one XZ stream (all blocks) starting at `start`. Supports LZMA2 with the delta and BCJ (x86, ARM, ARM64, ARM-Thumb, PowerPC, SPARC) filters in front. */
export function xzDecode(b: Uint8Array, opts: { start?: number; maxOut?: number; verify?: boolean } = {}): XzInfo {
  const s = opts.start ?? 0;
  const maxOut = opts.maxOut ?? 256 << 20;
  const magic = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
  if (s + 12 > b.length || magic.some((m, k) => b[s + k] !== m)) throw new ParseError('not an XZ stream', s);
  const flags = b[s + 7] as number;
  const checkType = flags & 0x0f;
  const checkSize = checkType === 0 ? 0 : checkType <= 3 ? 4 : checkType <= 6 ? 8 : checkType <= 9 ? 16 : checkType <= 12 ? 32 : 64;
  const checkName = ({ 0: 'none', 1: 'crc32', 4: 'crc64', 10: 'sha256' } as Record<number, string>)[checkType] ?? `type ${checkType}`;
  if (crc32(b, s + 6, s + 8) >>> 0 !== new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(s + 8, true)) throw new ParseError('XZ stream header CRC mismatch', s);
  let p = s + 12;
  const blocks: XzInfo['blocks'] = [];
  const parts: Uint8Array[] = [];
  let total = 0;
  for (let guard = 0; ; guard++) {
    if (guard > 1_000_000) throw new ParseError('too many XZ blocks');
    if (p >= b.length) throw new ParseError('XZ stream truncated');
    if (b[p] === 0) break; // index indicator
    const hsize = ((b[p] as number) + 1) * 4;
    const hstart = p;
    if (p + hsize > b.length) throw new ParseError('XZ block header truncated');
    const bflags = b[p + 1] as number;
    let q = p + 2;
    let csize: number | undefined, usize: number | undefined;
    if (bflags & 0x40) [csize, q] = readVli(b, q, p + hsize);
    if (bflags & 0x80) [usize, q] = readVli(b, q, p + hsize);
    const nf = (bflags & 3) + 1;
    const filters: { id: number; props: Uint8Array }[] = [];
    for (let k = 0; k < nf; k++) {
      let id: number, ps: number;
      [id, q] = readVli(b, q, p + hsize);
      [ps, q] = readVli(b, q, p + hsize);
      if (q + ps > p + hsize) throw new ParseError('XZ filter properties truncated');
      filters.push({ id, props: b.subarray(q, q + ps) });
      q += ps;
    }
    p = hstart + hsize;
    const last = filters[filters.length - 1];
    if (!last || last.id !== 0x21) throw new ParseError('XZ block does not end with the LZMA2 filter');
    const dp = last.props[0] ?? 40;
    if (dp > 40) throw new ParseError('bad LZMA2 dictionary property');
    const dict = dp === 40 ? 0xffffffff : (2 | (dp & 1)) * 2 ** ((dp >>> 1) + 11);
    const r = lzma2Decode(b, dict, { start: p, maxOut: maxOut - total, end: csize !== undefined ? p + csize : undefined });
    let data = r.data;
    for (let k = filters.length - 2; k >= 0; k--) data = applyFilter(filters[k]!.id, filters[k]!.props, data);
    if (usize !== undefined && data.length !== usize) throw new ParseError('XZ block uncompressed size mismatch');
    const cs = r.end - p;
    if (csize !== undefined && cs !== csize) throw new ParseError('XZ block compressed size mismatch');
    p = r.end;
    while ((p - hstart) % 4 !== 0) { if (b[p] !== 0) throw new ParseError('XZ block padding is not zero'); p++; }
    let ok: boolean | null = null;
    if (checkSize) {
      if (p + checkSize > b.length) throw new ParseError('XZ block check truncated');
      if (opts.verify !== false) {
        if (checkType === 1) ok = (crc32(data) >>> 0) === new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(p, true);
        else if (checkType === 4) ok = crc64(data) === new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(p, true);
      }
      p += checkSize;
    }
    blocks.push({ compressedSize: cs, uncompressedSize: data.length, filters: filters.map((f) => FILTER_NAMES[f.id] ?? `0x${f.id.toString(16)}`), checkValid: ok });
    parts.push(data);
    total += data.length;
  }
  // index
  const istart = p;
  p++;
  let count: number;
  [count, p] = readVli(b, p, b.length);
  if (count !== blocks.length) throw new ParseError('XZ index record count does not match the blocks');
  for (let k = 0; k < count; k++) { [, p] = readVli(b, p, b.length); [, p] = readVli(b, p, b.length); }
  while ((p - istart) % 4 !== 0) p++;
  p += 4; // index CRC32
  p += 12; // stream footer
  if (p > b.length) throw new ParseError('XZ stream footer truncated');
  if (b[p - 2] !== 0x59 || b[p - 1] !== 0x5a) throw new ParseError('XZ stream footer magic missing');
  const out = new Uint8Array(total);
  let o = 0;
  for (const d of parts) { out.set(d, o); o += d.length; }
  return { check: checkName, blocks, end: p, data: out };
}

/** XZ/LZMA SDK filters: delta and the branch converters, decode direction. */
export function applyFilter(id: number, props: Uint8Array, d: Uint8Array): Uint8Array {
  const out = d.slice();
  const start = props.length >= 4 ? new DataView(props.buffer, props.byteOffset, props.byteLength).getUint32(0, true) : 0;
  switch (id) {
    case 0x03: {
      const dist = (props[0] ?? 0) + 1;
      for (let k = dist; k < out.length; k++) out[k] = ((out[k] as number) + (out[k - dist] as number)) & 0xff;
      return out;
    }
    case 0x04: return bcjX86(out, start);
    case 0x07: // ARM BL
      for (let i = 0; i + 4 <= out.length; i += 4) {
        if (out[i + 3] === 0xeb) {
          const src = (((out[i + 2] as number) << 16) | ((out[i + 1] as number) << 8) | (out[i] as number)) << 2;
          const dest = (src - (start + i + 8)) >>> 2;
          out[i + 2] = (dest >>> 16) & 0xff; out[i + 1] = (dest >>> 8) & 0xff; out[i] = dest & 0xff;
        }
      }
      return out;
    case 0x08: // ARM Thumb BL pairs
      for (let i = 0; i + 4 <= out.length; i += 2) {
        if (((out[i + 1] as number) & 0xf8) === 0xf0 && ((out[i + 3] as number) & 0xf8) === 0xf8) {
          const src = ((((out[i + 1] as number) & 7) << 19) | ((out[i] as number) << 11) | (((out[i + 3] as number) & 7) << 8) | (out[i + 2] as number)) << 1;
          const dest = ((src - (start + i + 4)) >>> 1) & 0x3fffff;
          out[i + 1] = 0xf0 | ((dest >>> 19) & 7); out[i] = (dest >>> 11) & 0xff; out[i + 3] = 0xf8 | ((dest >>> 8) & 7); out[i + 2] = dest & 0xff;
          i += 2;
        }
      }
      return out;
    case 0x0a: // ARM64 BL and ADRP
      for (let i = 0; i + 4 <= out.length; i += 4) {
        let ins = ((out[i] as number) | ((out[i + 1] as number) << 8) | ((out[i + 2] as number) << 16) | ((out[i + 3] as number) << 24)) >>> 0;
        const pc = (start + i) >>> 0;
        if ((ins >>> 26) === 0x25) {
          const src = ins & 0x03ffffff;
          ins = (0x94000000 | ((src - (pc >>> 2)) & 0x03ffffff)) >>> 0;
        } else if (((ins & 0x9f000000) >>> 0) === 0x90000000) {
          const src = ((ins >>> 29) & 3) | ((ins >>> 3) & 0x001ffffc);
          if (((src + 0x00020000) & 0x001c0000) !== 0) continue;
          const dest = (src - (pc >>> 12)) >>> 0;
          ins = (ins & 0x9000001f) >>> 0;
          ins = (ins | ((dest & 3) << 29)) >>> 0;
          ins = (ins | ((dest & 0x0003fffc) << 3)) >>> 0;
          ins = (ins | ((0 - (dest & 0x00020000)) & 0x00e00000)) >>> 0;
        } else continue;
        out[i] = ins & 0xff; out[i + 1] = (ins >>> 8) & 0xff; out[i + 2] = (ins >>> 16) & 0xff; out[i + 3] = ins >>> 24;
      }
      return out;
    case 0x05: // PowerPC branch (big endian)
      for (let i = 0; i + 4 <= out.length; i += 4) {
        if (((out[i] as number) >>> 2) === 0x12 && ((out[i + 3] as number) & 3) === 1) {
          const src = ((((out[i] as number) & 3) << 24) | ((out[i + 1] as number) << 16) | ((out[i + 2] as number) << 8) | ((out[i + 3] as number) & ~3)) >>> 0;
          const dest = (src - (start + i)) >>> 0;
          out[i] = 0x48 | ((dest >>> 24) & 3); out[i + 1] = (dest >>> 16) & 0xff; out[i + 2] = (dest >>> 8) & 0xff; out[i + 3] = ((out[i + 3] as number) & 3) | (dest & 0xfc);
        }
      }
      return out;
    case 0x09: // SPARC call
      for (let i = 0; i + 4 <= out.length; i += 4) {
        if ((out[i] === 0x40 && ((out[i + 1] as number) & 0xc0) === 0) || (out[i] === 0x7f && ((out[i + 1] as number) & 0xc0) === 0xc0)) {
          let src = (((out[i] as number) << 24) | ((out[i + 1] as number) << 16) | ((out[i + 2] as number) << 8) | (out[i + 3] as number)) >>> 0;
          src = (src << 2) >>> 0;
          let dest = (src - (start + i)) >>> 0;
          dest >>>= 2;
          dest = (((0 - ((dest >>> 22) & 1)) << 22) & 0x3fffffff) | (dest & 0x3fffff) | 0x40000000;
          out[i] = (dest >>> 24) & 0xff; out[i + 1] = (dest >>> 16) & 0xff; out[i + 2] = (dest >>> 8) & 0xff; out[i + 3] = dest & 0xff;
        }
      }
      return out;
    default:
      throw new ParseError(`XZ filter ${FILTER_NAMES[id] ?? '0x' + id.toString(16)} is not supported`);
  }
}

function bcjX86(buf: Uint8Array, startPos: number): Uint8Array {
  // x86 BCJ decoder (relative CALL/JMP targets back to relative form)
  const MASK_TO_ALLOWED = [true, true, true, false, true, false, false, false];
  const MASK_TO_BIT = [0, 1, 2, 2, 3, 3, 3, 3];
  const test86 = (b: number) => b === 0 || b === 0xff;
  let prevMask = 0, prevPos = -5;
  const size = buf.length;
  if (size < 5) return buf;
  for (let i = 0; i <= size - 5; i++) {
    const b0 = buf[i] as number;
    if (b0 !== 0xe8 && b0 !== 0xe9) continue;
    const off = i - prevPos;
    prevPos = i;
    if (off > 5) prevMask = 0;
    else for (let k = 0; k < off; k++) { prevMask &= 0x77; prevMask <<= 1; }
    let b4 = buf[i + 4] as number;
    if (test86(b4) && MASK_TO_ALLOWED[(prevMask >>> 1) & 7] && (prevMask >>> 1) < 0x10) {
      let src = ((b4 << 24) | ((buf[i + 3] as number) << 16) | ((buf[i + 2] as number) << 8) | (buf[i + 1] as number)) | 0;
      let dest: number;
      for (;;) {
        dest = (src - (startPos + i + 5)) | 0;
        if (prevMask === 0) break;
        const idx = MASK_TO_BIT[prevMask >>> 1] as number * 8;
        b4 = (dest >>> (24 - idx)) & 0xff;
        if (!test86(b4)) break;
        src = dest ^ ((1 << (32 - idx)) - 1);
      }
      dest &= 0x01ffffff;
      dest |= (dest & 0x01000000) ? 0xff000000 : 0;
      buf[i + 4] = (dest >>> 24) & 0xff; buf[i + 3] = (dest >>> 16) & 0xff; buf[i + 2] = (dest >>> 8) & 0xff; buf[i + 1] = dest & 0xff;
      i += 4;
      prevMask = 0;
    } else {
      prevMask = (prevMask << 1) | 1;
      if (test86(b4)) prevMask |= 0x10;
    }
  }
  return buf;
}
