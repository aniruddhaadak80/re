// bzip2 decoder in pure TypeScript (original code written from the published format description:
// Huffman coded MTF/RLE2 symbols, inverse Burrows-Wheeler transform, RLE1, per-block and stream
// CRCs). Handles concatenated streams. Bounded by maxOut and by the format's own size limits.

import { ParseError } from '../util.js';
import { OutBuf, OutputLimitError } from './inflate.js';

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i << 24;
    for (let k = 0; k < 8; k++) c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : c << 1;
    t[i] = c >>> 0;
  }
  return t;
})();

class Bits {
  pos: number;
  constructor(private b: Uint8Array, start: number, private end: number) { this.pos = start * 8; }
  bit(): number {
    const byte = this.pos >>> 3;
    if (byte >= this.end) throw new ParseError('bzip2 stream truncated');
    const v = ((this.b[byte] as number) >> (7 - (this.pos & 7))) & 1;
    this.pos++;
    return v;
  }
  bits(n: number): number {
    let v = 0;
    for (let k = 0; k < n; k++) v = (v * 2) + this.bit();
    return v;
  }
  get bytePos(): number { return Math.ceil(this.pos / 8); }
}

interface Table { limit: Int32Array; base: Int32Array; perm: Int32Array; minLen: number; maxLen: number }
function makeTable(len: Uint8Array, alpha: number): Table {
  let minLen = 32, maxLen = 0;
  for (let i = 0; i < alpha; i++) { const l = len[i] as number; if (l > maxLen) maxLen = l; if (l < minLen) minLen = l; }
  const perm = new Int32Array(alpha), base = new Int32Array(23), limit = new Int32Array(23);
  let pp = 0;
  for (let i = minLen; i <= maxLen; i++) for (let j = 0; j < alpha; j++) if (len[j] === i) perm[pp++] = j;
  for (let i = 0; i < alpha; i++) base[(len[i] as number) + 1]!++;
  for (let i = 1; i < 23; i++) base[i]! += base[i - 1]!;
  let vec = 0;
  for (let i = minLen; i <= maxLen; i++) { vec += base[i + 1]! - base[i]!; limit[i] = vec - 1; vec <<= 1; }
  for (let i = minLen + 1; i <= maxLen; i++) base[i] = ((limit[i - 1]! + 1) << 1) - base[i]!;
  return { limit, base, perm, minLen, maxLen };
}

function decodeSym(br: Bits, t: Table, alpha: number): number {
  let n = t.minLen;
  let v = br.bits(n);
  while (n <= t.maxLen && v > t.limit[n]!) { n++; v = (v << 1) | br.bit(); }
  if (n > t.maxLen) throw new ParseError('bzip2 bad Huffman code');
  const idx = v - t.base[n]!;
  if (idx < 0 || idx >= alpha) throw new ParseError('bzip2 bad Huffman code');
  return t.perm[idx]!;
}

export interface Bzip2Result { data: Uint8Array; end: number; blockSize: number; blocks: number; streams: number; crcValid: boolean }

/** Decode a bzip2 stream (and any streams concatenated right after it). */
export function bzip2Decode(b: Uint8Array, opts: { start?: number; maxOut?: number; concatenated?: boolean } = {}): Bzip2Result {
  let start = opts.start ?? 0;
  const out = new OutBuf(opts.maxOut ?? 256 << 20);
  let blocks = 0, streams = 0, crcValid = true, blockSize = 0, end = start;
  const tt = { a: new Uint32Array(0) };
  for (;;) {
    if (!(b[start] === 0x42 && b[start + 1] === 0x5a && b[start + 2] === 0x68)) { if (!streams) throw new ParseError('not a bzip2 stream'); break; }
    const level = (b[start + 3] ?? 0) - 0x30;
    if (level < 1 || level > 9) { if (!streams) throw new ParseError('bad bzip2 block size'); break; }
    blockSize = level * 100000;
    if (tt.a.length < blockSize) tt.a = new Uint32Array(blockSize);
    const br = new Bits(b, start + 4, b.length);
    let combined = 0;
    for (;;) {
      const m1 = br.bits(24), m2 = br.bits(24);
      if (m1 === 0x177245 && m2 === 0x385090) {
        const want = br.bits(32) >>> 0;
        if ((want >>> 0) !== (combined >>> 0)) crcValid = false;
        break;
      }
      if (m1 !== 0x314159 || m2 !== 0x265359) throw new ParseError('bad bzip2 block magic');
      const blockCrc = br.bits(32) >>> 0;
      const got = decodeBlock(br, blockSize, tt.a, out);
      if (got !== blockCrc) crcValid = false;
      combined = (((combined << 1) | (combined >>> 31)) ^ got) >>> 0;
      blocks++;
    }
    streams++;
    end = br.bytePos;
    if (opts.concatenated === false) break;
    start = end;
    if (start + 4 > b.length) break;
  }
  return { data: out.result(), end, blockSize, blocks, streams, crcValid };
}

function decodeBlock(br: Bits, blockSize: number, tt: Uint32Array, out: OutBuf): number {
  if (br.bit()) throw new ParseError('bzip2 randomised blocks are not supported');
  const origPtr = br.bits(24);
  const used = br.bits(16);
  const seq: number[] = [];
  for (let i = 0; i < 16; i++) if (used & (0x8000 >> i)) { const w = br.bits(16); for (let j = 0; j < 16; j++) if (w & (0x8000 >> j)) seq.push(i * 16 + j); }
  if (!seq.length) throw new ParseError('bzip2 block uses no symbols');
  const alpha = seq.length + 2;
  const nGroups = br.bits(3);
  if (nGroups < 2 || nGroups > 6) throw new ParseError('bad bzip2 group count');
  const nSel = br.bits(15);
  if (nSel < 1) throw new ParseError('bad bzip2 selector count');
  const mtfG = [0, 1, 2, 3, 4, 5].slice(0, nGroups);
  const selectors = new Uint8Array(Math.min(nSel, 18002));
  for (let i = 0; i < nSel; i++) {
    let j = 0;
    while (br.bit()) { j++; if (j >= nGroups) throw new ParseError('bad bzip2 selector'); }
    const g = mtfG[j]!;
    mtfG.splice(j, 1); mtfG.unshift(g);
    if (i < selectors.length) selectors[i] = g;
  }
  const tables: Table[] = [];
  for (let g = 0; g < nGroups; g++) {
    const len = new Uint8Array(alpha);
    let cur = br.bits(5);
    for (let s = 0; s < alpha; s++) {
      for (;;) {
        if (cur < 1 || cur > 20) throw new ParseError('bad bzip2 code length');
        if (!br.bit()) break;
        cur += br.bit() ? -1 : 1;
      }
      len[s] = cur;
    }
    tables.push(makeTable(len, alpha));
  }
  // MTF / RLE2 symbols into tt
  const mtf = new Uint8Array(256);
  for (let i = 0; i < 256; i++) mtf[i] = i;
  const counts = new Uint32Array(256);
  const eob = alpha - 1;
  let n = 0, groupPos = 0, sel = 0, run = 0, runW = 1;
  let table = tables[selectors[0]!]!;
  for (;;) {
    if (groupPos === 0) {
      if (sel >= selectors.length) throw new ParseError('bzip2 ran out of selectors');
      table = tables[selectors[sel++]!]!; groupPos = 50;
    }
    groupPos--;
    const sym = decodeSym(br, table, alpha);
    if (sym <= 1) {
      run += sym === 0 ? runW : 2 * runW;
      runW <<= 1;
      if (run > blockSize) throw new ParseError('bzip2 run longer than the block');
      continue;
    }
    if (run) {
      if (n + run > blockSize) throw new ParseError('bzip2 block overflow');
      const v = seq[mtf[0]!]!;
      counts[v]! += run;
      tt.fill(v, n, n + run);
      n += run; run = 0; runW = 1;
    }
    if (sym === eob) break;
    const idx = sym - 1;
    if (idx >= seq.length) throw new ParseError('bzip2 MTF index out of range');
    const m = mtf[idx]!;
    mtf.copyWithin(1, 0, idx);
    mtf[0] = m;
    if (n >= blockSize) throw new ParseError('bzip2 block overflow');
    const v = seq[m]!;
    counts[v]!++;
    tt[n++] = v;
  }
  if (origPtr >= n) throw new ParseError('bzip2 origPtr out of range');
  // inverse BWT
  const cf = new Uint32Array(256);
  for (let i = 1; i < 256; i++) cf[i] = cf[i - 1]! + counts[i - 1]!;
  for (let i = 0; i < n; i++) { const c = tt[i]! & 0xff; tt[cf[c]!]! |= i << 8; cf[c]!++; }
  // RLE1 and CRC
  let crc = 0xffffffff;
  const emit = (c: number) => { out.push(c); crc = ((crc << 8) ^ CRC_TABLE[((crc >>> 24) ^ c) & 0xff]!) >>> 0; };
  let pos = tt[origPtr]! >>> 8;
  let last = -1, same = 0;
  for (let k = 0; k < n; k++) {
    const e = tt[pos]!;
    const c = e & 0xff;
    pos = e >>> 8;
    if (same === 4) {
      for (let r = 0; r < c; r++) emit(last);
      same = 0; last = -1;
      continue;
    }
    if (c === last) same++; else { last = c; same = 1; }
    emit(c);
  }
  return (~crc) >>> 0;
}

export { OutputLimitError };
