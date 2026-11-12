// bzip2 decoder (pure TypeScript, written from the format description). Used for UDBZ disk image chunks.
// Every block CRC and the stream CRC are checked. Output is capped.

import { FormatError } from './util.js';

const CRC = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i << 24;
  for (let k = 0; k < 8; k++) c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : c << 1;
  CRC[i] = c >>> 0;
}

class Bits {
  private buf = 0; // up to 24 pending bits, high bits first
  private n = 0;
  private byte = 0;
  constructor(private readonly b: Uint8Array) {}
  get pos(): number { return this.byte * 8 - this.n; }
  set pos(p: number) { this.byte = p >>> 3; this.n = 0; this.buf = 0; const r = p & 7; if (r) this.get(r); }
  get(count: number): number {
    let v = 0;
    while (count > 0) {
      if (this.n === 0) {
        if (this.byte >= this.b.length) throw new FormatError('bzip2 stream is truncated', this.byte);
        this.buf = this.b[this.byte++] as number; this.n = 8;
      }
      const take = count < this.n ? count : this.n;
      const shift = this.n - take;
      v = (v * (1 << take)) + ((this.buf >>> shift) & ((1 << take) - 1));
      this.n -= take; count -= take;
    }
    return v >>> 0;
  }
  bit(): number { return this.get(1); }
}

const MAX_GROUPS = 6, MAX_ALPHA = 258, MAX_CODE_LEN = 20;

/** Decompress a complete bzip2 stream (one or more concatenated streams). */
export function bunzip2(input: Uint8Array, maxOut = 512 * 1024 * 1024): Uint8Array {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const br = new Bits(input);
  let streams = 0;
  while ((br.pos >>> 3) + 4 <= input.length) {
    // Stream header "BZh" + level
    if (streams > 0) br.pos = (br.pos + 7) & ~7;
    if ((br.pos >>> 3) + 4 > input.length) break;
    const b0 = br.get(8), b1 = br.get(8), b2 = br.get(8);
    if (b0 !== 0x42 || b1 !== 0x5a || b2 !== 0x68) { if (streams > 0) break; throw new FormatError('not a bzip2 stream', 0); }
    const level = br.get(8) - 0x30;
    if (level < 1 || level > 9) throw new FormatError('bad bzip2 block size');
    const blockMax = level * 100000;
    const tt = new Uint32Array(blockMax);
    let combined = 0;
    streams++;
    for (;;) {
      const m1 = br.get(24), m2 = br.get(24);
      if (m1 === 0x177245 && m2 === 0x385090) {
        const want = br.get(32);
        if (want !== combined >>> 0) throw new FormatError('bzip2 stream CRC mismatch');
        break;
      }
      if (m1 !== 0x314159 || m2 !== 0x265359) throw new FormatError('bad bzip2 block magic', br.pos >>> 3);
      const blockCrc = br.get(32);
      if (br.bit()) throw new FormatError('randomized bzip2 blocks are not supported');
      const origPtr = br.get(24);
      // symbol map
      const used = br.get(16);
      const seqToUnseq: number[] = [];
      for (let i = 0; i < 16; i++) {
        if (used & (0x8000 >>> i)) {
          const bits = br.get(16);
          for (let j = 0; j < 16; j++) if (bits & (0x8000 >>> j)) seqToUnseq.push(i * 16 + j);
        }
      }
      if (seqToUnseq.length === 0) throw new FormatError('bzip2 block uses no symbols');
      const alphaSize = seqToUnseq.length + 2;
      const nGroups = br.get(3);
      if (nGroups < 2 || nGroups > MAX_GROUPS) throw new FormatError('bad bzip2 table count');
      const nSelectors = br.get(15);
      if (nSelectors < 1) throw new FormatError('bad bzip2 selector count');
      const mtfGroups = [0, 1, 2, 3, 4, 5].slice(0, nGroups);
      const selectors = new Uint8Array(nSelectors);
      for (let i = 0; i < nSelectors; i++) {
        let j = 0;
        while (br.bit()) { j++; if (j >= nGroups) throw new FormatError('bad bzip2 selector'); }
        const v = mtfGroups[j] as number;
        mtfGroups.splice(j, 1);
        mtfGroups.unshift(v);
        selectors[i] = v;
      }
      // code length tables -> canonical decode tables
      const limits: Int32Array[] = [], bases: Int32Array[] = [], perms: Uint16Array[] = [], minLens: number[] = [];
      for (let t = 0; t < nGroups; t++) {
        const len = new Uint8Array(alphaSize);
        let cur = br.get(5);
        for (let s = 0; s < alphaSize; s++) {
          for (;;) {
            if (cur < 1 || cur > MAX_CODE_LEN) throw new FormatError('bad bzip2 code length');
            if (!br.bit()) break;
            cur += br.bit() ? -1 : 1;
          }
          len[s] = cur;
        }
        let minLen = 32, maxLen = 0;
        for (let s = 0; s < alphaSize; s++) { const l = len[s] as number; if (l > maxLen) maxLen = l; if (l < minLen) minLen = l; }
        const perm = new Uint16Array(alphaSize);
        let pp = 0;
        for (let l = minLen; l <= maxLen; l++) for (let s = 0; s < alphaSize; s++) if (len[s] === l) perm[pp++] = s;
        const count = new Int32Array(MAX_CODE_LEN + 2);
        for (let s = 0; s < alphaSize; s++) count[len[s] as number]!++;
        const limit = new Int32Array(MAX_CODE_LEN + 2).fill(-1);
        const base = new Int32Array(MAX_CODE_LEN + 2);
        let code = 0, idx = 0;
        for (let l = minLen; l <= maxLen; l++) {
          const c = count[l] as number;
          base[l] = idx - code;
          code += c; idx += c;
          limit[l] = code - 1;
          code <<= 1;
        }
        limits.push(limit); bases.push(base); perms.push(perm); minLens.push(minLen);
      }
      // MTF + RLE2 decode
      const mtf = new Uint8Array(256);
      for (let i = 0; i < 256; i++) mtf[i] = i;
      const unzftab = new Uint32Array(256);
      let count = 0, groupIdx = -1, groupLeft = 0;
      let runLen = 0, runBit = 1;
      const eob = alphaSize - 1;
      let gLimit = limits[0] as Int32Array, gBase = bases[0] as Int32Array, gPerm = perms[0] as Uint16Array, gMin = 0;
      for (;;) {
        if (groupLeft === 0) {
          groupIdx++;
          if (groupIdx >= nSelectors) throw new FormatError('bzip2 selectors ran out');
          const g = selectors[groupIdx] as number;
          gLimit = limits[g] as Int32Array; gBase = bases[g] as Int32Array; gPerm = perms[g] as Uint16Array; gMin = minLens[g] as number;
          groupLeft = 50;
        }
        groupLeft--;
        let l = gMin;
        let v = br.get(l);
        while (l <= MAX_CODE_LEN && v > (gLimit[l] as number)) { l++; v = (v << 1) | br.bit(); }
        if (l > MAX_CODE_LEN) throw new FormatError('bad bzip2 Huffman code');
        const sym = gPerm[v + (gBase[l] as number)];
        if (sym === undefined) throw new FormatError('bad bzip2 Huffman code');
        if (sym <= 1) { // RUNA / RUNB
          runLen += (sym + 1) * runBit;
          runBit <<= 1;
          if (runLen > blockMax) throw new FormatError('bzip2 run is longer than the block');
          continue;
        }
        if (runLen) {
          const byte = seqToUnseq[mtf[0] as number] as number;
          if (count + runLen > blockMax) throw new FormatError('bzip2 block overflow');
          unzftab[byte] = (unzftab[byte] as number) + runLen;
          tt.fill(byte, count, count + runLen);
          count += runLen;
          runLen = 0; runBit = 1;
        }
        if (sym === eob) break;
        const pos = sym - 1;
        const val = mtf[pos] as number;
        mtf.copyWithin(1, 0, pos);
        mtf[0] = val;
        const byte = seqToUnseq[val] as number;
        if (count >= blockMax) throw new FormatError('bzip2 block overflow');
        unzftab[byte]!++;
        tt[count++] = byte;
      }
      if (origPtr >= count) throw new FormatError('bzip2 origin pointer is out of range');
      // inverse BWT
      const cftab = new Uint32Array(257);
      for (let i = 0; i < 256; i++) cftab[i + 1] = (cftab[i] as number) + (unzftab[i] as number);
      for (let i = 0; i < count; i++) {
        const b = (tt[i] as number) & 0xff;
        const dst = cftab[b] as number;
        cftab[b] = dst + 1;
        tt[dst] = ((tt[dst] as number) & 0xff) | (i << 8);
      }
      // walk + RLE1 decode
      let out = new Uint8Array(Math.min(count + 1024, maxOut - total + 1));
      let o = 0, crc = 0xffffffff;
      const grow = (): void => {
        if (out.length >= maxOut - total) throw new FormatError('bzip2 output passed the size limit');
        const bigger = new Uint8Array(Math.min(out.length * 2, maxOut - total + 1));
        bigger.set(out); out = bigger;
      };
      let p = (tt[origPtr] as number) >>> 8;
      let last = -1, rep = 0;
      for (let i = 0; i < count; i++) {
        const e = tt[p] as number;
        const b = e & 0xff;
        p = e >>> 8;
        if (rep === 4) {
          for (let k = 0; k < b; k++) {
            if (o >= out.length) grow();
            out[o++] = last; crc = ((crc << 8) ^ (CRC[((crc >>> 24) ^ last) & 0xff] as number)) >>> 0;
          }
          rep = 0; last = -1;
          continue;
        }
        if (b === last) rep++; else { rep = 1; last = b; }
        if (o >= out.length) grow();
        out[o++] = b; crc = ((crc << 8) ^ (CRC[((crc >>> 24) ^ b) & 0xff] as number)) >>> 0;
      }
      crc = (~crc) >>> 0;
      if (crc !== blockCrc) throw new FormatError('bzip2 block CRC mismatch');
      combined = (((combined << 1) | (combined >>> 31)) ^ crc) >>> 0;
      total += o;
      if (total > maxOut) throw new FormatError('bzip2 output passed the size limit');
      chunks.push(out.subarray(0, o));
    }
  }
  const res = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { res.set(c, off); off += c.length; }
  return res;
}
