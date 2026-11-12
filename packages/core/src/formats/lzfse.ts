// LZFSE and LZVN decoder (Apple's codecs, used by ULFO disk images, AppleArchive and compressed
// files). Written in TypeScript from the format as published in Apple's BSD licensed reference
// implementation (github.com/lzfse/lzfse); the constant tables below are the format's own.
// Block types: bvx- (stored), bvx1 and bvx2 (LZFSE with FSE entropy coding), bvxn (LZVN), bvx$ (end).
// Every read and copy is bounds checked; output is capped.

import { FormatError } from './util.js';

export class UnsupportedCodec extends FormatError {}

const MAGIC_END = 0x24787662, MAGIC_RAW = 0x2d787662, MAGIC_V1 = 0x31787662, MAGIC_V2 = 0x32787662, MAGIC_LZVN = 0x6e787662;
const L_STATES = 64, M_STATES = 64, D_STATES = 256, LIT_STATES = 1024;
const L_SYMBOLS = 20, M_SYMBOLS = 20, D_SYMBOLS = 64, LIT_SYMBOLS = 256;
const L_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60];
const M_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312];
const D_BITS = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15];
const D_BASE = [0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372];
const FREQ_NBITS = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14];
const FREQ_VALUE = [0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1];

const clz32 = Math.clz32;

class Out {
  buf: Uint8Array;
  n = 0;
  constructor(hint: number, readonly max: number) { this.buf = new Uint8Array(Math.max(256, Math.min(hint, max))); }
  ensure(extra: number): void {
    if (this.n + extra > this.max) throw new FormatError('LZFSE output passes the size limit');
    if (this.n + extra <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.n + extra) size *= 2;
    const b = new Uint8Array(Math.min(size, this.max));
    b.set(this.buf.subarray(0, this.n));
    this.buf = b;
  }
  match(dist: number, len: number): void {
    if (dist <= 0 || dist > this.n) throw new FormatError(`LZFSE match distance ${dist} is out of range`);
    this.ensure(len);
    const b = this.buf;
    let s = this.n - dist, d = this.n;
    for (let i = 0; i < len; i++) b[d++] = b[s++] as number;
    this.n = d;
  }
  bytes(src: Uint8Array, from: number, len: number): void {
    if (from < 0 || from + len > src.length) throw new FormatError('LZFSE literal run passes the end of the input');
    this.ensure(len);
    this.buf.set(src.subarray(from, from + len), this.n);
    this.n += len;
  }
}

/** Backward bit reader with a 32 bit accumulator (the format's 32 bit decoder path). */
class InStream {
  accum = 0;
  nbits = 0;
  pos: number;
  constructor(private readonly b: Uint8Array, end: number, n: number, private readonly start: number) {
    this.pos = end;
    if (n) {
      if (this.pos < start + 4) throw new FormatError('LZFSE bit stream is too short');
      this.pos -= 4;
      this.accum = this.load(this.pos, 4);
      this.nbits = n + 32;
    } else {
      if (this.pos < start + 3) throw new FormatError('LZFSE bit stream is too short');
      this.pos -= 3;
      this.accum = this.load(this.pos, 3);
      this.nbits = 24;
    }
    if (this.nbits < 24 || this.nbits >= 32 || (this.accum >>> this.nbits) !== 0) throw new FormatError('LZFSE bit stream header is invalid');
  }
  private load(p: number, n: number): number {
    const b = this.b;
    let v = 0;
    for (let i = n - 1; i >= 0; i--) v = ((v << 8) | ((b[p + i] ?? 0) as number)) >>> 0;
    return v;
  }
  flush(): void {
    const n = (31 - this.nbits) & -8;
    if (!n) return;
    const p = this.pos - (n >> 3);
    if (p < this.start) throw new FormatError('LZFSE bit stream underflow');
    this.pos = p;
    const incoming = this.load(p, 4) & ((1 << n) - 1);
    this.accum = ((this.accum << n) | incoming) >>> 0;
    this.nbits += n;
  }
  pull(n: number): number {
    if (n > this.nbits) throw new FormatError('LZFSE bit stream ran out of bits');
    const nb = (this.nbits -= n);
    if (nb === 0) { const r = this.accum; this.accum = 0; return r; }
    const r = this.accum >>> nb;
    this.accum = (this.accum & (0xffffffff >>> (32 - nb))) >>> 0;
    return r;
  }
}

interface Tables { lit: { sym: Uint8Array; k: Int8Array; delta: Int32Array }; l: ValueTable; m: ValueTable; d: ValueTable }
interface ValueTable { total: Uint8Array; vbits: Uint8Array; delta: Int32Array; vbase: Int32Array }

function litTable(freq: Uint16Array | number[]): Tables['lit'] {
  const sym = new Uint8Array(LIT_STATES), k = new Int8Array(LIT_STATES), delta = new Int32Array(LIT_STATES);
  const nclz = clz32(LIT_STATES);
  let sum = 0, t = 0;
  for (let i = 0; i < LIT_SYMBOLS; i++) {
    const f = freq[i] as number;
    if (!f) continue;
    sum += f;
    if (sum > LIT_STATES) throw new FormatError('LZFSE literal frequencies sum past the state count');
    const kk = clz32(f) - nclz;
    const j0 = ((2 * LIT_STATES) >> kk) - f;
    for (let j = 0; j < f; j++, t++) {
      sym[t] = i;
      if (j < j0) { k[t] = kk; delta[t] = ((f + j) << kk) - LIT_STATES; } else { k[t] = kk - 1; delta[t] = (j - j0) << (kk - 1); }
    }
  }
  return { sym, k, delta };
}

function valueTable(nstates: number, nsym: number, freq: ArrayLike<number>, bits: number[], base: number[]): ValueTable {
  const total = new Uint8Array(nstates), vbits = new Uint8Array(nstates), delta = new Int32Array(nstates), vbase = new Int32Array(nstates);
  const nclz = clz32(nstates);
  let sum = 0, t = 0;
  for (let i = 0; i < nsym; i++) {
    const f = freq[i] as number;
    if (!f) continue;
    sum += f;
    if (sum > nstates) throw new FormatError('LZFSE frequencies sum past the state count');
    const kk = clz32(f) - nclz;
    const j0 = ((2 * nstates) >> kk) - f;
    for (let j = 0; j < f; j++, t++) {
      vbits[t] = bits[i] as number; vbase[t] = base[i] as number;
      if (j < j0) { total[t] = kk + (bits[i] as number); delta[t] = ((f + j) << kk) - nstates; } else { total[t] = kk - 1 + (bits[i] as number); delta[t] = (j - j0) << (kk - 1); }
    }
  }
  return { total, vbits, delta, vbase };
}

function valueDecode(st: { s: number }, t: ValueTable, inp: InStream): number {
  const s = st.s;
  if (s >= t.total.length) throw new FormatError('LZFSE state is out of range');
  const bits = inp.pull(t.total[s] as number);
  const vb = t.vbits[s] as number;
  st.s = (t.delta[s] as number) + (bits >>> vb);
  return (t.vbase[s] as number) + (bits & ((1 << vb) - 1));
}

function decodeLzfseBlock(src: Uint8Array, p: number, out: Out, h: { nRaw: number; nLiterals: number; nMatches: number; litPayload: number; lmdPayload: number; litBits: number; litState: number[]; lmdBits: number; lState: number; mState: number; dState: number; headerSize: number; freq: { l: ArrayLike<number>; m: ArrayLike<number>; d: ArrayLike<number>; lit: ArrayLike<number> } }): number {
  if (h.nLiterals > 4 * 10000 + 64 || h.nLiterals % 4) throw new FormatError('LZFSE literal count is invalid');
  for (const s of h.litState) if (s >= LIT_STATES) throw new FormatError('LZFSE literal state is out of range');
  if (h.lState >= L_STATES || h.mState >= M_STATES || h.dState >= D_STATES) throw new FormatError('LZFSE L, M or D state is out of range');
  const lit = litTable(h.freq.lit as number[]);
  const tl = valueTable(L_STATES, L_SYMBOLS, h.freq.l, L_BITS, L_BASE);
  const tm = valueTable(M_STATES, M_SYMBOLS, h.freq.m, M_BITS, M_BASE);
  const td = valueTable(D_STATES, D_SYMBOLS, h.freq.d, D_BITS, D_BASE);
  const payload = p + h.headerSize;
  const litEnd = payload + h.litPayload;
  const lmdEnd = litEnd + h.lmdPayload;
  if (lmdEnd > src.length) throw new FormatError('LZFSE block payload passes the end of the input');
  // literals
  const literals = new Uint8Array(h.nLiterals + 64);
  const li = new InStream(src, litEnd, h.litBits, 0); // like the reference, the literal stream may read back into the header
  const ls = h.litState.slice();
  for (let i = 0; i < h.nLiterals; i += 4) {
    for (let q = 0; q < 4; q++) {
      if (q === 0 || q === 2) li.flush();
      const s = ls[q] as number;
      literals[i + q] = lit.sym[s] as number;
      ls[q] = (lit.delta[s] as number) + li.pull(lit.k[s] as number);
      if ((ls[q] as number) >= LIT_STATES) throw new FormatError('LZFSE literal state is out of range');
    }
  }
  // L, M, D
  const mi = new InStream(src, lmdEnd, h.lmdBits, litEnd);
  const sl = { s: h.lState }, sm = { s: h.mState }, sd = { s: h.dState };
  let D = -1, litPos = 0;
  const start = out.n;
  for (let n = 0; n < h.nMatches; n++) {
    mi.flush(); const L = valueDecode(sl, tl, mi);
    mi.flush(); const M = valueDecode(sm, tm, mi);
    mi.flush(); const nd = valueDecode(sd, td, mi);
    if (nd) D = nd;
    if (litPos + L > literals.length) throw new FormatError('LZFSE literal run passes the decoded literals');
    out.bytes(literals, litPos, L);
    litPos += L;
    if (M) out.match(D, M);
  }
  // Remaining literals after the last match belong to the block too only when nRaw says so.
  const produced = out.n - start;
  if (produced < h.nRaw) {
    const rest = Math.min(h.nRaw - produced, h.nLiterals - litPos);
    if (rest > 0) out.bytes(literals, litPos, rest);
  }
  if (out.n - start !== h.nRaw) throw new FormatError(`LZFSE block decoded to ${out.n - start} bytes, header says ${h.nRaw}`);
  return lmdEnd;
}

function bitsField(lo: number, hi: number, offset: number, n: number): number {
  // 64 bit little endian field split in two 32 bit words
  let v = 0;
  for (let i = 0; i < n; i++) {
    const b = offset + i;
    const bit = b < 32 ? (lo >>> b) & 1 : (hi >>> (b - 32)) & 1;
    v += bit * 2 ** i;
  }
  return v;
}

function lzvn(src: Uint8Array, p: number, end: number, out: Out, nRaw: number): void {
  const start = out.n;
  let D = 0;
  while (p < end) {
    const op = src[p] as number;
    let L = 0, M = 0, len = 1;
    const need = (n: number): void => { if (p + n > end) throw new FormatError('LZVN opcode is truncated'); };
    if (op === 0x06) { p += 8; break; } // end of stream
    if (op === 0x0e || op === 0x16) { p++; continue; } // nop
    const lo3 = op & 7;
    if ((op >= 0x70 && op <= 0x7f) || (op >= 0xd0 && op <= 0xdf) || (op < 0x40 && (op & 7) === 6)) throw new FormatError(`LZVN opcode 0x${op.toString(16)} is undefined`);
    if (op >= 0xa0 && op <= 0xbf) { // med_d
      need(3); len = 3;
      const w = (src[p + 1] as number) | ((src[p + 2] as number) << 8);
      L = (op >> 3) & 3; M = (((op & 7) << 2) | (w & 3)) + 3; D = w >> 2;
    } else if (op >= 0xe0 && op <= 0xef) { // literals only
      if (op === 0xe0) { need(2); L = (src[p + 1] as number) + 16; len = 2; } else L = op & 15;
      need(len + L);
      out.bytes(src, p + len, L);
      p += len + L;
      continue;
    } else if (op >= 0xf0) { // match with the previous distance
      if (op === 0xf0) { need(2); M = (src[p + 1] as number) + 16; len = 2; } else M = op & 15;
      p += len;
      out.match(D, M);
      continue;
    } else if (lo3 === 7) { need(3); len = 3; L = op >> 6; M = ((op >> 3) & 7) + 3; D = (src[p + 1] as number) | ((src[p + 2] as number) << 8); }
    else if (lo3 === 6) { L = op >> 6; M = ((op >> 3) & 7) + 3; } // previous distance
    else { need(2); len = 2; L = op >> 6; M = ((op >> 3) & 7) + 3; D = ((op & 7) << 8) | (src[p + 1] as number); }
    need(len + L);
    out.bytes(src, p + len, L);
    p += len + L;
    out.match(D, M);
  }
  if (out.n - start !== nRaw) throw new FormatError(`LZVN block decoded to ${out.n - start} bytes, header says ${nRaw}`);
}

/** Decompress an LZFSE stream (any mix of block types). expected sizes the first allocation. */
export function lzfseDecompress(src: Uint8Array, expected = 0, maxOut = 512 * 1024 * 1024): Uint8Array {
  const out = new Out(expected || src.length * 4, Math.max(maxOut, expected));
  const dv = new DataView(src.buffer, src.byteOffset, src.byteLength);
  const u32 = (o: number): number => { if (o + 4 > src.length) throw new FormatError('LZFSE header is truncated', o); return dv.getUint32(o, true); };
  let p = 0;
  for (let guard = 0; guard < 1 << 20; guard++) {
    const magic = u32(p);
    if (magic === MAGIC_END) return out.buf.slice(0, out.n);
    if (magic === MAGIC_RAW) {
      const n = u32(p + 4);
      out.bytes(src, p + 8, n);
      p += 8 + n;
    } else if (magic === MAGIC_LZVN) {
      const nRaw = u32(p + 4), nPay = u32(p + 8);
      if (p + 12 + nPay > src.length) throw new FormatError('LZVN block passes the end of the input');
      out.ensure(nRaw);
      lzvn(src, p + 12, p + 12 + nPay, out, nRaw);
      p += 12 + nPay;
    } else if (magic === MAGIC_V2) {
      const nRaw = u32(p + 4);
      const f0l = u32(p + 8), f0h = u32(p + 12), f1l = u32(p + 16), f1h = u32(p + 20), f2l = u32(p + 24), f2h = u32(p + 28);
      const headerSize = f2l;
      if (headerSize < 32 || p + headerSize > src.length) throw new FormatError('LZFSE v2 header size is invalid', p);
      // frequency tables, packed with a small variable length code
      const freq = new Uint16Array(L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LIT_SYMBOLS);
      let q = p + 32;
      const qend = p + headerSize;
      let accum = 0, an = 0;
      for (let i = 0; i < freq.length; i++) {
        while (q < qend && an + 8 <= 32) { accum = (accum + (src[q] as number) * 2 ** an) >>> 0; an += 8; q++; }
        const b = accum & 31;
        const nb = FREQ_NBITS[b] as number;
        const val = nb === 8 ? 8 + ((accum >>> 4) & 0xf) : nb === 14 ? 24 + ((accum >>> 4) & 0x3ff) : (FREQ_VALUE[b] as number);
        if (nb > an) throw new FormatError('LZFSE frequency table is truncated', q);
        freq[i] = val;
        accum = accum >>> nb; an -= nb;
      }
      if (an >= 8 || q !== qend) throw new FormatError('LZFSE frequency table does not end with the header', q);
      const h = {
        nRaw, headerSize,
        nLiterals: bitsField(f0l, f0h, 0, 20), litPayload: bitsField(f0l, f0h, 20, 20), nMatches: bitsField(f0l, f0h, 40, 20), litBits: bitsField(f0l, f0h, 60, 3) - 7,
        litState: [bitsField(f1l, f1h, 0, 10), bitsField(f1l, f1h, 10, 10), bitsField(f1l, f1h, 20, 10), bitsField(f1l, f1h, 30, 10)],
        lmdPayload: bitsField(f1l, f1h, 40, 20), lmdBits: bitsField(f1l, f1h, 60, 3) - 7,
        lState: bitsField(f2l, f2h, 32, 10), mState: bitsField(f2l, f2h, 42, 10), dState: bitsField(f2l, f2h, 52, 10),
        freq: { l: freq.subarray(0, 20), m: freq.subarray(20, 40), d: freq.subarray(40, 104), lit: Array.from(freq.subarray(104)) },
      };
      out.ensure(nRaw);
      p = decodeLzfseBlock(src, p, out, h);
    } else if (magic === MAGIC_V1) {
      const nRaw = u32(p + 4);
      const r16 = (o: number): number => { if (p + o + 2 > src.length) throw new FormatError('LZFSE v1 header is truncated'); return dv.getUint16(p + o, true); };
      const i32 = (o: number): number => u32(p + o) | 0;
      const fr = (o: number, n: number): number[] => { const a: number[] = []; for (let i = 0; i < n; i++) a.push(r16(o + i * 2)); return a; };
      const h = {
        nRaw, headerSize: 772, nLiterals: u32(p + 12), nMatches: u32(p + 16), litPayload: u32(p + 20), lmdPayload: u32(p + 24), litBits: i32(28),
        litState: [r16(32), r16(34), r16(36), r16(38)], lmdBits: i32(40), lState: r16(44), mState: r16(46), dState: r16(48),
        freq: { l: fr(50, 20), m: fr(90, 20), d: fr(130, 64), lit: fr(258, 256) },
      };
      out.ensure(nRaw);
      p = decodeLzfseBlock(src, p, out, h);
    } else throw new FormatError(`unknown LZFSE block magic 0x${magic.toString(16)}`, p);
  }
  throw new FormatError('LZFSE stream has too many blocks');
}
