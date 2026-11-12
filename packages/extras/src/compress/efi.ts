// EFI 1.1 and Tiano decompression (the LZ77 + Huffman scheme of UEFI EFI_COMPRESSION_SECTION and the
// Tiano GUIDed section). Original TypeScript written from the algorithm as the UEFI specification
// and EDK2's BaseUefiDecompressLib describe it; the two variants differ only in the width of the
// position code count (4 bits for EFI, 5 bits for Tiano).

import { ParseError } from '../util.js';

const NC = 510, CBIT = 9, NT = 19, TBIT = 5, MAXNP = 31, NPT = 31;

class Dec {
  pos = 0;
  left = new Uint16Array(2 * NC - 1);
  right = new Uint16Array(2 * NC - 1);
  cLen = new Uint8Array(NC);
  ptLen = new Uint8Array(NPT);
  cTable = new Uint16Array(4096);
  ptTable = new Uint16Array(256);
  blockSize = 0;
  constructor(private src: Uint8Array, private start: number, private end: number, private pBit: number) { this.pos = start * 8; }
  /** The next 32 bits of the stream, zero past the end (as the reference bit buffer behaves). */
  peek(): number {
    const byte = this.pos >>> 3, sh = this.pos & 7;
    let v = 0;
    for (let k = 0; k < 5; k++) { const i = byte + k; v = v * 256 + (i < this.end ? (this.src[i] as number) : 0); }
    // v holds 40 bits; drop the leading sh bits and the trailing 8 - sh bits
    return Math.floor(v / 2 ** (8 - sh)) % 0x100000000;
  }
  skip(n: number): void { this.pos += n; }
  bits(n: number): number { if (!n) return 0; const v = Math.floor(this.peek() / 2 ** (32 - n)); this.pos += n; return v; }

  makeTable(n: number, len: Uint8Array, tableBits: number, table: Uint16Array): void {
    const count = new Uint16Array(17), weight = new Uint16Array(17), start = new Uint32Array(18);
    for (let i = 0; i < n; i++) { const l = len[i] as number; if (l > 16) throw new ParseError('EFI decompress: bad code length'); count[l]!++; }
    for (let i = 1; i <= 16; i++) start[i + 1] = (start[i]! + (count[i]! << (16 - i))) & 0xffff;
    if (start[17] !== 0) throw new ParseError('EFI decompress: bad Huffman table');
    const ju = 16 - tableBits;
    let i = 1;
    for (; i <= tableBits; i++) { start[i] = start[i]! >>> ju; weight[i] = 1 << (tableBits - i); }
    for (; i <= 16; i++) weight[i] = 1 << (16 - i);
    const first = start[tableBits + 1]! >>> ju;
    if (first !== 0) { const lim = 1 << tableBits; if (first < lim) table.fill(0, first, lim); }
    let avail = n;
    const mask = 1 << (15 - tableBits);
    const maxLen = 1 << tableBits;
    for (let ch = 0; ch < n; ch++) {
      const l = len[ch] as number;
      if (l === 0 || l >= 17) continue;
      const next = (start[l]! + weight[l]!) & 0xffff;
      if (l <= tableBits) {
        if (start[l]! >= next || next > maxLen) throw new ParseError('EFI decompress: bad Huffman table');
        for (let k = start[l]!; k < next; k++) table[k] = ch;
      } else {
        let idx3 = start[l]!;
        let arr: Uint16Array = table, at = idx3 >>> ju;
        if (at >= table.length) throw new ParseError('EFI decompress: bad Huffman table');
        for (let k = l - tableBits; k; k--) {
          if (arr[at] === 0 && avail < 2 * NC - 1) { this.right[avail] = 0; this.left[avail] = 0; arr[at] = avail++; }
          const node = arr[at] as number;
          if (node < 2 * NC - 1) { if (idx3 & mask) { arr = this.right; at = node; } else { arr = this.left; at = node; } }
          idx3 = (idx3 << 1) & 0xffff;
        }
        arr[at] = ch;
      }
      start[l] = next;
    }
  }

  readPtLen(nn: number, nbit: number, special: number): void {
    const number = this.bits(nbit);
    if (number === 0) {
      const c = this.bits(nbit);
      this.ptTable.fill(c);
      this.ptLen.fill(0, 0, nn);
      return;
    }
    if (number > nn) throw new ParseError('EFI decompress: bad length count');
    let i = 0;
    while (i < number && i < NPT) {
      let c = this.peek() >>> 29;
      if (c === 7) {
        let m = 1 << 28;
        const buf = this.peek();
        while (m && (buf & m)) { m >>>= 1; c++; }
        if (c > 16) throw new ParseError('EFI decompress: bad code length');
      }
      this.skip(c < 7 ? 3 : c - 3);
      this.ptLen[i++] = c;
      if (i === special) { let z = this.bits(2); while (z-- > 0 && i < NPT) this.ptLen[i++] = 0; }
    }
    while (i < nn && i < NPT) this.ptLen[i++] = 0;
    this.makeTable(nn, this.ptLen, 8, this.ptTable);
  }

  walk(v: number, limit: number, tableBits: number): number {
    if (v < limit) return v;
    const buf = this.peek();
    let m = 1 << (31 - tableBits);
    for (let guard = 0; v >= limit; guard++) {
      if (guard > 24 || !m) throw new ParseError('EFI decompress: bad code');
      v = buf & m ? this.right[v]! : this.left[v]!;
      m >>>= 1;
    }
    return v;
  }

  readCLen(): void {
    const number = this.bits(CBIT);
    if (number === 0) { const c = this.bits(CBIT); this.cLen.fill(0); this.cTable.fill(c); return; }
    let i = 0;
    while (i < number && i < NC) {
      const c = this.walk(this.ptTable[this.peek() >>> 24]!, NT, 8);
      this.skip(this.ptLen[c]!);
      if (c <= 2) {
        let z = c === 0 ? 1 : c === 1 ? this.bits(4) + 3 : this.bits(CBIT) + 20;
        while (z-- > 0 && i < NC) this.cLen[i++] = 0;
      } else this.cLen[i++] = c - 2;
    }
    this.cLen.fill(0, i);
    this.makeTable(NC, this.cLen, 12, this.cTable);
  }

  decodeC(): number {
    if (this.blockSize === 0) {
      this.blockSize = this.bits(16);
      this.readPtLen(NT, TBIT, 3);
      this.readCLen();
      this.readPtLen(MAXNP, this.pBit, 0x10000);
    }
    this.blockSize--;
    const c = this.walk(this.cTable[this.peek() >>> 20]!, NC, 12);
    if (c >= NC) throw new ParseError('EFI decompress: bad symbol');
    this.skip(this.cLen[c]!);
    return c;
  }

  decodeP(): number {
    const v = this.walk(this.ptTable[this.peek() >>> 24]!, MAXNP, 8);
    this.skip(this.ptLen[v]!);
    return v > 1 ? (1 << (v - 1)) + this.bits(v - 1) : v;
  }
}

export interface EfiDecompressResult { data: Uint8Array; variant: 'efi' | 'tiano'; compressedSize: number; end: number }

function run(b: Uint8Array, start: number, variant: 'efi' | 'tiano', maxOut: number): EfiDecompressResult {
  if (start + 8 > b.length) throw new ParseError('EFI compressed data is shorter than its header');
  const dv = new DataView(b.buffer, b.byteOffset + start, 8);
  const compSize = dv.getUint32(0, true), origSize = dv.getUint32(4, true);
  if (origSize > maxOut) throw new ParseError(`EFI decompressed size ${origSize} exceeds the limit of ${maxOut} bytes`);
  if (start + 8 + compSize > b.length) throw new ParseError('EFI compressed data runs past the end');
  const d = new Dec(b, start + 8, start + 8 + compSize, variant === 'efi' ? 4 : 5);
  const out = new Uint8Array(origSize);
  let o = 0;
  let guard = 0;
  while (o < origSize) {
    if (++guard > origSize + 1024 || d.pos > (start + 8 + compSize + 8) * 8) throw new ParseError('EFI decompress: stream ended early');
    const c = d.decodeC();
    if (c < 256) { out[o++] = c; continue; }
    let len = c - 253;
    const from = o - d.decodeP() - 1;
    if (from < 0) throw new ParseError('EFI decompress: back reference before the start');
    for (let s = from; len > 0 && o < origSize; len--) out[o++] = out[s++]!;
  }
  return { data: out, variant, compressedSize: compSize, end: start + 8 + compSize };
}

/** Decompress EFI 1.1 or Tiano data (8 byte size header first). With variant auto, EFI is tried first, then Tiano. */
export function efiDecompress(b: Uint8Array, opts: { start?: number; variant?: 'efi' | 'tiano' | 'auto'; maxOut?: number } = {}): EfiDecompressResult {
  const start = opts.start ?? 0, maxOut = opts.maxOut ?? 256 << 20;
  const v = opts.variant ?? 'auto';
  if (v !== 'auto') return run(b, start, v, maxOut);
  try { return run(b, start, 'efi', maxOut); } catch (e) {
    try { return run(b, start, 'tiano', maxOut); } catch { throw e; }
  }
}
