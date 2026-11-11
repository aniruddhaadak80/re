// LZXPRESS Huffman decompression (MS-XCA section 2.2), used by Windows 10+ compressed
// Prefetch files (MAM\x04) and other Windows formats. Pure TS, capped output size.

import { ParseError } from '../util.js';

/** Decompress an LZXPRESS Huffman stream into exactly `outSize` bytes (or fewer if input ends). */
export function lzxpressHuffman(input: Uint8Array, outSize: number, maxOut = 256 << 20): Uint8Array {
  if (!Number.isInteger(outSize) || outSize < 0 || outSize > maxOut) throw new ParseError(`bad decompressed size ${outSize}`);
  const out = new Uint8Array(outSize);
  let inPos = 0, outPos = 0;
  while (outPos < outSize) {
    if (inPos + 256 > input.length) throw new ParseError('truncated Huffman table', inPos);
    // 512 symbols, 4 bit code lengths
    const lens = new Uint8Array(512);
    for (let i = 0; i < 256; i++) { const b = input[inPos + i]!; lens[2 * i] = b & 15; lens[2 * i + 1] = b >> 4; }
    inPos += 256;
    const table = buildTable(lens);
    const blockEnd = Math.min(outSize, outPos + 65536);
    // bit reader: 32 bit window refilled 16 bits at a time
    const u16 = (p: number): number => (p + 1 < input.length ? input[p]! | (input[p + 1]! << 8) : p < input.length ? input[p]! : 0);
    let bits = ((u16(inPos) << 16) | u16(inPos + 2)) >>> 0;
    let avail = 32;
    inPos += 4;
    const consume = (n: number): void => {
      bits = (bits << n) >>> 0;
      avail -= n;
      if (avail < 16) { bits = (bits | (u16(inPos) << (16 - avail))) >>> 0; avail += 16; inPos += 2; }
    };
    while (outPos < blockEnd) {
      const e = table[bits >>> 17]!;
      if (!e) throw new ParseError('invalid Huffman code', inPos);
      const sym = e >> 4, len = e & 15;
      consume(len);
      if (sym < 256) { out[outPos++] = sym; continue; }
      let mlen = sym & 15;
      const dbits = (sym >> 4) & 15;
      if (mlen === 15) {
        if (inPos >= input.length) throw new ParseError('truncated match length', inPos);
        mlen = input[inPos++]!;
        if (mlen === 255) {
          if (inPos + 1 >= input.length) throw new ParseError('truncated match length', inPos);
          mlen = input[inPos]! | (input[inPos + 1]! << 8);
          inPos += 2;
          if (mlen === 0) {
            if (inPos + 3 >= input.length) throw new ParseError('truncated match length', inPos);
            mlen = (input[inPos]! | (input[inPos + 1]! << 8) | (input[inPos + 2]! << 16) | (input[inPos + 3]! << 24)) >>> 0;
            inPos += 4;
          }
          if (mlen < 15) throw new ParseError('bad match length', inPos);
          mlen -= 15;
        }
        mlen += 15;
      }
      mlen += 3;
      let dist = 0;
      if (dbits) { dist = bits >>> (32 - dbits); consume(dbits); }
      dist += 1 << dbits;
      if (dist > outPos) throw new ParseError('match distance before start of output', inPos);
      for (let i = 0; i < mlen && outPos < outSize; i++, outPos++) out[outPos] = out[outPos - dist]!;
    }
    // the next block's 256 byte table starts at the current read position (MS-XCA 2.2.4)
  }
  return out;
}

/** Canonical Huffman decode table indexed by the top 15 bits: entry = symbol << 4 | length. */
function buildTable(lens: Uint8Array): Uint16Array {
  const t = new Uint16Array(1 << 15);
  let code = 0;
  for (let len = 1; len <= 15; len++) {
    for (let sym = 0; sym < 512; sym++) {
      if (lens[sym] !== len) continue;
      const span = 1 << (15 - len);
      const start = code << (15 - len);
      if (start + span > t.length) throw new ParseError('oversubscribed Huffman table');
      t.fill((sym << 4) | len, start, start + span);
      code++;
    }
    code <<= 1;
  }
  return t;
}
