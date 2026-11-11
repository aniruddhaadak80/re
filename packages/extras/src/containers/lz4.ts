// LZ4 block format decoder (no frame header), as used by Unity asset bundles and others.

import { ParseError } from '../util.js';

/** Decompress one LZ4 block into exactly `outSize` bytes. */
export function lz4Block(src: Uint8Array, outSize: number, maxOut = 512 << 20): Uint8Array {
  if (!Number.isInteger(outSize) || outSize < 0 || outSize > maxOut) throw new ParseError(`bad LZ4 output size ${outSize}`);
  const out = new Uint8Array(outSize);
  let i = 0, o = 0;
  while (i < src.length) {
    const token = src[i++]!;
    let lit = token >> 4;
    if (lit === 15) { let c: number; do { if (i >= src.length) throw new ParseError('truncated LZ4 literal length', i); c = src[i++]!; lit += c; } while (c === 255); }
    if (i + lit > src.length || o + lit > outSize) throw new ParseError('LZ4 literal run out of range', i);
    out.set(src.subarray(i, i + lit), o);
    i += lit; o += lit;
    if (i >= src.length) break;
    if (i + 2 > src.length) throw new ParseError('truncated LZ4 offset', i);
    const off = src[i]! | (src[i + 1]! << 8);
    i += 2;
    if (off === 0 || off > o) throw new ParseError('bad LZ4 match offset', i);
    let ml = token & 15;
    if (ml === 15) { let c: number; do { if (i >= src.length) throw new ParseError('truncated LZ4 match length', i); c = src[i++]!; ml += c; } while (c === 255); }
    ml += 4;
    if (o + ml > outSize) throw new ParseError('LZ4 match runs past the output', i);
    for (let k = 0; k < ml; k++, o++) out[o] = out[o - off]!;
  }
  if (o !== outSize) throw new ParseError(`LZ4 produced ${o} bytes, expected ${outSize}`);
  return out;
}
