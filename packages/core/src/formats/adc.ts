// Apple Data Compression (ADC), the LZ77 variant used by UDCO disk image chunks.
// Control byte: 1xxxxxxx literal run of (x+1) bytes; 01xxxxxx three byte match of (x+4) bytes with a
// 16 bit big endian distance; 00xxxxyy two byte match of (xxxx+3) bytes with a 10 bit distance.
// The copy source is out - distance - 1.

import { FormatError } from './util.js';

export function adcDecompress(input: Uint8Array, expected: number, maxOut = 512 * 1024 * 1024): Uint8Array {
  const cap = Math.min(maxOut, Math.max(0, expected));
  const out = new Uint8Array(cap);
  let i = 0, o = 0;
  while (i < input.length && o < cap) {
    const c = input[i++] as number;
    if (c & 0x80) {
      const len = (c & 0x7f) + 1;
      if (i + len > input.length) throw new FormatError('ADC literal run passes the end of the chunk', i);
      if (o + len > cap) throw new FormatError('ADC output passes the expected size', i);
      out.set(input.subarray(i, i + len), o);
      i += len; o += len;
      continue;
    }
    let len: number, dist: number;
    if (c & 0x40) {
      if (i + 2 > input.length) throw new FormatError('ADC match is truncated', i);
      len = (c & 0x3f) + 4;
      dist = ((input[i] as number) << 8) | (input[i + 1] as number);
      i += 2;
    } else {
      if (i + 1 > input.length) throw new FormatError('ADC match is truncated', i);
      len = ((c >> 2) & 0x0f) + 3;
      dist = ((c & 3) << 8) | (input[i] as number);
      i += 1;
    }
    const src = o - dist - 1;
    if (src < 0) throw new FormatError('ADC match points before the start of the output', i);
    if (o + len > cap) throw new FormatError('ADC output passes the expected size', i);
    for (let k = 0; k < len; k++) out[o + k] = out[src + k] as number; // overlapping copy, byte by byte
    o += len;
  }
  return o === cap ? out : out.subarray(0, o);
}
