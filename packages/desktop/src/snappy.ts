// Snappy raw block decoder (the format LevelDB uses for compressed table blocks). Pure TS, no Node
// imports. Written from the public format description (google/snappy format_description.txt):
// a varint uncompressed length, then literals and back-references with 1, 2 or 4 byte offsets.
// Every read and copy is bounds-checked and the output size is capped before allocation.
import { InputError } from './proc.js';

/** Read the uncompressed length a Snappy block declares, without decoding it. */
export function snappyLength(b: Uint8Array): { length: number; headerBytes: number } {
  let v = 0, shift = 0, i = 0;
  for (; i < 5; i++) {
    if (i >= b.length) throw new InputError('snappy: truncated length');
    const c = b[i]!;
    v += (c & 0x7f) * 2 ** shift;
    if (!(c & 0x80)) return { length: v, headerBytes: i + 1 };
    shift += 7;
  }
  throw new InputError('snappy: length varint too long');
}

/** Decompress one raw Snappy block. maxOutput caps the declared size (default 64 MiB). */
export function snappyDecompress(b: Uint8Array, maxOutput = 64 * 1024 * 1024): Uint8Array {
  const { length, headerBytes } = snappyLength(b);
  if (length > maxOutput) throw new InputError(`snappy: block declares ${length} bytes, over the ${maxOutput} byte cap`);
  const out = new Uint8Array(length);
  let ip = headerBytes, op = 0;
  while (ip < b.length) {
    const tag = b[ip++]!;
    const kind = tag & 3;
    if (kind === 0) {
      // literal: length-1 in the upper 6 bits, or 1..4 extra little-endian length bytes
      let len = tag >>> 2;
      if (len >= 60) {
        const extra = len - 59;
        if (ip + extra > b.length) throw new InputError('snappy: truncated literal length');
        len = 0;
        for (let k = 0; k < extra; k++) len += b[ip + k]! * 2 ** (8 * k);
        ip += extra;
      }
      len += 1;
      if (ip + len > b.length) throw new InputError('snappy: literal runs past the input');
      if (op + len > length) throw new InputError('snappy: literal runs past the declared length');
      out.set(b.subarray(ip, ip + len), op);
      ip += len; op += len;
      continue;
    }
    let len: number, offset: number;
    if (kind === 1) {
      if (ip >= b.length) throw new InputError('snappy: truncated copy');
      len = ((tag >>> 2) & 7) + 4;
      offset = ((tag >>> 5) << 8) | b[ip++]!;
    } else if (kind === 2) {
      if (ip + 2 > b.length) throw new InputError('snappy: truncated copy');
      len = (tag >>> 2) + 1;
      offset = b[ip]! | (b[ip + 1]! << 8);
      ip += 2;
    } else {
      if (ip + 4 > b.length) throw new InputError('snappy: truncated copy');
      len = (tag >>> 2) + 1;
      offset = (b[ip]! | (b[ip + 1]! << 8) | (b[ip + 2]! << 16)) + b[ip + 3]! * 0x1000000;
      ip += 4;
    }
    if (offset === 0 || offset > op) throw new InputError('snappy: copy offset outside the output');
    if (op + len > length) throw new InputError('snappy: copy runs past the declared length');
    if (offset >= len) out.copyWithin(op, op - offset, op - offset + len);
    else for (let k = 0; k < len; k++) out[op + k] = out[op - offset + k]!; // overlapping run
    op += len;
  }
  if (op !== length) throw new InputError(`snappy: decoded ${op} of ${length} declared bytes`);
  return out;
}

// ---------------- CRC-32C (Castagnoli), used by LevelDB block trailers ----------------

let CRC_TABLE: Uint32Array | undefined;
function crcTable(): Uint32Array {
  if (CRC_TABLE) return CRC_TABLE;
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return (CRC_TABLE = t);
}

/** CRC-32C of bytes (optionally continuing from a previous value). */
export function crc32c(b: Uint8Array, crc = 0): number {
  const t = crcTable();
  let c = ~crc >>> 0;
  for (let i = 0; i < b.length; i++) c = t[(c ^ b[i]!) & 0xff]! ^ (c >>> 8);
  return ~c >>> 0;
}

/** LevelDB stores CRCs masked: rotate right by 15 and add a constant. */
export function unmaskCrc(masked: number): number {
  const rot = (masked - 0xa282ead8) >>> 0;
  return ((rot >>> 17) | (rot << 15)) >>> 0;
}
