// Zstandard frames: a bounds checked frame walker (header, blocks, checksum) that finds the exact
// compressed length and an output bound, with decoding delegated to fzstd (MIT, pure JS).

import { decompress as fzstdDecompress } from 'fzstd';
import { ParseError } from '../util.js';
import { OutputLimitError } from './inflate.js';

export const ZSTD_MAGIC = 0xfd2fb528;

export interface ZstdFrame { start: number; end: number; contentSize: number | null; windowSize: number | null; dictId: number | null; checksum: boolean; blocks: number; outputBound: number; skippable?: boolean }

const u32 = (b: Uint8Array, o: number) => ((b[o] as number) | ((b[o + 1] as number) << 8) | ((b[o + 2] as number) << 16) | ((b[o + 3] as number) << 24)) >>> 0;

/** Walk one frame (or a skippable frame) at `start` without decoding. */
export function zstdFrameInfo(b: Uint8Array, start = 0): ZstdFrame {
  if (start + 4 > b.length) throw new ParseError('zstd frame truncated', start);
  const magic = u32(b, start);
  if ((magic & 0xfffffff0) >>> 0 === 0x184d2a50) {
    if (start + 8 > b.length) throw new ParseError('skippable frame truncated', start);
    const size = u32(b, start + 4);
    if (start + 8 + size > b.length) throw new ParseError('skippable frame runs past the end', start);
    return { start, end: start + 8 + size, contentSize: 0, windowSize: null, dictId: null, checksum: false, blocks: 0, outputBound: 0, skippable: true };
  }
  if (magic !== ZSTD_MAGIC) throw new ParseError('not a zstd frame', start);
  let p = start + 4;
  if (p >= b.length) throw new ParseError('zstd frame header truncated', start);
  const fhd = b[p++] as number;
  if (fhd & 0x08) throw new ParseError('zstd reserved bit set', start);
  const fcsFlag = fhd >> 6, single = (fhd >> 5) & 1, checksum = (fhd >> 2) & 1, didFlag = fhd & 3;
  let windowSize: number | null = null;
  if (!single) {
    if (p >= b.length) throw new ParseError('zstd window descriptor truncated');
    const wd = b[p++] as number;
    const exp = wd >> 3, mant = wd & 7;
    const base = 2 ** (10 + exp);
    windowSize = base + (base / 8) * mant;
  }
  const didSize = [0, 1, 2, 4][didFlag] as number;
  if (p + didSize > b.length) throw new ParseError('zstd dictionary id truncated');
  let dictId: number | null = null;
  if (didSize) { dictId = 0; for (let k = didSize - 1; k >= 0; k--) dictId = dictId * 256 + (b[p + k] as number); }
  p += didSize;
  const fcsSize = fcsFlag === 0 ? (single ? 1 : 0) : fcsFlag === 1 ? 2 : fcsFlag === 2 ? 4 : 8;
  if (p + fcsSize > b.length) throw new ParseError('zstd content size truncated');
  let contentSize: number | null = null;
  if (fcsSize) {
    contentSize = 0;
    for (let k = fcsSize - 1; k >= 0; k--) contentSize = contentSize * 256 + (b[p + k] as number);
    if (fcsSize === 2) contentSize += 256;
  }
  p += fcsSize;
  if (windowSize === null) windowSize = contentSize;
  let blocks = 0, bound = 0;
  for (;;) {
    if (p + 3 > b.length) throw new ParseError('zstd block header truncated', p);
    const bh = (b[p] as number) | ((b[p + 1] as number) << 8) | ((b[p + 2] as number) << 16);
    p += 3;
    const last = bh & 1, type = (bh >> 1) & 3, size = bh >> 3;
    if (type === 3) throw new ParseError('zstd reserved block type', p - 3);
    const csize = type === 1 ? 1 : size;
    if (p + csize > b.length) throw new ParseError('zstd block runs past the end', p);
    p += csize;
    bound += type === 2 ? Math.min(131072, windowSize ?? 131072) : size;
    if (++blocks > 10_000_000) throw new ParseError('too many zstd blocks');
    if (last) break;
  }
  if (checksum) { if (p + 4 > b.length) throw new ParseError('zstd checksum truncated'); p += 4; }
  return { start, end: p, contentSize, windowSize, dictId, checksum: !!checksum, blocks, outputBound: contentSize ?? bound };
}

/** Decode one zstd frame at `start`, capped. Dictionary frames are refused. */
export function zstdDecodeFrame(b: Uint8Array, opts: { start?: number; maxOut?: number } = {}): { data: Uint8Array; frame: ZstdFrame } {
  const f = zstdFrameInfo(b, opts.start ?? 0);
  const max = opts.maxOut ?? 256 << 20;
  if (f.skippable) return { data: new Uint8Array(0), frame: f };
  if (f.dictId) throw new ParseError('zstd frame needs a dictionary');
  if (f.outputBound > max) throw new OutputLimitError(max);
  let data: Uint8Array;
  try {
    data = fzstdDecompress(b.subarray(f.start, f.end), f.contentSize !== null ? new Uint8Array(f.contentSize) : undefined);
  } catch (e) { throw new ParseError(`zstd: ${(e as Error).message}`); }
  if (data.length > max) throw new OutputLimitError(max);
  return { data, frame: f };
}
