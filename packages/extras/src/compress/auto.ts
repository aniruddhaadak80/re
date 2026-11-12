// One entry point over the pure TS decoders: detect the stream format from its magic bytes and
// decode it with an output cap. Browser safe.

import { ParseError, startsWithBytes } from '../util.js';
import { gunzipMember, inflateZlib, inflateRaw } from './inflate.js';
import { lzmaAloneDecode, looksLikeLzmaAlone, xzDecode, lzma2Decode } from './lzma.js';
import { lzopDecode, lzo1xDecompress, LZOP_MAGIC } from './lzo.js';
import { zstdDecodeFrame, zstdFrameInfo } from './zstd.js';
import { lz4Block } from '../containers/lz4.js';
import { bzip2Decode } from './bzip2.js';

export const COMPRESSION_FORMATS = ['gzip', 'zlib', 'deflate', 'xz', 'lzma', 'lzma2', 'lzop', 'lzo1x', 'zstd', 'lz4-block', 'bzip2'] as const;
export type CompressionFormat = (typeof COMPRESSION_FORMATS)[number];

/** Guess the compression format from the first bytes. Raw formats (deflate, lzo1x, lzma2, lz4-block) are never guessed. */
export function detectCompression(b: Uint8Array, at = 0): CompressionFormat | undefined {
  if (startsWithBytes(b, [0x1f, 0x8b, 0x08], at)) return 'gzip';
  if (startsWithBytes(b, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], at)) return 'xz';
  if (startsWithBytes(b, [0x28, 0xb5, 0x2f, 0xfd], at)) return 'zstd';
  if (startsWithBytes(b, LZOP_MAGIC, at)) return 'lzop';
  if (startsWithBytes(b, [0x42, 0x5a, 0x68], at) && (b[at + 3] ?? 0) >= 0x31 && (b[at + 3] ?? 0) <= 0x39) return 'bzip2';
  if (looksLikeLzmaAlone(b, at)) return 'lzma';
  const c0 = b[at], c1 = b[at + 1];
  if (c0 !== undefined && c1 !== undefined && (c0 & 0x0f) === 8 && (c0 >> 4) <= 7 && ((c0 << 8) | c1) % 31 === 0) return 'zlib';
  return undefined;
}

export interface DecompressResult { format: CompressionFormat; data: Uint8Array; inputEnd: number; details: Record<string, unknown> }

/** Decode one compressed stream starting at `start`. `size` is the known output size for raw formats. */
export function decompressAuto(b: Uint8Array, opts: { format?: CompressionFormat | string; start?: number; maxOut?: number; size?: number; dictSize?: number } = {}): DecompressResult {
  const start = Math.max(0, Math.floor(opts.start ?? 0));
  if (start >= b.length) throw new ParseError('start is past the end of the input');
  const maxOut = Math.max(0, Math.min(opts.maxOut ?? 256 << 20, 1 << 30));
  const format = (opts.format && opts.format !== 'auto' ? opts.format : detectCompression(b, start)) as CompressionFormat | undefined;
  if (!format) throw new ParseError('unknown compression format; pass format');
  switch (format) {
    case 'gzip': { const m = gunzipMember(b, { start, maxOut }); return { format, data: m.data, inputEnd: m.end, details: { name: m.name, comment: m.comment, mtime: m.mtime, os: m.os, crcValid: m.crcValid, sizeValid: m.sizeValid } }; }
    case 'zlib': { const r = inflateZlib(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: { adler32Valid: r.checksumValid } }; }
    case 'deflate': { const r = inflateRaw(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: {} }; }
    case 'xz': { const r = xzDecode(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: { check: r.check, blocks: r.blocks } }; }
    case 'lzma': { const r = lzmaAloneDecode(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: { ...r.props, declaredSize: r.declaredSize } }; }
    case 'lzma2': { const r = lzma2Decode(b, opts.dictSize ?? 1 << 26, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: {} }; }
    case 'lzop': { const r = lzopDecode(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: { name: r.name, mtime: r.mtime, method: r.method, level: r.level, blocks: r.blocks, checksumsValid: r.checksumsValid } }; }
    case 'lzo1x': { const r = lzo1xDecompress(b, { start, maxOut, ...(opts.size !== undefined ? { expectedSize: opts.size } : {}) }); return { format, data: r.data, inputEnd: r.end, details: {} }; }
    case 'zstd': { const r = zstdDecodeFrame(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.frame.end, details: { frame: r.frame } }; }
    case 'lz4-block': {
      if (opts.size === undefined) throw new ParseError('lz4-block needs size (the decoded length)');
      return { format, data: lz4Block(b.subarray(start), opts.size, maxOut), inputEnd: b.length, details: {} };
    }
    case 'bzip2': { const r = bzip2Decode(b, { start, maxOut }); return { format, data: r.data, inputEnd: r.end, details: { blockSize: r.blockSize, blocks: r.blocks, crcValid: r.crcValid } }; }
    default: throw new ParseError(`unsupported format ${String(format)}; one of ${COMPRESSION_FORMATS.join(', ')}`);
  }
}

export { zstdFrameInfo };
