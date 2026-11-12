// Byte entropy over a caller chosen window: fixed or sliding blocks (window and step), file wide
// entropy, and merged high and low entropy runs with exact offsets. One pass with a rolling byte
// histogram, so a sliding window costs about the same as fixed blocks.

import { sha256 } from '../hash.js';

export interface EntropyBlock { offset: number; length: number; entropy: number }
export interface EntropyRun { kind: 'high' | 'low'; offset: number; length: number; blocks: number; meanEntropy: number }
export interface EntropyWindowReport {
  schema: 'revlens/entropy@1';
  size: number;
  sha256: string;
  fileEntropy: number;
  range: { offset: number; length: number };
  window: number;
  step: number;
  blocks: EntropyBlock[];
  blockCount: number;
  truncated: boolean;
  runs: EntropyRun[];
  thresholds: { high: number; low: number };
  stats: { min: number; max: number; mean: number };
  limitations: string[];
}

export interface EntropyWindowOptions {
  offset?: number;
  length?: number;
  /** bytes per block; default 4096 */
  window?: number;
  /** distance between block starts; default = window (fixed blocks). Smaller values slide. */
  step?: number;
  /** rea compatible name for window; when given it must be a power of two from 256 to 65536 */
  blockSize?: number;
  high?: number;
  low?: number;
  maxBlocks?: number;
  /** keep the last partial block (default true) */
  partial?: boolean;
}

const LOG2 = new Float64Array(65537);

function entropyFromCounts(counts: Uint32Array, n: number): number {
  if (n <= 0) return 0;
  // H = log2(n) - (1/n) * sum c*log2(c)
  let s = 0;
  for (let i = 0; i < 256; i++) { const c = counts[i] as number; if (c > 1) s += c * (c < LOG2.length ? (LOG2[c] as number) || (LOG2[c] = Math.log2(c)) : Math.log2(c)); }
  const h = Math.log2(n) - s / n;
  return h < 0 ? 0 : h;
}

/** Entropy blocks and runs over [offset, offset+length). */
export function entropyWindow(bytes: Uint8Array, opts: EntropyWindowOptions = {}): EntropyWindowReport {
  if (opts.blockSize !== undefined) {
    const b = opts.blockSize;
    if (!Number.isInteger(b) || b < 256 || b > 65536 || (b & (b - 1))) throw new Error('block_size must be a power of two from 256 to 65536');
  }
  const window = Math.floor(opts.window ?? opts.blockSize ?? 4096);
  const step = Math.floor(opts.step ?? window);
  if (window < 16 || window > 16 * 1024 * 1024) throw new Error('window must be between 16 bytes and 16 MiB');
  if (step < 1 || step > window * 64) throw new Error('step must be at least 1 and at most 64 windows');
  const offset = Math.max(0, Math.floor(opts.offset ?? 0));
  if (offset > bytes.length) throw new Error(`offset ${offset} is past the end of the ${bytes.length} byte file`);
  const length = Math.min(bytes.length - offset, Math.floor(opts.length ?? bytes.length - offset));
  if (length < 0) throw new Error('length must not be negative');
  const maxBlocks = Math.min(opts.maxBlocks ?? 32768, 1_000_000);
  const high = opts.high ?? 7.2, low = opts.low ?? 1.0;
  const end = offset + length;
  const blocks: EntropyBlock[] = [];
  let truncated = false;
  const counts = new Uint32Array(256);
  // file wide entropy
  const all = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) all[bytes[i] as number]!++;
  const fileEntropy = entropyFromCounts(all, bytes.length);
  let curStart = offset, curEnd = offset; // histogram covers [curStart, curEnd)
  for (let s = offset; s < end; s += step) {
    const e = Math.min(end, s + window);
    if (e - s < window && opts.partial === false) break;
    if (blocks.length >= maxBlocks) { truncated = true; break; }
    if (s >= curEnd || step >= window) { counts.fill(0); for (let i = s; i < e; i++) counts[bytes[i] as number]!++; }
    else {
      for (let i = curStart; i < s; i++) counts[bytes[i] as number]!--;
      for (let i = curEnd; i < e; i++) counts[bytes[i] as number]!++;
    }
    curStart = s; curEnd = e;
    blocks.push({ offset: s, length: e - s, entropy: Math.round(entropyFromCounts(counts, e - s) * 10000) / 10000 });
    if (e === end) break;
  }
  // runs of adjacent (or overlapping) blocks over a threshold
  const runs: EntropyRun[] = [];
  let cur: { kind: 'high' | 'low'; start: number; end: number; n: number; sum: number } | null = null;
  const close = (): void => { if (cur) runs.push({ kind: cur.kind, offset: cur.start, length: cur.end - cur.start, blocks: cur.n, meanEntropy: Math.round((cur.sum / cur.n) * 10000) / 10000 }); cur = null; };
  for (const b of blocks) {
    const kind = b.entropy >= high ? 'high' : b.entropy <= low ? 'low' : null;
    if (!kind) { close(); continue; }
    if (cur && cur.kind === kind && b.offset <= cur.end) { cur.end = Math.max(cur.end, b.offset + b.length); cur.n++; cur.sum += b.entropy; }
    else { close(); cur = { kind, start: b.offset, end: b.offset + b.length, n: 1, sum: b.entropy }; }
  }
  close();
  let min = Infinity, max = -Infinity, sum = 0;
  for (const b of blocks) { if (b.entropy < min) min = b.entropy; if (b.entropy > max) max = b.entropy; sum += b.entropy; }
  const limitations = ['Entropy cannot tell compressed data from encrypted data.'];
  if (truncated) limitations.push(`Only the first ${maxBlocks} blocks were kept; use a larger window or step, or a shorter length.`);
  if (step < window) limitations.push('Blocks overlap (step is smaller than window), so runs can be longer than the sum of distinct bytes suggests.');
  return {
    schema: 'revlens/entropy@1', size: bytes.length, sha256: sha256(bytes), fileEntropy: Math.round(fileEntropy * 10000) / 10000,
    range: { offset, length }, window, step, blocks, blockCount: blocks.length, truncated, runs, thresholds: { high, low },
    stats: blocks.length ? { min, max, mean: Math.round((sum / blocks.length) * 10000) / 10000 } : { min: 0, max: 0, mean: 0 }, limitations,
  };
}
