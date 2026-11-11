// Windows Prefetch (.pf) files: SCCA versions 17 (XP/2003), 23 (Vista/7), 26 (8.x),
// 30 and 31 (10/11), including the MAM\x04 LZXPRESS Huffman compressed form of Windows 10+.

import { View, ParseError, filetime } from '../util.js';
import { lzxpressHuffman } from './lzxpress.js';

export interface PrefetchVolume { devicePath: string; created: string | null; serial: string; directories: string[]; fileReferenceCount?: number; offset: number }
export interface Prefetch {
  compressed: boolean; compressedSize?: number; version: number; windows: string; signature: string; fileSize: number;
  executable: string; hash: string; runCount: number; lastRunTimes: string[];
  metricsCount: number; traceChainCount: number; files: string[]; volumes: PrefetchVolume[];
  sections: { metrics: number; traceChains: number; filenameStrings: number; volumes: number };
}

const WIN: Record<number, string> = { 17: 'Windows XP / 2003', 23: 'Windows Vista / 7', 26: 'Windows 8.x', 30: 'Windows 10', 31: 'Windows 11' };

/** Decompress a MAM prefetch container, or return the input when it is plain SCCA. */
export function decompressPrefetch(b: Uint8Array): { data: Uint8Array; compressed: boolean } {
  const v = new View(b, true);
  if (b.length >= 8 && b[0] === 0x4d && b[1] === 0x41 && b[2] === 0x4d) {
    const sig = v.u32(0);
    const algo = (sig >>> 24) & 0x0f;
    const hasCrc = ((sig >>> 24) & 0xf0) !== 0;
    if (algo !== 4) throw new ParseError(`MAM compression format ${algo} is not supported (only 4, LZXPRESS Huffman)`);
    const size = v.u32(4);
    if (size > 64 << 20) throw new ParseError('decompressed prefetch over 64 MiB');
    return { data: lzxpressHuffman(b.subarray(hasCrc ? 12 : 8), size), compressed: true };
  }
  return { data: b, compressed: false };
}

/** Parse a Prefetch file (compressed or not). */
export function parsePrefetch(input: Uint8Array, opts: { maxFiles?: number } = {}): Prefetch {
  const { data, compressed } = decompressPrefetch(input);
  const v = new View(data, true);
  if (data.length < 84 || v.u32(4) !== 0x41434353) throw new ParseError('not a prefetch file (SCCA signature expected at offset 4)', 4);
  const version = v.u32(0);
  if (!WIN[version]) throw new ParseError(`unknown prefetch version ${version}`, 0);
  const sec = { metrics: v.u32(84), metricsCount: v.u32(88), trace: v.u32(92), traceCount: v.u32(96), names: v.u32(100), namesSize: v.u32(104), vols: v.u32(108), volCount: v.u32(112), volSize: v.u32(116) };
  let runCount = 0;
  const times: string[] = [];
  const ft = (o: number): string | null => (v.has(o, 8) ? filetime(v.u32(o), v.u32(o + 4)) : null);
  if (version === 17) { const t = ft(120); if (t) times.push(t); runCount = v.u32(144); }
  else if (version === 23) { const t = ft(128); if (t) times.push(t); runCount = v.u32(152); }
  else {
    for (let i = 0; i < 8; i++) { const t = ft(128 + i * 8); if (t) times.push(t); }
    // Windows 10 1903+ shortened the file information block: metrics start at 0x128 and run count moves to 200
    runCount = version >= 30 && sec.metrics === 0x128 ? v.u32(200) : v.u32(208);
  }
  const files: string[] = [];
  if (v.has(sec.names, Math.min(sec.namesSize, data.length - sec.names))) {
    const end = Math.min(data.length, sec.names + sec.namesSize);
    let p = sec.names;
    while (p + 1 < end && files.length < (opts.maxFiles ?? 10000)) {
      let s = '';
      while (p + 1 < end) { const c = v.u16(p); p += 2; if (!c) break; s += String.fromCharCode(c); }
      if (s) files.push(s);
    }
  }
  const volumes: PrefetchVolume[] = [];
  const entSize = version === 17 ? 40 : version === 30 || version === 31 ? 96 : 104;
  for (let i = 0; i < Math.min(sec.volCount, 64); i++) {
    const o = sec.vols + i * entSize;
    if (!v.has(o, 36)) break;
    const pathOff = v.u32(o), pathLen = v.u32(o + 4);
    const devicePath = v.has(sec.vols + pathOff, pathLen * 2) ? v.utf16(sec.vols + pathOff, Math.min(pathLen, 1024)) : '';
    const dirOff = v.u32(o + 28), dirCount = v.u32(o + 32);
    const directories: string[] = [];
    let p = sec.vols + dirOff;
    for (let d = 0; d < Math.min(dirCount, 4096) && v.has(p, 2); d++) {
      const n = v.u16(p);
      if (!v.has(p + 2, n * 2)) break;
      directories.push(v.utf16(p + 2, n));
      p += 2 + n * 2 + 2;
    }
    volumes.push({ devicePath, created: ft(o + 8), serial: v.u32(o + 16).toString(16).toUpperCase().padStart(8, '0'), directories, offset: o });
  }
  return {
    compressed, compressedSize: compressed ? input.length : undefined, version, windows: WIN[version]!, signature: 'SCCA', fileSize: v.u32(12),
    executable: v.utf16z(16, 30), hash: v.u32(76).toString(16).toUpperCase().padStart(8, '0'), runCount, lastRunTimes: times,
    metricsCount: sec.metricsCount, traceChainCount: sec.traceCount, files, volumes,
    sections: { metrics: sec.metrics, traceChains: sec.trace, filenameStrings: sec.names, volumes: sec.vols },
  };
}
