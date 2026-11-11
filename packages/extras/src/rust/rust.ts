// Rust binary facts: compiler version and commit, crates and versions from embedded
// registry paths, mangling schemes in use, panic message count. Works on stripped files.

import { latin1 } from '../util.js';
import { detectBin, parseBin, findSection, elfSymbols } from '../bin/container.js';
import { demangle } from '../demangle/index.js';

export interface RustCrate { name: string; version: string; source: string; offsets: number[] }
export interface RustInfo {
  isRust: boolean;
  confidence: number;
  rustcVersion?: string;
  rustcCommit?: string;
  rustcCommitOffset?: number;
  crates: RustCrate[];
  symbolSchemes: { legacy: number; v0: number };
  sampleSymbols: { mangled: string; demangled: string }[];
  panicStrings: number;
  signals: string[];
}

const RE_COMMIT = /\/rustc\/([0-9a-f]{40})\//g;
const RE_CRATE = /(index\.crates\.io-[0-9a-f]{16}|github\.com-[0-9a-f]{16}|crates\.io-[0-9a-f]{16})[/\\]([A-Za-z0-9_\-]{1,64}?)-(\d{1,4}\.\d{1,4}\.\d{1,6}(?:-[0-9A-Za-z.\-]{1,40})?(?:\+[0-9A-Za-z.\-]{1,40})?)[/\\]/g;
const RE_VERSION = /rustc version (\d+\.\d+\.\d+(?:-[a-z]+(?:\.\d+)?)?(?: \([0-9a-f]{7,10} \d{4}-\d{2}-\d{2}\))?)/;

/** Scan a binary (any format, including wasm) for Rust toolchain and crate evidence. */
export function rustInfo(bytes: Uint8Array, opts: { maxCrates?: number; maxScan?: number } = {}): RustInfo {
  const scan = bytes.subarray(0, Math.min(bytes.length, opts.maxScan ?? 512 << 20));
  const text = latin1(scan);
  const signals: string[] = [];
  const out: RustInfo = { isRust: false, confidence: 0, crates: [], symbolSchemes: { legacy: 0, v0: 0 }, sampleSymbols: [], panicStrings: 0, signals };
  const commits = new Map<string, number>();
  for (const m of text.matchAll(RE_COMMIT)) { if (!commits.has(m[1] as string)) commits.set(m[1] as string, m.index ?? 0); if (commits.size > 8) break; }
  if (commits.size) {
    const [c, o] = [...commits.entries()][0] as [string, number];
    out.rustcCommit = c; out.rustcCommitOffset = o; signals.push('rustc source path');
  }
  // .comment carries "rustc version ..." in ELF builds
  if (detectBin(bytes) === 'elf') {
    try {
      const img = parseBin(bytes);
      const cm = findSection(img, '.comment');
      if (cm) { const m = latin1(bytes.subarray(cm.offset, cm.offset + Math.min(cm.size, 4096))).match(RE_VERSION); if (m) { out.rustcVersion = m[1]; signals.push('.comment rustc version'); } }
      for (const which of ['symtab', 'dynsym'] as const) {
        for (const s of elfSymbols(img, which, 200000)) {
          const isV0 = s.name.startsWith('_R');
          const isLegacy = /^_ZN.*17h[0-9a-f]{16}E$/.test(s.name);
          if (isV0) out.symbolSchemes.v0++;
          if (isLegacy) out.symbolSchemes.legacy++;
          if ((isV0 || isLegacy) && out.sampleSymbols.length < 20) { const d = demangle(s.name); if (d.output) out.sampleSymbols.push({ mangled: s.name, demangled: d.output }); }
        }
      }
    } catch { /* malformed headers: string evidence still counts */ }
  }
  if (!out.rustcVersion) { const m = text.match(RE_VERSION); if (m) { out.rustcVersion = m[1]; signals.push('rustc version string'); } }
  const crates = new Map<string, RustCrate>();
  const maxC = opts.maxCrates ?? 500;
  for (const m of text.matchAll(RE_CRATE)) {
    const key = `${m[2]}@${m[3]}`;
    const c = crates.get(key);
    if (c) { if (c.offsets.length < 4) c.offsets.push(m.index ?? 0); continue; }
    if (crates.size >= maxC) break;
    crates.set(key, { name: m[2] as string, version: m[3] as string, source: (m[1] as string).startsWith('github') ? 'crates.io (git index)' : 'crates.io', offsets: [m.index ?? 0] });
  }
  out.crates = [...crates.values()].sort((a, b) => a.name.localeCompare(b.name));
  if (out.crates.length) signals.push('cargo registry paths');
  const panics = text.match(/called `(?:Option|Result)::unwrap\(\)` on an? `?(?:None|Err)/g);
  out.panicStrings = panics ? panics.length : 0;
  if (out.panicStrings) signals.push('unwrap panic messages');
  if (/library[/\\](?:std|core|alloc)[/\\]src[/\\]/.test(text)) signals.push('std library source paths');
  if (out.symbolSchemes.legacy + out.symbolSchemes.v0 > 0) signals.push('Rust mangled symbols');
  const score = (out.rustcCommit ? 0.4 : 0) + (out.rustcVersion ? 0.3 : 0) + (out.crates.length ? 0.2 : 0) + (out.panicStrings ? 0.1 : 0) + (out.symbolSchemes.legacy + out.symbolSchemes.v0 ? 0.3 : 0) + (signals.includes('std library source paths') ? 0.2 : 0);
  out.confidence = Math.min(1, Math.round(score * 100) / 100);
  out.isRust = out.confidence >= 0.4;
  return out;
}
