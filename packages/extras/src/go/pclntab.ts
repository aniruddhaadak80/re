// Go symbol recovery from the pclntab (runtime line table), which Go keeps even in
// stripped binaries. Supports the Go 1.2, 1.16, 1.18 and 1.20+ table layouts on ELF,
// PE and Mach-O. Gives function names with entry addresses and source file names.

import { View, ParseError } from '../util.js';
import { parseBin, findSection, vaToOffset, elfSymbols, type BinImage } from '../bin/container.js';

export const PCLN_MAGICS: Record<number, string> = {
  0xfffffffb: '1.2',
  0xfffffffa: '1.16',
  0xfffffff0: '1.18',
  0xfffffff1: '1.20',
};

export interface GoFunc {
  name: string;
  entry: number;
  end?: number;
  /** file offset of the entry point, when mapped */
  offset?: number;
  package?: string;
}

export interface GoPclntab {
  version: '1.2' | '1.16' | '1.18' | '1.20';
  goVersionRange: string;
  offset: number;
  ptrSize: number;
  quantum: number;
  bigEndian: boolean;
  textStart: number;
  functionCount: number;
  fileCount: number;
  functions: GoFunc[];
  files: string[];
  packages: { name: string; functions: number }[];
  source: 'section' | 'symbol' | 'scan';
  warnings: string[];
}

const RANGES: Record<string, string> = { '1.2': 'go1.2 to go1.15', '1.16': 'go1.16 to go1.17', '1.18': 'go1.18 to go1.19', '1.20': 'go1.20 or later' };
const MAX_FUNCS = 500000;
const MAX_FILES = 200000;

function plausibleHeader(v: View, off: number): { magic: number; le: boolean } | null {
  for (const le of [true, false]) {
    if (!v.has(off, 16)) return null;
    const m = v.u32(off, le);
    if (!PCLN_MAGICS[m]) continue;
    if (v.u8(off + 4) !== 0 || v.u8(off + 5) !== 0) continue;
    const q = v.u8(off + 6), ps = v.u8(off + 7);
    if (![1, 2, 4].includes(q) || ![4, 8].includes(ps)) continue;
    return { magic: m, le };
  }
  return null;
}

/** Locate the pclntab in an executable: named section, runtime.pclntab symbol, or a validated scan. */
export function locatePclntab(bytes: Uint8Array, img?: BinImage): { offset: number; source: GoPclntab['source'] } | null {
  const v = new View(bytes);
  if (img) {
    const sec = findSection(img, '.gopclntab', '__gopclntab');
    if (sec && sec.size && plausibleHeader(v, sec.offset)) return { offset: sec.offset, source: 'section' };
    if (img.format === 'elf') {
      try {
        const sym = elfSymbols(img).find((s) => s.name === 'runtime.pclntab');
        if (sym) { const o = vaToOffset(img, sym.value); if (o >= 0 && plausibleHeader(v, o)) return { offset: o, source: 'symbol' }; }
      } catch { /* fall through to scan */ }
    }
  }
  const cands = [0xfb, 0xfa, 0xf0, 0xf1];
  for (let i = 0; i + 16 <= bytes.length; i++) {
    const b0 = bytes[i] as number;
    let ok = false;
    if (cands.includes(b0) && bytes[i + 1] === 0xff && bytes[i + 2] === 0xff && bytes[i + 3] === 0xff) ok = true;
    else if (b0 === 0xff && bytes[i + 1] === 0xff && bytes[i + 2] === 0xff && cands.includes(bytes[i + 3] as number)) ok = true;
    if (!ok) continue;
    if (!plausibleHeader(v, i)) continue;
    try {
      const t = parsePclntabAt(bytes, i, img, 64);
      if (t.functionCount > 0 && t.functions.length > 0 && t.functions.every((f) => /^[\x21-\x7e]/.test(f.name))) return { offset: i, source: 'scan' };
    } catch { /* keep scanning */ }
  }
  return null;
}

/** Parse a pclntab at a file offset. maxFuncs bounds the function list. */
export function parsePclntabAt(bytes: Uint8Array, off: number, img?: BinImage, maxFuncs = MAX_FUNCS): GoPclntab {
  const base = new View(bytes);
  const h = plausibleHeader(base, off);
  if (!h) throw new ParseError('not a Go pclntab header', off);
  const v = new View(bytes, h.le);
  const version = PCLN_MAGICS[h.magic] as GoPclntab['version'];
  const quantum = v.u8(off + 6);
  const ps = v.u8(off + 7);
  const word = (o: number): number => v.uN(off + o, ps);
  const warnings: string[] = [];
  const functions: GoFunc[] = [];
  const files: string[] = [];
  let nfunc = 0, nfiles = 0, textStart = 0;

  if (version === '1.2') {
    nfunc = word(8);
    if (nfunc > MAX_FUNCS) throw new ParseError('function count too large', off);
    const ftab = off + 8 + ps;
    const n = Math.min(nfunc, maxFuncs);
    for (let i = 0; i < n; i++) {
      const entry = v.uN(ftab + i * 2 * ps, ps);
      const funcoff = v.uN(ftab + i * 2 * ps + ps, ps);
      const nameoff = v.i32(off + funcoff + ps);
      const name = v.utf8z(off + nameoff, 2048);
      const next = v.uN(ftab + (i + 1) * 2 * ps, ps);
      functions.push({ name, entry, end: next });
    }
    const fileOffPos = ftab + nfunc * 2 * ps + ps;
    if (v.has(fileOffPos, 4)) {
      const filetab = off + v.u32(fileOffPos);
      if (v.has(filetab, 4)) {
        nfiles = Math.max(0, v.u32(filetab) - 1);
        for (let i = 1; i <= Math.min(nfiles, MAX_FILES); i++) files.push(v.utf8z(off + v.u32(filetab + i * 4), 4096));
      }
    }
  } else {
    nfunc = word(8);
    nfiles = word(8 + ps);
    if (nfunc > MAX_FUNCS || nfiles > MAX_FILES) throw new ParseError('function or file count too large', off);
    let k = 2;
    if (version === '1.18' || version === '1.20') { textStart = word(8 + 2 * ps); k = 3; }
    const funcnameOff = off + word(8 + k * ps);
    const filetabOff = off + word(8 + (k + 2) * ps);
    const pclnOff = off + word(8 + (k + 4) * ps);
    if (textStart === 0 && img && (version === '1.18' || version === '1.20')) {
      const t = findSection(img, '.text', '__text');
      if (t) { textStart = img.format === 'pe' ? img.imageBase + t.vaddr : t.vaddr; warnings.push('header textStart was 0; used the text section address'); }
    }
    const n = Math.min(nfunc, maxFuncs);
    const wide = version === '1.16';
    const fsz = wide ? ps : 4;
    for (let i = 0; i < n; i++) {
      const e = pclnOff + i * 2 * fsz;
      const entryRaw = v.uN(e, fsz);
      const funcoff = v.uN(e + fsz, fsz);
      const nextRaw = v.uN(e + 2 * fsz, fsz);
      const nameoff = v.i32(pclnOff + funcoff + (wide ? ps : 4));
      const name = v.utf8z(funcnameOff + nameoff, 2048);
      functions.push({ name, entry: wide ? entryRaw : textStart + entryRaw, end: wide ? nextRaw : textStart + nextRaw });
    }
    let p = filetabOff;
    const enc = new TextEncoder();
    for (let i = 0; i < Math.min(nfiles, MAX_FILES); i++) {
      if (!v.has(p, 1)) break;
      const s = v.utf8z(p, 4096);
      files.push(s);
      p += enc.encode(s).length + 1;
    }
  }
  if (img) for (const f of functions) { const o = vaToOffset(img, f.entry); if (o >= 0) f.offset = o; }
  const pk = new Map<string, number>();
  for (const f of functions) {
    const pkg = goPackageOf(f.name);
    if (pkg) { f.package = pkg; pk.set(pkg, (pk.get(pkg) ?? 0) + 1); }
  }
  return {
    version, goVersionRange: RANGES[version] as string, offset: off, ptrSize: ps, quantum, bigEndian: !h.le, textStart,
    functionCount: nfunc, fileCount: nfiles, functions, files,
    packages: [...pk.entries()].map(([name, functions]) => ({ name, functions })).sort((a, b) => b.functions - a.functions),
    source: 'section', warnings,
  };
}

/** Package path of a Go symbol name, e.g. "net/http.(*Client).Do" -> "net/http". */
export function goPackageOf(name: string): string | null {
  if (!name || name.startsWith('type:') || name.startsWith('go:') || name.startsWith('type.')) return null;
  const lastSlash = name.lastIndexOf('/', name.indexOf('(') >= 0 ? name.indexOf('(') : name.length);
  const dot = name.indexOf('.', lastSlash + 1);
  if (dot <= 0) return null;
  return name.slice(0, dot);
}

/** Recover Go functions and source files from an executable. */
export function goSymbols(bytes: Uint8Array, opts: { maxFunctions?: number } = {}): GoPclntab | null {
  let img: BinImage | undefined;
  try { img = parseBin(bytes); } catch { img = undefined; }
  const loc = locatePclntab(bytes, img);
  if (!loc) return null;
  const t = parsePclntabAt(bytes, loc.offset, img, opts.maxFunctions ?? MAX_FUNCS);
  t.source = loc.source;
  return t;
}
