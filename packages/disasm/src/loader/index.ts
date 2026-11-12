// Format detection and loading entry point.
import type { Arch, BinaryImage } from '../types.js';
import { loadElf } from './elf.js';
import { loadPe } from './pe.js';
import { loadMachO, isFat, fatSlices } from './macho.js';
import { readGoPclntab } from './gopclntab.js';
import { loadRaw, loadDosCom, loadDol, isDol } from './rawmodes.js';

/** How to load the bytes: auto (ELF, PE, Mach-O, DOL, else raw when rawArch is set), or a forced mode. */
export type LoadMode = 'auto' | 'raw' | 'dos-com' | 'gamecube-dol';

export interface LoadOptions {
  /** for fat Mach-O: which slice to load (default: x86_64, then arm64, then the first) */
  arch?: Arch;
  /** for raw code: architecture and base address */
  rawArch?: Arch;
  rawBase?: number;
  /** read Go pclntab names (default true) */
  goSymbols?: boolean;
  /** force a load mode; raw needs rawArch (rawBase and rawEntry optional) */
  loadMode?: LoadMode;
  /** raw mode: entry address (default rawBase) */
  rawEntry?: number;
}

export function detectBinFormat(b: Uint8Array): 'elf' | 'pe' | 'macho' | 'macho-fat' | 'unknown' {
  if (b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'elf';
  if (b.length >= 0x40 && b[0] === 0x4d && b[1] === 0x5a) {
    const pe = b[0x3c]! | (b[0x3d]! << 8) | (b[0x3e]! << 16) | (b[0x3f]! << 24);
    if (pe > 0 && pe + 24 < b.length && b[pe] === 0x50 && b[pe + 1] === 0x45 && b[pe + 2] === 0 && b[pe + 3] === 0) return 'pe';
  }
  if (b.length >= 28) {
    const m = (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
    if (m === 0xfeedface || m === 0xfeedfacf || m === 0xcefaedfe || m === 0xcffaedfe) return 'macho';
    if (isFat(b)) return 'macho-fat';
  }
  return 'unknown';
}

/** Load a binary into a BinaryImage. Throws only for unsupported formats. */
export function loadImage(bytes: Uint8Array, opts: LoadOptions = {}): BinaryImage {
  const mode = opts.loadMode ?? 'auto';
  if (mode === 'dos-com') return loadDosCom(bytes);
  if (mode === 'gamecube-dol') return loadDol(bytes);
  if (mode === 'raw') {
    if (!opts.rawArch) throw new Error('raw load mode needs rawArch (x86, x86_64, x86_16, arm, arm64, ppc)');
    return loadRaw(bytes, opts.rawArch, opts.rawBase ?? 0, opts.rawEntry);
  }
  const fmt = detectBinFormat(bytes);
  let img: BinaryImage;
  if (fmt === 'unknown' && isDol(bytes)) return loadDol(bytes);
  if (fmt === 'elf') img = loadElf(bytes);
  else if (fmt === 'pe') img = loadPe(bytes);
  else if (fmt === 'macho') img = loadMachO(bytes);
  else if (fmt === 'macho-fat') {
    const slices = fatSlices(bytes);
    const pick = (opts.arch && slices.find((s) => s.arch === opts.arch))
      ?? slices.find((s) => s.arch === 'x86_64') ?? slices.find((s) => s.arch === 'arm64') ?? slices[0];
    if (!pick) throw new Error('fat Mach-O has no usable slices');
    img = loadMachO(bytes.subarray(pick.offset, pick.offset + pick.size), pick.offset);
    img.slices = slices;
  } else if (opts.rawArch) {
    img = loadRaw(bytes, opts.rawArch, opts.rawBase ?? 0, opts.rawEntry);
    img.sections = [];
  } else {
    throw new Error('not an ELF, PE, Mach-O or DOL file (pass rawArch, or loadMode dos-com / raw, to disassemble headerless code)');
  }
  if (opts.goSymbols !== false && img.format !== 'raw' && img.arch !== 'ppc') {
    try {
      const go = readGoPclntab(img);
      if (go.symbols.length) {
        const have = new Set(img.symbols.filter((s) => s.kind === 'func').map((s) => s.addr));
        for (const s of go.symbols) if (!have.has(s.addr)) img.symbols.push(s);
        img.goVersionHint = go.version;
      }
    } catch (e) {
      img.warnings.push('gopclntab: ' + (e as Error).message);
    }
  }
  return img;
}
