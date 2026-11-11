// Format detection and loading entry point.
import type { Arch, BinaryImage } from '../types.js';
import { loadElf } from './elf.js';
import { loadPe } from './pe.js';
import { loadMachO, isFat, fatSlices } from './macho.js';
import { readGoPclntab } from './gopclntab.js';

export interface LoadOptions {
  /** for fat Mach-O: which slice to load (default: x86_64, then arm64, then the first) */
  arch?: Arch;
  /** for raw code: architecture and base address */
  rawArch?: Arch;
  rawBase?: number;
  /** read Go pclntab names (default true) */
  goSymbols?: boolean;
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
  const fmt = detectBinFormat(bytes);
  let img: BinaryImage;
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
    const base = opts.rawBase ?? 0;
    img = {
      format: 'raw', arch: opts.rawArch, bits: opts.rawArch === 'x86_64' || opts.rawArch === 'arm64' ? 64 : 32, endian: 'le',
      entry: base, imageBase: base,
      segments: [{ name: 'raw', vaddr: base, vsize: bytes.length, offset: 0, fsize: bytes.length, r: true, w: false, x: true }],
      sections: [], symbols: [], imports: [], hints: [], bytes, fileOffset: 0, warnings: [],
    };
  } else {
    throw new Error('not an ELF, PE or Mach-O file (pass rawArch to disassemble raw code)');
  }
  if (opts.goSymbols !== false && img.format !== 'raw') {
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
