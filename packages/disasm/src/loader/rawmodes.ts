// Headerless and console load modes: raw binaries at a base address, DOS COM images and
// GameCube / Wii DOL executables.
import type { Arch, BinaryImage, SectionInfo, Segment, Sym } from '../types.js';

/** Raw bytes mapped at base as one executable segment. */
export function loadRaw(bytes: Uint8Array, arch: Arch, base = 0, entry?: number): BinaryImage {
  const bits: 32 | 64 = arch === 'x86_64' || arch === 'arm64' ? 64 : 32;
  return {
    format: 'raw', arch, bits, endian: arch === 'ppc' ? 'be' : 'le',
    entry: entry ?? base, imageBase: base,
    segments: [{ name: 'raw', vaddr: base, vsize: bytes.length, offset: 0, fsize: bytes.length, r: true, w: false, x: true }],
    sections: [{ name: 'raw', vaddr: base, size: bytes.length, offset: 0, fsize: bytes.length, exec: true, write: false }],
    symbols: [], imports: [], hints: [], bytes, fileOffset: 0, warnings: [],
  };
}

/** DOS COM: real mode code loaded at offset 0x100 of its segment, entry at 0x100, at most 0xff00 bytes. */
export function loadDosCom(bytes: Uint8Array): BinaryImage {
  const warnings: string[] = [];
  let b = bytes;
  if (b.length > 0xff00) { warnings.push(`COM image is ${b.length} bytes; DOS loads at most 65280 (0xff00), the rest is ignored`); b = b.subarray(0, 0xff00); }
  if (b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a) warnings.push('file starts with MZ: this is an EXE, not a COM image');
  const img = loadRaw(b, 'x86_16', 0x100, 0x100);
  img.format = 'dos-com';
  img.segments = [{ name: 'PSP+COM', vaddr: 0x100, vsize: Math.max(b.length, 1), offset: 0, fsize: b.length, r: true, w: true, x: true }];
  img.sections = [{ name: '.com', vaddr: 0x100, size: b.length, offset: 0, fsize: b.length, exec: true, write: true }];
  img.symbols = [{ addr: 0x100, name: 'start', kind: 'func', source: 'entry' }];
  img.warnings = warnings;
  return img;
}

const DOL_TEXT = 7, DOL_DATA = 11;

/** Strict check of a GameCube / Wii DOL header (no magic: offsets, sizes and addresses must line up). */
export function isDol(b: Uint8Array): boolean {
  if (b.length < 0x100) return false;
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let any = false;
  let entryOk = false;
  const entry = v.getUint32(0xe0);
  for (let i = 0; i < DOL_TEXT + DOL_DATA; i++) {
    const off = v.getUint32(i * 4), addr = v.getUint32(0x48 + i * 4), size = v.getUint32(0x90 + i * 4);
    if (size === 0) { if (off !== 0 && off < 0x100) return false; continue; }
    if (off < 0x100 || off + size > b.length) return false;
    if (addr < 0x80000000 || addr + size > 0x81800000 + 0x1000000) return false;
    any = true;
    if (i < DOL_TEXT && entry >= addr && entry < addr + size) entryOk = true;
  }
  return any && entryOk;
}

/** GameCube / Wii DOL: up to 7 text and 11 data sections, a bss range and the entry point (big endian PowerPC). */
export function loadDol(bytes: Uint8Array): BinaryImage {
  if (!isDol(bytes)) throw new Error('not a GameCube/Wii DOL (header offsets, sizes or entry do not line up)');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const segments: Segment[] = [];
  const sections: SectionInfo[] = [];
  for (let i = 0; i < DOL_TEXT + DOL_DATA; i++) {
    const off = v.getUint32(i * 4), addr = v.getUint32(0x48 + i * 4), size = v.getUint32(0x90 + i * 4);
    if (!size) continue;
    const text = i < DOL_TEXT;
    const name = text ? `.text${i}` : `.data${i - DOL_TEXT}`;
    segments.push({ name, vaddr: addr, vsize: size, offset: off, fsize: size, r: true, w: !text, x: text });
    sections.push({ name, vaddr: addr, size, offset: off, fsize: size, exec: text, write: !text });
  }
  const bssAddr = v.getUint32(0xd8), bssSize = v.getUint32(0xdc);
  const warnings: string[] = [];
  if (bssSize > 0 && bssSize < 0x2000000) {
    // bss overlaps data sections in many DOLs (sbss, sdata2): map only the uncovered parts
    const covered = segments.map((s) => [s.vaddr, s.vaddr + s.vsize] as [number, number]).sort((a, b) => a[0] - b[0]);
    let cur = bssAddr;
    const end = bssAddr + bssSize;
    let k = 0;
    for (const [s, e] of covered) {
      if (e <= cur || s >= end) continue;
      if (s > cur) { segments.push({ name: `.bss${k}`, vaddr: cur, vsize: s - cur, offset: 0, fsize: 0, r: true, w: true, x: false }); sections.push({ name: `.bss${k++}`, vaddr: cur, size: s - cur, offset: 0, fsize: 0, exec: false, write: true }); }
      cur = Math.max(cur, e);
    }
    if (cur < end) { segments.push({ name: `.bss${k}`, vaddr: cur, vsize: end - cur, offset: 0, fsize: 0, r: true, w: true, x: false }); sections.push({ name: `.bss${k}`, vaddr: cur, size: end - cur, offset: 0, fsize: 0, exec: false, write: true }); }
  } else if (bssSize) warnings.push(`bss size 0x${bssSize.toString(16)} ignored (too large)`);
  const entry = v.getUint32(0xe0);
  const symbols: Sym[] = [{ addr: entry, name: '__start', kind: 'func', source: 'entry' }];
  return {
    format: 'gamecube-dol', arch: 'ppc', bits: 32, endian: 'be', entry, imageBase: Math.min(...segments.map((s) => s.vaddr)),
    segments, sections, symbols, imports: [], hints: [], bytes, fileOffset: 0, warnings,
  };
}
