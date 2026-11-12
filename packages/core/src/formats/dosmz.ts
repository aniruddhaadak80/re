// Plain DOS MZ executables (no PE header): header fields, the load image, entry point, stack,
// relocation table with linear file offsets and the segment word each one patches, overlay data,
// and known packer, compiler and extender stubs. Also says when an MZ stub leads to an NE, LE, LX or
// PE header so callers can hand the file on.

import { BinView, FormatError } from './util.js';

export interface DosReloc { index: number; segment: number; offset: number; /** segment * 16 + offset inside the load module */ address: number; /** file offset of the patched word */ fileOffset: number; /** the segment value stored there before loading */ value: number; inImage: boolean }
export interface DosMz {
  format: 'dos-mz';
  header: { bytesOnLastPage: number; pages: number; relocations: number; headerParagraphs: number; minAlloc: number; maxAlloc: number; ss: number; sp: number; checksum: number; ip: number; cs: number; relocTableOffset: number; overlayNumber: number };
  headerSize: number;
  imageSize: number;
  loadModuleSize: number;
  entry: { cs: number; ip: number; address: number; fileOffset: number; inImage: boolean };
  stack: { ss: number; sp: number; address: number };
  /** memory the program asks for beyond the load module, in bytes */
  extraMemory: { min: number; max: number };
  relocations: DosReloc[];
  relocationsTruncated: boolean;
  overlay?: { offset: number; size: number; magic: string };
  newHeader?: { offset: number; kind: 'NE' | 'LE' | 'LX' | 'PE' | 'none' };
  computedChecksum: number;
  checksumValid: boolean | null;
  markers: { name: string; offset: number }[];
  warnings: string[];
}

const MARKERS: [string, string][] = [
  ['Turbo Pascal', 'Borland Turbo Pascal runtime'], ['Borland C++', 'Borland C++ runtime'], ['Turbo C', 'Borland Turbo C runtime'],
  ['Open Watcom', 'Open Watcom runtime'], ['WATCOM', 'Watcom runtime'], ['Microsoft C', 'Microsoft C runtime'], ['MS Run-Time Library', 'Microsoft C runtime'],
  ['UPX!', 'UPX packer'], ['PKLITE', 'PKLITE packer'], ['LZ91', 'LZEXE 0.91 packer'], ['LZ09', 'LZEXE 0.90 packer'], ['diet', 'DIET packer'],
  ['go32stub', 'DJGPP go32 stub (COFF image follows)'], ['CWSDPMI', 'CWSDPMI DPMI host'], ['DOS/4G', 'DOS/4G extender'], ['PMODE/W', 'PMODE/W extender'], ['DOS32A', 'DOS/32A extender'],
  ['This program cannot be run in DOS mode', 'PE stub message'], ['This program requires Microsoft Windows', 'Windows stub message'],
];

function find(b: Uint8Array, s: string, limit: number): number {
  const n = s.length, first = s.charCodeAt(0);
  const end = Math.min(b.length, limit) - n;
  for (let i = b.indexOf(first); i >= 0 && i <= end; i = b.indexOf(first, i + 1)) {
    let k = 1;
    while (k < n && b[i + k] === s.charCodeAt(k)) k++;
    if (k === n) return i;
  }
  return -1;
}

/** True for an MZ (or ZM) header. Does not exclude PE files; use dosNewHeader for that. */
export function isMz(b: Uint8Array): boolean { return b.length >= 28 && ((b[0] === 0x4d && b[1] === 0x5a) || (b[0] === 0x5a && b[1] === 0x4d)); }

/** The new executable header an MZ stub points at, if any. */
export function dosNewHeader(b: Uint8Array): { offset: number; kind: 'NE' | 'LE' | 'LX' | 'PE' | 'none' } {
  if (b.length < 0x40) return { offset: 0, kind: 'none' };
  const v = new BinView(b);
  const off = v.u32le(0x3c);
  if (off < 0x40 || off + 4 > b.length) return { offset: off, kind: 'none' };
  const s = String.fromCharCode(b[off] as number, b[off + 1] as number);
  if (s === 'PE' && b[off + 2] === 0 && b[off + 3] === 0) return { offset: off, kind: 'PE' };
  if (s === 'NE' || s === 'LE' || s === 'LX') return { offset: off, kind: s };
  return { offset: off, kind: 'none' };
}

/** Parse a DOS MZ executable. maxRelocs caps the relocation list. */
export function parseDosMz(bytes: Uint8Array, opts: { maxRelocs?: number } = {}): DosMz {
  const maxRelocs = opts.maxRelocs ?? 65536;
  if (!isMz(bytes)) throw new FormatError('no MZ signature', 0);
  const v = new BinView(bytes);
  const h = {
    bytesOnLastPage: v.u16le(2), pages: v.u16le(4), relocations: v.u16le(6), headerParagraphs: v.u16le(8), minAlloc: v.u16le(10), maxAlloc: v.u16le(12),
    ss: v.u16le(14), sp: v.u16le(16), checksum: v.u16le(18), ip: v.u16le(20), cs: v.u16le(22), relocTableOffset: v.u16le(24), overlayNumber: v.u16le(26),
  };
  const warnings: string[] = [];
  const headerSize = h.headerParagraphs * 16;
  let imageSize = h.pages * 512;
  if (h.bytesOnLastPage) imageSize -= 512 - h.bytesOnLastPage;
  if (h.bytesOnLastPage > 511) warnings.push(`bytes on last page is ${h.bytesOnLastPage}, more than a page`);
  if (imageSize > bytes.length) warnings.push(`header says the image is ${imageSize} bytes but the file has ${bytes.length}`);
  if (headerSize > Math.min(imageSize, bytes.length)) warnings.push('header is larger than the image');
  const loadModuleSize = Math.max(0, Math.min(imageSize, bytes.length) - headerSize);
  const entryAddr = ((h.cs * 16 + h.ip) & 0xfffff);
  const relocs: DosReloc[] = [];
  const count = Math.min(h.relocations, maxRelocs);
  for (let i = 0; i < count; i++) {
    const p = h.relocTableOffset + i * 4;
    if (!v.has(p, 4)) { warnings.push(`relocation table ends early at entry ${i}`); break; }
    const offset = v.u16le(p), segment = v.u16le(p + 2);
    const address = (segment * 16 + offset) & 0xfffff;
    const fileOffset = headerSize + address;
    const inImage = address + 2 <= loadModuleSize;
    relocs.push({ index: i, segment, offset, address, fileOffset, value: inImage && v.has(fileOffset, 2) ? v.u16le(fileOffset) : -1, inImage });
  }
  const bad = relocs.filter((r) => !r.inImage).length;
  if (bad) warnings.push(`${bad} relocations point outside the load module`);
  // DOS checksum: the 16 bit words of the image, including the checksum word, sum to 0xFFFF when it is set.
  let sum = 0;
  const lim = Math.min(imageSize, bytes.length);
  for (let i = 0; i < lim; i += 2) { if (i === 18) continue; sum = (sum + ((bytes[i] as number) | ((i + 1 < lim ? (bytes[i + 1] as number) : 0) << 8))) & 0xffff; }
  const computed = (~sum) & 0xffff;
  const markers: { name: string; offset: number }[] = [];
  for (const [needle, label] of MARKERS) { const o = find(bytes, needle, 1 << 20); if (o >= 0 && !markers.some((m) => m.name === label)) markers.push({ name: label, offset: o }); }
  if (v.has(0x1c, 4) && v.ascii(0x1c, 4) === 'LZ91' && !markers.some((m) => m.name.startsWith('LZEXE'))) markers.push({ name: 'LZEXE 0.91 packer', offset: 0x1c });
  const nh = dosNewHeader(bytes);
  const out: DosMz = {
    format: 'dos-mz', header: h, headerSize, imageSize, loadModuleSize,
    entry: { cs: h.cs, ip: h.ip, address: entryAddr, fileOffset: headerSize + entryAddr, inImage: entryAddr < loadModuleSize },
    stack: { ss: h.ss, sp: h.sp, address: (h.ss * 16 + h.sp) & 0xfffff },
    extraMemory: { min: h.minAlloc * 16, max: h.maxAlloc * 16 },
    relocations: relocs, relocationsTruncated: h.relocations > count,
    computedChecksum: computed, checksumValid: h.checksum === 0 ? null : computed === h.checksum,
    markers, warnings,
  };
  if (h.relocTableOffset >= 0x40 && nh.kind !== 'none') out.newHeader = nh;
  if (imageSize < bytes.length) {
    const tail = bytes.subarray(imageSize, Math.min(bytes.length, imageSize + 8));
    let magic = '';
    for (const c of tail) magic += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.';
    out.overlay = { offset: imageSize, size: bytes.length - imageSize, magic };
  }
  if (!out.entry.inImage) warnings.push('entry point is outside the load module');
  return out;
}
