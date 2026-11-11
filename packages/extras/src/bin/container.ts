// Minimal executable container model shared by extras: ELF, PE and Mach-O sections,
// segments and symbols, with virtual address to file offset mapping. Bounds checked.

import { View, ParseError } from '../util.js';

export type BinFormat = 'elf' | 'pe' | 'macho';

export interface BinSection {
  name: string;
  segment?: string;
  vaddr: number;
  vsize: number;
  offset: number;
  size: number;
  flags?: number;
  type?: number;
}
export interface BinSegment { name: string; vaddr: number; vsize: number; offset: number; size: number; flags: number; ptype?: number }
export interface BinSymbol { name: string; value: number; size?: number; type?: string; section?: number }

export interface BinImage {
  format: BinFormat;
  bits: 32 | 64;
  le: boolean;
  machine: string;
  imageBase: number;
  entry: number;
  sections: BinSection[];
  segments: BinSegment[];
  /** Mach-O fat files: offset of the chosen slice inside the file */
  sliceOffset: number;
  view: View;
}

export function detectBin(b: Uint8Array): BinFormat | null {
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'elf';
  if (b.length >= 0x40 && b[0] === 0x4d && b[1] === 0x5a) return 'pe';
  if (b.length >= 4) {
    const m = ((b[0] as number) << 24 | (b[1] as number) << 16 | (b[2] as number) << 8 | (b[3] as number)) >>> 0;
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xcafebabf].includes(m)) return 'macho';
  }
  return null;
}

const ELF_MACHINE: Record<number, string> = { 3: 'x86', 8: 'mips', 20: 'ppc', 21: 'ppc64', 40: 'arm', 62: 'x86-64', 183: 'aarch64', 243: 'riscv', 258: 'loongarch', 22: 's390', 2: 'sparc', 43: 'sparcv9' };
const PE_MACHINE: Record<number, string> = { 0x14c: 'x86', 0x8664: 'x86-64', 0x1c0: 'arm', 0x1c4: 'armnt', 0xaa64: 'aarch64', 0x200: 'ia64', 0x5064: 'riscv64' };
const MACHO_CPU: Record<number, string> = { 7: 'x86', 0x01000007: 'x86-64', 12: 'arm', 0x0100000c: 'aarch64', 0x0200000c: 'arm64_32', 18: 'ppc', 0x01000012: 'ppc64' };

export function parseBin(bytes: Uint8Array, opts: { arch?: string } = {}): BinImage {
  const f = detectBin(bytes);
  if (f === 'elf') return parseElf(bytes);
  if (f === 'pe') return parsePe(bytes);
  if (f === 'macho') return parseMacho(bytes, opts.arch);
  throw new ParseError('not an ELF, PE or Mach-O file');
}

// ---------------- ELF ----------------
export function parseElf(bytes: Uint8Array): BinImage {
  if (detectBin(bytes) !== 'elf') throw new ParseError('not an ELF file');
  const cls = bytes[4];
  const data = bytes[5];
  if (cls !== 1 && cls !== 2) throw new ParseError('bad ELF class');
  const le = data !== 2;
  const v = new View(bytes, le);
  const is64 = cls === 2;
  const ps = is64 ? 8 : 4;
  const machine = v.u16(18);
  const entry = v.uN(24, ps);
  const phoff = v.uN(24 + ps, ps);
  const shoff = v.uN(24 + 2 * ps, ps);
  const o = 24 + 3 * ps + 4;
  const phentsize = v.u16(o + 2), phnum = v.u16(o + 4), shentsize = v.u16(o + 6);
  let shnum = v.u16(o + 8);
  let shstrndx = v.u16(o + 10);
  const segments: BinSegment[] = [];
  for (let i = 0; i < Math.min(phnum, 4096); i++) {
    const b = phoff + i * phentsize;
    if (!v.has(b, is64 ? 56 : 32)) break;
    const type = v.u32(b);
    if (is64) segments.push({ name: `PT_${type.toString(16)}`, ptype: type, flags: v.u32(b + 4), offset: v.u64n(b + 8), vaddr: v.u64n(b + 16), size: v.u64n(b + 32), vsize: v.u64n(b + 40) });
    else segments.push({ name: `PT_${type.toString(16)}`, ptype: type, offset: v.u32(b + 4), vaddr: v.u32(b + 8), size: v.u32(b + 16), vsize: v.u32(b + 20), flags: v.u32(b + 24) });
  }
  const sections: BinSection[] = [];
  if (shoff && shentsize && v.has(shoff, shentsize)) {
    if (shnum === 0) shnum = is64 ? v.u64n(shoff + 32) : v.u32(shoff + 20);
    if (shstrndx === 0xffff) shstrndx = v.u32(shoff + (is64 ? 40 : 24));
    shnum = Math.min(shnum, 65536);
    const raw: { nameOff: number; type: number; flags: number; addr: number; off: number; size: number }[] = [];
    for (let i = 0; i < shnum; i++) {
      const b = shoff + i * shentsize;
      if (!v.has(b, is64 ? 64 : 40)) break;
      if (is64) raw.push({ nameOff: v.u32(b), type: v.u32(b + 4), flags: v.u64n(b + 8), addr: v.u64n(b + 16), off: v.u64n(b + 24), size: v.u64n(b + 32) });
      else raw.push({ nameOff: v.u32(b), type: v.u32(b + 4), flags: v.u32(b + 8), addr: v.u32(b + 12), off: v.u32(b + 16), size: v.u32(b + 20) });
    }
    const strs = raw[shstrndx];
    for (const s of raw) {
      let name = '';
      if (strs && v.has(strs.off + s.nameOff, 1)) { try { name = v.cstr(strs.off + s.nameOff, 256); } catch { name = ''; } }
      const fileSize = s.type === 8 ? 0 : s.size; // SHT_NOBITS
      sections.push({ name, vaddr: s.addr, vsize: s.size, offset: s.off, size: fileSize, flags: s.flags, type: s.type });
    }
  }
  return { format: 'elf', bits: is64 ? 64 : 32, le, machine: ELF_MACHINE[machine] ?? `elf-machine-${machine}`, imageBase: 0, entry, sections, segments, sliceOffset: 0, view: v };
}

export function elfSymbols(img: BinImage, which: 'symtab' | 'dynsym' = 'symtab', max = 500000): BinSymbol[] {
  const v = img.view;
  const is64 = img.bits === 64;
  const out: BinSymbol[] = [];
  const typeId = which === 'symtab' ? 2 : 11;
  const symSec = img.sections.find((s) => s.type === typeId);
  if (!symSec) return out;
  const idx = img.sections.indexOf(symSec);
  // sh_link of the symbol table names the string table; re-read it from the header
  const shoff = v.uN(24 + 2 * (is64 ? 8 : 4), is64 ? 8 : 4);
  const shentsize = v.u16(24 + 3 * (is64 ? 8 : 4) + 4 + 6);
  const link = v.u32(shoff + idx * shentsize + (is64 ? 40 : 24));
  const strSec = img.sections[link];
  if (!strSec) return out;
  const ent = is64 ? 24 : 16;
  const n = Math.min(Math.floor(symSec.size / ent), max);
  for (let i = 0; i < n; i++) {
    const b = symSec.offset + i * ent;
    if (!v.has(b, ent)) break;
    const nameOff = v.u32(b);
    let value: number, size: number, info: number, shndx: number;
    if (is64) { info = v.u8(b + 4); shndx = v.u16(b + 6); value = v.u64n(b + 8); size = v.u64n(b + 16); }
    else { value = v.u32(b + 4); size = v.u32(b + 8); info = v.u8(b + 12); shndx = v.u16(b + 14); }
    if (!nameOff || strSec.offset + nameOff >= v.length) continue;
    const name = v.cstr(strSec.offset + nameOff, 4096);
    const t = info & 0xf;
    out.push({ name, value, size, type: t === 2 ? 'func' : t === 1 ? 'object' : t === 6 ? 'tls' : String(t), section: shndx });
  }
  return out;
}

// ---------------- PE ----------------
export function parsePe(bytes: Uint8Array): BinImage {
  const v = new View(bytes, true);
  if (v.u16(0) !== 0x5a4d) throw new ParseError('missing MZ header');
  const pe = v.u32(0x3c);
  if (v.u32(pe) !== 0x4550) throw new ParseError('missing PE signature', pe);
  const machine = v.u16(pe + 4);
  const nsec = Math.min(v.u16(pe + 6), 96);
  const optSize = v.u16(pe + 20);
  const opt = pe + 24;
  const magic = v.u16(opt);
  const is64 = magic === 0x20b;
  const entry = v.u32(opt + 16);
  const imageBase = is64 ? v.u64n(opt + 24) : v.u32(opt + 28);
  const sections: BinSection[] = [];
  const secOff = opt + optSize;
  for (let i = 0; i < nsec; i++) {
    const b = secOff + i * 40;
    if (!v.has(b, 40)) break;
    let name = '';
    for (let j = 0; j < 8; j++) { const c = v.u8(b + j); if (!c) break; name += String.fromCharCode(c); }
    sections.push({ name, vsize: v.u32(b + 8), vaddr: v.u32(b + 12), size: v.u32(b + 16), offset: v.u32(b + 20), flags: v.u32(b + 36) });
  }
  return { format: 'pe', bits: is64 ? 64 : 32, le: true, machine: PE_MACHINE[machine] ?? `pe-machine-0x${machine.toString(16)}`, imageBase, entry, sections, segments: [], sliceOffset: 0, view: v };
}

// ---------------- Mach-O ----------------
export function machoSlices(bytes: Uint8Array): { arch: string; offset: number; size: number }[] {
  const v = new View(bytes, false);
  const magic = v.u32(0);
  if (magic !== 0xcafebabe && magic !== 0xcafebabf) return [{ arch: 'thin', offset: 0, size: bytes.length }];
  const n = Math.min(v.u32(4), 64);
  const is64 = magic === 0xcafebabf;
  const out: { arch: string; offset: number; size: number }[] = [];
  for (let i = 0; i < n; i++) {
    const b = 8 + i * (is64 ? 32 : 20);
    const cpu = v.u32(b);
    const off = is64 ? v.u64n(b + 8) : v.u32(b + 8);
    const size = is64 ? v.u64n(b + 16) : v.u32(b + 12);
    out.push({ arch: MACHO_CPU[cpu] ?? `cpu-${cpu}`, offset: off, size });
  }
  return out;
}

export function parseMacho(bytes: Uint8Array, arch?: string): BinImage {
  const slices = machoSlices(bytes);
  const pick = arch ? slices.find((s) => s.arch === arch) : slices[0];
  if (!pick) throw new ParseError(`no Mach-O slice for ${arch}`);
  const base = pick.offset;
  const bv = new View(bytes, true);
  bv.need(base, 28);
  const m = bv.u32(base, false);
  const le = m === 0xcefaedfe || m === 0xcffaedfe;
  const v = new View(bytes, le);
  const is64 = m === 0xfeedfacf || m === 0xcffaedfe;
  const cpu = v.u32(base + 4);
  const ncmds = Math.min(v.u32(base + 16), 4096);
  let p = base + (is64 ? 32 : 28);
  const sections: BinSection[] = [];
  const segments: BinSegment[] = [];
  let entry = 0;
  let textVm = 0;
  for (let i = 0; i < ncmds; i++) {
    if (!v.has(p, 8)) break;
    const cmd = v.u32(p), size = v.u32(p + 4);
    if (size < 8) break;
    if (cmd === 0x19 || cmd === 0x1) {
      const s64 = cmd === 0x19;
      const segname = v.cstr(p + 8, 16);
      const vmaddr = s64 ? v.u64n(p + 24) : v.u32(p + 24);
      const vmsize = s64 ? v.u64n(p + 32) : v.u32(p + 28);
      const fileoff = s64 ? v.u64n(p + 40) : v.u32(p + 32);
      const filesize = s64 ? v.u64n(p + 48) : v.u32(p + 36);
      const nsects = v.u32(p + (s64 ? 64 : 48));
      const initprotOff = s64 ? 60 : 44;
      segments.push({ name: segname, vaddr: vmaddr, vsize: vmsize, offset: base + fileoff, size: filesize, flags: v.u32(p + initprotOff) });
      if (segname === '__TEXT') textVm = vmaddr;
      let sp = p + (s64 ? 72 : 56);
      for (let j = 0; j < Math.min(nsects, 1024); j++) {
        const sectname = v.cstr(sp, 16);
        const addr = s64 ? v.u64n(sp + 32) : v.u32(sp + 32);
        const ssize = s64 ? v.u64n(sp + 40) : v.u32(sp + 36);
        const off = v.u32(sp + (s64 ? 48 : 40));
        const flags = v.u32(sp + (s64 ? 64 : 56));
        const zerofill = (flags & 0xff) === 1 || (flags & 0xff) === 0x0c;
        sections.push({ name: sectname, segment: segname, vaddr: addr, vsize: ssize, offset: zerofill ? 0 : base + off, size: zerofill ? 0 : ssize, flags });
        sp += s64 ? 80 : 68;
      }
    } else if (cmd === 0x80000028) {
      entry = v.u64n(p + 8); // LC_MAIN entryoff, relative to __TEXT
    }
    p += size;
  }
  if (entry) entry += textVm;
  return { format: 'macho', bits: is64 ? 64 : 32, le, machine: MACHO_CPU[cpu] ?? `cpu-${cpu}`, imageBase: textVm, entry, sections, segments, sliceOffset: base, view: v };
}

// ---------------- mapping ----------------
/** Map a virtual address to a file offset, or -1. PE addresses may be RVAs or full VAs. */
export function vaToOffset(img: BinImage, va: number): number {
  if (img.format === 'pe') {
    const rva = va >= img.imageBase && img.imageBase > 0 ? va - img.imageBase : va;
    for (const s of img.sections) {
      const span = Math.max(s.vsize, s.size);
      if (rva >= s.vaddr && rva < s.vaddr + span) {
        const d = rva - s.vaddr;
        return d < s.size ? s.offset + d : -1;
      }
    }
    if (rva < (img.sections[0]?.offset ?? 0x400)) return rva;
    return -1;
  }
  if (img.format === 'elf') {
    for (const sg of img.segments) {
      if (sg.ptype !== 1) continue;
      if (va >= sg.vaddr && va < sg.vaddr + sg.size) return sg.offset + (va - sg.vaddr);
    }
    for (const s of img.sections) if (s.size && va >= s.vaddr && va < s.vaddr + s.size && s.vaddr) return s.offset + (va - s.vaddr);
    return -1;
  }
  for (const sg of img.segments) if (va >= sg.vaddr && va < sg.vaddr + sg.size) return sg.offset + (va - sg.vaddr);
  return -1;
}

/** Map a file offset back to a virtual address (full VA for PE), or -1. */
export function offsetToVa(img: BinImage, off: number): number {
  if (img.format === 'pe') {
    for (const s of img.sections) if (off >= s.offset && off < s.offset + s.size) return img.imageBase + s.vaddr + (off - s.offset);
    return -1;
  }
  const segs = img.format === 'elf' ? img.segments.filter((s) => s.ptype === 1) : img.segments;
  for (const sg of segs) if (off >= sg.offset && off < sg.offset + sg.size) return sg.vaddr + (off - sg.offset);
  return -1;
}

export function findSection(img: BinImage, ...names: string[]): BinSection | undefined {
  for (const n of names) {
    const s = img.sections.find((x) => x.name === n);
    if (s) return s;
  }
  return undefined;
}
