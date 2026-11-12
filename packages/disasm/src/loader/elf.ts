// ELF loader: segments, sections, symtab/dynsym, PLT/GOT import slots, .eh_frame and .ARM.exidx function hints.
import { BR } from '../util.js';
import type { Arch, BinaryImage, FunctionHint, ImportRef, SectionInfo, Segment, Sym } from '../types.js';
import { parseEhFrame } from './ehframe.js';

const MAX_SECTIONS = 4096;
const MAX_PHDRS = 1024;
const MAX_SYMS = 2_000_000;

interface Shdr { name: string; type: number; flags: number; addr: number; offset: number; size: number; link: number; info: number; entsize: number }

export function loadElf(bytes: Uint8Array): BinaryImage {
  const cls = bytes[4];
  const data = bytes[5];
  const bits: 32 | 64 = cls === 2 ? 64 : 32;
  const r = new BR(bytes, data !== 2);
  const machine = r.u16(18);
  const arch: Arch = machine === 62 ? 'x86_64' : machine === 3 ? 'x86' : machine === 183 ? 'arm64' : machine === 40 ? 'arm' : 'unknown';
  const warnings: string[] = [];
  const is64 = bits === 64;
  const entryRaw = is64 ? r.u64(24) : r.u32(24);
  const phoff = is64 ? r.u64(32) : r.u32(28);
  const shoff = is64 ? r.u64(40) : r.u32(32);
  const phentsize = r.u16(is64 ? 54 : 42);
  const phnum = Math.min(r.u16(is64 ? 56 : 44), MAX_PHDRS);
  const shentsize = r.u16(is64 ? 58 : 46);
  let shnum = r.u16(is64 ? 60 : 48);
  const shstrndx = r.u16(is64 ? 62 : 50);

  const segments: Segment[] = [];
  let dynamicVaddr = 0, dynamicSize = 0;
  if (phentsize >= (is64 ? 56 : 32)) {
    for (let i = 0; i < phnum; i++) {
      const o = phoff + i * phentsize;
      if (!r.ok(o, phentsize)) break;
      const type = r.u32(o);
      const flags = is64 ? r.u32(o + 4) : r.u32(o + 24);
      const offset = is64 ? r.u64(o + 8) : r.u32(o + 4);
      const vaddr = is64 ? r.u64(o + 16) : r.u32(o + 8);
      const filesz = is64 ? r.u64(o + 32) : r.u32(o + 16);
      const memsz = is64 ? r.u64(o + 40) : r.u32(o + 20);
      if (type === 2) { dynamicVaddr = vaddr; dynamicSize = memsz; }
      if (type !== 1) continue; // PT_LOAD
      segments.push({ name: `LOAD${segments.length}`, vaddr, vsize: memsz, offset, fsize: Math.min(filesz, Math.max(0, bytes.length - offset)), r: (flags & 4) !== 0, w: (flags & 2) !== 0, x: (flags & 1) !== 0 });
    }
  }

  const shdrs: Shdr[] = [];
  if (shoff > 0 && shentsize >= (is64 ? 64 : 40)) {
    if (shnum === 0 && r.ok(shoff, shentsize)) shnum = is64 ? r.u64(shoff + 32) : r.u32(shoff + 20);
    shnum = Math.min(shnum, MAX_SECTIONS);
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shentsize;
      if (!r.ok(o, shentsize)) break;
      shdrs.push(is64
        ? { name: '', type: r.u32(o + 4), flags: r.u64(o + 8), addr: r.u64(o + 16), offset: r.u64(o + 24), size: r.u64(o + 32), link: r.u32(o + 40), info: r.u32(o + 44), entsize: r.u64(o + 56) }
        : { name: '', type: r.u32(o + 4), flags: r.u32(o + 8), addr: r.u32(o + 12), offset: r.u32(o + 16), size: r.u32(o + 20), link: r.u32(o + 24), info: r.u32(o + 28), entsize: r.u32(o + 36) });
    }
    const strsec = shdrs[shstrndx];
    for (let i = 0; i < shdrs.length; i++) {
      const o = shoff + i * shentsize;
      shdrs[i]!.name = strsec ? r.cstr(strsec.offset + r.u32(o), 256) : '';
    }
  }

  const sections: SectionInfo[] = shdrs
    .filter((s) => (s.flags & 2) !== 0 && s.addr > 0)
    .map((s) => ({ name: s.name, vaddr: s.addr, size: s.size, offset: s.offset, fsize: s.type === 8 ? 0 : Math.min(s.size, Math.max(0, bytes.length - s.offset)), exec: (s.flags & 4) !== 0, write: (s.flags & 1) !== 0 }));

  const symbols: Sym[] = [];
  const symTables = new Map<number, { name: string; value: number }[]>();
  const readSymtab = (idx: number, source: 'symtab' | 'dynsym'): { name: string; value: number }[] => {
    const cached = symTables.get(idx);
    if (cached) return cached;
    const s = shdrs[idx];
    const list: { name: string; value: number }[] = [];
    symTables.set(idx, list);
    if (!s) return list;
    const str = shdrs[s.link];
    const ent = s.entsize || (is64 ? 24 : 16);
    if (ent < (is64 ? 24 : 16)) return list;
    const n = Math.min(Math.floor(s.size / ent), MAX_SYMS);
    for (let i = 0; i < n; i++) {
      const o = s.offset + i * ent;
      if (!r.ok(o, ent)) break;
      const nameOff = r.u32(o);
      const info = is64 ? r.u8(o + 4) : r.u8(o + 12);
      const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
      const value = is64 ? r.u64(o + 8) : r.u32(o + 4);
      const size = is64 ? r.u64(o + 16) : r.u32(o + 8);
      const name = str ? r.cstr(str.offset + nameOff, 512) : '';
      list.push({ name, value });
      const type = info & 0xf;
      if (!name || value === 0 || shndx === 0) continue;
      if (type === 2 || type === 10) {
        const thumb = arch === 'arm' && (value & 1) === 1;
        symbols.push({ addr: thumb ? value - 1 : value, name, size: size || undefined, kind: 'func', source, thumb: thumb || undefined, local: (info >> 4) === 0 || undefined });
      } else if (type === 1) {
        symbols.push({ addr: value, name, size: size || undefined, kind: 'object', source });
      } else if (type === 0 && arch === 'arm' && name.startsWith('$')) {
        // mapping symbols $a/$t/$d are not names
      }
    }
    return list;
  };
  shdrs.forEach((s, i) => { if (s.type === 2) readSymtab(i, 'symtab'); });
  shdrs.forEach((s, i) => { if (s.type === 11) readSymtab(i, 'dynsym'); });

  // Relocations that name import slots
  const imports: ImportRef[] = [];
  const slotTypes = arch === 'x86_64' ? [6, 7] : arch === 'x86' ? [6, 7] : arch === 'arm64' ? [1025, 1026] : arch === 'arm' ? [21, 22] : [];
  // pointers the dynamic loader writes at load time (RELA RELATIVE: value = image base + addend)
  const relocPtrs = new Map<number, number>();
  const relativeType = arch === 'x86_64' ? 8 : arch === 'arm64' ? 1027 : -1;
  const addReloc = (offset: number, symIdx: number, type: number, syms: { name: string }[], addend?: number) => {
    if (type === relativeType && addend !== undefined) { if (relocPtrs.size < 2_000_000) relocPtrs.set(offset, addend); return; }
    if (!slotTypes.includes(type)) return;
    const name = syms[symIdx]?.name;
    if (!name) return;
    imports.push({ name, slot: offset });
  };
  for (const s of shdrs) {
    if (s.type !== 4 && s.type !== 9) continue;
    const syms = readSymtab(s.link, shdrs[s.link]?.type === 2 ? 'symtab' : 'dynsym');
    const rela = s.type === 4;
    const ent = s.entsize || (is64 ? (rela ? 24 : 16) : (rela ? 12 : 8));
    const n = Math.min(Math.floor(s.size / Math.max(ent, 1)), 500000);
    for (let i = 0; i < n; i++) {
      const o = s.offset + i * ent;
      if (!r.ok(o, ent)) break;
      if (is64) {
        const info = r.u64(o + 8);
        addReloc(r.u64(o), Math.floor(info / 2 ** 32), info % 2 ** 32, syms, rela ? r.i64(o + 16) : undefined);
      } else {
        const info = r.u32(o + 4);
        addReloc(r.u32(o), info >>> 8, info & 0xff, syms);
      }
    }
  }
  if (shdrs.length === 0 && dynamicVaddr) warnings.push('no section headers; imports from PT_DYNAMIC are not resolved');
  void dynamicSize;

  const hints: FunctionHint[] = [];
  const eh = shdrs.find((s) => s.name === '.eh_frame' && s.type !== 8);
  if (eh) {
    for (const h of parseEhFrame(r.sub(eh.offset, eh.size), eh.addr, bits, r.le)) hints.push({ addr: h.addr, size: h.size, source: 'eh-frame' });
  }
  const exidx = shdrs.find((s) => s.type === 0x70000001 || s.name === '.ARM.exidx');
  if (exidx && arch === 'arm') {
    const n = Math.min(Math.floor(exidx.size / 8), 1_000_000);
    for (let i = 0; i < n; i++) {
      const o = exidx.offset + i * 8;
      const w = r.u32(o);
      const rel = (w & 0x40000000) ? (w | 0x80000000) | 0 : w & 0x7fffffff;
      const fn = (exidx.addr + i * 8 + rel) >>> 0;
      hints.push({ addr: fn & ~1, source: 'arm-exidx', thumb: (fn & 1) === 1 || undefined });
    }
  }

  const debugSections: { name: string; offset: number; size: number }[] = [];
  const debugCompressed: string[] = [];
  for (const s of shdrs) {
    if ((s.flags & 2) !== 0 || s.type === 8 || !/^\.(z?debug_)/.test(s.name)) continue;
    if (s.offset >= bytes.length) continue;
    debugSections.push({ name: s.name, offset: s.offset, size: Math.min(s.size, bytes.length - s.offset) });
    if ((s.flags & 0x800) !== 0) debugCompressed.push(s.name);
  }

  const entryThumb = arch === 'arm' && (entryRaw & 1) === 1;
  return {
    format: 'elf', arch, bits, endian: r.le ? 'le' : 'be',
    entry: entryRaw ? (entryThumb ? entryRaw - 1 : entryRaw) : undefined,
    entryThumb: entryThumb || undefined,
    imageBase: segments.length ? Math.min(...segments.map((s) => s.vaddr)) : 0,
    segments, sections, symbols, imports, hints,
    bytes, fileOffset: 0, warnings,
    ...(relocPtrs.size ? { relocPtrs } : {}),
    ...(debugSections.length ? { debugSections } : {}),
    ...(debugCompressed.length ? { debugCompressed } : {}),
  };
}
