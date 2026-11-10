import type { Analyzer, Section } from '../types.js';
import { Reader, entropy } from '../bytes.js';

const ET = { 0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN (PIE or shared object)', 4: 'CORE' } as const;
const MACH: Record<number, string> = { 0x02: 'SPARC', 0x03: 'x86', 0x08: 'MIPS', 0x14: 'PowerPC', 0x16: 'S390', 0x28: 'ARM', 0x2a: 'SuperH', 0x32: 'IA-64', 0x3e: 'x86-64', 0xb7: 'AArch64', 0xf3: 'RISC-V' };

export const elfAnalyzer: Analyzer = {
  id: 'elf',
  title: 'ELF',
  description: 'Parses ELF headers, sections, dynamic libraries, symbols and hardening flags.',
  applies: (ctx) => ctx.format === 'elf',
  run(ctx) {
    const { bytes, report } = ctx;
    const little = bytes[5] === 1;
    const is64 = bytes[4] === 2;
    const r = new Reader(bytes, little);
    report.file.bits = is64 ? 64 : 32;
    report.file.endian = little ? 'le' : 'be';
    const eType = r.u16(16);
    const machine = r.u16(18);
    report.file.arch = MACH[machine] ?? `machine 0x${machine.toString(16)}`;

    const shoff = is64 ? Number(r.u64(40)) : r.u32(32);
    const shentsize = r.u16(is64 ? 58 : 46);
    const shnum = r.u16(is64 ? 60 : 48);
    const shstrndx = r.u16(is64 ? 62 : 50);

    const sections: Section[] = [];
    let strtabOff = 0, strtabSize = 0;
    if (shoff && shnum && shstrndx < shnum) {
      const sheader = shoff + shstrndx * shentsize;
      strtabOff = is64 ? Number(r.u64(sheader + 24)) : r.u32(sheader + 16);
      strtabSize = is64 ? Number(r.u64(sheader + 32)) : r.u32(sheader + 20);
    }
    const nameAt = (o: number): string => {
      if (!strtabOff || o >= strtabSize) return '';
      let s = '';
      for (let i = strtabOff + o; i < bytes.length && bytes[i]; i++) s += String.fromCharCode(bytes[i] as number);
      return s;
    };
    const dynNeeded: string[] = [];
    for (let i = 0; i < shnum && shoff; i++) {
      const b = shoff + i * shentsize;
      if (b + shentsize > bytes.length) break;
      const nameOff = r.u32(b);
      const off = is64 ? Number(r.u64(b + 24)) : r.u32(b + 16);
      const size = is64 ? Number(r.u64(b + 32)) : r.u32(b + 20);
      const addr = is64 ? Number(r.u64(b + 16)) : r.u32(b + 12);
      if (i === 0) continue; // SHT_NULL
      const nm = nameAt(nameOff) || `sec${i}`;
      const ent = off + size <= bytes.length && size > 0 ? Number(entropy(bytes, off, off + size).toFixed(3)) : 0;
      sections.push({ name: nm, offset: off, size, vaddr: addr, entropy: ent });
    }
    report.sections = sections;

    // DT_NEEDED entries from .dynamic, resolved against .dynstr.
    const dyn = sections.find((s) => s.name === '.dynamic');
    const dynstr = sections.find((s) => s.name === '.dynstr');
    if (dyn && dynstr) {
      const esz = is64 ? 16 : 8;
      for (let o = dyn.offset; o + esz <= dyn.offset + dyn.size && o + esz <= bytes.length; o += esz) {
        const tag = is64 ? Number(r.u64(o)) : r.u32(o);
        const val = is64 ? Number(r.u64(o + 8)) : r.u32(o + 4);
        if (tag === 0) break;
        if (tag === 1) { // DT_NEEDED
          let s = '';
          for (let i = dynstr.offset + val; i < bytes.length && bytes[i]; i++) s += String.fromCharCode(bytes[i] as number);
          if (s) dynNeeded.push(s);
        }
      }
    }
    if (dynNeeded.length) report.imports.push({ library: 'DT_NEEDED', symbols: dynNeeded });

    // Imported (undefined) and exported (defined, global) dynamic symbols.
    const dynsym = sections.find((s) => s.name === '.dynsym');
    if (dynsym && dynstr) {
      const esz = is64 ? 24 : 16;
      const imported: string[] = [];
      for (let o = dynsym.offset + esz; o + esz <= dynsym.offset + dynsym.size && o + esz <= bytes.length && imported.length + report.exports.length < 20000; o += esz) {
        const nameOff = r.u32(o);
        const info = is64 ? (bytes[o + 4] as number) : (bytes[o + 12] as number);
        const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
        let nm = '';
        for (let i = dynstr.offset + nameOff; i < bytes.length && bytes[i] && nm.length < 256; i++) nm += String.fromCharCode(bytes[i] as number);
        if (!nm) continue;
        const bind = info >> 4;
        if (shndx === 0) imported.push(nm);
        else if (bind === 1 || bind === 2) report.exports.push(nm);
      }
      if (imported.length) report.imports.push({ library: 'dynamic symbols', symbols: imported });
    }

    const interp = sections.find((s) => s.name === '.interp');
    const hasGnuStack = sections.some((s) => s.name === '.note.GNU-stack');
    const relro = sections.some((s) => s.name === '.data.rel.ro') || sections.some((s) => s.name === '.got.plt');
    report.hardening = {
      type: ET[eType as 0 | 1 | 2 | 3 | 4] ?? `type ${eType}`,
      pie: eType === 3,
      stripped: !sections.some((s) => s.name === '.symtab'),
      dynamicallyLinked: !!interp,
      nxLikely: hasGnuStack || is64,
      relroLikely: relro,
    };
    report.meta.elf = { machine: report.file.arch, sectionCount: sections.length, dynNeeded };
  },
};
