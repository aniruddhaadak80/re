// Mach-O loader (thin and fat): segments, sections, LC_SYMTAB, stubs and pointer sections via the
// indirect symbol table, LC_MAIN / LC_UNIXTHREAD entry, LC_FUNCTION_STARTS.
import { BR, uleb } from '../util.js';
import type { Arch, BinaryImage, FunctionHint, ImportRef, SectionInfo, Segment, Sym } from '../types.js';

const MAX_CMDS = 4096;
const MAX_SYMS = 2_000_000;

export function cpuToArch(cpu: number): Arch {
  switch (cpu >>> 0) {
    case 7: return 'x86';
    case 0x01000007: return 'x86_64';
    case 12: return 'arm';
    case 0x0100000c: return 'arm64';
    default: return 'unknown';
  }
}

export function isFat(bytes: Uint8Array): boolean {
  if (bytes.length < 8) return false;
  const r = new BR(bytes, false);
  const m = r.u32(0);
  return (m === 0xcafebabe || m === 0xcafebabf) && r.u32(4) > 0 && r.u32(4) < 32;
}

export function fatSlices(bytes: Uint8Array): { arch: Arch; offset: number; size: number }[] {
  const r = new BR(bytes, false);
  const fat64 = r.u32(0) === 0xcafebabf;
  const n = Math.min(r.u32(4), 32);
  const out: { arch: Arch; offset: number; size: number }[] = [];
  for (let i = 0; i < n; i++) {
    const o = 8 + i * (fat64 ? 32 : 20);
    const cpu = r.u32(o);
    const offset = fat64 ? r.u64(o + 8) : r.u32(o + 8);
    const size = fat64 ? r.u64(o + 16) : r.u32(o + 12);
    if (offset <= 0 || offset >= bytes.length) continue;
    out.push({ arch: cpuToArch(cpu), offset, size: Math.min(size, bytes.length - offset) });
  }
  return out;
}

export function loadMachO(bytes: Uint8Array, fileOffset = 0): BinaryImage {
  const magicLe = new BR(bytes, true).u32(0);
  const le = magicLe === 0xfeedface || magicLe === 0xfeedfacf;
  const r = new BR(bytes, le);
  const magic = r.u32(0);
  const is64 = magic === 0xfeedfacf;
  const bits: 32 | 64 = is64 ? 64 : 32;
  const arch = cpuToArch(r.u32(4));
  const ncmds = Math.min(r.u32(16), MAX_CMDS);
  const warnings: string[] = [];
  let off = is64 ? 32 : 28;

  const segments: Segment[] = [];
  const sections: (SectionInfo & { type: number; reserved1: number; reserved2: number })[] = [];
  const dylibs: string[] = [];
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;
  let indirect: { off: number; n: number } | undefined;
  let entryOff: number | undefined;
  let entryAbs: number | undefined;
  let fnStarts: { off: number; size: number } | undefined;
  let textVmaddr = 0, textFileoff = 0;

  for (let i = 0; i < ncmds; i++) {
    if (!r.ok(off, 8)) break;
    const cmd = r.u32(off);
    const size = r.u32(off + 4);
    if (size < 8 || !r.ok(off, size)) break;
    if (cmd === 0x19 || cmd === 0x1) {
      const s64 = cmd === 0x19;
      const segname = r.fixstr(off + 8, 16);
      const vmaddr = s64 ? r.u64(off + 24) : r.u32(off + 24);
      const vmsize = s64 ? r.u64(off + 32) : r.u32(off + 28);
      const fileoff = s64 ? r.u64(off + 40) : r.u32(off + 32);
      const filesize = s64 ? r.u64(off + 48) : r.u32(off + 36);
      const initprot = s64 ? r.u32(off + 60) : r.u32(off + 44);
      const nsects = Math.min(s64 ? r.u32(off + 64) : r.u32(off + 48), 1024);
      if (segname === '__TEXT') { textVmaddr = vmaddr; textFileoff = fileoff; }
      if (initprot !== 0 && vmsize > 0) {
        segments.push({ name: segname, vaddr: vmaddr, vsize: vmsize, offset: fileoff, fsize: Math.max(0, Math.min(filesize, bytes.length - fileoff)), r: (initprot & 1) !== 0, w: (initprot & 2) !== 0, x: (initprot & 4) !== 0 });
      }
      const shBase = off + (s64 ? 72 : 56);
      const shSize = s64 ? 80 : 68;
      for (let j = 0; j < nsects; j++) {
        const so = shBase + j * shSize;
        if (so + shSize > off + size) break;
        const sectname = r.fixstr(so, 16);
        const addr = s64 ? r.u64(so + 32) : r.u32(so + 32);
        const ssize = s64 ? r.u64(so + 40) : r.u32(so + 36);
        const offset = s64 ? r.u32(so + 48) : r.u32(so + 40);
        const flags = s64 ? r.u32(so + 64) : r.u32(so + 56);
        const reserved1 = s64 ? r.u32(so + 68) : r.u32(so + 60);
        const reserved2 = s64 ? r.u32(so + 72) : r.u32(so + 64);
        const type = flags & 0xff;
        const zerofill = type === 1 || type === 0xc || type === 0x12;
        sections.push({
          name: sectname, vaddr: addr, size: ssize, offset,
          fsize: zerofill ? 0 : Math.max(0, Math.min(ssize, bytes.length - offset)),
          exec: (flags & 0x80000000) !== 0 || (flags & 0x400) !== 0,
          write: segname.startsWith('__DATA'),
          type, reserved1, reserved2,
        });
      }
    } else if (cmd === 0x2) {
      symtab = { symoff: r.u32(off + 8), nsyms: r.u32(off + 12), stroff: r.u32(off + 16), strsize: r.u32(off + 20) };
    } else if (cmd === 0xb) {
      indirect = { off: r.u32(off + 56), n: r.u32(off + 60) };
    } else if (cmd === 0x80000028) {
      entryOff = r.u64(off + 8);
    } else if (cmd === 0x5 || cmd === 0x4) {
      const st = off + 16;
      if (arch === 'x86_64') entryAbs = r.u64(st + 16 * 8);
      else if (arch === 'arm64') entryAbs = r.u64(st + 32 * 8);
      else if (arch === 'x86') entryAbs = r.u32(st + 10 * 4);
      else if (arch === 'arm') entryAbs = r.u32(st + 15 * 4);
    } else if (cmd === 0x26) {
      fnStarts = { off: r.u32(off + 8), size: r.u32(off + 12) };
    } else if (cmd === 0xc || cmd === 0x80000018 || cmd === 0x8000001f || cmd === 0x20 || cmd === 0x80000023) {
      dylibs.push(r.cstr(off + r.u32(off + 8), 512));
    }
    off += size;
  }

  // symbols
  const symbols: Sym[] = [];
  const allSyms: { name: string; lib?: string }[] = [];
  if (symtab) {
    const ent = is64 ? 16 : 12;
    const n = Math.min(symtab.nsyms, MAX_SYMS);
    for (let i = 0; i < n; i++) {
      const o = symtab.symoff + i * ent;
      if (!r.ok(o, ent)) break;
      const strx = r.u32(o);
      const type = r.u8(o + 4);
      const sect = r.u8(o + 5);
      const desc = r.u16(o + 6);
      const value = is64 ? r.u64(o + 8) : r.u32(o + 8);
      const name = strx < symtab.strsize ? r.cstr(symtab.stroff + strx, 512) : '';
      const ord = (desc >> 8) & 0xff;
      allSyms.push({ name, lib: ord > 0 && ord <= dylibs.length ? baseName(dylibs[ord - 1]!) : undefined });
      if ((type & 0xe0) !== 0) continue; // stab
      if ((type & 0x0e) !== 0x0e || !name || sect === 0) continue;
      const sec = sections[sect - 1];
      const thumb = arch === 'arm' && (desc & 0x8) !== 0;
      symbols.push({ addr: value, name, kind: sec?.exec ? 'func' : 'object', source: 'macho', thumb: thumb || undefined });
    }
  }

  // stubs and pointer slots via the indirect symbol table
  const imports: ImportRef[] = [];
  if (indirect && symtab) {
    const ind = (k: number): string | undefined => {
      if (k < 0 || k >= Math.min(indirect!.n, 4_000_000)) return undefined;
      const idx = r.u32(indirect!.off + k * 4);
      if (idx & 0xc0000000) return undefined;
      return allSyms[idx]?.name || undefined;
    };
    const lib = (name: string) => allSyms.find((s) => s.name === name)?.lib;
    for (const s of sections) {
      if (s.type === 8 && s.reserved2 > 0) {
        const n = Math.min(Math.floor(s.size / s.reserved2), 200000);
        for (let k = 0; k < n; k++) {
          const name = ind(s.reserved1 + k);
          if (name) imports.push({ name, library: lib(name), stub: s.vaddr + k * s.reserved2 });
        }
      } else if (s.type === 6 || s.type === 7) {
        const ps = bits / 8;
        const n = Math.min(Math.floor(s.size / ps), 200000);
        for (let k = 0; k < n; k++) {
          const name = ind(s.reserved1 + k);
          if (name) imports.push({ name, library: lib(name), slot: s.vaddr + k * ps });
        }
      }
    }
  }

  const hints: FunctionHint[] = [];
  if (fnStarts && r.ok(fnStarts.off, fnStarts.size)) {
    const data = r.sub(fnStarts.off, fnStarts.size);
    let p = 0;
    let addr = textVmaddr;
    let count = 0;
    while (p < data.length && count++ < 2_000_000) {
      const [d, np] = uleb(data, p);
      p = np;
      if (d === 0) break;
      addr += d;
      const thumb = arch === 'arm' && (addr & 1) === 1;
      hints.push({ addr: thumb ? addr - 1 : addr, source: 'function-starts', thumb: thumb || undefined });
    }
  }
  void textFileoff;

  let entry: number | undefined;
  if (entryOff !== undefined) entry = textVmaddr + entryOff;
  else if (entryAbs) entry = entryAbs;
  let entryThumb = false;
  if (entry !== undefined && arch === 'arm' && (entry & 1)) { entry -= 1; entryThumb = true; }

  return {
    format: 'macho', arch, bits, endian: le ? 'le' : 'be',
    entry, entryThumb: entryThumb || undefined,
    imageBase: textVmaddr,
    segments, sections: sections.map(({ type, reserved1, reserved2, ...s }) => { void type; void reserved1; void reserved2; return s; }),
    symbols, imports, hints, bytes, fileOffset, warnings,
  };
}

function baseName(p: string): string {
  const i = p.lastIndexOf('/');
  return i >= 0 ? p.slice(i + 1) : p;
}
