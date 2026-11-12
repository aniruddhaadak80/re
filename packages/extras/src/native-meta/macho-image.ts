// A small Mach-O image model for metadata readers: segments, sections, virtual address reads,
// pointer fixups (LC_DYLD_CHAINED_FIXUPS in every user space format, classic dyld bind opcodes,
// arm64e pointer authentication stripping) and the symbol table. Every read is bounds checked
// and every table walk is capped, so hostile files end in an error or a partial answer.

import { ParseError } from '../util.js';
import { machoSlices } from '../bin/container.js';

export interface MSection { seg: string; name: string; addr: number; size: number; offset: number; flags: number }
export interface MSegment { name: string; vmaddr: number; vmsize: number; fileoff: number; filesize: number }
export type Fixup = { kind: 'rebase'; target: number; auth?: { key: string; diversity: number; addrDiv: boolean } } | { kind: 'bind'; name: string; addend: number; lib: number; auth?: { key: string; diversity: number; addrDiv: boolean } };

const CPU: Record<number, string> = { 7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32' };
export const POINTER_FORMATS: Record<number, string> = {
  1: 'DYLD_CHAINED_PTR_ARM64E', 2: 'DYLD_CHAINED_PTR_64', 3: 'DYLD_CHAINED_PTR_32', 4: 'DYLD_CHAINED_PTR_32_CACHE',
  5: 'DYLD_CHAINED_PTR_32_FIRMWARE', 6: 'DYLD_CHAINED_PTR_64_OFFSET', 7: 'DYLD_CHAINED_PTR_ARM64E_KERNEL',
  8: 'DYLD_CHAINED_PTR_64_KERNEL_CACHE', 9: 'DYLD_CHAINED_PTR_ARM64E_USERLAND', 10: 'DYLD_CHAINED_PTR_ARM64E_FIRMWARE',
  11: 'DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE', 12: 'DYLD_CHAINED_PTR_ARM64E_USERLAND24',
};
const KEYS = ['IA', 'IB', 'DA', 'DB'];
const MAX_FIXUPS = 4_000_000;
const MAX_SYMBOLS = 2_000_000;

export interface ImageLimits { maxFixups?: number; maxSymbols?: number }

/** One thin Mach-O image (a slice of a fat file is picked by arch). */
export class MachImage {
  readonly bytes: Uint8Array;
  readonly dv: DataView;
  readonly base: number;
  readonly le: boolean;
  readonly is64: boolean;
  readonly ptrSize: 4 | 8;
  readonly cpu: number;
  readonly cpuSubtype: number;
  readonly arch: string;
  readonly fileType: number;
  readonly segments: MSegment[] = [];
  readonly sections: MSection[] = [];
  readonly fixups = new Map<number, Fixup>();
  readonly symbols = new Map<number, string>();
  readonly notes: string[] = [];
  pointerFormat?: string;
  fixupSource: 'chained' | 'dyld-info' | 'none' = 'none';
  /** preferred load address (vmaddr of the segment mapped at file offset 0) */
  imageBase = 0;
  private chainedOff = -1; private chainedSize = 0;
  private dyldInfo: { bindOff: number; bindSize: number; weakOff: number; weakSize: number; lazyOff: number; lazySize: number } | undefined;
  private symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;
  readonly dylibs: string[] = [];

  constructor(file: Uint8Array, arch?: string, limits: ImageLimits = {}) {
    const slices = machoSlices(file);
    let pick = slices[0];
    if (arch) {
      const norm = (a: string) => ({ 'x86-64': 'x86_64', amd64: 'x86_64', aarch64: 'arm64', arm64e: 'arm64', i386: 'x86' } as Record<string, string>)[a.toLowerCase()] ?? a.toLowerCase();
      pick = slices.find((s) => s.arch === arch) ?? slices.find((s) => norm(s.arch) === norm(arch));
    }
    if (!pick) throw new ParseError(`no Mach-O slice for ${arch}; slices: ${slices.map((s) => s.arch).join(', ')}`);
    if (pick.arch !== 'thin' && (pick.offset < 0 || pick.offset + pick.size > file.length || pick.size < 32)) throw new ParseError('fat slice out of range');
    this.bytes = pick.arch === 'thin' ? file : file.subarray(pick.offset, pick.offset + pick.size);
    this.dv = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    this.base = 0;
    if (this.bytes.length < 28) throw new ParseError('file too small for a Mach-O header');
    const m = this.dv.getUint32(0, false);
    if (m === 0xcffaedfe || m === 0xcefaedfe) this.le = true;
    else if (m === 0xfeedfacf || m === 0xfeedface) this.le = false;
    else throw new ParseError('not a Mach-O image');
    this.is64 = m === 0xcffaedfe || m === 0xfeedfacf;
    this.ptrSize = this.is64 ? 8 : 4;
    this.cpu = this.u32(4);
    this.cpuSubtype = this.u32(8) & 0xffffff;
    this.arch = CPU[this.cpu] ?? `cpu-${this.cpu}`;
    if (this.arch === 'arm64' && this.cpuSubtype === 2) this.arch = 'arm64e';
    if (this.cpu === 0x0200000c) this.ptrSize = 4;
    this.fileType = this.u32(12);
    this.loadCommands();
    this.loadSymbols(limits.maxSymbols ?? MAX_SYMBOLS);
    if (this.chainedOff >= 0) this.loadChained(limits.maxFixups ?? MAX_FIXUPS);
    else if (this.dyldInfo) this.loadDyldInfo(limits.maxFixups ?? MAX_FIXUPS);
  }

  // ---------- raw reads ----------
  has(off: number, n: number): boolean { return Number.isInteger(off) && off >= 0 && n >= 0 && off + n <= this.bytes.length; }
  u8(o: number): number { if (!this.has(o, 1)) throw new ParseError('read out of range', o); return this.bytes[o]!; }
  u16(o: number): number { if (!this.has(o, 2)) throw new ParseError('read out of range', o); return this.dv.getUint16(o, this.le); }
  u32(o: number): number { if (!this.has(o, 4)) throw new ParseError('read out of range', o); return this.dv.getUint32(o, this.le); }
  i32(o: number): number { if (!this.has(o, 4)) throw new ParseError('read out of range', o); return this.dv.getInt32(o, this.le); }
  /** 64 bit value as hi, lo 32 bit halves (exact, no precision loss). */
  u64parts(o: number): [number, number] {
    if (!this.has(o, 8)) throw new ParseError('read out of range', o);
    const a = this.dv.getUint32(o, this.le), b = this.dv.getUint32(o + 4, this.le);
    return this.le ? [b, a] : [a, b];
  }
  u64n(o: number): number { const [hi, lo] = this.u64parts(o); return hi * 0x100000000 + lo; }
  cstrAt(o: number, max = 4096): string {
    if (o < 0 || o >= this.bytes.length) throw new ParseError('string out of range', o);
    const end = Math.min(this.bytes.length, o + max);
    let i = o;
    while (i < end && this.bytes[i] !== 0) i++;
    return new TextDecoder('utf-8', { fatal: false }).decode(this.bytes.subarray(o, i));
  }

  // ---------- address space ----------
  private segIdx: MSegment[] = [];
  /** File offset for a virtual address, or -1 when it is not backed by file bytes. */
  toOffset(addr: number): number {
    const s = this.segIdx;
    let lo = 0, hi = s.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const g = s[mid]!;
      if (addr < g.vmaddr) hi = mid - 1;
      else if (addr >= g.vmaddr + g.vmsize) lo = mid + 1;
      else { const d = addr - g.vmaddr; return d < g.filesize ? g.fileoff + d : -1; }
    }
    return -1;
  }
  /** Virtual address for a file offset, or -1. */
  toAddr(off: number): number {
    for (const g of this.segIdx) if (off >= g.fileoff && off < g.fileoff + g.filesize) return g.vmaddr + (off - g.fileoff);
    return -1;
  }
  section(seg: string | undefined, name: string): MSection | undefined {
    return this.sections.find((s) => s.name === name && (seg === undefined || s.seg === seg));
  }
  sectionsNamed(name: string): MSection[] { return this.sections.filter((s) => s.name === name); }
  sectionOf(addr: number): MSection | undefined { return this.sections.find((s) => addr >= s.addr && addr < s.addr + s.size); }
  readU32(addr: number): number { const o = this.toOffset(addr); if (o < 0) throw new ParseError(`address 0x${addr.toString(16)} not in file`); return this.u32(o); }
  readI32(addr: number): number { const o = this.toOffset(addr); if (o < 0) throw new ParseError(`address 0x${addr.toString(16)} not in file`); return this.i32(o); }
  readU16(addr: number): number { const o = this.toOffset(addr); if (o < 0) throw new ParseError(`address 0x${addr.toString(16)} not in file`); return this.u16(o); }
  readU8(addr: number): number { const o = this.toOffset(addr); if (o < 0) throw new ParseError(`address 0x${addr.toString(16)} not in file`); return this.u8(o); }
  readCString(addr: number, max = 4096): string { const o = this.toOffset(addr); if (o < 0) throw new ParseError(`address 0x${addr.toString(16)} not in file`); return this.cstrAt(o, max); }

  /** Pointer at addr with fixups applied: a target address, a bound symbol, or null for 0. */
  readPointer(addr: number): { addr?: number; bind?: string; addend?: number; auth?: Fixup['auth']; raw: number } {
    const fx = this.fixups.get(addr);
    const o = this.toOffset(addr);
    if (o < 0) throw new ParseError(`pointer at 0x${addr.toString(16)} not in file`);
    if (fx) {
      if (fx.kind === 'rebase') return { addr: fx.target, auth: fx.auth, raw: fx.target };
      return { bind: fx.name, addend: fx.addend, auth: fx.auth, raw: 0 };
    }
    const raw = this.ptrSize === 8 ? this.u64n(o) : this.u32(o);
    return { addr: raw === 0 ? undefined : this.strip(raw), raw };
  }
  /** Pointer value as an address (binds and nulls give undefined). */
  ptr(addr: number): number | undefined { return this.readPointer(addr).addr; }

  /** Remove pointer authentication and tag bits from a raw arm64e pointer (no fixup info). */
  strip(v: number): number {
    if (this.ptrSize === 4) return v >>> 0;
    if (v < 2 ** 47) return v;
    // arm64e signed pointer or a top byte tag: keep the low 47 bits, then rebase when it looks like an offset
    const low = v % 2 ** 47;
    if (this.toOffset(low) >= 0) return low;
    const asOff = this.imageBase + (v % 2 ** 32);
    if (this.toOffset(asOff) >= 0) return asOff;
    return low;
  }

  /** Symbol name at an address (defined symbols only). */
  symbolAt(addr: number): string | undefined { return this.symbols.get(addr); }

  // ---------- load commands ----------
  private loadCommands(): void {
    const ncmds = Math.min(this.u32(16), 8192);
    let p = this.is64 ? 32 : 28;
    for (let i = 0; i < ncmds; i++) {
      if (!this.has(p, 8)) { this.notes.push('load commands truncated'); break; }
      const cmd = this.u32(p) >>> 0, size = this.u32(p + 4);
      if (size < 8 || !this.has(p, size)) { this.notes.push(`bad load command size at 0x${p.toString(16)}`); break; }
      if (cmd === 0x19 || cmd === 0x1) this.segment(p, cmd === 0x19, size);
      else if (cmd === 0x2) this.symtab = { symoff: this.u32(p + 8), nsyms: this.u32(p + 12), stroff: this.u32(p + 16), strsize: this.u32(p + 20) };
      else if (cmd === 0x80000034) { this.chainedOff = this.u32(p + 8); this.chainedSize = this.u32(p + 12); }
      else if (cmd === 0x22 || cmd === 0x80000022) {
        this.dyldInfo = { bindOff: this.u32(p + 16), bindSize: this.u32(p + 20), weakOff: this.u32(p + 24), weakSize: this.u32(p + 28), lazyOff: this.u32(p + 32), lazySize: this.u32(p + 36) };
      } else if (cmd === 0xc || cmd === 0x80000018 || cmd === 0x8000001f || cmd === 0x80000023) {
        const so = this.u32(p + 8);
        this.dylibs.push(so < size ? this.cstrAt(p + so, size - so) : '');
      }
      p += size;
    }
    this.segIdx = this.segments.filter((s) => s.vmsize > 0).sort((a, b) => a.vmaddr - b.vmaddr);
    const text = this.segments.find((s) => s.fileoff === 0 && s.filesize > 0) ?? this.segments.find((s) => s.name === '__TEXT');
    this.imageBase = text?.vmaddr ?? 0;
  }

  private segment(p: number, is64: boolean, size: number): void {
    const name = this.cstrAt(p + 8, 16);
    const vmaddr = is64 ? this.u64n(p + 24) : this.u32(p + 24);
    const vmsize = is64 ? this.u64n(p + 32) : this.u32(p + 28);
    const fileoff = is64 ? this.u64n(p + 40) : this.u32(p + 32);
    let filesize = is64 ? this.u64n(p + 48) : this.u32(p + 36);
    if (fileoff > this.bytes.length) filesize = 0;
    else if (fileoff + filesize > this.bytes.length) { filesize = this.bytes.length - fileoff; this.notes.push(`segment ${name} truncated`); }
    this.segments.push({ name, vmaddr, vmsize, fileoff, filesize });
    const nsects = Math.min(this.u32(p + (is64 ? 64 : 48)), Math.floor((size - (is64 ? 72 : 56)) / (is64 ? 80 : 68)), 1024);
    let s = p + (is64 ? 72 : 56);
    for (let k = 0; k < nsects; k++) {
      const sname = this.cstrAt(s, 16), seg = this.cstrAt(s + 16, 16);
      const addr = is64 ? this.u64n(s + 32) : this.u32(s + 32);
      const ssize = is64 ? this.u64n(s + 40) : this.u32(s + 36);
      const offset = this.u32(s + (is64 ? 48 : 40));
      const flags = this.u32(s + (is64 ? 64 : 56));
      this.sections.push({ seg, name: sname, addr, size: ssize, offset, flags });
      s += is64 ? 80 : 68;
    }
  }

  private loadSymbols(max: number): void {
    const st = this.symtab;
    if (!st) return;
    const ent = this.is64 ? 16 : 12;
    const n = Math.min(st.nsyms, max, Math.floor(Math.max(0, this.bytes.length - st.symoff) / ent));
    if (n < st.nsyms) this.notes.push(`symbol table capped at ${n} of ${st.nsyms}`);
    for (let i = 0; i < n; i++) {
      const o = st.symoff + i * ent;
      const strx = this.u32(o), type = this.u8(o + 4);
      if (type & 0xe0) continue; // stabs
      if ((type & 0x0e) !== 0x0e) continue; // N_SECT only
      const value = this.is64 ? this.u64n(o + 8) : this.u32(o + 8);
      if (strx >= st.strsize || st.stroff + strx >= this.bytes.length) continue;
      const name = this.cstrAt(st.stroff + strx, 2048);
      if (!name) continue;
      const cur = this.symbols.get(value);
      if (!cur || (cur.startsWith('l') && !name.startsWith('l'))) this.symbols.set(value, name);
    }
  }

  private loadChained(maxFixups: number): void {
    const h = this.chainedOff;
    if (!this.has(h, 28)) { this.notes.push('chained fixups header out of range'); return; }
    this.fixupSource = 'chained';
    const startsOff = h + this.u32(h + 4), importsOff = h + this.u32(h + 8), symbolsOff = h + this.u32(h + 12);
    const importsCount = this.u32(h + 16), importsFormat = this.u32(h + 20);
    const end = h + this.chainedSize;
    const importName = (ord: number): { name: string; lib: number; addend: number } => {
      if (ord >= importsCount) return { name: `<import ${ord}>`, lib: 0, addend: 0 };
      let nameOff = 0, lib = 0, addend = 0;
      if (importsFormat === 1) { const v = this.u32(importsOff + ord * 4); lib = v & 0xff; nameOff = v >>> 9; }
      else if (importsFormat === 2) { const v = this.u32(importsOff + ord * 8); lib = v & 0xff; nameOff = v >>> 9; addend = this.i32(importsOff + ord * 8 + 4); }
      else if (importsFormat === 3) { const [hi, lo] = this.u64parts(importsOff + ord * 16); lib = lo & 0xffff; nameOff = hi; addend = this.u64n(importsOff + ord * 16 + 8); }
      else return { name: `<import ${ord}>`, lib: 0, addend: 0 };
      const so = symbolsOff + nameOff;
      return { name: so < end && so < this.bytes.length ? this.cstrAt(so, 1024) : `<import ${ord}>`, lib: lib > 0x7f ? lib - 0x100 : lib, addend };
    };
    const segCount = Math.min(this.u32(startsOff), 64);
    let count = 0;
    for (let si = 0; si < segCount; si++) {
      const so = this.u32(startsOff + 4 + si * 4);
      if (so === 0) continue;
      const s = startsOff + so;
      if (!this.has(s, 22)) { this.notes.push('chained starts out of range'); continue; }
      const pageSize = this.u16(s + 4), fmt = this.u16(s + 6);
      const segOffset = this.u64n(s + 8);
      const pageCount = Math.min(this.u16(s + 20), 65535);
      this.pointerFormat ??= POINTER_FORMATS[fmt] ?? `format ${fmt}`;
      const seg = this.segments[si];
      if (!seg) continue;
      const stride = fmt === 1 || fmt === 9 || fmt === 12 ? 8 : 4;
      for (let pi = 0; pi < pageCount; pi++) {
        let start = this.u16(s + 22 + pi * 2);
        if (start === 0xffff) continue;
        if (start & 0x8000) { this.notes.push('multi start pages (32 bit) not followed'); continue; }
        let off = segOffset + pi * pageSize + start; // offset from the start of the image in VM terms
        for (let guard = 0; guard < 65536; guard++) {
          const vm = this.imageBase + off;
          const fo = this.toOffset(vm);
          if (fo < 0 || !this.has(fo, fmt === 3 || fmt === 4 || fmt === 5 ? 4 : 8)) break;
          if (++count > maxFixups) { this.notes.push(`fixups capped at ${maxFixups}`); return; }
          let next = 0;
          if (fmt === 3 || fmt === 4 || fmt === 5) {
            const v = this.u32(fo);
            const bind = v >>> 31;
            next = (v >>> 26) & 0x1f;
            if (bind) { const im = importName(v & 0xfffff); this.fixups.set(vm, { kind: 'bind', name: im.name, lib: im.lib, addend: ((v >>> 20) & 0x3f) + im.addend }); }
            else this.fixups.set(vm, { kind: 'rebase', target: v & 0x3ffffff });
            start = 0;
          } else {
            const [hi, lo] = this.u64parts(fo);
            if (fmt === 2 || fmt === 6) {
              const bind = hi >>> 31;
              next = (hi >>> 19) & 0xfff;
              if (bind) {
                const ord = lo & 0xffffff, add = (lo >>> 24) & 0xff;
                const im = importName(ord);
                this.fixups.set(vm, { kind: 'bind', name: im.name, lib: im.lib, addend: add + im.addend });
              } else {
                const target = (hi & 0xf) * 0x100000000 + lo; // 36 bits
                const high8 = (hi >>> 4) & 0xff;
                const t = fmt === 6 ? this.imageBase + target : target;
                this.fixups.set(vm, { kind: 'rebase', target: high8 ? t + high8 * 2 ** 56 : t });
              }
            } else if (fmt === 1 || fmt === 9 || fmt === 12 || fmt === 7 || fmt === 10) {
              const auth = hi >>> 31, bind = (hi >>> 30) & 1;
              next = (hi >>> 19) & 0x7ff;
              const authInfo = auth ? { diversity: hi & 0xffff, addrDiv: ((hi >>> 16) & 1) === 1, key: KEYS[(hi >>> 17) & 3]! } : undefined;
              if (bind) {
                const ord = fmt === 12 ? lo & 0xffffff : lo & 0xffff;
                const im = importName(ord);
                let addend = 0;
                if (!auth) { addend = hi & 0x7ffff; if (addend & 0x40000) addend -= 0x80000; }
                this.fixups.set(vm, { kind: 'bind', name: im.name, lib: im.lib, addend: addend + im.addend, auth: authInfo });
              } else if (auth) {
                this.fixups.set(vm, { kind: 'rebase', target: this.imageBase + lo, auth: authInfo });
              } else {
                const target = (hi & 0x7ff) * 0x100000000 + lo; // 43 bits
                const high8 = (hi >>> 11) & 0xff;
                const t = fmt === 1 ? target : this.imageBase + target;
                this.fixups.set(vm, { kind: 'rebase', target: high8 ? t + high8 * 2 ** 56 : t });
              }
            } else if (fmt === 8 || fmt === 11) {
              next = (hi >>> 19) & 0xfff;
              this.fixups.set(vm, { kind: 'rebase', target: this.imageBase + (lo & 0x3fffffff) });
            } else { this.notes.push(`unknown chained pointer format ${fmt}`); break; }
          }
          if (next === 0) break;
          off += next * stride;
        }
      }
    }
  }

  private loadDyldInfo(maxFixups: number): void {
    const d = this.dyldInfo!;
    this.fixupSource = 'dyld-info';
    this.runBind(d.bindOff, d.bindSize, maxFixups, false);
    this.runBind(d.weakOff, d.weakSize, maxFixups, true);
  }

  /** Interpret dyld bind opcodes (non lazy and weak binds), recording a bind fixup per pointer. */
  private runBind(off: number, size: number, maxFixups: number, weak: boolean): void {
    if (!size || !this.has(off, Math.min(size, this.bytes.length - off))) return;
    const end = Math.min(this.bytes.length, off + size);
    let p = off, seg = 0, segOff = 0, name = '', addend = 0, lib = 0, steps = 0;
    const uleb = (): number => { let r = 0, s = 1, b = 0; do { if (p >= end) throw new ParseError('bind opcodes truncated', p); b = this.bytes[p++]!; r += (b & 0x7f) * s; s *= 128; } while (b & 0x80 && s < 2 ** 63); return r; };
    const sleb = (): number => { let r = 0, s = 1, b = 0; do { if (p >= end) throw new ParseError('bind opcodes truncated', p); b = this.bytes[p++]!; r += (b & 0x7f) * s; s *= 128; } while (b & 0x80 && s < 2 ** 63); if (b & 0x40) r -= s; return r; };
    const bindAt = () => {
      const sg = this.segments[seg];
      if (sg && this.fixups.size < maxFixups) this.fixups.set(sg.vmaddr + segOff, { kind: 'bind', name, addend, lib });
    };
    try {
      while (p < end && steps++ < 2_000_000) {
        const b = this.bytes[p++]!, op = b & 0xf0, imm = b & 0x0f;
        switch (op) {
          case 0x00: if (!weak) return; break;
          case 0x10: lib = imm; break;
          case 0x20: lib = uleb(); break;
          case 0x30: lib = imm ? (imm | 0xf0) - 0x100 : 0; break;
          case 0x40: { const s0 = p; while (p < end && this.bytes[p] !== 0) p++; name = new TextDecoder().decode(this.bytes.subarray(s0, p)); p++; break; }
          case 0x50: break;
          case 0x60: addend = sleb(); break;
          case 0x70: seg = imm; segOff = uleb(); break;
          case 0x80: segOff += uleb(); break;
          case 0x90: bindAt(); segOff += this.ptrSize; break;
          case 0xa0: bindAt(); segOff += uleb() + this.ptrSize; break;
          case 0xb0: bindAt(); segOff += imm * this.ptrSize + this.ptrSize; break;
          case 0xc0: { const n = Math.min(uleb(), 1_000_000), skip = uleb(); for (let i = 0; i < n; i++) { bindAt(); segOff += skip + this.ptrSize; } break; }
          default: this.notes.push(`unknown bind opcode 0x${b.toString(16)}`); return;
        }
      }
    } catch (e) { this.notes.push((e as Error).message); }
  }
}
