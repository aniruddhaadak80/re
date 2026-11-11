// Exported symbol names of native libraries shipped next to .NET assemblies: ELF .dynsym,
// PE export directory (with forwarders and ordinals) and Mach-O export trie or symbol table.
// Small, bounded readers; only what P/Invoke matching needs.

import { ParseError } from '../util.js';

export interface NativeExport { name: string; address?: string; ordinal?: number; forwarder?: string }
export interface NativeLibrary { format: 'elf' | 'pe' | 'macho'; arch?: string; exports: NativeExport[]; soname?: string; truncated: boolean }

const MAX_EXPORTS = 200_000;

class R {
  readonly dv: DataView;
  constructor(readonly b: Uint8Array, public le = true) { this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength); }
  ok(o: number, n: number): boolean { return o >= 0 && n >= 0 && o + n <= this.b.length; }
  need(o: number, n: number): void { if (!this.ok(o, n)) throw new ParseError(`read out of range at 0x${o.toString(16)}`); }
  u8(o: number): number { this.need(o, 1); return this.b[o]!; }
  u16(o: number): number { this.need(o, 2); return this.dv.getUint16(o, this.le); }
  u32(o: number): number { this.need(o, 4); return this.dv.getUint32(o, this.le); }
  u64(o: number): number { this.need(o, 8); return Number(this.dv.getBigUint64(o, this.le)); }
  cstr(o: number, max = 1024): string { let s = ''; for (let i = o; i < this.b.length && i < o + max; i++) { const c = this.b[i]!; if (c === 0) return s; s += String.fromCharCode(c); } return s; }
}
const hex = (n: number): string => `0x${n.toString(16)}`;

function elfExports(b: Uint8Array): NativeLibrary {
  const is64 = b[4] === 2;
  const r = new R(b, b[5] !== 2);
  const word = (o: number): number => (is64 ? r.u64(o) : r.u32(o));
  const shoff = word(is64 ? 0x28 : 0x20), shentsize = r.u16(is64 ? 0x3a : 0x2e), shnum = r.u16(is64 ? 0x3c : 0x30);
  const mach: Record<number, string> = { 3: 'x86', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv' };
  const out: NativeLibrary = { format: 'elf', arch: mach[r.u16(18)], exports: [], truncated: false };
  if (shnum > 10000) throw new ParseError('too many ELF sections');
  const sec = (i: number) => { const o = shoff + i * shentsize; return is64 ? { type: r.u32(o + 4), offset: r.u64(o + 24), size: r.u64(o + 32), link: r.u32(o + 40), entsize: r.u64(o + 56) } : { type: r.u32(o + 4), offset: r.u32(o + 16), size: r.u32(o + 20), link: r.u32(o + 24), entsize: r.u32(o + 36) }; };
  for (let i = 0; i < shnum; i++) {
    const s = sec(i);
    if (s.type === 6) { // dynamic: DT_SONAME
      const str = sec(s.link);
      for (let o = s.offset; o + (is64 ? 16 : 8) <= s.offset + s.size && r.ok(o, is64 ? 16 : 8); o += is64 ? 16 : 8) { const tag = word(o); if (tag === 0) break; if (tag === 14) out.soname = r.cstr(str.offset + word(o + (is64 ? 8 : 4))); }
    }
    if (s.type !== 11) continue;
    const str = sec(s.link);
    const ent = s.entsize || (is64 ? 24 : 16);
    for (let k = 1; k < Math.floor(s.size / ent); k++) {
      const o = s.offset + k * ent;
      if (!r.ok(o, ent)) break;
      const info = is64 ? r.u8(o + 4) : r.u8(o + 12);
      const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
      const bind = info >> 4, type = info & 0xf;
      if (!shndx || (bind !== 1 && bind !== 2) || (type !== 2 && type !== 1 && type !== 10)) continue;
      const nameOff = r.u32(o);
      if (nameOff >= str.size) continue;
      const name = r.cstr(str.offset + nameOff);
      if (!name) continue;
      if (out.exports.length >= MAX_EXPORTS) { out.truncated = true; break; }
      out.exports.push({ name, address: hex(is64 ? r.u64(o + 8) : r.u32(o + 4)) });
    }
  }
  return out;
}

function peExports(b: Uint8Array): NativeLibrary {
  const r = new R(b);
  const pe = r.u32(0x3c);
  if (r.u32(pe) !== 0x4550) throw new ParseError('bad PE signature');
  const machine = r.u16(pe + 4), nsec = r.u16(pe + 6), optSize = r.u16(pe + 20);
  const opt = pe + 24;
  const is64 = r.u16(opt) === 0x20b;
  const dd = opt + (is64 ? 112 : 96);
  const numDirs = r.u32(opt + (is64 ? 108 : 92));
  const archs: Record<number, string> = { 0x14c: 'x86', 0x8664: 'x86_64', 0xaa64: 'arm64', 0x1c4: 'arm' };
  const out: NativeLibrary = { format: 'pe', arch: archs[machine], exports: [], truncated: false };
  if (numDirs < 1) return out;
  const expRva = r.u32(dd), expSize = r.u32(dd + 4);
  if (!expRva) return out;
  const secs: { va: number; vs: number; raw: number; rs: number }[] = [];
  const st = opt + optSize;
  for (let i = 0; i < Math.min(nsec, 96); i++) { const o = st + i * 40; secs.push({ vs: r.u32(o + 8), va: r.u32(o + 12), rs: r.u32(o + 16), raw: r.u32(o + 20) }); }
  const off = (rva: number): number => { for (const s of secs) if (rva >= s.va && rva < s.va + Math.max(s.vs, s.rs)) return rva - s.va + s.raw; throw new ParseError(`RVA 0x${rva.toString(16)} not in a section`); };
  const e = off(expRva);
  const base = r.u32(e + 16), nFuncs = r.u32(e + 20), nNames = r.u32(e + 24);
  const funcs = off(r.u32(e + 28)), names = nNames ? off(r.u32(e + 32)) : 0, ords = nNames ? off(r.u32(e + 36)) : 0;
  if (nFuncs > MAX_EXPORTS || nNames > MAX_EXPORTS) out.truncated = true;
  const named = new Set<number>();
  for (let i = 0; i < Math.min(nNames, MAX_EXPORTS); i++) {
    const idx = r.u16(ords + i * 2);
    const name = r.cstr(off(r.u32(names + i * 4)));
    const rva = idx < nFuncs ? r.u32(funcs + idx * 4) : 0;
    named.add(idx);
    const x: NativeExport = { name, ordinal: base + idx, address: hex(rva) };
    if (rva >= expRva && rva < expRva + expSize) x.forwarder = r.cstr(off(rva));
    out.exports.push(x);
  }
  for (let i = 0; i < Math.min(nFuncs, MAX_EXPORTS); i++) if (!named.has(i)) { const rva = r.u32(funcs + i * 4); if (rva) out.exports.push({ name: `#${base + i}`, ordinal: base + i, address: hex(rva) }); }
  return out;
}

function machoExports(b: Uint8Array): NativeLibrary {
  const r = new R(b);
  let off = 0;
  const m0 = r.u32(0);
  if (m0 === 0xbebafeca || m0 === 0xcafebabe) { // fat: first slice
    const be = new R(b, false);
    off = be.u32(8 + 8);
  }
  const mr = new R(b);
  const magic = mr.u32(off);
  if (magic !== 0xfeedfacf && magic !== 0xfeedface) throw new ParseError('not a little endian Mach-O');
  const is64 = magic === 0xfeedfacf;
  const cpu = mr.u32(off + 4);
  const arch = ({ 0x0100000c: 'arm64', 0x01000007: 'x86_64', 7: 'x86', 12: 'arm' } as Record<number, string>)[cpu];
  const ncmds = mr.u32(off + 16);
  const out: NativeLibrary = { format: 'macho', arch, exports: [], truncated: false };
  let p = off + (is64 ? 32 : 28);
  let trie: [number, number] | undefined, symtab: [number, number, number, number] | undefined;
  for (let i = 0; i < Math.min(ncmds, 4096); i++) {
    const cmd = mr.u32(p), size = mr.u32(p + 4);
    if (size < 8) break;
    if ((cmd === 0x22 || cmd === 0x80000022) && mr.u32(p + 44)) trie = [mr.u32(p + 40), mr.u32(p + 44)];
    if (cmd === 0x80000033) trie = [mr.u32(p + 8), mr.u32(p + 12)];
    if (cmd === 0xd) out.soname = mr.cstr(p + mr.u32(p + 8));
    if (cmd === 0x2) symtab = [mr.u32(p + 8), mr.u32(p + 12), mr.u32(p + 16), mr.u32(p + 20)];
    p += size;
  }
  if (trie) {
    const [to, ts] = trie;
    const start = off + to, end = Math.min(b.length, start + ts);
    const uleb = (q: { p: number }): number => { let v = 0, mul = 1; for (let i = 0; i < 10; i++) { if (q.p >= end) throw new ParseError('truncated uleb'); const c = b[q.p++]!; v += (c & 0x7f) * mul; mul *= 128; if (!(c & 0x80)) return v; } throw new ParseError('uleb too long'); };
    const stack: [number, string, number][] = [[start, '', 0]];
    const seen = new Set<number>();
    while (stack.length) {
      const [node, prefix, depth] = stack.pop()!;
      if (seen.has(node) || depth > 128 || node >= end) continue;
      seen.add(node);
      const q = { p: node };
      const tsz = uleb(q);
      if (tsz) {
        const q2 = { p: q.p };
        const flags = uleb(q2);
        const x: NativeExport = { name: prefix.startsWith('_') ? prefix.slice(1) : prefix };
        if (flags & 8) { uleb(q2); x.forwarder = mr.cstr(q2.p); } else x.address = hex(uleb(q2));
        if (out.exports.length >= MAX_EXPORTS) { out.truncated = true; break; }
        out.exports.push(x);
      }
      q.p += tsz;
      const kids = q.p < end ? b[q.p++]! : 0;
      for (let k = 0; k < kids; k++) {
        let s = '';
        while (q.p < end && b[q.p] !== 0 && s.length < 4096) s += String.fromCharCode(b[q.p++]!);
        q.p++;
        stack.push([start + uleb(q), prefix + s, depth + 1]);
      }
    }
    out.exports.sort((a, c) => (a.name < c.name ? -1 : a.name > c.name ? 1 : 0));
  } else if (symtab) {
    const [so, ns, stro] = symtab;
    const ent = is64 ? 16 : 12;
    for (let i = 0; i < Math.min(ns, MAX_EXPORTS); i++) {
      const o = off + so + i * ent;
      if (!mr.ok(o, ent)) break;
      const type = mr.u8(o + 4);
      if (type & 0xe0 || (type & 0x0e) !== 0x0e || !(type & 1)) continue; // external, defined in a section
      const name = mr.cstr(off + stro + mr.u32(o));
      out.exports.push({ name: name.startsWith('_') ? name.slice(1) : name, address: hex(is64 ? mr.u64(o + 8) : mr.u32(o + 8)) });
    }
  }
  return out;
}

/** Read the exported symbols of an ELF, PE or Mach-O library. Mach-O leading underscores are dropped. */
export function nativeExports(b: Uint8Array): NativeLibrary {
  if (b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return elfExports(b);
  if (b.length >= 64 && b[0] === 0x4d && b[1] === 0x5a) return peExports(b);
  if (b.length >= 32) { const m = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, true); if (m === 0xfeedfacf || m === 0xfeedface || m === 0xbebafeca) return machoExports(b); }
  throw new ParseError('not an ELF, PE or Mach-O library');
}

/** Library names the runtime probes for a DllImport name, by platform (NativeLibrary probing rules). */
export function probingNames(dll: string): string[] {
  const base = dll.replace(/\.(dll|so|dylib)$/i, '');
  const names = new Set([dll, `${base}.dll`, `${base}.so`, `lib${base}.so`, `${base}.dylib`, `lib${base}.dylib`]);
  if (base.startsWith('lib')) { names.add(`${base.slice(3)}.dll`); }
  return [...names];
}
