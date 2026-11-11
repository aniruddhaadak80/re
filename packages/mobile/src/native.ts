// Native libraries inside APKs: ELF dynamic symbols, needed libraries, JNI entry points.
// A deliberately small ELF reader; @revlens/core has the full ELF analyzer.

import { Buf, ParseError, utf8 } from './bytes.js';

export interface ElfSymbol { name: string; value: string; size: number; type: string; bind: string; defined: boolean }

export interface ElfSummary {
  bits: 32 | 64;
  endian: 'le' | 'be';
  machine: string;
  type: string;
  soname?: string;
  needed: string[];
  exports: ElfSymbol[];
  imports: string[];
  jniOnLoad: boolean;
  jniExports: string[];
  /** JNI_OnLoad, JNI_OnUnload, ANativeActivity_onCreate and other loader entry points that are exported */
  entryPoints: string[];
  /** RegisterNatives-style libraries usually export only JNI_OnLoad */
  registersNativesDynamically: boolean;
  buildId?: string;
}

const MACHINES: Record<number, string> = { 3: 'x86', 8: 'mips', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv' };
const STT = ['NOTYPE', 'OBJECT', 'FUNC', 'SECTION', 'FILE', 'COMMON', 'TLS'];
const STB = ['LOCAL', 'GLOBAL', 'WEAK'];

const ENTRY_POINTS = new Set(['JNI_OnLoad', 'JNI_OnUnload', 'ANativeActivity_onCreate', 'android_main', 'GameActivity_onCreate', 'Java_com_unity3d_player_UnityPlayer_initJni']);

export const ELF_LIMITS = { maxSymbols: 500_000, maxSections: 10_000 };

export function isElf(b: Uint8Array): boolean {
  return b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
}

export function parseElfDynamic(bytes: Uint8Array): ElfSummary {
  if (!isElf(bytes)) throw new ParseError('not an ELF file');
  const cls = bytes[4];
  const data = bytes[5];
  if ((cls !== 1 && cls !== 2) || (data !== 1 && data !== 2)) throw new ParseError('bad ELF class or data encoding');
  const is64 = cls === 2;
  const r = new Buf(bytes, data === 1);
  const word = (o: number): number => (is64 ? Number(r.u64(o)) : r.u32(o));
  const type = r.u16(16);
  const machine = r.u16(18);
  const shoff = is64 ? Number(r.u64(0x28)) : r.u32(0x20);
  const shentsize = r.u16(is64 ? 0x3a : 0x2e);
  const shnum = r.u16(is64 ? 0x3c : 0x30);
  if (shnum > ELF_LIMITS.maxSections) throw new ParseError('too many ELF sections');
  const sections: { type: number; offset: number; size: number; link: number; entsize: number; name: number }[] = [];
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize;
    if (!r.has(o, is64 ? 64 : 40)) break;
    sections.push(is64
      ? { name: r.u32(o), type: r.u32(o + 4), offset: Number(r.u64(o + 24)), size: Number(r.u64(o + 32)), link: r.u32(o + 40), entsize: Number(r.u64(o + 56)) }
      : { name: r.u32(o), type: r.u32(o + 4), offset: r.u32(o + 16), size: r.u32(o + 20), link: r.u32(o + 24), entsize: r.u32(o + 36) });
  }
  const out: ElfSummary = {
    bits: is64 ? 64 : 32, endian: data === 1 ? 'le' : 'be', machine: MACHINES[machine] ?? `machine${machine}`,
    type: ({ 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE' } as Record<number, string>)[type] ?? String(type),
    needed: [], exports: [], imports: [], jniOnLoad: false, jniExports: [], entryPoints: [], registersNativesDynamically: false,
  };
  const strAt = (secIdx: number, off: number): string => {
    const s = sections[secIdx];
    if (!s || off >= s.size) return '';
    return r.cstr(s.offset + off, Math.min(4096, s.size - off));
  };
  const dynsymIdx = sections.findIndex((s) => s.type === 11);
  if (dynsymIdx >= 0) {
    const ds = sections[dynsymIdx] as (typeof sections)[number];
    const ent = ds.entsize || (is64 ? 24 : 16);
    const n = Math.min(Math.floor(ds.size / ent), ELF_LIMITS.maxSymbols);
    for (let i = 1; i < n; i++) {
      const o = ds.offset + i * ent;
      if (!r.has(o, ent)) break;
      const nameOff = r.u32(o);
      let info: number, shndx: number, value: number, size: number;
      if (is64) { info = r.u8(o + 4); shndx = r.u16(o + 6); value = Number(r.u64(o + 8)); size = Number(r.u64(o + 16)); }
      else { value = r.u32(o + 4); size = r.u32(o + 8); info = r.u8(o + 12); shndx = r.u16(o + 14); }
      const name = strAt(ds.link, nameOff);
      if (!name) continue;
      const bind = STB[info >> 4] ?? String(info >> 4);
      const t = STT[info & 0xf] ?? String(info & 0xf);
      const defined = shndx !== 0;
      if (!defined) { if (out.imports.length < 20_000) out.imports.push(name); continue; }
      if (bind === 'LOCAL') continue;
      out.exports.push({ name, value: `0x${value.toString(16)}`, size, type: t, bind, defined });
      if (name === 'JNI_OnLoad') out.jniOnLoad = true;
      if (name.startsWith('Java_')) out.jniExports.push(name);
      if (ENTRY_POINTS.has(name)) out.entryPoints.push(name);
    }
  }
  const dynIdx = sections.findIndex((s) => s.type === 6);
  if (dynIdx >= 0) {
    const d = sections[dynIdx] as (typeof sections)[number];
    const ent = is64 ? 16 : 8;
    for (let i = 0; i < Math.min(d.size / ent, 4096); i++) {
      const o = d.offset + i * ent;
      if (!r.has(o, ent)) break;
      const tag = word(o);
      const val = word(o + (is64 ? 8 : 4));
      if (tag === 0) break;
      if (tag === 1) out.needed.push(strAt(d.link, val));
      if (tag === 14) out.soname = strAt(d.link, val);
    }
  }
  // GNU build id note
  for (const s of sections) {
    if (s.type !== 7 || !r.has(s.offset, 16)) continue;
    const namesz = r.u32(s.offset), descsz = r.u32(s.offset + 4), ntype = r.u32(s.offset + 8);
    if (ntype === 3 && namesz === 4 && descsz <= 64 && utf8(r.slice(s.offset + 12, 3)) === 'GNU') {
      const d = r.slice(s.offset + 16, descsz);
      out.buildId = [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
      break;
    }
  }
  out.registersNativesDynamically = out.jniOnLoad && out.jniExports.length === 0;
  return out;
}

/** ABI directory names used under lib/ in APKs. */
export const ABIS = ['arm64-v8a', 'armeabi-v7a', 'armeabi', 'x86', 'x86_64', 'mips', 'mips64', 'riscv64'];
