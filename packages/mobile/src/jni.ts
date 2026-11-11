// JNI binding map: DEX native methods matched to Java_* exports (short and long mangled names),
// to JNINativeMethod tables recovered from shared libraries (what RegisterNatives receives), and
// to string hints (class paths and JNI signatures in .rodata) when no table can be rebuilt.

import { Buf, ParseError } from './bytes.js';
import { isElf } from './native.js';
import type { NativeMethod } from './dex/analysis.js';

export interface ElfSection { name: string; type: number; flags: number; addr: number; offset: number; size: number; link: number; entsize: number }
interface Loaded {
  bits: 32 | 64; little: boolean; machine: number; r: Buf; sections: ElfSection[];
  segments: { vaddr: number; offset: number; filesz: number; memsz: number; flags: number }[];
  relocs: Map<number, number>; symbols: Map<number, string>; exports: Map<string, number>;
}

export const JNI_LIMITS = { maxRelocs: 2_000_000, maxSymbols: 500_000, maxTableEntries: 20_000, maxHints: 5000 };

// RELATIVE relocation types per e_machine
const RELATIVE: Record<number, number> = { 183: 1027, 62: 8, 40: 23, 3: 8, 243: 3, 8: 3 };
// absolute pointer relocations that carry a symbol: AArch64 ABS64/GLOB_DAT, x86-64 64/GLOB_DAT, ARM ABS32/GLOB_DAT, i386 32/GLOB_DAT
const ABS: Record<number, number[]> = { 183: [257, 1025], 62: [1, 6], 40: [2, 21], 3: [1, 6], 243: [2] };

function loadElf(bytes: Uint8Array): Loaded {
  if (!isElf(bytes)) throw new ParseError('not an ELF file');
  const is64 = bytes[4] === 2, little = bytes[5] === 1;
  if ((bytes[4] !== 1 && bytes[4] !== 2) || (bytes[5] !== 1 && bytes[5] !== 2)) throw new ParseError('bad ELF class or data encoding');
  const r = new Buf(bytes, little);
  const word = (o: number): number => (is64 ? Number(r.u64(o)) : r.u32(o));
  const machine = r.u16(18);
  const phoff = word(is64 ? 0x20 : 0x1c), shoff = word(is64 ? 0x28 : 0x20);
  const phentsize = r.u16(is64 ? 0x36 : 0x2a), phnum = r.u16(is64 ? 0x38 : 0x2c);
  const shentsize = r.u16(is64 ? 0x3a : 0x2e), shnum = r.u16(is64 ? 0x3c : 0x30), shstrndx = r.u16(is64 ? 0x3e : 0x32);
  if (shnum > 10000 || phnum > 10000) throw new ParseError('too many ELF headers');
  const segments: Loaded['segments'] = [];
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (!r.has(o, is64 ? 56 : 32)) break;
    if (r.u32(o) !== 1) continue;
    segments.push(is64
      ? { flags: r.u32(o + 4), offset: Number(r.u64(o + 8)), vaddr: Number(r.u64(o + 16)), filesz: Number(r.u64(o + 32)), memsz: Number(r.u64(o + 40)) }
      : { offset: r.u32(o + 4), vaddr: r.u32(o + 8), filesz: r.u32(o + 16), memsz: r.u32(o + 20), flags: r.u32(o + 24) });
  }
  const raw: Omit<ElfSection, 'name'>[] & { nameOff?: number }[] = [];
  const names: number[] = [];
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize;
    if (!r.has(o, is64 ? 64 : 40)) break;
    names.push(r.u32(o));
    raw.push(is64
      ? { type: r.u32(o + 4), flags: Number(r.u64(o + 8)), addr: Number(r.u64(o + 16)), offset: Number(r.u64(o + 24)), size: Number(r.u64(o + 32)), link: r.u32(o + 40), entsize: Number(r.u64(o + 56)) }
      : { type: r.u32(o + 4), flags: r.u32(o + 8), addr: r.u32(o + 12), offset: r.u32(o + 16), size: r.u32(o + 20), link: r.u32(o + 24), entsize: r.u32(o + 36) });
  }
  const shstr = raw[shstrndx];
  const sections: ElfSection[] = raw.map((s, i) => ({ ...s, name: shstr && names[i]! < shstr.size && r.has(shstr.offset + names[i]!, 1) ? r.cstr(shstr.offset + names[i]!, 256) : '' }));
  const L: Loaded = { bits: is64 ? 64 : 32, little, machine, r, sections, segments, relocs: new Map(), symbols: new Map(), exports: new Map() };
  // symbols: dynsym then symtab
  const symVals: number[][] = [];
  sections.forEach((s, idx) => {
    if (s.type !== 11 && s.type !== 2) { symVals[idx] = []; return; }
    const ent = s.entsize || (is64 ? 24 : 16);
    const n = Math.min(Math.floor(s.size / ent), JNI_LIMITS.maxSymbols);
    const strs = sections[s.link];
    const vals: number[] = [0];
    for (let i = 1; i < n; i++) {
      const o = s.offset + i * ent;
      if (!r.has(o, ent)) break;
      const nameOff = r.u32(o);
      const info = is64 ? r.u8(o + 4) : r.u8(o + 12);
      const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
      const value = is64 ? Number(r.u64(o + 8)) : r.u32(o + 4);
      vals.push(shndx ? value : 0);
      if (!strs || nameOff >= strs.size || !shndx) continue;
      const name = r.cstr(strs.offset + nameOff, 1024);
      if (!name) continue;
      const t = info & 0xf;
      if (t === 2 || t === 1 || t === 0) {
        const v = machine === 40 ? value & ~1 : value;
        if (!L.symbols.has(v) || s.type === 11) L.symbols.set(v, name);
        if (s.type === 11 && info >> 4 !== 0) L.exports.set(name, v);
      }
    }
    symVals[idx] = vals;
  });
  // relocations: RELA (4), REL (9), RELR (19)
  const rel = RELATIVE[machine], abs = ABS[machine] ?? [];
  let count = 0;
  for (const s of sections) {
    if (s.type === 4 || s.type === 9) {
      const ent = s.entsize || (is64 ? (s.type === 4 ? 24 : 16) : (s.type === 4 ? 12 : 8));
      const syms = symVals[s.link] ?? [];
      for (let o = s.offset; o + ent <= s.offset + s.size && count < JNI_LIMITS.maxRelocs; o += ent, count++) {
        if (!r.has(o, ent)) break;
        const off = word(o);
        const info = word(o + (is64 ? 8 : 4));
        const type = is64 ? info % 2 ** 32 : info & 0xff;
        const sym = is64 ? Math.floor(info / 2 ** 32) : info >>> 8;
        const addend = s.type === 4 ? (is64 ? Number(r.i64(o + 16)) : r.i32(o + 8)) : readVa(L, off) ?? 0;
        if (type === rel) L.relocs.set(off, addend);
        else if (abs.includes(type) && syms[sym]) L.relocs.set(off, syms[sym]! + (s.type === 4 ? addend : 0));
      }
    } else if (s.type === 19) {
      // RELR: an address entry, then bitmaps of following words
      const ws = is64 ? 8 : 4;
      let where = 0;
      for (let o = s.offset; o + ws <= s.offset + s.size && count < JNI_LIMITS.maxRelocs; o += ws) {
        if (!r.has(o, ws)) break;
        const e = word(o);
        if (e % 2 === 0) { where = e; const v = readVa(L, where); if (v !== undefined) L.relocs.set(where, v); where += ws; count++; }
        else {
          let bits = Math.floor(e / 2);
          for (let i = 0; bits > 0 && i < ws * 8 - 1; i++, bits = Math.floor(bits / 2)) if (bits % 2) { const a = where + i * ws; const v = readVa(L, a); if (v !== undefined) L.relocs.set(a, v); count++; }
          where += (ws * 8 - 1) * ws;
        }
      }
    }
  }
  return L;
}

function vaToOff(L: Loaded, va: number, n = 1): number | undefined {
  for (const s of L.segments) if (va >= s.vaddr && va + n <= s.vaddr + s.filesz) return s.offset + (va - s.vaddr);
  for (const s of L.sections) if (s.addr && s.type !== 8 && va >= s.addr && va + n <= s.addr + s.size) return s.offset + (va - s.addr);
  return undefined;
}
function readVa(L: Loaded, va: number): number | undefined {
  const o = vaToOff(L, va, L.bits / 8);
  if (o === undefined || !L.r.has(o, L.bits / 8)) return undefined;
  return L.bits === 64 ? Number(L.r.u64(o)) : L.r.u32(o);
}
function strVa(L: Loaded, va: number, max = 512): string | undefined {
  const o = vaToOff(L, va);
  if (o === undefined) return undefined;
  const b = L.r.bytes;
  let e = o;
  while (e < b.length && e - o < max && b[e] !== 0) { if (b[e]! < 0x20 || b[e]! > 0x7e) return undefined; e++; }
  if (e >= b.length || b[e] !== 0 || e === o) return undefined;
  let s = '';
  for (let i = o; i < e; i++) s += String.fromCharCode(b[i]!);
  return s;
}
function isExecVa(L: Loaded, va: number): boolean {
  for (const s of L.segments) if (s.flags & 1 && va >= s.vaddr && va < s.vaddr + s.memsz) return true;
  return L.segments.length === 0 && L.sections.some((s) => s.flags & 4 && va >= s.addr && va < s.addr + s.size);
}

const ID = /^[A-Za-z_$][A-Za-z0-9_$]{0,255}$/;
const FT = '(?:\\[*(?:[ZBCSIJFD]|L[A-Za-z0-9_$/]+;))';
export const JNI_SIG = new RegExp(`^\\(${FT}*\\)(?:${FT}|V)$`);
const CLASS_PATH = /^(?:[A-Za-z_$][A-Za-z0-9_$]*\/)+[A-Za-z_$][A-Za-z0-9_$]*$/;

export interface JniTableEntry { name: string; signature: string; fn: string; fnSymbol?: string; slotVaddr: string }
export interface JniTable { vaddr: string; fileOffset: number; section: string; entries: JniTableEntry[] }
export interface JniLibScan { bits: 32 | 64; machine: string; jniOnLoad: boolean; javaExports: { name: string; address: string }[]; tables: JniTable[]; classHints: string[]; signatureHints: string[] }

const MACH: Record<number, string> = { 3: 'x86', 8: 'mips', 40: 'arm', 62: 'x86_64', 183: 'arm64', 243: 'riscv' };
const hex = (n: number): string => `0x${n.toString(16)}`;

/** Recover JNINativeMethod tables, Java_* exports and JNI string hints from one ELF shared library. */
export function scanJniLibrary(bytes: Uint8Array): JniLibScan {
  const L = loadElf(bytes);
  const ps = L.bits / 8;
  const ptr = (va: number): number | undefined => L.relocs.get(va) ?? readVa(L, va);
  const tables: JniTable[] = [];
  let total = 0;
  for (const s of L.sections) {
    // allocated, non-executable data: .data.rel.ro, .data, .rodata and friends
    if (s.type !== 1 || !(s.flags & 2) || s.flags & 4 || !s.addr || s.size < ps * 3) continue;
    let cur: JniTable | undefined;
    // PROGBITS data lives in the file: never walk past the bytes the file holds, whatever size the header claims
    const end = s.addr + Math.min(s.size, Math.max(0, L.r.bytes.length - s.offset));
    for (let va = s.addr; va + ps * 3 <= end && total < JNI_LIMITS.maxTableEntries;) {
      const n = ptr(va), g = ptr(va + ps), f = ptr(va + 2 * ps);
      const name = n !== undefined ? strVa(L, n, 256) : undefined;
      const sig = name && ID.test(name) && g !== undefined ? strVa(L, g, 1024) : undefined;
      if (name && sig && JNI_SIG.test(sig) && f !== undefined && f !== 0 && isExecVa(L, f)) {
        const fn = L.machine === 40 ? f & ~1 : f;
        if (!cur) { cur = { vaddr: hex(va), fileOffset: vaToOff(L, va) ?? -1, section: s.name, entries: [] }; tables.push(cur); }
        const sym = L.symbols.get(fn);
        cur.entries.push(sym ? { name, signature: sig, fn: hex(fn), fnSymbol: sym, slotVaddr: hex(va) } : { name, signature: sig, fn: hex(fn), slotVaddr: hex(va) });
        total++;
        va += 3 * ps;
      } else { cur = undefined; va += ps; }
    }
  }
  // string hints from read-only string data
  const classHints = new Set<string>(), signatureHints = new Set<string>();
  for (const s of L.sections) {
    if (s.type !== 1 || !(s.flags & 2) || s.flags & 4 || s.size > 64 << 20) continue;
    const b = L.r.bytes;
    let st = s.offset;
    const end = Math.min(b.length, s.offset + s.size);
    for (let i = s.offset; i <= end && classHints.size + signatureHints.size < JNI_LIMITS.maxHints; i++) {
      if (i < end && b[i]! >= 0x20 && b[i]! <= 0x7e) continue;
      if (i < end && b[i] !== 0) { st = i + 1; continue; }
      if (i - st >= 3 && i - st < 1024) {
        let str = '';
        for (let k = st; k < i; k++) str += String.fromCharCode(b[k]!);
        if (CLASS_PATH.test(str) && /[a-z]/.test(str)) classHints.add(str);
        else if (JNI_SIG.test(str)) signatureHints.add(str);
      }
      st = i + 1;
    }
  }
  const javaExports = [...L.exports].filter(([n]) => n.startsWith('Java_')).map(([name, v]) => ({ name, address: hex(v) }));
  return { bits: L.bits, machine: MACH[L.machine] ?? `machine${L.machine}`, jniOnLoad: L.exports.has('JNI_OnLoad'), javaExports, tables, classHints: [...classHints], signatureHints: [...signatureHints] };
}

export interface JniBinding { abi: string; library: string; how: 'export-short' | 'export-long' | 'register-natives' | 'string-hint'; symbol?: string; address?: string; evidence?: string }
export interface JniMethodMap { class: string; method: string; signature: string; jni: string; jniLong: string; bindings: JniBinding[] }

/** Match DEX native methods against scanned libraries. `libs` holds one scan per (abi, path). */
export function mapJni(methods: NativeMethod[], libs: { abi: string; path: string; scan: JniLibScan }[]): { methods: JniMethodMap[]; unresolved: JniMethodMap[]; orphanExports: { abi: string; library: string; name: string }[] } {
  const out: JniMethodMap[] = [];
  const used = new Set<string>();
  for (const m of methods) {
    const classPath = m.class.replace(/\./g, '/');
    const e: JniMethodMap = { ...m, bindings: [] };
    for (const l of libs) {
      const short = l.scan.javaExports.find((x) => x.name === m.jni), long = l.scan.javaExports.find((x) => x.name === m.jniLong);
      if (long) { e.bindings.push({ abi: l.abi, library: l.path, how: 'export-long', symbol: long.name, address: long.address }); used.add(`${l.abi}:${l.path}:${long.name}`); }
      else if (short) { e.bindings.push({ abi: l.abi, library: l.path, how: 'export-short', symbol: short.name, address: short.address }); used.add(`${l.abi}:${l.path}:${short.name}`); }
      if (long || short) continue;
      // RegisterNatives tables: name + signature match; the class comes from FindClass hints in the same library
      const hit = l.scan.tables.flatMap((t) => t.entries).find((t) => t.name === m.method && t.signature === m.signature);
      if (hit && (l.scan.classHints.includes(classPath) || l.scan.classHints.length === 0)) {
        e.bindings.push({ abi: l.abi, library: l.path, how: 'register-natives', symbol: hit.fnSymbol, address: hit.fn, evidence: `JNINativeMethod at ${hit.slotVaddr}${l.scan.classHints.includes(classPath) ? `, class string ${classPath}` : ''}` });
        continue;
      }
      if (l.scan.classHints.includes(classPath) && l.scan.signatureHints.includes(m.signature)) e.bindings.push({ abi: l.abi, library: l.path, how: 'string-hint', evidence: `class string ${classPath} and signature ${m.signature} in the library` });
    }
    out.push(e);
  }
  const orphanExports: { abi: string; library: string; name: string }[] = [];
  for (const l of libs) for (const x of l.scan.javaExports) if (!used.has(`${l.abi}:${l.path}:${x.name}`)) orphanExports.push({ abi: l.abi, library: l.path, name: x.name });
  return { methods: out, unresolved: out.filter((x) => !x.bindings.length), orphanExports };
}
