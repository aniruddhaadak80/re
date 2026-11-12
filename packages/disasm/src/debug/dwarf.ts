// DWARF 2 to 5 type and function reader (pure TypeScript, browser safe).
// Reads .debug_info / .debug_abbrev / .debug_str / .debug_line_str / .debug_str_offsets /
// .debug_addr / .debug_loc / .debug_loclists from ELF, Mach-O (__DWARF) and PE images and returns
// structs, unions, enums, typedefs, function prototypes, parameters, locals and globals with C style
// type names. Every read is bounds checked; counts, depth and time are capped.
import type { BinaryImage } from '../types.js';

export interface DwarfMember { name?: string; type: string; typeRef?: number; offset?: number; bitSize?: number; bitOffset?: number; size?: number }
export interface DwarfEnumerator { name: string; value: number }
export interface DwarfType {
  /** offset of the DIE in .debug_info (stable id) */
  id: number;
  kind: 'base' | 'struct' | 'union' | 'class' | 'enum' | 'typedef' | 'pointer' | 'reference' | 'rvalue-reference' | 'const' | 'volatile' | 'restrict' | 'atomic' | 'array' | 'function' | 'ptr-to-member' | 'unspecified';
  name?: string;
  /** C style rendering, like llvm-dwarfdump prints in quotes */
  display: string;
  size?: number;
  encoding?: string;
  target?: number;
  members?: DwarfMember[];
  enumerators?: DwarfEnumerator[];
  /** array dimensions (element counts; -1 when unknown) */
  dims?: number[];
  /** function types: return type and parameter types */
  returns?: string;
  params?: string[];
  variadic?: boolean;
  declaration?: boolean;
  /** typedefs: the aliased type rendered */
  aliasOf?: string;
  file?: string;
  line?: number;
  unit: number;
}
export interface DwarfLocation {
  /** register name (DW_OP_regN) */
  reg?: string;
  /** offset from the frame base (DW_OP_fbreg) */
  fbreg?: number;
  /** register plus offset (DW_OP_bregN) */
  breg?: { reg: string; offset: number };
  /** absolute address (DW_OP_addr / DW_OP_addrx) */
  addr?: number;
  /** constant value (DW_OP_litN, DW_OP_consts, DW_OP_constu with DW_OP_stack_value) */
  value?: number;
  /** a location list: the first range's location, which is the value at function entry for parameters */
  list?: boolean;
  expr?: string;
}
export interface DwarfVar { name: string; type: string; typeRef?: number; location?: DwarfLocation; artificial?: boolean }
export interface DwarfFunction {
  id: number;
  name: string;
  /** C++: name with namespaces and classes, like geo::Rect::area */
  qualifiedName?: string;
  linkageName?: string;
  low?: number;
  high?: number;
  returns: string;
  returnsRef?: number;
  params: DwarfVar[];
  locals: DwarfVar[];
  variadic?: boolean;
  external?: boolean;
  declaration?: boolean;
  inlined?: boolean;
  noreturn?: boolean;
  frameBase?: DwarfLocation;
  file?: string;
  line?: number;
  /** C prototype text */
  prototype: string;
  unit: number;
}
export interface DwarfGlobal { id: number; name: string; type: string; typeRef?: number; addr?: number; external?: boolean; declaration?: boolean; unit: number }
export interface DwarfUnit { offset: number; version: number; unitType: string; addrSize: number; name?: string; producer?: string; language?: string; compDir?: string; low?: number; high?: number; dies: number }
export interface DwarfInfo {
  present: boolean;
  units: DwarfUnit[];
  types: DwarfType[];
  functions: DwarfFunction[];
  globals: DwarfGlobal[];
  sections: string[];
  warnings: string[];
  complete: boolean;
}
export interface DwarfOptions { budgetMs?: number; maxDies?: number }

const MAX_DIES_DEFAULT = 2_000_000;
const MAX_DEPTH = 64;

interface Sec { name: string; bytes: Uint8Array }

/** Collects the DWARF sections of a loaded image (ELF .debug_*, Mach-O __debug_*, PE .debug_*). */
export function dwarfSections(img: BinaryImage): Map<string, Uint8Array> {
  const m = new Map<string, Uint8Array>();
  const add = (name: string, off: number, size: number) => {
    const n = name.replace(/^__/, '.').replace(/^\.zdebug/, '.zdebug');
    if (!/^\.debug_|^\.zdebug_/.test(n)) return;
    if (off < 0 || size <= 0 || off >= img.bytes.length || m.has(n)) return;
    m.set(n, img.bytes.subarray(off, Math.min(img.bytes.length, off + size)));
  };
  for (const s of img.debugSections ?? []) add(s.name, s.offset, s.size);
  for (const s of img.sections) if (s.fsize > 0) add(s.name, s.offset, s.fsize);
  return m;
}

class Rd {
  readonly b: Uint8Array;
  readonly v: DataView;
  pos: number;
  readonly le: boolean;
  constructor(b: Uint8Array, pos = 0, le = true) { this.b = b; this.v = new DataView(b.buffer, b.byteOffset, b.byteLength); this.pos = pos; this.le = le; }
  need(n: number) { if (this.pos + n > this.b.length || this.pos < 0) throw new RangeError('dwarf: read past end'); }
  u8() { this.need(1); return this.b[this.pos++]!; }
  u16() { this.need(2); const x = this.v.getUint16(this.pos, this.le); this.pos += 2; return x; }
  u24() { this.need(3); const a = this.b[this.pos]!, b = this.b[this.pos + 1]!, c = this.b[this.pos + 2]!; this.pos += 3; return this.le ? a | (b << 8) | (c << 16) : (a << 16) | (b << 8) | c; }
  u32() { this.need(4); const x = this.v.getUint32(this.pos, this.le); this.pos += 4; return x; }
  u64() { this.need(8); const x = Number(this.v.getBigUint64(this.pos, this.le)); this.pos += 8; return x; }
  i8() { const x = this.u8(); return x > 127 ? x - 256 : x; }
  i16() { const x = this.u16(); return x > 32767 ? x - 65536 : x; }
  i32() { this.need(4); const x = this.v.getInt32(this.pos, this.le); this.pos += 4; return x; }
  i64() { this.need(8); const x = Number(this.v.getBigInt64(this.pos, this.le)); this.pos += 8; return x; }
  uleb() {
    let r = 0, mul = 1;
    for (let i = 0; i < 10; i++) { const c = this.u8(); r += (c & 0x7f) * mul; mul *= 128; if (!(c & 0x80)) return r; }
    return r;
  }
  sleb() {
    let r = 0, mul = 1, c = 0;
    for (let i = 0; i < 10; i++) { c = this.u8(); r += (c & 0x7f) * mul; mul *= 128; if (!(c & 0x80)) break; }
    if (c & 0x40) r -= mul;
    return r;
  }
  cstr(max = 4096) {
    const start = this.pos;
    const end = Math.min(this.b.length, start + max);
    let i = start;
    while (i < end && this.b[i] !== 0) i++;
    const s = latin(this.b.subarray(start, i));
    this.pos = Math.min(this.b.length, i + 1);
    if (i >= this.b.length) throw new RangeError('dwarf: unterminated string');
    return s;
  }
  addr(size: number) { return size === 8 ? this.u64() : size === 4 ? this.u32() : size === 2 ? this.u16() : this.u8(); }
  off(is64: boolean) { return is64 ? this.u64() : this.u32(); }
}

const dec = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { fatal: false }) : undefined;
function latin(b: Uint8Array): string {
  if (dec) return dec.decode(b);
  let s = '';
  for (const c of b) s += String.fromCharCode(c);
  return s;
}
function cstrAt(b: Uint8Array | undefined, off: number): string | undefined {
  if (!b || off < 0 || off >= b.length) return undefined;
  let i = off;
  const end = Math.min(b.length, off + 4096);
  while (i < end && b[i] !== 0) i++;
  return latin(b.subarray(off, i));
}

// ---- constants ----
const TAG: Record<number, string> = {
  0x01: 'array_type', 0x02: 'class_type', 0x04: 'enumeration_type', 0x05: 'formal_parameter', 0x0b: 'lexical_block', 0x0d: 'member',
  0x0f: 'pointer_type', 0x10: 'reference_type', 0x11: 'compile_unit', 0x13: 'structure_type', 0x15: 'subroutine_type', 0x16: 'typedef',
  0x17: 'union_type', 0x18: 'unspecified_parameters', 0x1d: 'inlined_subroutine', 0x1f: 'ptr_to_member_type', 0x21: 'subrange_type',
  0x24: 'base_type', 0x26: 'const_type', 0x28: 'enumerator', 0x2e: 'subprogram', 0x34: 'variable', 0x35: 'volatile_type', 0x37: 'restrict_type',
  0x39: 'namespace', 0x3b: 'unspecified_type', 0x41: 'type_unit', 0x42: 'rvalue_reference_type', 0x47: 'atomic_type', 0x4a: 'skeleton_unit',
  0x2f: 'template_type_parameter', 0x30: 'template_value_parameter', 0x1c: 'inheritance', 0x48: 'call_site', 0x4109: 'GNU_call_site',
};
const AT = {
  sibling: 0x01, location: 0x02, name: 0x03, byte_size: 0x0b, bit_offset: 0x0c, bit_size: 0x0d, stmt_list: 0x10, low_pc: 0x11, high_pc: 0x12,
  language: 0x13, comp_dir: 0x1b, const_value: 0x1c, producer: 0x25, prototyped: 0x27, lower_bound: 0x22, upper_bound: 0x2f, abstract_origin: 0x31,
  artificial: 0x34, count: 0x37, data_member_location: 0x38, decl_file: 0x3a, decl_line: 0x3b, declaration: 0x3c, encoding: 0x3e,
  external: 0x3f, frame_base: 0x40, specification: 0x47, type: 0x49, ranges: 0x55, data_bit_offset: 0x6b, linkage_name: 0x6e,
  str_offsets_base: 0x72, addr_base: 0x73, rnglists_base: 0x74, loclists_base: 0x8c, noreturn: 0x87, mips_linkage_name: 0x2007,
};
const ATE: Record<number, string> = { 1: 'address', 2: 'boolean', 3: 'complex_float', 4: 'float', 5: 'signed', 6: 'signed_char', 7: 'unsigned', 8: 'unsigned_char', 0x10: 'UTF', 0x12: 'ASCII', 0x0d: 'signed_fixed', 0x0e: 'unsigned_fixed' };
const LANG: Record<number, string> = { 1: 'C89', 2: 'C', 4: 'C++', 0x0c: 'C99', 0x0d: 'Ada95', 0x1a: 'C++11', 0x1c: 'Rust', 0x1d: 'C11', 0x21: 'C++14', 0x16: 'Go', 0x1e: 'Swift', 0x2c: 'C17', 0x8001: 'Mips_Assembler', 0x10: 'ObjC', 0x11: 'ObjC++', 0x24: 'Zig', 0x26: 'Kotlin', 0x0e: 'Fortran95', 0x19: 'C++03', 0x1b: 'Dylan', 0x2b: 'C++17', 0x2d: 'C++20', 0x8e57: 'GOOGLE_RenderScript' };
const REGS_X64 = ['rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
const REGS_X86 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
function regName(arch: string, n: number): string {
  if (arch === 'x86_64') { if (n < REGS_X64.length) return REGS_X64[n]!; if (n >= 17 && n <= 32) return 'xmm' + (n - 17); }
  if (arch === 'x86') { if (n < REGS_X86.length) return REGS_X86[n]!; if (n >= 21 && n <= 28) return 'xmm' + (n - 21); }
  if (arch === 'arm64') { if (n <= 30) return 'x' + n; if (n === 31) return 'sp'; if (n >= 64 && n <= 95) return 'v' + (n - 64); }
  if (arch === 'arm') { if (n <= 15) return ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'][n]!; if (n >= 256 && n <= 287) return 'd' + (n - 256); }
  return 'reg' + n;
}

interface Abbrev { tag: number; children: boolean; attrs: { at: number; form: number; implicit?: number }[] }

type AttrVal = { form: number; v: number; s?: string; block?: Uint8Array };

interface Die { off: number; tag: number; attrs: Map<number, AttrVal>; children: Die[]; parent?: Die; unit: UnitCtx }

interface UnitCtx {
  off: number; version: number; addrSize: number; is64: boolean; strOffBase: number; addrBase: number; loclistsBase: number; unitType: number; end: number; base: number;
}

const FORM_ADDRX = new Set([0x1b, 0x29, 0x2a, 0x2b, 0x2c, 0x1f01]);
const FORM_STRX = new Set([0x1a, 0x25, 0x26, 0x27, 0x28, 0x1f02]);
const FORM_REF = new Set([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
const FORM_CONST = new Set([0x05, 0x06, 0x07, 0x0b, 0x0d, 0x0f, 0x21]);
const FORM_BLOCK = new Set([0x03, 0x04, 0x09, 0x0a, 0x18]);

function parseAbbrevs(b: Uint8Array, off: number, le: boolean): Map<number, Abbrev> {
  const m = new Map<number, Abbrev>();
  const r = new Rd(b, off, le);
  for (let n = 0; n < 100000 && r.pos < b.length; n++) {
    const code = r.uleb();
    if (code === 0) break;
    const tag = r.uleb();
    const children = r.u8() === 1;
    const attrs: Abbrev['attrs'] = [];
    for (let k = 0; k < 512; k++) {
      const at = r.uleb(); const form = r.uleb();
      if (at === 0 && form === 0) break;
      const a: Abbrev['attrs'][0] = { at, form };
      if (form === 0x21) a.implicit = r.sleb();
      attrs.push(a);
    }
    m.set(code, { tag, children, attrs });
  }
  return m;
}

function readForm(r: Rd, form: number, u: UnitCtx, depth = 0): AttrVal {
  switch (form) {
    case 0x01: return { form, v: r.addr(u.addrSize) };
    case 0x03: { const n = r.u16(); r.need(n); const block = r.b.subarray(r.pos, r.pos + n); r.pos += n; return { form, v: n, block }; }
    case 0x04: { const n = r.u32(); r.need(n); const block = r.b.subarray(r.pos, r.pos + n); r.pos += n; return { form, v: n, block }; }
    case 0x05: return { form, v: r.u16() };
    case 0x06: return { form, v: r.u32() };
    case 0x07: return { form, v: r.u64() };
    case 0x08: return { form, v: 0, s: r.cstr() };
    case 0x09: case 0x18: { const n = r.uleb(); r.need(n); const block = r.b.subarray(r.pos, r.pos + n); r.pos += n; return { form, v: n, block }; }
    case 0x0a: { const n = r.u8(); r.need(n); const block = r.b.subarray(r.pos, r.pos + n); r.pos += n; return { form, v: n, block }; }
    case 0x0b: return { form, v: r.u8() };
    case 0x0c: return { form, v: r.u8() };
    case 0x0d: return { form, v: r.sleb() };
    case 0x0e: case 0x1f: case 0x1d: case 0x1f21: return { form, v: r.off(u.is64) };
    case 0x0f: return { form, v: r.uleb() };
    case 0x10: return { form, v: u.version <= 2 ? r.addr(u.addrSize) : r.off(u.is64) };
    case 0x11: return { form, v: u.off + r.u8() };
    case 0x12: return { form, v: u.off + r.u16() };
    case 0x13: return { form, v: u.off + r.u32() };
    case 0x14: return { form, v: u.off + r.u64() };
    case 0x15: return { form, v: u.off + r.uleb() };
    case 0x16: { if (depth > 4) throw new RangeError('dwarf: nested indirect form'); return readForm(r, r.uleb(), u, depth + 1); }
    case 0x17: return { form, v: r.off(u.is64) };
    case 0x19: return { form, v: 1 };
    case 0x1a: case 0x1b: case 0x22: case 0x23: case 0x1f01: case 0x1f02: return { form, v: r.uleb() };
    case 0x1c: return { form, v: r.u32() };
    case 0x1e: { r.need(16); r.pos += 16; return { form, v: 0 }; }
    case 0x20: return { form, v: r.u64() };
    case 0x24: return { form, v: r.u64() };
    case 0x25: case 0x29: return { form, v: r.u8() };
    case 0x26: case 0x2a: return { form, v: r.u16() };
    case 0x27: case 0x2b: return { form, v: r.u24() };
    case 0x28: case 0x2c: return { form, v: r.u32() };
    case 0x1f20: return { form, v: r.off(u.is64) };
    default: throw new RangeError(`dwarf: unknown form 0x${form.toString(16)}`);
  }
}

/** Reads the DWARF types, functions and globals of an image. */
export function readDwarf(img: BinaryImage, opts: DwarfOptions = {}): DwarfInfo {
  const secs = dwarfSections(img);
  const out: DwarfInfo = { present: false, units: [], types: [], functions: [], globals: [], sections: [...secs.keys()].sort(), warnings: [], complete: true };
  const info = secs.get('.debug_info');
  const abbrev = secs.get('.debug_abbrev');
  if (secs.has('.zdebug_info')) out.warnings.push('zlib compressed .zdebug sections are not decompressed');
  if (!info || !abbrev) return out;
  if (img.debugCompressed?.includes('.debug_info')) { out.warnings.push('.debug_info is SHF_COMPRESSED (zlib or zstd); not decompressed'); return out; }
  out.present = true;
  const le = img.endian !== 'be';
  const str = secs.get('.debug_str'), lineStr = secs.get('.debug_line_str'), strOffs = secs.get('.debug_str_offsets'), addrSec = secs.get('.debug_addr');
  const loclists = secs.get('.debug_loclists'), loc = secs.get('.debug_loc');
  const deadline = Date.now() + (opts.budgetMs ?? 20000);
  const maxDies = opts.maxDies ?? MAX_DIES_DEFAULT;
  const abbrevCache = new Map<number, Map<number, Abbrev>>();
  const dies = new Map<number, Die>();
  const roots: Die[] = [];
  let dieCount = 0;
  const r = new Rd(info, 0, le);

  units: while (r.pos + 11 <= info.length) {
    const uoff = r.pos;
    let len = r.u32();
    let is64 = false;
    if (len === 0xffffffff) { len = r.u64(); is64 = true; }
    else if (len >= 0xfffffff0) { out.warnings.push(`unit at 0x${uoff.toString(16)}: reserved length`); break; }
    const end = r.pos + len;
    if (end > info.length || len < 7) { out.warnings.push(`unit at 0x${uoff.toString(16)}: length past end of .debug_info`); out.complete = false; break; }
    const version = r.u16();
    let unitType = 1, addrSize = 0, abOff = 0;
    try {
      if (version >= 5) { unitType = r.u8(); addrSize = r.u8(); abOff = r.off(is64); if (unitType === 2 || unitType === 6) { r.u64(); r.off(is64); } else if (unitType === 4 || unitType === 5) r.u64(); }
      else if (version >= 2 && version <= 4) { abOff = r.off(is64); addrSize = r.u8(); }
      else { out.warnings.push(`unit at 0x${uoff.toString(16)}: unsupported version ${version}`); r.pos = end; continue; }
    } catch { out.warnings.push(`unit at 0x${uoff.toString(16)}: truncated header`); break; }
    if (![1, 2, 4, 8].includes(addrSize)) { out.warnings.push(`unit at 0x${uoff.toString(16)}: bad address size ${addrSize}`); r.pos = end; continue; }
    let abbrevs = abbrevCache.get(abOff);
    if (!abbrevs) {
      try { abbrevs = parseAbbrevs(abbrev, abOff, le); } catch { abbrevs = new Map(); out.warnings.push(`abbrev table at 0x${abOff.toString(16)} truncated`); }
      abbrevCache.set(abOff, abbrevs);
    }
    const u: UnitCtx = { off: uoff, version, addrSize, is64, strOffBase: 8, addrBase: 8, loclistsBase: 12, unitType, end, base: 0 };
    const unitInfo: DwarfUnit = { offset: uoff, version, unitType: ['?', 'compile', 'type', 'partial', 'skeleton', 'split_compile', 'split_type'][unitType] ?? String(unitType), addrSize, dies: 0 };
    const stack: Die[] = [];
    const ur = new Rd(info.subarray(0, end), r.pos, le);
    let first: Die | undefined;
    try {
      while (ur.pos < end) {
        const doff = ur.pos;
        const code = ur.uleb();
        if (code === 0) { stack.pop(); if (!stack.length && first) break; continue; }
        const ab = abbrevs.get(code);
        if (!ab) { out.warnings.push(`unit at 0x${uoff.toString(16)}: unknown abbrev ${code} at 0x${doff.toString(16)}`); out.complete = false; break; }
        const attrs = new Map<number, AttrVal>();
        for (const a of ab.attrs) {
          const val = a.form === 0x21 ? { form: a.form, v: a.implicit ?? 0 } : readForm(ur, a.form, u);
          if (!attrs.has(a.at)) attrs.set(a.at, val);
        }
        const d: Die = { off: doff, tag: ab.tag, attrs, children: [], parent: stack[stack.length - 1], unit: u };
        if (++dieCount > maxDies) { out.warnings.push(`stopped after ${maxDies} DIEs`); out.complete = false; break units; }
        if ((dieCount & 4095) === 0 && Date.now() > deadline) { out.warnings.push('time budget reached'); out.complete = false; break units; }
        unitInfo.dies++;
        dies.set(doff, d);
        if (d.parent) d.parent.children.push(d);
        else if (!first) {
          first = d; roots.push(d);
          const sb = attrs.get(AT.str_offsets_base); if (sb) u.strOffBase = sb.v;
          const abase = attrs.get(AT.addr_base); if (abase) u.addrBase = abase.v;
          const lb = attrs.get(AT.loclists_base); if (lb) u.loclistsBase = lb.v;
          const lo = attrs.get(AT.low_pc); if (lo) u.base = resolveAddr(lo, u);
        }
        if (ab.children) { if (stack.length >= MAX_DEPTH) throw new RangeError('dwarf: DIE nesting too deep'); stack.push(d); }
        else if (!stack.length) break;
      }
    } catch (e) {
      out.warnings.push(`unit at 0x${uoff.toString(16)}: ${(e as Error).message}`);
      out.complete = false;
    }
    if (first) {
      const g = (a: number) => attrStr(first!, a);
      unitInfo.name = g(AT.name); unitInfo.producer = g(AT.producer); unitInfo.compDir = g(AT.comp_dir);
      const lang = first.attrs.get(AT.language); if (lang) unitInfo.language = LANG[lang.v] ?? `0x${lang.v.toString(16)}`;
      const lo = first.attrs.get(AT.low_pc); if (lo) { unitInfo.low = resolveAddr(lo, u); const hi = first.attrs.get(AT.high_pc); if (hi) unitInfo.high = FORM_CONST.has(hi.form) ? unitInfo.low + hi.v : resolveAddr(hi, u); }
    }
    out.units.push(unitInfo);
    r.pos = end;
  }

  function resolveAddr(a: AttrVal, u: UnitCtx): number {
    if (FORM_ADDRX.has(a.form)) {
      if (!addrSec) return 0;
      const o = u.addrBase + a.v * u.addrSize;
      if (o < 0 || o + u.addrSize > addrSec.length) return 0;
      return new Rd(addrSec, o, le).addr(u.addrSize);
    }
    return a.v;
  }
  function attrStr(d: Die, at: number): string | undefined {
    const a = d.attrs.get(at);
    if (!a) return undefined;
    if (a.s !== undefined) return a.s;
    if (a.form === 0x0e) return cstrAt(str, a.v);
    if (a.form === 0x1f) return cstrAt(lineStr, a.v);
    if (FORM_STRX.has(a.form)) {
      if (!strOffs || !str) return undefined;
      const sz = d.unit.is64 ? 8 : 4;
      const o = d.unit.strOffBase + a.v * sz;
      if (o < 0 || o + sz > strOffs.length) return undefined;
      return cstrAt(str, new Rd(strOffs, o, le).off(d.unit.is64));
    }
    return undefined;
  }
  /** follow abstract_origin / specification for a missing attribute */
  function attrDeep(d: Die, at: number, depth = 0): { die: Die; a: AttrVal } | undefined {
    const a = d.attrs.get(at);
    if (a) return { die: d, a };
    if (depth > 6) return undefined;
    for (const link of [AT.abstract_origin, AT.specification]) {
      const l = d.attrs.get(link);
      if (l && FORM_REF.has(l.form)) { const t = dies.get(l.v); if (t && t !== d) { const x = attrDeep(t, at, depth + 1); if (x) return x; } }
    }
    return undefined;
  }
  function nameOf(d: Die): string | undefined { const x = attrDeep(d, AT.name); return x ? attrStr(x.die, AT.name) : undefined; }
  function typeRefOf(d: Die): number | undefined { const x = attrDeep(d, AT.type); return x && FORM_REF.has(x.a.form) ? x.a.v : undefined; }
  function num(d: Die, at: number): number | undefined { const a = d.attrs.get(at); return a && (FORM_CONST.has(a.form) || a.form === 0x0c || a.form === 0x19) ? a.v : undefined; }
  function flag(d: Die, at: number): boolean { const x = attrDeep(d, at); return !!x && x.a.v !== 0; }

  // ---- type names ----
  const nameCache = new Map<number, string>();
  function typeName(ref: number | undefined, depth = 0): string {
    if (ref === undefined) return 'void';
    const c = nameCache.get(ref);
    if (c !== undefined) return c;
    if (depth > 24) return '...';
    const d = dies.get(ref);
    if (!d) return `<type 0x${ref.toString(16)}>`;
    nameCache.set(ref, '<recursive>');
    const s = renderType(d, depth);
    nameCache.set(ref, s);
    return s;
  }
  const join = (base: string, q: string) => (base.endsWith('*') || base.endsWith('&') ? base + q : base + ' ' + q);
  function renderType(d: Die, depth: number): string {
    const tag = TAG[d.tag] ?? '';
    const n = nameOf(d);
    const t = typeRefOf(d);
    switch (tag) {
      case 'base_type': case 'unspecified_type': return n ?? (tag === 'unspecified_type' ? 'void' : '<base>');
      case 'typedef': return n ? (isCxx(d) ? qual(d) + n : n) : typeName(t, depth + 1);
      case 'structure_type': return n ? (isCxx(d) ? qual(d) + n : 'struct ' + n) : 'struct <anonymous>';
      case 'class_type': return n ? qual(d) + n : 'class <anonymous>';
      case 'union_type': return n ? (isCxx(d) ? qual(d) + n : 'union ' + n) : 'union <anonymous>';
      case 'enumeration_type': return n ? (isCxx(d) ? qual(d) + n : 'enum ' + n) : 'enum <anonymous>';
      case 'const_type': case 'volatile_type': case 'restrict_type': case 'atomic_type': {
        const q = tag === 'const_type' ? 'const' : tag === 'volatile_type' ? 'volatile' : tag === 'restrict_type' ? 'restrict' : '_Atomic';
        const inner = typeName(t, depth + 1);
        const td = t !== undefined ? dies.get(t) : undefined;
        // const applied to a pointer reads "char *const"; otherwise prefix
        if (td && ['pointer_type', 'reference_type', 'rvalue_reference_type'].includes(TAG[td.tag] ?? '')) return join(inner, q);
        if (td && TAG[td.tag] === 'array_type') return q + ' ' + inner;
        return q + ' ' + inner;
      }
      case 'pointer_type': case 'reference_type': case 'rvalue_reference_type': {
        const sym = tag === 'pointer_type' ? '*' : tag === 'reference_type' ? '&' : '&&';
        const td = t !== undefined ? dies.get(t) : undefined;
        if (td && TAG[td.tag] === 'subroutine_type') { const f = fnParts(td, depth); return `${f.ret} (${sym})(${f.params})`; }
        if (td && TAG[td.tag] === 'array_type') { const a = arrParts(td, depth); return `${a.elem} (${sym})${a.dims}`; }
        const inner = typeName(t, depth + 1);
        const fp = /^(.*) \((\*+|&|&&)\)(\(.*\))$/.exec(inner);
        if (fp) return `${fp[1]} (${fp[2]}${sym})${fp[3]}`;
        return join(inner, sym);
      }
      case 'array_type': { const a = arrParts(d, depth); return a.elem + a.dims; }
      case 'subroutine_type': { const f = fnParts(d, depth); return `${f.ret} (${f.params})`; }
      case 'ptr_to_member_type': return typeName(t, depth + 1) + ' ::*';
      default: return n ?? `<${tag || 'tag 0x' + d.tag.toString(16)}>`;
    }
  }
  /** "ns::Outer::" for a C++ entity declared inside namespaces or classes */
  function qual(d: Die): string {
    const parts: string[] = [];
    let cur = d.parent;
    for (let i = 0; cur && i < 16; i++, cur = cur.parent) {
      const tg = TAG[cur.tag];
      if (tg === 'namespace' || tg === 'structure_type' || tg === 'class_type' || tg === 'union_type') parts.unshift(nameOf(cur) ?? (tg === 'namespace' ? '(anonymous namespace)' : '<anonymous>'));
    }
    return parts.length ? parts.join('::') + '::' : '';
  }
  function isCxx(d: Die): boolean {
    let u: Die | undefined = d;
    while (u?.parent) u = u.parent;
    const lang = u?.attrs.get(AT.language)?.v;
    return lang === 4 || lang === 0x1a || lang === 0x21 || lang === 0x19 || lang === 0x2b || lang === 0x2d || lang === 0x11;
  }
  function dimsOf(d: Die): number[] {
    const out: number[] = [];
    for (const c of d.children) {
      if (TAG[c.tag] !== 'subrange_type') continue;
      const cnt = num(c, AT.count);
      const ub = num(c, AT.upper_bound);
      const lb = num(c, AT.lower_bound) ?? 0;
      out.push(cnt !== undefined ? cnt : ub !== undefined && ub !== 0xffffffff && ub !== -1 ? ub - lb + 1 : -1);
    }
    return out;
  }
  function arrParts(d: Die, depth: number) {
    const dims = dimsOf(d);
    return { elem: typeName(typeRefOf(d), depth + 1), dims: (dims.length ? dims : [-1]).map((x) => (x >= 0 ? `[${x}]` : '[]')).join('') };
  }
  function fnParts(d: Die, depth: number) {
    const ps: string[] = [];
    let variadic = false;
    for (const c of d.children) {
      const tg = TAG[c.tag];
      if (tg === 'formal_parameter') ps.push(typeName(typeRefOf(c), depth + 1));
      else if (tg === 'unspecified_parameters') variadic = true;
    }
    if (variadic) ps.push('...');
    const proto = d.attrs.get(AT.prototyped);
    return { ret: typeName(typeRefOf(d), depth + 1), params: ps.length ? ps.join(', ') : proto ? 'void' : '' };
  }

  // ---- locations ----
  function parseExpr(b: Uint8Array, u: UnitCtx): DwarfLocation {
    const rr = new Rd(b, 0, le);
    const loc: DwarfLocation = {};
    try {
      const op = rr.u8();
      if (op >= 0x50 && op <= 0x6f) loc.reg = regName(img.arch, op - 0x50);
      else if (op === 0x90) loc.reg = regName(img.arch, rr.uleb());
      else if (op === 0x91) loc.fbreg = rr.sleb();
      else if (op >= 0x70 && op <= 0x8f) loc.breg = { reg: regName(img.arch, op - 0x70), offset: rr.sleb() };
      else if (op === 0x92) { const reg = rr.uleb(); loc.breg = { reg: regName(img.arch, reg), offset: rr.sleb() }; }
      else if (op === 0x03) loc.addr = rr.addr(u.addrSize);
      else if (op === 0xa1 || op === 0xfb) loc.addr = resolveAddr({ form: 0x1b, v: rr.uleb() }, u);
      else if (op === 0x9c) loc.expr = 'call_frame_cfa';
      else if (op >= 0x30 && op <= 0x4f) loc.value = op - 0x30;
      else if (op === 0x10) loc.value = rr.uleb();
      else if (op === 0x11) loc.value = rr.sleb();
      else if (op === 0x08) loc.value = rr.u8();
      else if (op === 0x09) loc.value = rr.i8();
      else loc.expr = `op 0x${op.toString(16)}`;
      if (loc.value !== undefined && rr.pos < b.length && b[rr.pos] === 0x9f) rr.pos++;
      if (rr.pos < b.length && !loc.expr) loc.expr = 'composite';
    } catch { loc.expr = 'truncated'; }
    return loc;
  }
  function firstListEntry(a: AttrVal, u: UnitCtx): DwarfLocation | undefined {
    try {
      if (u.version >= 5) {
        if (!loclists) return undefined;
        let off = a.v;
        if (a.form === 0x22) { const sz = u.is64 ? 8 : 4; const o = u.loclistsBase + a.v * sz; off = u.loclistsBase + new Rd(loclists, o, le).off(u.is64); }
        const rr = new Rd(loclists, off, le);
        for (let i = 0; i < 64; i++) {
          const k = rr.u8();
          if (k === 0) return undefined;
          if (k === 1) { rr.uleb(); continue; }
          if (k === 6) { rr.addr(u.addrSize); continue; }
          if (k === 2) { rr.uleb(); rr.uleb(); }
          else if (k === 3) { rr.uleb(); rr.uleb(); }
          else if (k === 4) { rr.uleb(); rr.uleb(); }
          else if (k === 5) { /* default */ }
          else if (k === 7) { rr.addr(u.addrSize); rr.addr(u.addrSize); }
          else if (k === 8) { rr.addr(u.addrSize); rr.uleb(); }
          else return undefined;
          const n = rr.uleb(); rr.need(n);
          const l = parseExpr(rr.b.subarray(rr.pos, rr.pos + n), u);
          l.list = true;
          return l;
        }
        return undefined;
      }
      if (!loc) return undefined;
      const rr = new Rd(loc, a.v, le);
      for (let i = 0; i < 64; i++) {
        const s = rr.addr(u.addrSize), e = rr.addr(u.addrSize);
        if (s === 0 && e === 0) return undefined;
        const maxA = u.addrSize === 8 ? 2 ** 64 - 1 : 2 ** (u.addrSize * 8) - 1;
        if (s === maxA || (u.addrSize === 8 && s >= 2 ** 63)) continue; // base address selection
        const n = rr.u16(); rr.need(n);
        const l = parseExpr(rr.b.subarray(rr.pos, rr.pos + n), u);
        l.list = true;
        return l;
      }
    } catch { /* truncated list */ }
    return undefined;
  }
  function locOf(d: Die, at: number): DwarfLocation | undefined {
    const a = d.attrs.get(at);
    if (!a) return undefined;
    if (a.block && (a.form === 0x18 || FORM_BLOCK.has(a.form))) return parseExpr(a.block, d.unit);
    if (a.form === 0x17 || a.form === 0x22 || (d.unit.version < 4 && (a.form === 0x06 || a.form === 0x07))) return firstListEntry(a, d.unit);
    return undefined;
  }

  // ---- collect ----
  const fileOf = (d: Die): number | undefined => num(d, AT.decl_line);
  const kindOf: Record<string, DwarfType['kind']> = {
    base_type: 'base', structure_type: 'struct', union_type: 'union', class_type: 'class', enumeration_type: 'enum', typedef: 'typedef',
    pointer_type: 'pointer', reference_type: 'reference', rvalue_reference_type: 'rvalue-reference', const_type: 'const', volatile_type: 'volatile',
    restrict_type: 'restrict', atomic_type: 'atomic', array_type: 'array', subroutine_type: 'function', ptr_to_member_type: 'ptr-to-member', unspecified_type: 'unspecified',
  };
  const collectLocals = (d: Die, into: DwarfVar[], depth: number) => {
    for (const c of d.children) {
      const tg = TAG[c.tag];
      if (tg === 'variable') {
        const n = nameOf(c);
        if (n && into.length < 4096) into.push({ name: n, type: typeName(typeRefOf(c)), typeRef: typeRefOf(c), location: locOf(c, AT.location) });
      } else if (tg === 'lexical_block' && depth < 32) collectLocals(c, into, depth + 1);
    }
  };
  for (const d of dies.values()) {
    if (Date.now() > deadline) { out.complete = false; out.warnings.push('time budget reached while collecting'); break; }
    const tag = TAG[d.tag] ?? '';
    const kind = kindOf[tag];
    if (kind) {
      const t: DwarfType = { id: d.off, kind, display: typeName(d.off), unit: d.unit.off };
      const n = nameOf(d); if (n) t.name = n;
      const sz = num(d, AT.byte_size); if (sz !== undefined) t.size = sz;
      const tr = typeRefOf(d); if (tr !== undefined) t.target = tr;
      if (kind === 'typedef') t.aliasOf = typeName(tr);
      if (flag(d, AT.declaration)) t.declaration = true;
      const ln = fileOf(d); if (ln !== undefined) t.line = ln;
      if (kind === 'base') { const e = num(d, AT.encoding); if (e !== undefined) t.encoding = ATE[e] ?? String(e); }
      if (kind === 'struct' || kind === 'union' || kind === 'class') {
        t.members = [];
        for (const c of d.children) {
          const ct = TAG[c.tag];
          if (ct !== 'member' && ct !== 'inheritance') continue;
          const m: DwarfMember = { type: typeName(typeRefOf(c)) };
          const mn = nameOf(c); if (mn) m.name = mn; else if (ct === 'inheritance') m.name = '<base>';
          const tr2 = typeRefOf(c); if (tr2 !== undefined) m.typeRef = tr2;
          const dml = c.attrs.get(AT.data_member_location);
          if (dml) { if (dml.block) { const rr = new Rd(dml.block, 0, le); try { if (rr.u8() === 0x23) m.offset = rr.uleb(); } catch { /* ignore */ } } else m.offset = dml.v; }
          const bs = num(c, AT.bit_size); if (bs !== undefined) m.bitSize = bs;
          const dbo = num(c, AT.data_bit_offset);
          if (dbo !== undefined) { m.bitOffset = dbo; if (m.offset === undefined) m.offset = Math.floor(dbo / 8); }
          else { const bo = num(c, AT.bit_offset); const bsz = num(c, AT.byte_size); if (bo !== undefined && bs !== undefined) { const unitBits = (bsz ?? 4) * 8; m.bitOffset = (m.offset ?? 0) * 8 + unitBits - bo - bs; } }
          const msz = num(c, AT.byte_size); if (msz !== undefined) m.size = msz;
          if (m.offset === undefined && kind === 'union') m.offset = 0;
          if (t.members.length < 4096) t.members.push(m);
        }
      }
      if (kind === 'enum') {
        t.enumerators = [];
        for (const c of d.children) if (TAG[c.tag] === 'enumerator' && t.enumerators.length < 65536) {
          const cv = c.attrs.get(AT.const_value);
          let v = cv?.v ?? 0;
          // unsigned data forms of a signed enum: sign extend by the enum size
          if (cv && (cv.form === 0x0b || cv.form === 0x05 || cv.form === 0x06) && t.size) { const bits = Math.min(32, (cv.form === 0x0b ? 1 : cv.form === 0x05 ? 2 : 4) * 8); if (v >= 2 ** (bits - 1) && signedEnum(d)) v -= 2 ** bits; }
          t.enumerators.push({ name: nameOf(c) ?? '?', value: v });
        }
      }
      if (kind === 'array') t.dims = dimsOf(d);
      if (kind === 'function') { const f = fnParts(d, 0); t.returns = f.ret; t.params = f.params && f.params !== 'void' ? f.params.split(', ') : []; if (f.params.endsWith('...')) t.variadic = true; }
      out.types.push(t);
      continue;
    }
    if (tag === 'subprogram') {
      const n = nameOf(d);
      if (!n) continue;
      const f: DwarfFunction = { id: d.off, name: n, returns: typeName(typeRefOf(d)), params: [], locals: [], prototype: '', unit: d.unit.off };
      if (isCxx(d)) { const spec = d.attrs.get(AT.specification) ?? d.attrs.get(AT.abstract_origin); const decl = spec && FORM_REF.has(spec.form) ? dies.get(spec.v) : undefined; const q = qual(decl ?? d); if (q) f.qualifiedName = q + n; }
      const rr = typeRefOf(d); if (rr !== undefined) f.returnsRef = rr;
      const ln = attrDeep(d, AT.linkage_name) ?? attrDeep(d, AT.mips_linkage_name);
      if (ln) { const s = attrStr(ln.die, ln.a === ln.die.attrs.get(AT.linkage_name) ? AT.linkage_name : AT.mips_linkage_name); if (s) f.linkageName = s; }
      const lo = d.attrs.get(AT.low_pc);
      if (lo) { f.low = resolveAddr(lo, d.unit); const hi = d.attrs.get(AT.high_pc); if (hi) f.high = FORM_CONST.has(hi.form) ? f.low + hi.v : resolveAddr(hi, d.unit); }
      if (flag(d, AT.external)) f.external = true;
      if (d.attrs.has(AT.declaration)) f.declaration = true;
      if (flag(d, AT.noreturn)) f.noreturn = true;
      const fb = locOf(d, AT.frame_base); if (fb) f.frameBase = fb;
      const line = num(attrDeep(d, AT.decl_line)?.die ?? d, AT.decl_line); if (line !== undefined) f.line = line;
      let paramSrc = d;
      if (!d.children.some((c) => TAG[c.tag] === 'formal_parameter')) { const ao = d.attrs.get(AT.abstract_origin) ?? d.attrs.get(AT.specification); const t = ao ? dies.get(ao.v) : undefined; if (t) paramSrc = t; }
      for (const c of paramSrc.children) {
        const tg = TAG[c.tag];
        if (tg === 'formal_parameter') {
          const own = paramSrc === d ? c : c;
          const pv: DwarfVar = { name: nameOf(own) ?? (flag(c, AT.artificial) && f.params.length === 0 ? 'this' : `p${f.params.length + 1}`), type: typeName(typeRefOf(own)) };
          const tr2 = typeRefOf(own); if (tr2 !== undefined) pv.typeRef = tr2;
          const l = paramSrc === d ? locOf(c, AT.location) : undefined; if (l) pv.location = l;
          if (flag(c, AT.artificial)) pv.artificial = true;
          f.params.push(pv);
        } else if (tg === 'unspecified_parameters') f.variadic = true;
      }
      collectLocals(d, f.locals, 0);
      const proto = attrDeep(d, AT.prototyped);
      const ps = f.params.map((p) => declare(p.type, p.name));
      if (f.variadic) ps.push('...');
      f.prototype = `${f.returns} ${f.qualifiedName ?? n}(${ps.length ? ps.join(', ') : proto ? 'void' : ''})`;
      if (f.noreturn) f.prototype = '_Noreturn ' + f.prototype;
      out.functions.push(f);
      continue;
    }
    if (tag === 'variable' && d.parent && (TAG[d.parent.tag] === 'compile_unit' || TAG[d.parent.tag] === 'namespace' || TAG[d.parent.tag] === 'partial_unit')) {
      const n = nameOf(d);
      if (!n) continue;
      const g: DwarfGlobal = { id: d.off, name: n, type: typeName(typeRefOf(d)), unit: d.unit.off };
      const tr = typeRefOf(d); if (tr !== undefined) g.typeRef = tr;
      const l = locOf(d, AT.location); if (l?.addr !== undefined) g.addr = l.addr;
      if (flag(d, AT.external)) g.external = true;
      if (d.attrs.has(AT.declaration)) g.declaration = true;
      out.globals.push(g);
    }
  }
  function signedEnum(d: Die): boolean {
    const t = typeRefOf(d);
    const td = t !== undefined ? dies.get(t) : undefined;
    if (!td) return true;
    const e = num(td, AT.encoding);
    return e === 5 || e === 6;
  }
  return out;
}

/** C declaration of a variable of a rendered type: "int x", "char *p", "int (*f)(int)", "int a[4]". */
export function declare(type: string, name: string): string {
  const fp = /^(.*) \((\*+|&|&&)\)(\(.*\))$/.exec(type);
  if (fp) return `${fp[1]} (${fp[2]}${name})${fp[3]}`;
  const ar = /^(.*?)((?:\[\d*\])+)$/.exec(type);
  if (ar && !type.includes('(')) return `${ar[1]} ${name}${ar[2]}`;
  return type.endsWith('*') || type.endsWith('&') ? type + name : `${type} ${name}`;
}

/** C text for a struct, union or enum type: a readable header declaration. */
export function typeDecl(t: DwarfType): string {
  if ((t.kind === 'struct' || t.kind === 'union' || t.kind === 'class') && t.members) {
    const lines = t.members.map((m) => `  ${declare(m.type, m.name ?? '')}${m.bitSize !== undefined ? ' : ' + m.bitSize : ''}; // offset ${m.offset ?? '?'}${m.bitOffset !== undefined ? `, bit ${m.bitOffset}` : ''}`);
    const kw = /^(struct|union|class|enum) /.test(t.display) ? '' : (t.kind === 'struct' ? 'struct ' : t.kind === 'union' ? 'union ' : 'class ');
    return `${kw}${t.display} {${t.size !== undefined ? ` // size ${t.size}` : ''}\n${lines.join('\n')}\n};`;
  }
  if (t.kind === 'enum' && t.enumerators) return `${t.display.startsWith('enum ') ? '' : 'enum '}${t.display} {\n${t.enumerators.map((e) => `  ${e.name} = ${e.value},`).join('\n')}\n};`;
  if (t.kind === 'typedef') return `typedef ${declare(t.aliasOf ?? 'void', t.name ?? '')};`;
  return t.display;
}

/** Size and field helpers over the types of one DwarfInfo. */
export class DwarfTypes {
  readonly byId = new Map<number, DwarfType>();
  constructor(info: DwarfInfo) { for (const t of info.types) this.byId.set(t.id, t); }
  /** strip typedef, const, volatile, restrict and atomic */
  strip(id: number | undefined): DwarfType | undefined {
    let t = id !== undefined ? this.byId.get(id) : undefined;
    for (let i = 0; i < 32 && t && ['typedef', 'const', 'volatile', 'restrict', 'atomic'].includes(t.kind); i++) t = t.target !== undefined ? this.byId.get(t.target) : undefined;
    return t;
  }
  sizeOf(id: number | undefined, depth = 0): number | undefined {
    if (depth > 32) return undefined;
    const t = id !== undefined ? this.byId.get(id) : undefined;
    if (!t) return undefined;
    if (t.size !== undefined) return t.size;
    if (['typedef', 'const', 'volatile', 'restrict', 'atomic'].includes(t.kind)) return this.sizeOf(t.target, depth + 1);
    if (t.kind === 'array') { const e = this.sizeOf(t.target, depth + 1); const n = (t.dims ?? []).reduce((a, b) => (b < 0 ? NaN : a * b), 1); return e !== undefined && Number.isFinite(n) ? e * n : undefined; }
    return undefined;
  }
  isFloat(id: number | undefined): boolean { const t = this.strip(id); return !!t && t.kind === 'base' && (t.encoding === 'float' || t.encoding === 'complex_float'); }
  isAggregate(id: number | undefined): boolean { const t = this.strip(id); return !!t && (t.kind === 'struct' || t.kind === 'union' || t.kind === 'class' || t.kind === 'array'); }
  /** pointee struct of a pointer type, when there is one */
  pointee(id: number | undefined): DwarfType | undefined {
    const p = this.strip(id);
    if (!p || (p.kind !== 'pointer' && p.kind !== 'reference' && p.kind !== 'rvalue-reference')) return undefined;
    const s = this.strip(p.target);
    return s && (s.kind === 'struct' || s.kind === 'union' || s.kind === 'class') ? s : undefined;
  }
  /** "->field", "->arr[2]" or "->inner.x" for byte offset off inside the struct a pointer of type id points to */
  fieldPath(id: number | undefined, off: number): string | undefined {
    const s = this.pointee(id);
    if (!s) return undefined;
    const p = this.memberPath(s, off, 0);
    return p === undefined ? undefined : '->' + p;
  }
  private memberPath(s: DwarfType, off: number, depth: number): string | undefined {
    if (depth > 8 || !s.members) return undefined;
    const exact = s.members.find((m) => m.offset === off && m.name && m.name !== '<base>');
    if (exact) return exact.name;
    for (const m of s.members) {
      if (m.offset === undefined || !m.name || off < m.offset) continue;
      const size = this.sizeOf(m.typeRef);
      if (size === undefined || off >= m.offset + size) continue;
      const rel = off - m.offset;
      const mt = this.strip(m.typeRef);
      if (mt?.kind === 'array') {
        const es = this.sizeOf(mt.target);
        if (es && rel % es === 0) return `${m.name}[${rel / es}]`;
        return undefined;
      }
      if (mt && (mt.kind === 'struct' || mt.kind === 'union' || mt.kind === 'class')) { const inner = this.memberPath(mt, rel, depth + 1); return inner === undefined ? undefined : `${m.name}.${inner}`; }
      return undefined;
    }
    return undefined;
  }
}
