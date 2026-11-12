// PDB (MSF 7.00) reader: PDB info stream, TPI and IPI type records (CodeView leaves), DBI module
// list, global symbols (typedefs as S_UDT, globals, procedure references, constants) and module
// procedure symbols with parameters and locals. Pure TypeScript, browser safe, bounds checked.
// Format notes from the public LLVM documentation (llvm.org/docs/PDB) and microsoft-pdb (MIT).

export interface PdbMember { name: string; type: string; typeIndex: number; offset?: number; bitSize?: number; bitOffset?: number; access?: string; kind: 'member' | 'static' | 'base' | 'vbase' | 'method' | 'nested' | 'vfptr' }
export interface PdbEnumerator { name: string; value: number }
export interface PdbType {
  index: number;
  leaf: string;
  kind: 'struct' | 'class' | 'union' | 'enum' | 'pointer' | 'modifier' | 'procedure' | 'member-function' | 'arglist' | 'array' | 'bitfield' | 'fieldlist' | 'methodlist' | 'vtshape' | 'other';
  name?: string;
  uniqueName?: string;
  display: string;
  size?: number;
  forwardRef?: boolean;
  /** forward reference resolved to its definition (same name, not a forward reference) */
  definition?: number;
  fieldList?: number;
  members?: PdbMember[];
  enumerators?: PdbEnumerator[];
  underlying?: string;
  referent?: number;
  pointerKind?: string;
  modifiers?: string[];
  returns?: string;
  params?: string[];
  callConv?: string;
  classType?: string;
  thisType?: string;
  element?: string;
  bitSize?: number;
  bitOffset?: number;
}
export interface PdbFuncId { index: number; name: string; type: string; typeIndex: number; scope?: string; className?: string }
export interface PdbUdt { name: string; typeIndex: number; type: string }
export interface PdbGlobal { name: string; kind: string; typeIndex?: number; type?: string; segment?: number; offset?: number; rva?: number; value?: number; module?: number }
export interface PdbLocal { name: string; type: string; param: boolean; register?: string; frameOffset?: number }
export interface PdbProc { name: string; kind: string; segment: number; offset: number; rva?: number; size: number; type: string; typeIndex: number; prototype: string; locals: PdbLocal[]; module: number }
export interface PdbInfo {
  valid: boolean;
  blockSize: number;
  streams: number;
  guid?: string;
  age?: number;
  signature?: number;
  version?: number;
  /** symbol server key GUID+age, matching the PE CodeView RSDS record */
  symbolServerId?: string;
  machine?: string;
  tpi?: { version: number; begin: number; end: number; records: number };
  ipi?: { version: number; begin: number; end: number; records: number };
  types: PdbType[];
  funcIds: PdbFuncId[];
  udts: PdbUdt[];
  globals: PdbGlobal[];
  procs: PdbProc[];
  modules: { index: number; name: string; objFile: string; symbolStream: number; symbolBytes: number }[];
  sections: { name: string; rva: number; size: number }[];
  warnings: string[];
  complete: boolean;
}

const MSF_MAGIC = 'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0';
const MAX_STREAMS = 65535;

/** True when the bytes start with the MSF 7.00 superblock magic. */
export function isPdb(b: Uint8Array): boolean {
  if (b.length < 56) return false;
  for (let i = 0; i < 32; i++) if (b[i] !== MSF_MAGIC.charCodeAt(i)) return false;
  return true;
}

class R {
  readonly b: Uint8Array; readonly v: DataView; pos: number;
  constructor(b: Uint8Array, pos = 0) { this.b = b; this.v = new DataView(b.buffer, b.byteOffset, b.byteLength); this.pos = pos; }
  need(n: number) { if (this.pos < 0 || this.pos + n > this.b.length) throw new RangeError('pdb: read past end'); }
  u8() { this.need(1); return this.b[this.pos++]!; }
  u16() { this.need(2); const x = this.v.getUint16(this.pos, true); this.pos += 2; return x; }
  i16() { this.need(2); const x = this.v.getInt16(this.pos, true); this.pos += 2; return x; }
  u32() { this.need(4); const x = this.v.getUint32(this.pos, true); this.pos += 4; return x; }
  i32() { this.need(4); const x = this.v.getInt32(this.pos, true); this.pos += 4; return x; }
  u64() { this.need(8); const x = Number(this.v.getBigUint64(this.pos, true)); this.pos += 8; return x; }
  i64() { this.need(8); const x = Number(this.v.getBigInt64(this.pos, true)); this.pos += 8; return x; }
  cstr(end = this.b.length) {
    const s = this.pos; const lim = Math.min(end, this.b.length);
    let i = s; while (i < lim && this.b[i] !== 0) i++;
    const out = utf8(this.b.subarray(s, i));
    this.pos = Math.min(lim, i + 1);
    return out;
  }
  /** CodeView numeric leaf */
  num(): number {
    const k = this.u16();
    if (k < 0x8000) return k;
    switch (k) {
      case 0x8000: { const x = this.u8(); return x > 127 ? x - 256 : x; }
      case 0x8001: return this.i16();
      case 0x8002: return this.u16();
      case 0x8003: return this.i32();
      case 0x8004: return this.u32();
      case 0x8009: return this.i64();
      case 0x800a: return this.u64();
      default: throw new RangeError(`pdb: numeric leaf 0x${k.toString(16)}`);
    }
  }
}

const td = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { fatal: false }) : undefined;
function utf8(b: Uint8Array): string { if (td) return td.decode(b); let s = ''; for (const c of b) s += String.fromCharCode(c); return s; }

/** MSF container: stream directory and stream reads. */
export class Msf {
  readonly blockSize: number;
  readonly sizes: number[] = [];
  private readonly blocks: number[][] = [];
  private readonly b: Uint8Array;
  constructor(b: Uint8Array) {
    if (!isPdb(b)) throw new Error('not a PDB (MSF 7.00 magic missing)');
    this.b = b;
    const r = new R(b, 32);
    const bs = r.u32(); r.u32(); const numBlocks = r.u32(); const dirBytes = r.u32(); r.u32(); const mapAddr = r.u32();
    if (![512, 1024, 2048, 4096, 8192, 16384, 32768].includes(bs)) throw new Error(`pdb: bad block size ${bs}`);
    this.blockSize = bs;
    if (numBlocks * bs > b.length + bs * 4) throw new Error('pdb: block count exceeds file size');
    if (dirBytes > b.length) throw new Error('pdb: directory larger than the file');
    const nDirBlocks = Math.ceil(dirBytes / bs);
    const mr = new R(b, mapAddr * bs);
    const dirBlocks: number[] = [];
    for (let i = 0; i < nDirBlocks; i++) dirBlocks.push(mr.u32());
    const dir = this.gather(dirBlocks, dirBytes);
    const dr = new R(dir);
    const n = dr.u32();
    if (n > MAX_STREAMS) throw new Error(`pdb: ${n} streams`);
    for (let i = 0; i < n; i++) { const s = dr.u32(); this.sizes.push(s === 0xffffffff ? 0 : s); }
    for (let i = 0; i < n; i++) {
      const cnt = Math.ceil(this.sizes[i]! / bs);
      if (cnt > numBlocks) throw new Error('pdb: stream larger than the file');
      const list: number[] = [];
      for (let k = 0; k < cnt; k++) list.push(dr.u32());
      this.blocks.push(list);
    }
  }
  private gather(blocks: number[], size: number): Uint8Array {
    const out = new Uint8Array(size);
    let o = 0;
    for (const blk of blocks) {
      const start = blk * this.blockSize;
      const n = Math.min(this.blockSize, size - o);
      if (start < 0 || start + n > this.b.length) throw new RangeError(`pdb: block ${blk} past end of file`);
      out.set(this.b.subarray(start, start + n), o);
      o += n;
    }
    return out;
  }
  get count() { return this.sizes.length; }
  stream(i: number): Uint8Array | undefined {
    if (i < 0 || i >= this.sizes.length || i === 0xffff) return undefined;
    return this.gather(this.blocks[i]!, this.sizes[i]!);
  }
}

// ---- type names ----
const SIMPLE: Record<number, string> = {
  0x00: '<none>', 0x03: 'void', 0x08: 'HRESULT', 0x10: 'signed char', 0x20: 'unsigned char', 0x68: 'int8_t', 0x69: 'uint8_t', 0x70: 'char', 0x71: 'wchar_t',
  0x7a: 'char16_t', 0x7b: 'char32_t', 0x7c: 'char8_t', 0x11: 'short', 0x21: 'unsigned short', 0x72: 'short', 0x73: 'unsigned short', 0x12: 'long', 0x22: 'unsigned long',
  0x74: 'int', 0x75: 'unsigned', 0x13: '__int64', 0x23: 'unsigned __int64', 0x76: '__int64', 0x77: 'unsigned __int64', 0x14: '__int128', 0x24: 'unsigned __int128',
  0x78: '__int128', 0x79: 'unsigned __int128', 0x40: 'float', 0x41: 'double', 0x42: 'long double', 0x43: '__float128', 0x46: '_Float16', 0x30: 'bool', 0x31: 'bool16', 0x32: 'bool32', 0x33: 'bool64',
};
const SIMPLE_SIZE: Record<number, number> = { 0x03: 0, 0x10: 1, 0x20: 1, 0x68: 1, 0x69: 1, 0x70: 1, 0x71: 2, 0x7a: 2, 0x7b: 4, 0x7c: 1, 0x11: 2, 0x21: 2, 0x72: 2, 0x73: 2, 0x12: 4, 0x22: 4, 0x74: 4, 0x75: 4, 0x13: 8, 0x23: 8, 0x76: 8, 0x77: 8, 0x14: 16, 0x24: 16, 0x78: 16, 0x79: 16, 0x40: 4, 0x41: 8, 0x42: 10, 0x30: 1, 0x08: 4 };
const CALLCONV: Record<number, string> = { 0: 'cdecl', 1: 'cdecl far', 2: 'pascal', 4: 'fastcall', 7: 'stdcall', 0x0b: 'thiscall', 0x11: 'mipscall', 0x12: 'generic', 0x16: 'armcall', 0x17: 'clrcall', 0x18: 'inline', 0x19: 'vectorcall', 0x1a: 'swift' };
const PTR_KIND: Record<number, string> = { 0x0a: 'ptr32', 0x0c: 'ptr64', 0x00: 'near16', 0x0b: 'unaligned', 0x0d: 'ptr128' };
const ACCESS = ['', 'private', 'protected', 'public'];
const REG_AMD64: Record<number, string> = { 0: 'none', 328: 'rax', 329: 'rbx', 330: 'rcx', 331: 'rdx', 332: 'rsi', 333: 'rdi', 334: 'rbp', 335: 'rsp', 336: 'r8', 337: 'r9', 338: 'r10', 339: 'r11', 340: 'r12', 341: 'r13', 342: 'r14', 343: 'r15', 344: 'r8b', 352: 'r8w', 360: 'r8d', 361: 'r9d', 362: 'r10d', 363: 'r11d', 364: 'r12d', 365: 'r13d', 366: 'r14d', 367: 'r15d', 17: 'eax', 18: 'ecx', 19: 'edx', 20: 'ebx', 21: 'esp', 22: 'ebp', 23: 'esi', 24: 'edi', 33: 'rip', 154: 'xmm0', 155: 'xmm1', 156: 'xmm2', 157: 'xmm3', 158: 'xmm4', 159: 'xmm5', 160: 'xmm6', 161: 'xmm7' };

export interface PdbOptions { budgetMs?: number; maxRecords?: number }

/** Reads a PDB file: info stream, TPI/IPI types, globals and module procedures. */
export function readPdb(bytes: Uint8Array, opts: PdbOptions = {}): PdbInfo {
  const out: PdbInfo = { valid: false, blockSize: 0, streams: 0, types: [], funcIds: [], udts: [], globals: [], procs: [], modules: [], sections: [], warnings: [], complete: true };
  const deadline = Date.now() + (opts.budgetMs ?? 20000);
  const maxRecords = opts.maxRecords ?? 1_000_000;
  const msf = new Msf(bytes);
  out.valid = true; out.blockSize = msf.blockSize; out.streams = msf.count;
  // PDB info stream
  try {
    const s = msf.stream(1);
    if (s && s.length >= 28) {
      const r = new R(s);
      out.version = r.u32(); out.signature = r.u32(); out.age = r.u32();
      const g = s.subarray(12, 28);
      const hex = (a: number, b: number, rev: boolean) => { const x = [...g.subarray(a, b)]; if (rev) x.reverse(); return x.map((c) => c.toString(16).padStart(2, '0')).join(''); };
      out.guid = `${hex(0, 4, true)}-${hex(4, 6, true)}-${hex(6, 8, true)}-${hex(8, 10, false)}-${hex(10, 16, false)}`.toUpperCase();
      out.symbolServerId = out.guid.replace(/-/g, '') + out.age.toString(16).toUpperCase();
    }
  } catch (e) { out.warnings.push('info stream: ' + (e as Error).message); }

  const types = new Map<number, PdbType>();
  const raw = new Map<number, { kind: number; data: Uint8Array }>();
  const ipiRaw = new Map<number, { kind: number; data: Uint8Array }>();
  const readTypeStream = (idx: number, into: Map<number, { kind: number; data: Uint8Array }>) => {
    const s = msf.stream(idx);
    if (!s || s.length < 56) return undefined;
    const r = new R(s);
    const version = r.u32(); const hdr = r.u32(); const begin = r.u32(); const end = r.u32(); const bytesLen = r.u32();
    if (hdr < 56 || hdr > s.length) throw new RangeError('pdb: bad TPI header size');
    let pos = hdr; let ti = begin;
    const stop = Math.min(s.length, hdr + bytesLen);
    while (pos + 4 <= stop && ti < end) {
      const len = s[pos]! | (s[pos + 1]! << 8);
      if (len < 2 || pos + 2 + len > stop) { out.warnings.push(`type record 0x${ti.toString(16)} overruns the stream`); out.complete = false; break; }
      const kind = s[pos + 2]! | (s[pos + 3]! << 8);
      into.set(ti, { kind, data: s.subarray(pos + 4, pos + 2 + len) });
      pos += 2 + len; ti++;
      if (into.size > maxRecords) { out.warnings.push('type record cap reached'); out.complete = false; break; }
      if ((ti & 4095) === 0 && Date.now() > deadline) { out.warnings.push('time budget reached in type stream'); out.complete = false; break; }
    }
    return { version, begin, end, records: into.size };
  };
  try { out.tpi = readTypeStream(2, raw); } catch (e) { out.warnings.push('TPI: ' + (e as Error).message); out.complete = false; }
  try { out.ipi = readTypeStream(4, ipiRaw); } catch (e) { out.warnings.push('IPI: ' + (e as Error).message); out.complete = false; }

  // ---- decode TPI leaves ----
  const fieldLists = new Map<number, PdbMember[] | PdbEnumerator[]>();
  const nameCache = new Map<number, string>();
  const name = (ti: number, depth = 0): string => {
    if (ti < 0x1000) {
      const mode = (ti >> 8) & 0xf;
      const base = SIMPLE[ti & 0xff] ?? `<simple 0x${(ti & 0xff).toString(16)}>`;
      return mode === 0 ? base : base + '*';
    }
    const c = nameCache.get(ti);
    if (c !== undefined) return c;
    if (depth > 24) return '...';
    nameCache.set(ti, '<recursive>');
    const t = types.get(ti) ?? decode(ti, depth + 1);
    const s = t?.display ?? `<type 0x${ti.toString(16)}>`;
    nameCache.set(ti, s);
    return s;
  };
  const decode = (ti: number, depth: number): PdbType | undefined => {
    const rec = raw.get(ti);
    if (!rec) return undefined;
    if (types.has(ti)) return types.get(ti);
    const r = new R(rec.data);
    const leaf = rec.kind;
    let t: PdbType;
    try {
      switch (leaf) {
        case 0x1505: case 0x1504: case 0x1519: { // LF_STRUCTURE, LF_CLASS, LF_INTERFACE
          const count = r.u16(); const prop = r.u16(); const fl = r.u32(); r.u32(); r.u32();
          const size = r.num(); const n = r.cstr();
          const uniq = prop & 0x200 ? r.cstr() : undefined;
          const kind = leaf === 0x1504 ? 'class' : 'struct';
          t = { index: ti, leaf: leaf === 0x1504 ? 'LF_CLASS' : 'LF_STRUCTURE', kind, name: n, display: n, size, ...(prop & 0x80 ? { forwardRef: true } : {}), ...(fl ? { fieldList: fl } : {}), ...(uniq ? { uniqueName: uniq } : {}) };
          void count;
          break;
        }
        case 0x1506: { // LF_UNION
          r.u16(); const prop = r.u16(); const fl = r.u32(); const size = r.num(); const n = r.cstr(); const uniq = prop & 0x200 ? r.cstr() : undefined;
          t = { index: ti, leaf: 'LF_UNION', kind: 'union', name: n, display: n, size, ...(prop & 0x80 ? { forwardRef: true } : {}), ...(fl ? { fieldList: fl } : {}), ...(uniq ? { uniqueName: uniq } : {}) };
          break;
        }
        case 0x1507: { // LF_ENUM
          r.u16(); const prop = r.u16(); const ut = r.u32(); const fl = r.u32(); const n = r.cstr();
          t = { index: ti, leaf: 'LF_ENUM', kind: 'enum', name: n, display: n, underlying: name(ut, depth), ...(prop & 0x80 ? { forwardRef: true } : {}), ...(fl ? { fieldList: fl } : {}) };
          break;
        }
        case 0x1002: { // LF_POINTER
          const ref = r.u32(); const attr = r.u32();
          const ptrKind = attr & 0x1f; const mode = (attr >> 5) & 7;
          const isConst = (attr >> 10) & 1, isVol = (attr >> 9) & 1;
          const inner = name(ref, depth);
          const sym = mode === 1 ? '&' : mode === 4 ? '&&' : mode === 2 || mode === 3 ? '::*' : '*';
          let display: string;
          const fnRef = raw.get(ref);
          if (fnRef && (fnRef.kind === 0x1008 || fnRef.kind === 0x1009)) { const f = decode(ref, depth); display = `${f?.returns ?? '?'} (${sym})(${(f?.params ?? []).join(', ')})`; }
          else display = inner + sym;
          if (isConst) display += ' const';
          if (isVol) display += ' volatile';
          t = { index: ti, leaf: 'LF_POINTER', kind: 'pointer', display, referent: ref, pointerKind: PTR_KIND[ptrKind] ?? String(ptrKind), size: (attr >> 13) & 0x3f };
          break;
        }
        case 0x1001: { // LF_MODIFIER
          const ref = r.u32(); const m = r.u16();
          const mods = [m & 1 ? 'const' : '', m & 2 ? 'volatile' : '', m & 4 ? '__unaligned' : ''].filter(Boolean);
          t = { index: ti, leaf: 'LF_MODIFIER', kind: 'modifier', display: `${mods.join(' ')} ${name(ref, depth)}`.trim(), referent: ref, modifiers: mods };
          break;
        }
        case 0x1008: { // LF_PROCEDURE
          const ret = r.u32(); const cc = r.u8(); r.u8(); r.u16(); const al = r.u32();
          const params = argList(al, depth);
          t = { index: ti, leaf: 'LF_PROCEDURE', kind: 'procedure', display: `${name(ret, depth)} (${params.join(', ')})`, returns: name(ret, depth), params, callConv: CALLCONV[cc] ?? String(cc) };
          break;
        }
        case 0x1009: { // LF_MFUNCTION
          const ret = r.u32(); const cls = r.u32(); const ths = r.u32(); const cc = r.u8(); r.u8(); r.u16(); const al = r.u32();
          const params = argList(al, depth);
          t = { index: ti, leaf: 'LF_MFUNCTION', kind: 'member-function', display: `${name(ret, depth)} ${name(cls, depth)}::(${params.join(', ')})`, returns: name(ret, depth), params, callConv: CALLCONV[cc] ?? String(cc), classType: name(cls, depth), ...(ths ? { thisType: name(ths, depth) } : {}) };
          break;
        }
        case 0x1201: { const n = r.u32(); const ps: string[] = []; for (let i = 0; i < Math.min(n, 4096); i++) ps.push(name(r.u32(), depth)); t = { index: ti, leaf: 'LF_ARGLIST', kind: 'arglist', display: `(${ps.join(', ')})`, params: ps }; break; }
        case 0x1503: { // LF_ARRAY
          const el = r.u32(); r.u32(); const size = r.num(); const n = r.cstr();
          const es = sizeOf(el, depth);
          const cnt = es ? Math.floor(size / es) : undefined;
          t = { index: ti, leaf: 'LF_ARRAY', kind: 'array', display: `${name(el, depth)}[${cnt ?? ''}]`, size, element: name(el, depth), ...(n ? { name: n } : {}) };
          break;
        }
        case 0x1205: { const bt = r.u32(); const len = r.u8(); const pos = r.u8(); t = { index: ti, leaf: 'LF_BITFIELD', kind: 'bitfield', display: `${name(bt, depth)} : ${len}`, bitSize: len, bitOffset: pos, referent: bt }; break; }
        case 0x1203: t = { index: ti, leaf: 'LF_FIELDLIST', kind: 'fieldlist', display: '<fieldlist>' }; break;
        case 0x1206: t = { index: ti, leaf: 'LF_METHODLIST', kind: 'methodlist', display: '<methodlist>' }; break;
        case 0x000a: t = { index: ti, leaf: 'LF_VTSHAPE', kind: 'vtshape', display: '<vtshape>' }; break;
        default: t = { index: ti, leaf: `0x${leaf.toString(16)}`, kind: 'other', display: `<leaf 0x${leaf.toString(16)}>` };
      }
    } catch (e) {
      t = { index: ti, leaf: `0x${leaf.toString(16)}`, kind: 'other', display: `<bad record 0x${ti.toString(16)}>` };
      out.warnings.push(`type 0x${ti.toString(16)}: ${(e as Error).message}`);
    }
    types.set(ti, t);
    return t;
  };
  const argList = (al: number, depth: number): string[] => {
    const rec = raw.get(al);
    if (!rec || rec.kind !== 0x1201) return [];
    const r = new R(rec.data);
    try { const n = r.u32(); const ps: string[] = []; for (let i = 0; i < Math.min(n, 4096); i++) ps.push(name(r.u32(), depth)); return ps; } catch { return []; }
  };
  function sizeOf(ti: number, depth: number): number | undefined {
    if (ti < 0x1000) return ((ti >> 8) & 0xf) ? 8 : SIMPLE_SIZE[ti & 0xff];
    const t = decode(ti, depth + 1);
    if (!t) return undefined;
    if (t.kind === 'modifier' && t.referent !== undefined && depth < 24) return sizeOf(t.referent, depth + 1);
    if ((t.kind === 'struct' || t.kind === 'class' || t.kind === 'union') && t.forwardRef) { const d = defByName.get(t.kind + ':' + (t.uniqueName ?? t.name)); if (d !== undefined) return decode(d, depth + 1)?.size; }
    if (t.kind === 'enum' && depth < 24) return 4;
    return t.size;
  }
  const decodeFieldList = (fl: number, isEnum: boolean): PdbMember[] | PdbEnumerator[] => {
    const cached = fieldLists.get(fl);
    if (cached) return cached;
    const members: PdbMember[] = []; const enums: PdbEnumerator[] = [];
    let cur: number | undefined = fl;
    const seen = new Set<number>();
    while (cur !== undefined && !seen.has(cur) && seen.size < 64) {
      seen.add(cur);
      const rec = raw.get(cur);
      cur = undefined;
      if (!rec || rec.kind !== 0x1203) break;
      const r = new R(rec.data);
      try {
        while (r.pos < rec.data.length) {
          const b0 = rec.data[r.pos]!;
          if (b0 >= 0xf0) { r.pos += b0 & 0x0f; continue; }
          const k = r.u16();
          if (k === 0x150d) { const attr = r.u16(); const ty = r.u32(); const off = r.num(); const n = r.cstr(); const m: PdbMember = { kind: 'member', name: n, type: name(ty, 1), typeIndex: ty, offset: off, access: ACCESS[attr & 3] }; const bt = types.get(ty) ?? decode(ty, 1); if (bt?.kind === 'bitfield') { m.bitSize = bt.bitSize; m.bitOffset = off * 8 + (bt.bitOffset ?? 0); m.type = name(bt.referent!, 1); } members.push(m); }
          else if (k === 0x1502) { r.u16(); const v = r.num(); enums.push({ name: r.cstr(), value: v }); }
          else if (k === 0x150e) { const attr = r.u16(); const ty = r.u32(); members.push({ kind: 'static', name: r.cstr(), type: name(ty, 1), typeIndex: ty, access: ACCESS[attr & 3] }); }
          else if (k === 0x1400) { const attr = r.u16(); const ty = r.u32(); const off = r.num(); members.push({ kind: 'base', name: name(ty, 1), type: name(ty, 1), typeIndex: ty, offset: off, access: ACCESS[attr & 3] }); }
          else if (k === 0x1401 || k === 0x1402) { const attr = r.u16(); const ty = r.u32(); r.u32(); r.num(); r.num(); members.push({ kind: 'vbase', name: name(ty, 1), type: name(ty, 1), typeIndex: ty, access: ACCESS[attr & 3] }); }
          else if (k === 0x1409) { r.u16(); const ty = r.u32(); members.push({ kind: 'vfptr', name: '__vfptr', type: name(ty, 1), typeIndex: ty, offset: 0 }); }
          else if (k === 0x1510) { r.u16(); const ty = r.u32(); members.push({ kind: 'nested', name: r.cstr(), type: name(ty, 1), typeIndex: ty }); }
          else if (k === 0x1511) { const attr = r.u16(); const ty = r.u32(); const mprop = (attr >> 2) & 7; if (mprop === 4 || mprop === 6) r.u32(); members.push({ kind: 'method', name: r.cstr(), type: name(ty, 1), typeIndex: ty, access: ACCESS[attr & 3] }); }
          else if (k === 0x150f) { const cnt = r.u16(); const ml = r.u32(); const n = r.cstr(); members.push({ kind: 'method', name: n, type: `<${cnt} overloads>`, typeIndex: ml }); }
          else if (k === 0x1404) { r.u16(); cur = r.u32(); }
          else { out.warnings.push(`field list 0x${fl.toString(16)}: unknown member leaf 0x${k.toString(16)}`); break; }
        }
      } catch (e) { out.warnings.push(`field list 0x${fl.toString(16)}: ${(e as Error).message}`); }
    }
    const res = isEnum ? enums : members;
    fieldLists.set(fl, res);
    return res;
  };
  const defByName = new Map<string, number>();
  for (const [ti, rec] of raw) {
    if (![0x1505, 0x1504, 0x1506, 0x1507, 0x1519].includes(rec.kind)) continue;
    const t = decode(ti, 0);
    if (t && !t.forwardRef) { const k = t.kind + ':' + (t.uniqueName ?? t.name); if (!defByName.has(k)) defByName.set(k, ti); }
  }
  for (const ti of raw.keys()) {
    if ((ti & 1023) === 0 && Date.now() > deadline) { out.warnings.push('time budget reached decoding types'); out.complete = false; break; }
    const t = decode(ti, 0);
    if (!t) continue;
    if ((t.kind === 'struct' || t.kind === 'class' || t.kind === 'union' || t.kind === 'enum')) {
      if (t.forwardRef) { const d = defByName.get(t.kind + ':' + (t.uniqueName ?? t.name)); if (d !== undefined) t.definition = d; }
      else if (t.fieldList !== undefined) {
        const f = decodeFieldList(t.fieldList, t.kind === 'enum');
        if (t.kind === 'enum') t.enumerators = (f as PdbEnumerator[]).map((e) => ({ name: e.name, value: signExtend(e.value, t.underlying) }));
        else t.members = f as PdbMember[];
      }
    }
  }
  out.types = [...types.values()].sort((a, b) => a.index - b.index);

  // ---- IPI: function ids ----
  const ipiStr = new Map<number, string>();
  for (const [ti, rec] of ipiRaw) {
    const r = new R(rec.data);
    try {
      if (rec.kind === 0x1605) { r.u32(); ipiStr.set(ti, r.cstr()); }
      else if (rec.kind === 0x1601) { const scope = r.u32(); const ty = r.u32(); const n = r.cstr(); out.funcIds.push({ index: ti, name: n, type: name(ty), typeIndex: ty, ...(scope ? { scope: ipiStr.get(scope) ?? `0x${scope.toString(16)}` } : {}) }); }
      else if (rec.kind === 0x1602) { const cls = r.u32(); const ty = r.u32(); const n = r.cstr(); out.funcIds.push({ index: ti, name: n, type: name(ty), typeIndex: ty, className: name(cls) }); }
    } catch { /* skip bad id record */ }
  }

  // ---- DBI: modules, section headers, global symbols ----
  let symRecordStream = -1;
  try {
    const s = msf.stream(3);
    if (s && s.length >= 64) {
      const r = new R(s);
      r.i32(); r.u32(); r.u32(); r.u16();
      r.u16(); r.u16(); r.u16(); symRecordStream = r.u16(); r.u16();
      const modInfoSize = r.i32(); const secContribSize = r.i32(); const secMapSize = r.i32(); const srcInfoSize = r.i32();
      const tsmSize = r.i32(); r.u32(); const optDbgSize = r.i32(); const ecSize = r.i32(); r.u16(); const machine = r.u16(); r.u32();
      out.machine = machine === 0x8664 ? 'x64' : machine === 0x14c ? 'x86' : machine === 0xaa64 ? 'arm64' : machine === 0x1c4 ? 'arm' : `0x${machine.toString(16)}`;
      let pos = 64;
      const modEnd = pos + Math.max(0, modInfoSize);
      while (pos + 64 <= modEnd && out.modules.length < 100000) {
        const mr = new R(s, pos);
        mr.u32(); mr.pos += 28; mr.u16(); mr.u16(); mr.u32(); mr.u32(); mr.u32();
        mr.pos = pos + 34; const symStream = mr.u16(); const symBytes = mr.u32(); mr.pos = pos + 64;
        const nm = mr.cstr(modEnd); const obj = mr.cstr(modEnd);
        out.modules.push({ index: out.modules.length, name: nm, objFile: obj, symbolStream: symStream, symbolBytes: symBytes });
        pos = (mr.pos + 3) & ~3;
      }
      const optPos = 64 + modInfoSize + secContribSize + secMapSize + srcInfoSize + tsmSize + ecSize;
      if (optDbgSize >= 22 && optPos + optDbgSize <= s.length) {
        const secHdrStream = new R(s, optPos + 10).u16();
        const sh = secHdrStream !== 0xffff ? msf.stream(secHdrStream) : undefined;
        if (sh) for (let o = 0; o + 40 <= sh.length && out.sections.length < 1024; o += 40) {
          const hr = new R(sh, o);
          let n = ''; for (let i = 0; i < 8 && sh[o + i]; i++) n += String.fromCharCode(sh[o + i]!);
          hr.pos = o + 8; const vsize = hr.u32(); const va = hr.u32();
          out.sections.push({ name: n, rva: va, size: vsize });
        }
      }
    }
  } catch (e) { out.warnings.push('DBI: ' + (e as Error).message); }
  const rvaOf = (seg: number, off: number) => (seg >= 1 && seg <= out.sections.length ? out.sections[seg - 1]!.rva + off : undefined);

  const parseSyms = (s: Uint8Array, start: number, module: number | undefined) => {
    let pos = start;
    let curProc: PdbProc | undefined;
    let depth = 0;
    let n = 0;
    while (pos + 4 <= s.length) {
      const len = s[pos]! | (s[pos + 1]! << 8);
      if (len < 2 || pos + 2 + len > s.length) break;
      const kind = s[pos + 2]! | (s[pos + 3]! << 8);
      const r = new R(s.subarray(pos + 4, pos + 2 + len));
      pos += 2 + len;
      if (++n > maxRecords || ((n & 4095) === 0 && Date.now() > deadline)) { out.warnings.push('symbol record cap or time budget reached'); out.complete = false; break; }
      try {
        switch (kind) {
          case 0x1108: { const ti = r.u32(); out.udts.push({ name: r.cstr(), typeIndex: ti, type: name(ti) }); break; } // S_UDT
          case 0x110d: case 0x110c: { const ti = r.u32(); const off = r.u32(); const seg = r.u16(); out.globals.push({ name: r.cstr(), kind: kind === 0x110d ? 'S_GDATA32' : 'S_LDATA32', typeIndex: ti, type: name(ti), segment: seg, offset: off, rva: rvaOf(seg, off), ...(module !== undefined ? { module } : {}) }); break; }
          case 0x1107: { const ti = r.u32(); const v = r.num(); out.globals.push({ name: r.cstr(), kind: 'S_CONSTANT', typeIndex: ti, type: name(ti), value: v }); break; }
          case 0x110e: { r.u32(); const off = r.u32(); const seg = r.u16(); out.globals.push({ name: r.cstr(), kind: 'S_PUB32', segment: seg, offset: off, rva: rvaOf(seg, off) }); break; }
          case 0x1125: case 0x1127: { r.u32(); r.u32(); const mod = r.u16(); out.globals.push({ name: r.cstr(), kind: kind === 0x1125 ? 'S_PROCREF' : 'S_LPROCREF', module: mod }); break; }
          case 0x1110: case 0x110f: case 0x1146: case 0x1147: { // S_GPROC32, S_LPROC32, _ID variants
            r.u32(); r.u32(); r.u32(); const size = r.u32(); r.u32(); r.u32(); const ti = r.u32(); const off = r.u32(); const seg = r.u16(); r.u8(); const nm = r.cstr();
            let typeIdx = ti;
            if (kind === 0x1146 || kind === 0x1147) { const f = out.funcIds.find((x) => x.index === ti); if (f) typeIdx = f.typeIndex; }
            curProc = { name: nm, kind: kind === 0x1110 || kind === 0x1147 ? 'S_GPROC32' : 'S_LPROC32', segment: seg, offset: off, rva: rvaOf(seg, off), size, type: name(typeIdx), typeIndex: typeIdx, prototype: '', locals: [], module: module ?? -1 };
            out.procs.push(curProc); depth = 1;
            break;
          }
          case 0x1103: case 0x1104: case 0x1102: case 0x114d: case 0x115d: depth++; break; // block, with, thunk and inline site scopes
          case 0x0006: case 0x114f: case 0x114e: depth--; if (depth <= 0) curProc = undefined; break; // S_END, S_PROC_ID_END, S_INLINESITE_END
          case 0x113e: { if (!curProc) break; const ti = r.u32(); const flags = r.u16(); curProc.locals.push({ name: r.cstr(), type: name(ti), param: (flags & 1) !== 0 }); break; } // S_LOCAL
          case 0x1141: { const l = curProc?.locals[curProc.locals.length - 1]; if (l && l.register === undefined) l.register = REG_AMD64[r.u16()] ?? undefined; break; } // S_DEFRANGE_REGISTER
          case 0x1144: { const l = curProc?.locals[curProc.locals.length - 1]; if (l) l.frameOffset = r.i32(); break; } // S_DEFRANGE_FRAMEPOINTER_REL
          case 0x1142: { const l = curProc?.locals[curProc.locals.length - 1]; if (l) l.frameOffset = r.i32(); break; } // S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE
          case 0x1111: { if (!curProc) break; const off = r.i32(); const ti = r.u32(); const reg = r.u16(); curProc.locals.push({ name: r.cstr(), type: name(ti), param: false, register: REG_AMD64[reg], frameOffset: off }); break; } // S_REGREL32
          default: break;
        }
      } catch { /* skip bad symbol */ }
    }
  };
  if (symRecordStream >= 0 && symRecordStream !== 0xffff) { const s = msf.stream(symRecordStream); if (s) parseSyms(s, 0, undefined); }
  for (const m of out.modules) {
    if (Date.now() > deadline) { out.complete = false; break; }
    if (m.symbolStream === 0xffff) continue;
    const s = msf.stream(m.symbolStream);
    if (s && s.length > 4) parseSyms(s.subarray(0, Math.min(s.length, m.symbolBytes || s.length)), 4, m.index);
  }
  for (const p of out.procs) {
    const t = types.get(p.typeIndex);
    const params = p.locals.filter((l) => l.param);
    const ps = (t?.params ?? []).map((ty, i) => (params[i] ? `${ty} ${params[i]!.name}` : ty));
    p.prototype = `${t?.returns ?? 'int'} ${p.name}(${ps.join(', ')})`;
  }
  return out;
}

function signExtend(v: number, underlying: string | undefined): number {
  if (!underlying || /unsigned|uint|bool/.test(underlying)) return v;
  const bits = /char|int8/.test(underlying) ? 8 : /short|int16/.test(underlying) ? 16 : /__int64|long long|int64/.test(underlying) ? 64 : 32;
  if (bits < 64 && v >= 2 ** (bits - 1) && v < 2 ** bits) return v - 2 ** bits;
  return v;
}

/** C text for a struct, class, union or enum read from a PDB. */
export function pdbTypeDecl(t: PdbType): string {
  const kw = t.kind === 'class' ? 'class' : t.kind === 'union' ? 'union' : t.kind === 'enum' ? 'enum' : 'struct';
  if (t.enumerators) return `${kw} ${t.name}${t.underlying ? ' : ' + t.underlying : ''} {\n${t.enumerators.map((e) => `  ${e.name} = ${e.value},`).join('\n')}\n};`;
  if (t.members) {
    const lines = t.members.map((m) => {
      if (m.kind === 'base') return `  // base ${m.type} at offset ${m.offset}`;
      if (m.kind === 'method') return `  ${m.type.startsWith('<') ? '' : ''}${m.name}(); // method ${m.type}`;
      if (m.kind === 'nested') return `  // nested ${m.name}`;
      if (m.kind === 'vfptr') return `  void **__vfptr; // offset 0`;
      const decl = /\(\*\)/.test(m.type) ? m.type.replace('(*)', `(*${m.name})`) : /\[\d*\]$/.test(m.type) ? m.type.replace(/(\[\d*\])$/, ` ${m.name}$1`) : `${m.type} ${m.name}`;
      return `  ${m.kind === 'static' ? 'static ' : ''}${decl}${m.bitSize !== undefined ? ' : ' + m.bitSize : ''};${m.offset !== undefined ? ` // offset ${m.offset}` : ''}`;
    });
    return `${kw} ${t.name} {${t.size !== undefined ? ` // size ${t.size}` : ''}\n${lines.join('\n')}\n};`;
  }
  return t.display;
}
