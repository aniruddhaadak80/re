// Parsers for radare2 and rizin JSON commands (aflj, pdfj, pdgj, axtj, izj, iij, ij).
// radare2 names the address field `addr`, rizin uses `offset`; both are accepted.
import { bool, extractJson, hex, num, str, PARSE_LIMITS } from './common.js';

export interface R2Function {
  name: string;
  address: string;
  size: number;
  basicBlocks?: number;
  instructions?: number;
  signature?: string;
  callingConvention?: string;
  calls?: number;
  calledBy?: number;
  noreturn?: boolean;
}

export interface R2Instruction {
  address: string;
  size?: number;
  bytes?: string;
  text: string;
  type?: string;
  jump?: string;
  comment?: string;
}

export interface R2Disassembly {
  name?: string;
  address?: string;
  size?: number;
  instructions: R2Instruction[];
}

export interface R2Xref {
  from: string;
  type?: string;
  opcode?: string;
  function?: string;
  functionAddress?: string;
}

export interface R2String {
  value: string;
  vaddr?: string;
  paddr?: string;
  length?: number;
  size?: number;
  type?: string;
  section?: string;
}

export interface R2Import {
  name: string;
  library?: string;
  plt?: string;
  bind?: string;
  type?: string;
  ordinal?: number;
}

export interface R2Info {
  file?: string;
  format?: string;
  size?: number;
  arch?: string;
  bits?: number;
  os?: string;
  machine?: string;
  type?: string;
  lang?: string;
  endian?: string;
  compiler?: string;
  stripped?: boolean;
  canary?: boolean;
  nx?: boolean;
  pic?: boolean;
  relro?: string;
  baddr?: string;
}

function asArray(v: unknown, key?: string): unknown[] {
  if (Array.isArray(v)) return v.slice(0, PARSE_LIMITS.maxItems);
  if (key && v && typeof v === 'object' && Array.isArray((v as Record<string, unknown>)[key])) {
    return ((v as Record<string, unknown>)[key] as unknown[]).slice(0, PARSE_LIMITS.maxItems);
  }
  return [];
}

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function addrOf(o: Record<string, unknown>): string | undefined {
  return hex(o.addr ?? o.offset);
}

/** Parse `aflj` output. Accepts the raw text or already parsed JSON. */
export function parseR2Functions(input: string | unknown): R2Function[] {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const out: R2Function[] = [];
  for (const it of asArray(data, 'functions')) {
    const o = obj(it);
    const address = addrOf(o);
    const name = str(o.name, 1024);
    if (!address || !name) continue;
    const f: R2Function = { name, address, size: num(o.size) ?? num(o.realsz) ?? 0 };
    const nb = num(o.nbbs); if (nb !== undefined) f.basicBlocks = nb;
    const ni = num(o.ninstrs); if (ni !== undefined) f.instructions = ni;
    const sig = str(o.signature, 2048); if (sig) f.signature = sig;
    const cc = str(o.calltype ?? o.cc_name, 64); if (cc) f.callingConvention = cc;
    const outd = num(o.outdegree); if (outd !== undefined) f.calls = outd;
    const ind = num(o.indegree); if (ind !== undefined) f.calledBy = ind;
    const nr = bool(o.noreturn); if (nr !== undefined) f.noreturn = nr;
    out.push(f);
  }
  out.sort((a, b) => (parseInt(a.address, 16) - parseInt(b.address, 16)));
  return out;
}

/** Parse `pdfj` (one function) or `pdj` (an instruction list). */
export function parseR2Disasm(input: string | unknown): R2Disassembly {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const top = obj(data);
  const ops = Array.isArray(data) ? asArray(data) : asArray(top.ops);
  const instructions: R2Instruction[] = [];
  for (const it of ops) {
    const o = obj(it);
    const address = addrOf(o);
    if (!address) continue;
    const text = str(o.disasm, 512) ?? str(o.opcode, 512) ?? (o.type === 'invalid' ? 'invalid' : '');
    const ins: R2Instruction = { address, text };
    const sz = num(o.size); if (sz !== undefined) ins.size = sz;
    const by = str(o.bytes, 64); if (by && /^[0-9a-f]*$/i.test(by)) ins.bytes = by.toLowerCase();
    const ty = str(o.type, 32); if (ty) ins.type = ty;
    const j = hex(o.jump); if (j) ins.jump = j;
    const c = str(o.comment, 512); if (c) ins.comment = c;
    instructions.push(ins);
  }
  const res: R2Disassembly = { instructions };
  const name = str(top.name, 1024); if (name) res.name = name;
  const address = addrOf(top); if (address) res.address = address;
  const size = num(top.size); if (size !== undefined) res.size = size;
  return res;
}

/** Parse `pdgj` (r2ghidra / rz-ghidra JSON). Returns the C text, or undefined. */
export function parseR2Decompile(input: string | unknown): string | undefined {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const code = str(obj(data).code, 4 * 1024 * 1024);
  return code && code.trim() ? code : undefined;
}

/** Parse `axtj` (references to an address). */
export function parseR2Xrefs(input: string | unknown): R2Xref[] {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const out: R2Xref[] = [];
  for (const it of asArray(data)) {
    const o = obj(it);
    const from = hex(o.from);
    if (!from) continue;
    const x: R2Xref = { from };
    const ty = str(o.type, 32); if (ty) x.type = ty;
    const op = str(o.opcode, 512); if (op) x.opcode = op;
    const fn = str(o.fcn_name ?? o.realname, 1024); if (fn) x.function = fn;
    const fa = hex(o.fcn_addr); if (fa) x.functionAddress = fa;
    out.push(x);
  }
  return out;
}

/** Parse `izj` / `izzj` (strings). */
export function parseR2Strings(input: string | unknown): R2String[] {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const out: R2String[] = [];
  for (const it of asArray(data, 'strings')) {
    const o = obj(it);
    const value = str(o.string, 8192);
    if (value === undefined) continue;
    const s: R2String = { value };
    const va = hex(o.vaddr); if (va) s.vaddr = va;
    const pa = hex(o.paddr); if (pa) s.paddr = pa;
    const len = num(o.length); if (len !== undefined) s.length = len;
    const sz = num(o.size); if (sz !== undefined) s.size = sz;
    const ty = str(o.type, 32); if (ty) s.type = ty;
    const se = str(o.section, 128); if (se) s.section = se;
    out.push(s);
  }
  return out;
}

/** Parse `iij` (imports). */
export function parseR2Imports(input: string | unknown): R2Import[] {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const out: R2Import[] = [];
  for (const it of asArray(data, 'imports')) {
    const o = obj(it);
    const name = str(o.name, 1024);
    if (!name) continue;
    const im: R2Import = { name };
    const lib = str(o.libname, 512); if (lib) im.library = lib;
    const plt = hex(o.plt); if (plt && plt !== '0x0') im.plt = plt;
    const b = str(o.bind, 32); if (b) im.bind = b;
    const t = str(o.type, 32); if (t) im.type = t;
    const ord = num(o.ordinal); if (ord !== undefined) im.ordinal = ord;
    out.push(im);
  }
  return out;
}

/** Parse `ij` (binary info). */
export function parseR2Info(input: string | unknown): R2Info {
  const data = obj(typeof input === 'string' ? extractJson(input) : input);
  const core = obj(data.core);
  const bin = obj(data.bin);
  const info: R2Info = {};
  const set = <K extends keyof R2Info>(k: K, v: R2Info[K] | undefined) => { if (v !== undefined) info[k] = v; };
  set('file', str(core.file, 4096));
  set('format', str(core.format, 64));
  set('size', num(core.size));
  set('arch', str(bin.arch, 64));
  set('bits', num(bin.bits));
  set('os', str(bin.os, 64));
  set('machine', str(bin.machine, 128));
  set('type', str(bin.bintype, 64));
  set('lang', str(bin.lang, 64));
  set('endian', str(bin.endian, 16));
  set('compiler', str(bin.compiler, 256));
  set('stripped', bool(bin.stripped));
  set('canary', bool(bin.canary));
  set('nx', bool(bin.nx));
  set('pic', bool(bin.pic));
  set('relro', str(bin.relro, 32));
  set('baddr', hex(bin.baddr));
  return info;
}
