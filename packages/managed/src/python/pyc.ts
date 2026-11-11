// .pyc header parsing, magic number to version mapping and a dis-like disassembler.
import { ByteReader, ParseError, LIMITS, hex } from '../util.js';
import { unmarshal, isCode, pyRepr, toJsonValue, type PyCode, type PyValue } from './marshal.js';
import { PY_OPCODES, type PyOpcodeTable } from './opcodes.js';

/** Magic number ranges from CPython Lib/importlib/_bootstrap_external.py. */
const MAGIC_RANGES: [number, number, string][] = [
  [20121, 20121, '1.5'], [50428, 50428, '1.6'], [50823, 50823, '2.0'], [60202, 60202, '2.1'], [60717, 60717, '2.2'],
  [62011, 62021, '2.3'], [62041, 62061, '2.4'], [62071, 62131, '2.5'], [62151, 62161, '2.6'], [62171, 62211, '2.7'],
  [3000, 3131, '3.0'], [3141, 3151, '3.1'], [3160, 3180, '3.2'], [3190, 3230, '3.3'], [3250, 3310, '3.4'], [3320, 3351, '3.5'],
  [3360, 3379, '3.6'], [3390, 3399, '3.7'], [3400, 3419, '3.8'], [3420, 3429, '3.9'], [3430, 3449, '3.10'], [3450, 3499, '3.11'],
  [3500, 3549, '3.12'], [3550, 3599, '3.13'], [3600, 3699, '3.14'], [3700, 3799, '3.15'],
];

/** Final release magic per version (used when rebuilding headers). */
export const PYC_MAGIC: Record<string, number> = { '3.6': 3379, '3.7': 3394, '3.8': 3413, '3.9': 3425, '3.10': 3439, '3.11': 3495, '3.12': 3531, '3.13': 3571 };

export function versionForMagic(magic: number): string | undefined {
  for (const [lo, hi, v] of MAGIC_RANGES) if (magic >= lo && magic <= hi) return v;
  return undefined;
}

export const SUPPORTED_VERSIONS = Object.keys(PY_OPCODES);

/** 16 byte .pyc header for a version: magic, flags 0, mtime 0, size 0. */
export function pycHeader(version: string, sourceSize = 0): Uint8Array {
  const magic = PYC_MAGIC[version];
  if (magic === undefined) throw new ParseError(`no pyc magic for Python ${version}`);
  const h = new Uint8Array(16);
  const dv = new DataView(h.buffer);
  dv.setUint16(0, magic, true); h[2] = 0x0d; h[3] = 0x0a;
  dv.setUint32(12, sourceSize >>> 0, true);
  return h;
}

export interface PycHeader { magic: number; version?: string; flags: number; hashBased: boolean; checkSource: boolean; mtime?: number; sourceSize?: number; sourceHash?: string; headerSize: number }

export function isPyc(bytes: Uint8Array): boolean {
  if (bytes.length < 16 || bytes[2] !== 0x0d || bytes[3] !== 0x0a) return false;
  return versionForMagic((bytes[0] as number) | ((bytes[1] as number) << 8)) !== undefined;
}

export function parsePycHeader(bytes: Uint8Array): PycHeader {
  const r = new ByteReader(bytes);
  const magic = r.u16();
  if (r.u8() !== 0x0d || r.u8() !== 0x0a) throw new ParseError('bad pyc magic terminator');
  const version = versionForMagic(magic);
  const minor = version ? Number(version.split('.')[1]) : 0;
  const major = version ? Number(version.split('.')[0]) : 3;
  if (major === 3 && minor >= 7) {
    const flags = r.u32();
    if (flags & 1) return { magic, version, flags, hashBased: true, checkSource: (flags & 2) !== 0, sourceHash: hex(r.take(8)), headerSize: 16 };
    return { magic, version, flags, hashBased: false, checkSource: true, mtime: r.u32(), sourceSize: r.u32(), headerSize: 16 };
  }
  if (major === 3 && minor >= 3) return { magic, version, flags: 0, hashBased: false, checkSource: true, mtime: r.u32(), sourceSize: r.u32(), headerSize: 12 };
  return { magic, version, flags: 0, hashBased: false, checkSource: true, mtime: r.u32(), headerSize: 8 };
}

export interface PyInstruction {
  offset: number;
  opcode: number;
  opname: string;
  arg?: number;
  argval?: string | number | boolean | null;
  argrepr?: string;
  /** jump target byte offset */
  target?: number;
  /** offset of the first EXTENDED_ARG prefix, when present */
  start?: number;
}

function table(version: string): PyOpcodeTable {
  const t = PY_OPCODES[version];
  if (!t) throw new ParseError(`no opcode table for Python ${version} (supported ${SUPPORTED_VERSIONS.join(', ')})`);
  return t;
}

/**
 * Disassemble one code object's bytecode like dis.get_instructions (caches and EXTENDED_ARG folded in).
 * Argument values follow the per version rules of CPython's dis module.
 */
export function disassemble(code: PyCode, version: string, max = LIMITS.maxInstructions): { instructions: PyInstruction[]; error?: string } {
  const t = table(version);
  const minor = Number(version.split('.')[1]);
  const sets = {
    c: new Set(t.hasconst), n: new Set(t.hasname), jr: new Set(t.hasjrel), ja: new Set(t.hasjabs), l: new Set(t.haslocal), f: new Set(t.hasfree), cmp: new Set(t.hascompare), arg: new Set(t.hasarg),
  };
  const hasArg = (op: number) => (minor >= 12 ? sets.arg.has(op) : op >= (t.haveArgument ?? 90));
  const b = code.code;
  const out: PyInstruction[] = [];
  let ext = 0;
  let extStart = -1;
  const cellAndFree = [...code.cellvars, ...code.freevars];
  const local = (i: number) => (minor >= 11 ? code.localsplusnames?.[i] : code.varnames[i]);
  for (let i = 0; i + 1 < b.length; ) {
    if (out.length >= max) return { instructions: out, error: 'instruction cap reached' };
    const offset = i;
    const op = b[i] as number;
    const raw = b[i + 1] as number;
    i += 2;
    const name = t.names[op];
    if (name === undefined) return { instructions: out, error: `unknown opcode ${op} at offset ${offset}` };
    const caches = t.cache[op] ?? 0;
    if (name === 'CACHE') { continue; }
    const argFull = hasArg(op) ? raw | ext : undefined;
    if (op === t.extendedArg) {
      ext = ((raw | ext) << 8) >>> 0;
      if (extStart < 0) extStart = offset;
      i += caches * 2;
      // dis lists EXTENDED_ARG as its own instruction
      out.push({ offset, opcode: op, opname: name, arg: argFull });
      continue;
    }
    ext = 0;
    const ins: PyInstruction = { offset, opcode: op, opname: name };
    if (argFull !== undefined) {
      const arg = argFull;
      ins.arg = arg;
      if (extStart >= 0) ins.start = extStart;
      if (sets.c.has(op)) {
        const v = code.consts[arg] as PyValue | undefined;
        ins.argrepr = v === undefined ? `<const ${arg}>` : pyRepr(v);
        ins.argval = v === undefined || (typeof v === 'object' && v !== null) ? ins.argrepr : v;
      } else if (sets.n.has(op)) {
        let idx = arg;
        let extra = '';
        if (minor >= 11 && name === 'LOAD_GLOBAL') { idx = arg >> 1; if (arg & 1) extra = 'NULL'; }
        else if (minor >= 12 && name === 'LOAD_ATTR') { idx = arg >> 1; if (arg & 1) extra = 'NULL|self'; }
        else if (minor >= 12 && name === 'LOAD_SUPER_ATTR') { idx = arg >> 2; if (arg & 1) extra = 'NULL|self'; }
        const nm = code.names[idx] ?? `<name ${idx}>`;
        ins.argval = nm;
        // 3.11 and 3.12 print the NULL push first, 3.13 after the name.
        ins.argrepr = !extra ? nm : minor >= 13 ? `${nm} + ${extra}` : `${extra} + ${nm}`;
      } else if (sets.l.has(op)) {
        if (minor >= 13 && (name === 'LOAD_FAST_LOAD_FAST' || name === 'STORE_FAST_STORE_FAST' || name === 'STORE_FAST_LOAD_FAST')) {
          const a = local(arg >> 4), c = local(arg & 15);
          ins.argval = `${a}, ${c}`; ins.argrepr = `${a}, ${c}`;
        } else {
          const nm = local(arg);
          ins.argval = nm ?? `<local ${arg}>`; ins.argrepr = ins.argval as string;
        }
      } else if (sets.f.has(op)) {
        const nm = minor >= 11 ? code.localsplusnames?.[arg] : cellAndFree[arg];
        ins.argval = nm ?? `<free ${arg}>`; ins.argrepr = ins.argval as string;
      } else if (sets.cmp.has(op)) {
        const idx = minor >= 13 ? arg >> 5 : minor >= 12 ? arg >> 4 : arg;
        ins.argval = t.cmpOp[idx] ?? `<cmp ${idx}>`; ins.argrepr = ins.argval as string;
        if (minor >= 13 && arg & 16) ins.argrepr = `bool(${ins.argrepr})`;
      } else if (sets.jr.has(op) || sets.ja.has(op)) {
        let target: number;
        if (sets.ja.has(op)) target = minor >= 10 ? arg * 2 : arg;
        else {
          const backward = minor >= 11 && name.includes('JUMP_BACKWARD');
          const delta = minor >= 10 ? arg * 2 : arg;
          target = offset + 2 + (backward ? -delta : delta);
          if (minor >= 12) target += caches * 2;
        }
        ins.target = target; ins.argval = target; ins.argrepr = `to ${target}`;
      } else if (name === 'BINARY_OP' && t.nbOps.length) {
        ins.argval = arg; ins.argrepr = t.nbOps[arg] ?? String(arg);
      } else {
        ins.argval = arg;
      }
    }
    extStart = -1;
    i += caches * 2;
    out.push(ins);
  }
  return { instructions: out };
}

export interface PycFile {
  header: PycHeader;
  version: string;
  code: PyCode;
}

/** Parse a .pyc file (header + marshalled module code object). */
export function parsePyc(bytes: Uint8Array, versionOverride?: string): PycFile {
  const header = parsePycHeader(bytes);
  const version = versionOverride ?? header.version;
  if (!version) throw new ParseError(`unknown pyc magic ${header.magic}`);
  if (!PY_OPCODES[version]) throw new ParseError(`Python ${version} bytecode is not supported (supported ${SUPPORTED_VERSIONS.join(', ')})`);
  const { value } = unmarshal(bytes, { minor: Number(version.split('.')[1]) }, header.headerSize);
  if (!isCode(value)) throw new ParseError('pyc body is not a code object');
  return { header, version, code: value };
}

export interface CodeSummary {
  path: string;
  name: string;
  qualname: string;
  firstlineno: number;
  argcount: number;
  posonlyargcount: number;
  kwonlyargcount: number;
  stacksize: number;
  flags: number;
  flagNames: string[];
  codeSize: number;
  names: string[];
  varnames: string[];
  freevars: string[];
  cellvars: string[];
  consts: unknown[];
  children: string[];
}

const CO_FLAGS: Record<number, string> = { 0x1: 'OPTIMIZED', 0x2: 'NEWLOCALS', 0x4: 'VARARGS', 0x8: 'VARKEYWORDS', 0x10: 'NESTED', 0x20: 'GENERATOR', 0x40: 'NOFREE', 0x80: 'COROUTINE', 0x100: 'ITERABLE_COROUTINE', 0x200: 'ASYNC_GENERATOR' };

/** Walk the code object tree, depth first, with a path like module/<func>/<lambda>. */
export function walkCode(root: PyCode, visit: (c: PyCode, path: string, depth: number) => void, maxDepth = LIMITS.maxDepth, maxNodes = 50000): void {
  let n = 0;
  const go = (c: PyCode, path: string, depth: number) => {
    if (depth > maxDepth || n++ >= maxNodes) return;
    visit(c, path, depth);
    for (const k of c.consts) if (isCode(k)) go(k, `${path}/${k.name}`, depth + 1);
  };
  go(root, root.name, 0);
}

export function summarizeCode(c: PyCode, path: string): CodeSummary {
  const flagNames: string[] = [];
  for (const [k, v] of Object.entries(CO_FLAGS)) if (c.flags & Number(k)) flagNames.push(v);
  return {
    path, name: c.name, qualname: c.qualname, firstlineno: c.firstlineno, argcount: c.argcount, posonlyargcount: c.posonlyargcount, kwonlyargcount: c.kwonlyargcount,
    stacksize: c.stacksize, flags: c.flags, flagNames, codeSize: c.code.length, names: c.names, varnames: c.varnames, freevars: c.freevars, cellvars: c.cellvars,
    consts: c.consts.map((x) => toJsonValue(x, 0, 50)), children: c.consts.filter(isCode).map((k) => k.name),
  };
}

/** dis-like text for a code tree. */
export function disText(root: PyCode, version: string, opts: { maxLines?: number } = {}): string {
  const maxLines = opts.maxLines ?? 20000;
  const lines: string[] = [];
  walkCode(root, (c, path) => {
    if (lines.length >= maxLines) return;
    lines.push(`Disassembly of ${path} (${c.filename}, line ${c.firstlineno}):`);
    const d = disassemble(c, version);
    const targets = new Set(d.instructions.map((i) => i.target).filter((x): x is number => x !== undefined));
    for (const ins of d.instructions) {
      if (lines.length >= maxLines) { lines.push('... output truncated'); return; }
      const mark = targets.has(ins.offset) ? '>>' : '  ';
      const arg = ins.arg === undefined ? '' : String(ins.arg).padStart(5);
      lines.push(`  ${mark} ${String(ins.offset).padStart(6)} ${ins.opname.padEnd(24)}${arg}${ins.argrepr ? ` (${ins.argrepr})` : ''}`);
    }
    if (d.error) lines.push(`  ; ${d.error}`);
    lines.push('');
  });
  return lines.join('\n');
}
