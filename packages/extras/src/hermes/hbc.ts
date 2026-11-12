// Hermes bytecode (HBC) reader and disassembler for bytecode versions 84 to 96, with best effort
// support for the Static Hermes versions 97 to 99. Layouts follow Hermes's BytecodeFileFormat.h
// (MIT); opcode tables are generated from BytecodeList.def by scripts/gen_hermes_opcodes.py.
// Every read is bounds checked and every table is capped.

import { ParseError } from '../util.js';
import { OPERAND_TYPES, TABLES, VERSION_TABLE } from './opcodes.js';

export const HBC_MAGIC_LO = 0x03bc1fc6, HBC_MAGIC_HI = 0x1f1903c1;
export const HBC_DELTA_MAGIC_LO = 0xfc43e039, HBC_DELTA_MAGIC_HI = 0xe0e6fc3e;

export type OperandType = typeof OPERAND_TYPES[number];
export interface OpcodeDef { code: number; name: string; operands: OperandType[]; ids: Record<number, 's' | 'b' | 'f'> }
export interface HbcHeader {
  version: number; sourceHash: string; fileLength: number; globalCodeIndex: number; functionCount: number;
  stringKindCount: number; identifierCount: number; stringCount: number; overflowStringCount: number; stringStorageSize: number;
  bigIntCount: number; bigIntStorageSize: number; regExpCount: number; regExpStorageSize: number;
  arrayBufferSize: number; objKeyBufferSize: number; objValueBufferSize: number; objShapeTableCount: number; numStringSwitchImms: number;
  segmentID: number; cjsModuleCount: number; functionSourceCount: number; debugInfoOffset: number;
  options: { staticBuiltins: boolean; cjsModulesStaticallyResolved: boolean; hasAsync: boolean; raw: number };
}
export interface HbcFunction {
  index: number; name: string; nameId: number; offset: number; size: number; paramCount: number; frameSize: number;
  environmentSize: number; readCacheIndex: number; writeCacheIndex: number; infoOffset: number;
  prohibitInvoke: number; strictMode: boolean; hasExceptionHandler: boolean; hasDebugInfo: boolean; overflowed: boolean; headerOffset: number;
  /** Static Hermes (97+) only */
  numberRegCount?: number; nonPtrRegCount?: number; loopDepth?: number;
}
export interface HbcString { id: number; kind: 'ASCII' | 'UTF-16'; identifier: boolean; offset: number; length: number; value: string }
export interface HbcOperand { type: OperandType; value: number; text?: string; kind?: 'string' | 'bigint' | 'function' }
export interface HbcInsn { offset: number; opcode: number; name: string; size: number; operands: HbcOperand[]; target?: number }

const SIZES: Record<OperandType, number> = { Reg8: 1, Reg32: 4, UInt8: 1, UInt16: 2, UInt32: 4, Addr8: 1, Addr32: 4, Imm32: 4, Double: 8 };
const tableCache = new Map<number, OpcodeDef[]>();

/** Opcode table of a bytecode version, or undefined when the version is not known. */
export function opcodeTable(version: number): OpcodeDef[] | undefined {
  const t = VERSION_TABLE[version];
  if (t === undefined) return undefined;
  let defs = tableCache.get(t);
  if (!defs) {
    defs = TABLES[t]!.map((e, code) => {
      const [sig, idPart] = e.split('|');
      const [name, ops] = sig!.split(':');
      const ids: Record<number, 's' | 'b' | 'f'> = {};
      for (const x of idPart ? idPart.split(',') : []) ids[Number(x.slice(1)) - 1] = x[0] as 's' | 'b' | 'f';
      return { code, name: name!, operands: ops ? ops.split(',').map((i) => OPERAND_TYPES[Number(i)]!) : [], ids };
    });
    tableCache.set(t, defs);
  }
  return defs;
}
export const SUPPORTED_HBC_VERSIONS = Object.keys(VERSION_TABLE).map(Number);

/** True when the bytes start with the Hermes bytecode magic (or the delta form). */
export function isHbc(b: Uint8Array): boolean {
  if (b.length < 12) return false;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const lo = dv.getUint32(0, true), hi = dv.getUint32(4, true);
  return (lo === HBC_MAGIC_LO && hi === HBC_MAGIC_HI) || (lo === HBC_DELTA_MAGIC_LO && hi === HBC_DELTA_MAGIC_HI);
}

const align4 = (n: number) => (n + 3) & ~3;

export class HbcFile {
  readonly bytes: Uint8Array;
  readonly dv: DataView;
  readonly header: HbcHeader;
  readonly functions: HbcFunction[] = [];
  readonly notes: string[] = [];
  readonly layout: Record<string, { offset: number; size: number }> = {};
  readonly opcodes: OpcodeDef[] | undefined;
  private stringTableOff = 0; private overflowOff = 0; private storageOff = 0; private kindsOff = 0;
  private kindRuns: { count: number; identifier: boolean }[] = [];
  private stringCache = new Map<number, HbcString>();

  constructor(bytes: Uint8Array, opts: { maxFunctions?: number } = {}) {
    this.bytes = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (!isHbc(bytes)) throw new ParseError('not Hermes bytecode (bad magic)');
    if (this.u32(0) === HBC_DELTA_MAGIC_LO) throw new ParseError('Hermes delta bytecode prepare files are not supported');
    const version = this.u32(8);
    const sh = (version >= 97 && version <= 99) ? 'sh' : 'classic';
    if (version < 84 || version > 99) this.notes.push(`bytecode version ${version} is outside the tested range 84-99; header read with the version 96 layout`);
    let p = 32; // after magic, version and the 20 byte source hash
    const next = () => { const v = this.u32(p); p += 4; return v; };
    const h: Partial<HbcHeader> = { version, sourceHash: [...bytes.subarray(12, 32)].map((x) => x.toString(16).padStart(2, '0')).join('') };
    h.fileLength = next(); h.globalCodeIndex = next(); h.functionCount = next(); h.stringKindCount = next(); h.identifierCount = next();
    h.stringCount = next(); h.overflowStringCount = next(); h.stringStorageSize = next();
    h.bigIntCount = 0; h.bigIntStorageSize = 0; h.objShapeTableCount = 0; h.numStringSwitchImms = 0; h.objValueBufferSize = 0;
    if (version >= 87) { h.bigIntCount = next(); h.bigIntStorageSize = next(); }
    h.regExpCount = next(); h.regExpStorageSize = next();
    if (sh === 'sh' && version >= 99) { h.arrayBufferSize = next(); h.objKeyBufferSize = next(); h.objShapeTableCount = next(); h.numStringSwitchImms = next(); }
    else { h.arrayBufferSize = next(); h.objKeyBufferSize = next(); h.objValueBufferSize = next(); }
    h.segmentID = next(); h.cjsModuleCount = next(); h.functionSourceCount = next(); h.debugInfoOffset = next();
    const opt = this.u8(p);
    h.options = { staticBuiltins: (opt & 1) !== 0, cjsModulesStaticallyResolved: (opt & 2) !== 0, hasAsync: (opt & 4) !== 0, raw: opt };
    this.header = h as HbcHeader;
    this.opcodes = opcodeTable(version);
    if (!this.opcodes) this.notes.push(`no opcode table for version ${version}; disassembly is unavailable`);
    this.layoutSections(128, sh, opts.maxFunctions ?? 2_000_000);
  }

  u8(o: number): number { if (o < 0 || o >= this.bytes.length) throw new ParseError('read out of range', o); return this.bytes[o]!; }
  u16(o: number): number { if (o < 0 || o + 2 > this.bytes.length) throw new ParseError('read out of range', o); return this.dv.getUint16(o, true); }
  u32(o: number): number { if (o < 0 || o + 4 > this.bytes.length) throw new ParseError('read out of range', o); return this.dv.getUint32(o, true); }
  i32(o: number): number { if (o < 0 || o + 4 > this.bytes.length) throw new ParseError('read out of range', o); return this.dv.getInt32(o, true); }

  private layoutSections(start: number, sh: 'sh' | 'classic', maxFunctions: number): void {
    const h = this.header;
    const fhSize = sh === 'sh' ? 12 : 16;
    let p = start;
    const sect = (name: string, size: number) => { p = align4(p); if (size < 0 || p + size > this.bytes.length) throw new ParseError(`${name} section out of range (${size} bytes at 0x${p.toString(16)})`); this.layout[name] = { offset: p, size }; const at = p; p += size; return at; };
    const fhOff = sect('functionHeaders', h.functionCount * fhSize);
    this.kindsOff = sect('stringKinds', h.stringKindCount * 4);
    sect('identifierHashes', h.identifierCount * 4);
    this.stringTableOff = sect('stringTable', h.stringCount * 4);
    this.overflowOff = sect('overflowStringTable', h.overflowStringCount * 8);
    this.storageOff = sect('stringStorage', h.stringStorageSize);
    sect('arrayBuffer', h.arrayBufferSize);
    sect('objKeyBuffer', h.objKeyBufferSize);
    if (sh === 'sh' && h.version >= 99) sect('objShapeTable', h.objShapeTableCount * 8);
    else sect('objValueBuffer', h.objValueBufferSize);
    if (h.version >= 87) { sect('bigIntTable', h.bigIntCount * 8); sect('bigIntStorage', h.bigIntStorageSize); }
    sect('regExpTable', h.regExpCount * 8);
    sect('regExpStorage', h.regExpStorageSize);
    sect('cjsModuleTable', h.cjsModuleCount * 8);
    sect('functionSourceTable', h.functionSourceCount * 8);
    let total = 0;
    for (let i = 0; i < h.stringKindCount && i < 1_000_000; i++) {
      const e = this.u32(this.kindsOff + i * 4);
      const run = { count: e & 0x7fffffff, identifier: (e >>> 31) === 1 };
      this.kindRuns.push(run); total += run.count;
    }
    if (total !== h.stringCount) this.notes.push(`string kind runs cover ${total} of ${h.stringCount} strings`);
    const n = Math.min(h.functionCount, maxFunctions);
    if (n < h.functionCount) this.notes.push(`function list capped at ${n} of ${h.functionCount}`);
    for (let i = 0; i < n; i++) {
      try { this.functions.push(this.readFunction(i, fhOff + i * fhSize, sh)); }
      catch (e) { this.notes.push(`function ${i}: ${(e as Error).message}`); break; }
    }
  }

  private readFunction(index: number, o: number, sh: 'sh' | 'classic'): HbcFunction {
    const w0 = this.u32(o), w1 = this.u32(o + 4);
    let f: HbcFunction;
    if (sh === 'classic') {
      const w2 = this.u32(o + 8), flags = this.u8(o + 15);
      f = {
        index, name: '', nameId: w1 >>> 15, offset: w0 & 0x1ffffff, size: w1 & 0x7fff, paramCount: w0 >>> 25, frameSize: w2 >>> 25,
        infoOffset: w2 & 0x1ffffff, environmentSize: this.u8(o + 12), readCacheIndex: this.u8(o + 13), writeCacheIndex: this.u8(o + 14),
        prohibitInvoke: flags & 3, strictMode: (flags & 4) !== 0, hasExceptionHandler: (flags & 8) !== 0, hasDebugInfo: (flags & 16) !== 0, overflowed: (flags & 32) !== 0, headerOffset: o,
      };
      if (f.overflowed) {
        const L = f.infoOffset * 65536 + (f.offset & 0xffff);
        const lf = this.u8(L + 30);
        f = {
          index, name: '', offset: this.u32(L), paramCount: this.u32(L + 4), size: this.u32(L + 8), nameId: this.u32(L + 12), infoOffset: this.u32(L + 16),
          frameSize: this.u32(L + 20), environmentSize: this.u32(L + 24), readCacheIndex: this.u8(L + 28), writeCacheIndex: this.u8(L + 29),
          prohibitInvoke: lf & 3, strictMode: (lf & 4) !== 0, hasExceptionHandler: (lf & 8) !== 0, hasDebugInfo: (lf & 16) !== 0, overflowed: true, headerOffset: L,
        };
      }
    } else {
      // Static Hermes small header: Offset:25 ParamCount:5 LoopDepth:2 | Size:14 Name:8 NumberRegs:5 NonPtrRegs:5 | FrameSize ReadCache WriteCache flags
      const flags = this.u8(o + 11);
      f = {
        index, name: '', offset: w0 & 0x1ffffff, paramCount: (w0 >>> 25) & 0x1f, size: w1 & 0x3fff, nameId: (w1 >>> 14) & 0xff, infoOffset: 0,
        frameSize: this.u8(o + 8), environmentSize: 0, readCacheIndex: this.u8(o + 9), writeCacheIndex: this.u8(o + 10) & 0x7f,
        prohibitInvoke: flags & 3, strictMode: (flags & 4) !== 0, hasExceptionHandler: (flags & 8) !== 0, hasDebugInfo: (flags & 16) !== 0, overflowed: (flags & 32) !== 0, headerOffset: o,
        numberRegCount: (w1 >>> 22) & 0x1f, nonPtrRegCount: (w1 >>> 27) & 0x1f, loopDepth: (w0 >>> 30) & 3,
      };
      if (f.overflowed) {
        const L = ((((w1 >>> 14) & 0xff) << 25) | (w0 & 0x1ffffff)) >>> 0;
        const lf = this.u8(L + 35);
        f = { ...f, offset: this.u32(L), paramCount: this.u32(L + 4), loopDepth: this.u32(L + 8), size: this.u32(L + 12), nameId: this.u32(L + 16), numberRegCount: this.u32(L + 20), nonPtrRegCount: this.u32(L + 24), frameSize: this.u32(L + 28),
          readCacheIndex: this.u8(L + 32), writeCacheIndex: this.u8(L + 33), prohibitInvoke: lf & 3, strictMode: (lf & 4) !== 0, hasExceptionHandler: (lf & 8) !== 0, hasDebugInfo: (lf & 16) !== 0, headerOffset: L };
        this.notes.push(`function ${index}: Static Hermes overflow header read best effort`);
      }
    }
    if (f.offset + f.size > this.bytes.length) throw new ParseError(`bytecode of function ${index} out of range`);
    f.name = this.stringValue(f.nameId);
    return f;
  }

  /** One string table entry, decoded. */
  string(id: number): HbcString {
    const hit = this.stringCache.get(id);
    if (hit) return hit;
    if (!Number.isInteger(id) || id < 0 || id >= this.header.stringCount) throw new ParseError(`string id ${id} out of range`);
    const e = this.u32(this.stringTableOff + id * 4);
    const utf16 = (e & 1) === 1;
    let offset = (e >>> 1) & 0x7fffff, length = e >>> 24;
    if (length === 255) {
      const ov = this.overflowOff + offset * 8;
      offset = this.u32(ov); length = this.u32(ov + 4);
    }
    const start = this.storageOff + offset;
    const bytesLen = utf16 ? length * 2 : length;
    if (start + bytesLen > this.storageOff + this.header.stringStorageSize || bytesLen > 64 << 20) throw new ParseError(`string ${id} out of range`);
    let value = '';
    if (utf16) { for (let i = 0; i < length; i++) value += String.fromCharCode(this.dv.getUint16(start + i * 2, true)); }
    else { const b = this.bytes.subarray(start, start + length); for (let i = 0; i < b.length; i++) value += String.fromCharCode(b[i]!); }
    let identifier = false, acc = 0;
    for (const r of this.kindRuns) { if (id < acc + r.count) { identifier = r.identifier; break; } acc += r.count; }
    const s: HbcString = { id, kind: utf16 ? 'UTF-16' : 'ASCII', identifier, offset, length, value };
    if (this.stringCache.size < 100000) this.stringCache.set(id, s);
    return s;
  }
  stringValue(id: number): string { try { return this.string(id).value; } catch { return `<string ${id}>`; } }

  /** Exception handler table of a function (empty when it has none). */
  exceptionHandlers(f: HbcFunction): { start: number; end: number; target: number }[] {
    if (!f.hasExceptionHandler || this.header.version >= 97) return [];
    let p = align4(f.infoOffset);
    const n = Math.min(this.u32(p), 65536);
    p += 4;
    const out: { start: number; end: number; target: number }[] = [];
    for (let i = 0; i < n; i++) out.push({ start: this.u32(p + i * 12), end: this.u32(p + i * 12 + 4), target: this.u32(p + i * 12 + 8) });
    return out;
  }

  /** Decode the instructions of a function. */
  disassemble(f: HbcFunction, opts: { maxInsns?: number } = {}): { insns: HbcInsn[]; complete: boolean; error?: string } {
    const ops = this.opcodes;
    if (!ops) return { insns: [], complete: false, error: `no opcode table for version ${this.header.version}` };
    const out: HbcInsn[] = [];
    const max = opts.maxInsns ?? 200000;
    let p = f.offset;
    const end = f.offset + f.size;
    while (p < end) {
      if (out.length >= max) return { insns: out, complete: false };
      const code = this.bytes[p]!;
      const def = ops[code];
      if (!def) return { insns: out, complete: false, error: `unknown opcode 0x${code.toString(16)} at offset ${p - f.offset}` };
      let q = p + 1;
      const operands: HbcOperand[] = [];
      for (let k = 0; k < def.operands.length; k++) {
        const t = def.operands[k]!;
        const sz = SIZES[t];
        if (q + sz > end) return { insns: out, complete: false, error: `truncated instruction at offset ${p - f.offset}` };
        let v: number;
        switch (t) {
          case 'Reg8': case 'UInt8': v = this.bytes[q]!; break;
          case 'Addr8': v = (this.bytes[q]! << 24) >> 24; break;
          case 'UInt16': v = this.dv.getUint16(q, true); break;
          case 'Reg32': case 'UInt32': v = this.dv.getUint32(q, true); break;
          case 'Addr32': case 'Imm32': v = this.dv.getInt32(q, true); break;
          case 'Double': v = this.dv.getFloat64(q, true); break;
        }
        const o: HbcOperand = { type: t, value: v };
        const idk = def.ids[k];
        if (idk === 's') { o.kind = 'string'; o.text = this.stringValue(v); }
        else if (idk === 'f') { o.kind = 'function'; const fn = this.functions[v]; o.text = fn ? fn.name : `<function ${v}>`; }
        else if (idk === 'b') o.kind = 'bigint';
        operands.push(o);
        q += sz;
      }
      const insn: HbcInsn = { offset: p - f.offset, opcode: code, name: def.name, size: q - p, operands };
      const ai = def.operands.findIndex((t) => t === 'Addr8' || t === 'Addr32');
      if (ai >= 0) insn.target = insn.offset + operands[ai]!.value;
      out.push(insn);
      p = q;
    }
    return { insns: out, complete: true };
  }
}

/** Hermes style %e formatting of a double (six digits, two digit exponent). */
export function formatDouble(v: number): string {
  if (Number.isNaN(v)) return 'nan';
  if (!Number.isFinite(v)) return v > 0 ? 'inf' : '-inf';
  const s = v.toExponential(6);
  const m = /^(-?\d\.\d+)e([+-])(\d+)$/.exec(s);
  if (!m) return s;
  return `${m[1]}e${m[2]}${m[3]!.padStart(2, '0')}`;
}

/** One instruction as hbcdump -raw-disassemble prints it. */
export function rawInsnText(i: HbcInsn): string {
  const ops = i.operands.map((o) => `${o.type === 'Double' ? formatDouble(o.value) : o.value}<${o.type}>`).join(', ');
  return `[@ ${i.offset}] ${i.name}${ops ? ' ' + ops : ''}`;
}

/** Function heading as hbcdump prints it. */
export function functionHeading(f: HbcFunction): string {
  if (f.numberRegCount !== undefined) return `${f.prohibitInvoke === 1 ? 'NC' : ''}Function<${f.name}>${f.index}(${f.paramCount} params, ${f.frameSize} registers, ${f.numberRegCount} numbers, ${f.nonPtrRegCount} non-pointers):`;
  return `${f.prohibitInvoke === 1 ? 'NC' : ''}Function<${f.name}>${f.index}(${f.paramCount} params, ${f.frameSize} registers, ${f.environmentSize} symbols):`;
}

/** Readable instruction text with string and function operands resolved, for agents. */
export function prettyInsnText(i: HbcInsn): string {
  const ops = i.operands.map((o) => {
    if (o.kind === 'string') return JSON.stringify(o.text ?? '');
    if (o.kind === 'function') return `${o.text ?? 'fn'}#${o.value}`;
    if (o.type === 'Reg8' || o.type === 'Reg32') return `r${o.value}`;
    if (o.type === 'Addr8' || o.type === 'Addr32') return `L${i.offset + o.value}`;
    if (o.type === 'Double') return String(o.value);
    return String(o.value);
  });
  return `${i.name}${ops.length ? ' ' + ops.join(', ') : ''}`;
}
