// Lua bytecode listing for PUC Lua 5.1 to 5.4 and LuaJIT 2.0 / 2.1 dumps (string.dump / luac output).
import { ByteReader, ParseError, LIMITS, latin1 } from '../util.js';

const OPS: Record<string, string[]> = {
  '5.1': 'MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORLOOP SETLIST CLOSE CLOSURE VARARG'.split(' '),
  '5.2': 'MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG'.split(' '),
  '5.3': 'MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR UNM BNOT NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG'.split(' '),
  '5.4': 'MOVE LOADI LOADF LOADK LOADKX LOADFALSE LFALSESKIP LOADTRUE LOADNIL GETUPVAL SETUPVAL GETTABUP GETTABLE GETI GETFIELD SETTABUP SETTABLE SETI SETFIELD NEWTABLE SELF ADDI ADDK SUBK MULK MODK POWK DIVK IDIVK BANDK BORK BXORK SHRI SHLI ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR MMBIN MMBINI MMBINK UNM BNOT NOT LEN CONCAT CLOSE TBC JMP EQ LT LE EQK EQI LTI LEI GTI GEI TEST TESTSET CALL TAILCALL RETURN RETURN0 RETURN1 FORLOOP FORPREP TFORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG VARARGPREP EXTRAARG'.split(' '),
};
const LJ_OPS_21 = 'ISLT ISGE ISLE ISGT ISEQV ISNEV ISEQS ISNES ISEQN ISNEN ISEQP ISNEP ISTC ISFC IST ISF ISTYPE ISNUM MOV NOT UNM LEN ADDVN SUBVN MULVN DIVVN MODVN ADDNV SUBNV MULNV DIVNV MODNV ADDVV SUBVV MULVV DIVVV MODVV POW CAT KSTR KCDATA KSHORT KNUM KPRI KNIL UGET USETV USETS USETN USETP UCLO FNEW TNEW TDUP GGET GSET TGETV TGETS TGETB TGETR TSETV TSETS TSETB TSETM TSETR CALLM CALL CALLMT CALLT ITERC ITERN VARG ISNEXT RETM RET RET0 RET1 FORI JFORI FORL IFORL JFORL ITERL IITERL JITERL LOOP ILOOP JLOOP JMP FUNCF IFUNCF JFUNCF FUNCV IFUNCV JFUNCV FUNCC FUNCCW'.split(' ');
const LJ_OPS_20 = LJ_OPS_21.filter((n) => !['ISTYPE', 'ISNUM', 'TGETR', 'TSETR'].includes(n));

// Operand shapes: Bx / sBx / Ax / sJ ops, everything else is A B C.
const BX = new Set(['LOADK', 'GETGLOBAL', 'SETGLOBAL', 'CLOSURE', 'LOADKX']);
const SBX_OLD = new Set(['JMP', 'FORLOOP', 'FORPREP', 'TFORLOOP']);
const BX54 = new Set(['LOADK', 'LOADKX', 'CLOSURE', 'FORLOOP', 'FORPREP', 'TFORPREP', 'TFORLOOP']);
const SBX54 = new Set(['LOADI', 'LOADF']);

export type LuaConst = null | boolean | number | string | { int: string } | { proto: number };

export interface LuaInstruction { pc: number; word: number; op: string; opcode: number; a: number; b?: number; c?: number; bx?: number; sbx?: number; k?: number; d?: number; comment?: string }

export interface LuaFunction {
  path: string;
  source?: string;
  lineDefined: number;
  lastLineDefined: number;
  numParams: number;
  isVararg: boolean;
  maxStack: number;
  numUpvalues: number;
  instructions: LuaInstruction[];
  constants: LuaConst[];
  upvalueNames: string[];
  locals: string[];
  children: LuaFunction[];
  /** file offset where this function starts */
  offset: number;
}

export interface LuaChunk {
  flavor: 'puc' | 'luajit';
  version: string;
  format?: number;
  header: Record<string, unknown>;
  main: LuaFunction;
  functionCount: number;
  stripped: boolean;
}

export function isLuaBytecode(b: Uint8Array): boolean {
  return b.length > 5 && b[0] === 0x1b && ((b[1] === 0x4c && b[2] === 0x75 && b[3] === 0x61) || (b[1] === 0x4c && b[2] === 0x4a));
}

/** Parse a Lua or LuaJIT bytecode dump. */
export function parseLua(bytes: Uint8Array): LuaChunk {
  if (!isLuaBytecode(bytes)) throw new ParseError('not a Lua bytecode dump (expected ESC Lua or ESC LJ)');
  if (bytes[1] === 0x4c && bytes[2] === 0x4a) return parseLuaJit(bytes);
  const v = bytes[4] as number;
  const version = `${v >> 4}.${v & 0xf}`;
  if (!OPS[version]) throw new ParseError(`unsupported Lua version ${version}`);
  const st = new State(bytes, version);
  return st.chunk();
}

class State {
  r: ByteReader;
  sizeInt = 4; sizeT = 8; sizeIns = 4; sizeNum = 8; sizeInteger = 8; integral = false;
  count = 0;
  stripped = true;
  constructor(bytes: Uint8Array, readonly version: string) { this.r = new ByteReader(bytes); }

  chunk(): LuaChunk {
    const r = this.r;
    r.skip(5);
    const format = r.u8();
    const header: Record<string, unknown> = { format };
    if (this.version === '5.1' || this.version === '5.2') {
      const endian = r.u8();
      this.r.little = endian === 1;
      this.sizeInt = r.u8(); this.sizeT = r.u8(); this.sizeIns = r.u8(); this.sizeNum = r.u8(); this.integral = r.u8() === 1;
      if (this.version === '5.2') r.skip(6);
      Object.assign(header, { littleEndian: endian === 1, sizeofInt: this.sizeInt, sizeofSizeT: this.sizeT, sizeofInstruction: this.sizeIns, sizeofNumber: this.sizeNum, integralNumbers: this.integral });
    } else {
      r.skip(6); // LUAC_DATA
      if (this.version === '5.3') { this.sizeInt = r.u8(); this.sizeT = r.u8(); }
      this.sizeIns = r.u8(); this.sizeInteger = r.u8(); this.sizeNum = r.u8();
      // LUAC_INT 0x5678 tells the byte order.
      const intBytes = r.take(this.sizeInteger);
      this.r.little = intBytes[0] === 0x78;
      r.skip(this.sizeNum);
      Object.assign(header, { littleEndian: this.r.little, sizeofInt: this.sizeInt, sizeofSizeT: this.sizeT, sizeofInstruction: this.sizeIns, sizeofInteger: this.sizeInteger, sizeofNumber: this.sizeNum });
      header.mainUpvalues = r.u8();
    }
    for (const s of [this.sizeInt, this.sizeT, this.sizeIns, this.sizeNum]) if (![4, 8].includes(s)) throw new ParseError(`unsupported Lua type size ${s}`);
    const main = this.func('main', undefined, 0);
    return { flavor: 'puc', version: this.version, format, header, main, functionCount: this.count, stripped: this.stripped };
  }

  int(): number { return this.sizeInt === 8 ? Number(this.r.i64()) : this.r.i32(); }
  sizet(): number { return this.sizeT === 8 ? Number(this.r.u64()) : this.r.u32(); }
  varint(): number {
    let x = 0, b = 0, n = 0;
    do { b = this.r.u8(); x = x * 128 + (b & 0x7f); if (++n > 9) throw new ParseError('varint too long', this.r.pos); } while ((b & 0x80) === 0);
    return x;
  }
  count32(): number {
    const n = this.version === '5.4' ? this.varint() : this.int();
    if (n < 0 || n > this.r.remaining() + 1) throw new ParseError(`bad count ${n}`, this.r.pos);
    return n;
  }
  str(): string | undefined {
    let size: number;
    if (this.version === '5.4') { size = this.varint(); if (size === 0) return undefined; size -= 1; return latin1(this.r.take(size)); }
    if (this.version === '5.3') { size = this.r.u8(); if (size === 0xff) size = this.sizet(); if (size === 0) return undefined; return latin1(this.r.take(size - 1)); }
    size = this.sizet();
    if (size === 0) return undefined;
    const s = this.r.take(size);
    return latin1(s.subarray(0, size - 1));
  }
  num(): number { return this.sizeNum === 8 ? this.r.f64() : this.r.f32(); }
  integer(): LuaConst { const v = this.sizeInteger === 8 ? this.r.i64() : BigInt(this.r.i32()); return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : { int: v.toString() }; }

  func(path: string, parentSource: string | undefined, depth: number): LuaFunction {
    if (depth > LIMITS.maxDepth) throw new ParseError('Lua function nesting too deep');
    if (++this.count > 100000) throw new ParseError('too many Lua functions');
    const r = this.r;
    const v = this.version;
    const offset = r.pos;
    let source: string | undefined;
    if (v === '5.1' || v === '5.3' || v === '5.4') source = this.str();
    const lineDefined = v === '5.4' ? this.varint() : this.int();
    const lastLineDefined = v === '5.4' ? this.varint() : this.int();
    let numUpvalues = 0;
    if (v === '5.1') numUpvalues = r.u8();
    const numParams = r.u8();
    const isVararg = r.u8() !== 0;
    const maxStack = r.u8();
    const ncode = this.count32();
    if (ncode > LIMITS.maxInstructions * 5) throw new ParseError('too many instructions');
    const words: number[] = [];
    for (let i = 0; i < ncode; i++) words.push(r.u32());
    const constants: LuaConst[] = [];
    const children: LuaFunction[] = [];
    const nk = this.count32();
    for (let i = 0; i < nk; i++) {
      const t = r.u8();
      if (v === '5.4') {
        if (t === 0x00) constants.push(null);
        else if (t === 0x01) constants.push(false);
        else if (t === 0x11) constants.push(true);
        else if (t === 0x03) constants.push(this.integer());
        else if (t === 0x13) constants.push(this.num());
        else if (t === 0x04 || t === 0x14) constants.push(this.str() ?? '');
        else throw new ParseError(`bad Lua 5.4 constant tag 0x${t.toString(16)}`, r.pos - 1);
      } else if (v === '5.3') {
        if (t === 0) constants.push(null);
        else if (t === 1) constants.push(r.u8() !== 0);
        else if (t === 3) constants.push(this.num());
        else if (t === 0x13) constants.push(this.integer());
        else if (t === 4 || t === 0x14) constants.push(this.str() ?? '');
        else throw new ParseError(`bad Lua 5.3 constant tag ${t}`, r.pos - 1);
      } else {
        if (t === 0) constants.push(null);
        else if (t === 1) constants.push(r.u8() !== 0);
        else if (t === 3) constants.push(this.integral ? Number(this.sizeNum === 8 ? r.i64() : r.i32()) : this.num());
        else if (t === 4) constants.push(this.str() ?? '');
        else throw new ParseError(`bad Lua constant tag ${t}`, r.pos - 1);
      }
    }
    const readUpvalDesc = () => {
      const n = this.count32();
      for (let i = 0; i < n; i++) { r.u8(); r.u8(); if (v === '5.4') r.u8(); }
      return n;
    };
    const readProtos = (src: string | undefined) => {
      const n = this.count32();
      for (let i = 0; i < n; i++) children.push(this.func(`${path}/${i + 1}`, src, depth + 1));
    };
    const upvalueNames: string[] = [];
    const locals: string[] = [];
    if (v === '5.2') { readProtos(parentSource); numUpvalues = readUpvalDesc(); }
    else if (v === '5.3' || v === '5.4') { numUpvalues = readUpvalDesc(); readProtos(source ?? parentSource); }
    else readProtos(source ?? parentSource);
    // debug
    if (v === '5.2') source = this.str();
    if (v === '5.4') {
      const nli = this.count32(); r.skip(nli);
      const nabs = this.count32(); for (let i = 0; i < nabs; i++) { this.varint(); this.varint(); }
      if (nli || nabs) this.stripped = false;
    } else {
      const nli = this.count32(); r.skip(nli * this.sizeInt);
      if (nli) this.stripped = false;
    }
    const nloc = this.count32();
    for (let i = 0; i < nloc; i++) {
      locals.push(this.str() ?? '');
      if (v === '5.4') { this.varint(); this.varint(); } else { this.int(); this.int(); }
    }
    const nup = this.count32();
    for (let i = 0; i < nup; i++) upvalueNames.push(this.str() ?? '');
    if (nloc || nup) this.stripped = false;
    const instructions = words.map((w, pc) => this.decode(w, pc, constants, upvalueNames));
    return { path, source: source ?? parentSource, lineDefined, lastLineDefined, numParams, isVararg, maxStack, numUpvalues, instructions, constants, upvalueNames, locals, children, offset };
  }

  decode(w: number, pc: number, k: LuaConst[], up: string[]): LuaInstruction {
    const names = OPS[this.version] as string[];
    if (this.version === '5.4') {
      const opcode = w & 0x7f;
      const op = names[opcode] ?? `OP_${opcode}`;
      const a = (w >>> 7) & 0xff;
      const ins: LuaInstruction = { pc, word: w >>> 0, op, opcode, a };
      if (op === 'EXTRAARG') { ins.bx = w >>> 7; return ins; }
      if (op === 'JMP') { ins.sbx = (w >>> 7) - 16777215; ins.comment = `to ${pc + 1 + ins.sbx}`; return ins; }
      if (BX54.has(op)) { ins.bx = w >>> 15; if (op === 'LOADK') ins.comment = constText(k[ins.bx]); return ins; }
      if (SBX54.has(op)) { ins.sbx = (w >>> 15) - 65535; return ins; }
      ins.k = (w >>> 15) & 1; ins.b = (w >>> 16) & 0xff; ins.c = (w >>> 24) & 0xff;
      if (op === 'GETFIELD' || op === 'SETFIELD') ins.comment = constText(k[op === 'GETFIELD' ? ins.c : ins.b]);
      if (op === 'GETTABUP') ins.comment = `${up[ins.b] ?? 'up' + ins.b} ${constText(k[ins.c])}`;
      if (op === 'SETTABUP') ins.comment = `${up[a] ?? 'up' + a} ${constText(k[ins.b])}`;
      return ins;
    }
    const opcode = w & 0x3f;
    const op = names[opcode] ?? `OP_${opcode}`;
    const a = (w >>> 6) & 0xff;
    const ins: LuaInstruction = { pc, word: w >>> 0, op, opcode, a };
    if (op === 'EXTRAARG') { ins.bx = w >>> 6; return ins; }
    if (BX.has(op)) { ins.bx = w >>> 14; if (op === 'LOADK' || op === 'GETGLOBAL' || op === 'SETGLOBAL') ins.comment = constText(k[ins.bx]); return ins; }
    if (SBX_OLD.has(op)) { ins.sbx = (w >>> 14) - 131071; ins.comment = `to ${pc + 1 + ins.sbx}`; return ins; }
    ins.b = (w >>> 23) & 0x1ff; ins.c = (w >>> 14) & 0x1ff;
    const rk = (x: number) => (x & 0x100 ? constText(k[x & 0xff]) : undefined);
    if (op === 'GETTABUP') ins.comment = `${up[ins.b] ?? 'up' + ins.b} ${rk(ins.c) ?? ''}`.trim();
    else if (op === 'SETTABUP') ins.comment = `${up[a] ?? 'up' + a} ${rk(ins.b) ?? ''}`.trim();
    else if (op === 'GETTABLE' || op === 'SELF') { const t = rk(ins.c); if (t) ins.comment = t; }
    return ins;
  }
}

function constText(c: LuaConst | undefined): string {
  if (c === undefined) return '?';
  if (c === null) return 'nil';
  if (typeof c === 'string') return JSON.stringify(c);
  if (typeof c === 'object') return 'int' in c ? c.int : `proto ${c.proto}`;
  return String(c);
}

// ---------------- LuaJIT ----------------

function uleb(r: ByteReader): number {
  let v = 0, shift = 0, b = 0, n = 0;
  do { b = r.u8(); v += (b & 0x7f) * 2 ** shift; shift += 7; if (++n > 5) throw new ParseError('uleb128 too long', r.pos); } while (b & 0x80);
  return v;
}

function parseLuaJit(bytes: Uint8Array): LuaChunk {
  const r = new ByteReader(bytes, 3);
  const ver = r.u8();
  const flags = uleb(r);
  const be = (flags & 1) !== 0, strip = (flags & 2) !== 0, ffi = (flags & 4) !== 0, fr2 = (flags & 8) !== 0;
  let chunkname: string | undefined;
  if (!strip) { const n = uleb(r); chunkname = latin1(r.take(n)); }
  const names = ver === 1 ? LJ_OPS_20 : LJ_OPS_21;
  const stack: LuaFunction[] = [];
  let count = 0;
  while (r.remaining() > 0) {
    const len = uleb(r);
    if (len === 0) break;
    const start = r.pos;
    if (start + len > bytes.length) throw new ParseError('LuaJIT proto past end', start);
    if (++count > 100000) throw new ParseError('too many LuaJIT protos');
    r.seek(start + len);
    const p = new ByteReader(bytes.subarray(start, start + len), 0, !be);
    const pflags = p.u8(), numParams = p.u8(), framesize = p.u8(), sizeuv = p.u8();
    const sizekgc = uleb(p), sizekn = uleb(p), sizebc = uleb(p);
    let firstline = 0, numline = 0, sizedbg = 0;
    if (!strip) { sizedbg = uleb(p); if (sizedbg) { firstline = uleb(p); numline = uleb(p); } }
    if (sizebc > p.remaining() / 4) throw new ParseError('LuaJIT bytecode count past end', start);
    const words: number[] = [];
    for (let i = 0; i < sizebc; i++) words.push(p.u32());
    p.skip(sizeuv * 2);
    const constants: LuaConst[] = [];
    const children: LuaFunction[] = [];
    const kgc: LuaConst[] = [];
    for (let i = 0; i < sizekgc; i++) {
      const t = uleb(p);
      if (t === 0) { const child = stack.pop(); if (!child) throw new ParseError('LuaJIT child proto missing', start); children.unshift(child); kgc.push({ proto: children.length }); }
      else if (t === 1) { skipKTable(p); kgc.push('<table>'); }
      else if (t === 2 || t === 3) { const lo = uleb(p), hi = uleb(p); kgc.push({ int: ((BigInt(hi) << 32n) | BigInt(lo)).toString() + (t === 3 ? 'ULL' : 'LL') }); }
      else if (t === 4) { uleb(p); uleb(p); uleb(p); uleb(p); kgc.push('<complex>'); }
      else kgc.push(latin1(p.take(t - 5)));
    }
    const kn: LuaConst[] = [];
    for (let i = 0; i < sizekn; i++) {
      const b0 = p.bytes[p.pos] as number;
      const isNum = (b0 & 1) !== 0;
      // uleb128_33: the first byte carries one flag bit.
      let lo = (p.u8() >> 1) & 0x3f; let shift = 6; let b = b0;
      while (b & 0x80) { b = p.u8(); lo += (b & 0x7f) * 2 ** shift; shift += 7; if (shift > 40) throw new ParseError('bad uleb33', p.pos); }
      if (isNum) {
        const hi = uleb(p);
        const buf = new DataView(new ArrayBuffer(8));
        buf.setUint32(0, lo >>> 0, true); buf.setUint32(4, hi >>> 0, true);
        kn.push(buf.getFloat64(0, true));
      } else kn.push(lo | 0);
    }
    // Instructions index gc constants from the end (D = ~index).
    constants.push(...kn, ...kgc);
    const fn: LuaFunction = {
      path: '', source: chunkname, lineDefined: firstline, lastLineDefined: firstline + numline, numParams, isVararg: (pflags & 2) !== 0, maxStack: framesize, numUpvalues: sizeuv,
      instructions: words.map((w, pc) => {
        const opcode = w & 0xff;
        const op = names[opcode] ?? `BC_${opcode}`;
        const ins: LuaInstruction = { pc, word: w >>> 0, op, opcode, a: (w >>> 8) & 0xff, b: w >>> 24, c: (w >>> 16) & 0xff, d: w >>> 16 };
        if (op === 'KSTR' || op === 'GGET' || op === 'GSET' || op === 'TGETS' || op === 'TSETS') {
          const idx = op === 'TGETS' || op === 'TSETS' ? (ins.c as number) : (ins.d as number);
          const s = kgc[kgc.length - 1 - idx];
          if (typeof s === 'string') ins.comment = JSON.stringify(s);
        } else if (op === 'KNUM') { const n = kn[ins.d as number]; if (n !== undefined) ins.comment = String(n); }
        else if (op === 'KSHORT') ins.comment = String((ins.d as number) << 16 >> 16);
        else if (op === 'JMP' || op === 'FORI' || op === 'FORL' || op === 'ITERL' || op === 'LOOP' || op === 'ISNEXT' || op === 'UCLO') ins.comment = `to ${pc + 1 + ((ins.d as number) - 0x8000)}`;
        return ins;
      }),
      constants, upvalueNames: [], locals: [], children, offset: start,
    };
    void sizedbg;
    stack.push(fn);
  }
  const main = stack.pop();
  if (!main) throw new ParseError('LuaJIT dump has no prototypes');
  const setPaths = (f: LuaFunction, path: string, d: number) => { f.path = path; if (d < LIMITS.maxDepth) f.children.forEach((c, i) => setPaths(c, `${path}/${i + 1}`, d + 1)); };
  setPaths(main, 'main', 0);
  return {
    flavor: 'luajit', version: ver === 1 ? 'luajit2.0' : `luajit2.1`, format: ver,
    header: { bytecodeVersion: ver, bigEndian: be, stripped: strip, ffi, fr2, chunkname },
    main, functionCount: count, stripped: strip,
  };
}

function skipKTable(p: ByteReader): void {
  const narray = uleb(p), nhash = uleb(p);
  if (narray + nhash > 1 << 20) throw new ParseError('LuaJIT table constant too large');
  const kv = () => { const t = uleb(p); if (t === 3) uleb(p); else if (t === 4) { uleb(p); uleb(p); } else if (t >= 5) p.skip(t - 5); };
  for (let i = 0; i < narray; i++) kv();
  for (let i = 0; i < nhash; i++) { kv(); kv(); }
}

/** luac -l style text. */
export function luaListing(chunk: LuaChunk, maxLines = 20000): string {
  const lines: string[] = [];
  const walk = (f: LuaFunction, d: number) => {
    if (lines.length >= maxLines || d > LIMITS.maxDepth) return;
    lines.push(`function <${f.source ?? '?'}:${f.lineDefined},${f.lastLineDefined}> ${f.path} (${f.instructions.length} instructions at 0x${f.offset.toString(16)})`);
    lines.push(`${f.numParams}${f.isVararg ? '+' : ''} params, ${f.maxStack} slots, ${f.numUpvalues} upvalues, ${f.locals.length} locals, ${f.constants.length} constants, ${f.children.length} functions`);
    for (const i of f.instructions) {
      if (lines.length >= maxLines) { lines.push('... truncated'); return; }
      const ops = [i.a, i.b ?? i.bx ?? i.sbx ?? i.d, i.c].filter((x) => x !== undefined).join(' ');
      const shown = chunk.flavor === 'luajit' ? `${i.a} ${i.d}` : i.bx !== undefined ? `${i.a} ${i.bx}` : i.sbx !== undefined ? `${i.a} ${i.sbx}` : `${i.a} ${i.b ?? ''} ${i.c ?? ''}${i.k ? 'k' : ''}`.trim();
      void ops;
      lines.push(`\t${i.pc + 1}\t${i.op.padEnd(10)}\t${shown}${i.comment ? `\t; ${i.comment}` : ''}`);
    }
    lines.push('');
    for (const c of f.children) walk(c, d + 1);
  };
  walk(chunk.main, 0);
  return lines.join('\n');
}
