// Dalvik bytecode decoder and smali-style renderer. Output follows baksmali conventions
// (register names, label names, literal formatting) so it can be diffed against baksmali.

import { ParseError } from '../bytes.js';
import { OPS, PAYLOAD, type OpInfo } from './opcodes.js';
import type { ClassDef, CodeItem, DexFile, EncodedMethod, EncodedValue } from './parse.js';

export interface Insn {
  addr: number;
  op: OpInfo;
  units: number;
  regs: number[];
  /** range form: first register and count */
  range?: [number, number];
  lit?: bigint;
  /** pool index for string/type/field/method/proto/callsite/methodhandle */
  idx?: number;
  /** second index for invoke-polymorphic (proto) */
  idx2?: number;
  /** absolute branch or payload address */
  target?: number;
  payload?: { kind: 'packed'; first: number; targets: number[] } | { kind: 'sparse'; keys: number[]; targets: number[] } | { kind: 'array'; width: number; values: bigint[] };
}

export const DISASM_LIMITS = { maxInsns: 200_000, maxPayloadEntries: 65_536 };

function s4(v: number): number { return (v << 28) >> 28; }
function s8(v: number): number { return (v << 24) >> 24; }
function s16(v: number): number { return (v << 16) >> 16; }

/** Decode every instruction of a code item. Payload pseudo-instructions are returned with `payload` set. */
export function decodeCode(dex: DexFile, ci: CodeItem): Insn[] {
  const out: Insn[] = [];
  const u = (a: number): number => {
    if (a >= ci.insnsSize) throw new ParseError(`instruction reads past the end of code at unit ${a}`);
    return dex.unit(ci, a);
  };
  let addr = 0;
  while (addr < ci.insnsSize) {
    if (out.length >= DISASM_LIMITS.maxInsns) throw new ParseError('method has too many instructions');
    const w = u(addr);
    const opb = w & 0xff;
    const hi = w >> 8;
    // payloads
    if (opb === 0 && hi !== 0) {
      const ident = w;
      if (ident === PAYLOAD.PACKED) {
        const size = u(addr + 1);
        if (size > DISASM_LIMITS.maxPayloadEntries) throw new ParseError('switch payload too large');
        const first = (u(addr + 2) | (u(addr + 3) << 16)) | 0;
        const targets: number[] = [];
        for (let i = 0; i < size; i++) targets.push((u(addr + 4 + i * 2) | (u(addr + 5 + i * 2) << 16)) | 0);
        const units = 4 + size * 2;
        out.push({ addr, op: OPS[0] as OpInfo, units, regs: [], payload: { kind: 'packed', first, targets } });
        addr += units;
        continue;
      }
      if (ident === PAYLOAD.SPARSE) {
        const size = u(addr + 1);
        if (size > DISASM_LIMITS.maxPayloadEntries) throw new ParseError('switch payload too large');
        const keys: number[] = [], targets: number[] = [];
        for (let i = 0; i < size; i++) keys.push((u(addr + 2 + i * 2) | (u(addr + 3 + i * 2) << 16)) | 0);
        for (let i = 0; i < size; i++) targets.push((u(addr + 2 + size * 2 + i * 2) | (u(addr + 3 + size * 2 + i * 2) << 16)) | 0);
        const units = 2 + size * 4;
        out.push({ addr, op: OPS[0] as OpInfo, units, regs: [], payload: { kind: 'sparse', keys, targets } });
        addr += units;
        continue;
      }
      if (ident === PAYLOAD.ARRAY) {
        const width = u(addr + 1);
        const size = (u(addr + 2) | (u(addr + 3) << 16)) >>> 0;
        if (size > DISASM_LIMITS.maxPayloadEntries * 16 || ![1, 2, 4, 8].includes(width)) throw new ParseError('bad fill-array-data payload');
        const byteLen = width * size;
        const units = 4 + Math.ceil(byteLen / 2);
        if (addr + units > ci.insnsSize) throw new ParseError('array payload runs past the end of code');
        const base = ci.insnsOff + (addr + 4) * 2;
        const values: bigint[] = [];
        for (let i = 0; i < size; i++) {
          let v = 0n;
          for (let b = 0; b < width; b++) v |= BigInt(dex.r.u8(base + i * width + b)) << BigInt(8 * b);
          const bits = BigInt(width * 8);
          if (v >= 1n << (bits - 1n)) v -= 1n << bits;
          values.push(v);
        }
        out.push({ addr, op: OPS[0] as OpInfo, units, regs: [], payload: { kind: 'array', width, values } });
        addr += units;
        continue;
      }
    }
    const op = OPS[opb] as OpInfo;
    const ins: Insn = { addr, op, units: op.units, regs: [] };
    const A4 = (w >> 8) & 0xf, B4 = (w >> 12) & 0xf, AA = hi;
    switch (op.fmt) {
      case '10x': break;
      case '12x': ins.regs = [A4, B4]; break;
      case '11n': ins.regs = [A4]; ins.lit = BigInt(s4(B4)); break;
      case '11x': ins.regs = [AA]; break;
      case '10t': ins.target = addr + s8(AA); break;
      case '20t': ins.target = addr + s16(u(addr + 1)); break;
      case '22x': ins.regs = [AA, u(addr + 1)]; break;
      case '21t': ins.regs = [AA]; ins.target = addr + s16(u(addr + 1)); break;
      case '21s': ins.regs = [AA]; ins.lit = BigInt(s16(u(addr + 1))); break;
      case '21h': {
        ins.regs = [AA];
        const v = s16(u(addr + 1));
        ins.lit = op.op === 0x19 ? BigInt(v) << 48n : BigInt((v << 16) | 0);
        break;
      }
      case '21c': ins.regs = [AA]; ins.idx = u(addr + 1); break;
      case '23x': { const x = u(addr + 1); ins.regs = [AA, x & 0xff, x >> 8]; break; }
      case '22b': { const x = u(addr + 1); ins.regs = [AA, x & 0xff]; ins.lit = BigInt(s8(x >> 8)); break; }
      case '22t': ins.regs = [A4, B4]; ins.target = addr + s16(u(addr + 1)); break;
      case '22s': ins.regs = [A4, B4]; ins.lit = BigInt(s16(u(addr + 1))); break;
      case '22c': ins.regs = [A4, B4]; ins.idx = u(addr + 1); break;
      case '30t': ins.target = addr + ((u(addr + 1) | (u(addr + 2) << 16)) | 0); break;
      case '32x': ins.regs = [u(addr + 1), u(addr + 2)]; break;
      case '31i': ins.regs = [AA]; ins.lit = BigInt((u(addr + 1) | (u(addr + 2) << 16)) | 0); break;
      case '31t': ins.regs = [AA]; ins.target = addr + ((u(addr + 1) | (u(addr + 2) << 16)) | 0); break;
      case '31c': ins.regs = [AA]; ins.idx = (u(addr + 1) | (u(addr + 2) << 16)) >>> 0; break;
      case '35c': case '45cc': {
        const count = B4;
        const g = A4;
        const x = u(addr + 2);
        const all = [x & 0xf, (x >> 4) & 0xf, (x >> 8) & 0xf, (x >> 12) & 0xf, g];
        ins.regs = all.slice(0, Math.min(count, 5));
        ins.idx = u(addr + 1);
        if (op.fmt === '45cc') ins.idx2 = u(addr + 3);
        break;
      }
      case '3rc': case '4rcc': {
        const first = u(addr + 2);
        ins.range = [first, AA];
        ins.regs = [];
        for (let i = 0; i < Math.min(AA, 256); i++) ins.regs.push(first + i);
        ins.idx = u(addr + 1);
        if (op.fmt === '4rcc') ins.idx2 = u(addr + 3);
        break;
      }
      case '51l': {
        let v = 0n;
        for (let i = 0; i < 4; i++) v |= BigInt(u(addr + 1 + i)) << BigInt(16 * i);
        if (v >= 1n << 63n) v -= 1n << 64n;
        ins.regs = [AA]; ins.lit = v;
        break;
      }
      case 'xx': break;
    }
    // make sure the whole instruction is inside the code
    if (op.units > 1) u(addr + op.units - 1);
    out.push(ins);
    addr += op.units;
  }
  return out;
}

// ------------------------------------------------------------------ rendering

/** baksmali adds an L suffix only when a literal does not fit in 32 bits. */
function wideSuffix(v: bigint): string { return v > 0x7fffffffn || v < -0x80000000n ? 'L' : ''; }

export function hexLit(v: bigint | number, suffix = ''): string {
  const b = typeof v === 'bigint' ? v : BigInt(v);
  return b < 0n ? `-0x${(-b).toString(16)}${suffix}` : `0x${b.toString(16)}${suffix}`;
}

/** Quote a string the way baksmali does. */
export function smaliString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x20 && c < 0x7f) {
      if (c === 0x22) out += '\\"';
      else if (c === 0x27) out += "\\'";
      else if (c === 0x5c) out += '\\\\';
      else out += s[i];
    } else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else out += `\\u${c.toString(16).padStart(4, '0')}`;
  }
  return `${out}"`;
}

const ACCESS: [number, string, 'c' | 'f' | 'm' | 'cfm'][] = [
  [0x1, 'public', 'cfm'], [0x2, 'private', 'cfm'], [0x4, 'protected', 'cfm'], [0x8, 'static', 'cfm'], [0x10, 'final', 'cfm'],
  [0x20, 'synchronized', 'm'], [0x40, 'volatile', 'f'], [0x40, 'bridge', 'm'], [0x80, 'transient', 'f'], [0x80, 'varargs', 'm'],
  [0x100, 'native', 'm'], [0x200, 'interface', 'c'], [0x400, 'abstract', 'cm'as 'cfm'], [0x800, 'strictfp', 'cm' as 'cfm'], [0x1000, 'synthetic', 'cfm'],
  [0x2000, 'annotation', 'c'], [0x4000, 'enum', 'cf' as 'cfm'], [0x10000, 'constructor', 'm'], [0x20000, 'declared-synchronized', 'm'],
];

export function accessString(flags: number, kind: 'c' | 'f' | 'm'): string {
  return ACCESS.filter(([bit, , k]) => (flags & bit) !== 0 && k.includes(kind)).map(([, n]) => n).join(' ');
}

function label(prefix: string, addr: number): string { return `:${prefix}_${addr.toString(16)}`; }

function encodedValueText(dex: DexFile, v: EncodedValue): string {
  switch (v.t) {
    case 'byte': return hexLit(v.v, 't');
    case 'short': return hexLit(v.v, 's');
    case 'char': return v.v >= 0x20 && v.v < 0x7f && v.v !== 0x27 && v.v !== 0x5c ? `'${String.fromCharCode(v.v)}'` : `'\\u${v.v.toString(16).padStart(4, '0')}'`;
    case 'int': return hexLit(v.v);
    case 'long': return hexLit(v.v, 'L');
    case 'float': return `${fmtFloat(v.v)}f`;
    case 'double': return fmtFloat(v.v);
    case 'string': return smaliString(v.v);
    case 'type': return v.v;
    case 'field': case 'method': return v.v;
    case 'enum': return `.enum ${v.v}`;
    case 'methodtype': return v.v;
    case 'methodhandle': { const h = dex.methodHandle(v.v); return `${h.kindName}@${h.target}`; }
    case 'null': return 'null';
    case 'boolean': return String(v.v);
    case 'array': return `{ ${v.v.map((x) => encodedValueText(dex, x)).join(', ')} }`;
    case 'annotation': return `.subannotation ${v.type}`;
  }
}

function fmtFloat(n: number): string {
  if (Number.isNaN(n)) return 'NaN';
  if (!Number.isFinite(n)) return n > 0 ? 'Infinity' : '-Infinity';
  const s = String(n);
  return s.includes('.') || s.includes('e') ? s : `${s}.0`;
}

export interface RenderOptions {
  /** emit .line directives from debug info */
  lines?: boolean;
  /** cap output lines */
  maxLines?: number;
}

/** Render one method's body (from .registers to the last instruction) in baksmali style. */
export function renderMethodBody(dex: DexFile, ci: CodeItem, isStatic: boolean, opts: RenderOptions = {}): string[] {
  const insns = decodeCode(dex, ci);
  const paramBase = ci.registers - ci.ins;
  const reg = (r: number): string => (r >= paramBase ? `p${r - paramBase}` : `v${r}`);
  void isStatic;

  // collect labels per address
  const labels = new Map<number, Set<string>>();
  const addLabel = (addr: number, name: string): void => {
    let s = labels.get(addr);
    if (!s) { s = new Set(); labels.set(addr, s); }
    s.add(name);
  };
  const payloadOwner = new Map<number, number>();
  for (const i of insns) {
    if (i.target === undefined) continue;
    const n = i.op.name;
    if (n.startsWith('goto')) addLabel(i.target, label('goto', i.target));
    else if (n.startsWith('if-')) addLabel(i.target, label('cond', i.target));
    else if (n === 'packed-switch') { addLabel(i.target, label('pswitch_data', i.target)); payloadOwner.set(i.target, i.addr); }
    else if (n === 'sparse-switch') { addLabel(i.target, label('sswitch_data', i.target)); payloadOwner.set(i.target, i.addr); }
    else if (n === 'fill-array-data') addLabel(i.target, label('array', i.target));
  }
  const byAddr = new Map<number, Insn>();
  for (const i of insns) byAddr.set(i.addr, i);
  for (const i of insns) {
    if (!i.payload || i.payload.kind === 'array') continue;
    const owner = payloadOwner.get(i.addr);
    if (owner === undefined) continue;
    const pre = i.payload.kind === 'packed' ? 'pswitch' : 'sswitch';
    for (const t of i.payload.targets) addLabel(owner + t, label(pre, owner + t));
  }
  // try blocks: end label goes after the last instruction inside the range
  const afterInsn = new Map<number, string[]>();
  const lastInsnBefore = (end: number): number => {
    let last = -1;
    for (const i of insns) { if (i.addr < end) last = i.addr; else break; }
    return last;
  };
  for (const t of ci.tries) {
    const start = t.start, end = t.start + t.count;
    addLabel(start, label('try_start', start));
    const lastAddr = lastInsnBefore(end);
    const lines = afterInsn.get(lastAddr) ?? [];
    if (!lines.includes(`    ${label('try_end', end)}`)) lines.push(`    ${label('try_end', end)}`);
    for (const h of t.handlers) {
      addLabel(h.addr, label('catch', h.addr));
      lines.push(`    .catch ${h.type} {${label('try_start', start)} .. ${label('try_end', end)}} ${label('catch', h.addr)}`);
    }
    if (t.catchAll !== undefined) {
      addLabel(t.catchAll, label('catchall', t.catchAll));
      lines.push(`    .catchall {${label('try_start', start)} .. ${label('try_end', end)}} ${label('catchall', t.catchAll)}`);
    }
    afterInsn.set(lastAddr, lines);
  }

  const dbg = opts.lines ? dex.debugInfo(ci).lines : undefined;
  const out: string[] = [`    .registers ${ci.registers}`];
  const max = opts.maxLines ?? 100_000;
  for (const i of insns) {
    if (out.length > max) { out.push('    # output truncated'); break; }
    const ln = dbg?.get(i.addr);
    if (ln !== undefined) out.push(`    .line ${ln}`);
    const ls = labels.get(i.addr);
    if (ls) for (const l of [...ls].sort()) out.push(`    ${l}`);
    out.push(...renderInsn(dex, i, reg, payloadOwner));
    const after = afterInsn.get(i.addr);
    if (after) out.push(...after);
  }
  return out;
}

function refText(dex: DexFile, i: Insn): string {
  const idx = i.idx ?? 0;
  switch (i.op.ref) {
    case 'string': return smaliString(dex.string(idx));
    case 'type': return dex.type(idx);
    case 'field': return dex.fieldRef(idx);
    case 'method': return dex.methodRef(idx);
    case 'proto': return dex.protoString(idx);
    case 'callsite': {
      const cs = dex.callSite(idx);
      return `call_site_${idx}("${cs.name}")`;
    }
    case 'methodhandle': { const h = dex.methodHandle(idx); return `${h.kindName}@${h.target}`; }
    default: return '';
  }
}

function renderInsn(dex: DexFile, i: Insn, reg: (r: number) => string, payloadOwner: Map<number, number>): string[] {
  if (i.payload) {
    const p = i.payload;
    if (p.kind === 'packed') {
      const owner = payloadOwner.get(i.addr) ?? i.addr;
      return [`    .packed-switch ${hexLit(p.first)}`, ...p.targets.map((t) => `        ${label('pswitch', owner + t)}`), '    .end packed-switch'];
    }
    if (p.kind === 'sparse') {
      const owner = payloadOwner.get(i.addr) ?? i.addr;
      return ['    .sparse-switch', ...p.keys.map((k, n) => `        ${hexLit(k)} -> ${label('sswitch', owner + (p.targets[n] as number))}`), '    .end sparse-switch'];
    }
    const suf = p.width === 1 ? 't' : p.width === 2 ? 's' : '';
    return [`    .array-data ${p.width}`, ...p.values.map((v) => `        ${hexLit(v, p.width === 8 ? wideSuffix(v) : suf)}`), '    .end array-data'];
  }
  const n = i.op.name;
  const parts: string[] = [];
  const f = i.op.fmt;
  if (f === 'xx') return [`    # unknown opcode 0x${i.op.op.toString(16).padStart(2, '0')}`];
  if (f === '35c' || f === '45cc') parts.push(`{${i.regs.map(reg).join(', ')}}`);
  else if (f === '3rc' || f === '4rcc') {
    const [first, count] = i.range ?? [0, 0];
    parts.push(count === 0 ? '{}' : `{${reg(first)} .. ${reg(first + count - 1)}}`);
  } else parts.push(...i.regs.map(reg));
  if (i.op.ref !== 'none' && i.idx !== undefined) parts.push(refText(dex, i));
  if (i.idx2 !== undefined) parts.push(dex.protoString(i.idx2));
  if (i.lit !== undefined) {
    parts.push(hexLit(i.lit, wideSuffix(i.lit)));
  }
  if (i.target !== undefined) {
    const pre = n.startsWith('goto') ? 'goto' : n.startsWith('if-') ? 'cond' : n === 'packed-switch' ? 'pswitch_data' : n === 'sparse-switch' ? 'sswitch_data' : 'array';
    parts.push(label(pre, i.target));
  }
  return [parts.length ? `    ${n} ${parts.join(', ')}` : `    ${n}`];
}

export interface MethodView {
  classDef: ClassDef;
  method: EncodedMethod;
  direct: boolean;
}

/** Render a whole method in smali, header to .end method. */
export function renderMethod(dex: DexFile, mv: MethodView, opts: RenderOptions = {}): string {
  const m = dex.method(mv.method.methodIdx);
  const acc = accessString(mv.method.access, 'm');
  const sig = `${m.name}(${m.proto.params.join('')})${m.proto.ret}`;
  const lines = [`.method ${acc ? `${acc} ` : ''}${sig}`];
  const ci = dex.code(mv.method.codeOff);
  if (ci) lines.push(...renderMethodBody(dex, ci, (mv.method.access & 0x8) !== 0, opts));
  lines.push('.end method');
  return lines.join('\n');
}

/** Render a whole class in smali. */
export function renderClass(dex: DexFile, cd: ClassDef, opts: RenderOptions = {}): string {
  const out: string[] = [];
  const acc = accessString(cd.access, 'c');
  out.push(`.class ${acc ? `${acc} ` : ''}${cd.name}`);
  if (cd.superclass) out.push(`.super ${cd.superclass}`);
  if (cd.sourceFile !== undefined) out.push(`.source ${smaliString(cd.sourceFile)}`);
  if (cd.interfaces.length) { out.push('', '# interfaces'); for (const i of cd.interfaces) out.push(`.implements ${i}`); }
  const data = dex.classData(cd);
  const sv = dex.staticValues(cd);
  if (data.staticFields.length) {
    out.push('', '', '# static fields');
    data.staticFields.forEach((f, k) => {
      const fi = dex.field(f.fieldIdx);
      const a = accessString(f.access, 'f');
      const v = sv[k];
      const init = v && !isDefault(v) ? ` = ${encodedValueText(dex, v)}` : '';
      out.push(`.field ${a ? `${a} ` : ''}${fi.name}:${fi.type}${init}`);
    });
  }
  if (data.instanceFields.length) {
    out.push('', '', '# instance fields');
    for (const f of data.instanceFields) {
      const fi = dex.field(f.fieldIdx);
      const a = accessString(f.access, 'f');
      out.push(`.field ${a ? `${a} ` : ''}${fi.name}:${fi.type}`);
    }
  }
  const emit = (title: string, list: EncodedMethod[], direct: boolean): void => {
    if (!list.length) return;
    out.push('', '', `# ${title}`);
    for (const m of list) {
      try { out.push(renderMethod(dex, { classDef: cd, method: m, direct }, opts)); }
      catch (err) { out.push(`# method ${dex.methodRef(m.methodIdx)} could not be disassembled: ${(err as Error).message}`); }
      out.push('');
    }
  };
  emit('direct methods', data.directMethods, true);
  emit('virtual methods', data.virtualMethods, false);
  return out.join('\n');
}

function isDefault(v: EncodedValue): boolean {
  switch (v.t) {
    case 'null': return true;
    case 'boolean': return v.v === false;
    case 'long': return v.v === 0n;
    case 'byte': case 'short': case 'char': case 'int': return v.v === 0;
    case 'float': case 'double': return v.v === 0 && !Object.is(v.v, -0);
    default: return false;
  }
}
