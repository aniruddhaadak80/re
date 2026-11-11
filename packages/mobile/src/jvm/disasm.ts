// JVM bytecode disassembler with javap -c -p style output.

import { Buf, ParseError } from '../bytes.js';
import { classSigToJava, cpClass, cpNat, cpUtf8, descToJava, methodSigToJava, sigTypeToJava, splitMethodDesc, type ClassFile, type Member } from './classfile.js';

type Kind = 'none' | 'b' | 's' | 'lv' | 'cp1' | 'cp2' | 'br2' | 'br4' | 'iinc' | 'newarray' | 'table' | 'lookup' | 'iface' | 'indy' | 'multi' | 'wide';

const NAMES: string[] = [
  'nop', 'aconst_null', 'iconst_m1', 'iconst_0', 'iconst_1', 'iconst_2', 'iconst_3', 'iconst_4', 'iconst_5', 'lconst_0', 'lconst_1',
  'fconst_0', 'fconst_1', 'fconst_2', 'dconst_0', 'dconst_1', 'bipush', 'sipush', 'ldc', 'ldc_w', 'ldc2_w', 'iload', 'lload', 'fload',
  'dload', 'aload', 'iload_0', 'iload_1', 'iload_2', 'iload_3', 'lload_0', 'lload_1', 'lload_2', 'lload_3', 'fload_0', 'fload_1',
  'fload_2', 'fload_3', 'dload_0', 'dload_1', 'dload_2', 'dload_3', 'aload_0', 'aload_1', 'aload_2', 'aload_3', 'iaload', 'laload',
  'faload', 'daload', 'aaload', 'baload', 'caload', 'saload', 'istore', 'lstore', 'fstore', 'dstore', 'astore', 'istore_0', 'istore_1',
  'istore_2', 'istore_3', 'lstore_0', 'lstore_1', 'lstore_2', 'lstore_3', 'fstore_0', 'fstore_1', 'fstore_2', 'fstore_3', 'dstore_0',
  'dstore_1', 'dstore_2', 'dstore_3', 'astore_0', 'astore_1', 'astore_2', 'astore_3', 'iastore', 'lastore', 'fastore', 'dastore',
  'aastore', 'bastore', 'castore', 'sastore', 'pop', 'pop2', 'dup', 'dup_x1', 'dup_x2', 'dup2', 'dup2_x1', 'dup2_x2', 'swap', 'iadd',
  'ladd', 'fadd', 'dadd', 'isub', 'lsub', 'fsub', 'dsub', 'imul', 'lmul', 'fmul', 'dmul', 'idiv', 'ldiv', 'fdiv', 'ddiv', 'irem', 'lrem',
  'frem', 'drem', 'ineg', 'lneg', 'fneg', 'dneg', 'ishl', 'lshl', 'ishr', 'lshr', 'iushr', 'lushr', 'iand', 'land', 'ior', 'lor', 'ixor',
  'lxor', 'iinc', 'i2l', 'i2f', 'i2d', 'l2i', 'l2f', 'l2d', 'f2i', 'f2l', 'f2d', 'd2i', 'd2l', 'd2f', 'i2b', 'i2c', 'i2s', 'lcmp', 'fcmpl',
  'fcmpg', 'dcmpl', 'dcmpg', 'ifeq', 'ifne', 'iflt', 'ifge', 'ifgt', 'ifle', 'if_icmpeq', 'if_icmpne', 'if_icmplt', 'if_icmpge',
  'if_icmpgt', 'if_icmple', 'if_acmpeq', 'if_acmpne', 'goto', 'jsr', 'ret', 'tableswitch', 'lookupswitch', 'ireturn', 'lreturn',
  'freturn', 'dreturn', 'areturn', 'return', 'getstatic', 'putstatic', 'getfield', 'putfield', 'invokevirtual', 'invokespecial',
  'invokestatic', 'invokeinterface', 'invokedynamic', 'new', 'newarray', 'anewarray', 'arraylength', 'athrow', 'checkcast',
  'instanceof', 'monitorenter', 'monitorexit', 'wide', 'multianewarray', 'ifnull', 'ifnonnull', 'goto_w', 'jsr_w',
];

function kindOf(op: number): Kind {
  if (op === 0x10) return 'b';
  if (op === 0x11) return 's';
  if (op === 0x12) return 'cp1';
  if (op === 0x13 || op === 0x14) return 'cp2';
  if ((op >= 0x15 && op <= 0x19) || (op >= 0x36 && op <= 0x3a) || op === 0xa9) return 'lv';
  if (op === 0x84) return 'iinc';
  if ((op >= 0x99 && op <= 0xa8) || op === 0xc6 || op === 0xc7) return 'br2';
  if (op === 0xc8 || op === 0xc9) return 'br4';
  if (op === 0xaa) return 'table';
  if (op === 0xab) return 'lookup';
  if ((op >= 0xb2 && op <= 0xb8) || op === 0xbb || op === 0xbd || op === 0xc0 || op === 0xc1) return 'cp2';
  if (op === 0xb9) return 'iface';
  if (op === 0xba) return 'indy';
  if (op === 0xbc) return 'newarray';
  if (op === 0xc5) return 'multi';
  if (op === 0xc4) return 'wide';
  return 'none';
}

export interface JvmInsn {
  pc: number;
  op: number;
  name: string;
  /** operand text as javap prints it, without the comment */
  operand?: string;
  comment?: string;
  /** branch targets and switch entries */
  targets?: number[];
  switchLines?: string[];
  /** constant pool index operand */
  cpIndex?: number;
}

const ATYPES: Record<number, string> = { 4: 'boolean', 5: 'char', 6: 'float', 7: 'double', 8: 'byte', 9: 'short', 10: 'int', 11: 'long' };

function javapString(s: string): string {
  // javap prints control characters escaped
  let out = '';
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if (ch === '\n') out += '\\n';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '"') out += '\\"';
    else if (ch === "'") out += "\\'";
    else if (ch === '\\') out += '\\\\';
    else if (c < 0x20 || (c >= 0x7f && c < 0xa0)) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return out;
}

/** Java Float.toString / Double.toString formatting, using shortest round-trip digits. */
export function javaFloat(v: number, suffix: string): string {
  if (Number.isNaN(v)) return `NaN${suffix}`;
  if (!Number.isFinite(v)) return `${v > 0 ? 'Infinity' : '-Infinity'}${suffix}`;
  if (v === 0) return `${Object.is(v, -0) ? '-' : ''}0.0${suffix}`;
  let shortest = v;
  if (suffix === 'f') {
    for (let p = 1; p <= 9; p++) { const t = Number(v.toPrecision(p)); if (Math.fround(t) === v) { shortest = t; break; } }
  }
  const exp = shortest.toExponential(); // like -1.2345e+7
  const m = /^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(exp);
  if (!m) return String(v) + suffix;
  const sign = m[1] ?? '';
  const digits = (m[2] ?? '') + (m[3] ?? '');
  const e = parseInt(m[4] ?? '0', 10);
  const abs = Math.abs(shortest);
  let body: string;
  if (abs >= 1e-3 && abs < 1e7) {
    if (e >= 0) {
      const intPart = digits.slice(0, e + 1).padEnd(e + 1, '0');
      const frac = digits.slice(e + 1);
      body = `${intPart}.${frac || '0'}`;
    } else {
      body = `0.${'0'.repeat(-e - 1)}${digits}`;
    }
  } else {
    body = `${digits[0]}.${digits.slice(1) || '0'}E${e}`;
  }
  return `${sign}${body}${suffix}`;
}

function quoteName(n: string): string { return n === '<init>' || n === '<clinit>' ? `"${n}"` : n; }

function clsForComment(c: string): string { return c.startsWith('[') ? `"${c}"` : c; }

/** Describe a constant pool entry the way javap's comment column does. */
export function cpComment(cf: ClassFile, i: number): string {
  const e = cf.cp[i];
  if (!e) return `<bad #${i}>`;
  switch (e.tag) {
    case 3: return `int ${e.value}`;
    case 4: return `float ${javaFloat(e.value, 'f')}`;
    case 5: return `long ${e.value}l`;
    case 6: return `double ${javaFloat(e.value, 'd')}`;
    case 7: return `class ${clsForComment(cpUtf8(cf, e.name))}`;
    case 8: return `String ${javapString(cpUtf8(cf, e.string))}`;
    case 9: case 10: case 11: {
      const cls = cpClass(cf, e.cls);
      const nat = cpNat(cf, e.nat);
      const kind = e.tag === 9 ? 'Field' : e.tag === 10 ? 'Method' : 'InterfaceMethod';
      const owner = cls === cf.thisClass ? '' : `${clsForComment(cls)}.`;
      return `${kind} ${owner}${quoteName(nat.name)}:${nat.desc}`;
    }
    case 16: return `MethodType ${cpUtf8(cf, e.desc)}`;
    case 15: return `MethodHandle ${e.kind}:${cpComment(cf, e.ref)}`;
    case 17: case 18: { const nat = cpNat(cf, e.nat); return `${e.tag === 18 ? 'InvokeDynamic' : 'Dynamic'} #${e.bsm}:${quoteName(nat.name)}:${nat.desc}`; }
    case 1: return cpUtf8(cf, i);
    default: return `#${i}`;
  }
}

export const JVM_LIMITS = { maxInsns: 200_000, maxSwitch: 65_536 };

/** Decode the bytecode of one method. */
export function decodeJvm(cf: ClassFile, m: Member): JvmInsn[] {
  const code = m.code;
  if (!code) return [];
  const r = new Buf(cf.bytes, false);
  const base = code.codeOff;
  const len = code.codeLen;
  const out: JvmInsn[] = [];
  let pc = 0;
  const u8 = (o: number): number => { if (o >= len) throw new ParseError(`bytecode read past end at pc ${o}`); return r.u8(base + o); };
  const u16 = (o: number): number => (u8(o) << 8) | u8(o + 1);
  const s32 = (o: number): number => ((u8(o) << 24) | (u8(o + 1) << 16) | (u8(o + 2) << 8) | u8(o + 3)) | 0;
  while (pc < len) {
    if (out.length >= JVM_LIMITS.maxInsns) throw new ParseError('method has too many instructions');
    const op = u8(pc);
    const name = NAMES[op] ?? `unknown_${op}`;
    const ins: JvmInsn = { pc, op, name };
    const k = kindOf(op);
    let size = 1;
    switch (k) {
      case 'b': ins.operand = String((u8(pc + 1) << 24) >> 24); size = 2; break;
      case 's': ins.operand = String((u16(pc + 1) << 16) >> 16); size = 3; break;
      case 'lv': ins.operand = String(u8(pc + 1)); size = 2; break;
      case 'cp1': { const i = u8(pc + 1); ins.cpIndex = i; ins.operand = `#${i}`; ins.comment = cpComment(cf, i); size = 2; break; }
      case 'cp2': { const i = u16(pc + 1); ins.cpIndex = i; ins.operand = `#${i}`; ins.comment = cpComment(cf, i); size = 3; break; }
      case 'br2': { const t = pc + ((u16(pc + 1) << 16) >> 16); ins.targets = [t]; ins.operand = String(t); size = 3; break; }
      case 'br4': { const t = pc + s32(pc + 1); ins.targets = [t]; ins.operand = String(t); size = 5; break; }
      case 'iinc': ins.operand = `${u8(pc + 1)}, ${(u8(pc + 2) << 24) >> 24}`; size = 3; break;
      case 'newarray': ins.operand = ` ${ATYPES[u8(pc + 1)] ?? `atype${u8(pc + 1)}`}`; size = 2; break;
      case 'iface': { const i = u16(pc + 1); ins.cpIndex = i; ins.operand = `#${i},  ${u8(pc + 3)}`; ins.comment = cpComment(cf, i); size = 5; break; }
      case 'indy': { const i = u16(pc + 1); ins.cpIndex = i; ins.operand = `#${i},  0`; ins.comment = cpComment(cf, i); size = 5; break; }
      case 'multi': { const i = u16(pc + 1); ins.cpIndex = i; ins.operand = `#${i},  ${u8(pc + 3)}`; ins.comment = cpComment(cf, i); size = 4; break; }
      case 'wide': {
        const sub = u8(pc + 1);
        const subName = NAMES[sub] ?? `unknown_${sub}`;
        ins.name = subName + '_w';
        if (sub === 0x84) { ins.name = 'iinc_w'; ins.operand = `${u16(pc + 2)}, ${(u16(pc + 4) << 16) >> 16}`; size = 6; }
        else { ins.name = `${subName}_w`; ins.operand = String(u16(pc + 2)); size = 4; }
        break;
      }
      case 'table': case 'lookup': {
        let p = (pc + 4) & ~3;
        const def = pc + s32(p);
        const lines: string[] = [];
        const targets: number[] = [];
        if (k === 'table') {
          const lo = s32(p + 4), hi = s32(p + 8);
          if (hi < lo || hi - lo >= JVM_LIMITS.maxSwitch) throw new ParseError('bad tableswitch bounds');
          ins.operand = `{ // ${lo} to ${hi}`;
          for (let i = 0; i <= hi - lo; i++) { const t = pc + s32(p + 12 + i * 4); targets.push(t); lines.push(`${String(lo + i).padStart(22)}: ${t}`); }
          size = p + 12 + (hi - lo + 1) * 4 - pc;
        } else {
          const n = s32(p + 4);
          if (n < 0 || n >= JVM_LIMITS.maxSwitch) throw new ParseError('bad lookupswitch size');
          ins.operand = `{ // ${n}`;
          for (let i = 0; i < n; i++) { const key = s32(p + 8 + i * 8); const t = pc + s32(p + 12 + i * 8); targets.push(t); lines.push(`${String(key).padStart(22)}: ${t}`); }
          size = p + 8 + n * 8 - pc;
        }
        lines.push(`${'default'.padStart(22)}: ${def}`);
        targets.push(def);
        ins.targets = targets;
        ins.switchLines = lines;
        p = 0;
        break;
      }
      default: break;
    }
    if (size > 1) u8(pc + size - 1);
    out.push(ins);
    pc += size;
  }
  return out;
}

/** Render one instruction as javap -c prints it (may be several lines for switches). */
export function renderJvmInsn(ins: JvmInsn): string[] {
  const head = `${String(ins.pc).padStart(8)}: `;
  if (ins.operand === undefined) return [`${head}${ins.name}`];
  let line = `${head}${ins.name.padEnd(13)} ${ins.operand}`;
  if (ins.comment !== undefined) {
    line = line.length < 44 ? line.padEnd(44) : `${line} `;
    line += `// ${ins.comment}`;
  }
  if (ins.switchLines) return [line, ...ins.switchLines, '          }'];
  return [line];
}

// ------------------------------------------------------------- declarations

const MOD_ORDER: [number, string][] = [
  [0x0001, 'public'], [0x0004, 'protected'], [0x0002, 'private'], [0x0400, 'abstract'], [0x0008, 'static'], [0x0010, 'final'],
  [0x0040, 'volatile'], [0x0080, 'transient'], [0x0020, 'synchronized'], [0x0100, 'native'], [0x0800, 'strictfp'],
];

function mods(access: number, kind: 'field' | 'method' | 'class', isInterface = false): string {
  const out: string[] = [];
  for (const [bit, name] of MOD_ORDER) {
    if (!(access & bit)) continue;
    if (kind === 'field' && (name === 'synchronized' || name === 'native' || name === 'abstract' || name === 'strictfp')) continue;
    if (kind === 'method' && (name === 'transient' || name === 'volatile')) continue;
    if (kind === 'class' && (name === 'synchronized' || name === 'transient' || name === 'volatile' || name === 'native')) continue;
    out.push(name);
  }
  if (kind === 'method' && isInterface && !(access & 0x0400) && !(access & 0x0008) && !(access & 0x0002)) {
    const idx = out.indexOf('public');
    out.splice(idx + 1, 0, 'default');
  }
  return out.join(' ');
}

function simpleName(cls: string): string { return cls.replace(/\//g, '.'); }

export function fieldDecl(cf: ClassFile, f: Member): string {
  const type = f.signature ? sigTypeToJava(f.signature).text : descToJava(f.descriptor);
  const m = mods(f.access, 'field');
  return `${m ? `${m} ` : ''}${type} ${f.name};`;
}

export function methodDecl(cf: ClassFile, m: Member): string {
  const isInterface = (cf.access & 0x0200) !== 0;
  const md = mods(m.access, 'method', isInterface);
  if (m.name === '<clinit>') return 'static {};';
  let params: string[];
  let ret: string;
  let throws: string[] = m.exceptions.map(simpleName);
  let typeParams = '';
  if (m.signature) {
    const s = methodSigToJava(m.signature);
    params = s.params; ret = s.ret;
    if (s.throws.length) throws = s.throws;
    if (s.typeParams) typeParams = `${s.typeParams} `;
  } else {
    const d = splitMethodDesc(m.descriptor);
    params = d.params.map(descToJava);
    ret = descToJava(d.ret);
  }
  if ((m.access & 0x0080) && params.length) {
    const last = params[params.length - 1] as string;
    if (last.endsWith('[]')) params[params.length - 1] = `${last.slice(0, -2)}...`;
  }
  const name = m.name === '<init>' ? simpleName(cf.thisClass) : m.name;
  const head = `${md ? `${md} ` : ''}${typeParams}${m.name === '<init>' ? '' : `${ret} `}${name}(${params.join(', ')})`;
  return `${head}${throws.length ? ` throws ${throws.join(', ')}` : ''};`;
}

export function classDecl(cf: ClassFile): string {
  const isInterface = (cf.access & 0x0200) !== 0;
  let access = cf.access & ~0x0020;
  if (isInterface) access &= ~0x0400;
  const m = mods(access, 'class');
  const kw = isInterface ? 'interface' : 'class';
  let sup = cf.superClass ? simpleName(cf.superClass) : undefined;
  let ifaces = cf.interfaces.map(simpleName);
  let tp = '';
  // javap joins plain interface names with a bare comma, and generic ones with a comma and space
  let sep = ',';
  if (cf.signature) {
    sep = ', ';
    const s = classSigToJava(cf.signature);
    sup = s.superClass; ifaces = s.interfaces;
    if (s.typeParams) tp = s.typeParams;
  }
  let out = `${m ? `${m} ` : ''}${kw} ${simpleName(cf.thisClass)}${tp}`;
  if (isInterface) { if (ifaces.length) out += ` extends ${ifaces.join(sep)}`; }
  else {
    if (sup && sup !== 'java.lang.Object') out += ` extends ${sup}`;
    if (ifaces.length) out += ` implements ${ifaces.join(sep)}`;
  }
  return out;
}

/** Render a method's Code section (instructions plus exception table) like javap -c. */
export function renderJvmCode(cf: ClassFile, m: Member): string[] {
  if (!m.code) return [];
  const lines = ['    Code:'];
  for (const ins of decodeJvm(cf, m)) lines.push(...renderJvmInsn(ins));
  if (m.code.exceptions.length) {
    lines.push('    Exception table:', '       from    to  target type');
    for (const e of m.code.exceptions) {
      const t = e.catchType ? `Class ${cpClass(cf, e.catchType)}` : 'any';
      lines.push(`${String(e.start).padStart(12)}${String(e.end).padStart(6)}${String(e.handler).padStart(6)}   ${t}`);
    }
  }
  return lines;
}

/** Disassemble a whole class like `javap -c -p`. */
export function javap(cf: ClassFile, opts: { methods?: boolean; maxLines?: number } = {}): string {
  const out: string[] = [];
  if (cf.sourceFile) out.push(`Compiled from "${cf.sourceFile}"`);
  out.push(`${classDecl(cf)} {`);
  const blocks: string[][] = [];
  for (const f of cf.fields) blocks.push([`  ${fieldDecl(cf, f)}`]);
  for (const m of cf.methods) {
    const b = [`  ${methodDecl(cf, m)}`];
    if (opts.methods !== false) b.push(...renderJvmCode(cf, m));
    blocks.push(b);
  }
  if (blocks.length) out.push(blocks.map((b) => b.join('\n')).join('\n\n'));
  out.push('}');
  const text = out.join('\n').split('\n').map((l) => l.trimEnd()).join('\n');
  if (opts.maxLines && out.length > opts.maxLines) return text.split('\n').slice(0, opts.maxLines).join('\n') + '\n// output truncated';
  return text;
}
