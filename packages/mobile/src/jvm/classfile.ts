// Java .class file parser (JVMS chapter 4). Bounds-checked and safe on hostile input.

import { Buf, ParseError, mutf8 } from '../bytes.js';

export type CpEntry =
  | { tag: 1; text: string }
  | { tag: 3; value: number }
  | { tag: 4; value: number }
  | { tag: 5; value: bigint }
  | { tag: 6; value: number }
  | { tag: 7; name: number }
  | { tag: 8; string: number }
  | { tag: 9 | 10 | 11; cls: number; nat: number }
  | { tag: 12; name: number; desc: number }
  | { tag: 15; kind: number; ref: number }
  | { tag: 16; desc: number }
  | { tag: 17 | 18; bsm: number; nat: number }
  | { tag: 19 | 20; name: number }
  | { tag: 0 };

export interface Attribute { name: string; offset: number; length: number }

export interface ExceptionEntry { start: number; end: number; handler: number; catchType: number }

export interface CodeAttr {
  maxStack: number;
  maxLocals: number;
  codeOff: number;
  codeLen: number;
  exceptions: ExceptionEntry[];
  attributes: Attribute[];
}

export interface Member {
  access: number;
  name: string;
  descriptor: string;
  signature?: string;
  attributes: Attribute[];
  code?: CodeAttr;
  exceptions: string[];
  constantValue?: number;
}

export interface ClassFile {
  bytes: Uint8Array;
  minor: number;
  major: number;
  javaVersion: string;
  cp: CpEntry[];
  access: number;
  thisClass: string;
  superClass?: string;
  interfaces: string[];
  fields: Member[];
  methods: Member[];
  attributes: Attribute[];
  sourceFile?: string;
  signature?: string;
}

export const CLASS_LIMITS = { maxCp: 65_535, maxMembers: 65_535, maxAttrs: 65_535 };

export function isClassFile(b: Uint8Array): boolean {
  if (b.length < 10 || b[0] !== 0xca || b[1] !== 0xfe || b[2] !== 0xba || b[3] !== 0xbe) return false;
  const major = ((b[6] as number) << 8) | (b[7] as number);
  return major >= 45 && major < 100;
}

export function cpUtf8(cf: ClassFile, i: number): string {
  const e = cf.cp[i];
  return e && e.tag === 1 ? e.text : `<bad utf8 #${i}>`;
}

export function cpClass(cf: ClassFile, i: number): string {
  const e = cf.cp[i];
  return e && e.tag === 7 ? cpUtf8(cf, e.name) : `<bad class #${i}>`;
}

export function cpNat(cf: ClassFile, i: number): { name: string; desc: string } {
  const e = cf.cp[i];
  return e && e.tag === 12 ? { name: cpUtf8(cf, e.name), desc: cpUtf8(cf, e.desc) } : { name: `<bad nat #${i}>`, desc: '' };
}

export function parseClass(bytes: Uint8Array): ClassFile {
  const r = new Buf(bytes, false);
  if (!isClassFile(bytes)) throw new ParseError('not a Java class file (bad magic or version)');
  const minor = r.u16(4), major = r.u16(6);
  const cpCount = r.u16(8);
  const cp: CpEntry[] = [{ tag: 0 }];
  let p = 10;
  for (let i = 1; i < cpCount; i++) {
    const tag = r.u8(p);
    switch (tag) {
      case 1: { const len = r.u16(p + 1); r.check(p + 3, len); cp.push({ tag: 1, text: mutf8(bytes, p + 3, p + 3 + len) }); p += 3 + len; break; }
      case 3: cp.push({ tag: 3, value: r.i32(p + 1) }); p += 5; break;
      case 4: cp.push({ tag: 4, value: r.f32(p + 1) }); p += 5; break;
      case 5: cp.push({ tag: 5, value: r.i64(p + 1) }); cp.push({ tag: 0 }); i++; p += 9; break;
      case 6: cp.push({ tag: 6, value: r.f64(p + 1) }); cp.push({ tag: 0 }); i++; p += 9; break;
      case 7: cp.push({ tag: 7, name: r.u16(p + 1) }); p += 3; break;
      case 8: cp.push({ tag: 8, string: r.u16(p + 1) }); p += 3; break;
      case 9: case 10: case 11: cp.push({ tag, cls: r.u16(p + 1), nat: r.u16(p + 3) }); p += 5; break;
      case 12: cp.push({ tag: 12, name: r.u16(p + 1), desc: r.u16(p + 3) }); p += 5; break;
      case 15: cp.push({ tag: 15, kind: r.u8(p + 1), ref: r.u16(p + 2) }); p += 4; break;
      case 16: cp.push({ tag: 16, desc: r.u16(p + 1) }); p += 3; break;
      case 17: case 18: cp.push({ tag, bsm: r.u16(p + 1), nat: r.u16(p + 3) }); p += 5; break;
      case 19: case 20: cp.push({ tag, name: r.u16(p + 1) }); p += 3; break;
      default: throw new ParseError(`bad constant pool tag ${tag} at offset ${p}`);
    }
  }
  const cf: ClassFile = {
    bytes, minor, major, javaVersion: javaVersionOf(major), cp, access: 0, thisClass: '', interfaces: [], fields: [], methods: [], attributes: [],
  };
  cf.access = r.u16(p);
  cf.thisClass = cpClass(cf, r.u16(p + 2));
  const sup = r.u16(p + 4);
  if (sup) cf.superClass = cpClass(cf, sup);
  const ni = r.u16(p + 6);
  p += 8;
  for (let i = 0; i < ni; i++) { cf.interfaces.push(cpClass(cf, r.u16(p))); p += 2; }
  const readAttrs = (): Attribute[] => {
    const n = r.u16(p); p += 2;
    const out: Attribute[] = [];
    for (let i = 0; i < n; i++) {
      const name = cpUtf8(cf, r.u16(p));
      const len = r.u32(p + 2);
      r.check(p + 6, len);
      out.push({ name, offset: p + 6, length: len });
      p += 6 + len;
    }
    return out;
  };
  const readMembers = (isMethod: boolean): Member[] => {
    const n = r.u16(p); p += 2;
    const out: Member[] = [];
    for (let i = 0; i < n; i++) {
      const access = r.u16(p);
      const name = cpUtf8(cf, r.u16(p + 2));
      const descriptor = cpUtf8(cf, r.u16(p + 4));
      p += 6;
      const attributes = readAttrs();
      const m: Member = { access, name, descriptor, attributes, exceptions: [] };
      for (const a of attributes) {
        if (a.name === 'Signature' && a.length >= 2) m.signature = cpUtf8(cf, r.u16(a.offset));
        else if (a.name === 'ConstantValue' && a.length >= 2) m.constantValue = r.u16(a.offset);
        else if (isMethod && a.name === 'Exceptions') {
          const k = r.u16(a.offset);
          for (let j = 0; j < k && 2 + j * 2 + 2 <= a.length; j++) m.exceptions.push(cpClass(cf, r.u16(a.offset + 2 + j * 2)));
        } else if (isMethod && a.name === 'Code') m.code = parseCode(r, cf, a);
      }
      out.push(m);
    }
    return out;
  };
  cf.fields = readMembers(false);
  cf.methods = readMembers(true);
  cf.attributes = readAttrs();
  for (const a of cf.attributes) {
    if (a.name === 'SourceFile' && a.length >= 2) cf.sourceFile = cpUtf8(cf, r.u16(a.offset));
    else if (a.name === 'Signature' && a.length >= 2) cf.signature = cpUtf8(cf, r.u16(a.offset));
  }
  return cf;
}

function parseCode(r: Buf, cf: ClassFile, a: Attribute): CodeAttr {
  const o = a.offset;
  const end = o + a.length;
  const codeLen = r.u32(o + 4);
  if (o + 8 + codeLen > end) throw new ParseError('Code attribute is shorter than its code');
  const exOff = o + 8 + codeLen;
  const n = r.u16(exOff);
  const exceptions: ExceptionEntry[] = [];
  for (let i = 0; i < n; i++) {
    const e = exOff + 2 + i * 8;
    if (e + 8 > end) break;
    exceptions.push({ start: r.u16(e), end: r.u16(e + 2), handler: r.u16(e + 4), catchType: r.u16(e + 6) });
  }
  void cf;
  return { maxStack: r.u16(o), maxLocals: r.u16(o + 2), codeOff: o + 8, codeLen, exceptions, attributes: [] };
}

function javaVersionOf(major: number): string {
  if (major >= 49) return String(major - 44);
  return ({ 45: '1.1', 46: '1.2', 47: '1.3', 48: '1.4' } as Record<number, string>)[major] ?? `major ${major}`;
}

// ------------------------------------------------------------- descriptors and signatures

/** Field descriptor to Java source type, for example [Ljava/lang/String; to java.lang.String[]. */
export function descToJava(d: string): string {
  let dims = 0;
  while (d[dims] === '[') dims++;
  const base = d.slice(dims);
  const prim: Record<string, string> = { B: 'byte', C: 'char', D: 'double', F: 'float', I: 'int', J: 'long', S: 'short', Z: 'boolean', V: 'void' };
  const t = base.startsWith('L') ? base.slice(1, -1).replace(/\//g, '.') : (prim[base] ?? base);
  return t + '[]'.repeat(dims);
}

/** Split a method descriptor into parameter descriptors and return descriptor. */
export function splitMethodDesc(d: string): { params: string[]; ret: string } {
  const params: string[] = [];
  let i = 1;
  let guard = 0;
  while (i < d.length && d[i] !== ')' && guard++ < 256) {
    const s = i;
    while (d[i] === '[') i++;
    if (d[i] === 'L') { const e = d.indexOf(';', i); i = e < 0 ? d.length : e + 1; } else i++;
    params.push(d.slice(s, i));
  }
  return { params, ret: d.slice(i + 1) };
}

/** Render a generic signature type (JVMS 4.7.9.1) as Java source text. */
export function sigTypeToJava(sig: string): { text: string; next: number } {
  return readSigType(sig, 0, 0);
}

function readSigType(s: string, i: number, depth: number): { text: string; next: number } {
  if (depth > 32) return { text: '?', next: s.length };
  const c = s[i];
  const prim: Record<string, string> = { B: 'byte', C: 'char', D: 'double', F: 'float', I: 'int', J: 'long', S: 'short', Z: 'boolean', V: 'void' };
  if (c === '[') { const t = readSigType(s, i + 1, depth + 1); return { text: `${t.text}[]`, next: t.next }; }
  if (c === 'T') { const e = s.indexOf(';', i); return { text: s.slice(i + 1, e < 0 ? s.length : e), next: e < 0 ? s.length : e + 1 }; }
  if (c === 'L') {
    let out = '';
    let j = i + 1;
    let seg = '';
    while (j < s.length) {
      const ch = s[j] as string;
      if (ch === ';') { out += seg.replace(/\//g, '.'); return { text: out, next: j + 1 }; }
      if (ch === '.') { out += `${seg.replace(/\//g, '.')}.`; seg = ''; j++; continue; }
      if (ch === '<') {
        out += seg.replace(/\//g, '.');
        seg = '';
        j++;
        const args: string[] = [];
        let guard = 0;
        while (j < s.length && s[j] !== '>' && guard++ < 64) {
          const w = s[j];
          if (w === '*') { args.push('?'); j++; continue; }
          if (w === '+' || w === '-') {
            const t = readSigType(s, j + 1, depth + 1);
            args.push(`? ${w === '+' ? 'extends' : 'super'} ${t.text}`);
            j = t.next;
            continue;
          }
          const t = readSigType(s, j, depth + 1);
          args.push(t.text);
          j = t.next;
        }
        out += `<${args.join(', ')}>`;
        j++;
        continue;
      }
      seg += ch;
      j++;
    }
    return { text: out + seg, next: j };
  }
  return { text: prim[c ?? ''] ?? (c ?? '?'), next: i + 1 };
}

/** Parse a method signature into type params, params, return and throws (all as Java text). */
export function methodSigToJava(sig: string): { typeParams?: string; params: string[]; ret: string; throws: string[] } {
  let i = 0;
  let typeParams: string | undefined;
  if (sig[0] === '<') {
    const r = readTypeParams(sig, 0);
    typeParams = r.text;
    i = r.next;
  }
  const params: string[] = [];
  i++; // (
  let guard = 0;
  while (i < sig.length && sig[i] !== ')' && guard++ < 256) { const t = readSigType(sig, i, 0); params.push(t.text); i = t.next; }
  i++;
  const ret = readSigType(sig, i, 0);
  i = ret.next;
  const throws: string[] = [];
  guard = 0;
  while (sig[i] === '^' && guard++ < 64) { const t = readSigType(sig, i + 1, 0); throws.push(t.text); i = t.next; }
  return { ...(typeParams ? { typeParams } : {}), params, ret: ret.text, throws };
}

function readTypeParams(s: string, i: number): { text: string; next: number } {
  const parts: string[] = [];
  let j = i + 1;
  let guard = 0;
  while (j < s.length && s[j] !== '>' && guard++ < 64) {
    const colon = s.indexOf(':', j);
    if (colon < 0) break;
    const name = s.slice(j, colon);
    j = colon;
    const bounds: string[] = [];
    let g2 = 0;
    while (s[j] === ':' && g2++ < 16) {
      j++;
      if (s[j] === ':') continue;
      const t = readSigType(s, j, 0);
      if (t.text !== 'java.lang.Object') bounds.push(t.text);
      j = t.next;
    }
    parts.push(bounds.length ? `${name} extends ${bounds.join(' & ')}` : name);
  }
  return { text: `<${parts.join(', ')}>`, next: j + 1 };
}

/** Class signature: type params, superclass and interfaces as Java text. */
export function classSigToJava(sig: string): { typeParams?: string; superClass: string; interfaces: string[] } {
  let i = 0;
  let typeParams: string | undefined;
  if (sig[0] === '<') { const r = readTypeParams(sig, 0); typeParams = r.text; i = r.next; }
  const sup = readSigType(sig, i, 0);
  i = sup.next;
  const interfaces: string[] = [];
  let guard = 0;
  while (i < sig.length && guard++ < 64) { const t = readSigType(sig, i, 0); interfaces.push(t.text); i = t.next; }
  return { ...(typeParams ? { typeParams } : {}), superClass: sup.text, interfaces };
}
