// Protocol Buffers descriptors embedded in binaries and bundles: raw or gzipped
// FileDescriptorProto bytes (Go protoc-gen-go, C++ protoc, Java), Python _pb2 AddSerializedFile
// literals and protobuf-es fileDesc("base64") strings. Decodes them and rebuilds .proto text.

import { ParseError, utf8, latin1, inflate } from '../util.js';

// --- minimal protobuf wire reader ---
class Wire {
  p = 0;
  constructor(readonly b: Uint8Array, readonly end = b.length) {}
  get done(): boolean { return this.p >= this.end; }
  varint(): number {
    let r = 0, mul = 1;
    for (let i = 0; i < 10; i++) {
      if (this.p >= this.end) throw new ParseError('truncated varint', this.p);
      const c = this.b[this.p++]!;
      if (i < 8) r += (c & 0x7f) * mul;
      mul *= 128;
      if (!(c & 0x80)) return r;
    }
    throw new ParseError('varint too long', this.p);
  }
  tag(): [number, number] { const t = this.varint(); return [Math.floor(t / 8), t & 7]; }
  bytes(): Uint8Array { const n = this.varint(); if (this.p + n > this.end) throw new ParseError('length out of range', this.p); const s = this.b.subarray(this.p, this.p + n); this.p += n; return s; }
  skip(wt: number): void {
    if (wt === 0) this.varint();
    else if (wt === 1) this.p += 8;
    else if (wt === 2) this.bytes();
    else if (wt === 5) this.p += 4;
    else throw new ParseError(`unsupported wire type ${wt}`, this.p);
    if (this.p > this.end) throw new ParseError('field out of range', this.p);
  }
}

type Handler = (w: Wire, field: number, wt: number) => boolean;
function each(b: Uint8Array, h: Handler, depth: number): void {
  if (depth > 32) throw new ParseError('descriptor nesting too deep');
  const w = new Wire(b);
  while (!w.done) {
    const [f, wt] = w.tag();
    if (f === 0) throw new ParseError('field number 0');
    if (!h(w, f, wt)) w.skip(wt);
  }
}
const str = (w: Wire): string => { const s = utf8(w.bytes()); if (s.includes('\uFFFD')) throw new ParseError('invalid UTF-8 in descriptor'); return s; };

export interface ProtoField { name: string; number: number; label: string; type: string; typeName?: string; jsonName?: string; oneofIndex?: number; proto3Optional?: boolean }
export interface ProtoMessage { name: string; fields: ProtoField[]; nested: ProtoMessage[]; enums: ProtoEnum[]; oneofs: string[]; mapEntry?: boolean }
export interface ProtoEnum { name: string; values: { name: string; number: number }[] }
export interface ProtoMethod { name: string; inputType: string; outputType: string; clientStreaming: boolean; serverStreaming: boolean; httpRule?: string }
export interface ProtoService { name: string; methods: ProtoMethod[] }
export interface ProtoFile { name: string; package: string; syntax: string; edition?: number; dependencies: string[]; messages: ProtoMessage[]; enums: ProtoEnum[]; services: ProtoService[]; goPackage?: string; javaPackage?: string }

const TYPES = ['', 'double', 'float', 'int64', 'uint64', 'int32', 'fixed64', 'fixed32', 'bool', 'string', 'group', 'message', 'bytes', 'uint32', 'enum', 'sfixed32', 'sfixed64', 'sint32', 'sint64'];
const LABELS = ['', 'optional', 'required', 'repeated'];

function decodeEnum(b: Uint8Array, d: number): ProtoEnum {
  const e: ProtoEnum = { name: '', values: [] };
  each(b, (w, f, wt) => {
    if (f === 1 && wt === 2) { e.name = str(w); return true; }
    if (f === 2 && wt === 2) { const v = { name: '', number: 0 }; each(w.bytes(), (x, g, t) => { if (g === 1 && t === 2) { v.name = str(x); return true; } if (g === 2 && t === 0) { v.number = x.varint() | 0; return true; } return false; }, d + 1); e.values.push(v); return true; }
    return false;
  }, d);
  return e;
}
function decodeMessage(b: Uint8Array, d: number): ProtoMessage {
  const m: ProtoMessage = { name: '', fields: [], nested: [], enums: [], oneofs: [] };
  each(b, (w, f, wt) => {
    if (wt !== 2) return false;
    if (f === 1) { m.name = str(w); return true; }
    if (f === 2 || f === 6) {
      const fl: ProtoField = { name: '', number: 0, label: 'optional', type: '' };
      each(w.bytes(), (x, g, t) => {
        if (g === 1 && t === 2) fl.name = str(x);
        else if (g === 3 && t === 0) fl.number = x.varint();
        else if (g === 4 && t === 0) fl.label = LABELS[x.varint()] ?? 'optional';
        else if (g === 5 && t === 0) fl.type = TYPES[x.varint()] ?? 'unknown';
        else if (g === 6 && t === 2) fl.typeName = str(x);
        else if (g === 9 && t === 0) fl.oneofIndex = x.varint();
        else if (g === 10 && t === 2) fl.jsonName = str(x);
        else if (g === 17 && t === 0) fl.proto3Optional = x.varint() !== 0;
        else return false;
        return true;
      }, d + 1);
      if (f === 2) m.fields.push(fl);
      return true;
    }
    if (f === 3) { m.nested.push(decodeMessage(w.bytes(), d + 1)); return true; }
    if (f === 4) { m.enums.push(decodeEnum(w.bytes(), d + 1)); return true; }
    if (f === 8) { let n = ''; each(w.bytes(), (x, g, t) => { if (g === 1 && t === 2) { n = str(x); return true; } return false; }, d + 1); m.oneofs.push(n); return true; }
    if (f === 7) { each(w.bytes(), (x, g, t) => { if (g === 7 && t === 0) { m.mapEntry = x.varint() !== 0; return true; } return false; }, d + 1); return true; }
    return false;
  }, d);
  return m;
}
// google.api.http (field 72295728 in MethodOptions): first pattern only
function httpRule(opts: Uint8Array): string | undefined {
  let rule: string | undefined;
  each(opts, (w, f, wt) => {
    if (f === 72295728 && wt === 2) {
      each(w.bytes(), (x, g, t) => {
        const verbs: Record<number, string> = { 2: 'GET', 3: 'PUT', 4: 'POST', 5: 'DELETE', 6: 'PATCH' };
        if (t === 2 && verbs[g] && !rule) { rule = `${verbs[g]} ${str(x)}`; return true; }
        return false;
      }, 2);
      return true;
    }
    return false;
  }, 1);
  return rule;
}

/** Decode a serialized google.protobuf.FileDescriptorProto. */
export function decodeFileDescriptor(b: Uint8Array): ProtoFile {
  const fd: ProtoFile = { name: '', package: '', syntax: 'proto2', dependencies: [], messages: [], enums: [], services: [] };
  each(b, (w, f, wt) => {
    if (f === 1 && wt === 2) fd.name = str(w);
    else if (f === 2 && wt === 2) fd.package = str(w);
    else if (f === 3 && wt === 2) fd.dependencies.push(str(w));
    else if (f === 4 && wt === 2) fd.messages.push(decodeMessage(w.bytes(), 1));
    else if (f === 5 && wt === 2) fd.enums.push(decodeEnum(w.bytes(), 1));
    else if (f === 6 && wt === 2) {
      const s: ProtoService = { name: '', methods: [] };
      each(w.bytes(), (x, g, t) => {
        if (g === 1 && t === 2) { s.name = str(x); return true; }
        if (g === 2 && t === 2) {
          const m: ProtoMethod = { name: '', inputType: '', outputType: '', clientStreaming: false, serverStreaming: false };
          each(x.bytes(), (y, h, u) => {
            if (h === 1 && u === 2) m.name = str(y);
            else if (h === 2 && u === 2) m.inputType = str(y);
            else if (h === 3 && u === 2) m.outputType = str(y);
            else if (h === 4 && u === 2) m.httpRule = httpRule(y.bytes());
            else if (h === 5 && u === 0) m.clientStreaming = y.varint() !== 0;
            else if (h === 6 && u === 0) m.serverStreaming = y.varint() !== 0;
            else return false;
            return true;
          }, 3);
          s.methods.push(m);
          return true;
        }
        return false;
      }, 2);
      fd.services.push(s);
    } else if (f === 8 && wt === 2) {
      each(w.bytes(), (x, g, t) => { if (g === 11 && t === 2) { fd.goPackage = str(x); return true; } if (g === 1 && t === 2) { fd.javaPackage = str(x); return true; } return false; }, 2);
    } else if (f === 12 && wt === 2) fd.syntax = str(w);
    else if (f === 14 && wt === 0) { fd.edition = w.varint(); fd.syntax = 'editions'; }
    else return false;
    return true;
  }, 0);
  if (!/\.proto$/.test(fd.name)) throw new ParseError('descriptor name does not end in .proto');
  return fd;
}

/** Render a decoded descriptor back to .proto source text. */
export function protoToText(fd: ProtoFile): string {
  const out: string[] = [`// ${fd.name} (reconstructed by RevLens)`, `syntax = "${fd.syntax === 'editions' ? 'proto3' : fd.syntax}";`];
  if (fd.package) out.push(`package ${fd.package};`);
  for (const d of fd.dependencies) out.push(`import "${d}";`);
  if (fd.goPackage) out.push(`option go_package = "${fd.goPackage}";`);
  out.push('');
  const pfx = fd.package ? `.${fd.package}.` : '.';
  const rel = (t: string): string => (t.startsWith(pfx) ? t.slice(pfx.length) : t.replace(/^\./, ''));
  const tn = (f: ProtoField): string => (f.typeName ? rel(f.typeName) : f.type);
  const en = (e: ProtoEnum, ind: string): void => { out.push(`${ind}enum ${e.name} {`); for (const v of e.values) out.push(`${ind}  ${v.name} = ${v.number};`); out.push(`${ind}}`); };
  const msg = (m: ProtoMessage, ind: string): void => {
    out.push(`${ind}message ${m.name} {`);
    const maps = new Map(m.nested.filter((n) => n.mapEntry).map((n) => [n.name, n]));
    for (const e of m.enums) en(e, ind + '  ');
    // nested messages keep their descriptor order relative to synthesized map entries
    let nextNested = 0;
    const nestedUpTo = (k: number): void => { for (; nextNested < Math.min(k, m.nested.length); nextNested++) if (!m.nested[nextNested]!.mapEntry) msg(m.nested[nextNested]!, ind + '  '); };
    const entryIndex = (f: ProtoField): number => (f.label === 'repeated' && f.typeName ? m.nested.findIndex((n) => n.mapEntry && n.name === f.typeName!.split('.').pop()) : -1);
    const inOneof = new Map<number, ProtoField[]>();
    for (const f of m.fields) if (f.oneofIndex !== undefined && !f.proto3Optional) { const a = inOneof.get(f.oneofIndex) ?? []; a.push(f); inOneof.set(f.oneofIndex, a); }
    const line = (f: ProtoField, i2: string, oneof = false): string => {
      const entry = f.typeName ? maps.get(f.typeName.split('.').pop()!) : undefined;
      if (entry && f.label === 'repeated') { const [k, v] = entry.fields; return `${i2}map<${k ? tn(k) : '?'}, ${v ? tn(v) : '?'}> ${f.name} = ${f.number};`; }
      const label = oneof ? '' : f.label === 'repeated' ? 'repeated ' : f.label === 'required' ? 'required ' : fd.syntax === 'proto2' || f.proto3Optional ? 'optional ' : '';
      return `${i2}${label}${tn(f)} ${f.name} = ${f.number};`;
    };
    // fields in descriptor order; a oneof block goes where its first field is
    const done = new Set<number>();
    for (const f of m.fields) {
      const ei = entryIndex(f);
      if (ei >= 0) { nestedUpTo(ei); nextNested = Math.max(nextNested, ei + 1); }
      if (f.oneofIndex === undefined || f.proto3Optional) { out.push(line(f, ind + '  ')); continue; }
      const i = f.oneofIndex;
      if (done.has(i)) continue;
      done.add(i);
      out.push(`${ind}  oneof ${m.oneofs[i] ?? `oneof_${i}`} {`);
      for (const g of inOneof.get(i) ?? []) out.push(line(g, ind + '    ', true));
      out.push(`${ind}  }`);
    }
    nestedUpTo(m.nested.length);
    out.push(`${ind}}`);
  };
  for (const e of fd.enums) en(e, '');
  for (const m of fd.messages) msg(m, '');
  for (const s of fd.services) {
    out.push(`service ${s.name} {`);
    for (const m of s.methods) out.push(`  rpc ${m.name}(${m.clientStreaming ? 'stream ' : ''}${rel(m.inputType)}) returns (${m.serverStreaming ? 'stream ' : ''}${rel(m.outputType)});${m.httpRule ? ` // ${m.httpRule}` : ''}`);
    out.push('}');
  }
  return out.join('\n') + '\n';
}

export interface FoundDescriptor { offset: number; length: number; encoding: 'raw' | 'gzip' | 'python-literal' | 'base64'; file: ProtoFile; bytes: Uint8Array }

/** Length of a FileDescriptorProto that starts at `at`: consume top level fields while valid. */
function descriptorExtent(b: Uint8Array, at: number, max: number): number {
  const w = new Wire(b, Math.min(b.length, at + max));
  w.p = at;
  let last = at, seenName = false;
  const seen = new Set<number>();
  try {
    while (!w.done) {
      const start = w.p;
      const [f, wt] = w.tag();
      // FileDescriptorProto fields are 1..14; anything else ends the message
      if (f < 1 || f > 14 || (wt !== 0 && wt !== 2)) break;
      if (f === 1) { if (seenName) break; seenName = true; }
      if ((f === 2 || f === 8 || f === 9 || f === 12) && seen.has(f)) break;
      seen.add(f);
      w.skip(wt);
      last = w.p;
      if (start === w.p) break;
    }
  } catch { /* stop at the first bad field */ }
  return last - at;
}

function tryDecode(bytes: Uint8Array): ProtoFile | undefined {
  try { const f = decodeFileDescriptor(bytes); return f.name && (f.messages.length || f.enums.length || f.services.length || f.dependencies.length) ? f : undefined; } catch { return undefined; }
}

/** Find embedded FileDescriptorProto blobs (raw, gzip, Python literal, base64). */
export async function findProtoDescriptors(b: Uint8Array, opts: { max?: number; maxDescriptorSize?: number } = {}): Promise<FoundDescriptor[]> {
  const out: FoundDescriptor[] = [];
  const max = opts.max ?? 2000, cap = opts.maxDescriptorSize ?? 4 << 20;
  const names = new Set<string>();
  const push = (d: FoundDescriptor): void => { if (out.length < max && !names.has(d.file.name)) { names.add(d.file.name); out.push(d); } };
  // raw: 0x0a <len> "....proto"
  for (let i = 0; i + 8 < b.length && out.length < max; i++) {
    if (b[i] !== 0x0a) continue;
    const n = b[i + 1]!;
    if (n < 7 || n > 127 || i + 2 + n > b.length) continue;
    if (b[i + 1 + n - 5] !== 0x2e || b[i + 1 + n - 4] !== 0x70 || b[i + 1 + n - 3] !== 0x72 || b[i + 1 + n - 2] !== 0x6f || b[i + 1 + n - 1] !== 0x74 || b[i + 1 + n] !== 0x6f) continue;
    let ok = true;
    for (let k = i + 2; k < i + 2 + n; k++) { const c = b[k]!; if (c < 0x21 || c > 0x7e) { ok = false; break; } }
    if (!ok) continue;
    const len = descriptorExtent(b, i, cap);
    const file = tryDecode(b.subarray(i, i + len));
    if (file) { push({ offset: i, length: len, encoding: 'raw', file, bytes: b.subarray(i, i + len) }); i += len - 1; }
  }
  // gzip members that inflate to a descriptor (older protoc-gen-go fileDescriptor_* vars)
  for (let i = 0; i + 18 < b.length && out.length < max; i++) {
    if (b[i] !== 0x1f || b[i + 1] !== 0x8b || b[i + 2] !== 0x08) continue;
    try {
      const d = await inflate(b.subarray(i, Math.min(b.length, i + cap)), 'gzip', cap);
      if (d[0] !== 0x0a) continue;
      const len = descriptorExtent(d, 0, cap);
      const file = tryDecode(d.subarray(0, len));
      if (file) push({ offset: i, length: len, encoding: 'gzip', file, bytes: d.subarray(0, len) });
    } catch { /* not a descriptor */ }
  }
  // text: Python AddSerializedFile(b'...') and protobuf-es fileDesc("base64")
  if (b.length < 256 << 20) {
    const text = latin1(b);
    for (const m of text.matchAll(/AddSerializedFile\(\s*b(['"])/g)) {
      const start = m.index! + m[0].length;
      const bytes = pyBytes(text, start, m[1]!);
      const file = bytes && tryDecode(bytes);
      if (file) push({ offset: m.index!, length: bytes.length, encoding: 'python-literal', file, bytes });
      if (out.length >= max) break;
    }
    for (const m of text.matchAll(/fileDesc\(\s*["'`]([A-Za-z0-9+/=_-]{16,})["'`]/g)) {
      let bytes: Uint8Array | undefined;
      try { const s = atob(m[1]!.replace(/-/g, '+').replace(/_/g, '/')); bytes = new Uint8Array(s.length); for (let k = 0; k < s.length; k++) bytes[k] = s.charCodeAt(k); } catch { continue; }
      const file = tryDecode(bytes);
      if (file) push({ offset: m.index!, length: bytes.length, encoding: 'base64', file, bytes });
      if (out.length >= max) break;
    }
  }
  return out;
}

/** Decode a Python bytes literal body starting at `start` up to the closing quote. */
function pyBytes(t: string, start: number, q: string): Uint8Array | undefined {
  const out: number[] = [];
  for (let i = start; i < t.length && out.length < 8 << 20; i++) {
    const c = t[i]!;
    if (c === q) return new Uint8Array(out);
    if (c !== '\\') { out.push(c.charCodeAt(0) & 0xff); continue; }
    const n = t[++i];
    if (n === 'x') { out.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; }
    else if (n === 'n') out.push(10); else if (n === 'r') out.push(13); else if (n === 't') out.push(9);
    else if (n === '\\' || n === "'" || n === '"') out.push(n.charCodeAt(0));
    else if (n !== undefined && n >= '0' && n <= '7') { let o = n; while (o.length < 3 && t[i + 1]! >= '0' && t[i + 1]! <= '7') o += t[++i]; out.push(parseInt(o, 8) & 0xff); }
    else if (n === '\n') continue;
    else out.push(92, (n ?? '').charCodeAt(0));
  }
  return undefined;
}
