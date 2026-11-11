// DEX file parser (versions 035 to 041). Lazy, bounds-checked, safe on hostile input.
// Format reference: source.android.com/docs/core/runtime/dex-format.

import { Buf, ParseError, mutf8 } from '../bytes.js';

export const DEX_LIMITS = {
  maxIds: 4_000_000,
  maxClassMembers: 200_000,
  maxInsnUnits: 1 << 20,
  maxTries: 65_535,
  maxEncodedDepth: 32,
};

export const NO_INDEX = 0xffffffff;

export interface Proto { shorty: string; ret: string; params: string[] }
export interface FieldId { cls: string; type: string; name: string }
export interface MethodId { cls: string; name: string; proto: Proto; protoIdx: number }

export interface EncodedField { fieldIdx: number; access: number }
export interface EncodedMethod { methodIdx: number; access: number; codeOff: number }

export interface ClassData {
  staticFields: EncodedField[];
  instanceFields: EncodedField[];
  directMethods: EncodedMethod[];
  virtualMethods: EncodedMethod[];
}

export interface ClassDef {
  index: number;
  typeIdx: number;
  name: string;
  access: number;
  superclass?: string;
  interfaces: string[];
  sourceFile?: string;
  annotationsOff: number;
  classDataOff: number;
  staticValuesOff: number;
  /** offset of the class_def_item in the file */
  offset: number;
}

export interface TryItem { start: number; count: number; handlers: { type?: string; addr: number }[]; catchAll?: number }

export interface CodeItem {
  offset: number;
  registers: number;
  ins: number;
  outs: number;
  debugInfoOff: number;
  /** offset of the first instruction code unit */
  insnsOff: number;
  /** length in 16-bit code units */
  insnsSize: number;
  tries: TryItem[];
}

export type EncodedValue =
  | { t: 'byte' | 'short' | 'char' | 'int' | 'float' | 'double'; v: number }
  | { t: 'long'; v: bigint }
  | { t: 'string' | 'type'; v: string }
  | { t: 'field' | 'method' | 'enum'; v: string }
  | { t: 'methodtype'; v: string }
  | { t: 'methodhandle'; v: number }
  | { t: 'array'; v: EncodedValue[] }
  | { t: 'annotation'; type: string; elements: { name: string; value: EncodedValue }[] }
  | { t: 'null' }
  | { t: 'boolean'; v: boolean };

export interface MethodHandle { kind: number; kindName: string; target: string }

export interface DexHeader {
  version: number;
  checksum: number;
  fileSize: number;
  headerSize: number;
  endianTag: number;
  mapOff: number;
  stringIds: [number, number];
  typeIds: [number, number];
  protoIds: [number, number];
  fieldIds: [number, number];
  methodIds: [number, number];
  classDefs: [number, number];
  data: [number, number];
  containerSize?: number;
  headerOffset?: number;
}

export function isDex(b: Uint8Array): boolean {
  return b.length >= 0x70 && b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a && b[7] === 0;
}

const HANDLE_KINDS = ['static-put', 'static-get', 'instance-put', 'instance-get', 'invoke-static', 'invoke-instance', 'invoke-constructor', 'invoke-direct', 'invoke-interface'];

export class DexFile {
  readonly r: Buf;
  readonly bytes: Uint8Array;
  readonly header: DexHeader;
  /** base of this dex inside the buffer (non-zero for later dex files inside a v41 container) */
  readonly base: number;
  readonly name: string;
  private strCache = new Map<number, string>();
  private typeCache = new Map<number, string>();
  private protoCache = new Map<number, Proto>();
  private _classes?: ClassDef[];
  private _classByName?: Map<string, ClassDef>;
  private _callSites?: number[];
  private _methodHandles?: number[];

  constructor(bytes: Uint8Array, name = 'classes.dex', base = 0) {
    this.bytes = bytes;
    this.r = new Buf(bytes);
    this.base = base;
    this.name = name;
    if (!isDex(bytes.subarray(base))) throw new ParseError('not a DEX file (bad magic)');
    const r = this.r;
    const vs = String.fromCharCode(r.u8(base + 4), r.u8(base + 5), r.u8(base + 6));
    const version = parseInt(vs, 10);
    if (!(version >= 35 && version <= 99)) throw new ParseError(`unsupported DEX version ${vs}`);
    const endian = r.u32(base + 40);
    if (endian !== 0x12345678) throw new ParseError(`unsupported DEX endian tag 0x${endian.toString(16)}`);
    const pair = (o: number): [number, number] => {
      const size = r.u32(base + o);
      const off = r.u32(base + o + 4);
      if (size > DEX_LIMITS.maxIds) throw new ParseError(`DEX table at 0x${o.toString(16)} claims ${size} items`);
      return [size, off];
    };
    this.header = {
      version,
      checksum: r.u32(base + 8),
      fileSize: r.u32(base + 32),
      headerSize: r.u32(base + 36),
      endianTag: endian,
      mapOff: r.u32(base + 52),
      stringIds: pair(56), typeIds: pair(64), protoIds: pair(72), fieldIds: pair(80),
      methodIds: pair(88), classDefs: pair(96), data: pair(104),
    };
    if (version >= 41 && this.header.headerSize >= 0x78) {
      this.header.containerSize = r.u32(base + 0x70);
      this.header.headerOffset = r.u32(base + 0x74);
    }
    // Validate table placement now so later accessors fail early and clearly.
    const tbl = (p: [number, number], sz: number, what: string): void => {
      if (p[0] && !r.has(p[1], p[0] * sz)) throw new ParseError(`DEX ${what} table is outside the file`);
    };
    tbl(this.header.stringIds, 4, 'string_ids'); tbl(this.header.typeIds, 4, 'type_ids');
    tbl(this.header.protoIds, 12, 'proto_ids'); tbl(this.header.fieldIds, 8, 'field_ids');
    tbl(this.header.methodIds, 8, 'method_ids'); tbl(this.header.classDefs, 32, 'class_defs');
  }

  get version(): number { return this.header.version; }
  get stringCount(): number { return this.header.stringIds[0]; }
  get typeCount(): number { return this.header.typeIds[0]; }
  get protoCount(): number { return this.header.protoIds[0]; }
  get fieldCount(): number { return this.header.fieldIds[0]; }
  get methodCount(): number { return this.header.methodIds[0]; }
  get classCount(): number { return this.header.classDefs[0]; }

  /** Offset of string_data_item for string i. */
  stringOffset(i: number): number { return this.r.u32(this.header.stringIds[1] + i * 4); }

  string(i: number): string {
    if (i < 0 || i >= this.stringCount) return `<bad string ${i}>`;
    const c = this.strCache.get(i);
    if (c !== undefined) return c;
    const off = this.stringOffset(i);
    const [len, n] = this.r.uleb(off);
    const start = off + n;
    // utf16 length is the char count; mutf8 bytes are at most 3 per char
    let end = start;
    const lim = Math.min(this.bytes.length, start + len * 3 + 1);
    while (end < lim && this.bytes[end] !== 0) end++;
    const s = mutf8(this.bytes, start, end, len);
    if (this.strCache.size < 500_000) this.strCache.set(i, s);
    return s;
  }

  type(i: number): string {
    if (i === 0xffff && i >= this.typeCount) return '<none>';
    if (i < 0 || i >= this.typeCount) return `<bad type ${i}>`;
    const c = this.typeCache.get(i);
    if (c !== undefined) return c;
    const s = this.string(this.r.u32(this.header.typeIds[1] + i * 4));
    this.typeCache.set(i, s);
    return s;
  }

  typeList(off: number): string[] {
    if (!off) return [];
    const n = this.r.u32(off);
    if (n > 65_535) throw new ParseError(`type_list at ${off} claims ${n} entries`);
    const out: string[] = [];
    for (let i = 0; i < n; i++) out.push(this.type(this.r.u16(off + 4 + i * 2)));
    return out;
  }

  proto(i: number): Proto {
    const c = this.protoCache.get(i);
    if (c) return c;
    if (i < 0 || i >= this.protoCount) return { shorty: '', ret: '<bad proto>', params: [] };
    const o = this.header.protoIds[1] + i * 12;
    const p: Proto = { shorty: this.string(this.r.u32(o)), ret: this.type(this.r.u32(o + 4)), params: this.typeList(this.r.u32(o + 8)) };
    this.protoCache.set(i, p);
    return p;
  }

  protoString(i: number): string { const p = this.proto(i); return `(${p.params.join('')})${p.ret}`; }

  field(i: number): FieldId {
    if (i < 0 || i >= this.fieldCount) return { cls: '<bad>', type: '<bad>', name: `<bad field ${i}>` };
    const o = this.header.fieldIds[1] + i * 8;
    return { cls: this.type(this.r.u16(o)), type: this.type(this.r.u16(o + 2)), name: this.string(this.r.u32(o + 4)) };
  }

  fieldRef(i: number): string { const f = this.field(i); return `${f.cls}->${f.name}:${f.type}`; }

  method(i: number): MethodId {
    if (i < 0 || i >= this.methodCount) return { cls: '<bad>', name: `<bad method ${i}>`, proto: { shorty: '', ret: 'V', params: [] }, protoIdx: -1 };
    const o = this.header.methodIds[1] + i * 8;
    const protoIdx = this.r.u16(o + 2);
    return { cls: this.type(this.r.u16(o)), name: this.string(this.r.u32(o + 4)), proto: this.proto(protoIdx), protoIdx };
  }

  methodRef(i: number): string {
    const m = this.method(i);
    return `${m.cls}->${m.name}(${m.proto.params.join('')})${m.proto.ret}`;
  }

  get classes(): ClassDef[] {
    if (this._classes) return this._classes;
    const out: ClassDef[] = [];
    const [n, off] = this.header.classDefs;
    for (let i = 0; i < n; i++) {
      const o = off + i * 32;
      const typeIdx = this.r.u32(o);
      const sup = this.r.u32(o + 8);
      const src = this.r.u32(o + 16);
      const cd: ClassDef = {
        index: i, typeIdx, name: this.type(typeIdx), access: this.r.u32(o + 4),
        interfaces: [], annotationsOff: this.r.u32(o + 20), classDataOff: this.r.u32(o + 24), staticValuesOff: this.r.u32(o + 28), offset: o,
      };
      if (sup !== NO_INDEX) cd.superclass = this.type(sup);
      if (src !== NO_INDEX) cd.sourceFile = this.string(src);
      try { cd.interfaces = this.typeList(this.r.u32(o + 12)); } catch { cd.interfaces = []; }
      out.push(cd);
    }
    this._classes = out;
    return out;
  }

  classByName(name: string): ClassDef | undefined {
    if (!this._classByName) {
      this._classByName = new Map();
      for (const c of this.classes) this._classByName.set(c.name, c);
    }
    return this._classByName.get(toDescriptor(name));
  }

  classData(cd: ClassDef): ClassData {
    const out: ClassData = { staticFields: [], instanceFields: [], directMethods: [], virtualMethods: [] };
    if (!cd.classDataOff) return out;
    let p = cd.classDataOff;
    const rd = (): number => { const [v, n] = this.r.uleb(p); p += n; return v; };
    const sf = rd(), inf = rd(), dm = rd(), vm = rd();
    if (sf + inf + dm + vm > DEX_LIMITS.maxClassMembers) throw new ParseError(`class ${cd.name} claims too many members`);
    const fields = (n: number, into: EncodedField[]): void => {
      let idx = 0;
      for (let i = 0; i < n; i++) { idx += rd(); into.push({ fieldIdx: idx, access: rd() }); }
    };
    const methods = (n: number, into: EncodedMethod[]): void => {
      let idx = 0;
      for (let i = 0; i < n; i++) { idx += rd(); const access = rd(); const codeOff = rd(); into.push({ methodIdx: idx, access, codeOff }); }
    };
    fields(sf, out.staticFields); fields(inf, out.instanceFields);
    methods(dm, out.directMethods); methods(vm, out.virtualMethods);
    return out;
  }

  code(off: number): CodeItem | undefined {
    if (!off) return undefined;
    const r = this.r;
    const insnsSize = r.u32(off + 12);
    if (insnsSize > DEX_LIMITS.maxInsnUnits) throw new ParseError(`code item at ${off} claims ${insnsSize} code units`);
    const insnsOff = off + 16;
    r.check(insnsOff, insnsSize * 2);
    const triesSize = r.u16(off + 6);
    const ci: CodeItem = { offset: off, registers: r.u16(off), ins: r.u16(off + 2), outs: r.u16(off + 4), debugInfoOff: r.u32(off + 8), insnsOff, insnsSize, tries: [] };
    if (triesSize) {
      let tOff = insnsOff + insnsSize * 2;
      if (insnsSize & 1) tOff += 2;
      const hBase = tOff + triesSize * 8;
      for (let i = 0; i < triesSize; i++) {
        const t = tOff + i * 8;
        const start = r.u32(t), count = r.u16(t + 4), hOff = r.u16(t + 6);
        const item: TryItem = { start, count, handlers: [] };
        let p = hBase + hOff;
        let [size, n] = r.sleb(p); p += n;
        const abs = Math.min(Math.abs(size), 1024);
        for (let k = 0; k < abs; k++) {
          const [ti, a] = r.uleb(p); p += a;
          const [addr, b] = r.uleb(p); p += b;
          item.handlers.push({ type: this.type(ti), addr });
        }
        if (size <= 0) { const [addr] = r.uleb(p); item.catchAll = addr; }
        ci.tries.push(item);
      }
    }
    return ci;
  }

  /** Read one 16-bit code unit of a method. */
  unit(ci: CodeItem, addr: number): number { return this.r.u16(ci.insnsOff + addr * 2); }

  // ------------------------------------------------------------- encoded values

  encodedValue(p: number, depth = 0): [EncodedValue, number] {
    if (depth > DEX_LIMITS.maxEncodedDepth) throw new ParseError('encoded value nesting too deep');
    const r = this.r;
    const h = r.u8(p);
    const type = h & 0x1f;
    const arg = h >> 5;
    const size = arg + 1;
    p++;
    const readU = (n: number): bigint => { let v = 0n; for (let i = 0; i < n; i++) v |= BigInt(r.u8(p + i)) << BigInt(8 * i); return v; };
    const readS = (n: number): bigint => { const v = readU(n); const bits = BigInt(n * 8); return v >= 1n << (bits - 1n) ? v - (1n << bits) : v; };
    switch (type) {
      case 0x00: return [{ t: 'byte', v: Number(readS(1)) }, 2];
      case 0x02: return [{ t: 'short', v: Number(readS(size)) }, 1 + size];
      case 0x03: return [{ t: 'char', v: Number(readU(size)) }, 1 + size];
      case 0x04: return [{ t: 'int', v: Number(readS(size)) }, 1 + size];
      case 0x06: return [{ t: 'long', v: readS(size) }, 1 + size];
      case 0x10: { const v = Number(readU(size) << BigInt((4 - size) * 8)); const dv = new DataView(new ArrayBuffer(4)); dv.setUint32(0, v >>> 0); return [{ t: 'float', v: dv.getFloat32(0) }, 1 + size]; }
      case 0x11: { const v = readU(size) << BigInt((8 - size) * 8); const dv = new DataView(new ArrayBuffer(8)); dv.setBigUint64(0, v); return [{ t: 'double', v: dv.getFloat64(0) }, 1 + size]; }
      case 0x15: return [{ t: 'methodtype', v: this.protoString(Number(readU(size))) }, 1 + size];
      case 0x16: return [{ t: 'methodhandle', v: Number(readU(size)) }, 1 + size];
      case 0x17: return [{ t: 'string', v: this.string(Number(readU(size))) }, 1 + size];
      case 0x18: return [{ t: 'type', v: this.type(Number(readU(size))) }, 1 + size];
      case 0x19: return [{ t: 'field', v: this.fieldRef(Number(readU(size))) }, 1 + size];
      case 0x1a: return [{ t: 'method', v: this.methodRef(Number(readU(size))) }, 1 + size];
      case 0x1b: return [{ t: 'enum', v: this.fieldRef(Number(readU(size))) }, 1 + size];
      case 0x1c: { const [arr, n] = this.encodedArray(p, depth + 1); return [{ t: 'array', v: arr }, 1 + n]; }
      case 0x1d: { const [ann, n] = this.encodedAnnotation(p, depth + 1); return [ann, 1 + n]; }
      case 0x1e: return [{ t: 'null' }, 1];
      case 0x1f: return [{ t: 'boolean', v: arg !== 0 }, 1];
      default: throw new ParseError(`bad encoded value type 0x${type.toString(16)} at ${p - 1}`);
    }
  }

  encodedArray(p: number, depth = 0): [EncodedValue[], number] {
    const start = p;
    const [n, a] = this.r.uleb(p); p += a;
    if (n > 1_000_000) throw new ParseError('encoded array too large');
    const out: EncodedValue[] = [];
    for (let i = 0; i < n; i++) { const [v, k] = this.encodedValue(p, depth); out.push(v); p += k; }
    return [out, p - start];
  }

  encodedAnnotation(p: number, depth = 0): [EncodedValue & { t: 'annotation' }, number] {
    const start = p;
    const [ti, a] = this.r.uleb(p); p += a;
    const [n, b] = this.r.uleb(p); p += b;
    if (n > 65_535) throw new ParseError('annotation has too many elements');
    const elements: { name: string; value: EncodedValue }[] = [];
    for (let i = 0; i < n; i++) {
      const [ni, c] = this.r.uleb(p); p += c;
      const [v, k] = this.encodedValue(p, depth); p += k;
      elements.push({ name: this.string(ni), value: v });
    }
    return [{ t: 'annotation', type: this.type(ti), elements }, p - start];
  }

  staticValues(cd: ClassDef): EncodedValue[] {
    if (!cd.staticValuesOff) return [];
    try { return this.encodedArray(cd.staticValuesOff)[0]; } catch { return []; }
  }

  /** Class-level annotation types (for example Lkotlin/Metadata;). */
  classAnnotations(cd: ClassDef): { visibility: number; annotation: EncodedValue & { t: 'annotation' } }[] {
    if (!cd.annotationsOff) return [];
    const out: { visibility: number; annotation: EncodedValue & { t: 'annotation' } }[] = [];
    try {
      const setOff = this.r.u32(cd.annotationsOff);
      if (!setOff) return out;
      const n = Math.min(this.r.u32(setOff), 256);
      for (let i = 0; i < n; i++) {
        const itemOff = this.r.u32(setOff + 4 + i * 4);
        const vis = this.r.u8(itemOff);
        out.push({ visibility: vis, annotation: this.encodedAnnotation(itemOff + 1)[0] });
      }
    } catch { /* ignore broken annotations */ }
    return out;
  }

  // ------------------------------------------------------------- map list items

  private mapItems(): { type: number; size: number; offset: number }[] {
    const off = this.header.mapOff;
    if (!off || !this.r.has(off, 4)) return [];
    const n = Math.min(this.r.u32(off), 64);
    const out = [];
    for (let i = 0; i < n; i++) {
      const o = off + 4 + i * 12;
      if (!this.r.has(o, 12)) break;
      out.push({ type: this.r.u16(o), size: this.r.u32(o + 4), offset: this.r.u32(o + 8) });
    }
    return out;
  }

  mapList(): { type: string; size: number; offset: number }[] {
    const names: Record<number, string> = {
      0x0000: 'header_item', 0x0001: 'string_id_item', 0x0002: 'type_id_item', 0x0003: 'proto_id_item', 0x0004: 'field_id_item',
      0x0005: 'method_id_item', 0x0006: 'class_def_item', 0x0007: 'call_site_id_item', 0x0008: 'method_handle_item',
      0x1000: 'map_list', 0x1001: 'type_list', 0x1002: 'annotation_set_ref_list', 0x1003: 'annotation_set_item',
      0x2000: 'class_data_item', 0x2001: 'code_item', 0x2002: 'string_data_item', 0x2003: 'debug_info_item',
      0x2004: 'annotation_item', 0x2005: 'encoded_array_item', 0x2006: 'annotations_directory_item', 0xf000: 'hiddenapi_class_data_item',
    };
    return this.mapItems().map((m) => ({ type: names[m.type] ?? `0x${m.type.toString(16)}`, size: m.size, offset: m.offset }));
  }

  get callSiteOffsets(): number[] {
    if (!this._callSites) {
      const m = this.mapItems().find((x) => x.type === 0x0007);
      this._callSites = [];
      if (m) for (let i = 0; i < Math.min(m.size, DEX_LIMITS.maxIds); i++) this._callSites.push(this.r.u32(m.offset + i * 4));
    }
    return this._callSites;
  }

  get methodHandleOffsets(): number[] {
    if (!this._methodHandles) {
      const m = this.mapItems().find((x) => x.type === 0x0008);
      this._methodHandles = [];
      if (m) for (let i = 0; i < Math.min(m.size, DEX_LIMITS.maxIds); i++) this._methodHandles.push(m.offset + i * 8);
    }
    return this._methodHandles;
  }

  methodHandle(i: number): MethodHandle {
    const off = this.methodHandleOffsets[i];
    if (off === undefined) return { kind: -1, kindName: 'bad', target: `<bad method handle ${i}>` };
    const kind = this.r.u16(off);
    const id = this.r.u16(off + 4);
    const target = kind <= 3 ? this.fieldRef(id) : this.methodRef(id);
    return { kind, kindName: HANDLE_KINDS[kind] ?? `kind${kind}`, target };
  }

  callSite(i: number): { name: string; values: EncodedValue[] } {
    const off = this.callSiteOffsets[i];
    if (off === undefined) return { name: `call_site_${i}`, values: [] };
    try {
      const values = this.encodedArray(off)[0];
      const name = values[1] && values[1].t === 'string' ? values[1].v : `call_site_${i}`;
      return { name, values };
    } catch { return { name: `call_site_${i}`, values: [] }; }
  }

  /** Line number table from debug_info_item, address to line, plus parameter names. */
  debugInfo(ci: CodeItem): { lines: Map<number, number>; params: (string | undefined)[] } {
    const lines = new Map<number, number>();
    const params: (string | undefined)[] = [];
    if (!ci.debugInfoOff) return { lines, params };
    try {
      let p = ci.debugInfoOff;
      const rd = (): number => { const [v, n] = this.r.uleb(p); p += n; return v; };
      const rds = (): number => { const [v, n] = this.r.sleb(p); p += n; return v; };
      let line = rd();
      const np = rd();
      for (let i = 0; i < Math.min(np, 255); i++) { const s = rd() - 1; params.push(s >= 0 ? this.string(s) : undefined); }
      let addr = 0;
      for (let guard = 0; guard < 1_000_000; guard++) {
        const op = this.r.u8(p++);
        if (op === 0x00) break;
        switch (op) {
          case 0x01: addr += rd(); break;
          case 0x02: line += rds(); break;
          case 0x03: rd(); rd(); rd(); break;
          case 0x04: rd(); rd(); rd(); rd(); break;
          case 0x05: case 0x06: rd(); break;
          case 0x07: case 0x08: break;
          case 0x09: rd(); break;
          default: {
            const adj = op - 0x0a;
            line += -4 + (adj % 15);
            addr += Math.floor(adj / 15);
            if (!lines.has(addr)) lines.set(addr, line);
          }
        }
      }
    } catch { /* keep what decoded */ }
    return { lines, params };
  }
}

/** Accept Java names (a.b.C), smali descriptors (La/b/C;) or slash names. */
export function toDescriptor(name: string): string {
  if (name.startsWith('L') && name.endsWith(';')) return name;
  if (name.startsWith('[')) return name;
  return `L${name.replace(/\./g, '/')};`;
}

/** La/b/C; to a.b.C */
export function toJavaName(desc: string): string {
  let dims = 0;
  while (desc[dims] === '[') dims++;
  let base = desc.slice(dims);
  const prims: Record<string, string> = { V: 'void', Z: 'boolean', B: 'byte', S: 'short', C: 'char', I: 'int', J: 'long', F: 'float', D: 'double' };
  if (base.startsWith('L') && base.endsWith(';')) base = base.slice(1, -1).replace(/\//g, '.');
  else base = prims[base] ?? base;
  return base + '[]'.repeat(dims);
}

/** Parse every DEX inside a buffer. Handles the v41 container format with several dex headers. */
export function openDex(bytes: Uint8Array, name = 'classes.dex'): DexFile[] {
  const first = new DexFile(bytes, name, 0);
  if (first.version < 41 || !first.header.containerSize) return [first];
  const out = [first];
  // v41 container: later headers follow at file_size boundaries, offsets are relative to the container start.
  let off = first.header.fileSize;
  while (off > 0 && off + 0x70 <= bytes.length && out.length < 256) {
    if (!isDex(bytes.subarray(off))) break;
    const d = new DexFile(bytes, `${name}#${out.length}`, off);
    out.push(d);
    if (!d.header.fileSize) break;
    off += d.header.fileSize;
  }
  return out;
}
