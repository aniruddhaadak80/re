// Objective-C runtime metadata from a linked Mach-O image: __objc_classlist, __objc_nlclslist,
// __objc_catlist, __objc_protolist, __objc_selrefs, __objc_classrefs and __objc_superrefs, with
// class_ro_t, method lists (absolute and relative), ivars, properties, protocols and categories.
// Layouts follow the public objc4 runtime headers (objc-runtime-new.h).

import type { MachImage } from './macho-image.js';
import { demangleSwift } from '../demangle/swift/index.js';

export interface ObjcMethod { name: string; types: string; imp?: string; impSymbol?: string }
export interface ObjcIvar { name: string; type: string; offset?: number; size: number; alignment: number }
export interface ObjcProperty { name: string; attributes: string }
export interface ObjcClassRef { name: string; addr?: string; external?: boolean }
export interface ObjcClass {
  addr: string; name: string; demangledName?: string; superclass?: ObjcClassRef; metaclass?: string;
  flags: number; flagNames: string[]; instanceStart: number; instanceSize: number; swift: boolean;
  methods: ObjcMethod[]; classMethods: ObjcMethod[]; ivars: ObjcIvar[]; properties: ObjcProperty[]; classProperties: ObjcProperty[];
  protocols: string[]; methodListKind?: 'absolute' | 'relative'; nonLazy?: boolean; errors?: string[];
}
export interface ObjcProtocol {
  addr: string; name: string; demangledName?: string; protocols: string[];
  instanceMethods: ObjcMethod[]; classMethods: ObjcMethod[]; optionalInstanceMethods: ObjcMethod[]; optionalClassMethods: ObjcMethod[];
  properties: ObjcProperty[]; extendedTypes?: string[]; errors?: string[];
}
export interface ObjcCategory {
  addr: string; name: string; class: ObjcClassRef; instanceMethods: ObjcMethod[]; classMethods: ObjcMethod[];
  protocols: string[]; properties: ObjcProperty[]; classProperties: ObjcProperty[]; nonLazy?: boolean; errors?: string[];
}
export interface ObjcMetadata {
  present: boolean;
  imageInfo?: { version: number; flags: number; swiftVersion?: number; flagNames: string[] };
  classes: ObjcClass[]; categories: ObjcCategory[]; protocols: ObjcProtocol[];
  selectorRefs: number; classRefs: ObjcClassRef[]; superRefs: number; methodNames: number;
  truncated: boolean; errors: string[];
}

export interface ObjcLimits { maxClasses?: number; maxMethods?: number; deadline?: number }

const RO_FLAGS: [number, string][] = [
  [1 << 0, 'RO_META'], [1 << 1, 'RO_ROOT'], [1 << 2, 'RO_HAS_CXX_STRUCTORS'], [1 << 4, 'RO_HIDDEN'], [1 << 5, 'RO_EXCEPTION'],
  [1 << 6, 'RO_HAS_SWIFT_INITIALIZER'], [1 << 7, 'RO_IS_ARC'], [1 << 8, 'RO_HAS_CXX_DTOR_ONLY'], [1 << 9, 'RO_HAS_WEAK_WITHOUT_ARC'],
  [1 << 10, 'RO_FORBIDS_ASSOCIATED_OBJECTS'],
];
const hx = (n: number) => '0x' + n.toString(16);

/** Readable name: Swift mangled class names (_TtC..., _TtP...) are demangled. */
export function objcDisplayName(n: string): string | undefined {
  if (n.startsWith('_Tt')) return demangleSwift(n) ?? undefined;
  return undefined;
}

class Reader {
  readonly errors: string[] = [];
  methodsLeft: number;
  constructor(readonly img: MachImage, readonly lim: Required<ObjcLimits>) { this.methodsLeft = lim.maxMethods; }
  get P() { return this.img.ptrSize; }
  ptr(a: number): number | undefined { return this.img.ptr(a); }
  str(a: number | undefined): string { if (!a) return ''; try { return this.img.readCString(a, 4096); } catch { return ''; } }
  /** Pointer to a class: local address, or an external class bound by name. */
  classRef(a: number): ObjcClassRef | undefined {
    const p = this.img.readPointer(a);
    if (p.bind) return { name: p.bind.replace(/^_OBJC_CLASS_\$_/, '').replace(/^_OBJC_METACLASS_\$_/, ''), external: true };
    if (!p.addr) return undefined;
    return { name: this.classNameAt(p.addr), addr: hx(p.addr) };
  }
  classNameAt(cls: number): string {
    const sym = this.img.symbolAt(cls);
    try {
      const ro = this.roOf(cls);
      if (ro !== undefined) { const n = this.str(this.ptr(ro + (this.P === 8 ? 24 : 16))); if (n) return n; }
    } catch { /* fall back to the symbol */ }
    return sym ? sym.replace(/^_OBJC_CLASS_\$_/, '').replace(/^_OBJC_METACLASS_\$_/, '') : hx(cls);
  }
  roOf(cls: number): number | undefined {
    const d = this.ptr(cls + 4 * this.P);
    if (d === undefined) return undefined;
    const m = this.P === 8 ? d - (d % 8) : d - (d % 4);
    return m % 2 ** 47; // FAST_DATA_MASK
  }
  methods(list: number | undefined, owner: string, meta: boolean): { items: ObjcMethod[]; kind?: 'absolute' | 'relative' } {
    if (!list) return { items: [] };
    const img = this.img;
    const raw = img.readU32(list);
    const count = img.readU32(list + 4);
    const relative = (raw & 0x80000000) !== 0;
    const entsize = raw & 0xfffc;
    const want = relative ? 12 : 3 * this.P;
    if (entsize < want || entsize > 256) throw new Error(`method list at ${hx(list)}: entsize ${entsize}`);
    const n = Math.min(count, 65536, this.methodsLeft);
    if (n < count) this.errors.push(`method list at ${hx(list)} capped at ${n} of ${count}`);
    this.methodsLeft -= n;
    const out: ObjcMethod[] = [];
    for (let i = 0; i < n; i++) {
      const e = list + 8 + i * entsize;
      let name: string, types: string, imp: number | undefined;
      if (relative) {
        const nameRef = e + img.readI32(e);
        // In an image the name field points at a selector reference; fall back to a direct string.
        const sel = (() => { try { return img.ptr(nameRef); } catch { return undefined; } })();
        name = sel ? this.str(sel) : '';
        if (!name) name = this.str(nameRef);
        types = this.str(e + 4 + img.readI32(e + 4));
        const io = img.readI32(e + 8);
        imp = io ? e + 8 + io : undefined;
      } else {
        name = this.str(this.ptr(e));
        types = this.str(this.ptr(e + this.P));
        imp = this.ptr(e + 2 * this.P);
      }
      const m: ObjcMethod = { name, types };
      if (imp !== undefined) {
        m.imp = hx(imp);
        const s = img.symbolAt(imp);
        if (s) m.impSymbol = s;
        else if (!owner.startsWith('0x')) m.impSymbol = `${meta ? '+' : '-'}[${owner} ${name}]`;
      }
      out.push(m);
    }
    return { items: out, kind: relative ? 'relative' : 'absolute' };
  }
  ivars(list: number | undefined): ObjcIvar[] {
    if (!list) return [];
    const img = this.img;
    const entsize = img.readU32(list), count = img.readU32(list + 4);
    const want = 3 * this.P + 8;
    if (entsize < want || entsize > 256) throw new Error(`ivar list at ${hx(list)}: entsize ${entsize}`);
    const out: ObjcIvar[] = [];
    for (let i = 0; i < Math.min(count, 65536); i++) {
      const e = list + 8 + i * entsize;
      const offPtr = this.ptr(e);
      let offset: number | undefined;
      if (offPtr) { try { offset = img.readU32(offPtr); } catch { offset = undefined; } }
      const align = img.readU32(e + 3 * this.P);
      out.push({ name: this.str(this.ptr(e + this.P)), type: this.str(this.ptr(e + 2 * this.P)), offset, size: img.readU32(e + 3 * this.P + 4), alignment: align === 0xffffffff ? this.P === 8 ? 3 : 2 : align });
    }
    return out;
  }
  properties(list: number | undefined): ObjcProperty[] {
    if (!list) return [];
    const img = this.img;
    const entsize = img.readU32(list), count = img.readU32(list + 4);
    if (entsize < 2 * this.P || entsize > 256) throw new Error(`property list at ${hx(list)}: entsize ${entsize}`);
    const out: ObjcProperty[] = [];
    for (let i = 0; i < Math.min(count, 65536); i++) {
      const e = list + 8 + i * entsize;
      out.push({ name: this.str(this.ptr(e)), attributes: this.str(this.ptr(e + this.P)) });
    }
    return out;
  }
  protocolList(list: number | undefined, depth = 0): string[] {
    if (!list || depth > 8) return [];
    const img = this.img;
    const count = this.P === 8 ? img.readU32(list) : img.readU32(list); // low word of a uintptr_t count
    const out: string[] = [];
    for (let i = 0; i < Math.min(count, 4096); i++) {
      const p = img.readPointer(list + this.P + i * this.P);
      if (p.bind) out.push(p.bind.replace(/^__OBJC_PROTOCOL_\$_/, '').replace(/^_OBJC_PROTOCOL_\$_/, ''));
      else if (p.addr) out.push(this.str(this.ptr(p.addr + this.P)) || hx(p.addr));
    }
    return out;
  }
}

function safe<T>(errs: string[], what: string, f: () => T, d: T): T {
  try { return f(); } catch (e) { errs.push(`${what}: ${(e as Error).message}`); return d; }
}

function listSection(img: MachImage, name: string): number[] {
  const out: number[] = [];
  for (const s of img.sectionsNamed(name)) {
    if (s.seg !== '__DATA' && s.seg !== '__DATA_CONST' && s.seg !== '__DATA_DIRTY' && s.seg !== '__AUTH_CONST' && s.seg !== '__AUTH' && s.seg !== '__OBJC2' && s.seg !== '__OBJC_CONST') continue;
    const n = Math.min(Math.floor(s.size / img.ptrSize), 2_000_000);
    for (let i = 0; i < n; i++) out.push(s.addr + i * img.ptrSize);
  }
  return out;
}

/** Read all Objective-C metadata of an image. */
export function readObjc(img: MachImage, limits: ObjcLimits = {}): ObjcMetadata {
  const lim: Required<ObjcLimits> = { maxClasses: limits.maxClasses ?? 100000, maxMethods: limits.maxMethods ?? 2_000_000, deadline: limits.deadline ?? Infinity };
  const r = new Reader(img, lim);
  const md: ObjcMetadata = { present: false, classes: [], categories: [], protocols: [], selectorRefs: 0, classRefs: [], superRefs: 0, methodNames: 0, truncated: false, errors: r.errors };
  const ii = img.sectionsNamed('__objc_imageinfo')[0];
  if (ii && ii.size >= 8) {
    md.present = true;
    try {
      const flags = img.readU32(ii.addr + 4);
      const names: string[] = [];
      if (flags & 2) names.push('SupportsGC'); if (flags & 4) names.push('RequiresGC'); if (flags & 8) names.push('OptimizedByDyld');
      if (flags & 0x20) names.push('IsSimulated'); if (flags & 0x40) names.push('HasCategoryClassProperties');
      const sv = (flags >> 8) & 0xff;
      md.imageInfo = { version: img.readU32(ii.addr), flags, flagNames: names, ...(sv ? { swiftVersion: sv } : {}) };
    } catch (e) { r.errors.push(`imageinfo: ${(e as Error).message}`); }
  }
  const timeUp = () => Date.now() > lim.deadline;
  const nl = new Set<number>();
  for (const a of listSection(img, '__objc_nlclslist')) { const p = safe(r.errors, 'nlclslist', () => img.ptr(a), undefined); if (p) nl.add(p); }
  const nlc = new Set<number>();
  for (const a of listSection(img, '__objc_nlcatlist')) { const p = safe(r.errors, 'nlcatlist', () => img.ptr(a), undefined); if (p) nlc.add(p); }

  for (const slot of listSection(img, '__objc_classlist')) {
    md.present = true;
    if (md.classes.length >= lim.maxClasses || timeUp()) { md.truncated = true; break; }
    const cls = safe(r.errors, `classlist ${hx(slot)}`, () => img.ptr(slot), undefined);
    if (!cls) continue;
    md.classes.push(readClass(r, cls, nl.has(cls)));
  }
  for (const slot of listSection(img, '__objc_catlist')) {
    md.present = true;
    if (timeUp()) { md.truncated = true; break; }
    const cat = safe(r.errors, `catlist ${hx(slot)}`, () => img.ptr(slot), undefined);
    if (!cat) continue;
    const errs: string[] = [];
    const P = img.ptrSize;
    const name = r.str(safe(errs, 'name', () => r.ptr(cat), undefined));
    const cref = safe(errs, 'class', () => r.classRef(cat + P), undefined) ?? { name: '?' };
    const owner = `${cref.name}(${name})`;
    const c: ObjcCategory = {
      addr: hx(cat), name, class: cref,
      instanceMethods: safe(errs, 'instance methods', () => r.methods(r.ptr(cat + 2 * P), owner, false).items, []),
      classMethods: safe(errs, 'class methods', () => r.methods(r.ptr(cat + 3 * P), owner, true).items, []),
      protocols: safe(errs, 'protocols', () => r.protocolList(r.ptr(cat + 4 * P)), []),
      properties: safe(errs, 'properties', () => r.properties(r.ptr(cat + 5 * P)), []),
      classProperties: md.imageInfo && md.imageInfo.flags & 0x40 ? safe(errs, 'class properties', () => r.properties(r.ptr(cat + 6 * P)), []) : [],
    };
    if (nlc.has(cat)) c.nonLazy = true;
    if (errs.length) c.errors = errs;
    md.categories.push(c);
  }
  const seenProto = new Set<number>();
  for (const slot of listSection(img, '__objc_protolist')) {
    md.present = true;
    if (timeUp()) { md.truncated = true; break; }
    const pr = safe(r.errors, `protolist ${hx(slot)}`, () => img.ptr(slot), undefined);
    if (!pr || seenProto.has(pr)) continue;
    seenProto.add(pr);
    md.protocols.push(readProtocol(r, pr));
  }
  for (const s of img.sectionsNamed('__objc_selrefs')) md.selectorRefs += Math.floor(s.size / img.ptrSize);
  for (const s of img.sectionsNamed('__objc_superrefs')) md.superRefs += Math.floor(s.size / img.ptrSize);
  for (const slot of listSection(img, '__objc_classrefs').slice(0, 20000)) {
    const c = safe(r.errors, `classrefs ${hx(slot)}`, () => r.classRef(slot), undefined);
    if (c) md.classRefs.push(c);
  }
  for (const s of img.sectionsNamed('__objc_methname')) {
    const o = img.toOffset(s.addr);
    if (o < 0) continue;
    const end = Math.min(img.bytes.length, o + s.size);
    for (let i = o; i < end; i++) if (img.bytes[i] === 0) md.methodNames++;
  }
  if (md.errors.length > 200) md.errors.splice(200, md.errors.length - 200, `${md.errors.length - 200} more errors`);
  return md;
}

function readClass(r: Reader, cls: number, nonLazy: boolean): ObjcClass {
  const img = r.img, P = img.ptrSize;
  const errs: string[] = [];
  const out: ObjcClass = { addr: hx(cls), name: hx(cls), flags: 0, flagNames: [], instanceStart: 0, instanceSize: 0, swift: false, methods: [], classMethods: [], ivars: [], properties: [], classProperties: [], protocols: [] };
  if (nonLazy) out.nonLazy = true;
  try {
    const data = r.ptr(cls + 4 * P);
    if (data !== undefined && data % 4 !== 0) out.swift = true;
    const ro = r.roOf(cls);
    if (ro === undefined) throw new Error('class has no data pointer');
    const o = P === 8 ? 8 : 0;
    out.flags = img.readU32(ro);
    out.flagNames = RO_FLAGS.filter(([b]) => out.flags & b).map(([, n]) => n);
    out.instanceStart = img.readU32(ro + 4);
    out.instanceSize = img.readU32(ro + 8);
    const f = ro + 12 + (P === 8 ? 4 : 0); // ivarLayout
    out.name = r.str(r.ptr(f + P)) || hx(cls);
    const dn = objcDisplayName(out.name);
    if (dn) out.demangledName = dn;
    const display = out.name;
    const m = safe(errs, 'methods', () => r.methods(r.ptr(f + 2 * P), display, false), { items: [] as ObjcMethod[] });
    out.methods = m.items; if (m.kind) out.methodListKind = m.kind;
    out.protocols = safe(errs, 'protocols', () => r.protocolList(r.ptr(f + 3 * P)), []);
    out.ivars = safe(errs, 'ivars', () => r.ivars(r.ptr(f + 4 * P)), []);
    out.properties = safe(errs, 'properties', () => r.properties(r.ptr(f + 6 * P)), []);
    void o;
    const sup = safe(errs, 'superclass', () => r.classRef(cls + P), undefined);
    if (sup) out.superclass = sup;
    const meta = safe(errs, 'isa', () => r.ptr(cls), undefined);
    if (meta) {
      out.metaclass = hx(meta);
      const mro = safe(errs, 'metaclass', () => r.roOf(meta), undefined);
      if (mro !== undefined) {
        const mf = mro + 12 + (P === 8 ? 4 : 0);
        out.classMethods = safe(errs, 'class methods', () => r.methods(r.ptr(mf + 2 * P), display, true).items, []);
        out.classProperties = safe(errs, 'class properties', () => r.properties(r.ptr(mf + 6 * P)), []);
      }
    }
  } catch (e) { errs.push((e as Error).message); }
  if (errs.length) out.errors = errs;
  return out;
}

function readProtocol(r: Reader, pr: number): ObjcProtocol {
  const img = r.img, P = img.ptrSize;
  const errs: string[] = [];
  const name = r.str(safe(errs, 'name', () => r.ptr(pr + P), undefined)) || hx(pr);
  const out: ObjcProtocol = {
    addr: hx(pr), name, protocols: safe(errs, 'protocols', () => r.protocolList(r.ptr(pr + 2 * P)), []),
    instanceMethods: safe(errs, 'instance methods', () => r.methods(r.ptr(pr + 3 * P), '0x', false).items, []),
    classMethods: safe(errs, 'class methods', () => r.methods(r.ptr(pr + 4 * P), '0x', true).items, []),
    optionalInstanceMethods: safe(errs, 'optional instance methods', () => r.methods(r.ptr(pr + 5 * P), '0x', false).items, []),
    optionalClassMethods: safe(errs, 'optional class methods', () => r.methods(r.ptr(pr + 6 * P), '0x', true).items, []),
    properties: safe(errs, 'properties', () => r.properties(r.ptr(pr + 7 * P)), []),
  };
  const dn = objcDisplayName(name);
  if (dn) out.demangledName = dn;
  // size and flags follow; extended method types exist when size covers them
  safe(errs, 'extended types', () => {
    const size = img.readU32(pr + 8 * P);
    if (size >= 8 * P + 8 + P) {
      const ext = r.ptr(pr + 8 * P + 8);
      const total = out.instanceMethods.length + out.classMethods.length + out.optionalInstanceMethods.length + out.optionalClassMethods.length;
      if (ext && total) {
        const t: string[] = [];
        for (let i = 0; i < Math.min(total, 65536); i++) t.push(r.str(r.ptr(ext + i * P)));
        out.extendedTypes = t;
      }
    }
  }, undefined);
  for (const m of [...out.instanceMethods, ...out.classMethods, ...out.optionalInstanceMethods, ...out.optionalClassMethods]) if (m.impSymbol?.includes('[0x')) delete m.impSymbol;
  if (errs.length) out.errors = errs;
  return out;
}
