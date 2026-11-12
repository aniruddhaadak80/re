// Swift 5 reflection and runtime metadata from a Mach-O image: __swift5_types (nominal type
// descriptors with parents, generic headers and class vtables), __swift5_fieldmd (stored
// properties and enum cases with their types), __swift5_protos (protocol descriptors with
// requirements), __swift5_proto (conformances) and __swift5_reflstr. Mangled type names with
// symbolic references are turned back into plain manglings and printed with the Swift
// demangler. Layouts follow the public Swift ABI headers (include/swift/ABI/Metadata.h).

import type { MachImage } from './macho-image.js';
import { demangleSwift } from '../demangle/swift/index.js';
import { Demangler } from '../demangle/swift/demangler.js';
import { NodePrinter, DEFAULT_OPTIONS } from '../demangle/swift/printer.js';
import { NONE, K, type Node } from '../demangle/swift/nodes.js';

/** Demangler that resolves symbolic references through a callback, as swift-reflection-dump does. */
class ResolvingDemangler extends Demangler {
  constructor(private readonly resolve: (kind: number, at: number) => Node | undefined) { super(); }
  override demangleSymbolicReference(rawKind: string): Node {
    const at = this.Pos - 1;
    if (this.Pos + 4 > this.Text.length) return NONE;
    this.Pos += 4;
    const n = this.resolve(rawKind.charCodeAt(0), at);
    if (!n) return NONE;
    this.addSubstitution(n);
    return n;
  }
}

export interface SwiftField { name: string; type: string | null; mangledType: string; var: boolean; indirect: boolean }
export interface SwiftVtableEntry { kind: string; instance: boolean; dynamic: boolean; async: boolean; impl?: string; symbol?: string }
export interface SwiftType {
  addr: string; kind: 'class' | 'struct' | 'enum' | 'protocol' | 'opaque' | 'other'; name: string; module: string;
  mangledName?: string; parent?: string; generic: boolean; genericParams?: number; flags: number;
  fields: SwiftField[]; fieldKind?: string; superclass?: string | null; numFields?: number;
  enumPayloadCases?: number; enumEmptyCases?: number; vtable?: SwiftVtableEntry[]; overrides?: number; accessFunction?: string;
  conformances: string[]; fieldDescriptor?: string; fromFieldDescriptorOnly?: boolean; errors?: string[];
}
export interface SwiftProtocol { addr: string; name: string; module: string; requirements: { kind: string; instance: boolean; async: boolean; defaultImpl?: string }[]; associatedTypes: string[]; requirementsInSignature: number }
export interface SwiftConformance { addr: string; protocol: string; type: string; typeKind: string; retroactive: boolean; conditionalRequirements: number; resilientWitnesses: boolean; genericWitnessTable: boolean; witnessTable?: string }
export interface SwiftMetadata {
  present: boolean; sections: Record<string, number>;
  types: SwiftType[]; protocols: SwiftProtocol[]; conformances: SwiftConformance[];
  reflectionStrings: number; truncated: boolean; errors: string[];
}
export interface SwiftLimits { maxTypes?: number; deadline?: number }

const hx = (n: number) => '0x' + n.toString(16);
const KIND: Record<number, SwiftType['kind']> = { 16: 'class', 17: 'struct', 18: 'enum', 3: 'protocol', 4: 'opaque' };
const FIELD_KIND = ['struct', 'class', 'enum', 'multi-payload-enum', 'protocol', 'class-protocol', 'objc-protocol', 'objc-class'];
const METHOD_KIND = ['method', 'init', 'getter', 'setter', 'modify', 'read', 'modify2', 'read2'];
const REQ_KIND = ['base-protocol', 'method', 'init', 'getter', 'setter', 'read', 'modify', 'associated-type-access', 'associated-conformance-access', 'read2', 'modify2'];

const MODULE_MANGLE: Record<string, string> = { Swift: 's', __C: 'So', __C_Synthesized: 'SC' };

function ident(s: string): string | null {
  if (!s || !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(s)) return null;
  return `${s.length}${s}`;
}

/** Strip the symbol prefix and descriptor suffix of a bound Swift descriptor symbol, giving a type or protocol mangling. */
function symbolToMangling(sym: string): string | null {
  const m = /^_?\$s(.*)(Mn|Mp|N|Mf|Ma)$/.exec(sym);
  if (!m) return null;
  if (m[2] === 'Mp') return m[1] + 'P';
  return m[1]!;
}

export class SwiftReader {
  readonly errors: string[] = [];
  private ctxCache = new Map<number, { kind: number; flags: number; name: string; parent?: number; mangled: string | null; path: string; module: string }>();
  constructor(readonly img: MachImage) {}

  /** Target of a relative direct pointer at addr. */
  rel(addr: number): number | undefined { const o = this.img.readI32(addr); return o === 0 ? undefined : addr + o; }
  /** Target of a relative indirectable pointer: a local address or a bound symbol. */
  relIndirect(addr: number): { addr?: number; bind?: string } | undefined {
    const o = this.img.readI32(addr);
    if (o === 0) return undefined;
    if (o & 1) {
      const slot = addr + (o & ~1);
      const p = this.img.readPointer(slot);
      return p.bind ? { bind: p.bind } : p.addr ? { addr: p.addr } : undefined;
    }
    return { addr: addr + o };
  }

  /** Context descriptor facts, with its Swift mangling (no prefix) and dotted path. */
  context(addr: number, depth = 0): { kind: number; flags: number; name: string; parent?: number; mangled: string | null; path: string; module: string } {
    const hit = this.ctxCache.get(addr);
    if (hit) return hit;
    if (depth > 24) throw new Error('context nesting too deep');
    const img = this.img;
    const flags = img.readU32(addr);
    const kind = flags & 0x1f;
    const par = this.relIndirect(addr + 4);
    let parent: ReturnType<SwiftReader['context']> | undefined;
    let parentMangled: string | null = '';
    let parentPath = '';
    let module = '';
    if (par?.addr !== undefined) {
      parent = this.context(par.addr, depth + 1);
      parentMangled = parent.mangled; parentPath = parent.path; module = parent.module;
    } else if (par?.bind) {
      const mg = symbolToMangling(par.bind);
      parentMangled = mg;
      const d = mg ? demangleSwift('$s' + mg + 'D') : null;
      parentPath = d ?? par.bind; module = (d ?? '').split('.')[0] ?? '';
    }
    let name = '';
    let mangled: string | null = null;
    let path = '';
    if (kind === 0) { // module
      name = this.str(this.rel(addr + 8));
      mangled = MODULE_MANGLE[name] ?? ident(name);
      path = name; module = name;
    } else if (kind === 1) { // extension: the extended context is a mangled type name
      const ext = this.rel(addr + 8);
      const m = ext !== undefined ? this.mangledName(ext, depth + 1) : null;
      mangled = m;
      path = (m ? demangleSwift('$s' + m + 'D') : null) ?? parentPath;
      name = path;
    } else if (kind === 2) { // anonymous (private) context: transparent for naming
      mangled = parentMangled; path = parentPath; name = '';
    } else {
      name = this.str(this.rel(addr + 8));
      const suffix = kind === 16 ? 'C' : kind === 17 ? 'V' : kind === 18 ? 'O' : kind === 3 ? 'P' : '';
      const id = ident(name);
      mangled = parentMangled !== null && id && suffix ? parentMangled + id + suffix : null;
      path = parentPath ? `${parentPath}.${name}` : name;
    }
    const out = { kind, flags, name, parent: par?.addr, mangled, path, module };
    this.ctxCache.set(addr, out);
    return out;
  }

  str(a: number | undefined, max = 1024): string { if (a === undefined) return ''; try { return this.img.readCString(a, max); } catch { return ''; } }

  /** Rebuild a plain mangling from a mangled name with symbolic references, or null when a reference cannot be resolved. */
  mangledName(addr: number, depth = 0): string | null {
    if (depth > 24) return null;
    const img = this.img;
    let out = '';
    let p = addr;
    for (let guard = 0; guard < 4096; guard++) {
      const b = img.readU8(p);
      if (b === 0) return out;
      if (b >= 0x01 && b <= 0x17) {
        const t = p + 1 + img.readI32(p + 1);
        let sub: string | null = null;
        if (b === 0x01) sub = this.context(t, depth + 1).mangled;
        else if (b === 0x02) {
          const q = img.readPointer(t);
          if (q.bind) sub = symbolToMangling(q.bind);
          else if (q.addr) sub = this.context(q.addr, depth + 1).mangled;
        } else return null; // accessor functions and unique extended existentials need running code
        if (sub === null) return null;
        out += sub;
        p += 5;
        continue;
      }
      if (b >= 0x18 && b <= 0x1f) return null;
      out += String.fromCharCode(b);
      p++;
    }
    return null;
  }

  /** Node for a context given by its plain mangling (fresh demangler, no shared substitutions). */
  private nodeFor(mangling: string | null): Node | undefined {
    if (!mangling) return undefined;
    try {
      const d = new Demangler();
      const n = d.demangleType(mangling);
      if (!n || n.getKind() === K.Suffix || d.Pos !== mangling.length) return undefined;
      return n;
    } catch { return undefined; }
  }

  /** Readable type from a mangled name address, resolving symbolic references like the Swift runtime. */
  typeName(addr: number | undefined): { text: string | null; mangled: string } {
    if (addr === undefined) return { text: null, mangled: '' };
    const img = this.img;
    let raw = '';
    try {
      for (let p = addr, guard = 0; guard < 4096; guard++) {
        const b = img.readU8(p);
        if (b === 0) break;
        if (b >= 0x01 && b <= 0x17) { raw += String.fromCharCode(b); for (let k = 1; k <= 4; k++) raw += String.fromCharCode(img.readU8(p + k)); p += 5; continue; }
        if (b >= 0x18 && b <= 0x1f) { raw += String.fromCharCode(b); for (let k = 1; k <= img.ptrSize; k++) raw += String.fromCharCode(img.readU8(p + k)); p += 1 + img.ptrSize; continue; }
        raw += String.fromCharCode(b); p++;
      }
    } catch (e) { this.errors.push(`mangled name at ${hx(addr)}: ${(e as Error).message}`); return { text: null, mangled: '' }; }
    const shown = this.rawMangled(addr);
    if (!raw) return { text: '', mangled: '' };
    const resolve = (kind: number, at: number): Node | undefined => {
      const field = addr + at;
      try {
        const t = field + 1 + img.readI32(field + 1);
        if (kind === 0x01) return this.nodeFor(this.context(t).mangled);
        if (kind === 0x02) {
          const q = img.readPointer(t);
          if (q.bind) return this.nodeFor(symbolToMangling(q.bind));
          if (q.addr) return this.nodeFor(this.context(q.addr).mangled);
        }
      } catch { /* unresolvable */ }
      return undefined;
    };
    try {
      const d = new ResolvingDemangler(resolve);
      const n = d.demangleType(raw);
      if (!n || n.getKind() === K.Suffix || d.Pos !== raw.length || d.NodeStack.length) return { text: null, mangled: shown };
      const text = new NodePrinter(DEFAULT_OPTIONS).printRoot(n);
      return { text: text || null, mangled: shown };
    } catch { return { text: null, mangled: shown }; }
  }
  private rawMangled(addr: number): string {
    let s = '';
    try { for (let p = addr, i = 0; i < 256; i++, p++) { const b = this.img.readU8(p); if (b === 0) break; s += b < 0x20 ? `\\x${b.toString(16).padStart(2, '0')}` : String.fromCharCode(b); } } catch { /* partial */ }
    return s;
  }

  fields(fd: number): { kind: string; fields: SwiftField[]; superclass?: string | null } {
    const img = this.img;
    const kindN = img.readU16(fd + 8), recSize = img.readU16(fd + 10), n = img.readU32(fd + 12);
    if (recSize < 12 || recSize > 64) throw new Error(`field record size ${recSize}`);
    const out: SwiftField[] = [];
    for (let i = 0; i < Math.min(n, 65536); i++) {
      const r = fd + 16 + i * recSize;
      const fl = img.readU32(r);
      const t = this.typeName(this.rel(r + 4));
      out.push({ name: this.str(this.rel(r + 8)), type: t.text, mangledType: t.mangled, var: (fl & 2) !== 0, indirect: (fl & 1) !== 0 });
    }
    const sup = this.rel(fd + 4);
    return { kind: FIELD_KIND[kindN] ?? `kind ${kindN}`, fields: out, ...(sup !== undefined ? { superclass: this.typeName(sup).text } : {}) };
  }

  symbolFor(addr: number): string | undefined {
    const s = this.img.symbolAt(addr);
    if (!s) return undefined;
    return demangleSwift(s) ?? s;
  }

  type(addr: number): SwiftType {
    const img = this.img;
    const errs: string[] = [];
    const c = this.context(addr);
    const kind = KIND[c.kind] ?? 'other';
    const t: SwiftType = { addr: hx(addr), kind, name: c.path, module: c.module, generic: (c.flags & 0x80) !== 0, flags: c.flags, fields: [], conformances: [] };
    if (c.mangled) t.mangledName = c.mangled;
    if (c.parent !== undefined) t.parent = hx(c.parent);
    if (c.kind < 16 || c.kind > 18) return t;
    try {
      const acc = this.rel(addr + 12);
      if (acc !== undefined) t.accessFunction = hx(acc);
      const fd = this.rel(addr + 16);
      if (fd !== undefined) {
        t.fieldDescriptor = hx(fd);
        const f = this.fields(fd);
        t.fields = f.fields; t.fieldKind = f.kind;
      }
      let end = addr + 20;
      const ks = c.flags >>> 16;
      if (c.kind === 16) {
        const sup = this.rel(addr + 20);
        t.superclass = sup !== undefined ? this.typeName(sup).text : undefined;
        t.numFields = img.readU32(addr + 36);
        end = addr + 44;
      } else if (c.kind === 17) { t.numFields = img.readU32(addr + 20); end = addr + 28; }
      else { const pc = img.readU32(addr + 20); t.enumPayloadCases = pc & 0xffffff; t.enumEmptyCases = img.readU32(addr + 24); end = addr + 28; }
      if (t.superclass === undefined) delete t.superclass;
      if (t.generic) {
        const nParams = img.readU16(end + 8), nReq = img.readU16(end + 10), gflags = img.readU16(end + 14);
        t.genericParams = nParams;
        end += 16 + Math.ceil(nParams / 4) * 4 + nReq * 12;
        if (gflags & 1) { const packs = img.readU16(end); end += 4 + packs * 8; }
        if (gflags & ~1) { if (c.kind === 16) errs.push('generic header flags not modeled; vtable skipped'); return finish(); }
      }
      if (c.kind === 16) {
        if (ks & (1 << 13)) end += 4; // resilient superclass
        const mi = ks & 3;
        if (mi === 1) end += 12; else if (mi === 2) end += 4;
        if (ks & (1 << 15)) {
          const size = img.readU32(end + 4);
          end += 8;
          const vt: SwiftVtableEntry[] = [];
          for (let i = 0; i < Math.min(size, 16384); i++) {
            const e = end + i * 8;
            const fl = img.readU32(e);
            const impl = this.rel(e + 4);
            const ent: SwiftVtableEntry = { kind: METHOD_KIND[fl & 0xf] ?? `kind ${fl & 0xf}`, instance: (fl & 0x10) !== 0, dynamic: (fl & 0x20) !== 0, async: (fl & 0x40) !== 0 };
            if (impl !== undefined) { ent.impl = hx(impl); const s = this.symbolFor(impl); if (s) ent.symbol = s; }
            vt.push(ent);
          }
          t.vtable = vt;
          end += size * 8;
        }
        if (ks & (1 << 14)) t.overrides = img.readU32(end);
      }
    } catch (e) { errs.push((e as Error).message); }
    return finish();
    function finish(): SwiftType { if (errs.length) t.errors = errs; return t; }
  }

  protocol(addr: number): SwiftProtocol {
    const img = this.img;
    const c = this.context(addr);
    const nSig = img.readU32(addr + 12), nReq = img.readU32(addr + 16);
    const at = this.rel(addr + 20);
    const reqs: SwiftProtocol['requirements'] = [];
    const base = addr + 24 + Math.min(nSig, 4096) * 12;
    for (let i = 0; i < Math.min(nReq, 4096); i++) {
      const fl = img.readU32(base + i * 8);
      const d = this.rel(base + i * 8 + 4);
      reqs.push({ kind: REQ_KIND[fl & 0xf] ?? `kind ${fl & 0xf}`, instance: (fl & 0x10) !== 0, async: (fl & 0x20) !== 0, ...(d !== undefined ? { defaultImpl: hx(d) } : {}) });
    }
    const assoc = at !== undefined ? this.str(at, 4096).split(' ').filter(Boolean) : [];
    return { addr: hx(addr), name: c.path, module: c.module, requirements: reqs, associatedTypes: assoc, requirementsInSignature: nSig };
  }

  conformance(addr: number): SwiftConformance {
    const img = this.img;
    const pr = this.relIndirect(addr);
    let protocol = '?';
    if (pr?.addr !== undefined) protocol = this.context(pr.addr).path;
    else if (pr?.bind) protocol = (demangleSwift(pr.bind) ?? pr.bind).replace(/^protocol descriptor for /, '');
    const flags = img.readU32(addr + 12);
    const tk = (flags >>> 3) & 7;
    let type = '?';
    let typeKind = 'unknown';
    if (tk === 0 || tk === 1) {
      typeKind = tk === 0 ? 'direct-type-descriptor' : 'indirect-type-descriptor';
      const t = tk === 0 ? (() => { const a = this.rel(addr + 4); return a !== undefined ? { addr: a } : undefined; })() : (() => { const s = this.rel(addr + 4); if (s === undefined) return undefined; const p = img.readPointer(s); return p.bind ? { bind: p.bind } : p.addr ? { addr: p.addr } : undefined; })();
      if (t?.addr !== undefined) type = this.context(t.addr).path;
      else if (t && 'bind' in t && t.bind) type = (demangleSwift(t.bind) ?? t.bind).replace(/^nominal type descriptor for /, '');
    } else if (tk === 2) { typeKind = 'objc-class-name'; type = this.str(this.rel(addr + 4)); }
    else if (tk === 3) {
      typeKind = 'objc-class';
      const s = this.rel(addr + 4);
      if (s !== undefined) { const p = img.readPointer(s); type = p.bind ? p.bind.replace(/^_OBJC_CLASS_\$_/, '') : p.addr ? hx(p.addr) : '?'; }
    }
    const wt = this.rel(addr + 8);
    return { addr: hx(addr), protocol, type, typeKind, retroactive: (flags & 0x40) !== 0, conditionalRequirements: (flags >>> 8) & 0xff, resilientWitnesses: (flags & 0x10000) !== 0, genericWitnessTable: (flags & 0x20000) !== 0, ...(wt !== undefined ? { witnessTable: hx(wt) } : {}) };
  }
}

/** Read the Swift 5 metadata sections of an image. */
export function readSwift(img: MachImage, limits: SwiftLimits = {}): SwiftMetadata {
  const r = new SwiftReader(img);
  const maxTypes = limits.maxTypes ?? 200000;
  const deadline = limits.deadline ?? Infinity;
  const md: SwiftMetadata = { present: false, sections: {}, types: [], protocols: [], conformances: [], reflectionStrings: 0, truncated: false, errors: r.errors };
  for (const s of img.sections) if (s.name.startsWith('__swift5_')) { md.sections[s.name] = s.size; md.present = true; }
  const entries = (name: string): number[] => {
    const out: number[] = [];
    for (const s of img.sectionsNamed(name)) for (let i = 0; i < Math.min(Math.floor(s.size / 4), 2_000_000); i++) out.push(s.addr + i * 4);
    return out;
  };
  const byAddr = new Map<string, SwiftType>();
  for (const e of entries('__swift5_types')) {
    if (md.types.length >= maxTypes || Date.now() > deadline) { md.truncated = true; break; }
    try {
      const o = img.readI32(e);
      let d = e + (o & ~3);
      if (o & 3) { const p = img.ptr(d); if (!p) continue; d = p; }
      const t = r.type(d);
      md.types.push(t);
      byAddr.set(t.addr, t);
    } catch (err) { md.errors.push(`type at ${hx(e)}: ${(err as Error).message}`); }
  }
  for (const e of entries('__swift5_protos')) {
    if (Date.now() > deadline) { md.truncated = true; break; }
    try {
      const o = img.readI32(e);
      let d = e + (o & ~1);
      if (o & 1) { const p = img.ptr(d); if (!p) continue; d = p; }
      md.protocols.push(r.protocol(d));
    } catch (err) { md.errors.push(`protocol at ${hx(e)}: ${(err as Error).message}`); }
  }
  for (const e of entries('__swift5_proto')) {
    if (Date.now() > deadline) { md.truncated = true; break; }
    try {
      const c = r.conformance(e + img.readI32(e));
      md.conformances.push(c);
    } catch (err) { md.errors.push(`conformance at ${hx(e)}: ${(err as Error).message}`); }
  }
  // Field descriptors that no type descriptor points at (types from other images, imported C types, private contexts)
  const seenFd = new Set(md.types.map((t) => t.fieldDescriptor).filter(Boolean));
  for (const s of img.sectionsNamed('__swift5_fieldmd')) {
    let p = s.addr;
    const end = s.addr + s.size;
    for (let guard = 0; p + 16 <= end && guard < 1_000_000; guard++) {
      if (Date.now() > deadline || md.types.length >= maxTypes) { md.truncated = true; break; }
      try {
        const recSize = img.readU16(p + 10), n = img.readU32(p + 12);
        if (recSize < 12 || n > 65536) { md.errors.push(`field descriptor at ${hx(p)}: bad header`); break; }
        if (!seenFd.has(hx(p))) {
          const tn = r.typeName(r.rel(p));
          const f = r.fields(p);
          const kind: SwiftType['kind'] = f.kind === 'struct' ? 'struct' : f.kind === 'class' || f.kind === 'objc-class' ? 'class' : f.kind.includes('enum') ? 'enum' : f.kind.includes('protocol') ? 'protocol' : 'other';
          const name = tn.text ?? tn.mangled;
          md.types.push({ addr: hx(p), kind, name, module: name.split('.')[0] ?? '', generic: false, flags: 0, fields: f.fields, fieldKind: f.kind, fieldDescriptor: hx(p), fromFieldDescriptorOnly: true, conformances: [], ...(f.superclass !== undefined ? { superclass: f.superclass } : {}) });
        }
        p += 16 + n * recSize;
      } catch (err) { md.errors.push(`field descriptor at ${hx(p)}: ${(err as Error).message}`); break; }
    }
  }
  const byName = new Map<string, SwiftType>();
  for (const t of md.types) if (!byName.has(t.name)) byName.set(t.name, t);
  for (const c of md.conformances) byName.get(c.type)?.conformances.push(c.protocol);
  for (const s of img.sectionsNamed('__swift5_reflstr')) {
    const o = img.toOffset(s.addr);
    if (o < 0) continue;
    const end = Math.min(img.bytes.length, o + s.size);
    for (let i = o; i < end; i++) if (img.bytes[i] === 0) md.reflectionStrings++;
  }
  if (md.errors.length > 200) md.errors.splice(200, md.errors.length - 200, `${md.errors.length - 200} more errors`);
  return md;
}
