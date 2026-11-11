// Unity IL2CPP global-metadata.dat reader: header, images, type and method names, string literals.
// Struct strides differ between metadata versions 24 to 31, so they are inferred and validated
// against the data instead of hardcoded per Unity release.

import { Buf, ParseError, utf8 } from './bytes.js';

export const IL2CPP_MAGIC = 0xfab11baf;
export const IL2CPP_LIMITS = { maxTypes: 500_000, maxMethods: 2_000_000, maxLiterals: 2_000_000 };

/** Header section names in order, for metadata versions 24 to 31. */
const SECTIONS = [
  'stringLiterals', 'stringLiteralData', 'strings', 'events', 'properties', 'methods', 'parameterDefaultValues',
  'fieldDefaultValues', 'fieldAndParameterDefaultValueData', 'fieldMarshaledSizes', 'parameters', 'fields',
  'genericParameters', 'genericParameterConstraints', 'genericContainers', 'nestedTypes', 'interfaces',
  'vtableMethods', 'interfaceOffsets', 'typeDefinitions',
];

export interface Il2cppSection { name: string; offset: number; size: number }

export interface Il2cppImage { name: string; typeStart: number; typeCount: number }

export interface Il2cppType { index: number; namespace: string; name: string; fullName: string; image?: string }

export interface Il2cppMethod { index: number; name: string; declaringType: number; typeName?: string }

export interface Il2cppMetadata {
  version: number;
  sections: Il2cppSection[];
  images: Il2cppImage[];
  typeCount: number;
  methodCount: number;
  literalCount: number;
  strides: { image?: number; type?: number; method?: number };
  warnings: string[];
}

export function isIl2cppMetadata(b: Uint8Array): boolean {
  return b.length >= 8 && new Buf(b).u32(0) === IL2CPP_MAGIC;
}

class Ctx {
  r: Buf;
  strings: Il2cppSection;
  constructor(public b: Uint8Array, public secs: Map<string, Il2cppSection>) {
    this.r = new Buf(b);
    this.strings = secs.get('strings') as Il2cppSection;
  }
  str(idx: number): string | undefined {
    if (idx < 0 || idx >= this.strings.size) return undefined;
    return this.r.cstr(this.strings.offset + idx, Math.min(1024, this.strings.size - idx));
  }
}

const IDENT = /^[A-Za-z_<`.$][\w<>`.$|,=\-[\] ]{0,512}$/;

function readHeader(b: Uint8Array): { version: number; secs: Map<string, Il2cppSection>; imagePairs: Il2cppSection[] } {
  const r = new Buf(b);
  if (r.u32(0) !== IL2CPP_MAGIC) throw new ParseError('not an IL2CPP global-metadata.dat (bad magic)');
  const version = r.i32(4);
  const secs = new Map<string, Il2cppSection>();
  SECTIONS.forEach((name, k) => {
    const off = r.u32(8 + k * 8);
    const size = r.u32(12 + k * 8);
    secs.set(name, { name, offset: off, size: r.has(off, size) ? size : 0 });
  });
  // images sit at pair 20 (no rgctx section) or 21 (older 24.x with rgctxEntries)
  const imagePairs: Il2cppSection[] = [20, 21].map((k) => ({ name: 'images', offset: r.u32(8 + k * 8), size: r.u32(12 + k * 8) }));
  return { version, secs, imagePairs };
}

function readImages(ctx: Ctx, cand: Il2cppSection[]): { images: Il2cppImage[]; stride?: number; section?: Il2cppSection } {
  for (const sec of cand) {
    if (!sec.size || !ctx.r.has(sec.offset, sec.size)) continue;
    for (const stride of [40, 32, 36, 44, 48]) {
      if (sec.size % stride) continue;
      const n = sec.size / stride;
      if (n === 0 || n > 10_000) continue;
      const images: Il2cppImage[] = [];
      let expect = 0;
      let ok = true;
      for (let i = 0; i < n; i++) {
        const o = sec.offset + i * stride;
        const name = ctx.str(ctx.r.i32(o));
        const typeStart = ctx.r.i32(o + 8), typeCount = ctx.r.u32(o + 12);
        if (!name || !IDENT.test(name) || typeStart !== expect) { ok = false; break; }
        images.push({ name, typeStart, typeCount });
        expect += typeCount;
      }
      if (ok) return { images, stride, section: sec };
    }
  }
  return { images: [] };
}

function inferStride(_ctx: Ctx, sec: Il2cppSection, count: number | undefined, check: (o: number, i: number) => boolean, candidates: number[]): number | undefined {
  let best: number | undefined;
  let bestScore = -1;
  for (const s of candidates) {
    if (!sec.size || sec.size % s) continue;
    if (count !== undefined && sec.size / s !== count) continue;
    const n = Math.min(sec.size / s, 64);
    let score = 0;
    for (let i = 0; i < n; i++) { try { if (check(sec.offset + i * s, i)) score++; } catch { /* bad */ } }
    if (score > bestScore) { best = s; bestScore = score; }
  }
  return bestScore > 0 ? best : undefined;
}

export interface Il2cppParsed extends Il2cppMetadata {
  types(offset?: number, limit?: number, filter?: string): { total: number; items: Il2cppType[] };
  methods(offset?: number, limit?: number, filter?: string): { total: number; items: Il2cppMethod[] };
  literals(offset?: number, limit?: number, filter?: string): { total: number; items: { index: number; value: string }[] };
}

/** Parse global-metadata.dat. Type and method listing is lazy and paged. */
export function parseIl2cppMetadata(b: Uint8Array): Il2cppParsed {
  const { version, secs, imagePairs } = readHeader(b);
  const warnings: string[] = [];
  if (version < 24 || version > 31) warnings.push(`metadata version ${version} is outside the tested 24 to 31 range, names may be wrong`);
  const ctx = new Ctx(b, secs);
  const { images, stride: imageStride } = readImages(ctx, imagePairs);
  if (!images.length) warnings.push('could not locate the image table');
  const typeTotal = images.reduce((a, i) => a + i.typeCount, 0) || undefined;
  const typeSec = secs.get('typeDefinitions') as Il2cppSection;
  const typeStride = inferStride(ctx, typeSec, typeTotal, (o) => {
    const n = ctx.str(ctx.r.i32(o)), ns = ctx.str(ctx.r.i32(o + 4));
    return n !== undefined && ns !== undefined && IDENT.test(n) && (ns === '' || IDENT.test(ns));
  }, [88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 84, 80, 76, 72]);
  const typeCount = typeStride ? Math.min(typeSec.size / typeStride, IL2CPP_LIMITS.maxTypes) : 0;
  const methSec = secs.get('methods') as Il2cppSection;
  let lastDecl = -1;
  const methodStride = inferStride(ctx, methSec, undefined, (o, i) => {
    if (i === 0) lastDecl = -1;
    const n = ctx.str(ctx.r.i32(o));
    const decl = ctx.r.i32(o + 4);
    const ok = n !== undefined && IDENT.test(n) && decl >= lastDecl && (typeCount === 0 || decl < typeCount);
    if (ok) lastDecl = decl;
    return ok;
  }, [24, 28, 32, 36, 40, 44, 48, 52, 56]);
  const methodCount = methodStride ? Math.min(methSec.size / methodStride, IL2CPP_LIMITS.maxMethods) : 0;
  const litSec = secs.get('stringLiterals') as Il2cppSection;
  const litData = secs.get('stringLiteralData') as Il2cppSection;
  const literalCount = Math.min(Math.floor(litSec.size / 8), IL2CPP_LIMITS.maxLiterals);

  const imageOf = (t: number): string | undefined => images.find((im) => t >= im.typeStart && t < im.typeStart + im.typeCount)?.name;
  const typeAt = (i: number): Il2cppType => {
    const o = typeSec.offset + i * (typeStride as number);
    const name = ctx.str(ctx.r.i32(o)) ?? `<type ${i}>`;
    const namespace = ctx.str(ctx.r.i32(o + 4)) ?? '';
    const t: Il2cppType = { index: i, namespace, name, fullName: namespace ? `${namespace}.${name}` : name };
    const img = imageOf(i);
    if (img) t.image = img;
    return t;
  };
  const page = <T>(total: number, get: (i: number) => T, match: (x: T) => boolean, offset = 0, limit = 200, filtered = false) => {
    const items: T[] = [];
    if (!filtered) {
      for (let i = offset; i < Math.min(total, offset + limit); i++) items.push(get(i));
      return { total, items };
    }
    let seen = 0;
    for (let i = 0; i < total && items.length < limit; i++) {
      const x = get(i);
      if (!match(x)) continue;
      if (seen++ >= offset) items.push(x);
    }
    return { total, items };
  };
  return {
    version,
    sections: [...secs.values()],
    images,
    typeCount, methodCount, literalCount,
    strides: { ...(imageStride ? { image: imageStride } : {}), ...(typeStride ? { type: typeStride } : {}), ...(methodStride ? { method: methodStride } : {}) },
    warnings,
    types(offset = 0, limit = 200, filter?: string) {
      const f = filter?.toLowerCase();
      return page(typeCount, typeAt, (t) => !f || t.fullName.toLowerCase().includes(f), offset, limit, !!f);
    },
    methods(offset = 0, limit = 200, filter?: string) {
      const f = filter?.toLowerCase();
      const get = (i: number): Il2cppMethod => {
        const o = methSec.offset + i * (methodStride as number);
        const m: Il2cppMethod = { index: i, name: ctx.str(ctx.r.i32(o)) ?? `<method ${i}>`, declaringType: ctx.r.i32(o + 4) };
        if (typeStride && m.declaringType >= 0 && m.declaringType < typeCount) m.typeName = typeAt(m.declaringType).fullName;
        return m;
      };
      return page(methodCount, get, (m) => !f || `${m.typeName ?? ''}::${m.name}`.toLowerCase().includes(f), offset, limit, !!f);
    },
    literals(offset = 0, limit = 200, filter?: string) {
      const f = filter?.toLowerCase();
      const get = (i: number) => {
        const o = litSec.offset + i * 8;
        const len = ctx.r.u32(o), idx = ctx.r.u32(o + 4);
        const ok = idx + len <= litData.size && len < 1 << 20;
        return { index: i, value: ok ? utf8(ctx.r.slice(litData.offset + idx, len)) : '' };
      };
      return page(literalCount, get, (l) => !f || l.value.toLowerCase().includes(f), offset, limit, !!f);
    },
  };
}
