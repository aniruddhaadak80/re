// COM type library reader (MSFT format, as written by midl and widl): library attributes, type
// infos (enums, records, unions, aliases, interfaces, dispinterfaces, coclasses, modules) with
// GUIDs, versions, flags, functions (memid, vtable offset, invoke kind, calling convention,
// parameters with flags), variables and constants. Reads standalone .tlb files and TYPELIB
// resources inside PE files. Pure TypeScript, bounds checked. Layout follows Wine's typelib.h
// (LGPL documentation of the format; no code copied).
import { peResources } from '../pe/pe.js';

export interface TlbParam { name: string; type: string; flags: string[] }
export interface TlbFunc { name: string; memid: number; vtableOffset: number; invokeKind: string; funcKind: string; callConv: string; returns: string; params: TlbParam[]; optionalParams: number; helpString?: string; entry?: string | number; flags: number }
export interface TlbVar { name: string; memid: number; type: string; kind: string; offset?: number; value?: number | string; helpString?: string }
export interface TlbTypeInfo {
  index: number;
  name: string;
  kind: string;
  guid?: string;
  version: string;
  flags: string[];
  size: number;
  helpString?: string;
  funcs: TlbFunc[];
  vars: TlbVar[];
  /** base interface (interfaces), implemented interfaces (coclasses) */
  implements: { name: string; flags: string[] }[];
  /** aliases: the aliased type */
  aliasOf?: string;
  /** modules: the DLL name */
  dllName?: string;
  cbSizeVft: number;
}
export interface TypeLib {
  format: 'MSFT' | 'SLTG';
  name: string;
  guid?: string;
  version: string;
  lcid: number;
  syskind: string;
  flags: string[];
  helpString?: string;
  helpFile?: string;
  typeInfos: TlbTypeInfo[];
  imports: { guid?: string; file?: string }[];
  warnings: string[];
  /** where the library came from: the file itself or a PE resource */
  source?: { kind: 'file' } | { kind: 'pe-resource'; name: string; lang: number; offset: number; size: number };
}

const KIND = ['enum', 'record', 'module', 'interface', 'dispatch', 'coclass', 'alias', 'union'];
const SYSKIND = ['win16', 'win32', 'mac', 'win64'];
const VT: Record<number, string> = {
  0: 'void', 1: 'NULL', 2: 'short', 3: 'long', 4: 'float', 5: 'double', 6: 'CURRENCY', 7: 'DATE', 8: 'BSTR', 9: 'IDispatch*', 10: 'SCODE', 11: 'VARIANT_BOOL',
  12: 'VARIANT', 13: 'IUnknown*', 14: 'DECIMAL', 16: 'signed char', 17: 'unsigned char', 18: 'unsigned short', 19: 'unsigned long', 20: 'int64', 21: 'uint64', 22: 'int', 23: 'unsigned int',
  24: 'void', 25: 'HRESULT', 26: 'PTR', 27: 'SAFEARRAY', 28: 'CARRAY', 29: 'USERDEFINED', 30: 'LPSTR', 31: 'LPWSTR', 36: 'RECORD', 37: 'INT_PTR', 38: 'UINT_PTR', 64: 'FILETIME', 71: 'CF', 72: 'CLSID',
};
const INVOKE: Record<number, string> = { 1: 'func', 2: 'propget', 4: 'propput', 8: 'propputref' };
const FUNCKIND = ['virtual', 'purevirtual', 'nonvirtual', 'static', 'dispatch'];
const CALLCONV: Record<number, string> = { 0: 'fastcall', 1: 'cdecl', 2: 'pascal', 3: 'macpascal', 4: 'stdcall', 5: 'fpfastcall', 6: 'syscall', 7: 'mpwcdecl', 8: 'mpwpascal' };
const VARKIND = ['perinstance', 'static', 'const', 'dispatch'];
const PARAMFLAG: [number, string][] = [[1, 'in'], [2, 'out'], [4, 'lcid'], [8, 'retval'], [0x10, 'optional'], [0x20, 'hasdefault'], [0x40, 'hascustdata']];
const TYPEFLAG: [number, string][] = [[1, 'appobject'], [2, 'cancreate'], [4, 'licensed'], [8, 'predeclid'], [0x10, 'hidden'], [0x20, 'control'], [0x40, 'dual'], [0x80, 'nonextensible'], [0x100, 'oleautomation'], [0x200, 'restricted'], [0x400, 'aggregatable'], [0x800, 'replaceable'], [0x1000, 'dispatchable'], [0x2000, 'reversebind'], [0x4000, 'proxy']];
const LIBFLAG: [number, string][] = [[1, 'restricted'], [2, 'control'], [4, 'hidden'], [8, 'hasdiskimage']];
const IMPLFLAG: [number, string][] = [[1, 'default'], [2, 'source'], [4, 'restricted'], [8, 'defaultvtable']];
const bits = (v: number, t: [number, string][]) => t.filter(([b]) => (v & b) !== 0).map(([, n]) => n);

class V {
  readonly b: Uint8Array; readonly d: DataView;
  constructor(b: Uint8Array) { this.b = b; this.d = new DataView(b.buffer, b.byteOffset, b.byteLength); }
  ok(o: number, n: number) { return Number.isInteger(o) && o >= 0 && n >= 0 && o + n <= this.b.length; }
  i32(o: number) { if (!this.ok(o, 4)) throw new RangeError(`tlb: read at 0x${o.toString(16)} past end`); return this.d.getInt32(o, true); }
  u32(o: number) { return this.i32(o) >>> 0; }
  i16(o: number) { if (!this.ok(o, 2)) throw new RangeError('tlb: read past end'); return this.d.getInt16(o, true); }
  u16(o: number) { return this.i16(o) & 0xffff; }
  str(o: number, n: number) { if (!this.ok(o, n)) throw new RangeError('tlb: string past end'); let s = ''; for (let i = 0; i < n; i++) s += String.fromCharCode(this.b[o + i]!); return s; }
  guid(o: number) {
    if (!this.ok(o, 16)) throw new RangeError('tlb: guid past end');
    const h = (a: number, n: number) => [...this.b.subarray(a, a + n)].map((c) => c.toString(16).padStart(2, '0')).join('');
    const d1 = this.u32(o).toString(16).padStart(8, '0'), d2 = this.u16(o + 4).toString(16).padStart(4, '0'), d3 = this.u16(o + 6).toString(16).padStart(4, '0');
    return `{${d1}-${d2}-${d3}-${h(o + 8, 2)}-${h(o + 10, 6)}}`.toUpperCase();
  }
}

/** True when the bytes are an MSFT or SLTG type library. */
export function isTypeLib(b: Uint8Array): boolean {
  return b.length >= 8 && ((b[0] === 0x4d && b[1] === 0x53 && b[2] === 0x46 && b[3] === 0x54) || (b[0] === 0x53 && b[1] === 0x4c && b[2] === 0x54 && b[3] === 0x47));
}

/** Reads a type library from a .tlb file. */
export function readTypeLib(bytes: Uint8Array, opts: { maxTypes?: number } = {}): TypeLib {
  if (bytes.length >= 4 && bytes[0] === 0x53 && bytes[1] === 0x4c && bytes[2] === 0x54 && bytes[3] === 0x47) {
    return { format: 'SLTG', name: '', version: '', lcid: 0, syskind: '', flags: [], typeInfos: [], imports: [], warnings: ['SLTG (old format) type libraries are detected but not decoded'] };
  }
  const v = new V(bytes);
  if (!isTypeLib(bytes)) throw new Error('not a type library (MSFT magic missing)');
  const warnings: string[] = [];
  const posguid = v.i32(8), lcid = v.i32(12), varflags = v.i32(20), version = v.u32(24), flags = v.i32(28);
  const nTypes = v.i32(32);
  if (nTypes < 0 || nTypes > (opts.maxTypes ?? 65536)) throw new Error(`tlb: ${nTypes} type infos`);
  const helpstring = v.i32(36), nameOff = v.i32(56), helpfile = v.i32(60);
  let pos = 0x54;
  if (varflags & 0x100) pos += 4;
  const tiOffsets: number[] = [];
  for (let i = 0; i < nTypes; i++) { tiOffsets.push(v.i32(pos)); pos += 4; }
  const seg: { off: number; len: number }[] = [];
  for (let i = 0; i < 15; i++) { seg.push({ off: v.i32(pos), len: v.i32(pos + 4) }); pos += 16; }
  const [segTI, segImpInfo, segImpFiles, segRef, , segGuid, , segName, segString, segTypedesc, segArray, segCust] = seg as [typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0], typeof seg[0]];
  const inSeg = (s: { off: number; len: number }, o: number, n: number) => s.off >= 0 && o >= 0 && o + n <= s.len && v.ok(s.off + o, n);
  const name = (o: number): string => {
    if (o < 0 || !inSeg(segName, o, 12)) return '';
    const len = v.i32(segName.off + o + 8) & 0xff;
    return inSeg(segName, o + 12, len) ? v.str(segName.off + o + 12, len) : '';
  };
  const string = (o: number): string | undefined => {
    if (o < 0 || !inSeg(segString, o, 2)) return undefined;
    const len = v.u16(segString.off + o);
    return inSeg(segString, o + 2, len) ? v.str(segString.off + o + 2, len) : undefined;
  };
  const guidAt = (o: number) => (o >= 0 && inSeg(segGuid, o, 16) ? v.guid(segGuid.off + o) : undefined);

  // type info headers first, so user defined references can be named
  interface Base { kind: number; memoffset: number; cElement: number; posguid: number; flags: number; nameOff: number; version: number; doc: number; cImpl: number; cbVft: number; size: number; dt1: number; dt2: number }
  const bases: Base[] = [];
  for (let i = 0; i < nTypes; i++) {
    const o = segTI.off + i * 0x64;
    if (!inSeg(segTI, i * 0x64, 0x64)) { warnings.push(`type info ${i} past the type info segment`); break; }
    bases.push({ kind: v.i32(o), memoffset: v.i32(o + 4), cElement: v.i32(o + 24), posguid: v.i32(o + 44), flags: v.i32(o + 48), nameOff: v.i32(o + 52), version: v.u32(o + 56), doc: v.i32(o + 60), cImpl: v.i16(o + 76), cbVft: v.u16(o + 78), size: v.i32(o + 80), dt1: v.i32(o + 84), dt2: v.i32(o + 88) });
  }
  const tiName = (i: number) => (bases[i] ? name(bases[i]!.nameOff) : `<typeinfo ${i}>`);
  const imports: TypeLib['imports'] = [];
  const impName = (href: number): string => {
    const o = href & ~3;
    if (!inSeg(segImpInfo, o, 12)) return `<import 0x${href.toString(16)}>`;
    const g = guidAt(v.i32(segImpInfo.off + o + 8));
    const fo = v.i32(segImpInfo.off + o + 4);
    let file: string | undefined;
    if (inSeg(segImpFiles, fo, 14)) { const n = v.u16(segImpFiles.off + fo + 12) >> 2; if (inSeg(segImpFiles, fo + 14, n)) file = v.str(segImpFiles.off + fo + 14, n); }
    if (!imports.some((x) => x.guid === g)) imports.push({ guid: g, file });
    return g === '{00020400-0000-0000-C000-000000000046}' ? 'IDispatch' : g === '{00000000-0000-0000-C000-000000000046}' ? 'IUnknown' : `<imported ${g ?? '?'}${file ? ' from ' + file : ''}>`;
  };
  const hrefName = (href: number): string => {
    if (href === -1) return '<none>';
    if (href & 1) return impName(href);
    const i = Math.floor((href & ~3) / 0x64);
    return tiName(i);
  };
  const typeName = (t: number, depth = 0): string => {
    if (depth > 16) return '...';
    if (t < 0) { const vt = t & 0xfff; return VT[vt] ?? `VT_${vt}`; }
    const o = t;
    if (!inSeg(segTypedesc, o, 8)) return `<typedesc 0x${t.toString(16)}>`;
    const vt = v.u16(segTypedesc.off + o) & 0xfff;
    const ref = v.i32(segTypedesc.off + o + 4);
    const hi = v.i16(segTypedesc.off + o + 6);
    if (vt === 26) return (hi < 0 ? VT[ref & 0xfff] ?? `VT_${ref & 0xfff}` : typeName(ref, depth + 1)) + '*';
    if (vt === 27) return `SAFEARRAY(${hi < 0 ? VT[ref & 0xfff] ?? '?' : typeName(ref, depth + 1)})`;
    if (vt === 29) return hrefName(ref);
    if (vt === 28) {
      if (!inSeg(segArray, ref, 8)) return '<array>';
      const elem = v.i32(segArray.off + ref);
      const nd = v.u16(segArray.off + ref + 4);
      const dims: number[] = [];
      for (let k = 0; k < Math.min(nd, 16); k++) if (inSeg(segArray, ref + 8 + k * 8, 4)) dims.push(v.i32(segArray.off + ref + 8 + k * 8));
      return `${typeName(elem, depth + 1)}${dims.map((n) => `[${n}]`).join('')}`;
    }
    return VT[vt] ?? `VT_${vt}`;
  };
  const constValue = (off: number): number | string | undefined => {
    if (off < 0) return off & 0x3ffffff;
    if (!inSeg(segCust, off, 2)) return undefined;
    const vt = v.u16(segCust.off + off);
    const d = segCust.off + off + 2;
    if (vt === 3 || vt === 22) return v.i32(d);
    if (vt === 19 || vt === 23) return v.u32(d);
    if (vt === 2) return v.i16(d);
    if (vt === 18) return v.u16(d);
    if (vt === 16) { const x = v.b[d] ?? 0; return x > 127 ? x - 256 : x; }
    if (vt === 17) return v.b[d] ?? 0;
    if (vt === 8) { const n = v.i32(d); return n >= 0 && v.ok(d + 4, n) ? v.str(d + 4, n) : undefined; }
    if (vt === 5) return v.ok(d, 8) ? v.d.getFloat64(d, true) : undefined;
    if (vt === 4) return v.ok(d, 4) ? v.d.getFloat32(d, true) : undefined;
    return undefined;
  };

  const typeInfos: TlbTypeInfo[] = [];
  bases.forEach((b, idx) => {
    const kind = KIND[b.kind & 0xf] ?? `kind ${b.kind & 0xf}`;
    const ti: TlbTypeInfo = { index: idx, name: name(b.nameOff), kind, guid: guidAt(b.posguid), version: `${b.version & 0xffff}.${b.version >>> 16}`, flags: bits(b.flags, TYPEFLAG), size: b.size, funcs: [], vars: [], implements: [], cbSizeVft: b.cbVft };
    const hs = string(b.doc); if (hs !== undefined) ti.helpString = hs;
    try {
      if (kind === 'alias') ti.aliasOf = typeName(b.dt1);
      else if (kind === 'module') { const d = string(b.dt1); if (d !== undefined) ti.dllName = d; }
      else if (kind === 'coclass') {
        let r = b.dt1;
        for (let k = 0; k < Math.max(0, b.cImpl) && r >= 0 && k < 256; k++) {
          if (!inSeg(segRef, r, 16)) break;
          ti.implements.push({ name: hrefName(v.i32(segRef.off + r)), flags: bits(v.i32(segRef.off + r + 4), IMPLFLAG) });
          r = v.i32(segRef.off + r + 12);
        }
      } else if (b.cImpl > 0 && b.dt1 !== -1 && kind !== 'dispatch') ti.implements.push({ name: hrefName(b.dt1), flags: [] });
      else if (kind === 'dispatch' && b.dt1 !== -1) ti.implements.push({ name: hrefName(b.dt1), flags: [] });
      const nF = b.cElement & 0xffff, nV = b.cElement >>> 16;
      if ((nF || nV) && b.memoffset > 0 && v.ok(b.memoffset, 4)) {
        const infolen = v.i32(b.memoffset);
        if (infolen < 0 || !v.ok(b.memoffset + 4, infolen)) throw new RangeError('member data past end');
        const ids = (k: number) => v.i32(b.memoffset + 4 + infolen + k * 4);
        let rec = b.memoffset + 4;
        for (let k = 0; k < nF; k++) {
          const reclen = v.i32(rec) & 0xffff;
          if (reclen < 24 || rec + reclen > b.memoffset + 4 + infolen) { warnings.push(`${ti.name}: function record ${k} out of range`); break; }
          const dt = v.i32(rec + 4), fflags = v.i32(rec + 8), vtoff = v.i16(rec + 12), fk = v.i32(rec + 16), nargs = v.i16(rec + 20), noargs = v.i16(rec + 22);
          const nArgs = Math.max(0, Math.min(nargs, 1024));
          const optLen = reclen - nArgs * 12;
          const opt = (i: number) => (optLen > 24 + i * 4 ? v.i32(rec + 24 + i * 4) : undefined);
          const f: TlbFunc = {
            name: name(ids(nF + nV + k)), memid: ids(k), vtableOffset: vtoff, invokeKind: INVOKE[(fk >> 3) & 0xf] ?? String((fk >> 3) & 0xf), funcKind: FUNCKIND[fk & 7] ?? String(fk & 7),
            callConv: CALLCONV[(fk >> 8) & 0xf] ?? String((fk >> 8) & 0xf), returns: typeName(dt), params: [], optionalParams: noargs, flags: fflags & 0xffff,
          };
          const hsf = opt(1); if (hsf !== undefined && hsf >= 0) { const s = string(hsf); if (s !== undefined) f.helpString = s; }
          const ent = opt(2); if (ent !== undefined && ent !== -1) f.entry = fk & 0x2000 ? ent : string(ent) ?? ent;
          const pbase = rec + reclen - nArgs * 12;
          for (let a = 0; a < nArgs; a++) {
            const pdt = v.i32(pbase + a * 12), pn = v.i32(pbase + a * 12 + 4), pf = v.i32(pbase + a * 12 + 8);
            f.params.push({ name: pn >= 0 ? name(pn) : `arg${a}`, type: typeName(pdt), flags: bits(pf, PARAMFLAG) });
          }
          ti.funcs.push(f);
          rec += reclen;
        }
        for (let k = 0; k < nV; k++) {
          const reclen = v.i32(rec) & 0xffff;
          if (reclen < 20 || rec + reclen > b.memoffset + 4 + infolen) { warnings.push(`${ti.name}: variable record ${k} out of range`); break; }
          const dt = v.i32(rec + 4), vk = v.i16(rec + 12), offs = v.i32(rec + 16);
          const kindName = VARKIND[vk] ?? String(vk);
          const x: TlbVar = { name: name(ids(nF + nV + nF + k)), memid: ids(nF + k), type: typeName(dt), kind: kindName };
          if (kindName === 'const') x.value = constValue(offs); else x.offset = offs;
          if (reclen >= 28) { const s = string(v.i32(rec + 24)); if (s !== undefined) x.helpString = s; }
          ti.vars.push(x);
          rec += reclen;
        }
      }
    } catch (e) { warnings.push(`${ti.name}: ${(e as Error).message}`); }
    typeInfos.push(ti);
  });
  // variable names: the names array holds function names then variable names
  for (const ti of typeInfos) for (const x of ti.vars) if (!x.name) x.name = '?';
  return {
    format: 'MSFT', name: name(nameOff), guid: guidAt(posguid), version: `${version & 0xffff}.${version >>> 16}`, lcid, syskind: SYSKIND[varflags & 0xf] ?? String(varflags & 0xf),
    flags: bits(flags, LIBFLAG), ...(string(helpstring) !== undefined ? { helpString: string(helpstring) } : {}), ...(string(helpfile) !== undefined ? { helpFile: string(helpfile) } : {}),
    typeInfos, imports, warnings, source: { kind: 'file' },
  };
}

/** Type libraries in a file: a .tlb itself, or every TYPELIB resource of a PE (DLL, EXE, OCX). */
export function typeLibsIn(bytes: Uint8Array): TypeLib[] {
  if (isTypeLib(bytes)) return [readTypeLib(bytes)];
  if (bytes.length > 0x40 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    const out: TypeLib[] = [];
    for (const r of peResources(bytes)) {
      if (r.type !== 'TYPELIB' || r.offset < 0 || r.offset + r.size > bytes.length) continue;
      const data = bytes.subarray(r.offset, r.offset + r.size);
      try { const t = readTypeLib(data); t.source = { kind: 'pe-resource', name: r.name, lang: r.lang, offset: r.offset, size: r.size }; out.push(t); }
      catch (e) { out.push({ format: 'MSFT', name: '', version: '', lcid: 0, syskind: '', flags: [], typeInfos: [], imports: [], warnings: [(e as Error).message], source: { kind: 'pe-resource', name: r.name, lang: r.lang, offset: r.offset, size: r.size } }); }
    }
    return out;
  }
  throw new Error('not a type library or a PE file with TYPELIB resources');
}

/** IDL like text for one type info. */
export function typeInfoIdl(t: TlbTypeInfo): string {
  const attrs = [t.guid ? `uuid(${t.guid.slice(1, -1)})` : '', t.version !== '0.0' ? `version(${t.version})` : '', ...t.flags, t.helpString ? `helpstring("${t.helpString}")` : ''].filter(Boolean);
  const head = attrs.length ? `[${attrs.join(', ')}]\n` : '';
  if (t.kind === 'enum') return `${head}enum ${t.name} {\n${t.vars.map((x) => `  ${x.name} = ${x.value},`).join('\n')}\n};`;
  if (t.kind === 'record' || t.kind === 'union') return `${head}${t.kind === 'record' ? 'struct' : 'union'} ${t.name} {\n${t.vars.map((x) => `  ${x.type} ${x.name}; // offset ${x.offset}`).join('\n')}\n};`;
  if (t.kind === 'alias') return `typedef ${t.aliasOf} ${t.name};`;
  if (t.kind === 'coclass') return `${head}coclass ${t.name} {\n${t.implements.map((i) => `  ${i.flags.length ? `[${i.flags.join(', ')}] ` : ''}interface ${i.name};`).join('\n')}\n};`;
  const fns = t.funcs.map((f) => {
    const fa = [f.invokeKind !== 'func' ? f.invokeKind : '', `id(0x${(f.memid >>> 0).toString(16)})`, f.entry !== undefined ? `entry(${typeof f.entry === 'string' ? `"${f.entry}"` : f.entry})` : ''].filter(Boolean);
    return `  [${fa.join(', ')}] ${f.returns} ${f.callConv === 'stdcall' && t.kind === 'module' ? '__stdcall ' : ''}${f.name}(${f.params.map((p) => `${p.flags.length ? `[${p.flags.join(', ')}] ` : ''}${p.type} ${p.name}`).join(', ')}); // vtable +${f.vtableOffset}`;
  });
  const base = t.implements[0] ? ` : ${t.implements[0].name}` : '';
  const word = t.kind === 'dispatch' ? 'dispinterface' : t.kind === 'module' ? 'module' : 'interface';
  const head2 = t.dllName ? head.replace(/^\[/, `[dllname("${t.dllName}"), `) || `[dllname("${t.dllName}")]\n` : head;
  return `${head2}${word} ${t.name}${word === 'module' ? '' : base} {\n${fns.join('\n')}\n};`;
}
