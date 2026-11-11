// High level .NET assembly model built on the metadata tables: names, types, members,
// attributes, P/Invoke, resources, IL with resolved tokens, xrefs and packer detection.
import { ByteReader, ParseError, LIMITS, hex, utf8, indexOfBytes, ascii, hex32 } from '../util.js';
import { rvaToOffset, MACHINES, sectionOf } from './pe.js';
import {
  parseMetadata, getString, getGuid, getBlob, getUserString, decodeCoded, rows, row, tokenOf, readCompressedU,
  TABLE_NAMES, CLI_FLAGS, flagNames, listUserStrings, type Metadata,
} from './metadata.js';
import { decodeMethodSig, decodeFieldSig, decodeTypeSpec, decodeMethodSpec, decodeLocalsSig, readType } from './signature.js';
import { readMethodBody, decodeCil, ilLabel, type CilInstruction, type ExceptionClause } from './cil.js';

export interface DotnetAssembly {
  md: Metadata;
  typeName: (table: number, rid: number) => string;
  /** Resolve any metadata token to readable text. */
  tokenText: (token: number) => string;
  typeOfMethod: Map<number, number>;
  typeOfField: Map<number, number>;
  enclosing: Map<number, number>;
}

const VISIBILITY = ['private', 'public', 'nested public', 'nested private', 'nested family', 'nested assembly', 'nested famandassem', 'nested famorassem'];
const MEMBER_ACCESS = ['compilercontrolled', 'private', 'famandassem', 'assembly', 'family', 'famorassem', 'public'];

/** Load a .NET assembly from bytes. Throws ParseError when the file has no CLI metadata. */
export function loadAssembly(bytes: Uint8Array): DotnetAssembly {
  const md = parseMetadata(bytes);
  const typeDefs = rows(md, 0x02);
  const methodPtr = rows(md, 0x05), fieldPtr = rows(md, 0x03);
  const enclosing = new Map<number, number>();
  for (const n of rows(md, 0x29)) enclosing.set(n.NestedClass as number, n.EnclosingClass as number);

  const typeOfMethod = new Map<number, number>();
  const typeOfField = new Map<number, number>();
  const nMethods = rows(md, 0x06).length, nFields = rows(md, 0x04).length;
  for (let i = 0; i < typeDefs.length; i++) {
    const t = typeDefs[i] as Record<string, number>;
    const next = typeDefs[i + 1];
    const mEnd = next ? (next.MethodList as number) : (methodPtr.length || nMethods) + 1;
    const fEnd = next ? (next.FieldList as number) : (fieldPtr.length || nFields) + 1;
    for (let m = t.MethodList as number; m < mEnd && m <= Math.max(nMethods, methodPtr.length); m++) {
      const rid = methodPtr.length ? (methodPtr[m - 1]?.Method ?? m) : m;
      typeOfMethod.set(rid, i + 1);
    }
    for (let f = t.FieldList as number; f < fEnd && f <= Math.max(nFields, fieldPtr.length); f++) {
      const rid = fieldPtr.length ? (fieldPtr[f - 1]?.Field ?? f) : f;
      typeOfField.set(rid, i + 1);
    }
  }

  const tdCache = new Map<number, string>();
  const typeDefName = (rid: number, depth = 0): string => {
    const c = tdCache.get(rid); if (c !== undefined) return c;
    const t = row(md, 0x02, rid);
    if (!t) return `<TypeDef#${rid}>`;
    const name = getString(md, t.TypeName as number), ns = getString(md, t.TypeNamespace as number);
    const enc = enclosing.get(rid);
    let full = ns ? `${ns}.${name}` : name;
    if (enc && enc !== rid && depth < 32) full = `${typeDefName(enc, depth + 1)}/${name}`;
    tdCache.set(rid, full);
    return full;
  };
  const typeRefName = (rid: number, depth = 0): string => {
    const t = row(md, 0x01, rid);
    if (!t) return `<TypeRef#${rid}>`;
    const name = getString(md, t.TypeName as number), ns = getString(md, t.TypeNamespace as number);
    const scope = decodeCoded('ResolutionScope', t.ResolutionScope as number);
    if (scope.table === 0x01 && scope.row && depth < 32) return `${typeRefName(scope.row, depth + 1)}/${name}`;
    return ns ? `${ns}.${name}` : name;
  };
  const specDepth = { d: 0 };
  const typeName = (table: number, rid: number): string => {
    if (table === 0x02) return typeDefName(rid);
    if (table === 0x01) return typeRefName(rid);
    if (table === 0x1b) {
      const s = row(md, 0x1b, rid);
      if (!s || specDepth.d > 8) return `<TypeSpec#${rid}>`;
      specDepth.d++;
      try { return decodeTypeSpec(getBlob(md, s.Signature as number), typeName); } finally { specDepth.d--; }
    }
    return `<${TABLE_NAMES[table] ?? table}#${rid}>`;
  };

  const memberRefParent = (v: number): string => {
    const p = decodeCoded('MemberRefParent', v);
    if (p.table === 0x1a) return `[${getString(md, row(md, 0x1a, p.row)?.Name ?? 0)}]`;
    if (p.table === 0x06) return methodDefName(p.row);
    return typeName(p.table, p.row);
  };
  const methodDefName = (rid: number): string => {
    const m = row(md, 0x06, rid);
    if (!m) return `<MethodDef#${rid}>`;
    const owner = typeOfMethod.get(rid);
    return `${owner ? typeDefName(owner) : '<Module>'}::${getString(md, m.Name as number)}`;
  };
  const sigText = (blob: Uint8Array): string => {
    const s = decodeMethodSig(blob, typeName);
    if (s) return `(${s.params.join(', ')})`;
    const f = decodeFieldSig(blob, typeName);
    return f ? ` : ${f}` : '';
  };

  const tokenText = (token: number): string => {
    const table = token >>> 24, rid = token & 0xffffff;
    try {
      switch (table) {
        case 0x70: { const s = getUserString(md, rid); return s === undefined ? `<us#${rid}>` : JSON.stringify(s); }
        case 0x01: case 0x02: case 0x1b: return typeName(table, rid);
        case 0x06: {
          const m = row(md, 0x06, rid);
          return m ? methodDefName(rid) + sigText(getBlob(md, m.Signature as number)) : `<MethodDef#${rid}>`;
        }
        case 0x04: {
          const f = row(md, 0x04, rid);
          if (!f) return `<Field#${rid}>`;
          const owner = typeOfField.get(rid);
          return `${owner ? typeDefName(owner) : '<Module>'}::${getString(md, f.Name as number)}`;
        }
        case 0x0a: {
          const m = row(md, 0x0a, rid);
          if (!m) return `<MemberRef#${rid}>`;
          return `${memberRefParent(m.Class as number)}::${getString(md, m.Name as number)}${sigText(getBlob(md, m.Signature as number))}`;
        }
        case 0x2b: {
          const s = row(md, 0x2b, rid);
          if (!s) return `<MethodSpec#${rid}>`;
          const mm = decodeCoded('MethodDefOrRef', s.Method as number);
          const base = tokenText(tokenOf(mm.table, mm.row));
          const args = decodeMethodSpec(getBlob(md, s.Instantiation as number), typeName);
          const i = base.indexOf('(');
          return i > 0 ? `${base.slice(0, i)}<${args.join(', ')}>${base.slice(i)}` : `${base}<${args.join(', ')}>`;
        }
        case 0x11: return `<StandAloneSig#${rid}>`;
        default: return `<${TABLE_NAMES[table] ?? '0x' + table.toString(16)}#${rid}>`;
      }
    } catch (e) {
      return `<bad token ${hex32(token)}>`;
    }
  };
  return { md, typeName, tokenText, typeOfMethod, typeOfField, enclosing };
}

// ---------------- info ----------------

export interface AssemblyRefInfo { name: string; version: string; culture: string; publicKeyToken: string }
export interface CustomAttributeInfo { owner: string; type: string; args: unknown[]; named: Record<string, unknown> }

export function assemblyName(asm: DotnetAssembly): { name: string; version: string; culture: string; publicKey: string; hashAlg: number; flags: number } | undefined {
  const a = row(asm.md, 0x20, 1);
  if (!a) return undefined;
  return {
    name: getString(asm.md, a.Name as number),
    version: `${a.MajorVersion}.${a.MinorVersion}.${a.BuildNumber}.${a.RevisionNumber}`,
    culture: getString(asm.md, a.Culture as number) || 'neutral',
    publicKey: hex(getBlob(asm.md, a.PublicKey as number)).slice(0, 320),
    hashAlg: a.HashAlgId as number,
    flags: a.Flags as number,
  };
}

export function assemblyRefs(asm: DotnetAssembly): AssemblyRefInfo[] {
  return rows(asm.md, 0x23).map((a) => {
    const pk = getBlob(asm.md, a.PublicKeyOrToken as number);
    return {
      name: getString(asm.md, a.Name as number),
      version: `${a.MajorVersion}.${a.MinorVersion}.${a.BuildNumber}.${a.RevisionNumber}`,
      culture: getString(asm.md, a.Culture as number) || 'neutral',
      publicKeyToken: pk.length === 8 ? hex(pk) : pk.length ? `key:${hex(pk).slice(0, 16)}...` : '',
    };
  });
}

/** Decode a custom attribute value blob against its constructor signature (primitives, strings, Type, enums as int). */
function decodeCaBlob(asm: DotnetAssembly, ctorSig: Uint8Array, value: Uint8Array): { args: unknown[]; named: Record<string, unknown> } {
  const out = { args: [] as unknown[], named: {} as Record<string, unknown> };
  const sig = decodeMethodSig(ctorSig, asm.typeName);
  if (!sig || value.length < 2) return out;
  const r = new ByteReader(value);
  if (r.u16() !== 1) return out;
  const serString = (): string | null => {
    if (r.bytes[r.pos] === 0xff) { r.pos++; return null; }
    const n = readCompressedU(r);
    return utf8(r.take(n));
  };
  const elem = (t: string): unknown => {
    switch (t) {
      case 'bool': return r.u8() !== 0;
      case 'char': return String.fromCharCode(r.u16());
      case 'sbyte': return r.i8();
      case 'byte': return r.u8();
      case 'short': return r.i16();
      case 'ushort': return r.u16();
      case 'int': return r.i32();
      case 'uint': return r.u32();
      case 'long': return r.i64().toString();
      case 'ulong': return r.u64().toString();
      case 'float': return r.f32();
      case 'double': return r.f64();
      case 'string': case 'System.Type': return serString();
      default: throw new ParseError('unsupported attribute argument type ' + t);
    }
  };
  try {
    for (const p of sig.params) {
      if (p.endsWith('[]')) {
        const n = r.u32();
        if (n === 0xffffffff) { out.args.push(null); continue; }
        const et = p.slice(0, -2); const arr: unknown[] = [];
        for (let i = 0; i < n && i < 4096; i++) arr.push(elem(et));
        out.args.push(arr);
      } else if (p === 'object') { out.args.push('<boxed>'); return out; }
      else {
        let v: unknown;
        try { v = elem(p); } catch { v = r.i32(); } // enums are int32 in nearly all real attributes
        out.args.push(v);
      }
    }
    const nNamed = r.remaining() >= 2 ? r.u16() : 0;
    for (let i = 0; i < nNamed && i < 256; i++) {
      r.u8(); // FIELD / PROPERTY
      const et = r.u8();
      let tname = '';
      if (et === 0x55) tname = serString() ?? '';
      const name = serString() ?? '';
      const prim: Record<number, string> = { 0x02: 'bool', 0x03: 'char', 0x04: 'sbyte', 0x05: 'byte', 0x06: 'short', 0x07: 'ushort', 0x08: 'int', 0x09: 'uint', 0x0a: 'long', 0x0b: 'ulong', 0x0c: 'float', 0x0d: 'double', 0x0e: 'string', 0x50: 'System.Type' };
      const t = prim[et] ?? (et === 0x55 ? 'int' : '');
      if (!t) break;
      out.named[name] = elem(t);
      void tname;
    }
  } catch { /* partial decode is fine */ }
  return out;
}

export function customAttributes(asm: DotnetAssembly, max = 20000): CustomAttributeInfo[] {
  const md = asm.md;
  const out: CustomAttributeInfo[] = [];
  for (const ca of rows(md, 0x0c)) {
    if (out.length >= max) break;
    const ctor = decodeCoded('CustomAttributeType', ca.Type as number);
    let typeStr = '';
    let ctorSig: Uint8Array = new Uint8Array(0);
    if (ctor.table === 0x0a) {
      const m = row(md, 0x0a, ctor.row);
      if (m) {
        const p = decodeCoded('MemberRefParent', m.Class as number);
        typeStr = asm.typeName(p.table, p.row);
        ctorSig = getBlob(md, m.Signature as number);
      }
    } else if (ctor.table === 0x06) {
      const m = row(md, 0x06, ctor.row);
      const owner = asm.typeOfMethod.get(ctor.row);
      typeStr = owner ? asm.typeName(0x02, owner) : '';
      if (m) ctorSig = getBlob(md, m.Signature as number);
    }
    const parent = decodeCoded('HasCustomAttribute', ca.Parent as number);
    const ownerStr = parent.table === 0x20 ? 'assembly' : parent.table === 0x00 ? 'module' : asm.tokenText(tokenOf(parent.table, parent.row));
    const { args, named } = decodeCaBlob(asm, ctorSig, getBlob(md, ca.Value as number));
    out.push({ owner: ownerStr, type: typeStr, args, named });
  }
  return out;
}

export interface PInvokeInfo { library: string; entry: string; member: string; flags: number; token: string }

export function pinvokes(asm: DotnetAssembly): PInvokeInfo[] {
  const md = asm.md;
  return rows(md, 0x1c).map((im) => {
    const mf = decodeCoded('MemberForwarded', im.MemberForwarded as number);
    const tok = tokenOf(mf.table, mf.row);
    return {
      library: getString(md, row(md, 0x1a, im.ImportScope as number)?.Name ?? 0),
      entry: getString(md, im.ImportName as number),
      member: asm.tokenText(tok),
      flags: im.MappingFlags as number,
      token: hex32(tok),
    };
  });
}

export interface ResourceInfo { name: string; public: boolean; implementation: string; offset?: number; size?: number; kind?: string }

export function resources(asm: DotnetAssembly): ResourceInfo[] {
  const md = asm.md;
  const baseOff = md.cli.resources.rva ? rvaToOffset(md.pe, md.cli.resources.rva) : -1;
  return rows(md, 0x28).map((m) => {
    const impl = decodeCoded('Implementation', m.Implementation as number);
    const info: ResourceInfo = {
      name: getString(md, m.Name as number),
      public: ((m.Flags as number) & 7) === 1,
      implementation: impl.row === 0 ? 'embedded' : impl.table === 0x23 ? `assemblyref:${getString(md, row(md, 0x23, impl.row)?.Name ?? 0)}` : `file:${getString(md, row(md, 0x26, impl.row)?.Name ?? 0)}`,
    };
    if (impl.row === 0 && baseOff >= 0) {
      const at = baseOff + (m.Offset as number);
      if (at + 4 <= md.pe.bytes.length) {
        const size = new DataView(md.pe.bytes.buffer, md.pe.bytes.byteOffset).getUint32(at, true);
        info.offset = at + 4; info.size = size;
        const magic = at + 8 <= md.pe.bytes.length ? new DataView(md.pe.bytes.buffer, md.pe.bytes.byteOffset).getUint32(at + 4, true) : 0;
        info.kind = magic === 0xbeefcace ? 'resources' : 'raw';
      }
    }
    return info;
  });
}

export function targetFramework(cas: CustomAttributeInfo[]): string | undefined {
  const t = cas.find((c) => c.owner === 'assembly' && c.type === 'System.Runtime.Versioning.TargetFrameworkAttribute');
  return t && typeof t.args[0] === 'string' ? t.args[0] : undefined;
}

// ---------------- types ----------------

export interface MethodInfo { token: string; name: string; signature: string; rva: number; fileOffset?: number; flags: number; implFlags: number; access: string; static: boolean; abstract: boolean; pinvoke: boolean; params: string[] }
export interface FieldInfo { token: string; name: string; type: string; flags: number; access: string; static: boolean }
export interface TypeInfo { token: string; name: string; namespace: string; fullName: string; flags: number; visibility: string; kind: string; extends?: string; interfaces: string[]; methods: MethodInfo[]; fields: FieldInfo[]; nested: boolean }

function methodInfo(asm: DotnetAssembly, rid: number): MethodInfo | undefined {
  const md = asm.md;
  const m = row(md, 0x06, rid);
  if (!m) return undefined;
  const sig = decodeMethodSig(getBlob(md, m.Signature as number), asm.typeName);
  const flags = m.Flags as number;
  const rva = m.RVA as number;
  const params: string[] = [];
  const next = row(md, 0x06, rid + 1);
  const pEnd = next ? (next.ParamList as number) : rows(md, 0x08).length + 1;
  for (let p = m.ParamList as number; p < pEnd && params.length < 256; p++) {
    const pr = row(md, 0x08, p);
    if (pr && (pr.Sequence as number) > 0) params.push(getString(md, pr.Name as number));
  }
  const info: MethodInfo = {
    token: hex32(tokenOf(0x06, rid)), name: getString(md, m.Name as number),
    signature: sig ? `${sig.ret} (${sig.params.map((t, i) => params[i] ? `${t} ${params[i]}` : t).join(', ')})` : '?',
    rva, flags, implFlags: m.ImplFlags as number, access: MEMBER_ACCESS[flags & 7] ?? '?', static: (flags & 0x10) !== 0, abstract: (flags & 0x400) !== 0,
    pinvoke: (flags & 0x2000) !== 0, params,
  };
  if (rva) { const o = rvaToOffset(md.pe, rva); if (o >= 0) info.fileOffset = o; }
  return info;
}

export function listTypes(asm: DotnetAssembly, opts: { members?: boolean } = {}): TypeInfo[] {
  const md = asm.md;
  const ifaces = new Map<number, string[]>();
  for (const ii of rows(md, 0x09)) {
    const c = decodeCoded('TypeDefOrRef', ii.Interface as number);
    const list = ifaces.get(ii.Class as number) ?? [];
    list.push(asm.typeName(c.table, c.row));
    ifaces.set(ii.Class as number, list);
  }
  const methodsOf = new Map<number, number[]>(), fieldsOf = new Map<number, number[]>();
  if (opts.members) {
    for (const [m, t] of asm.typeOfMethod) { const l = methodsOf.get(t) ?? []; l.push(m); methodsOf.set(t, l); }
    for (const [f, t] of asm.typeOfField) { const l = fieldsOf.get(t) ?? []; l.push(f); fieldsOf.set(t, l); }
  }
  return rows(md, 0x02).map((t, i) => {
    const rid = i + 1;
    const flags = t.Flags as number;
    const ext = decodeCoded('TypeDefOrRef', t.Extends as number);
    const extends_ = ext.row ? asm.typeName(ext.table, ext.row) : undefined;
    const kind = flags & 0x20 ? 'interface' : extends_ === 'System.Enum' ? 'enum' : extends_ === 'System.ValueType' ? 'struct' : extends_ === 'System.MulticastDelegate' ? 'delegate' : 'class';
    const info: TypeInfo = {
      token: hex32(tokenOf(0x02, rid)), name: getString(md, t.TypeName as number), namespace: getString(md, t.TypeNamespace as number),
      fullName: asm.typeName(0x02, rid), flags, visibility: VISIBILITY[flags & 7] ?? '?', kind, extends: extends_,
      interfaces: ifaces.get(rid) ?? [], methods: [], fields: [], nested: asm.enclosing.has(rid),
    };
    if (opts.members) {
      for (const m of methodsOf.get(rid) ?? []) { const mi = methodInfo(asm, m); if (mi) info.methods.push(mi); }
      for (const f of fieldsOf.get(rid) ?? []) {
        const fr = row(md, 0x04, f); if (!fr) continue;
        const ff = fr.Flags as number;
        info.fields.push({ token: hex32(tokenOf(0x04, f)), name: getString(md, fr.Name as number), type: decodeFieldSig(getBlob(md, fr.Signature as number), asm.typeName) ?? '?', flags: ff, access: MEMBER_ACCESS[ff & 7] ?? '?', static: (ff & 0x10) !== 0 });
      }
    }
    return info;
  });
}

// ---------------- IL ----------------

export interface MethodIl {
  token: string; name: string; signature: string; rva: number;
  body?: { offset: number; format: 'tiny' | 'fat'; maxStack: number; codeSize: number; initLocals: boolean; locals: string[]; clauses: (ExceptionClause & { catchType?: string })[] };
  instructions: (CilInstruction & { label: string; fileOffset: number })[];
  text: string;
  error?: string;
}

/** Find MethodDef rids by token (0x06xxxxxx or number), "Type::Method", or bare method name. */
export function findMethods(asm: DotnetAssembly, query: string | number): number[] {
  const md = asm.md;
  const n = rows(md, 0x06).length;
  if (typeof query === 'number' || /^(0x)?06[0-9a-f]{6}$/i.test(String(query))) {
    const tok = typeof query === 'number' ? query : parseInt(String(query), 16);
    const rid = tok & 0xffffff;
    return rid >= 1 && rid <= n && tok >>> 24 === 6 ? [rid] : [];
  }
  const q = String(query);
  const out: number[] = [];
  const [tpart, mpart] = q.includes('::') ? q.split('::') as [string, string] : [undefined, q];
  for (let rid = 1; rid <= n; rid++) {
    const m = row(md, 0x06, rid)!;
    if (getString(md, m.Name as number) !== mpart) continue;
    if (tpart !== undefined) {
      const owner = asm.typeOfMethod.get(rid);
      const full = owner ? asm.typeName(0x02, owner) : '';
      if (full !== tpart && !full.endsWith('.' + tpart) && !full.endsWith('/' + tpart)) continue;
    }
    out.push(rid);
  }
  return out;
}

function formatOperand(asm: DotnetAssembly, ins: CilInstruction): string {
  switch (ins.operandKind) {
    case 'none': return '';
    case 'br8': case 'br32': return ilLabel(ins.target as number);
    case 'switch': return '(' + (ins.target as number[]).map(ilLabel).join(', ') + ')';
    case 'tok': return asm.tokenText(ins.token as number);
    case 'r4': case 'r8': return String(ins.operand);
    default: return String(ins.operand);
  }
}

/** Disassemble one method by MethodDef rid. */
export function methodIl(asm: DotnetAssembly, rid: number, maxInstructions = LIMITS.maxInstructions): MethodIl {
  const md = asm.md;
  const mi = methodInfo(asm, rid);
  if (!mi) throw new ParseError(`no MethodDef row ${rid}`);
  const owner = asm.typeOfMethod.get(rid);
  const name = `${owner ? asm.typeName(0x02, owner) : '<Module>'}::${mi.name}`;
  const res: MethodIl = { token: mi.token, name, signature: mi.signature, rva: mi.rva, instructions: [], text: '' };
  if (!mi.rva) { res.error = mi.abstract ? 'abstract method has no body' : mi.pinvoke ? 'P/Invoke method has no IL body' : 'method has no IL body (RVA 0)'; res.text = `// ${res.error}`; return res; }
  if (mi.implFlags & 0x3) { res.error = 'method body is native or runtime provided'; res.text = `// ${res.error}`; return res; }
  const off = mi.fileOffset ?? -1;
  if (off < 0) { res.error = 'method RVA not mapped to file'; return res; }
  const body = readMethodBody(md.pe.bytes, off);
  let locals: string[] = [];
  if (body.localVarSigTok >>> 24 === 0x11) {
    const s = row(md, 0x11, body.localVarSigTok & 0xffffff);
    if (s) locals = decodeLocalsSig(getBlob(md, s.Signature as number), asm.typeName);
  }
  res.body = {
    offset: body.offset, format: body.format, maxStack: body.maxStack, codeSize: body.codeSize, initLocals: body.initLocals, locals,
    clauses: body.clauses.map((c) => ({ ...c, catchType: c.kind === 'catch' && c.classTokenOrFilter ? asm.tokenText(c.classTokenOrFilter) : undefined })),
  };
  const dec = decodeCil(body.code, maxInstructions);
  if (dec.error) res.error = dec.error;
  const lines: string[] = [`.method ${mi.token} ${name} ${mi.signature}`, `  // rva ${hex32(mi.rva)} file offset ${hex32(off)} ${body.format} header, code size ${body.codeSize}`, `  .maxstack ${body.maxStack}`];
  if (locals.length) lines.push(`  .locals ${body.initLocals ? 'init ' : ''}(${locals.map((l, i) => `[${i}] ${l}`).join(', ')})`);
  for (const ins of dec.instructions) {
    const text = formatOperand(asm, ins);
    const full = { ...ins, label: ilLabel(ins.offset), fileOffset: body.codeOffset + ins.offset, text: text || undefined };
    res.instructions.push(full);
    lines.push(`  ${full.label}: ${ins.opcode}${text ? ' ' + text : ''}`);
  }
  for (const c of res.body.clauses) lines.push(`  .try ${ilLabel(c.tryOffset)} to ${ilLabel(c.tryOffset + c.tryLength)} ${c.kind}${c.catchType ? ' ' + c.catchType : ''} handler ${ilLabel(c.handlerOffset)} to ${ilLabel(c.handlerOffset + c.handlerLength)}`);
  if (dec.error) lines.push(`  // ${dec.error}`);
  res.text = lines.join('\n');
  return res;
}

// ---------------- xrefs ----------------

export interface Xref { from: string; fromToken: string; offset: number; label: string; opcode: string; to: string; toToken: string }

/**
 * Scan every method body for token operands. `match` filters on the referenced token or its resolved text.
 * Budgeted by instruction count so a huge assembly stays bounded.
 */
export function xrefs(asm: DotnetAssembly, match: (token: number, text: string) => boolean, opts: { max?: number; instructionBudget?: number } = {}): { xrefs: Xref[]; scannedMethods: number; budgetExhausted: boolean } {
  const md = asm.md;
  const max = opts.max ?? 2000;
  let budget = opts.instructionBudget ?? 5_000_000;
  const out: Xref[] = [];
  const n = rows(md, 0x06).length;
  let scanned = 0;
  const textCache = new Map<number, string>();
  for (let rid = 1; rid <= n && out.length < max; rid++) {
    const m = row(md, 0x06, rid)!;
    if (!m.RVA || ((m.ImplFlags as number) & 3)) continue;
    const off = rvaToOffset(md.pe, m.RVA as number);
    if (off < 0) continue;
    let body;
    try { body = readMethodBody(md.pe.bytes, off); } catch { continue; }
    const dec = decodeCil(body.code, Math.max(1, budget));
    budget -= dec.instructions.length;
    scanned++;
    let fromName: string | undefined;
    for (const ins of dec.instructions) {
      if (ins.token === undefined) continue;
      let t = textCache.get(ins.token);
      if (t === undefined) { t = asm.tokenText(ins.token); textCache.set(ins.token, t); }
      if (!match(ins.token, t)) continue;
      fromName ??= asm.tokenText(tokenOf(0x06, rid));
      out.push({ from: fromName, fromToken: hex32(tokenOf(0x06, rid)), offset: ins.offset, label: ilLabel(ins.offset), opcode: ins.opcode, to: t, toToken: hex32(ins.token) });
      if (out.length >= max) break;
    }
    if (budget <= 0) return { xrefs: out, scannedMethods: scanned, budgetExhausted: true };
  }
  return { xrefs: out, scannedMethods: scanned, budgetExhausted: false };
}

// ---------------- packers, bundles, ReadyToRun ----------------

export interface ObfuscatorHit { name: string; evidence: string }

const OBF_TYPES: [RegExp, string][] = [
  [/^ConfusedByAttribute$/, 'ConfuserEx'],
  [/^DotfuscatorAttribute$/, 'Dotfuscator'],
  [/^PoweredByAttribute$/, 'SmartAssembly'],
  [/^BabelAttribute$|^BabelObfuscatorAttribute$/, 'Babel'],
  [/^ObfuscatedByGoliath$/, 'Goliath.NET'],
  [/^Xenocode\.Client\.Attributes/, 'Xenocode'],
  [/^ZYXDNGuarder$/, 'DNGuard'],
  [/^YanoAttribute$/, 'Yano'],
  [/^CryptoObfuscator/, 'Crypto Obfuscator'],
  [/^NineRays\.Obfuscator/, 'Spices.Net'],
  [/^EMyPID_8234_$/, '.NET Reactor'],
  [/^__BeaEnc/, 'BeaEnc'],
];
const OBF_STRINGS: [string, string][] = [
  ['ConfuserEx v', 'ConfuserEx'], ['Confuser v', 'Confuser'], ['Dotfuscator', 'Dotfuscator'], ['SmartAssembly', 'SmartAssembly'],
  ['Eazfuscator', 'Eazfuscator.NET'], ['.NET Reactor', '.NET Reactor'], ['ArmDot', 'ArmDot'], ['Agile.NET', 'Agile.NET'], ['KoiVM', 'KoiVM'],
];

export function detectObfuscators(asm: DotnetAssembly): ObfuscatorHit[] {
  const md = asm.md;
  const hits: ObfuscatorHit[] = [];
  const seen = new Set<string>();
  const add = (name: string, evidence: string) => { if (!seen.has(name)) { seen.add(name); hits.push({ name, evidence }); } };
  for (const tbl of [0x01, 0x02]) {
    for (const t of rows(md, tbl)) {
      const nm = getString(md, t.TypeName as number); const ns = getString(md, t.TypeNamespace as number);
      for (const [re, name] of OBF_TYPES) if (re.test(nm) || re.test(`${ns}.${nm}`)) add(name, `${tbl === 1 ? 'TypeRef' : 'TypeDef'} ${ns ? ns + '.' : ''}${nm}`);
    }
  }
  for (const s of listUserStrings(md, 50000)) for (const [needle, name] of OBF_STRINGS) if (s.value.includes(needle)) add(name, `user string ${JSON.stringify(s.value.slice(0, 80))}`);
  for (const [needle, name] of OBF_STRINGS) {
    const at = indexOfBytes(md.strings, ascii(needle));
    if (at >= 0) add(name, `#Strings offset ${at}`);
  }
  // Heuristic: many type or method names that are not printable identifiers.
  const names = [...rows(md, 0x02).map((t) => getString(md, t.TypeName as number)), ...rows(md, 0x06).map((m) => getString(md, m.Name as number))];
  const odd = names.filter((n) => n.length > 0 && /[^\x20-\x7e]/.test(n)).length;
  if (names.length >= 20 && odd / names.length > 0.3) add('unknown renamer', `${odd} of ${names.length} type and method names use non ASCII or control characters`);
  if (md.tableStream === '#-') add('uncompressed metadata (#-)', 'metadata uses the #- table stream, common with ENC or protectors');
  if (md.streams.filter((s) => s.name === '#~' || s.name === '#Strings').length > 2) add('duplicate metadata streams', 'repeated #~ or #Strings stream, a known anti tool trick');
  return hits;
}

export interface ReadyToRunInfo { rva: number; majorVersion: number; minorVersion: number; flags: number; sections: { type: number; name: string; rva: number; size: number }[]; compositeOrComponent?: string }
const R2R_SECTIONS: Record<number, string> = {
  100: 'CompilerIdentifier', 101: 'ImportSections', 102: 'RuntimeFunctions', 103: 'MethodDefEntryPoints', 104: 'ExceptionInfo', 105: 'DebugInfo',
  106: 'DelayLoadMethodCallThunks', 108: 'AvailableTypes', 109: 'InstanceMethodEntryPoints', 110: 'InliningInfo', 111: 'ProfileDataInfo',
  112: 'ManifestMetadata', 113: 'AttributePresence', 114: 'InliningInfo2', 115: 'ComponentAssemblies', 116: 'OwnerCompositeExecutable',
  117: 'PgoInstrumentationData', 118: 'ManifestAssemblyMvids', 119: 'CrossModuleInlineInfo', 120: 'HotColdMap', 121: 'MethodIsGenericMap', 122: 'EnclosingTypeMap', 123: 'TypeGenericInfoMap',
};

/** Parse the ReadyToRun header pointed to by the CLI ManagedNativeHeader. */
export function readyToRun(asm: DotnetAssembly): ReadyToRunInfo | undefined {
  const md = asm.md;
  const mnh = md.cli.managedNativeHeader;
  if (!mnh.rva) return undefined;
  const off = rvaToOffset(md.pe, mnh.rva);
  if (off < 0) return undefined;
  const r = new ByteReader(md.pe.bytes, off);
  try {
    if (r.u32() !== 0x00525452) return undefined; // 'RTR'
    const majorVersion = r.u16(), minorVersion = r.u16(), flags = r.u32(), n = r.u32();
    const sections: ReadyToRunInfo['sections'] = [];
    for (let i = 0; i < Math.min(n, 64); i++) {
      const type = r.u32(), rva = r.u32(), size = r.u32();
      sections.push({ type, name: R2R_SECTIONS[type] ?? `type${type}`, rva, size });
    }
    let comp: string | undefined;
    const id = sections.find((s) => s.type === 100);
    if (id) { const o = rvaToOffset(md.pe, id.rva); if (o >= 0) comp = new ByteReader(md.pe.bytes, o).cstr(Math.min(id.size, 256)); }
    return { rva: mnh.rva, majorVersion, minorVersion, flags, sections, compositeOrComponent: comp };
  } catch { return undefined; }
}

export interface BundleEntry { path: string; offset: number; size: number; compressedSize: number; type: string }
export interface BundleInfo { headerOffset: number; version: string; bundleId: string; fileCount: number; files: BundleEntry[]; depsJson?: { offset: number; size: number }; runtimeConfigJson?: { offset: number; size: number }; flags?: string }

// SHA-256 of ".net core bundle", the marker the apphost searches for.
const BUNDLE_SIG = Uint8Array.from([0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, 0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae]);
const BUNDLE_TYPES = ['unknown', 'assembly', 'nativebinary', 'depsjson', 'runtimeconfigjson', 'symbols'];

/** Detect a .NET single-file bundle (apphost with an appended manifest) in any executable format. */
export function singleFileBundle(bytes: Uint8Array): BundleInfo | undefined {
  const at = indexOfBytes(bytes, BUNDLE_SIG);
  if (at < 8) return undefined;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerOffset = Number(dv.getBigInt64(at - 8, true));
  if (headerOffset <= 0 || headerOffset >= bytes.length) return { headerOffset: 0, version: 'not bundled (placeholder apphost)', bundleId: '', fileCount: 0, files: [] };
  const r = new ByteReader(bytes, headerOffset);
  const str = () => {
    let len = 0, shift = 0, b = 0, guard = 0;
    do { b = r.u8(); len |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80 && guard++ < 4);
    if (len > 4096) throw new ParseError('bundle path too long', r.pos);
    return utf8(r.take(len));
  };
  try {
    const major = r.u32(), minor = r.u32(), count = r.i32();
    if (count < 0 || count > LIMITS.maxEntries) throw new ParseError('bad bundle file count');
    const bundleId = str();
    const info: BundleInfo = { headerOffset, version: `${major}.${minor}`, bundleId, fileCount: count, files: [] };
    if (major >= 2) {
      info.depsJson = { offset: Number(r.i64()), size: Number(r.i64()) };
      info.runtimeConfigJson = { offset: Number(r.i64()), size: Number(r.i64()) };
      const fl = Number(r.u64());
      info.flags = fl & 1 ? 'NetcoreApp3CompatMode' : 'none';
    }
    for (let i = 0; i < count; i++) {
      const offset = Number(r.i64()), size = Number(r.i64());
      const compressedSize = major >= 6 ? Number(r.i64()) : 0;
      const type = r.u8();
      info.files.push({ path: str(), offset, size, compressedSize, type: BUNDLE_TYPES[type] ?? `type${type}` });
    }
    return info;
  } catch (e) {
    return { headerOffset, version: 'unreadable', bundleId: e instanceof Error ? e.message : '', fileCount: 0, files: [] };
  }
}

// ---------------- summary ----------------

export interface DotnetInfo {
  assembly?: ReturnType<typeof assemblyName>;
  module: { name: string; mvid: string };
  runtimeVersion: string;
  cliRuntime: string;
  cliFlags: string[];
  machine: string;
  entryPoint?: string;
  targetFramework?: string;
  metadata: { offset: number; tablesVersion: string; tableStream: string; streams: { name: string; offset: number; size: number }[]; rowCounts: Record<string, number>; tableError?: string };
  assemblyRefs: AssemblyRefInfo[];
  moduleRefs: string[];
  attributes: CustomAttributeInfo[];
  pinvoke: PInvokeInfo[];
  resources: ResourceInfo[];
  counts: { types: number; methods: number; fields: number; memberRefs: number; typeRefs: number; userStrings: number };
  obfuscators: ObfuscatorHit[];
  readyToRun?: ReadyToRunInfo;
  strongNameSigned: boolean;
}

export function dotnetInfo(asm: DotnetAssembly, opts: { maxAttributes?: number } = {}): DotnetInfo {
  const md = asm.md;
  const mod = row(md, 0x00, 1);
  const rowCounts: Record<string, number> = {};
  for (const [, t] of md.tables) rowCounts[t.name] = t.rows.length;
  const cas = customAttributes(asm, opts.maxAttributes ?? 500);
  const ep = md.cli.entryPointToken;
  const r2r = readyToRun(asm);
  return {
    assembly: assemblyName(asm),
    module: { name: mod ? getString(md, mod.Name as number) : '', mvid: mod ? getGuid(md, mod.Mvid as number) : '' },
    runtimeVersion: md.version,
    cliRuntime: md.cli.runtime,
    cliFlags: flagNames(md.cli.flags, CLI_FLAGS),
    machine: MACHINES[md.pe.machine] ?? `0x${md.pe.machine.toString(16)}`,
    entryPoint: ep ? (md.cli.flags & 0x10 ? `native rva ${hex32(ep)}` : asm.tokenText(ep)) : undefined,
    targetFramework: targetFramework(cas),
    metadata: { offset: md.rootOffset, tablesVersion: `${md.tablesMajor}.${md.tablesMinor}`, tableStream: md.tableStream, streams: md.streams, rowCounts, tableError: md.tableError },
    assemblyRefs: assemblyRefs(asm),
    moduleRefs: rows(md, 0x1a).map((m) => getString(md, m.Name as number)),
    attributes: cas.filter((c) => c.owner === 'assembly' || c.owner === 'module'),
    pinvoke: pinvokes(asm),
    resources: resources(asm),
    counts: {
      types: rows(md, 0x02).length, methods: rows(md, 0x06).length, fields: rows(md, 0x04).length,
      memberRefs: rows(md, 0x0a).length, typeRefs: rows(md, 0x01).length, userStrings: listUserStrings(md, LIMITS.maxEntries).length,
    },
    obfuscators: detectObfuscators(asm),
    readyToRun: r2r,
    strongNameSigned: (md.cli.flags & 0x8) !== 0,
  };
}

export { sectionOf, readType };
