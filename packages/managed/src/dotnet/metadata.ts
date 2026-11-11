// ECMA-335 CLI header, metadata root, heaps and the #~ / #- table stream.
import { ByteReader, ParseError, LIMITS, latin1, utf8, utf16le, hex } from '../util.js';
import { parsePe, rvaToOffset, type PeImage } from './pe.js';

export const TABLE_NAMES: Record<number, string> = {
  0x00: 'Module', 0x01: 'TypeRef', 0x02: 'TypeDef', 0x03: 'FieldPtr', 0x04: 'Field', 0x05: 'MethodPtr', 0x06: 'MethodDef',
  0x07: 'ParamPtr', 0x08: 'Param', 0x09: 'InterfaceImpl', 0x0a: 'MemberRef', 0x0b: 'Constant', 0x0c: 'CustomAttribute',
  0x0d: 'FieldMarshal', 0x0e: 'DeclSecurity', 0x0f: 'ClassLayout', 0x10: 'FieldLayout', 0x11: 'StandAloneSig', 0x12: 'EventMap',
  0x13: 'EventPtr', 0x14: 'Event', 0x15: 'PropertyMap', 0x16: 'PropertyPtr', 0x17: 'Property', 0x18: 'MethodSemantics',
  0x19: 'MethodImpl', 0x1a: 'ModuleRef', 0x1b: 'TypeSpec', 0x1c: 'ImplMap', 0x1d: 'FieldRVA', 0x1e: 'ENCLog', 0x1f: 'ENCMap',
  0x20: 'Assembly', 0x21: 'AssemblyProcessor', 0x22: 'AssemblyOS', 0x23: 'AssemblyRef', 0x24: 'AssemblyRefProcessor',
  0x25: 'AssemblyRefOS', 0x26: 'File', 0x27: 'ExportedType', 0x28: 'ManifestResource', 0x29: 'NestedClass',
  0x2a: 'GenericParam', 0x2b: 'MethodSpec', 0x2c: 'GenericParamConstraint',
  0x30: 'Document', 0x31: 'MethodDebugInformation', 0x32: 'LocalScope', 0x33: 'LocalVariable', 0x34: 'LocalConstant',
  0x35: 'ImportScope', 0x36: 'StateMachineMethod', 0x37: 'CustomDebugInformation',
};

/** Coded index definitions: tag bit count and the tables each tag selects (-1 = unused tag). */
export const CODED: Record<string, { bits: number; tables: number[] }> = {
  TypeDefOrRef: { bits: 2, tables: [0x02, 0x01, 0x1b] },
  HasConstant: { bits: 2, tables: [0x04, 0x08, 0x17] },
  HasCustomAttribute: { bits: 5, tables: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b] },
  HasFieldMarshal: { bits: 1, tables: [0x04, 0x08] },
  HasDeclSecurity: { bits: 2, tables: [0x02, 0x06, 0x20] },
  MemberRefParent: { bits: 3, tables: [0x02, 0x01, 0x1a, 0x06, 0x1b] },
  HasSemantics: { bits: 1, tables: [0x14, 0x17] },
  MethodDefOrRef: { bits: 1, tables: [0x06, 0x0a] },
  MemberForwarded: { bits: 1, tables: [0x04, 0x06] },
  Implementation: { bits: 2, tables: [0x26, 0x23, 0x27] },
  CustomAttributeType: { bits: 3, tables: [-1, -1, 0x06, 0x0a, -1] },
  ResolutionScope: { bits: 2, tables: [0x00, 0x1a, 0x23, 0x01] },
  TypeOrMethodDef: { bits: 1, tables: [0x02, 0x06] },
  HasCustomDebugInformation: { bits: 5, tables: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b, 0x30, 0x32, 0x33, 0x34, 0x35] },
};

// Column kinds: 'u8x2' and 'u16' are 2 bytes, 'u32' 4, 'str' / 'guid' / 'blob' heap indexes,
// 't:N' simple index into table N, 'c:Name' coded index.
type Col = [name: string, kind: string];
const S: Record<number, Col[]> = {
  0x00: [['Generation', 'u16'], ['Name', 'str'], ['Mvid', 'guid'], ['EncId', 'guid'], ['EncBaseId', 'guid']],
  0x01: [['ResolutionScope', 'c:ResolutionScope'], ['TypeName', 'str'], ['TypeNamespace', 'str']],
  0x02: [['Flags', 'u32'], ['TypeName', 'str'], ['TypeNamespace', 'str'], ['Extends', 'c:TypeDefOrRef'], ['FieldList', 't:4'], ['MethodList', 't:6']],
  0x03: [['Field', 't:4']],
  0x04: [['Flags', 'u16'], ['Name', 'str'], ['Signature', 'blob']],
  0x05: [['Method', 't:6']],
  0x06: [['RVA', 'u32'], ['ImplFlags', 'u16'], ['Flags', 'u16'], ['Name', 'str'], ['Signature', 'blob'], ['ParamList', 't:8']],
  0x07: [['Param', 't:8']],
  0x08: [['Flags', 'u16'], ['Sequence', 'u16'], ['Name', 'str']],
  0x09: [['Class', 't:2'], ['Interface', 'c:TypeDefOrRef']],
  0x0a: [['Class', 'c:MemberRefParent'], ['Name', 'str'], ['Signature', 'blob']],
  0x0b: [['Type', 'u16'], ['Parent', 'c:HasConstant'], ['Value', 'blob']],
  0x0c: [['Parent', 'c:HasCustomAttribute'], ['Type', 'c:CustomAttributeType'], ['Value', 'blob']],
  0x0d: [['Parent', 'c:HasFieldMarshal'], ['NativeType', 'blob']],
  0x0e: [['Action', 'u16'], ['Parent', 'c:HasDeclSecurity'], ['PermissionSet', 'blob']],
  0x0f: [['PackingSize', 'u16'], ['ClassSize', 'u32'], ['Parent', 't:2']],
  0x10: [['Offset', 'u32'], ['Field', 't:4']],
  0x11: [['Signature', 'blob']],
  0x12: [['Parent', 't:2'], ['EventList', 't:20']],
  0x13: [['Event', 't:20']],
  0x14: [['EventFlags', 'u16'], ['Name', 'str'], ['EventType', 'c:TypeDefOrRef']],
  0x15: [['Parent', 't:2'], ['PropertyList', 't:23']],
  0x16: [['Property', 't:23']],
  0x17: [['Flags', 'u16'], ['Name', 'str'], ['Type', 'blob']],
  0x18: [['Semantics', 'u16'], ['Method', 't:6'], ['Association', 'c:HasSemantics']],
  0x19: [['Class', 't:2'], ['MethodBody', 'c:MethodDefOrRef'], ['MethodDeclaration', 'c:MethodDefOrRef']],
  0x1a: [['Name', 'str']],
  0x1b: [['Signature', 'blob']],
  0x1c: [['MappingFlags', 'u16'], ['MemberForwarded', 'c:MemberForwarded'], ['ImportName', 'str'], ['ImportScope', 't:26']],
  0x1d: [['RVA', 'u32'], ['Field', 't:4']],
  0x1e: [['Token', 'u32'], ['FuncCode', 'u32']],
  0x1f: [['Token', 'u32']],
  0x20: [['HashAlgId', 'u32'], ['MajorVersion', 'u16'], ['MinorVersion', 'u16'], ['BuildNumber', 'u16'], ['RevisionNumber', 'u16'], ['Flags', 'u32'], ['PublicKey', 'blob'], ['Name', 'str'], ['Culture', 'str']],
  0x21: [['Processor', 'u32']],
  0x22: [['OSPlatformID', 'u32'], ['OSMajorVersion', 'u32'], ['OSMinorVersion', 'u32']],
  0x23: [['MajorVersion', 'u16'], ['MinorVersion', 'u16'], ['BuildNumber', 'u16'], ['RevisionNumber', 'u16'], ['Flags', 'u32'], ['PublicKeyOrToken', 'blob'], ['Name', 'str'], ['Culture', 'str'], ['HashValue', 'blob']],
  0x24: [['Processor', 'u32'], ['AssemblyRef', 't:35']],
  0x25: [['OSPlatformId', 'u32'], ['OSMajorVersion', 'u32'], ['OSMinorVersion', 'u32'], ['AssemblyRef', 't:35']],
  0x26: [['Flags', 'u32'], ['Name', 'str'], ['HashValue', 'blob']],
  0x27: [['Flags', 'u32'], ['TypeDefId', 'u32'], ['TypeName', 'str'], ['TypeNamespace', 'str'], ['Implementation', 'c:Implementation']],
  0x28: [['Offset', 'u32'], ['Flags', 'u32'], ['Name', 'str'], ['Implementation', 'c:Implementation']],
  0x29: [['NestedClass', 't:2'], ['EnclosingClass', 't:2']],
  0x2a: [['Number', 'u16'], ['Flags', 'u16'], ['Owner', 'c:TypeOrMethodDef'], ['Name', 'str']],
  0x2b: [['Method', 'c:MethodDefOrRef'], ['Instantiation', 'blob']],
  0x2c: [['Owner', 't:42'], ['Constraint', 'c:TypeDefOrRef']],
  0x30: [['Name', 'blob'], ['HashAlgorithm', 'guid'], ['Hash', 'blob'], ['Language', 'guid']],
  0x31: [['Document', 't:48'], ['SequencePoints', 'blob']],
  0x32: [['Method', 't:6'], ['ImportScope', 't:53'], ['VariableList', 't:51'], ['ConstantList', 't:52'], ['StartOffset', 'u32'], ['Length', 'u32']],
  0x33: [['Attributes', 'u16'], ['Index', 'u16'], ['Name', 'str']],
  0x34: [['Name', 'str'], ['Signature', 'blob']],
  0x35: [['Parent', 't:53'], ['Imports', 'blob']],
  0x36: [['MoveNextMethod', 't:6'], ['KickoffMethod', 't:6']],
  0x37: [['Parent', 'c:HasCustomDebugInformation'], ['Kind', 'guid'], ['Value', 'blob']],
};

export type Row = Record<string, number>;
export interface Table { id: number; name: string; rows: Row[]; rowSize: number; offset: number }

export interface StreamHeader { name: string; offset: number; size: number }

export interface CliHeader {
  cb: number; runtime: string; flags: number; entryPointToken: number;
  metadata: { rva: number; size: number }; resources: { rva: number; size: number };
  strongNameSignature: { rva: number; size: number }; managedNativeHeader: { rva: number; size: number };
  vtableFixups: { rva: number; size: number };
}

export interface Metadata {
  pe: PeImage;
  cli: CliHeader;
  /** file offset of the metadata root (BSJB) */
  rootOffset: number;
  version: string;
  streams: StreamHeader[];
  tableStream: '#~' | '#-';
  tablesMajor: number;
  tablesMinor: number;
  heapSizes: number;
  tables: Map<number, Table>;
  /** table ids whose rows could not be read (unknown schema or truncation) */
  tableError?: string;
  strings: Uint8Array;
  blob: Uint8Array;
  guid: Uint8Array;
  us: Uint8Array;
  stringsOffset: number;
  usOffset: number;
  blobOffset: number;
}

export const CLI_FLAGS: Record<number, string> = {
  0x1: 'ILONLY', 0x2: '32BITREQUIRED', 0x4: 'IL_LIBRARY', 0x8: 'STRONGNAMESIGNED', 0x10: 'NATIVE_ENTRYPOINT', 0x10000: 'TRACKDEBUGDATA', 0x20000: '32BITPREFERRED',
};

export function flagNames(v: number, map: Record<number, string>): string[] {
  const out: string[] = [];
  for (const [k, n] of Object.entries(map)) if (v & Number(k)) out.push(n);
  return out;
}

export function hasCliHeader(bytes: Uint8Array): boolean {
  try {
    const pe = parsePe(bytes);
    const d = pe.dirs[14];
    return !!d && d.rva !== 0 && d.size >= 0x48 && rvaToOffset(pe, d.rva) >= 0;
  } catch { return false; }
}

function heapIndexSize(heapSizes: number, bit: number): number { return heapSizes & bit ? 4 : 2; }

/** Parse the CLI header and metadata of a .NET PE image. Throws ParseError when there is none. */
export function parseMetadata(bytes: Uint8Array): Metadata {
  const pe = parsePe(bytes);
  const d = pe.dirs[14];
  if (!d || d.rva === 0) throw new ParseError('no CLI header (not a .NET assembly)');
  const cliOff = rvaToOffset(pe, d.rva);
  if (cliOff < 0) throw new ParseError('CLI header RVA not mapped');
  const r = new ByteReader(bytes, cliOff);
  const cb = r.u32();
  const major = r.u16(); const minor = r.u16();
  const md = { rva: r.u32(), size: r.u32() };
  const flags = r.u32();
  const entryPointToken = r.u32();
  const resources = { rva: r.u32(), size: r.u32() };
  const strongNameSignature = { rva: r.u32(), size: r.u32() };
  r.skip(8); // code manager table
  const vtableFixups = { rva: r.u32(), size: r.u32() };
  r.skip(8); // export address table jumps
  const managedNativeHeader = { rva: r.u32(), size: r.u32() };
  const cli: CliHeader = { cb, runtime: `${major}.${minor}`, flags, entryPointToken, metadata: md, resources, strongNameSignature, managedNativeHeader, vtableFixups };

  const rootOffset = rvaToOffset(pe, md.rva);
  if (rootOffset < 0) throw new ParseError('metadata RVA not mapped');
  const mr = new ByteReader(bytes, rootOffset);
  if (mr.u32() !== 0x424a5342) throw new ParseError('bad metadata signature (expected BSJB)', rootOffset);
  mr.skip(8);
  const vlen = mr.u32();
  if (vlen > 256) throw new ParseError('metadata version string too long', mr.pos);
  const version = latin1(mr.take(vlen)).replace(/\0.*$/s, '');
  mr.skip(2);
  const nstreams = mr.u16();
  if (nstreams > 16) throw new ParseError('too many metadata streams', mr.pos);
  const streams: StreamHeader[] = [];
  for (let i = 0; i < nstreams; i++) {
    const off = mr.u32(); const size = mr.u32();
    const name = mr.cstr(32);
    while ((mr.pos - rootOffset) % 4) mr.pos++;
    streams.push({ name, offset: rootOffset + off, size });
  }
  const view = (name: string): [Uint8Array, number] => {
    // When a stream name repeats, the runtime uses the last one... the first is the common reading of tools; take first.
    const s = streams.find((x) => x.name === name);
    if (!s) return [new Uint8Array(0), 0];
    const start = Math.min(s.offset, bytes.length);
    const end = Math.min(bytes.length, s.offset + s.size);
    return [bytes.subarray(start, end), start];
  };
  const [strings, stringsOffset] = view('#Strings');
  const [blob, blobOffset] = view('#Blob');
  const [guid] = view('#GUID');
  const [us, usOffset] = view('#US');
  const tsName = streams.some((s) => s.name === '#~') ? '#~' : '#-';
  const [ts] = view(tsName);
  const meta: Metadata = {
    pe, cli, rootOffset, version, streams, tableStream: tsName, tablesMajor: 0, tablesMinor: 0, heapSizes: 0,
    tables: new Map(), strings, blob, guid, us, stringsOffset, usOffset, blobOffset,
  };
  if (ts.length) parseTables(meta, ts, streams.find((s) => s.name === tsName)?.offset ?? 0);
  return meta;
}

function parseTables(meta: Metadata, ts: Uint8Array, base: number): void {
  const r = new ByteReader(ts);
  r.skip(4);
  meta.tablesMajor = r.u8(); meta.tablesMinor = r.u8();
  meta.heapSizes = r.u8();
  r.skip(1);
  const validLo = r.u32(), validHi = r.u32();
  r.skip(8); // sorted
  const counts = new Array<number>(64).fill(0);
  const present: number[] = [];
  for (let i = 0; i < 64; i++) {
    const bit = i < 32 ? (validLo >>> i) & 1 : (validHi >>> (i - 32)) & 1;
    if (bit) {
      const n = r.u32();
      if (n > LIMITS.maxRowsPerTable) throw new ParseError(`table ${TABLE_NAMES[i] ?? i} row count ${n} too large`);
      counts[i] = n; present.push(i);
    }
  }
  if (meta.heapSizes & 0x40) r.skip(4); // extra data
  const strSize = heapIndexSize(meta.heapSizes, 1), guidSize = heapIndexSize(meta.heapSizes, 2), blobSize = heapIndexSize(meta.heapSizes, 4);
  const colSize = (kind: string): number => {
    if (kind === 'u16') return 2;
    if (kind === 'u32') return 4;
    if (kind === 'str') return strSize;
    if (kind === 'guid') return guidSize;
    if (kind === 'blob') return blobSize;
    if (kind.startsWith('t:')) return (counts[Number(kind.slice(2))] ?? 0) > 0xffff ? 4 : 2;
    const c = CODED[kind.slice(2)];
    if (!c) throw new ParseError(`unknown coded index ${kind}`);
    let max = 0;
    for (const t of c.tables) if (t >= 0) max = Math.max(max, counts[t] ?? 0);
    return max < 1 << (16 - c.bits) ? 2 : 4;
  };
  for (const id of present) {
    const schema = S[id];
    const n = counts[id] as number;
    if (!schema) { meta.tableError = `unknown table 0x${id.toString(16)} with ${n} rows; later tables skipped`; return; }
    const sizes = schema.map(([, k]) => colSize(k));
    const rowSize = sizes.reduce((a, b) => a + b, 0);
    const offset = base + r.pos;
    if (r.remaining() < rowSize * n) { meta.tableError = `table ${TABLE_NAMES[id]} truncated`; return; }
    const rows: Row[] = new Array(n);
    for (let i = 0; i < n; i++) {
      const row: Row = {};
      for (let c = 0; c < schema.length; c++) row[(schema[c] as Col)[0]] = r.uN(sizes[c] as number);
      rows[i] = row;
    }
    meta.tables.set(id, { id, name: TABLE_NAMES[id] ?? `0x${id.toString(16)}`, rows, rowSize, offset });
  }
}

// ---------- heap access ----------

export function getString(meta: Metadata, idx: number): string {
  if (!idx || idx >= meta.strings.length) return '';
  let end = idx;
  const lim = Math.min(meta.strings.length, idx + 4096);
  while (end < lim && meta.strings[end] !== 0) end++;
  return utf8(meta.strings.subarray(idx, end));
}

export function getGuid(meta: Metadata, idx: number): string {
  if (!idx) return '';
  const o = (idx - 1) * 16;
  if (o + 16 > meta.guid.length) return '';
  const b = meta.guid.subarray(o, o + 16);
  const le = (s: number, n: number) => hex(Uint8Array.from(b.subarray(s, s + n)).reverse());
  return `${le(0, 4)}-${le(4, 2)}-${le(6, 2)}-${hex(b, 8, 10)}-${hex(b, 10, 16)}`;
}

/** ECMA-335 compressed unsigned integer. */
export function readCompressedU(r: ByteReader): number {
  const b = r.u8();
  if ((b & 0x80) === 0) return b;
  if ((b & 0xc0) === 0x80) return ((b & 0x3f) << 8) | r.u8();
  if ((b & 0xe0) === 0xc0) return (((b & 0x1f) << 24) | (r.u8() << 16) | (r.u8() << 8) | r.u8()) >>> 0;
  throw new ParseError('bad compressed integer', r.pos - 1);
}

export function readCompressedI(r: ByteReader): number {
  const b0 = r.bytes[r.pos] ?? 0;
  const u = readCompressedU(r);
  const bits = (b0 & 0x80) === 0 ? 7 : (b0 & 0xc0) === 0x80 ? 14 : 29;
  const neg = u & 1;
  let v = u >>> 1;
  if (neg) v -= 1 << (bits - 1);
  return v;
}

export function getBlob(meta: Metadata, idx: number): Uint8Array {
  if (idx >= meta.blob.length) return new Uint8Array(0);
  const r = new ByteReader(meta.blob, idx);
  try {
    const len = readCompressedU(r);
    return meta.blob.subarray(r.pos, Math.min(meta.blob.length, r.pos + len));
  } catch { return new Uint8Array(0); }
}

export function getUserString(meta: Metadata, idx: number): string | undefined {
  if (idx >= meta.us.length) return undefined;
  const r = new ByteReader(meta.us, idx);
  try {
    const len = readCompressedU(r);
    const b = meta.us.subarray(r.pos, Math.min(meta.us.length, r.pos + len));
    return utf16le(b.subarray(0, b.length & ~1));
  } catch { return undefined; }
}

/** Enumerate every user string in #US with its heap offset. */
export function listUserStrings(meta: Metadata, max = LIMITS.maxEntries): { offset: number; token: number; value: string }[] {
  const out: { offset: number; token: number; value: string }[] = [];
  const r = new ByteReader(meta.us, 1);
  while (r.pos < meta.us.length && out.length < max) {
    const at = r.pos;
    let len: number;
    try { len = readCompressedU(r); } catch { break; }
    if (len === 0) continue;
    if (r.pos + len > meta.us.length) break;
    const b = r.take(len);
    out.push({ offset: at, token: 0x70000000 | at, value: utf16le(b.subarray(0, b.length & ~1)) });
  }
  return out;
}

/** Enumerate #Strings heap entries. */
export function listStrings(meta: Metadata, max = LIMITS.maxEntries): { offset: number; value: string }[] {
  const out: { offset: number; value: string }[] = [];
  let i = 1;
  const s = meta.strings;
  while (i < s.length && out.length < max) {
    let e = i;
    while (e < s.length && s[e] !== 0) e++;
    if (e > i) out.push({ offset: i, value: utf8(s.subarray(i, e)) });
    i = e + 1;
  }
  return out;
}

export function decodeCoded(kind: string, value: number): { table: number; row: number } {
  const c = CODED[kind];
  if (!c) return { table: -1, row: 0 };
  const tag = value & ((1 << c.bits) - 1);
  return { table: c.tables[tag] ?? -1, row: value >>> c.bits };
}

export function rows(meta: Metadata, id: number): Row[] { return meta.tables.get(id)?.rows ?? []; }
export function row(meta: Metadata, id: number, rid: number): Row | undefined { return rid > 0 ? meta.tables.get(id)?.rows[rid - 1] : undefined; }
export function tokenOf(table: number, rid: number): number { return ((table << 24) | rid) >>> 0; }
