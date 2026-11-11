// Deep PE inspection beyond the core analyzer: resources, version info, manifest, rich header,
// debug directory (PDB), TLS callbacks, load config, exports, delay imports, overlay, checksum,
// installer detection, and Authenticode signatures with hash and signature verification.

import { View, ParseError, utf8, toHex, entropyOf, guid, startsWithBytes, indexOfBytes, ascii, unixTime } from '../util.js';
import { parsePe, vaToOffset, type BinImage } from '../bin/container.js';
import { derAt, children, content, raw, oid, intHex, time, parseCertificate, x509Name, ALG_OIDS, type Certificate, type Der } from '../asn1.js';
import { md5, sha1, sha256 } from '@revlens/core';

export const RT_TYPES: Record<number, string> = {
  1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR',
  10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE', 19: 'PLUGPLAY',
  20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST',
};

export interface PeHeaders {
  machine: string;
  bits: 32 | 64;
  timestamp: number;
  timestampIso: string | null;
  characteristics: number;
  subsystem: number;
  dllCharacteristics: number;
  imageBase: number;
  entryRva: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checksum: number;
  computedChecksum: number;
  checksumValid: boolean;
  linkerVersion: string;
  osVersion: string;
  dataDirectories: { index: number; name: string; rva: number; size: number }[];
}

const DIR_NAMES = ['export', 'import', 'resource', 'exception', 'security', 'basereloc', 'debug', 'architecture', 'globalptr', 'tls', 'load_config', 'bound_import', 'iat', 'delay_import', 'clr', 'reserved'];

interface Ctx { v: View; img: BinImage; optOff: number; is64: boolean; dirs: { rva: number; size: number }[] }

function ctx(bytes: Uint8Array): Ctx {
  const img = parsePe(bytes);
  const v = img.view;
  const pe = v.u32(0x3c);
  const optOff = pe + 24;
  const is64 = v.u16(optOff) === 0x20b;
  const nrva = Math.min(v.u32(optOff + (is64 ? 108 : 92)), 16);
  const dirStart = optOff + (is64 ? 112 : 96);
  const dirs: { rva: number; size: number }[] = [];
  for (let i = 0; i < nrva; i++) dirs.push({ rva: v.u32(dirStart + i * 8), size: v.u32(dirStart + i * 8 + 4) });
  return { v, img, optOff, is64, dirs };
}
function rvaOff(c: Ctx, rva: number): number { return vaToOffset(c.img, rva); }

/** PE checksum as computed by the Windows loader (CheckSumMappedFile). */
export function peChecksum(bytes: Uint8Array, checksumOffset: number): number {
  let sum = 0;
  const len = bytes.length;
  for (let i = 0; i < len; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) continue;
    const w = (bytes[i] as number) | ((i + 1 < len ? (bytes[i + 1] as number) : 0) << 8);
    sum += w;
    sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  }
  sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  return (sum + len) >>> 0;
}

export function peHeaders(bytes: Uint8Array): PeHeaders {
  const c = ctx(bytes);
  const { v, optOff, is64, img } = c;
  const pe = v.u32(0x3c);
  const ts = v.u32(pe + 8);
  const checksumOff = optOff + 64;
  const checksum = v.u32(checksumOff);
  const computed = peChecksum(bytes, checksumOff);
  return {
    machine: img.machine, bits: is64 ? 64 : 32, timestamp: ts, timestampIso: unixTime(ts),
    characteristics: v.u16(pe + 22), subsystem: v.u16(optOff + 68), dllCharacteristics: v.u16(optOff + 70),
    imageBase: img.imageBase, entryRva: v.u32(optOff + 16), sizeOfImage: v.u32(optOff + 56), sizeOfHeaders: v.u32(optOff + 60),
    checksum, computedChecksum: computed, checksumValid: checksum === computed,
    linkerVersion: `${v.u8(optOff + 2)}.${v.u8(optOff + 3)}`, osVersion: `${v.u16(optOff + 40)}.${v.u16(optOff + 42)}`,
    dataDirectories: c.dirs.map((d, i) => ({ index: i, name: DIR_NAMES[i] ?? String(i), rva: d.rva, size: d.size })).filter((d) => d.rva || d.size),
  };
}

// ---------------- rich header ----------------
export interface RichEntry { productId: number; build: number; count: number; product: string }
export interface RichHeader { offset: number; key: string; entries: RichEntry[]; hash: string; checksumValid: boolean }

function richProduct(id: number): string {
  if (id === 0) return 'Unmarked objects';
  if (id === 1) return 'Total imports';
  if (id >= 0x0104 && id <= 0x010e) return 'Visual Studio 2017-2022 (14.1x-14.3x)';
  if (id >= 0x00fd && id <= 0x0103) return 'Visual Studio 2015 (14.0)';
  if (id >= 0x00db && id <= 0x00fc) return 'Visual Studio 2013 (12.0)';
  if (id >= 0x00c7 && id <= 0x00da) return 'Visual Studio 2012 (11.0)';
  if (id >= 0x0098 && id <= 0x00c6) return 'Visual Studio 2010 (10.0)';
  if (id >= 0x0083 && id <= 0x0097) return 'Visual Studio 2008 (9.0)';
  if (id >= 0x006d && id <= 0x0082) return 'Visual Studio 2005 (8.0)';
  if (id >= 0x005a && id <= 0x006c) return 'Visual Studio .NET 2003 (7.1)';
  if (id >= 0x0019 && id <= 0x0059) return 'Visual Studio .NET 2002 (7.0) or earlier';
  return 'unknown';
}
const RICH_KIND: Record<number, string> = { 0x0102: 'Linker', 0x0103: 'CVTRES', 0x0104: 'C', 0x0105: 'C++', 0x0101: 'Export', 0x0100: 'Import', 0x00ff: 'MASM', 0x0106: 'AliasObj' };

export function richHeader(bytes: Uint8Array): RichHeader | null {
  const v = new View(bytes);
  const pe = v.u32(0x3c);
  const end = Math.min(pe, bytes.length);
  const rich = indexOfBytes(bytes, ascii('Rich'), 0x40, end);
  if (rich < 0 || !v.has(rich + 4, 4)) return null;
  const key = v.u32(rich + 4);
  let start = -1;
  for (let p = rich - 4; p >= 0x40; p -= 4) { if ((v.u32(p) ^ key) === 0x536e6144) { start = p; break; } }
  if (start < 0) return null;
  const entries: RichEntry[] = [];
  const clear: number[] = [];
  for (let p = start; p < rich; p += 4) { const w = (v.u32(p) ^ key) >>> 0; clear.push(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, w >>> 24); }
  for (let p = start + 16; p + 8 <= rich; p += 8) {
    const compid = (v.u32(p) ^ key) >>> 0;
    const count = (v.u32(p + 4) ^ key) >>> 0;
    const productId = compid >>> 16, build = compid & 0xffff;
    entries.push({ productId, build, count, product: `${RICH_KIND[productId] ? RICH_KIND[productId] + ', ' : ''}${richProduct(productId)}` });
  }
  let cs = start >>> 0;
  for (let i = 0; i < start; i++) {
    if (i >= 0x3c && i < 0x40) continue;
    const b = bytes[i] as number;
    const r = i % 32;
    cs = (cs + (((b << r) | (r ? b >>> (32 - r) : 0)) >>> 0)) >>> 0;
  }
  for (const e of entries) {
    const cid = ((e.productId << 16) | e.build) >>> 0;
    const r = e.count % 32;
    cs = (cs + (((cid << r) | (r ? cid >>> (32 - r) : 0)) >>> 0)) >>> 0;
  }
  return { offset: start, key: key.toString(16).padStart(8, '0'), entries, hash: md5(new Uint8Array(clear)), checksumValid: cs === key };
}

// ---------------- resources ----------------
export interface PeResource {
  type: string;
  typeId: number | null;
  name: string;
  lang: number;
  codepage: number;
  rva: number;
  offset: number;
  size: number;
  sha256: string;
  entropy: number;
  magic: string;
}

export function sniff(b: Uint8Array): string {
  const sigs: [number[], string][] = [
    [[0x4d, 0x5a], 'pe'], [[0x50, 0x4b, 0x03, 0x04], 'zip'], [[0x89, 0x50, 0x4e, 0x47], 'png'], [[0x1f, 0x8b], 'gzip'],
    [[0x37, 0x7a, 0xbc, 0xaf], '7z'], [[0x52, 0x61, 0x72, 0x21], 'rar'], [[0xd0, 0xcf, 0x11, 0xe0], 'ole'], [[0x3c, 0x3f, 0x78, 0x6d], 'xml'],
    [[0x7f, 0x45, 0x4c, 0x46], 'elf'], [[0x25, 0x50, 0x44, 0x46], 'pdf'], [[0xff, 0xd8, 0xff], 'jpeg'], [[0x47, 0x49, 0x46, 0x38], 'gif'],
    [[0x42, 0x5a, 0x68], 'bzip2'], [[0xfd, 0x37, 0x7a, 0x58, 0x5a], 'xz'], [[0x28, 0x00, 0x00, 0x00], 'bitmap-header'],
  ];
  for (const [s, n] of sigs) if (startsWithBytes(b, s)) return n;
  return '';
}

export function peResources(bytes: Uint8Array, opts: { limit?: number } = {}): PeResource[] {
  const c = ctx(bytes);
  const dir = c.dirs[2];
  if (!dir || !dir.rva) return [];
  const base = rvaOff(c, dir.rva);
  if (base < 0) return [];
  const v = c.v;
  const out: PeResource[] = [];
  const limit = opts.limit ?? 20000;
  const seen = new Set<number>();
  const nameAt = (off: number): string => { const n = v.u16(base + off); return v.utf16(base + off + 2, Math.min(n, 512)); };
  const walk = (dirOff: number, level: number, path: { id: number | null; name: string }[]): void => {
    if (level > 2 || seen.has(dirOff) || out.length >= limit) return;
    seen.add(dirOff);
    const d = base + dirOff;
    const n = Math.min(v.u16(d + 12) + v.u16(d + 14), 4096);
    for (let i = 0; i < n && out.length < limit; i++) {
      const e = d + 16 + i * 8;
      const nameField = v.u32(e);
      const dataField = v.u32(e + 4);
      const id = nameField & 0x80000000 ? null : nameField & 0xffff;
      const name = nameField & 0x80000000 ? nameAt(nameField & 0x7fffffff) : String(nameField & 0xffff);
      const np = [...path, { id, name }];
      if (dataField & 0x80000000) walk(dataField & 0x7fffffff, level + 1, np);
      else {
        const de = base + dataField;
        const rva = v.u32(de), size = v.u32(de + 4), codepage = v.u32(de + 8);
        const off = rvaOff(c, rva);
        const t = np[0] as { id: number | null; name: string };
        const ok = off >= 0 && v.has(off, size);
        const data = ok ? v.sub(off, size) : new Uint8Array(0);
        out.push({
          type: t.id !== null ? RT_TYPES[t.id] ?? String(t.id) : t.name, typeId: t.id,
          name: np[1]?.name ?? '', lang: np[2]?.id ?? 0, codepage, rva, offset: off, size,
          sha256: ok ? sha256(data) : '', entropy: ok ? Number(entropyOf(data).toFixed(3)) : 0, magic: ok ? sniff(data) : '',
        });
      }
    }
  };
  walk(0, 0, []);
  return out;
}

// ---------------- version info ----------------
export interface VersionInfo { fileVersion?: string; productVersion?: string; fileFlags?: number; fileOs?: number; strings: Record<string, string>; translations: string[] }

export function peVersionInfo(bytes: Uint8Array): VersionInfo | null {
  const r = peResources(bytes).find((x) => x.typeId === 16);
  if (!r || r.offset < 0) return null;
  const v = new View(bytes);
  const end = r.offset + r.size;
  const info: VersionInfo = { strings: {}, translations: [] };
  let budget = 4096;
  const block = (p: number, depth: number): number => {
    if (depth > 6 || !v.has(p, 6) || --budget < 0) return end;
    const len = v.u16(p), valLen = v.u16(p + 2), type = v.u16(p + 4);
    if (len < 6) return end;
    const key = v.utf16z(p + 6, 64);
    let q = p + 6 + (key.length + 1) * 2;
    q = (q + 3) & ~3;
    const blockEnd = Math.min(p + len, end);
    if (key === 'VS_VERSION_INFO' && valLen >= 52 && v.u32(q) === 0xfeef04bd) {
      const fms = v.u32(q + 8), fls = v.u32(q + 12), pms = v.u32(q + 16), pls = v.u32(q + 20);
      info.fileVersion = `${fms >>> 16}.${fms & 0xffff}.${fls >>> 16}.${fls & 0xffff}`;
      info.productVersion = `${pms >>> 16}.${pms & 0xffff}.${pls >>> 16}.${pls & 0xffff}`;
      info.fileFlags = v.u32(q + 28);
      info.fileOs = v.u32(q + 32);
    }
    let valueEnd = q + (type === 1 ? valLen * 2 : valLen);
    if (depth >= 3 && type === 1) info.strings[key] = v.utf16z(q, Math.max(0, valLen));
    if (key === 'Translation' && valLen >= 4) {
      for (let i = 0; i + 4 <= valLen; i += 4) info.translations.push(`${v.u16(q + i).toString(16).padStart(4, '0')}${v.u16(q + i + 2).toString(16).padStart(4, '0')}`);
    }
    valueEnd = (valueEnd + 3) & ~3;
    let c = depth >= 3 ? blockEnd : valueEnd;
    while (c + 6 <= blockEnd) {
      const next = block(c, depth + 1);
      if (next <= c) break;
      c = (next + 3) & ~3;
    }
    return p + len;
  };
  block(r.offset, 0);
  return info;
}

// ---------------- manifest ----------------
export interface ManifestInfo {
  xml: string;
  requestedExecutionLevel?: string;
  uiAccess?: string;
  dpiAware?: string;
  dpiAwareness?: string;
  longPathAware?: string;
  assemblyIdentity?: Record<string, string>;
  supportedOS: { id: string; name: string }[];
  dependencies: string[];
}
const OS_GUIDS: Record<string, string> = {
  '{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}': 'Windows 10 and 11', '{1f676c76-80e1-4239-95bb-83d0f6d0da78}': 'Windows 8.1',
  '{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}': 'Windows 8', '{35138b9a-5d96-4fbd-8e2d-a2440225f93a}': 'Windows 7', '{e2011457-1546-43c5-a5fe-008deee3d3f0}': 'Windows Vista',
};
function attr(tag: string, name: string): string | undefined {
  const m = new RegExp(`\\b${name}\\s*=\\s*["']([^"']{0,512})["']`).exec(tag);
  return m?.[1];
}
export function parseManifest(xml: string): ManifestInfo {
  const out: ManifestInfo = { xml: xml.slice(0, 65536), supportedOS: [], dependencies: [] };
  const x = xml.slice(0, 1 << 20);
  const rel = /<(?:\w+:)?requestedExecutionLevel\b[^>]{0,1024}>/.exec(x);
  if (rel) { out.requestedExecutionLevel = attr(rel[0], 'level'); out.uiAccess = attr(rel[0], 'uiAccess'); }
  const tagText = (t: string): string | undefined => { const m = new RegExp(`<(?:\\w+:)?${t}\\b[^>]{0,256}>([^<]{0,256})<`).exec(x); return m?.[1]?.trim(); };
  out.dpiAware = tagText('dpiAware');
  out.dpiAwareness = tagText('dpiAwareness');
  out.longPathAware = tagText('longPathAware');
  const ai = /<(?:\w+:)?assemblyIdentity\b[^>]{0,1024}>/.exec(x);
  if (ai) {
    const rec: Record<string, string> = {};
    for (const k of ['name', 'version', 'type', 'processorArchitecture', 'publicKeyToken', 'language']) { const v = attr(ai[0], k); if (v) rec[k] = v; }
    out.assemblyIdentity = rec;
  }
  for (const m of x.matchAll(/<(?:\w+:)?supportedOS\b[^>]{0,256}>/g)) {
    const id = (attr(m[0], 'Id') ?? '').toLowerCase();
    out.supportedOS.push({ id, name: OS_GUIDS[id] ?? 'unknown' });
    if (out.supportedOS.length > 32) break;
  }
  for (const m of x.matchAll(/<(?:\w+:)?dependentAssembly\b[^>]{0,256}>\s{0,256}<(?:\w+:)?assemblyIdentity\b([^>]{0,1024})>/g)) {
    const n = attr(m[1] ?? '', 'name');
    if (n) out.dependencies.push(`${n}${attr(m[1] ?? '', 'version') ? ' ' + attr(m[1] ?? '', 'version') : ''}`);
    if (out.dependencies.length > 64) break;
  }
  return out;
}
export function peManifest(bytes: Uint8Array): ManifestInfo | null {
  const r = peResources(bytes).find((x) => x.typeId === 24);
  if (!r || r.offset < 0) return null;
  const text = utf8(bytes.subarray(r.offset, r.offset + Math.min(r.size, 1 << 20))).replace(/^\uFEFF/, '');
  return parseManifest(text);
}

// ---------------- string tables ----------------
export function peStringTable(bytes: Uint8Array, limit = 5000): { id: number; lang: number; value: string }[] {
  const out: { id: number; lang: number; value: string }[] = [];
  const v = new View(bytes);
  for (const r of peResources(bytes)) {
    if (r.typeId !== 6 || r.offset < 0) continue;
    const blockId = Number(r.name);
    let p = r.offset;
    for (let i = 0; i < 16 && p + 2 <= r.offset + r.size; i++) {
      const n = v.u16(p);
      const s = n ? v.utf16(p + 2, Math.min(n, 8192)) : '';
      if (s) out.push({ id: (blockId - 1) * 16 + i, lang: r.lang, value: s });
      p += 2 + n * 2;
      if (out.length >= limit) return out;
    }
  }
  return out;
}

// ---------------- debug directory ----------------
const DEBUG_TYPES: Record<number, string> = { 1: 'COFF', 2: 'CODEVIEW', 3: 'FPO', 4: 'MISC', 5: 'EXCEPTION', 6: 'FIXUP', 9: 'BORLAND', 10: 'RESERVED10', 11: 'CLSID', 12: 'VC_FEATURE', 13: 'POGO', 14: 'ILTCG', 15: 'MPX', 16: 'REPRO', 17: 'EMBEDDED_PDB', 19: 'PDBCHECKSUM', 20: 'EX_DLLCHARACTERISTICS' };
export interface DebugEntry { type: string; typeId: number; timestamp: number; size: number; rva: number; offset: number; pdb?: { path: string; guid: string; age: number; symbolServerId: string }; exDllCharacteristics?: number; features?: string[] }

export function peDebug(bytes: Uint8Array): DebugEntry[] {
  const c = ctx(bytes);
  const d = c.dirs[6];
  if (!d || !d.rva) return [];
  const off = rvaOff(c, d.rva);
  if (off < 0) return [];
  const v = c.v;
  const out: DebugEntry[] = [];
  for (let i = 0; i < Math.min(Math.floor(d.size / 28), 64); i++) {
    const e = off + i * 28;
    if (!v.has(e, 28)) break;
    const typeId = v.u32(e + 12);
    const size = v.u32(e + 16), rva = v.u32(e + 20), ptr = v.u32(e + 24);
    const entry: DebugEntry = { type: DEBUG_TYPES[typeId] ?? String(typeId), typeId, timestamp: v.u32(e + 4), size, rva, offset: ptr };
    if (typeId === 2 && v.has(ptr, 24) && v.u32(ptr) === 0x53445352) {
      const g = guid(bytes, ptr + 4);
      const age = v.u32(ptr + 20);
      const path = v.utf8z(ptr + 24, Math.min(Math.max(size - 24, 1), 1024));
      entry.pdb = { path, guid: g, age, symbolServerId: g.replace(/-/g, '') + age.toString(16).toUpperCase() };
    }
    if (typeId === 20 && v.has(ptr, 4)) {
      const f = v.u32(ptr);
      entry.exDllCharacteristics = f;
      entry.features = [];
      if (f & 1) entry.features.push('CET_COMPAT');
      if (f & 2) entry.features.push('CET_COMPAT_STRICT_MODE');
      if (f & 0x40) entry.features.push('FORWARD_CFI_COMPAT');
    }
    out.push(entry);
  }
  return out;
}

// ---------------- TLS and load config ----------------
export function peTls(bytes: Uint8Array): { callbacks: number[]; startAddressOfRawData: number; endAddressOfRawData: number } | null {
  const c = ctx(bytes);
  const d = c.dirs[9];
  if (!d || !d.rva) return null;
  const off = rvaOff(c, d.rva);
  if (off < 0) return null;
  const ps = c.is64 ? 8 : 4;
  const v = c.v;
  const start = v.uN(off, ps), end = v.uN(off + ps, ps), cbVa = v.uN(off + 3 * ps, ps);
  const callbacks: number[] = [];
  if (cbVa) {
    let p = vaToOffset(c.img, cbVa);
    for (let i = 0; p >= 0 && i < 256; i++, p += ps) {
      if (!v.has(p, ps)) break;
      const cb = v.uN(p, ps);
      if (!cb) break;
      callbacks.push(cb);
    }
  }
  return { callbacks, startAddressOfRawData: start, endAddressOfRawData: end };
}

export interface LoadConfig { size: number; securityCookie: number; seHandlerCount?: number; guardFlags?: number; guardFlagNames: string[]; guardCFFunctionCount?: number; cfgEnabled: boolean }
const GUARD_FLAGS: [number, string][] = [
  [0x100, 'CF_INSTRUMENTED'], [0x200, 'CFW_INSTRUMENTED'], [0x400, 'CF_FUNCTION_TABLE_PRESENT'], [0x800, 'SECURITY_COOKIE_UNUSED'],
  [0x1000, 'PROTECT_DELAYLOAD_IAT'], [0x2000, 'DELAYLOAD_IAT_IN_ITS_OWN_SECTION'], [0x4000, 'CF_EXPORT_SUPPRESSION_INFO_PRESENT'],
  [0x8000, 'CF_ENABLE_EXPORT_SUPPRESSION'], [0x10000, 'CF_LONGJUMP_TABLE_PRESENT'], [0x100000, 'RF_INSTRUMENTED'],
  [0x200000, 'RF_ENABLE'], [0x400000, 'RF_STRICT'], [0x800000, 'RETPOLINE_PRESENT'], [0x4000000, 'EH_CONTINUATION_TABLE_PRESENT'],
  [0x8000000, 'XFG_ENABLED'], [0x10000000, 'CASTGUARD_PRESENT'], [0x20000000, 'MEMCPY_PRESENT'],
];
export function peLoadConfig(bytes: Uint8Array): LoadConfig | null {
  const c = ctx(bytes);
  const d = c.dirs[10];
  if (!d || !d.rva) return null;
  const off = rvaOff(c, d.rva);
  if (off < 0) return null;
  const v = c.v;
  const size = v.u32(off);
  const ps = c.is64 ? 8 : 4;
  const cookieOff = c.is64 ? 0x58 : 0x3c;
  const r: LoadConfig = { size, securityCookie: size > cookieOff ? v.uN(off + cookieOff, ps) : 0, guardFlagNames: [], cfgEnabled: false };
  if (!c.is64 && size > 0x44) r.seHandlerCount = v.u32(off + 0x44);
  const gfOff = c.is64 ? 0x90 : 0x58;
  const gcountOff = c.is64 ? 0x80 : 0x50;
  if (size >= gfOff + 4) {
    const gf = v.u32(off + gfOff);
    r.guardFlags = gf;
    r.guardFlagNames = GUARD_FLAGS.filter(([b]) => gf & b).map(([, n]) => n);
    r.guardCFFunctionCount = v.uN(off + gcountOff, ps);
    r.cfgEnabled = (gf & 0x100) !== 0;
  }
  return r;
}

// ---------------- exports / delay imports ----------------
export interface PeExports { dllName: string; ordinalBase: number; timestamp: number; functions: { ordinal: number; rva: number; name?: string; forwarder?: string }[] }
export function peExports(bytes: Uint8Array, limit = 50000): PeExports | null {
  const c = ctx(bytes);
  const d = c.dirs[0];
  if (!d || !d.rva) return null;
  const off = rvaOff(c, d.rva);
  if (off < 0) return null;
  const v = c.v;
  const nameRva = v.u32(off + 12), base = v.u32(off + 16), nfun = Math.min(v.u32(off + 20), limit), nnames = Math.min(v.u32(off + 24), limit);
  const aFun = rvaOff(c, v.u32(off + 28)), aNames = rvaOff(c, v.u32(off + 32)), aOrd = rvaOff(c, v.u32(off + 36));
  const names = new Map<number, string>();
  for (let i = 0; i < nnames && aNames >= 0 && aOrd >= 0; i++) {
    const no = rvaOff(c, v.u32(aNames + i * 4));
    if (no >= 0) names.set(v.u16(aOrd + i * 2), v.cstr(no, 1024));
  }
  const functions: PeExports['functions'] = [];
  for (let i = 0; i < nfun && aFun >= 0; i++) {
    const rva = v.u32(aFun + i * 4);
    if (!rva) continue;
    const f: PeExports['functions'][number] = { ordinal: base + i, rva };
    const n = names.get(i);
    if (n) f.name = n;
    if (rva >= d.rva && rva < d.rva + d.size) { const fo = rvaOff(c, rva); if (fo >= 0) f.forwarder = v.cstr(fo, 512); }
    functions.push(f);
  }
  const no = rvaOff(c, nameRva);
  return { dllName: no >= 0 ? v.cstr(no, 512) : '', ordinalBase: base, timestamp: v.u32(off + 4), functions };
}

export function peDelayImports(bytes: Uint8Array): { dll: string; functions: string[] }[] {
  const c = ctx(bytes);
  const d = c.dirs[13];
  if (!d || !d.rva) return [];
  let off = rvaOff(c, d.rva);
  const v = c.v;
  const out: { dll: string; functions: string[] }[] = [];
  const ps = c.is64 ? 8 : 4;
  for (let n = 0; off >= 0 && v.has(off, 32) && n < 512; n++, off += 32) {
    const attrs = v.u32(off), nameRva = v.u32(off + 4), intRva = v.u32(off + 16);
    if (!nameRva) break;
    const toOff = (x: number): number => rvaOff(c, attrs & 1 ? x : x - c.img.imageBase);
    const no = toOff(nameRva);
    const dll = no >= 0 ? v.cstr(no, 256) : '';
    const fns: string[] = [];
    let p = toOff(intRva);
    for (let i = 0; p >= 0 && i < 4096 && v.has(p, ps); i++, p += ps) {
      const e = v.uN(p, ps);
      if (!e) break;
      const ordFlag = c.is64 ? e >= 2 ** 63 : (e & 0x80000000) !== 0;
      if (ordFlag) { fns.push(`ord${e & 0xffff}`); continue; }
      const ho = toOff(e);
      if (ho >= 0) fns.push(v.cstr(ho + 2, 512));
    }
    out.push({ dll, functions: fns });
  }
  return out;
}

// ---------------- overlay and installers ----------------
export interface Overlay { offset: number; size: number; entropy: number; magic: string; sha256: string }
export function peOverlay(bytes: Uint8Array): Overlay | null {
  const c = ctx(bytes);
  let end = 0;
  for (const s of c.img.sections) end = Math.max(end, s.offset + s.size);
  const cert = c.dirs[4];
  let tail = bytes.length;
  if (cert && cert.rva && cert.rva + cert.size === bytes.length && cert.rva >= end) tail = cert.rva;
  if (end >= tail) return null;
  const data = bytes.subarray(end, tail);
  return { offset: end, size: data.length, entropy: Number(entropyOf(data).toFixed(3)), magic: sniff(data), sha256: sha256(data) };
}

export interface InstallerInfo { kind: string; evidence: { offset: number; snippet: string }[]; details: Record<string, string | number> }
export function detectInstaller(bytes: Uint8Array): InstallerInfo[] {
  const out: InstallerInfo[] = [];
  const find = (s: string, from = 0): number => indexOfBytes(bytes, ascii(s), from);
  const add = (kind: string, off: number, snippet: string, details: Record<string, string | number> = {}): void => { out.push({ kind, evidence: [{ offset: off, snippet }], details }); };
  let o: number;
  if ((o = find('NullsoftInst')) >= 0) {
    const v = new View(bytes);
    const details: Record<string, string | number> = {};
    if (o >= 8 && v.has(o - 8, 28)) { details.flags = v.u32(o - 8); details.headerSize = v.u32(o + 12); details.archiveSize = v.u32(o + 16); }
    add('NSIS', o, 'NullsoftInst', details);
  }
  if ((o = find('Inno Setup Setup Data (')) >= 0) {
    const end = bytes.indexOf(0x29, o + 23);
    const ver = end > 0 && end - o < 80 ? utf8(bytes.subarray(o + 23, end)) : '';
    add('Inno Setup', o, 'Inno Setup Setup Data', { version: ver });
  } else if ((o = find('rDlPtS')) >= 0) add('Inno Setup', o, 'rDlPtS loader signature');
  if ((o = find('.wixburn')) >= 0) add('WiX Burn bundle', o, '.wixburn');
  if ((o = find('InstallShield')) >= 0) add('InstallShield', o, 'InstallShield');
  if ((o = find('AU3!EA06')) >= 0 || (o = find('AU3!EA05')) >= 0) add('AutoIt compiled script', o, 'AU3!EA0x');
  if ((o = indexOfBytes(bytes, new Uint8Array([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]))) >= 0) add('PyInstaller', o, 'MEI cookie');
  if ((o = find('Smart Install Maker')) >= 0) add('Smart Install Maker', o, 'Smart Install Maker');
  if ((o = find('WiseMain')) >= 0) add('Wise Installer', o, 'WiseMain');
  if ((o = find('Setup Factory')) >= 0) add('Setup Factory', o, 'Setup Factory');
  if ((o = find('SquirrelTemp')) >= 0 || (o = find('Squirrel.Windows')) >= 0) add('Squirrel (Electron)', o, 'Squirrel');
  let ov: Overlay | null = null;
  try { ov = peOverlay(bytes); } catch { ov = null; }
  if (ov) {
    if (ov.magic === '7z') add('7-Zip SFX', ov.offset, '7z signature in overlay');
    if (ov.magic === 'rar') add('WinRAR SFX', ov.offset, 'Rar! signature in overlay');
    if (ov.magic === 'zip') add('ZIP SFX', ov.offset, 'PK signature in overlay');
    if (ov.magic === 'ole') add('MSI or OLE payload', ov.offset, 'compound file in overlay');
  }
  return out;
}

// ---------------- Authenticode ----------------
export interface AuthenticodeSignature {
  offset: number;
  length: number;
  revision: number;
  certificateType: number;
  digestAlgorithm: string;
  signedDigest: string;
  computedDigest: string;
  digestMatches: boolean;
  /** true when the signer's signature over the authenticated attributes verifies with its certificate */
  signatureVerified: boolean | null;
  messageDigestMatches: boolean | null;
  signer: { issuer: string; serial: string; certificate?: Certificate };
  signingTime: string | null;
  programName?: string;
  moreInfo?: string;
  timestamped: boolean;
  nested: number;
  certificates: Certificate[];
  warnings: string[];
}

const SUBTLE_HASH: Record<string, string> = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
async function digest(alg: string, parts: Uint8Array[]): Promise<string> {
  if (alg === 'sha1' || alg === 'sha256' || alg === 'md5') {
    let total = 0;
    for (const p of parts) total += p.length;
    const all = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { all.set(p, o); o += p.length; }
    return alg === 'sha1' ? sha1(all) : alg === 'sha256' ? sha256(all) : md5(all);
  }
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || !SUBTLE_HASH[alg]) throw new ParseError(`hash ${alg} not available`);
  const blob = new Blob(parts as BlobPart[]);
  return toHex(new Uint8Array(await subtle.digest(SUBTLE_HASH[alg] as string, await blob.arrayBuffer())));
}

/** Authenticode digest of a PE file: everything except the checksum, the security directory entry and the certificate table. */
export async function authenticodeDigest(bytes: Uint8Array, alg = 'sha256'): Promise<string> {
  const c = ctx(bytes);
  const checksumOff = c.optOff + 64;
  const secDirOff = c.optOff + (c.is64 ? 112 : 96) + 4 * 8;
  const cert = c.dirs[4] ?? { rva: 0, size: 0 };
  const certStart = cert.rva && cert.rva <= bytes.length ? cert.rva : bytes.length;
  const certEnd = Math.min(bytes.length, cert.rva + cert.size);
  const parts = [bytes.subarray(0, checksumOff), bytes.subarray(checksumOff + 4, secDirOff), bytes.subarray(secDirOff + 8, certStart)];
  if (cert.rva && certEnd < bytes.length) parts.push(bytes.subarray(certEnd));
  return digest(alg, parts);
}

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6';
const OID_RFC3161 = '1.3.6.1.4.1.311.3.3.1';
const OID_NESTED = '1.3.6.1.4.1.311.2.4.1';
const OID_OPUS = '1.3.6.1.4.1.311.2.1.12';

async function verifySigner(cert: Certificate | undefined, digestAlg: string, signedAttrs: Uint8Array | null, signature: Uint8Array): Promise<boolean | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || !cert?.spki || !signedAttrs) return null;
  const hash = SUBTLE_HASH[digestAlg];
  if (!hash) return null;
  try {
    if (cert.publicKeyAlgorithm === 'rsaEncryption') {
      const key = await subtle.importKey('spki', cert.spki as BufferSource, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
      return await subtle.verify('RSASSA-PKCS1-v1_5', key, signature as BufferSource, signedAttrs as BufferSource);
    }
    return null;
  } catch {
    return null;
  }
}

const first = (d: Der | undefined): Der | undefined => (d ? children(d)[0] : undefined);
const algName = (d: Der | undefined): string => { const o = first(d); return o ? ALG_OIDS[oid(o)] ?? oid(o) : 'unknown'; };

async function parseSignedData(ci: Der, fileBytes: Uint8Array | null, depth: number, sigs: AuthenticodeSignature[], base: { offset: number; length: number; revision: number; type: number }): Promise<void> {
  if (depth > 4) return;
  const [ctype, explicit] = children(ci);
  if (!ctype || oid(ctype) !== OID_SIGNED_DATA || !explicit) throw new ParseError('not a PKCS#7 SignedData', ci.start);
  const sd = first(explicit);
  if (!sd) throw new ParseError('empty SignedData', ci.start);
  const parts = children(sd);
  const contentInfo = parts[2];
  if (!contentInfo) throw new ParseError('no content in SignedData', sd.start);
  const warnings: string[] = [];
  const spc = first(children(contentInfo)[1]);
  let digestAlgorithm = 'unknown', signedDigest = '';
  if (spc) {
    const di = children(spc)[1];
    if (di) {
      const [alg, dg] = children(di);
      digestAlgorithm = algName(alg);
      if (dg) signedDigest = toHex(content(dg));
    }
  }
  const certificates: Certificate[] = [];
  let signerInfos: Der | undefined;
  for (const p of parts.slice(3)) {
    if (p.cls === 2 && p.tag === 0) { for (const cd of children(p)) { try { certificates.push(parseCertificate(cd)); } catch { warnings.push('unreadable certificate'); } } }
    else if (p.cls === 0 && p.tag === 0x11) signerInfos = p;
  }
  const si = first(signerInfos);
  let issuer = '', serial = '', signingTime: string | null = null, programName: string | undefined, moreInfo: string | undefined;
  let timestamped = false, nested = 0, signatureVerified: boolean | null = null, messageDigestMatches: boolean | null = null;
  let signerCert: Certificate | undefined;
  const nestedSigs: AuthenticodeSignature[] = [];
  if (si) {
    const sp = children(si);
    const ias = sp[1];
    if (ias) { const [iss, ser] = children(ias); if (iss) issuer = x509Name(iss).dn; if (ser) serial = intHex(ser); }
    signerCert = certificates.find((c) => c.serial === serial && c.issuer === issuer) ?? certificates.find((c) => c.serial === serial);
    let idx = 3;
    let authAttrs: Der | undefined;
    const maybe = sp[idx];
    if (maybe && maybe.cls === 2 && maybe.tag === 0) { authAttrs = maybe; idx++; }
    const encDigest = sp[idx + 1];
    const unauth = sp[idx + 2];
    let messageDigest = '';
    if (authAttrs) {
      for (const a of children(authAttrs)) {
        const [ao, vals] = children(a);
        if (!ao || !vals) continue;
        const o = oid(ao);
        const f = first(vals);
        if (o === OID_MESSAGE_DIGEST && f) messageDigest = toHex(content(f));
        if (o === OID_SIGNING_TIME && f) signingTime = time(f);
        if (o === OID_OPUS && f) {
          for (const fld of children(f)) {
            if (fld.cls !== 2) continue;
            const inner = fld.constructed ? first(fld) : undefined;
            if (fld.tag === 0 && inner) programName = inner.tag === 0 && inner.cls === 2 ? new TextDecoder('utf-16be').decode(content(inner)) : new TextDecoder().decode(content(inner));
            if (fld.tag === 1 && inner) moreInfo = new TextDecoder().decode(content(inner));
          }
        }
      }
      const attrBytes = raw(authAttrs).slice();
      attrBytes[0] = 0x31; // signature covers the attributes encoded as a SET
      if (spc && messageDigest) {
        try { messageDigestMatches = (await digest(digestAlgorithm, [spc.bytes.subarray(spc.hdr, spc.end)])) === messageDigest; } catch { messageDigestMatches = null; }
      }
      if (encDigest) signatureVerified = await verifySigner(signerCert, digestAlgorithm, attrBytes, content(encDigest));
    }
    if (unauth && unauth.cls === 2) {
      for (const a of children(unauth)) {
        const [ao, vals] = children(a);
        if (!ao || !vals) continue;
        const o = oid(ao);
        if (o === OID_COUNTER_SIGNATURE || o === OID_RFC3161) timestamped = true;
        if (o === OID_NESTED) {
          for (const nci of children(vals)) { nested++; try { await parseSignedData(nci, fileBytes, depth + 1, nestedSigs, base); } catch { warnings.push('unreadable nested signature'); } }
        }
      }
    }
  }
  let computedDigest = '';
  if (fileBytes && (SUBTLE_HASH[digestAlgorithm] !== undefined || digestAlgorithm === 'md5')) {
    try { computedDigest = await authenticodeDigest(fileBytes, digestAlgorithm); } catch (e) { warnings.push(`digest not computed: ${(e as Error).message}`); }
  }
  sigs.push({
    offset: base.offset, length: base.length, revision: base.revision, certificateType: base.type,
    digestAlgorithm, signedDigest, computedDigest, digestMatches: !!computedDigest && computedDigest === signedDigest,
    signatureVerified, messageDigestMatches,
    signer: { issuer, serial, ...(signerCert ? { certificate: signerCert } : {}) },
    signingTime, ...(programName ? { programName } : {}), ...(moreInfo ? { moreInfo } : {}),
    timestamped, nested, certificates, warnings,
  });
  sigs.push(...nestedSigs);
}

/** Parse and check every Authenticode signature in a PE file. */
export async function peAuthenticode(bytes: Uint8Array): Promise<AuthenticodeSignature[]> {
  const c = ctx(bytes);
  const d = c.dirs[4];
  if (!d || !d.rva || !d.size) return [];
  const v = c.v;
  const out: AuthenticodeSignature[] = [];
  let p = d.rva;
  const end = Math.min(bytes.length, d.rva + d.size);
  for (let n = 0; p + 8 <= end && n < 16; n++) {
    const len = v.u32(p), rev = v.u16(p + 4), type = v.u16(p + 6);
    if (len < 8 || p + len > end) break;
    if (type === 2) {
      try {
        const ci = derAt(bytes, p + 8, p + len);
        await parseSignedData(ci, bytes, 0, out, { offset: p, length: len, revision: rev, type });
      } catch (e) {
        out.push({ offset: p, length: len, revision: rev, certificateType: type, digestAlgorithm: 'unknown', signedDigest: '', computedDigest: '', digestMatches: false, signatureVerified: null, messageDigestMatches: null, signer: { issuer: '', serial: '' }, signingTime: null, timestamped: false, nested: 0, certificates: [], warnings: [`unparsable PKCS#7: ${(e as Error).message}`] });
      }
    }
    p += (len + 7) & ~7;
  }
  return out;
}

/** Everything in one call, for the analyzer and the x_pe_inspect tool. */
export async function inspectPe(bytes: Uint8Array): Promise<Record<string, unknown>> {
  const safe = <T>(f: () => T): T | null => { try { return f(); } catch { return null; } };
  const res = safe(() => peResources(bytes)) ?? [];
  return {
    headers: safe(() => peHeaders(bytes)),
    richHeader: safe(() => richHeader(bytes)),
    resources: { count: res.length, items: res.slice(0, 500) },
    versionInfo: safe(() => peVersionInfo(bytes)),
    manifest: safe(() => { const m = peManifest(bytes); return m ? { ...m, xml: m.xml.slice(0, 4096) } : null; }),
    debug: safe(() => peDebug(bytes)),
    tls: safe(() => peTls(bytes)),
    loadConfig: safe(() => peLoadConfig(bytes)),
    exports: safe(() => { const e = peExports(bytes); return e ? { ...e, count: e.functions.length, functions: e.functions.slice(0, 500) } : null; }),
    delayImports: safe(() => peDelayImports(bytes)),
    overlay: safe(() => peOverlay(bytes)),
    installers: safe(() => detectInstaller(bytes)),
    authenticode: await peAuthenticode(bytes).catch((e: Error) => ({ error: e.message })),
  };
}
