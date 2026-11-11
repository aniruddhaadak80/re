// Mach-O extras: load command inventory, build and minimum OS versions, UUID, linked dylibs
// with @rpath/@loader_path resolution, encryption info, symbols, and code signatures
// (CodeDirectory, cdhash, page hash verification, entitlements, requirements, CMS signer).

import { View, toHex, ParseError, utf8 } from '../util.js';
import { machoSlices } from '../bin/container.js';
import { derAt, children, x509Name, intHex, parseCertificate, type Certificate } from '../asn1.js';
import { sha1, sha256 } from '@revlens/core';

const LC: Record<number, string> = {
  0x1: 'LC_SEGMENT', 0x2: 'LC_SYMTAB', 0x5: 'LC_UNIXTHREAD', 0xb: 'LC_DYSYMTAB', 0xc: 'LC_LOAD_DYLIB', 0xd: 'LC_ID_DYLIB', 0xe: 'LC_LOAD_DYLINKER',
  0xf: 'LC_ID_DYLINKER', 0x19: 'LC_SEGMENT_64', 0x1b: 'LC_UUID', 0x1d: 'LC_CODE_SIGNATURE', 0x1e: 'LC_SEGMENT_SPLIT_INFO',
  0x21: 'LC_ENCRYPTION_INFO', 0x22: 'LC_DYLD_INFO', 0x80000022: 'LC_DYLD_INFO_ONLY', 0x80000018: 'LC_LOAD_WEAK_DYLIB',
  0x8000001c: 'LC_RPATH', 0x8000001f: 'LC_REEXPORT_DYLIB', 0x80000023: 'LC_LOAD_UPWARD_DYLIB', 0x24: 'LC_VERSION_MIN_MACOSX',
  0x25: 'LC_VERSION_MIN_IPHONEOS', 0x26: 'LC_FUNCTION_STARTS', 0x29: 'LC_DATA_IN_CODE', 0x2a: 'LC_SOURCE_VERSION',
  0x2b: 'LC_DYLIB_CODE_SIGN_DRS', 0x2c: 'LC_ENCRYPTION_INFO_64', 0x2f: 'LC_VERSION_MIN_TVOS', 0x30: 'LC_VERSION_MIN_WATCHOS',
  0x31: 'LC_NOTE', 0x32: 'LC_BUILD_VERSION', 0x80000028: 'LC_MAIN', 0x80000033: 'LC_DYLD_EXPORTS_TRIE', 0x80000034: 'LC_DYLD_CHAINED_FIXUPS',
  0x35: 'LC_FILESET_ENTRY', 0x36: 'LC_ATOM_INFO', 0x2e: 'LC_LINKER_OPTIMIZATION_HINT', 0x2d: 'LC_LINKER_OPTION',
};
const PLATFORMS: Record<number, string> = { 1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 10: 'DriverKit', 11: 'visionOS', 12: 'visionOS Simulator' };
const TOOLS: Record<number, string> = { 1: 'clang', 2: 'swift', 3: 'ld', 4: 'lld' };

function ver(x: number): string { return `${x >>> 16}.${(x >>> 8) & 0xff}.${x & 0xff}`; }

export interface MachoInfo {
  arch: string;
  sliceOffset: number;
  fileType: number;
  flags: number;
  flagNames: string[];
  loadCommands: { cmd: string; offset: number; size: number }[];
  uuid?: string;
  build?: { platform: string; minos: string; sdk: string; tools: string[] };
  minVersion?: { kind: string; version: string; sdk: string };
  sourceVersion?: string;
  dylinker?: string;
  idDylib?: string;
  dylibs: { name: string; kind: string; currentVersion: string; compatVersion: string; resolved: string[] }[];
  rpaths: string[];
  encryption?: { cryptid: number; offset: number; size: number };
  codeSignature?: { offset: number; size: number };
  entry?: number;
}

const MH_FLAGS: [number, string][] = [
  [0x1, 'NOUNDEFS'], [0x4, 'DYLDLINK'], [0x80, 'TWOLEVEL'], [0x200000, 'PIE'], [0x1000000, 'NO_HEAP_EXECUTION'],
  [0x20000, 'ALLOW_STACK_EXECUTION'], [0x800000, 'HAS_TLV_DESCRIPTORS'], [0x2000000, 'APP_EXTENSION_SAFE'], [0x80000000, 'DYLIB_IN_CACHE'],
];

function slice(bytes: Uint8Array, arch?: string): { v: View; base: number; is64: boolean; arch: string } {
  const slices = machoSlices(bytes);
  const s = arch ? slices.find((x) => x.arch === arch) : slices[0];
  if (!s) throw new ParseError(`no slice ${arch ?? ''}`);
  const bv = new View(bytes, false);
  const m = bv.u32(s.offset);
  if (![0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(m)) throw new ParseError('not a Mach-O image', s.offset);
  const le = m === 0xcefaedfe || m === 0xcffaedfe;
  return { v: new View(bytes, le), base: s.offset, is64: m === 0xfeedfacf || m === 0xcffaedfe, arch: s.arch };
}

export function machoInfo(bytes: Uint8Array, arch?: string): MachoInfo {
  const { v, base, is64, arch: a } = slice(bytes, arch);
  const ncmds = Math.min(v.u32(base + 16), 4096);
  const flags = v.u32(base + 24);
  const info: MachoInfo = {
    arch: a, sliceOffset: base, fileType: v.u32(base + 12), flags, flagNames: MH_FLAGS.filter(([b]) => flags & b).map(([, n]) => n),
    loadCommands: [], dylibs: [], rpaths: [],
  };
  let p = base + (is64 ? 32 : 28);
  let textVm = 0;
  for (let i = 0; i < ncmds; i++) {
    if (!v.has(p, 8)) break;
    const cmd = v.u32(p), size = v.u32(p + 4);
    if (size < 8 || !v.has(p, size)) break;
    info.loadCommands.push({ cmd: LC[cmd] ?? `0x${cmd.toString(16)}`, offset: p, size });
    const lstr = (o: number): string => v.utf8z(p + v.u32(p + o), Math.max(1, size - v.u32(p + o)));
    switch (cmd) {
      case 0x19: case 0x1: if (v.cstr(p + 8, 16) === '__TEXT') textVm = cmd === 0x19 ? v.u64n(p + 24) : v.u32(p + 24); break;
      case 0x1b: info.uuid = toHex(v.sub(p + 8, 16)).toUpperCase().replace(/^(.{8})(.{4})(.{4})(.{4})/, '$1-$2-$3-$4-'); break;
      case 0x32: {
        const nt = Math.min(v.u32(p + 20), 32);
        const tools: string[] = [];
        for (let t = 0; t < nt; t++) tools.push(`${TOOLS[v.u32(p + 24 + t * 8)] ?? v.u32(p + 24 + t * 8)} ${ver(v.u32(p + 28 + t * 8))}`);
        info.build = { platform: PLATFORMS[v.u32(p + 8)] ?? String(v.u32(p + 8)), minos: ver(v.u32(p + 12)), sdk: ver(v.u32(p + 16)), tools };
        break;
      }
      case 0x24: case 0x25: case 0x2f: case 0x30:
        info.minVersion = { kind: (LC[cmd] as string).replace('LC_VERSION_MIN_', ''), version: ver(v.u32(p + 8)), sdk: ver(v.u32(p + 12)) };
        break;
      case 0x2a: { const x = v.u64(p + 8); info.sourceVersion = [x >> 40n, (x >> 30n) & 0x3ffn, (x >> 20n) & 0x3ffn, (x >> 10n) & 0x3ffn, x & 0x3ffn].map(String).join('.'); break; }
      case 0xe: info.dylinker = lstr(8); break;
      case 0xd: info.idDylib = lstr(8); break;
      case 0xc: case 0x80000018: case 0x8000001f: case 0x80000023:
        info.dylibs.push({ name: lstr(8), kind: (LC[cmd] as string).replace('LC_', '').toLowerCase(), currentVersion: ver(v.u32(p + 16)), compatVersion: ver(v.u32(p + 20)), resolved: [] });
        break;
      case 0x8000001c: info.rpaths.push(lstr(8)); break;
      case 0x21: case 0x2c: info.encryption = { offset: v.u32(p + 8), size: v.u32(p + 12), cryptid: v.u32(p + 16) }; break;
      case 0x1d: info.codeSignature = { offset: base + v.u32(p + 8), size: v.u32(p + 12) }; break;
      case 0x80000028: info.entry = v.u64n(p + 8); break;
    }
    p += size;
  }
  if (info.entry !== undefined) info.entry += textVm;
  return info;
}

/** Expand @rpath, @loader_path and @executable_path for each linked dylib. */
export function resolveDylibs(info: MachoInfo, opts: { executablePath?: string; loaderPath?: string } = {}): MachoInfo['dylibs'] {
  const exe = opts.executablePath ?? '@executable_path/x';
  const loader = opts.loaderPath ?? exe;
  const dir = (s: string): string => (s.includes('/') ? s.slice(0, s.lastIndexOf('/')) : s);
  const sub = (s: string): string => s.replace(/^@executable_path/, dir(exe)).replace(/^@loader_path/, dir(loader));
  for (const d of info.dylibs) {
    if (d.name.startsWith('@rpath/')) d.resolved = info.rpaths.slice(0, 64).map((r) => sub(r) + d.name.slice(6));
    else d.resolved = [sub(d.name)];
  }
  return info.dylibs;
}

export interface MachoSymbol { name: string; value: number; type: number; sect: number; external: boolean; undefined: boolean }
export function machoSymbols(bytes: Uint8Array, arch?: string, limit = 500000): MachoSymbol[] {
  const { v, base, is64 } = slice(bytes, arch);
  const ncmds = Math.min(v.u32(base + 16), 4096);
  let p = base + (is64 ? 32 : 28);
  const out: MachoSymbol[] = [];
  for (let i = 0; i < ncmds; i++) {
    if (!v.has(p, 8)) break;
    const cmd = v.u32(p), size = v.u32(p + 4);
    if (size < 8) break;
    if (cmd === 0x2) {
      const symoff = base + v.u32(p + 8), nsyms = Math.min(v.u32(p + 12), limit), stroff = base + v.u32(p + 16);
      const ent = is64 ? 16 : 12;
      for (let s = 0; s < nsyms; s++) {
        const e = symoff + s * ent;
        if (!v.has(e, ent)) break;
        const strx = v.u32(e), type = v.u8(e + 4), sect = v.u8(e + 5);
        const value = is64 ? v.u64n(e + 8) : v.u32(e + 8);
        if ((type & 0xe0) !== 0) continue;
        const name = strx && v.has(stroff + strx, 1) ? v.cstr(stroff + strx, 4096) : '';
        out.push({ name, value, type, sect, external: (type & 1) === 1, undefined: (type & 0x0e) === 0 });
      }
    }
    p += size;
  }
  return out;
}

// ---------------- code signature ----------------
export interface CodeDirectory {
  offset: number;
  version: string;
  flags: number;
  flagNames: string[];
  identifier: string;
  teamId?: string;
  hashType: string;
  hashSize: number;
  pageSize: number;
  codeLimit: number;
  nCodeSlots: number;
  nSpecialSlots: number;
  platform: number;
  execSegFlags?: number;
  cdhash: string;
  pagesChecked: number;
  pagesMatching: number;
  pageHashesValid: boolean;
}
export interface CodeSignature {
  offset: number;
  size: number;
  blobs: { type: string; magic: string; offset: number; length: number }[];
  codeDirectories: CodeDirectory[];
  entitlements?: string;
  entitlementKeys: string[];
  requirementsCount?: number;
  cms?: { signer?: string; serial?: string; certificates: Certificate[] };
  adhoc: boolean;
  hardenedRuntime: boolean;
}

const CS_FLAGS: [number, string][] = [
  [0x1, 'VALID'], [0x2, 'ADHOC'], [0x4, 'GET_TASK_ALLOW'], [0x100, 'HARD'], [0x200, 'KILL'], [0x400, 'CHECK_EXPIRATION'],
  [0x800, 'RESTRICT'], [0x1000, 'ENFORCEMENT'], [0x2000, 'REQUIRE_LV'], [0x10000, 'RUNTIME'], [0x20000, 'LINKER_SIGNED'],
];
const SLOT_NAMES: Record<number, string> = { 0: 'CodeDirectory', 1: 'Info.plist', 2: 'Requirements', 3: 'Resources', 4: 'Application', 5: 'Entitlements', 7: 'DER entitlements', 0x1000: 'Alternate CodeDirectory', 0x10000: 'CMS signature' };

export function machoCodeSignature(bytes: Uint8Array, arch?: string): CodeSignature | null {
  const info = machoInfo(bytes, arch);
  if (!info.codeSignature) return null;
  const { offset, size } = info.codeSignature;
  const be = new View(bytes, false);
  if (!be.has(offset, 12) || be.u32(offset) !== 0xfade0cc0) throw new ParseError('code signature superblob not found', offset);
  const count = Math.min(be.u32(offset + 8), 64);
  const sig: CodeSignature = { offset, size, blobs: [], codeDirectories: [], entitlementKeys: [], adhoc: false, hardenedRuntime: false };
  for (let i = 0; i < count; i++) {
    const type = be.u32(offset + 12 + i * 8), boff = offset + be.u32(offset + 16 + i * 8);
    if (!be.has(boff, 8)) continue;
    const magic = be.u32(boff), len = be.u32(boff + 4);
    if (len < 8 || !be.has(boff, len)) continue;
    sig.blobs.push({ type: SLOT_NAMES[type] ?? `slot ${type}`, magic: '0x' + magic.toString(16), offset: boff, length: len });
    if (magic === 0xfade0c02) sig.codeDirectories.push(codeDirectory(bytes, boff, len, info.sliceOffset));
    else if (magic === 0xfade7171) {
      sig.entitlements = utf8(be.sub(boff + 8, len - 8));
      sig.entitlementKeys = [...sig.entitlements.matchAll(/<key>([^<]{1,256})<\/key>/g)].map((m) => m[1] as string).slice(0, 256);
    } else if (magic === 0xfade0c01) sig.requirementsCount = be.u32(boff + 8);
    else if (magic === 0xfade0b01 && len > 8) {
      try {
        const ci = derAt(bytes, boff + 8, boff + len);
        const sd = children(children(ci)[1]!)[0]!;
        const certs: Certificate[] = [];
        let signer: string | undefined, serial: string | undefined;
        for (const pp of children(sd).slice(3)) {
          if (pp.cls === 2 && pp.tag === 0) for (const cd of children(pp)) { try { certs.push(parseCertificate(cd)); } catch { /* skip */ } }
          if (pp.cls === 0 && pp.tag === 0x11) {
            const si = children(pp)[0];
            const ias = si ? children(si)[1] : undefined;
            if (ias) { const [iss, ser] = children(ias); if (iss) signer = x509Name(iss).dn; if (ser) serial = intHex(ser); }
          }
        }
        sig.cms = { ...(signer ? { signer } : {}), ...(serial ? { serial } : {}), certificates: certs };
      } catch { sig.cms = { certificates: [] }; }
    }
  }
  const primary = sig.codeDirectories[0];
  if (primary) { sig.adhoc = (primary.flags & 2) !== 0; sig.hardenedRuntime = (primary.flags & 0x10000) !== 0; }
  return sig;
}

function codeDirectory(bytes: Uint8Array, off: number, len: number, sliceBase: number): CodeDirectory {
  const v = new View(bytes, false);
  const version = v.u32(off + 8), flags = v.u32(off + 12), hashOffset = v.u32(off + 16), identOffset = v.u32(off + 20);
  const nSpecial = v.u32(off + 24), nCode = v.u32(off + 28), codeLimit = v.u32(off + 32);
  const hashSize = v.u8(off + 36), hashType = v.u8(off + 37), platform = v.u8(off + 38), pageLog = v.u8(off + 39);
  const cd: CodeDirectory = {
    offset: off, version: '0x' + version.toString(16), flags, flagNames: CS_FLAGS.filter(([b]) => flags & b).map(([, n]) => n),
    identifier: v.cstr(off + identOffset, 1024), hashType: hashType === 1 ? 'sha1' : hashType === 2 ? 'sha256' : hashType === 3 ? 'sha256-truncated' : hashType === 4 ? 'sha384' : String(hashType),
    hashSize, pageSize: pageLog && pageLog < 31 ? 2 ** pageLog : 0, codeLimit, nCodeSlots: nCode, nSpecialSlots: nSpecial, platform,
    cdhash: '', pagesChecked: 0, pagesMatching: 0, pageHashesValid: false,
  };
  if (version >= 0x20200 && v.u32(off + 48)) cd.teamId = v.cstr(off + v.u32(off + 48), 256);
  if (version >= 0x20400 && len >= 88) cd.execSegFlags = Number(v.u64(off + 80));
  const blob = v.sub(off, len);
  if (hashType === 1) cd.cdhash = sha1(blob);
  else if (hashType === 2 || hashType === 3) cd.cdhash = sha256(blob).slice(0, 40);
  if ((hashType === 1 || hashType === 2) && cd.pageSize && nCode <= 1 << 20) {
    const hfn = hashType === 1 ? sha1 : sha256;
    let ok = 0, n = 0;
    for (let i = 0; i < nCode; i++) {
      const start = sliceBase + i * cd.pageSize;
      const end = Math.min(sliceBase + codeLimit, start + cd.pageSize);
      if (end <= start || end > bytes.length) break;
      const stored = toHex(v.sub(off + hashOffset + i * hashSize, hashSize));
      n++;
      if (stored === hfn(bytes.subarray(start, end)).slice(0, hashSize * 2)) ok++;
    }
    cd.pagesChecked = n;
    cd.pagesMatching = ok;
    cd.pageHashesValid = n > 0 && n === ok && n === nCode;
  }
  return cd;
}
