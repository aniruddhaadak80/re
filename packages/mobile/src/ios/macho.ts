// Just enough Mach-O reading for iOS apps: per-arch encryption state, linked dylibs and the
// code signature SuperBlob (CodeDirectory identifier, team id, entitlements). Full Mach-O analysis lives in @revlens/core.

import { Buf, ParseError, utf8 } from '../bytes.js';
import { parsePlist, type PlistValue } from './plist.js';

export interface MachoSlice {
  offset: number;
  cpu: string;
  bits: 32 | 64;
  fileType: number;
  encrypted?: boolean;
  dylibs: string[];
  rpaths: string[];
  signature?: CodeSignature;
}

export interface CodeSignature {
  offset: number;
  size: number;
  identifier?: string;
  teamId?: string;
  flags?: number;
  hashType?: string;
  hasCms: boolean;
  entitlementsXml?: string;
  entitlements?: PlistValue;
  derEntitlements: boolean;
  blobs: { type: string; offset: number }[];
}

const CPU: Record<number, string> = { 7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32', 18: 'ppc', 0x01000012: 'ppc64' };
const BLOB: Record<number, string> = { 0: 'CodeDirectory', 1: 'InfoSlot', 2: 'Requirements', 3: 'ResourceDir', 4: 'Application', 5: 'Entitlements', 7: 'DerEntitlements', 0x1000: 'AlternateCodeDirectory', 0x10000: 'CMS' };
const HASHES: Record<number, string> = { 1: 'sha1', 2: 'sha256', 3: 'sha256-truncated', 4: 'sha384' };

export function isMacho(b: Uint8Array): boolean {
  if (b.length < 8) return false;
  const m = ((b[0] as number) << 24 | (b[1] as number) << 16 | (b[2] as number) << 8 | (b[3] as number)) >>> 0;
  if (m === 0xcafebabe) {
    // Java class files share this magic; a fat header has a small arch count instead of a class version
    const n = ((b[4] as number) << 24 | (b[5] as number) << 16 | (b[6] as number) << 8 | (b[7] as number)) >>> 0;
    return n > 0 && n < 30;
  }
  return m === 0xfeedface || m === 0xfeedfacf || m === 0xcefaedfe || m === 0xcffaedfe || m === 0xbebafeca;
}

function parseSignature(b: Uint8Array, off: number, size: number): CodeSignature {
  const r = new Buf(b, false);
  const sig: CodeSignature = { offset: off, size, hasCms: false, derEntitlements: false, blobs: [] };
  if (!r.has(off, 12) || r.u32(off) !== 0xfade0cc0) return sig;
  const count = Math.min(r.u32(off + 8), 64);
  for (let i = 0; i < count; i++) {
    const type = r.u32(off + 12 + i * 8);
    const boff = off + r.u32(off + 16 + i * 8);
    sig.blobs.push({ type: BLOB[type] ?? `0x${type.toString(16)}`, offset: boff });
    if (!r.has(boff, 8)) continue;
    const magic = r.u32(boff);
    const len = r.u32(boff + 4);
    if (!r.has(boff, len)) continue;
    if (magic === 0xfade0c02 && type === 0) {
      const version = r.u32(boff + 8);
      sig.flags = r.u32(boff + 12);
      const identOff = r.u32(boff + 20);
      if (identOff < len) sig.identifier = r.cstr(boff + identOff, 512);
      sig.hashType = HASHES[r.u8(boff + 37)] ?? String(r.u8(boff + 37));
      if (version >= 0x20200 && len >= 52) {
        const t = r.u32(boff + 48);
        if (t && t < len) sig.teamId = r.cstr(boff + t, 64);
      }
    } else if (magic === 0xfade7171) {
      sig.entitlementsXml = utf8(r.slice(boff + 8, len - 8));
      try { sig.entitlements = parsePlist(r.slice(boff + 8, len - 8)); } catch { /* keep xml */ }
    } else if (magic === 0xfade7172) sig.derEntitlements = true;
    else if (magic === 0xfade0b01) sig.hasCms = len > 8;
  }
  return sig;
}

function parseThin(b: Uint8Array, base: number, end: number): MachoSlice {
  const magicBE = new Buf(b, false).u32(base);
  const little = magicBE === 0xcefaedfe || magicBE === 0xcffaedfe;
  const r = new Buf(b, little);
  const magic = r.u32(base);
  const is64 = magic === 0xfeedfacf;
  if (magic !== 0xfeedface && magic !== 0xfeedfacf) throw new ParseError('not a thin Mach-O');
  const cpu = r.u32(base + 4);
  const ncmds = Math.min(r.u32(base + 16), 4096);
  const slice: MachoSlice = { offset: base, cpu: CPU[cpu] ?? `cpu${cpu}`, bits: is64 ? 64 : 32, fileType: r.u32(base + 12), dylibs: [], rpaths: [] };
  let p = base + (is64 ? 32 : 28);
  for (let i = 0; i < ncmds; i++) {
    if (!r.has(p, 8) || p >= end) break;
    const cmd = r.u32(p);
    const size = r.u32(p + 4);
    if (size < 8) break;
    const lc = cmd & 0x7fffffff;
    if (lc === 0x0c || lc === 0x18 || lc === 0x1f || lc === 0x0d) { // LOAD_DYLIB, LOAD_WEAK_DYLIB, REEXPORT_DYLIB, ID_DYLIB
      const nameOff = r.u32(p + 8);
      if (lc !== 0x0d && nameOff < size) slice.dylibs.push(r.cstr(p + nameOff, size - nameOff));
    } else if (lc === 0x1c) {
      const nameOff = r.u32(p + 8);
      if (nameOff < size) slice.rpaths.push(r.cstr(p + nameOff, size - nameOff));
    } else if (lc === 0x21 || lc === 0x2c) {
      slice.encrypted = r.u32(p + 16) !== 0;
    } else if (lc === 0x1d) {
      const dataoff = r.u32(p + 8), datasize = r.u32(p + 12);
      slice.signature = parseSignature(b, base + dataoff, datasize);
    }
    p += size;
  }
  return slice;
}

/** Read every architecture slice of a Mach-O or fat binary. */
export function parseMachoSlices(b: Uint8Array): MachoSlice[] {
  if (!isMacho(b)) throw new ParseError('not a Mach-O file');
  const r = new Buf(b, false);
  const m = r.u32(0);
  if (m === 0xcafebabe || m === 0xbebafeca) {
    const rr = new Buf(b, m === 0xcafebabe ? false : true);
    const n = Math.min(rr.u32(4), 32);
    const out: MachoSlice[] = [];
    for (let i = 0; i < n; i++) {
      const off = rr.u32(8 + i * 20 + 8);
      const size = rr.u32(8 + i * 20 + 12);
      try { out.push(parseThin(b, off, off + size)); } catch { /* skip bad slice */ }
    }
    return out;
  }
  return [parseThin(b, 0, b.length)];
}
