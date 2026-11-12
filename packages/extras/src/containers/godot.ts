// Godot engine resource packs (.pck): format versions 0 and 1 (Godot 3), 2 (Godot 4.0 to 4.3) and
// 3 (Godot 4.4+, directory at an offset). Standalone files, packs appended to an exported game
// executable (u64 size + "GDPC" trailer) and packs found by scanning are supported. Written from
// the format as Godot's file_access_pack.cpp reads it (MIT); no code was copied.

import { md5 } from '@revlens/core';
import { ParseError, utf8 } from '../util.js';

const MAGIC = 0x43504447; // "GDPC" little endian
export const PACK_DIR_ENCRYPTED = 1, PACK_REL_FILEBASE = 2, PACK_SPARSE_BUNDLE = 4;
export const PACK_FILE_ENCRYPTED = 1, PACK_FILE_REMOVAL = 2;

export interface GodotPckEntry { path: string; offset: number; size: number; md5: string; flags: number; encrypted: boolean; removal: boolean; entryOffset: number }
export interface GodotPck {
  packStart: number; embedded: 'none' | 'trailer' | 'scan'; formatVersion: number; engineVersion: string; packFlags: number;
  flags: { encryptedDirectory: boolean; relativeFileBase: boolean; sparseBundle: boolean };
  fileBase: number; directoryOffset: number; fileCount: number; files: GodotPckEntry[]; encryptedFiles: number;
  offsetsRelativeToPack: boolean; warnings: string[];
}

const u32 = (b: Uint8Array, o: number) => ((b[o] as number) | ((b[o + 1] as number) << 8) | ((b[o + 2] as number) << 16) | ((b[o + 3] as number) << 24)) >>> 0;
function u64(b: Uint8Array, o: number): number {
  const lo = u32(b, o), hi = u32(b, o + 4);
  if (hi > 0x1fffff) throw new ParseError(`64-bit value at ${o} is too large`);
  return hi * 0x100000000 + lo;
}
const need = (b: Uint8Array, o: number, n: number) => { if (o < 0 || o + n > b.length) throw new ParseError(`pck truncated at ${o}`); };

/** Where the pack starts: offset 0, a trailer at the end of an executable, or the first plausible GDPC header. */
export function findGodotPck(b: Uint8Array): { start: number; embedded: GodotPck['embedded'] } | undefined {
  if (b.length >= 8 && u32(b, 0) === MAGIC) return { start: 0, embedded: 'none' };
  if (b.length >= 16 && u32(b, b.length - 4) === MAGIC) {
    const ds = u32(b, b.length - 12) + u32(b, b.length - 8) * 0x100000000;
    const start = b.length - 12 - ds;
    if (start >= 0 && start + 4 <= b.length && u32(b, start) === MAGIC) return { start, embedded: 'trailer' };
  }
  // a pack inside an ELF or PE section without a trailer: scan for a header with a sane version
  for (let i = 4; i + 24 <= b.length; i++) {
    if (b[i] !== 0x47 || b[i + 1] !== 0x44 || b[i + 2] !== 0x50 || b[i + 3] !== 0x43) continue;
    const ver = u32(b, i + 4), major = u32(b, i + 8);
    if (ver <= 3 && major >= 2 && major <= 5 && u32(b, i + 12) < 100) return { start: i, embedded: 'scan' };
  }
  return undefined;
}

export function isGodotPck(b: Uint8Array): boolean { return b.length >= 8 && u32(b, 0) === MAGIC; }

/** Read the pack header and file table. */
export function inspectGodotPck(b: Uint8Array, opts: { maxFiles?: number } = {}): GodotPck {
  const loc = findGodotPck(b);
  if (!loc) throw new ParseError('no Godot pack (GDPC) found');
  const s = loc.start;
  need(b, s, 24);
  const version = u32(b, s + 4);
  if (version > 3) throw new ParseError(`unsupported pck format version ${version}`);
  const engine = `${u32(b, s + 8)}.${u32(b, s + 12)}.${u32(b, s + 16)}`;
  const warnings: string[] = [];
  let p = s + 20, packFlags = 0, fileBase = 0, dirOff: number;
  if (version >= 2) {
    need(b, p, 12);
    packFlags = u32(b, p); fileBase = u64(b, p + 4); p += 12;
    if (version === 3 || packFlags & PACK_REL_FILEBASE) fileBase += s;
    if (version === 3) { need(b, p, 8); dirOff = u64(b, p) + s; }
    else dirOff = p + 64;
  } else dirOff = p + 64;
  need(b, dirOff, 4);
  const count = u32(b, dirOff);
  const max = Math.min(opts.maxFiles ?? 200000, 1_000_000);
  const enc = (packFlags & PACK_DIR_ENCRYPTED) !== 0;
  const files: GodotPckEntry[] = [];
  if (enc) warnings.push('the file directory is AES-256 encrypted with the game\'s script encryption key; entries cannot be listed without it');
  else {
    if (count > max) warnings.push(`file count ${count} capped at ${max}`);
    let q = dirOff + 4;
    for (let k = 0; k < Math.min(count, max); k++) {
      need(b, q, 4);
      const sl = u32(b, q);
      if (sl > 4096) throw new ParseError(`path length ${sl} at ${q} is too long`);
      need(b, q + 4, sl + 32 + (version >= 2 ? 4 : 0));
      let path = utf8(b.subarray(q + 4, q + 4 + sl));
      const nul = path.indexOf('\0');
      if (nul >= 0) path = path.slice(0, nul);
      const e = q;
      q += 4 + sl;
      const offset = u64(b, q), size = u64(b, q + 8);
      const m = Array.from(b.subarray(q + 16, q + 32), (x) => x.toString(16).padStart(2, '0')).join('');
      q += 32;
      const flags = version >= 2 ? u32(b, q) : 0;
      if (version >= 2) q += 4;
      files.push({ path: path.startsWith('res://') || path.startsWith('user://') ? path : `res://${path}`, offset: offset + fileBase, size, md5: m, flags, encrypted: (flags & PACK_FILE_ENCRYPTED) !== 0, removal: (flags & PACK_FILE_REMOVAL) !== 0, entryOffset: e });
    }
  }
  // Godot 3 stores offsets relative to the pack start while its reader adds the open offset only;
  // for packs not at offset 0, pick the base whose data fits and whose MD5 matches.
  let rel = version >= 2 ? fileBase === s && s > 0 : false;
  if (version < 2 && s > 0 && files.length) {
    const fits = (base: number) => files.every((f) => f.offset + base + f.size <= b.length);
    const probe = files.filter((f) => !f.encrypted && f.size > 0 && f.size < 1 << 20).sort((x, y) => x.size - y.size)[0];
    const ok = (base: number) => fits(base) && (!probe || md5(b.subarray(probe.offset + base, probe.offset + base + probe.size)) === probe.md5);
    if (!ok(0) && ok(s)) { rel = true; for (const f of files) f.offset += s; }
  }
  for (const f of files) if (f.offset + f.size > b.length) { warnings.push(`${f.path} data runs past the end of the file`); break; }
  return {
    packStart: s, embedded: loc.embedded, formatVersion: version, engineVersion: engine, packFlags,
    flags: { encryptedDirectory: enc, relativeFileBase: (packFlags & PACK_REL_FILEBASE) !== 0 || version === 3, sparseBundle: (packFlags & PACK_SPARSE_BUNDLE) !== 0 },
    fileBase, directoryOffset: dirOff, fileCount: count, files, encryptedFiles: files.filter((f) => f.encrypted).length, offsetsRelativeToPack: rel, warnings,
  };
}

/** The bytes of one entry (by res:// path or plain path) and whether its MD5 matches the directory. */
export function godotPckFile(b: Uint8Array, p: GodotPck, path: string): { entry: GodotPckEntry; data: Uint8Array; md5Matches: boolean | null } {
  const want = path.startsWith('res://') ? path : `res://${path.replace(/^\/+/, '')}`;
  const entry = p.files.find((f) => f.path === want);
  if (!entry) throw new ParseError(`no ${path} in the pack`);
  if (entry.offset + entry.size > b.length) throw new ParseError(`${path} data runs past the end of the file`);
  const data = b.subarray(entry.offset, entry.offset + entry.size);
  if (entry.encrypted) return { entry, data, md5Matches: null };
  return { entry, data, md5Matches: /^0+$/.test(entry.md5) ? null : md5(data) === entry.md5 };
}
