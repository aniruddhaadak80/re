// Windows Jump Lists: *.automaticDestinations-ms (OLE compound file with a DestList stream
// and one shell link stream per entry) and *.customDestinations-ms (concatenated shell links).

import { View, ParseError, filetime, guid, indexOfBytes, fromHex } from '../util.js';
import { Cfb } from './cfb.js';
import { parseLnk, type Lnk } from './lnk.js';

export interface DestListEntry {
  entryNumber: number; stream: string; hostname: string; path: string; pinStatus: number; pinned: boolean;
  accessCount?: number; lastModified: string | null; droidVolume: string; droidFile: string; birthDroidVolume: string; birthDroidFile: string;
  offset: number; lnk?: LnkSummary; lnkError?: string;
}
export interface LnkSummary { target?: string; localBasePath?: string; arguments?: string; workingDir?: string; fileSize: number; created: string | null; modified: string | null; accessed: string | null; machineId?: string; driveSerial?: string; volumeLabel?: string }
export interface AutomaticJumpList {
  kind: 'automatic'; appId: string | null; destListVersion: number; entryCount: number; pinnedCount: number; lastEntryNumber: number; lastRevision: number;
  streams: { name: string; size: number }[]; entries: DestListEntry[];
}
export interface CustomJumpList { kind: 'custom'; appId: string | null; header: number[]; footerValid: boolean; links: (LnkSummary & { offset: number; category?: number })[] }

/** Shorter LNK view for jump list entries. */
export function lnkSummary(l: Lnk): LnkSummary {
  const tracker = l.extra.find((e) => e.machineId);
  return { target: l.target, localBasePath: l.linkInfo?.localBasePath, arguments: l.arguments, workingDir: l.workingDir, fileSize: l.fileSize, created: l.created, modified: l.modified, accessed: l.accessed, machineId: tracker?.machineId, driveSerial: l.linkInfo?.driveSerial, volumeLabel: l.linkInfo?.volumeLabel };
}

const appIdOf = (name?: string): string | null => { const m = name?.match(/([0-9a-f]{16})\.(?:automatic|custom)Destinations-ms$/i); return m ? m[1]!.toLowerCase() : null; };

/** Parse the DestList stream of an automatic jump list. */
export function parseDestList(b: Uint8Array, maxEntries = 10000): { version: number; entryCount: number; pinnedCount: number; lastEntryNumber: number; lastRevision: number; entries: DestListEntry[] } {
  const v = new View(b, true);
  if (b.length < 32) throw new ParseError('DestList header truncated', 0);
  const version = v.u32(0), count = v.u32(4), pinnedCount = v.u32(8);
  const entries: DestListEntry[] = [];
  let p = 32;
  for (let i = 0; i < Math.min(count, maxEntries); i++) {
    const fixed = version >= 2 ? 130 : 114;
    if (!v.has(p, fixed)) break;
    const plen = v.u16(p + fixed - 2);
    if (!v.has(p + fixed, plen * 2)) break;
    const num = v.u32(p + 88);
    const pin = v.i32(p + 108);
    entries.push({
      entryNumber: num, stream: num.toString(16), hostname: v.cstr(p + 72, 16), path: v.utf16(p + fixed, plen), pinStatus: pin, pinned: pin >= 0,
      accessCount: version >= 2 ? v.u32(p + 116) : undefined, lastModified: filetime(v.u32(p + 100), v.u32(p + 104)),
      droidVolume: guid(b, p + 8), droidFile: guid(b, p + 24), birthDroidVolume: guid(b, p + 40), birthDroidFile: guid(b, p + 56), offset: p,
    });
    p += fixed + plen * 2 + (version >= 2 ? 4 : 0);
  }
  return { version, entryCount: count, pinnedCount, lastEntryNumber: v.u32(16), lastRevision: v.u32(24), entries };
}

/** Parse an *.automaticDestinations-ms jump list, decoding each entry's embedded shell link. */
export function parseAutomaticJumpList(b: Uint8Array, opts: { name?: string; maxEntries?: number } = {}): AutomaticJumpList {
  const cfb = new Cfb(b);
  const streams = cfb.streams().map((e) => ({ name: e.path, size: e.size }));
  const dl = cfb.stream('DestList');
  const d = dl ? parseDestList(cfb.read(dl), opts.maxEntries) : { version: 0, entryCount: 0, pinnedCount: 0, lastEntryNumber: 0, lastRevision: 0, entries: [] };
  for (const e of d.entries) {
    const s = cfb.stream(e.stream);
    if (!s) continue;
    try { e.lnk = lnkSummary(parseLnk(cfb.read(s))); } catch (err) { e.lnkError = (err as Error).message; }
  }
  return { kind: 'automatic', appId: appIdOf(opts.name), destListVersion: d.version, entryCount: d.entryCount, pinnedCount: d.pinnedCount, lastEntryNumber: d.lastEntryNumber, lastRevision: d.lastRevision, streams, entries: d.entries };
}

const LNK_SIG = fromHex('4c0000000114020000000000c000000000000046');

/** Parse a *.customDestinations-ms jump list: categories of concatenated shell links. */
export function parseCustomJumpList(b: Uint8Array, opts: { name?: string; maxLinks?: number } = {}): CustomJumpList {
  const v = new View(b, true);
  if (b.length < 16) throw new ParseError('custom jump list truncated', 0);
  const links: CustomJumpList['links'] = [];
  let p = indexOfBytes(b, LNK_SIG, 0);
  while (p >= 0 && links.length < (opts.maxLinks ?? 5000)) {
    try { links.push({ offset: p, ...lnkSummary(parseLnk(b.subarray(p))) }); } catch { /* not a link */ }
    p = indexOfBytes(b, LNK_SIG, p + 4);
  }
  return { kind: 'custom', appId: appIdOf(opts.name), header: [v.u32(0), v.u32(4), v.u32(8), v.u32(12)], footerValid: b.length >= 4 && v.u32(b.length - 4) === 0xbabffbab, links };
}

/** Parse either jump list kind, picked by content. */
export function parseJumpList(b: Uint8Array, opts: { name?: string } = {}): AutomaticJumpList | CustomJumpList {
  return b.length >= 8 && b[0] === 0xd0 && b[1] === 0xcf ? parseAutomaticJumpList(b, opts) : parseCustomJumpList(b, opts);
}
