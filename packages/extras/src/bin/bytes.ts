// Raw byte access for agents: read a range, search a pattern with wildcards, and map
// between virtual addresses and file offsets. Every result carries file offsets.

import { ParseError, toHex, latin1 } from '../util.js';
import { detectBin, parseBin, vaToOffset, offsetToVa, type BinImage } from './container.js';

export const MAX_READ = 64 * 1024;

export interface ByteRead { offset: number; length: number; hex: string; ascii: string; truncated: boolean }

/** Read up to 64 KiB at a file offset. */
export function readBytes(bytes: Uint8Array, offset: number, length = 256): ByteRead {
  if (!Number.isInteger(offset) || offset < 0 || offset > bytes.length) throw new ParseError('offset out of range', offset);
  const want = Math.max(0, Math.floor(length));
  const n = Math.min(want, MAX_READ, bytes.length - offset);
  const sub = bytes.subarray(offset, offset + n);
  return { offset, length: n, hex: toHex(sub), ascii: latin1(sub).replace(/[^\x20-\x7e]/g, '.'), truncated: n < want };
}

/** Pattern compiled from "4d 5a ?? 00" style text. null entries are wildcards. */
export function compilePattern(p: string): (number | null)[] {
  const tokens = p.trim().split(/\s+/).filter(Boolean);
  const out: (number | null)[] = [];
  for (const t of tokens) {
    if (t.length % 2) throw new ParseError(`pattern token "${t}" must be whole bytes`);
    for (let i = 0; i < t.length; i += 2) {
      const pair = t.slice(i, i + 2);
      if (pair === '??' || pair === '..') out.push(null);
      else if (/^[0-9a-fA-F]{2}$/.test(pair)) out.push(parseInt(pair, 16));
      else throw new ParseError(`bad pattern byte "${pair}"`);
    }
  }
  if (!out.length) throw new ParseError('empty pattern');
  if (out.length > 4096) throw new ParseError('pattern longer than 4096 bytes');
  if (out.every((x) => x === null)) throw new ParseError('pattern needs at least one fixed byte');
  return out;
}

export interface ByteHit { offset: number; va?: string; section?: string; context: string }

/**
 * Search bytes for a hex pattern (with ?? wildcards) or a text string (ascii and utf16le).
 * Returns at most `limit` hits starting from `start`.
 */
export function searchBytes(bytes: Uint8Array, query: { hex?: string; text?: string }, opts: { start?: number; end?: number; limit?: number } = {}): { hits: ByteHit[]; complete: boolean; nextOffset?: number } {
  const pats: (number | null)[][] = [];
  if (query.hex) pats.push(compilePattern(query.hex));
  if (query.text) {
    if (query.text.length > 1024) throw new ParseError('text query longer than 1024 characters');
    const a: number[] = []; const w: number[] = [];
    for (const ch of query.text) { const c = ch.charCodeAt(0); a.push(c & 0xff); w.push(c & 0xff, (c >> 8) & 0xff); }
    pats.push(a, w);
  }
  if (!pats.length) throw new ParseError('pass hex or text');
  const limit = Math.max(1, Math.min(1000, Math.floor(opts.limit ?? 100)));
  const start = Math.max(0, Math.floor(opts.start ?? 0));
  const end = Math.min(bytes.length, Math.floor(opts.end ?? bytes.length));
  let img: BinImage | undefined;
  try { if (detectBin(bytes)) img = parseBin(bytes); } catch { img = undefined; }
  const hits: ByteHit[] = [];
  for (let i = start; i < end; i++) {
    for (const pat of pats) {
      if (i + pat.length > end) continue;
      let ok = true;
      for (let j = 0; j < pat.length; j++) { const v = pat[j]; if (v !== null && bytes[i + j] !== v) { ok = false; break; } }
      if (!ok) continue;
      const h: ByteHit = { offset: i, context: toHex(bytes.subarray(Math.max(0, i - 8), Math.min(bytes.length, i + pat.length + 8))) };
      if (img) {
        const va = offsetToVa(img, i);
        if (va >= 0) h.va = '0x' + va.toString(16);
        const s = img.sections.find((x) => i >= x.offset && i < x.offset + x.size);
        if (s) h.section = s.name;
      }
      hits.push(h);
      if (hits.length >= limit) return { hits, complete: false, nextOffset: i + 1 };
      break;
    }
  }
  return { hits, complete: true };
}

export interface AddressMapping { va?: string; offset?: number; section?: string; segment?: string; mapped: boolean }

/** Convert a virtual address to a file offset or the reverse, using section and segment tables. */
export function addressMap(bytes: Uint8Array, q: { va?: number | string; offset?: number }, arch?: string): AddressMapping {
  const img = parseBin(bytes, arch ? { arch } : {});
  if (q.va !== undefined) {
    const va = typeof q.va === 'string' ? parseInt(q.va, q.va.startsWith('0x') ? 16 : 10) : q.va;
    if (!Number.isFinite(va)) throw new ParseError('bad va');
    const off = vaToOffset(img, va);
    // PE section addresses are RVAs; accept either a full VA or an RVA
    const a = img.format === 'pe' && img.imageBase > 0 && va >= img.imageBase ? va - img.imageBase : va;
    const s = img.sections.find((x) => a >= x.vaddr && a < x.vaddr + Math.max(x.vsize, x.size));
    const g = img.segments.find((x) => a >= x.vaddr && a < x.vaddr + x.vsize);
    return { va: '0x' + va.toString(16), offset: off >= 0 ? off : undefined, section: s?.name, segment: g?.name, mapped: off >= 0 };
  }
  if (q.offset !== undefined) {
    const off = q.offset;
    const va = offsetToVa(img, off);
    const s = img.sections.find((x) => off >= x.offset && off < x.offset + x.size);
    const g = img.segments.find((x) => off >= x.offset && off < x.offset + x.size);
    return { offset: off, va: va >= 0 ? '0x' + va.toString(16) : undefined, section: s?.name, segment: g?.name, mapped: va >= 0 };
  }
  throw new ParseError('pass va or offset');
}
