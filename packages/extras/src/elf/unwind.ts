// ELF unwind ranges from .eh_frame_hdr and .eh_frame: every FDE's code range, with the
// CIE it uses. The function start list is a strong function boundary source for stripped files.

import { View, ParseError, hexs } from '../util.js';
import { parseElf, findSection, type BinImage, type BinSection } from '../bin/container.js';

export interface UnwindRange { start: string; end: string; size: number; fdeOffset: number; cieOffset: number; augmentation?: string }
export interface UnwindInfo {
  source: '.eh_frame_hdr' | '.eh_frame';
  hdr?: { offset: number; version: number; ehFramePtr: string; fdeCount: number; tableEncoding: string };
  ranges: UnwindRange[];
  total: number;
  cies: number;
  truncated: boolean;
  issues: string[];
}

class Reader {
  constructor(readonly v: View, public p: number, readonly sec: BinSection, readonly bits: number) {}
  va(pos: number): number { return this.sec.vaddr + (pos - this.sec.offset); }
  uleb(): number { let r = 0, s = 0, b: number; do { b = this.v.u8(this.p++); if (s < 49) r += (b & 0x7f) * 2 ** s; s += 7; } while (b & 0x80); return r; }
  sleb(): number { let r = 0, s = 0, b: number; do { b = this.v.u8(this.p++); if (s < 49) r += (b & 0x7f) * 2 ** s; s += 7; } while (b & 0x80); if (s < 53 && (b & 0x40)) r -= 2 ** s; return r; }
  enc(e: number, dataBase = 0, valueOnly = false): number {
    if (e === 0xff) return 0;
    const at = this.p;
    let x: number;
    switch (e & 0x0f) {
      case 0x00: x = this.bits === 64 ? this.v.u64n(this.p) : this.v.u32(this.p); this.p += this.bits / 8; break;
      case 0x01: x = this.uleb(); break;
      case 0x02: x = this.v.u16(this.p); this.p += 2; break;
      case 0x03: x = this.v.u32(this.p); this.p += 4; break;
      case 0x04: x = this.v.u64n(this.p); this.p += 8; break;
      case 0x09: x = this.sleb(); break;
      case 0x0a: x = this.v.i16(this.p); this.p += 2; break;
      case 0x0b: x = this.v.i32(this.p); this.p += 4; break;
      case 0x0c: { const big = this.v.dv.getBigInt64((this.v.need(this.p, 8), this.p), this.v.le); x = Number(big); this.p += 8; break; }
      default: throw new ParseError(`unsupported pointer encoding ${hexs(e, 2)}`, at);
    }
    if (valueOnly) return x;
    const app = e & 0x70;
    if (app === 0x10) x += this.va(at);
    else if (app === 0x30) x += dataBase;
    return x;
  }
}

interface Cie { fdeEnc: number; aug: string; hasAugData: boolean }

function readCie(r: Reader, at: number, cache: Map<number, Cie>, end: number): Cie {
  const hit = cache.get(at);
  if (hit) return hit;
  const v = r.v;
  let p = at;
  let len = v.u32(p); p += 4;
  let wide = false;
  if (len === 0xffffffff) { len = v.u64n(p); p += 8; wide = true; }
  const body = p;
  if (body + len > end) throw new ParseError('CIE runs past section end', at);
  p += wide ? 8 : 4; // CIE id, 0 in .eh_frame
  const ver = v.u8(p); p += 1;
  let aug = '';
  while (aug.length < 16) { const c = v.u8(p++); if (!c) break; aug += String.fromCharCode(c); }
  const rr = new Reader(v, p, r.sec, r.bits);
  if (aug.includes('eh')) rr.p += r.bits / 8;
  rr.uleb(); rr.sleb(); // code and data alignment
  if (ver === 1) rr.p += 1; else rr.uleb(); // return address register
  let fdeEnc = 0;
  if (aug.startsWith('z')) {
    rr.uleb();
    for (const ch of aug.slice(1)) {
      if (ch === 'R') fdeEnc = v.u8(rr.p++);
      else if (ch === 'P') { const pe = v.u8(rr.p++); rr.enc(pe & 0x7f); }
      else if (ch === 'L') rr.p += 1;
      else if (ch === 'S' || ch === 'B' || ch === 'G') { /* no data */ }
      else break;
    }
  }
  const c: Cie = { fdeEnc, aug, hasAugData: aug.startsWith('z') };
  cache.set(at, c);
  return c;
}

/** Read FDE code ranges. Uses the binary search table in .eh_frame_hdr when present, else walks .eh_frame. */
export function elfUnwind(bytes: Uint8Array, opts: { limit?: number; offset?: number } = {}): UnwindInfo {
  const img: BinImage = parseElf(bytes);
  const v = img.view;
  const eh = findSection(img, '.eh_frame');
  const hdr = findSection(img, '.eh_frame_hdr');
  const cap = 2_000_000;
  const limit = Math.max(1, Math.min(50000, opts.limit ?? 1000));
  const skip = Math.max(0, opts.offset ?? 0);
  const issues: string[] = [];
  const cies = new Map<number, Cie>();
  if (!eh || !eh.size) throw new ParseError('no .eh_frame section');
  const ehEnd = eh.offset + eh.size;
  const fdeAt = (fileOff: number): UnwindRange | null => {
    let p = fileOff;
    const len = v.u32(p); p += 4;
    if (len === 0) return null;
    if (len === 0xffffffff) p += 8;
    const idPos = p;
    const cieRel = v.u32(p); p += 4;
    if (cieRel === 0) return null; // a CIE
    const cieOff = idPos - cieRel;
    if (cieOff < eh.offset || cieOff >= ehEnd) throw new ParseError('FDE points at a CIE outside .eh_frame', fileOff);
    const cie = readCie(new Reader(v, cieOff, eh, img.bits), cieOff, cies, ehEnd);
    const r = new Reader(v, p, eh, img.bits);
    const start = r.enc(cie.fdeEnc);
    const size = r.enc(cie.fdeEnc & 0x0f, 0, true);
    return { start: hexs(start), end: hexs(start + size), size, fdeOffset: fileOff, cieOffset: cieOff, augmentation: cie.aug || undefined };
  };
  const ranges: UnwindRange[] = [];
  let total = 0;
  let truncated = false;
  if (hdr && hdr.size >= 8) {
    const r = new Reader(v, hdr.offset, hdr, img.bits);
    const version = v.u8(r.p), ptrEnc = v.u8(r.p + 1), cntEnc = v.u8(r.p + 2), tblEnc = v.u8(r.p + 3);
    r.p += 4;
    const ehPtr = r.enc(ptrEnc, hdr.vaddr);
    const count = cntEnc === 0xff ? 0 : r.enc(cntEnc, hdr.vaddr);
    if (count > cap) throw new ParseError('implausible FDE count', hdr.offset);
    total = count;
    if (tblEnc !== 0xff) {
      for (let i = skip; i < count; i++) {
        if (ranges.length >= limit) { truncated = true; break; }
        const tr = new Reader(v, 0, hdr, img.bits);
        // fixed size entries: compute the slot position directly so paging is O(1)
        const w = (tblEnc & 0x0f) === 0x03 || (tblEnc & 0x0f) === 0x0b ? 4 : (tblEnc & 0x0f) === 0x04 || (tblEnc & 0x0f) === 0x0c ? 8 : 0;
        if (!w) { issues.push('variable length table encoding'); break; }
        tr.p = r.p + i * 2 * w;
        if (tr.p + 2 * w > hdr.offset + hdr.size) { issues.push('table runs past .eh_frame_hdr'); break; }
        tr.enc(tblEnc, hdr.vaddr);
        const fdeVa = tr.enc(tblEnc, hdr.vaddr);
        const fdeOff = eh.offset + (fdeVa - eh.vaddr);
        if (fdeOff < eh.offset || fdeOff >= ehEnd) { issues.push(`table entry ${i} points outside .eh_frame`); continue; }
        try { const x = fdeAt(fdeOff); if (x) ranges.push(x); } catch (e) { issues.push((e as Error).message); }
      }
      return { source: '.eh_frame_hdr', hdr: { offset: hdr.offset, version, ehFramePtr: hexs(ehPtr), fdeCount: count, tableEncoding: hexs(tblEnc, 2) }, ranges, total, cies: cies.size, truncated, issues };
    }
  }
  let p = eh.offset;
  let seen = 0;
  while (p + 4 <= ehEnd && seen < cap) {
    let len = v.u32(p);
    if (len === 0) break;
    let hl = 4;
    if (len === 0xffffffff) { len = v.u64n(p + 4); hl = 12; }
    const next = p + hl + len;
    if (next > ehEnd) { issues.push('entry runs past .eh_frame'); break; }
    if (v.u32(p + hl) !== 0) {
      total++;
      if (total > skip && ranges.length < limit) { try { const x = fdeAt(p); if (x) ranges.push(x); } catch (e) { issues.push((e as Error).message); } }
      else if (ranges.length >= limit) truncated = true;
    }
    seen++;
    p = next;
  }
  return { source: '.eh_frame', ranges, total, cies: cies.size, truncated, issues };
}
