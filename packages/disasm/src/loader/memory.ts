// Virtual address space of a loaded image: maps vaddr ranges to file bytes.
import type { BinaryImage, SectionInfo } from '../types.js';

interface Region { start: number; end: number; offset: number; fsize: number; exec: boolean; write: boolean; name: string }

export class Memory {
  readonly regions: Region[];
  private readonly bytes: Uint8Array;

  constructor(img: BinaryImage) {
    this.bytes = img.bytes;
    const sectionRegs: Region[] = img.sections
      .filter((s) => s.vaddr > 0 && s.size > 0)
      .map(regionOf)
      .sort((a, b) => a.start - b.start);
    const segRegs: Region[] = img.segments
      .filter((g) => g.vsize > 0)
      .map((g) => ({ start: g.vaddr, end: g.vaddr + g.vsize, offset: g.offset, fsize: g.fsize, exec: g.x, write: g.w, name: g.name }));
    const out: Region[] = [];
    const kept: Region[] = [];
    for (const r of sectionRegs) {
      const last = kept[kept.length - 1];
      if (last && r.start < last.end) continue; // overlapping sections: keep the first
      kept.push(r);
      out.push(r);
    }
    for (const g of segRegs) {
      // add the uncovered pieces of each segment
      let cur = g.start;
      for (const r of kept) {
        if (r.end <= cur || r.start >= g.end) continue;
        if (r.start > cur) out.push(piece(g, cur, r.start));
        cur = Math.max(cur, r.end);
      }
      if (cur < g.end) out.push(piece(g, cur, g.end));
    }
    out.sort((a, b) => a.start - b.start);
    // drop overlaps from segment pieces of overlapping segments
    const final: Region[] = [];
    for (const r of out) {
      const last = final[final.length - 1];
      if (last && r.start < last.end) {
        if (r.end <= last.end) continue;
        final.push({ ...r, offset: r.offset + (last.end - r.start), fsize: Math.max(0, r.fsize - (last.end - r.start)), start: last.end });
        continue;
      }
      final.push(r);
    }
    this.regions = final.slice(0, 100000);
  }

  find(addr: number): Region | undefined {
    let lo = 0, hi = this.regions.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const r = this.regions[mid]!;
      if (addr < r.start) hi = mid - 1;
      else if (addr >= r.end) lo = mid + 1;
      else return r;
    }
    return undefined;
  }

  isMapped(addr: number): boolean { return this.find(addr) !== undefined; }
  isExec(addr: number): boolean { return this.find(addr)?.exec ?? false; }
  sectionName(addr: number): string | undefined { return this.find(addr)?.name; }

  /** file offset for a vaddr, or -1 when not backed by file bytes */
  toOffset(addr: number): number {
    const r = this.find(addr);
    if (!r) return -1;
    const d = addr - r.start;
    if (d >= r.fsize) return -1;
    return r.offset + d;
  }

  /** Reads up to len bytes at addr without crossing its region; bss reads as zeros. */
  read(addr: number, len: number): Uint8Array {
    const r = this.find(addr);
    if (!r || len <= 0) return new Uint8Array(0);
    const n = Math.min(len, r.end - addr, 1 << 26);
    const d = addr - r.start;
    const out = new Uint8Array(n);
    const avail = Math.max(0, Math.min(n, r.fsize - d));
    if (avail > 0) {
      const off = r.offset + d;
      const end = Math.min(this.bytes.length, off + avail);
      if (off >= 0 && off < end) out.set(this.bytes.subarray(off, end));
    }
    return out;
  }

  /** zero copy view of file bytes at addr when fully file backed */
  view(addr: number, len: number): Uint8Array {
    const r = this.find(addr);
    if (!r) return new Uint8Array(0);
    const d = addr - r.start;
    const n = Math.max(0, Math.min(len, r.fsize - d, r.end - addr));
    const off = r.offset + d;
    if (n <= 0 || off < 0 || off >= this.bytes.length) return new Uint8Array(0);
    return this.bytes.subarray(off, Math.min(this.bytes.length, off + n));
  }

  readPtr(addr: number, bits: 32 | 64, le = true): number | undefined {
    const b = this.view(addr, bits / 8);
    if (b.length < bits / 8) return undefined;
    const v = new DataView(b.buffer, b.byteOffset, b.length);
    return bits === 64 ? Number(v.getBigUint64(0, le)) : v.getUint32(0, le);
  }

  readU32(addr: number, le = true): number | undefined {
    const b = this.view(addr, 4);
    if (b.length < 4) return undefined;
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, le);
  }

  execRegions(): Region[] { return this.regions.filter((r) => r.exec && r.fsize > 0); }
}

function regionOf(s: SectionInfo): Region {
  return { start: s.vaddr, end: s.vaddr + s.size, offset: s.offset, fsize: s.fsize, exec: s.exec, write: s.write, name: s.name };
}

function piece(g: Region, from: number, to: number): Region {
  const d = from - g.start;
  return { start: from, end: to, offset: g.offset + d, fsize: Math.max(0, Math.min(to - from, g.fsize - d)), exec: g.exec, write: g.write, name: g.name };
}
