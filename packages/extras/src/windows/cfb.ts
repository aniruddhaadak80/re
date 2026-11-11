// OLE Compound File Binary (MS-CFB) reader: header, DIFAT, FAT, mini FAT, directory tree
// and stream extraction. Used for Jump Lists, and useful for MSI, legacy Office and more.

import { View, ParseError, filetime, guid } from '../util.js';

const FREE = 0xffffffff, END = 0xfffffffe, FATSECT = 0xfffffffd, DIFSECT = 0xfffffffc;

export interface CfbEntry { id: number; name: string; path: string; type: 'storage' | 'stream' | 'root' | 'unknown'; size: number; startSector: number; clsid: string; created: string | null; modified: string | null }

/** Parsed compound file. */
export class Cfb {
  readonly v: View;
  readonly sectorSize: number;
  readonly miniSectorSize: number;
  readonly miniCutoff: number;
  readonly version: number;
  readonly fat: Uint32Array;
  private miniFat: Uint32Array;
  readonly entries: CfbEntry[] = [];
  private miniStream?: Uint8Array;
  private raw: { left: number; right: number; child: number }[] = [];

  constructor(readonly bytes: Uint8Array, readonly opts: { maxStreamSize?: number } = {}) {
    const v = (this.v = new View(bytes, true));
    if (bytes.length < 512 || v.u32(0) !== 0xe011cfd0 || v.u32(4) !== 0xe11ab1a1) throw new ParseError('not an OLE compound file (D0CF11E0 signature expected)', 0);
    this.version = v.u16(26);
    const shift = v.u16(30), mshift = v.u16(32);
    if (shift !== 9 && shift !== 12) throw new ParseError(`bad sector shift ${shift}`, 30);
    if (mshift !== 6) throw new ParseError(`bad mini sector shift ${mshift}`, 32);
    this.sectorSize = 1 << shift;
    this.miniSectorSize = 1 << mshift;
    this.miniCutoff = v.u32(56);
    const nFat = v.u32(44), dirStart = v.u32(48), miniFatStart = v.u32(60), nMiniFat = v.u32(64);
    let difat = v.u32(68);
    const nDifat = v.u32(72);
    const maxSectors = Math.ceil(bytes.length / this.sectorSize) + 1;
    if (nFat > maxSectors) throw new ParseError('FAT sector count larger than the file', 44);
    const fatSectors: number[] = [];
    for (let i = 0; i < 109 && fatSectors.length < nFat; i++) fatSectors.push(v.u32(76 + i * 4));
    for (let d = 0; d < nDifat && difat < END && fatSectors.length < nFat; d++) {
      const o = this.secOff(difat);
      const per = this.sectorSize / 4 - 1;
      for (let i = 0; i < per && fatSectors.length < nFat; i++) fatSectors.push(v.u32(o + i * 4));
      difat = v.u32(o + per * 4);
    }
    const per = this.sectorSize / 4;
    this.fat = new Uint32Array(fatSectors.length * per);
    fatSectors.forEach((s, i) => { const o = this.secOff(s); for (let j = 0; j < per; j++) this.fat[i * per + j] = v.u32(o + j * 4); });
    const mf = nMiniFat && miniFatStart < END ? this.chainBytes(miniFatStart, this.fat, this.sectorSize, (s) => this.secOff(s), nMiniFat * this.sectorSize) : new Uint8Array(0);
    const mv = new View(mf, true);
    this.miniFat = new Uint32Array(mf.length >> 2);
    for (let i = 0; i < this.miniFat.length; i++) this.miniFat[i] = mv.u32(i * 4);
    const dir = this.chainBytes(dirStart, this.fat, this.sectorSize, (s) => this.secOff(s), 64 << 20);
    const dv = new View(dir, true);
    for (let i = 0; i * 128 + 128 <= dir.length && i < 100000; i++) {
      const o = i * 128;
      const nlen = dv.u16(o + 64);
      const t = dv.u8(o + 66);
      const name = nlen >= 2 ? dv.utf16(o, Math.min(32, nlen / 2 - 1)) : '';
      const size = this.version === 3 ? dv.u32(o + 120) : Number(dv.u64(o + 120) & 0xffffffffn);
      this.entries.push({ id: i, name, path: '', type: t === 5 ? 'root' : t === 1 ? 'storage' : t === 2 ? 'stream' : 'unknown', size, startSector: dv.u32(o + 116), clsid: guid(dir, o + 80), created: filetime(dv.u32(o + 100), dv.u32(o + 104)), modified: filetime(dv.u32(o + 108), dv.u32(o + 112)) });
      this.raw.push({ left: dv.u32(o + 68), right: dv.u32(o + 72), child: dv.u32(o + 76) });
    }
    // resolve paths by walking the red-black trees from the root's child
    const seen = new Set<number>();
    const visit = (id: number, prefix: string, depth: number): void => {
      if (id >= this.entries.length || seen.has(id) || depth > 64) return;
      seen.add(id);
      const e = this.entries[id]!, r = this.raw[id]!;
      e.path = prefix ? `${prefix}/${e.name}` : e.name;
      visit(r.left, prefix, depth + 1);
      visit(r.right, prefix, depth + 1);
      if (e.type === 'storage') visit(r.child, e.path, depth + 1);
    };
    if (this.entries[0]) { this.entries[0].path = ''; seen.add(0); visit(this.raw[0]!.child, '', 0); }
  }

  private secOff(s: number): number {
    const o = (s + 1) * this.sectorSize;
    if (s >= DIFSECT || !this.v.has(o, this.sectorSize)) throw new ParseError(`sector ${s} out of range`, o);
    return o;
  }

  private chainBytes(start: number, fat: Uint32Array, size: number, off: (s: number) => number, max: number): Uint8Array {
    const parts: Uint8Array[] = [];
    let s = start, total = 0;
    const seen = new Set<number>();
    while (s !== END && s !== FREE && s !== FATSECT && total < max) {
      if (seen.has(s) || s >= fat.length) throw new ParseError(`broken sector chain at ${s}`);
      seen.add(s);
      const o = off(s);
      parts.push(fat === this.miniFat ? this.miniStream!.subarray(o, o + size) : this.v.sub(o, size));
      total += size;
      s = fat[s]!;
    }
    const out = new Uint8Array(total);
    let p = 0;
    for (const x of parts) { out.set(x, p); p += x.length; }
    return out;
  }

  /** Bytes of a stream entry, capped. */
  read(e: CfbEntry): Uint8Array {
    if (e.type !== 'stream' && e.type !== 'root') throw new ParseError(`${e.path} is not a stream`);
    const max = this.opts.maxStreamSize ?? 64 << 20;
    if (e.size > max) throw new ParseError(`stream ${e.path} is larger than ${max} bytes`);
    if (e.type === 'stream' && e.size < this.miniCutoff) {
      if (!this.miniStream) { const root = this.entries[0]!; this.miniStream = this.chainBytes(root.startSector, this.fat, this.sectorSize, (s) => this.secOff(s), Math.max(root.size, 0) + this.sectorSize); }
      const ms = this.miniStream;
      return this.chainBytes(e.startSector, this.miniFat, this.miniSectorSize, (s) => { const o = s * this.miniSectorSize; if (o + this.miniSectorSize > ms.length) throw new ParseError(`mini sector ${s} out of range`); return o; }, e.size + this.miniSectorSize).subarray(0, e.size);
    }
    return this.chainBytes(e.startSector, this.fat, this.sectorSize, (s) => this.secOff(s), e.size + this.sectorSize).subarray(0, e.size);
  }

  /** Find a stream by path (case-insensitive). */
  stream(path: string): CfbEntry | undefined { const p = path.toLowerCase(); return this.entries.find((e) => e.type === 'stream' && e.path.toLowerCase() === p); }
  streams(): CfbEntry[] { return this.entries.filter((e) => e.type === 'stream' && e.path); }
}
