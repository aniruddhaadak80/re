// Minimal ZIP reader (central directory, stored and deflate members, ZIP64 sizes) used by
// sigrok sessions, HarmonyOS packages and firmware carving. Pure TypeScript, bounds checked.

import { ParseError, utf8, latin1, crc32 } from '../util.js';
import { inflateRaw } from './inflate.js';

export interface ZipEntry { name: string; method: number; compressedSize: number; size: number; crc: number; localOffset: number; dataOffset: number; flags: number; isDir: boolean }

const u16 = (b: Uint8Array, o: number) => (b[o] as number) | ((b[o + 1] as number) << 8);
const u32 = (b: Uint8Array, o: number) => ((b[o] as number) | ((b[o + 1] as number) << 8) | ((b[o + 2] as number) << 16) | ((b[o + 3] as number) << 24)) >>> 0;

/** Find the end of central directory and list entries. */
export function zipEntries(b: Uint8Array, opts: { maxEntries?: number; base?: number } = {}): ZipEntry[] {
  const base = opts.base ?? 0;
  let eocd = -1;
  for (let o = b.length - 22; o >= Math.max(base, b.length - 22 - 65535); o--) {
    if (b[o] === 0x50 && b[o + 1] === 0x4b && b[o + 2] === 5 && b[o + 3] === 6) { eocd = o; break; }
  }
  if (eocd < 0) throw new ParseError('zip end of central directory not found');
  let count = u16(b, eocd + 10);
  let cdOff = u32(b, eocd + 16);
  // ZIP64 locator
  if ((cdOff === 0xffffffff || count === 0xffff) && eocd >= 20 && u32(b, eocd - 20) === 0x07064b50) {
    const z = Number(new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(eocd - 12, true));
    if (z + 56 <= b.length && u32(b, z) === 0x06064b50) {
      const dv = new DataView(b.buffer, b.byteOffset + z, 56);
      count = Number(dv.getBigUint64(32, true));
      cdOff = Number(dv.getBigUint64(48, true));
    }
  }
  // archives embedded at an offset (self extracting, appended): shift by the difference
  const cdSize = u32(b, eocd + 12);
  let shift = 0;
  if (cdOff + cdSize <= eocd && u32(b, cdOff) !== 0x02014b50 && eocd - cdSize >= 0 && u32(b, eocd - cdSize) === 0x02014b50) shift = eocd - cdSize - cdOff;
  const max = Math.min(count, opts.maxEntries ?? 100000);
  const out: ZipEntry[] = [];
  let p = cdOff + shift;
  for (let k = 0; k < max; k++) {
    if (p + 46 > b.length || u32(b, p) !== 0x02014b50) throw new ParseError('bad zip central directory entry', p);
    const flags = u16(b, p + 8), method = u16(b, p + 10);
    let csize = u32(b, p + 20), size = u32(b, p + 24);
    const nlen = u16(b, p + 28), xlen = u16(b, p + 30), clen = u16(b, p + 32);
    let loff = u32(b, p + 42);
    if (p + 46 + nlen + xlen > b.length) throw new ParseError('zip entry name out of range', p);
    const nameBytes = b.subarray(p + 46, p + 46 + nlen);
    const name = flags & 0x800 ? utf8(nameBytes) : latin1(nameBytes);
    // ZIP64 extra field
    let x = p + 46 + nlen;
    const xend = x + xlen;
    while (x + 4 <= xend) {
      const id = u16(b, x), sz = u16(b, x + 2);
      if (id === 1) {
        let q = x + 4;
        const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
        if (size === 0xffffffff && q + 8 <= xend) { size = Number(dv.getBigUint64(q, true)); q += 8; }
        if (csize === 0xffffffff && q + 8 <= xend) { csize = Number(dv.getBigUint64(q, true)); q += 8; }
        if (loff === 0xffffffff && q + 8 <= xend) { loff = Number(dv.getBigUint64(q, true)); q += 8; }
      }
      x += 4 + sz;
    }
    loff += shift;
    let dataOffset = -1;
    if (loff + 30 <= b.length && u32(b, loff) === 0x04034b50) dataOffset = loff + 30 + u16(b, loff + 26) + u16(b, loff + 28);
    out.push({ name, method, compressedSize: csize, size, crc: u32(b, p + 16), localOffset: loff, dataOffset, flags, isDir: name.endsWith('/') });
    p += 46 + nlen + xlen + clen;
  }
  return out;
}

/** Read one member (stored or deflate), capped, CRC checked. */
export function zipRead(b: Uint8Array, e: ZipEntry, maxOut = 256 << 20): Uint8Array {
  if (e.dataOffset < 0 || e.dataOffset + e.compressedSize > b.length) throw new ParseError(`zip member ${e.name} data out of range`);
  if (e.flags & 1) throw new ParseError(`zip member ${e.name} is encrypted`);
  if (e.size > maxOut) throw new ParseError(`zip member ${e.name} is larger than the limit`);
  const raw = b.subarray(e.dataOffset, e.dataOffset + e.compressedSize);
  let data: Uint8Array;
  if (e.method === 0) data = raw.slice();
  else if (e.method === 8) data = inflateRaw(raw, { maxOut: Math.min(maxOut, e.size + 1024) }).data;
  else throw new ParseError(`zip member ${e.name} uses unsupported method ${e.method}`);
  if (data.length !== e.size || crc32(data) >>> 0 !== e.crc) throw new ParseError(`zip member ${e.name} failed its size or CRC check`);
  return data;
}

export function isZip(b: Uint8Array): boolean { return b.length >= 22 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5) ; }
