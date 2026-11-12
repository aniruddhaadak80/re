// ZIP central directory reader with Zip64 support, used by the MSIX and APPX views. It keeps the
// local header size of each member, which the MSIX block map records as LfhSize.

import { BinView, FormatError } from './util.js';
import { decompress } from '../archive/inflate.js';
import { decodeUtf8 } from '../bytes.js';

export interface ZipMember { name: string; method: number; compressedSize: number; size: number; crc32: number; localOffset: number; flags: number; dataOffset: number; localHeaderSize: number }

/** List members. Returns the members and the offset of the central directory. */
export function readZip(bytes: Uint8Array, opts: { maxMembers?: number } = {}): { members: ZipMember[]; centralDirectory: number; zip64: boolean; comment: string } {
  const max = opts.maxMembers ?? 200_000;
  const v = new BinView(bytes);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) throw new FormatError('no ZIP end of central directory record');
  let count = v.u16le(eocd + 10);
  let cd = v.u32le(eocd + 16);
  let zip64 = false;
  const comment = decodeUtf8(v.sub(eocd + 22, Math.min(v.u16le(eocd + 20), bytes.length - eocd - 22)));
  // Zip64 locator sits 20 bytes before the EOCD.
  if (eocd >= 20 && v.u32le(eocd - 20) === 0x07064b50) {
    const rec = v.u64le(eocd - 12);
    if (v.has(rec, 56) && v.u32le(rec) === 0x06064b50) { zip64 = true; count = v.u64le(rec + 32); cd = v.u64le(rec + 48); }
  }
  const members: ZipMember[] = [];
  let p = cd;
  for (let i = 0; i < count && i < max; i++) {
    if (!v.has(p, 46) || v.u32le(p) !== 0x02014b50) throw new FormatError('broken central directory entry', p);
    const flags = v.u16le(p + 8), method = v.u16le(p + 10), crc = v.u32le(p + 16);
    let csize = v.u32le(p + 20), usize = v.u32le(p + 24);
    const nlen = v.u16le(p + 28), xlen = v.u16le(p + 30), clen = v.u16le(p + 32);
    let local = v.u32le(p + 42);
    const name = decodeUtf8(v.sub(p + 46, nlen));
    // Zip64 extended information extra field
    let x = p + 46 + nlen;
    const xend = x + xlen;
    while (x + 4 <= xend && v.has(x, 4)) {
      const id = v.u16le(x), sz = v.u16le(x + 2);
      if (id === 1) {
        let q = x + 4;
        if (usize === 0xffffffff && q + 8 <= x + 4 + sz) { usize = v.u64le(q); q += 8; }
        if (csize === 0xffffffff && q + 8 <= x + 4 + sz) { csize = v.u64le(q); q += 8; }
        if (local === 0xffffffff && q + 8 <= x + 4 + sz) { local = v.u64le(q); q += 8; }
      }
      x += 4 + sz;
    }
    let dataOffset = -1, lfh = 0;
    if (v.has(local, 30) && v.u32le(local) === 0x04034b50) { lfh = 30 + v.u16le(local + 26) + v.u16le(local + 28); dataOffset = local + lfh; }
    members.push({ name, method, compressedSize: csize, size: usize, crc32: crc, localOffset: local, flags, dataOffset, localHeaderSize: lfh });
    p += 46 + nlen + xlen + clen;
  }
  return { members, centralDirectory: cd, zip64, comment };
}

/** Decompressed bytes of a member (stored or deflate). */
export async function readZipMember(bytes: Uint8Array, m: ZipMember, maxBytes = 256 * 1024 * 1024): Promise<Uint8Array> {
  if (m.dataOffset < 0 || m.dataOffset + m.compressedSize > bytes.length) throw new FormatError(`${m.name}: data is outside the file`, m.localOffset);
  if (m.size > maxBytes) throw new FormatError(`${m.name}: ${m.size} bytes is over the ${maxBytes} byte limit`);
  const raw = bytes.subarray(m.dataOffset, m.dataOffset + m.compressedSize);
  if (m.method === 0) return raw;
  if (m.method === 8) return decompress(raw, 'deflate-raw', Math.max(m.size, 1) + 64);
  throw new FormatError(`${m.name}: ZIP method ${m.method} is not supported`);
}
