// SquashFS 4.0 extraction (little endian): inodes, directories, data blocks, fragments and sparse
// blocks, with gzip (zlib), lzma, lzo, xz, lz4 and zstd compression, all decoded in TypeScript.
// Synchronous and capped: entries, total output and per file size.

import { View, ParseError, utf8, unixTime } from '../util.js';
import { inflateZlib } from '../compress/inflate.js';
import { lzmaAloneDecode, xzDecode } from '../compress/lzma.js';
import { lzo1xDecompress } from '../compress/lzo.js';
import { zstdDecodeFrame } from '../compress/zstd.js';
import { lz4Block } from '../containers/lz4.js';

export const SQUASHFS_COMPRESSORS: Record<number, string> = { 1: 'gzip', 2: 'lzma', 3: 'lzo', 4: 'xz', 5: 'lz4', 6: 'zstd' };

export interface SquashSuper {
  offset: number; inodes: number; mkfsTime: string | null; blockSize: number; fragments: number; compression: string; compressionId: number; flags: number;
  idCount: number; version: string; rootInode: bigint; bytesUsed: number; idTable: number; xattrTable: number; inodeTable: number; directoryTable: number; fragmentTable: number; exportTable: number;
}

export interface SquashFileEntry {
  path: string; type: 'dir' | 'file' | 'symlink' | 'block' | 'char' | 'fifo' | 'socket';
  mode: string; uid: number; gid: number; mtime: number; inode: number; size?: number; target?: string; rdev?: number; nlink?: number;
  data?: Uint8Array; error?: string;
}

export interface SquashExtractOptions { maxEntries?: number; maxFileSize?: number; maxTotal?: number; withData?: boolean; deadline?: number }

const NONE = 0xffffffff;

export function readSquashSuper(b: Uint8Array, off = 0): SquashSuper {
  const v = new View(b, true);
  if (v.u32(off) !== 0x73717368) throw new ParseError(v.u32(off) === 0x68737173 ? 'big endian squashfs is not supported' : 'not a squashfs image', off);
  const major = v.u16(off + 28), minor = v.u16(off + 30);
  if (major !== 4) throw new ParseError(`squashfs ${major}.${minor} is not supported (4.0 only)`, off);
  const blockSize = v.u32(off + 12), blockLog = v.u16(off + 22);
  if (blockSize < 4096 || blockSize > 1 << 20 || 1 << blockLog !== blockSize) throw new ParseError('bad squashfs block size', off);
  const u64 = (o: number) => { const x = v.u64(off + o); return x === 0xffffffffffffffffn ? -1 : Number(x); };
  return {
    offset: off, inodes: v.u32(off + 4), mkfsTime: unixTime(v.u32(off + 8)), blockSize, fragments: v.u32(off + 16), compressionId: v.u16(off + 20), compression: SQUASHFS_COMPRESSORS[v.u16(off + 20)] ?? `id ${v.u16(off + 20)}`,
    flags: v.u16(off + 24), idCount: v.u16(off + 26), version: `${major}.${minor}`, rootInode: v.u64(off + 32), bytesUsed: u64(40), idTable: u64(48), xattrTable: u64(56), inodeTable: u64(64), directoryTable: u64(72), fragmentTable: u64(80), exportTable: u64(88),
  };
}

/** Decompress one squashfs block with the image's compressor. */
export function squashDecompress(id: number, src: Uint8Array, max: number): Uint8Array {
  switch (id) {
    case 1: return inflateZlib(src, { maxOut: max }).data;
    case 2: return lzmaAloneDecode(src, { maxOut: max }).data;
    case 3: return lzo1xDecompress(src, { maxOut: max }).data;
    case 4: return xzDecode(src, { maxOut: max }).data;
    case 5: {
      // LZ4 block: the output size is not stored; try the full size and shrink on the error message
      for (let size = max; size > 0;) {
        try { return lz4Block(src, size, max); } catch (e) {
          const m = /LZ4 produced (\d+) bytes/.exec((e as Error).message);
          if (m && Number(m[1]) < size) { size = Number(m[1]); continue; }
          throw e;
        }
      }
      return new Uint8Array(0);
    }
    case 6: return zstdDecodeFrame(src, { maxOut: max }).data;
    default: throw new ParseError(`squashfs compressor ${SQUASHFS_COMPRESSORS[id] ?? id} is not supported`);
  }
}

/** Extract a squashfs 4.0 image at `off`: all entries, and file data when withData is set. */
export function extractSquashfs(b: Uint8Array, off = 0, opts: SquashExtractOptions = {}): { super: SquashSuper; entries: SquashFileEntry[]; truncated: boolean; totalBytes: number; errors: string[] } {
  const sb = readSquashSuper(b, off);
  const v = new View(b, true);
  const maxEntries = opts.maxEntries ?? 50000;
  const maxFile = opts.maxFileSize ?? 64 << 20;
  const maxTotal = opts.maxTotal ?? 512 << 20;
  const errors: string[] = [];
  const end = sb.bytesUsed > 0 ? Math.min(b.length, off + sb.bytesUsed) : b.length;
  const abs = (x: number) => { const a = off + x; if (x < 0 || a > end) throw new ParseError('squashfs table offset out of range', a); return a; };
  const cache = new Map<number, { data: Uint8Array; next: number }>();
  const meta = (a: number): { data: Uint8Array; next: number } => {
    const c = cache.get(a);
    if (c) return c;
    const hdr = v.u16(a);
    const len = hdr & 0x7fff;
    if (a + 2 + len > end) throw new ParseError('squashfs metadata block out of range', a);
    const raw = v.sub(a + 2, len);
    const data = hdr & 0x8000 ? raw : squashDecompress(sb.compressionId, raw, 8192);
    const r = { data, next: a + 2 + len };
    if (cache.size > 200000) cache.clear();
    cache.set(a, r);
    return r;
  };
  const readMeta = (tableStart: number, block: number, offset: number, n: number): { bytes: Uint8Array; block: number; offset: number } => {
    const out = new Uint8Array(n);
    let got = 0, blk = block, o = offset;
    for (let guard = 0; got < n; guard++) {
      if (guard > 100000) throw new ParseError('squashfs metadata read did not progress');
      const m = meta(tableStart + blk);
      const take = Math.min(n - got, m.data.length - o);
      if (take <= 0) { if (m.next >= end) throw new ParseError('squashfs metadata out of range'); blk = m.next - tableStart; o = 0; continue; }
      out.set(m.data.subarray(o, o + take), got);
      got += take; o += take;
      if (o >= m.data.length) { blk = m.next - tableStart; o = 0; }
    }
    return { bytes: out, block: blk, offset: o };
  };
  const inodeTable = abs(sb.inodeTable), dirTable = abs(sb.directoryTable);
  // fragment table
  const fragments: { start: number; size: number }[] = [];
  if (sb.fragments && sb.fragmentTable >= 0 && sb.fragments < 1 << 22) {
    const ft = abs(sb.fragmentTable);
    const nIdx = Math.ceil(sb.fragments / 512);
    for (let k = 0; k < nIdx; k++) {
      const ptr = v.u64n(ft + k * 8);
      const count = Math.min(512, sb.fragments - k * 512);
      const blk = readMeta(off + ptr, 0, 0, count * 16).bytes;
      const bv = new View(blk, true);
      for (let j = 0; j < count; j++) fragments.push({ start: bv.u64n(j * 16), size: bv.u32(j * 16 + 8) });
    }
  }
  // uid/gid table
  const ids: number[] = [];
  if (sb.idCount && sb.idTable >= 0 && sb.idCount <= 65536) {
    const it = abs(sb.idTable);
    for (let k = 0; k < Math.ceil(sb.idCount / 2048); k++) {
      const ptr = v.u64n(it + k * 8);
      const count = Math.min(2048, sb.idCount - k * 2048);
      const blk = new View(readMeta(off + ptr, 0, 0, count * 4).bytes, true);
      for (let j = 0; j < count; j++) ids.push(blk.u32(j * 4));
    }
  }
  interface Inode { type: number; mode: number; uid: number; gid: number; mtime: number; inode: number; dirBlock?: number; dirOffset?: number; dirSize?: number; size?: number; blocksStart?: number; fragment?: number; fragOffset?: number; blockSizes?: number[]; target?: string; rdev?: number; nlink?: number }
  const readInode = (ref: bigint): Inode => {
    const h = readMeta(inodeTable, Number(ref >> 16n), Number(ref & 0xffffn), 16);
    const hv = new View(h.bytes, true);
    const type = hv.u16(0);
    const r: Inode = { type, mode: hv.u16(2), uid: ids[hv.u16(4)] ?? hv.u16(4), gid: ids[hv.u16(6)] ?? hv.u16(6), mtime: hv.u32(8), inode: hv.u32(12) };
    const more = (n: number) => { const x = readMeta(inodeTable, h.block, h.offset, n); return x; };
    if (type === 1) { const x = new View(more(16).bytes, true); r.dirBlock = x.u32(0); r.nlink = x.u32(4); r.dirSize = x.u16(8); r.dirOffset = x.u16(10); }
    else if (type === 8) { const x = new View(more(24).bytes, true); r.nlink = x.u32(0); r.dirSize = x.u32(4); r.dirBlock = x.u32(8); r.dirOffset = x.u16(18); }
    else if (type === 2 || type === 9) {
      const fixed = type === 2 ? 16 : 40;
      const m1 = more(fixed);
      const x = new View(m1.bytes, true);
      if (type === 2) { r.blocksStart = x.u32(0); r.fragment = x.u32(4); r.fragOffset = x.u32(8); r.size = x.u32(12); r.nlink = 1; }
      else { r.blocksStart = x.u64n(0); r.size = x.u64n(8); r.nlink = x.u32(24); r.fragment = x.u32(28); r.fragOffset = x.u32(32); }
      const size = r.size ?? 0;
      const nb = r.fragment === NONE ? Math.ceil(size / sb.blockSize) : Math.floor(size / sb.blockSize);
      if (nb > 1 << 22) throw new ParseError('squashfs file has too many blocks');
      const bs = new View(readMeta(inodeTable, m1.block, m1.offset, nb * 4).bytes, true);
      r.blockSizes = [];
      for (let k = 0; k < nb; k++) r.blockSizes.push(bs.u32(k * 4));
    } else if (type === 3 || type === 10) {
      const x1 = more(8);
      const xv = new View(x1.bytes, true);
      r.nlink = xv.u32(0);
      const tl = xv.u32(4);
      if (tl > 65536) throw new ParseError('squashfs symlink target too long');
      r.target = utf8(readMeta(inodeTable, x1.block, x1.offset, tl).bytes);
    } else if (type === 4 || type === 5 || type === 11 || type === 12) { const x = new View(more(8).bytes, true); r.nlink = x.u32(0); r.rdev = x.u32(4); }
    else if (type === 6 || type === 7 || type === 13 || type === 14) { r.nlink = new View(more(4).bytes, true).u32(0); }
    else throw new ParseError(`squashfs inode type ${type} is unknown`);
    return r;
  };
  let total = 0;
  const fileData = (ino: Inode): Uint8Array => {
    const size = ino.size ?? 0;
    if (size > maxFile) throw new ParseError(`file larger than the ${maxFile} byte limit`);
    if (total + size > maxTotal) throw new ParseError('total extracted size limit reached');
    const out = new Uint8Array(size);
    let pos = off + (ino.blocksStart ?? 0), o = 0;
    for (const w of ino.blockSizes ?? []) {
      const len = w & 0xffffff;
      const want = Math.min(sb.blockSize, size - o);
      if (len === 0) { o += want; continue; } // sparse
      if (pos + len > end) throw new ParseError('squashfs data block out of range', pos);
      const raw = b.subarray(pos, pos + len);
      const d = w & 0x1000000 ? raw : squashDecompress(sb.compressionId, raw, sb.blockSize);
      out.set(d.subarray(0, want), o);
      o += want; pos += len;
    }
    if (ino.fragment !== undefined && ino.fragment !== NONE) {
      const f = fragments[ino.fragment];
      if (!f) throw new ParseError('squashfs fragment index out of range');
      const len = f.size & 0xffffff;
      if (off + f.start + len > end) throw new ParseError('squashfs fragment out of range');
      const raw = b.subarray(off + f.start, off + f.start + len);
      const d = f.size & 0x1000000 ? raw : squashDecompress(sb.compressionId, raw, sb.blockSize);
      const tail = size - o;
      if ((ino.fragOffset ?? 0) + tail > d.length) throw new ParseError('squashfs fragment shorter than the file tail');
      out.set(d.subarray(ino.fragOffset ?? 0, (ino.fragOffset ?? 0) + tail), o);
      o += tail;
    }
    total += size;
    return out;
  };
  const TYPE: Record<number, SquashFileEntry['type']> = { 1: 'dir', 2: 'file', 3: 'symlink', 4: 'block', 5: 'char', 6: 'fifo', 7: 'socket', 8: 'dir', 9: 'file', 10: 'symlink', 11: 'block', 12: 'char', 13: 'fifo', 14: 'socket' };
  const entries: SquashFileEntry[] = [];
  let truncated = false;
  const seenDirs = new Set<string>();
  const walk = (dir: Inode, path: string, depth: number): void => {
    if (depth > 128 || dir.dirBlock === undefined || dir.dirSize === undefined || dir.dirOffset === undefined) return;
    const key = `${dir.dirBlock}:${dir.dirOffset}`;
    if (seenDirs.has(key)) { errors.push(`directory loop at ${path || '/'}`); return; }
    seenDirs.add(key);
    let remaining = dir.dirSize - 3;
    let blk = dir.dirBlock, o = dir.dirOffset;
    while (remaining > 12) {
      if (opts.deadline && Date.now() > opts.deadline) { truncated = true; return; }
      const hdr = readMeta(dirTable, blk, o, 12);
      blk = hdr.block; o = hdr.offset; remaining -= 12;
      const hv = new View(hdr.bytes, true);
      const count = hv.u32(0) + 1, start = hv.u32(4), base = hv.u32(8);
      if (count > 256) throw new ParseError('bad squashfs directory header');
      for (let i = 0; i < count && remaining > 0; i++) {
        const e = readMeta(dirTable, blk, o, 8);
        const ev = new View(e.bytes, true);
        const ioff = ev.u16(0), nameSize = ev.u16(6) + 1;
        void base;
        const nm = readMeta(dirTable, e.block, e.offset, nameSize);
        blk = nm.block; o = nm.offset; remaining -= 8 + nameSize;
        const name = utf8(nm.bytes);
        if (entries.length >= maxEntries) { truncated = true; return; }
        const p = `${path}/${name}`;
        let child: Inode;
        try { child = readInode((BigInt(start) << 16n) | BigInt(ioff)); } catch (err) { errors.push(`${p}: ${(err as Error).message}`); continue; }
        const t = TYPE[child.type] ?? 'file';
        const ent: SquashFileEntry = { path: p, type: t, mode: (child.mode & 0o7777).toString(8).padStart(4, '0'), uid: child.uid, gid: child.gid, mtime: child.mtime, inode: child.inode, ...(child.nlink !== undefined ? { nlink: child.nlink } : {}) };
        if (t === 'file') {
          ent.size = child.size;
          if (opts.withData) { try { ent.data = fileData(child); } catch (err) { ent.error = (err as Error).message; errors.push(`${p}: ${ent.error}`); } }
        }
        if (child.target !== undefined) ent.target = child.target;
        if (child.rdev !== undefined) ent.rdev = child.rdev;
        entries.push(ent);
        if (t === 'dir') walk(child, p, depth + 1);
      }
    }
  };
  walk(readInode(sb.rootInode), '', 0);
  return { super: sb, entries, truncated, totalBytes: total, errors };
}
