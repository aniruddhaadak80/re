// Firmware extraction (binwalk/unblob style, pure TypeScript): carve known formats out of a blob,
// unpack them (gzip, xz, lzma, zstd, lz4, zip, cpio, tar, squashfs, uImage, FIT, TRX, Android boot
// and vendor_boot images v0 to v4, UEFI firmware volumes with FFS files and LZMA sections) and
// recurse into what comes out, with depth, count, size and time limits. Member names are
// sanitized so nothing can escape the output root. Browser safe: results stay in memory; the
// Node entry writes them to disk (writeExtraction in ../node.ts).

import { sha256 } from '@revlens/core';
import { View, ParseError, latin1, guid, utf8, crc32 } from '../util.js';
import { gunzipMember, inflateRaw } from '../compress/inflate.js';
import { lzmaAloneDecode, looksLikeLzmaAlone, xzDecode } from '../compress/lzma.js';
import { lzo1xDecompress, lzopDecode, LZOP_MAGIC } from '../compress/lzo.js';
import { zstdDecodeFrame } from '../compress/zstd.js';
import { zipEntries, zipRead } from '../compress/zip.js';
import { lz4Block } from '../containers/lz4.js';
import { tarEntries } from '../signals/recording.js';
import { extractSquashfs } from './squashfs.js';
import { parseUImage, parseFdt, parseCpio } from './firmware.js';

export interface ExtractOptions {
  maxDepth?: number; maxFiles?: number; maxTotalBytes?: number; maxFileSize?: number; timeBudgetMs?: number;
  /** Also emit the bytes between recognised chunks as unknown-*.bin files. */
  carveUnknown?: boolean;
  /** Keep file bytes in the result (needed to write them out). Default true. */
  keepData?: boolean;
  /** Formats to skip by type name. */
  skip?: string[];
}

export interface ExtractedFile {
  path: string; kind: 'file' | 'dir' | 'symlink' | 'device'; size: number; sha256?: string; data?: Uint8Array;
  target?: string; mode?: string; depth: number;
  /** The chain of formats that produced this file, outermost first. */
  via: string[];
  offset?: number;
}
export interface ExtractChunk { path: string; offset: number; end: number; type: string; description: string; depth: number; children: number; error?: string }
export interface ExtractResult {
  chunks: ExtractChunk[]; files: ExtractedFile[]; unknown: { path: string; offset: number; end: number }[];
  warnings: string[]; truncated: boolean; stats: { files: number; bytes: number; chunks: number; maxDepthReached: number; ms: number };
}

interface Member { name: string; kind: ExtractedFile['kind']; data?: Uint8Array; target?: string; mode?: string; offset?: number }
interface Unpacked { end: number; description: string; members: Member[]; /** When true the members are parts of the same blob and are not re-carved as one */ leaf?: boolean }
type Handler = (b: Uint8Array, off: number, ctx: Ctx) => Unpacked | undefined;
interface Ctx { opts: Required<Omit<ExtractOptions, 'skip'>> & { skip: Set<string> }; warn: (m: string) => void; budget: () => boolean; maxOut: () => number }

const u32le = (b: Uint8Array, o: number) => ((b[o] as number) | ((b[o + 1] as number) << 8) | ((b[o + 2] as number) << 16) | ((b[o + 3] as number) << 24)) >>> 0;
const u32be = (b: Uint8Array, o: number) => (((b[o] as number) << 24) | ((b[o + 1] as number) << 16) | ((b[o + 2] as number) << 8) | (b[o + 3] as number)) >>> 0;
const startsAt = (b: Uint8Array, o: number, sig: ArrayLike<number>) => { if (o + sig.length > b.length) return false; for (let k = 0; k < sig.length; k++) if (b[o + k] !== sig[k]) return false; return true; };
const al = (n: number, a: number) => Math.ceil(n / a) * a;

/** Make an archive member name safe: no absolute paths, no .. segments, no control characters. */
export function sanitizeMemberPath(name: string, warn?: (m: string) => void): string {
  const segs: string[] = [];
  for (const raw of name.replace(/\\/g, '/').split('/')) {
    if (raw === '' || raw === '.') continue;
    if (raw === '..') { warn?.(`path traversal segment removed from member name ${JSON.stringify(name.slice(0, 200))}`); continue; }
    let s = '';
    for (const ch of raw) { const c = ch.codePointAt(0)!; s += c < 0x20 || c === 0x7f ? '_' : ch; }
    if (new TextEncoder().encode(s).length > 255) s = s.slice(0, 200) + '~';
    segs.push(s);
    if (segs.length > 64) break;
  }
  return segs.join('/') || 'unnamed';
}

// ---------------- LZ4 frames ----------------
function lz4FrameDecode(b: Uint8Array, off: number, max: number): { data: Uint8Array; end: number } {
  let p = off + 4;
  if (p + 3 > b.length) throw new ParseError('LZ4 frame header truncated');
  const flg = b[p] as number, bd = b[p + 1] as number;
  if ((flg >> 6) !== 1) throw new ParseError('LZ4 frame version is not 1');
  const blockMax = [0, 0, 0, 0, 64 << 10, 256 << 10, 1 << 20, 4 << 20][(bd >> 4) & 7] as number;
  if (!blockMax) throw new ParseError('bad LZ4 block max size');
  const blockChecksum = (flg >> 4) & 1, contentSize = (flg >> 3) & 1, contentChecksum = (flg >> 2) & 1, dictId = flg & 1;
  p += 2 + (contentSize ? 8 : 0) + (dictId ? 4 : 0) + 1;
  const parts: Uint8Array[] = [];
  let total = 0;
  for (let guard = 0; ; guard++) {
    if (guard > 1_000_000) throw new ParseError('too many LZ4 blocks');
    if (p + 4 > b.length) throw new ParseError('LZ4 frame truncated');
    const w = u32le(b, p); p += 4;
    if (w === 0) break;
    const size = w & 0x7fffffff;
    if (p + size > b.length) throw new ParseError('LZ4 block runs past the end');
    let d: Uint8Array;
    if (w & 0x80000000) d = b.slice(p, p + size);
    else d = lz4Decode(b.subarray(p, p + size), blockMax);
    total += d.length;
    if (total > max) throw new ParseError('LZ4 output limit reached');
    parts.push(d);
    p += size + (blockChecksum ? 4 : 0);
  }
  if (contentChecksum) p += 4;
  return { data: concat(parts, total), end: p };
}
function lz4Decode(src: Uint8Array, maxOut: number): Uint8Array {
  for (let size = maxOut; ;) {
    try { return lz4Block(src, size, maxOut); } catch (e) {
      const m = /LZ4 produced (\d+) bytes/.exec((e as Error).message);
      if (m && Number(m[1]) < size) { size = Number(m[1]); continue; }
      throw e;
    }
  }
}
/** LZ4 legacy frames (Linux kernel and Android ramdisks): magic, then size-prefixed 8 MiB blocks until EOF or a non block. */
function lz4LegacyDecode(b: Uint8Array, off: number, max: number): { data: Uint8Array; end: number } {
  let p = off + 4;
  const parts: Uint8Array[] = [];
  let total = 0;
  while (p + 4 <= b.length) {
    const size = u32le(b, p);
    if (size === 0x184c2102) { p += 4; continue; } // concatenated legacy streams
    if (size === 0 || size > (8 << 20) + (8 << 20) / 255 + 16 || p + 4 + size > b.length) break;
    let d: Uint8Array;
    try { d = lz4Decode(b.subarray(p + 4, p + 4 + size), 8 << 20); } catch { break; }
    total += d.length;
    if (total > max) throw new ParseError('LZ4 output limit reached');
    parts.push(d);
    p += 4 + size;
    if (d.length < 8 << 20) break;
  }
  if (!parts.length) throw new ParseError('LZ4 legacy stream has no valid block');
  return { data: concat(parts, total), end: p };
}
function concat(parts: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let o = 0;
  for (const d of parts) { out.set(d, o); o += d.length; }
  return out;
}

// ---------------- payload decompression by name (uImage, FIT, TRX loader) ----------------
function decompressNamed(kind: string, d: Uint8Array, max: number): Uint8Array | undefined {
  switch (kind) {
    case 'gzip': return gunzipMember(d, { maxOut: max }).data;
    case 'lzma': return lzmaAloneDecode(d, { maxOut: max }).data;
    case 'xz': return xzDecode(d, { maxOut: max }).data;
    case 'lzo': return startsAt(d, 0, LZOP_MAGIC) ? lzopDecode(d, { maxOut: max }).data : lzo1xDecompress(d, { maxOut: max }).data;
    case 'lz4': return startsAt(d, 0, [0x04, 0x22, 0x4d, 0x18]) ? lz4FrameDecode(d, 0, max).data : startsAt(d, 0, [0x02, 0x21, 0x4c, 0x18]) ? lz4LegacyDecode(d, 0, max).data : undefined;
    case 'zstd': return zstdDecodeFrame(d, { maxOut: max }).data;
    default: return undefined;
  }
}

// ---------------- handlers ----------------
const H: Record<string, Handler> = {
  gzip(b, off, ctx) {
    const m = gunzipMember(b, { start: off, maxOut: ctx.maxOut() });
    return { end: m.end, description: `gzip${m.name ? ` "${m.name}"` : ''}, ${m.data.length} bytes, CRC ${m.crcValid ? 'ok' : 'bad'}`, members: [{ name: m.name ? sanitizeMemberPath(m.name.split('/').pop() ?? m.name) : 'gzip.uncompressed', kind: 'file', data: m.data }] };
  },
  xz(b, off, ctx) {
    const r = xzDecode(b, { start: off, maxOut: ctx.maxOut() });
    return { end: r.end, description: `xz, ${r.blocks.length} block(s), check ${r.check}${r.blocks.some((x) => x.checkValid === false) ? ' FAILED' : ''}, ${r.data.length} bytes`, members: [{ name: 'xz.uncompressed', kind: 'file', data: r.data }] };
  },
  lzma(b, off, ctx) {
    if (!looksLikeLzmaAlone(b, off)) return undefined;
    const r = lzmaAloneDecode(b, { start: off, maxOut: ctx.maxOut() });
    if (r.data.length < 16) return undefined;
    return { end: r.end, description: `lzma (lc=${r.props.lc} lp=${r.props.lp} pb=${r.props.pb}, dictionary ${r.props.dictSize}), ${r.data.length} bytes`, members: [{ name: 'lzma.uncompressed', kind: 'file', data: r.data }] };
  },
  zstd(b, off, ctx) {
    const r = zstdDecodeFrame(b, { start: off, maxOut: ctx.maxOut() });
    return { end: r.frame.end, description: `zstd frame, ${r.frame.blocks} blocks, ${r.data.length} bytes`, members: [{ name: 'zstd.uncompressed', kind: 'file', data: r.data }] };
  },
  lz4(b, off, ctx) {
    const r = lz4FrameDecode(b, off, ctx.maxOut());
    return { end: r.end, description: `LZ4 frame, ${r.data.length} bytes`, members: [{ name: 'lz4.uncompressed', kind: 'file', data: r.data }] };
  },
  'lz4-legacy'(b, off, ctx) {
    const r = lz4LegacyDecode(b, off, ctx.maxOut());
    return { end: r.end, description: `LZ4 legacy frame, ${r.data.length} bytes`, members: [{ name: 'lz4.uncompressed', kind: 'file', data: r.data }] };
  },
  lzop(b, off, ctx) {
    const r = lzopDecode(b, { start: off, maxOut: ctx.maxOut() });
    return { end: r.end, description: `lzop "${r.name}", ${r.blocks} blocks, ${r.data.length} bytes`, members: [{ name: r.name ? sanitizeMemberPath(r.name.split('/').pop()!) : 'lzop.uncompressed', kind: 'file', data: r.data }] };
  },
  zip(b, off, ctx) {
    // find the end of central directory after this local header
    for (let e = off + 30, guard = 0; e + 22 <= b.length && guard < 64; guard++) {
      let k = e;
      for (; k + 4 <= b.length; k++) if (b[k] === 0x50 && b[k + 1] === 0x4b && b[k + 2] === 5 && b[k + 3] === 6) break;
      if (k + 22 > b.length) return undefined;
      const clen = (b[k + 20] as number) | ((b[k + 21] as number) << 8);
      const slice = b.subarray(off, Math.min(b.length, k + 22 + clen));
      try {
        const ents = zipEntries(slice);
        const members: Member[] = [];
        for (const en of ents) {
          if (!ctx.budget()) break;
          if (en.isDir) { members.push({ name: en.name, kind: 'dir' }); continue; }
          try { members.push({ name: en.name, kind: 'file', data: zipRead(slice, en, Math.min(ctx.maxOut(), ctx.opts.maxFileSize)), offset: off + en.dataOffset }); }
          catch (err) { ctx.warn(`zip member ${en.name}: ${(err as Error).message}`); }
        }
        return { end: off + slice.length, description: `zip archive, ${ents.length} entries`, members };
      } catch { e = k + 4; }
    }
    return undefined;
  },
  cpio(b, off) {
    const r = parseCpio(b, off, 200000);
    if (!r.entries.length) return undefined;
    const members: Member[] = r.entries.map((e) => {
      const kind: Member['kind'] = e.type === 'dir' ? 'dir' : e.type === 'symlink' ? 'symlink' : e.type === 'file' ? 'file' : 'device';
      return { name: e.name, kind, mode: e.mode, ...(kind === 'file' ? { data: b.subarray(e.offset, e.offset + e.size), offset: e.offset } : {}), ...(e.target !== undefined ? { target: e.target } : {}) };
    });
    return { end: r.end, description: `cpio ${r.format}, ${r.entries.length} entries${r.trailer ? '' : ', no trailer'}`, members };
  },
  tar(b, off) {
    if (latin1(b.subarray(off + 257, off + 262)) !== 'ustar') return undefined;
    const sub = b.subarray(off);
    const ents = tarEntries(sub, 100000);
    if (!ents.length) return undefined;
    const last = ents[ents.length - 1]!;
    let end = off + last.offset + Math.ceil(last.size / 512) * 512;
    while (end + 512 <= b.length && b.subarray(end, end + 512).every((x) => x === 0)) end += 512;
    return { end, description: `tar archive, ${ents.length} files`, members: ents.map((e) => ({ name: e.name, kind: 'file' as const, data: sub.subarray(e.offset, e.offset + e.size), offset: off + e.offset })) };
  },
  squashfs(b, off, ctx) {
    const r = extractSquashfs(b, off, { withData: true, maxEntries: ctx.opts.maxFiles, maxFileSize: ctx.opts.maxFileSize, maxTotal: ctx.maxOut(), deadline: Date.now() + ctx.opts.timeBudgetMs });
    for (const e of r.errors.slice(0, 20)) ctx.warn(`squashfs: ${e}`);
    const end = off + (r.super.bytesUsed > 0 ? r.super.bytesUsed : b.length - off);
    return {
      end: Math.min(b.length, end), description: `squashfs ${r.super.version}, ${r.super.compression}, block ${r.super.blockSize}, ${r.entries.length} entries, ${r.super.bytesUsed} bytes`,
      members: r.entries.map((e) => ({ name: e.path, kind: e.type === 'dir' ? 'dir' : e.type === 'symlink' ? 'symlink' : e.type === 'file' ? 'file' : 'device', mode: e.mode, ...(e.data ? { data: e.data } : {}), ...(e.target !== undefined ? { target: e.target } : {}) })),
    };
  },
  uimage(b, off, ctx) {
    const u = parseUImage(b, off);
    if (!u.headerCrcValid || off + 64 + u.size > b.length) return undefined;
    const payload = b.subarray(off + 64, off + 64 + u.size);
    const members: Member[] = [];
    const base = sanitizeMemberPath(u.name || 'uimage').replace(/\//g, '_');
    const add = (name: string, d: Uint8Array) => {
      let out: Uint8Array | undefined;
      try { out = decompressNamed(u.compression, d, ctx.maxOut()); } catch (e) { ctx.warn(`uImage ${u.name}: ${u.compression} payload did not decode: ${(e as Error).message}`); }
      members.push({ name: out ? name : `${name}.${u.compression === 'none' ? 'bin' : u.compression}`, kind: 'file', data: out ?? d });
    };
    if (u.multi?.length) {
      let p = 4 * (u.multi.length + 1);
      u.multi.forEach((s, k) => { if (p + s <= payload.length) add(`${base}.${k}`, payload.subarray(p, p + s)); p = al(p + s, 4); });
    } else add(u.compression === 'none' ? `${base}.bin` : base, payload);
    return { end: off + 64 + u.size, description: `uImage "${u.name}", ${u.os} ${u.arch} ${u.type}, ${u.compression}, ${u.size} bytes, data CRC ${u.dataCrcValid ? 'ok' : 'bad'}`, members, leaf: true };
  },
  fdt(b, off, ctx) {
    const total = u32be(b, off + 4);
    if (total < 40 || off + total > b.length) return undefined;
    const f = parseFdt(b, off);
    if (!f.fit) return { end: off + total, description: `device tree blob v${f.version}${f.model ? `, model "${f.model}"` : ''}, ${f.nodeCount} nodes`, members: [{ name: 'devicetree.dtb', kind: 'file', data: b.subarray(off, off + total) }], leaf: true };
    const members: Member[] = [];
    let end = off + total;
    for (const img of f.fit.images) {
      if (img.dataOffset === undefined || img.dataOffset + img.dataSize > b.length) { ctx.warn(`FIT image ${img.name} data is outside the blob`); continue; }
      end = Math.max(end, img.dataOffset + img.dataSize);
      const d = b.subarray(img.dataOffset, img.dataOffset + img.dataSize);
      let out: Uint8Array | undefined;
      if (img.compression && img.compression !== 'none') { try { out = decompressNamed(img.compression, d, ctx.maxOut()); } catch (e) { ctx.warn(`FIT image ${img.name}: ${(e as Error).message}`); } }
      const bad = img.hashes.filter((h) => h.matches === false).map((h) => h.algo);
      if (bad.length) ctx.warn(`FIT image ${img.name}: ${bad.join(', ')} hash mismatch`);
      members.push({ name: sanitizeMemberPath(img.name).replace(/\//g, '_') + (out || !img.compression || img.compression === 'none' ? '' : `.${img.compression}`), kind: 'file', data: out ?? d, offset: img.dataOffset });
    }
    return { end, description: `FIT image${f.fit.description ? ` "${f.fit.description}"` : ''}, ${f.fit.images.length} images, default config ${f.fit.defaultConfig ?? 'none'}`, members, leaf: true };
  },
  trx(b, off) {
    if (off + 28 > b.length) return undefined;
    const len = u32le(b, off + 4);
    if (len < 28 || off + len > b.length) return undefined;
    const crc = u32le(b, off + 8), fv = u32le(b, off + 12);
    const version = fv >>> 16;
    if (version !== 1 && version !== 2) return undefined;
    const crcOk = ((~crc32(b, off + 12, off + len)) >>> 0) === crc;
    const n = version >= 2 ? 4 : 3;
    const parts: number[] = [];
    for (let k = 0; k < n; k++) { const o = u32le(b, off + 16 + k * 4); if (o && o < len) parts.push(o); }
    const members: Member[] = parts.map((o, k) => ({ name: `partition${k}`, kind: 'file' as const, data: b.subarray(off + o, off + (parts[k + 1] ?? len)), offset: off + o }));
    return { end: off + len, description: `TRX v${version}, ${len} bytes, CRC ${crcOk ? 'ok' : 'bad'}, ${parts.length} partitions at ${parts.map((p) => '0x' + p.toString(16)).join(', ')}`, members, leaf: true };
  },
  'android-boot'(b, off) {
    const v = new View(b, true);
    const hv = v.u32(off + 40);
    const members: Member[] = [];
    const take = (name: string, o: number, size: number) => { if (size > 0 && off + o + size <= b.length) members.push({ name, kind: 'file', data: b.subarray(off + o, off + o + size), offset: off + o }); };
    let end: number;
    let desc: string;
    if (hv >= 3 && hv <= 4) {
      const pg = 4096;
      const ks = v.u32(off + 8), rs = v.u32(off + 12), hsize = v.u32(off + 20);
      const kOff = al(hsize, pg), rOff = kOff + al(ks, pg);
      let next = rOff + al(rs, pg);
      take('kernel', kOff, ks); take('ramdisk', rOff, rs);
      if (hv === 4) { const sig = v.u32(off + 1580); take('boot_signature', next, sig); next += al(sig, pg); }
      end = off + next;
      desc = `Android boot image v${hv}, kernel ${ks} bytes, ramdisk ${rs} bytes, cmdline "${v.cstr(off + 44, 1536).slice(0, 120)}"`;
    } else if (hv <= 2) {
      const ks = v.u32(off + 8), rs = v.u32(off + 16), ss = v.u32(off + 24), pg = v.u32(off + 36);
      if (![2048, 4096, 8192, 16384, 32768, 65536, 131072].includes(pg)) return undefined;
      let o = pg;
      take('kernel', o, ks); o += al(ks, pg);
      take('ramdisk', o, rs); o += al(rs, pg);
      take('second', o, ss); o += al(ss, pg);
      if (hv >= 1) { const ds = v.u32(off + 1632); take('recovery_dtbo', o, ds); o += al(ds, pg); }
      if (hv === 2) { const dt = v.u32(off + 1648); take('dtb', o, dt); o += al(dt, pg); }
      end = off + o;
      desc = `Android boot image v${hv}, page ${pg}, kernel ${ks} bytes, ramdisk ${rs} bytes${ss ? `, second ${ss} bytes` : ''}, name "${v.cstr(off + 48, 16)}", cmdline "${v.cstr(off + 64, 512).slice(0, 120)}"`;
    } else return undefined;
    return { end: Math.min(end, b.length), description: desc, members, leaf: true };
  },
  'vendor-boot'(b, off) {
    const v = new View(b, true);
    const hv = v.u32(off + 8), pg = v.u32(off + 12);
    if ((hv !== 3 && hv !== 4) || ![2048, 4096, 8192, 16384].includes(pg)) return undefined;
    const vr = v.u32(off + 24), hsize = v.u32(off + 2096), dtb = v.u32(off + 2100);
    const members: Member[] = [];
    let o = al(hsize, pg);
    const take = (name: string, size: number) => { if (size > 0 && off + o + size <= b.length) members.push({ name, kind: 'file', data: b.subarray(off + o, off + o + size), offset: off + o }); o += al(size, pg); };
    take('vendor_ramdisk', vr); take('dtb', dtb);
    if (hv === 4) { take('vendor_ramdisk_table', v.u32(off + 2112)); take('bootconfig', v.u32(off + 2124)); }
    return { end: Math.min(off + o, b.length), description: `Android vendor_boot v${hv}, vendor ramdisk ${vr} bytes, dtb ${dtb} bytes, name "${v.cstr(off + 2080, 16)}"`, members, leaf: true };
  },
  'uefi-fv'(b, off, ctx) {
    const r = uefiVolume(b, off, ctx, 0);
    if (!r) return undefined;
    return { end: r.end, description: r.description, members: r.members, leaf: true };
  },
  elf(b, off) {
    // compute the size from the section and program headers so carving skips the whole file
    const cls = b[off + 4], le = b[off + 5] === 1;
    if (cls !== 1 && cls !== 2) return undefined;
    const v = new View(b, le);
    let size = 0;
    try {
      if (cls === 2) {
        const phoff = v.u64n(off + 32), shoff = v.u64n(off + 40), phent = v.u16(off + 54), phnum = v.u16(off + 56), shent = v.u16(off + 58), shnum = v.u16(off + 60);
        size = Math.max(shoff + shent * shnum, phoff + phent * phnum);
        for (let k = 0; k < phnum && k < 4096; k++) { const p = off + phoff + k * phent; size = Math.max(size, v.u64n(p + 8) + v.u64n(p + 32)); }
        for (let k = 0; k < shnum && k < 65535; k++) { const s = off + shoff + k * shent; if (v.u32(s + 4) !== 8) size = Math.max(size, v.u64n(s + 24) + v.u64n(s + 32)); }
      } else {
        const phoff = v.u32(off + 28), shoff = v.u32(off + 32), phent = v.u16(off + 42), phnum = v.u16(off + 44), shent = v.u16(off + 46), shnum = v.u16(off + 48);
        size = Math.max(shoff + shent * shnum, phoff + phent * phnum);
        for (let k = 0; k < phnum && k < 4096; k++) { const p = off + phoff + k * phent; size = Math.max(size, v.u32(p + 4) + v.u32(p + 16)); }
        for (let k = 0; k < shnum && k < 65535; k++) { const s = off + shoff + k * shent; if (v.u32(s + 4) !== 8) size = Math.max(size, v.u32(s + 16) + v.u32(s + 20)); }
      }
    } catch { return undefined; }
    if (size < 52 || off + size > b.length) return undefined;
    return { end: off + size, description: `ELF ${cls === 2 ? '64' : '32'}-bit ${le ? 'LSB' : 'MSB'}, ${size} bytes`, members: [{ name: 'file.elf', kind: 'file', data: b.subarray(off, off + size) }], leaf: true };
  },
};

// ---------------- UEFI volumes, FFS files and sections ----------------
const LZMA_GUID = 'EE4E5898-3914-4259-9D6E-DC7BD79403CF';
const CRC32_GUID = 'FC1BCDB0-7D31-49AA-936A-A4600D9DD083';
const FFS_TYPES: Record<number, string> = { 1: 'raw', 2: 'freeform', 3: 'sec_core', 4: 'pei_core', 5: 'dxe_core', 6: 'peim', 7: 'driver', 8: 'combined_peim_driver', 9: 'application', 0xa: 'mm', 0xb: 'fv_image', 0xc: 'combined_mm_dxe', 0xd: 'mm_core', 0xe: 'mm_standalone', 0xf: 'mm_core_standalone', 0xf0: 'pad' };
const SEC_EXT: Record<number, string> = { 0x10: 'pe32.efi', 0x11: 'pic', 0x12: 'te', 0x13: 'dxe.depex', 0x14: 'version', 0x15: 'ui', 0x16: 'compat16', 0x17: 'fv', 0x18: 'freeform', 0x19: 'raw', 0x1b: 'pei.depex', 0x1c: 'mm.depex' };

function uefiVolume(b: Uint8Array, off: number, ctx: Ctx, depth: number): { end: number; description: string; members: Member[] } | undefined {
  if (off + 56 > b.length || latin1(b.subarray(off + 40, off + 44)) !== '_FVH') return undefined;
  const v = new View(b, true);
  const fsGuid = guid(b, off + 16);
  const length = v.u64n(off + 32);
  if (length < 0x48 || off + length > b.length) return undefined;
  const attrs = v.u32(off + 44), hlen = v.u16(off + 48);
  let sum = 0;
  for (let k = 0; k + 1 < hlen; k += 2) sum = (sum + v.u16(off + k)) & 0xffff;
  const ffs = fsGuid === '8C8CE578-8A3D-4F1C-9935-896185C32DD3' || fsGuid === '5473C07A-3DCB-4DCA-BD6F-1E9689E7349A' || fsGuid === '7A9354D9-0468-444A-81CE-0BF617D890DF';
  const members: Member[] = [];
  const erase = attrs & 0x800 ? 0xff : 0;
  let files = 0;
  if (ffs && depth < 8) {
    const end = off + length;
    let extHdr = v.u16(off + 52);
    let p = extHdr ? off + extHdr + v.u32(off + extHdr + 16) : off + hlen;
    p = (p + 7) & ~7;
    if (!extHdr) extHdr = 0;
    while (p + 24 <= end && ctx.budget()) {
      if (b.subarray(p, p + 24).every((x) => x === erase)) break;
      const g = guid(b, p);
      const type = v.u8(p + 18), attr = v.u8(p + 19);
      let size = v.u8(p + 20) | (v.u8(p + 21) << 8) | (v.u8(p + 22) << 16);
      let hdr = 24;
      if (attr & 0x01 && size === 0) { size = v.u64n(p + 24); hdr = 32; }
      if (size < hdr || p + size > end) break;
      files++;
      if (type !== 0xf0) {
        const dir = `${String(files).padStart(3, '0')}-${g}-${FFS_TYPES[type] ?? 'type' + type}`;
        const body = b.subarray(p + hdr, p + size);
        if (type === 1) members.push({ name: `${dir}/raw.bin`, kind: 'file', data: body, offset: p + hdr });
        else {
          const secs = uefiSections(body, ctx, depth, p + hdr);
          const ui = secs.find((s) => s.name.endsWith('.ui.txt'));
          const label = ui?.data ? `-${sanitizeMemberPath(utf8(ui.data)).replace(/\//g, '_').slice(0, 64)}` : '';
          for (const s of secs) members.push({ ...s, name: `${dir}${label}/${s.name}` });
        }
      }
      p = (p + size + 7) & ~7;
    }
  }
  return { end: off + length, description: `UEFI firmware volume ${fsGuid}${ffs ? `, ${files} files` : ''}, ${length} bytes, header checksum ${sum === 0 ? 'ok' : 'bad'}`, members };
}

function uefiSections(body: Uint8Array, ctx: Ctx, depth: number, absBase: number, prefix = ''): Member[] {
  const v = new View(body, true);
  const out: Member[] = [];
  let s = 0, n = 0;
  while (s + 4 <= body.length && n < 256 && ctx.budget()) {
    let size = v.u8(s) | (v.u8(s + 1) << 8) | (v.u8(s + 2) << 16);
    const type = v.u8(s + 3);
    let hdr = 4;
    if (size === 0xffffff) { if (s + 8 > body.length) break; size = v.u32(s + 4); hdr = 8; }
    if (size < hdr || s + size > body.length) break;
    n++;
    const data = body.subarray(s + hdr, s + size);
    const tag = `${prefix}${String(n).padStart(2, '0')}`;
    try {
      if (type === 0x01) {
        // EFI_COMPRESSION_SECTION: uncompressed length u32, type u8 (0 none, 1 standard EFI/Tiano)
        const ctype = data[4];
        if (ctype === 0) out.push(...uefiSections(data.subarray(5), ctx, depth, absBase + s + hdr + 5, `${tag}.`));
        else out.push({ name: `${tag}.compressed-efi.bin`, kind: 'file', data: data.subarray(5), offset: absBase + s + hdr + 5 });
      } else if (type === 0x02) {
        const g = guid(data, 0);
        const dataOff = v.u16(s + hdr + 16);
        const inner = body.subarray(s + dataOff, s + size);
        if (g === LZMA_GUID) {
          const r = lzmaAloneDecode(inner, { maxOut: ctx.maxOut() });
          out.push(...uefiSections(r.data, ctx, depth, absBase + s + dataOff, `${tag}.`));
        } else if (g === CRC32_GUID) out.push(...uefiSections(inner, ctx, depth, absBase + s + dataOff, `${tag}.`));
        else out.push({ name: `${tag}.guided-${g}.bin`, kind: 'file', data: inner, offset: absBase + s + dataOff });
      } else if (type === 0x17) {
        const nested = uefiVolume(data, 0, ctx, depth + 1);
        if (nested) for (const m of nested.members) out.push({ ...m, name: `${tag}.fv/${m.name}` });
        else out.push({ name: `${tag}.fv`, kind: 'file', data, offset: absBase + s + hdr });
      } else if (type === 0x15) {
        let txt = '';
        for (let k = 0; k + 1 < data.length; k += 2) { const c = (data[k] as number) | ((data[k + 1] as number) << 8); if (!c) break; txt += String.fromCharCode(c); }
        out.push({ name: `${tag}.ui.txt`, kind: 'file', data: new TextEncoder().encode(txt), offset: absBase + s + hdr });
      } else out.push({ name: `${tag}.${SEC_EXT[type] ?? `section-${type.toString(16)}.bin`}`, kind: 'file', data, offset: absBase + s + hdr });
    } catch (e) {
      ctx.warn(`UEFI section ${tag}: ${(e as Error).message}`);
      out.push({ name: `${tag}.section-${type.toString(16)}.bin`, kind: 'file', data, offset: absBase + s + hdr });
    }
    s = (s + size + 3) & ~3;
  }
  return out;
}

// ---------------- signature scan ----------------
interface Candidate { off: number; type: string }
function candidates(b: Uint8Array, from: number, to: number, skip: Set<string>): Candidate[] {
  const out: Candidate[] = [];
  const add = (off: number, type: string) => { if (!skip.has(type)) out.push({ off, type }); };
  for (let i = from; i + 4 <= to; i++) {
    const c0 = b[i] as number;
    switch (c0) {
      case 0x1f: if (b[i + 1] === 0x8b && b[i + 2] === 8 && ((b[i + 3] as number) & 0xe0) === 0) add(i, 'gzip'); break;
      case 0xfd: if (startsAt(b, i, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) add(i, 'xz'); break;
      case 0x5d: if (b[i + 1] === 0 && b[i + 2] === 0 && looksLikeLzmaAlone(b, i)) add(i, 'lzma'); break;
      case 0x28: if (startsAt(b, i, [0x28, 0xb5, 0x2f, 0xfd])) add(i, 'zstd'); break;
      case 0x04: if (startsAt(b, i, [0x04, 0x22, 0x4d, 0x18])) add(i, 'lz4'); break;
      case 0x02: if (startsAt(b, i, [0x02, 0x21, 0x4c, 0x18])) add(i, 'lz4-legacy'); break;
      case 0x89: if (startsAt(b, i, LZOP_MAGIC)) add(i, 'lzop'); break;
      case 0x50: if (b[i + 1] === 0x4b && b[i + 2] === 3 && b[i + 3] === 4) add(i, 'zip'); break;
      case 0x30: if (startsAt(b, i, [0x30, 0x37, 0x30, 0x37, 0x30]) && (b[i + 5] === 0x31 || b[i + 5] === 0x32 || b[i + 5] === 0x37)) add(i, 'cpio'); break;
      case 0x68: if (startsAt(b, i, [0x68, 0x73, 0x71, 0x73])) add(i, 'squashfs'); break;
      case 0x27: if (startsAt(b, i, [0x27, 0x05, 0x19, 0x56])) add(i, 'uimage'); break;
      case 0xd0: if (startsAt(b, i, [0xd0, 0x0d, 0xfe, 0xed])) add(i, 'fdt'); break;
      case 0x48: if (startsAt(b, i, [0x48, 0x44, 0x52, 0x30])) add(i, 'trx'); break;
      case 0x41: if (startsAt(b, i, [0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21])) add(i, 'android-boot'); break;
      case 0x56: if (startsAt(b, i, [0x56, 0x4e, 0x44, 0x52, 0x42, 0x4f, 0x4f, 0x54])) add(i, 'vendor-boot'); break;
      case 0x5f: if (i >= 40 && startsAt(b, i, [0x5f, 0x46, 0x56, 0x48])) add(i - 40, 'uefi-fv'); break;
      case 0x7f: if (startsAt(b, i, [0x7f, 0x45, 0x4c, 0x46]) && (b[i + 6] === 1)) add(i, 'elf'); break;
      case 0x75: if (i >= 257 && startsAt(b, i, [0x75, 0x73, 0x74, 0x61, 0x72]) && (b[i + 5] === 0 || b[i + 5] === 0x20)) add(i - 257, 'tar'); break;
    }
    if (out.length > 200000) break;
  }
  return out.sort((a, c) => a.off - c.off);
}

/** Carve and unpack a firmware blob recursively. */
export function extractFirmware(bytes: Uint8Array, options: ExtractOptions = {}): ExtractResult {
  const t0 = Date.now();
  const opts = {
    maxDepth: Math.max(0, Math.min(16, options.maxDepth ?? 6)), maxFiles: options.maxFiles ?? 20000, maxTotalBytes: options.maxTotalBytes ?? 512 << 20,
    maxFileSize: options.maxFileSize ?? 128 << 20, timeBudgetMs: options.timeBudgetMs ?? 60000, carveUnknown: options.carveUnknown ?? false, keepData: options.keepData ?? true,
    skip: new Set(options.skip ?? []),
  };
  const res: ExtractResult = { chunks: [], files: [], unknown: [], warnings: [], truncated: false, stats: { files: 0, bytes: 0, chunks: 0, maxDepthReached: 0, ms: 0 } };
  const used = new Set<string>();
  const warn = (m: string) => { if (res.warnings.length < 500) res.warnings.push(m); };
  const budget = () => {
    if (res.files.length >= opts.maxFiles || res.stats.bytes >= opts.maxTotalBytes || Date.now() - t0 > opts.timeBudgetMs) { res.truncated = true; return false; }
    return true;
  };
  const ctx: Ctx = { opts, warn, budget, maxOut: () => Math.max(0, Math.min(opts.maxFileSize, opts.maxTotalBytes - res.stats.bytes)) };
  const uniq = (p: string) => { let q = p, k = 1; while (used.has(q)) q = `${p}~${k++}`; used.add(q); return q; };
  const emit = (path: string, m: Member, depth: number, via: string[]): ExtractedFile => {
    const f: ExtractedFile = { path: uniq(path), kind: m.kind, size: m.data?.length ?? 0, depth, via, ...(m.mode ? { mode: m.mode } : {}), ...(m.target !== undefined ? { target: m.target } : {}), ...(m.offset !== undefined ? { offset: m.offset } : {}) };
    if (m.data) { f.sha256 = sha256(m.data); if (opts.keepData) f.data = m.data; res.stats.bytes += m.data.length; }
    res.files.push(f);
    res.stats.files++;
    if (m.target !== undefined && (m.target.startsWith('/') || m.target.split('/').includes('..'))) {
      // symlinks are recorded, never created, so a target outside the tree is only noted
      f.target = m.target;
    }
    return f;
  };

  const carve = (b: Uint8Array, base: string, depth: number, via: string[], topLevel: boolean): number => {
    res.stats.maxDepthReached = Math.max(res.stats.maxDepthReached, depth);
    let pos = 0, found = 0;
    const cands = candidates(b, 0, b.length, opts.skip);
    for (const c of cands) {
      if (!budget()) break;
      if (c.off < pos) continue;
      let u: Unpacked | undefined;
      try { u = H[c.type]!(b, c.off, ctx); } catch (e) { if (topLevel || depth < 2) { /* not a valid chunk */ } u = undefined; void e; }
      if (!u || u.end <= c.off) continue;
      if (pos < c.off) addUnknown(b, base, pos, c.off, depth, via);
      found++;
      const dir = `${base}${base ? '/' : ''}${c.off.toString(16).padStart(8, '0')}-${c.type}`;
      const chunk: ExtractChunk = { path: dir, offset: c.off, end: u.end, type: c.type, description: u.description, depth, children: u.members.length };
      res.chunks.push(chunk);
      res.stats.chunks++;
      for (const m of u.members) {
        if (!budget()) break;
        const name = sanitizeMemberPath(m.name, warn);
        const f = emit(`${dir}/${name}`, m, depth + 1, [...via, c.type]);
        if (m.kind === 'file' && m.data && m.data.length >= 16 && depth + 1 <= opts.maxDepth) {
          // recurse unless the member is exactly what we just unpacked (avoid loops)
          if (!(m.data.length === u.end - c.off && m.data.byteOffset === b.byteOffset + c.off && m.data.buffer === b.buffer)) {
            carve(m.data, `${f.path}.extract`, depth + 1, [...via, c.type], false);
          }
        }
      }
      pos = u.end;
    }
    if (found && pos < b.length) addUnknown(b, base, pos, b.length, depth, via);
    return found;
  };
  const addUnknown = (b: Uint8Array, base: string, s: number, e: number, depth: number, via: string[]) => {
    // all-0xff or all-0x00 padding is not interesting
    let pad = true;
    for (let k = s; k < e && pad; k++) if (b[k] !== 0xff && b[k] !== 0) pad = false;
    if (pad) return;
    const path = `${base}${base ? '/' : ''}${s.toString(16).padStart(8, '0')}-${e.toString(16).padStart(8, '0')}.unknown`;
    res.unknown.push({ path, offset: s, end: e });
    if (opts.carveUnknown && budget()) emit(path, { name: path, kind: 'file', data: b.subarray(s, e) }, depth, via);
  };

  const found = carve(bytes, '', 0, [], true);
  if (!found) warn('no known format found at any offset');
  res.stats.ms = Date.now() - t0;
  return res;
}

/** A short, JSON friendly view of an extraction (no file bytes). */
export function extractionSummary(r: ExtractResult): Omit<ExtractResult, 'files'> & { files: Omit<ExtractedFile, 'data'>[] } {
  return { ...r, files: r.files.map(({ data: _d, ...f }) => { void _d; return f; }) };
}

export { inflateRaw };
