// Minimal, bounds-checked ZIP reader for APK, JAR, AAB and IPA containers.
// Reads the central directory, supports stored and deflate members, and zip64 sizes.

import { Buf, ParseError, utf8 } from './bytes.js';

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  crc32: number;
  /** offset of the local file header */
  localOffset: number;
  /** offset of the central directory record */
  cdOffset: number;
  flags: number;
}

export interface ZipArchive {
  bytes: Uint8Array;
  entries: ZipEntry[];
  /** offset of the first central directory record */
  centralDirOffset: number;
  centralDirSize: number;
  eocdOffset: number;
  comment: string;
  byName: Map<string, ZipEntry>;
}

export const ZIP_LIMITS = {
  maxEntries: 200_000,
  /** largest single member we will inflate */
  maxMemberBytes: 512 * 1024 * 1024,
};

export function isZip(b: Uint8Array): boolean {
  return b.length >= 22 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05) ;
}

/** Parse a ZIP central directory. Throws ParseError when no end record is found. */
export function openZip(bytes: Uint8Array): ZipArchive {
  const r = new Buf(bytes);
  let eocd = -1;
  const stop = Math.max(0, bytes.length - 22 - 0xffff);
  for (let i = bytes.length - 22; i >= stop; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) throw new ParseError('not a ZIP archive: end of central directory record not found');
  let count = r.u16(eocd + 10);
  let cdSize = r.u32(eocd + 12);
  let cdOff = r.u32(eocd + 16);
  const commentLen = r.u16(eocd + 20);
  const comment = r.has(eocd + 22, commentLen) ? utf8(r.slice(eocd + 22, commentLen)) : '';
  // zip64 locator sits right before the EOCD
  if ((cdOff === 0xffffffff || count === 0xffff) && eocd >= 20 && r.u32(eocd - 20) === 0x07064b50) {
    const z64 = Number(r.u64(eocd - 12));
    if (r.has(z64, 56) && r.u32(z64) === 0x06064b50) {
      count = Number(r.u64(z64 + 32));
      cdSize = Number(r.u64(z64 + 40));
      cdOff = Number(r.u64(z64 + 48));
    }
  }
  if (count > ZIP_LIMITS.maxEntries) throw new ParseError(`ZIP claims ${count} entries, above the ${ZIP_LIMITS.maxEntries} limit`);
  const entries: ZipEntry[] = [];
  const byName = new Map<string, ZipEntry>();
  let p = cdOff;
  for (let i = 0; i < count; i++) {
    if (!r.has(p, 46) || r.u32(p) !== 0x02014b50) break;
    const flags = r.u16(p + 8);
    const method = r.u16(p + 10);
    const crc32 = r.u32(p + 16);
    let csize = r.u32(p + 20);
    let usize = r.u32(p + 24);
    const nlen = r.u16(p + 28), xlen = r.u16(p + 30), clen = r.u16(p + 32);
    let local = r.u32(p + 42);
    if (!r.has(p + 46, nlen + xlen + clen)) break;
    const name = utf8(r.slice(p + 46, nlen));
    // zip64 extra field
    if (usize === 0xffffffff || csize === 0xffffffff || local === 0xffffffff) {
      let x = p + 46 + nlen;
      const xend = x + xlen;
      while (x + 4 <= xend) {
        const id = r.u16(x), sz = r.u16(x + 2);
        if (id === 0x0001) {
          let q = x + 4;
          if (usize === 0xffffffff && q + 8 <= x + 4 + sz) { usize = Number(r.u64(q)); q += 8; }
          if (csize === 0xffffffff && q + 8 <= x + 4 + sz) { csize = Number(r.u64(q)); q += 8; }
          if (local === 0xffffffff && q + 8 <= x + 4 + sz) { local = Number(r.u64(q)); q += 8; }
          break;
        }
        x += 4 + sz;
      }
    }
    const e: ZipEntry = { name, method, compressedSize: csize, size: usize, crc32, localOffset: local, cdOffset: p, flags };
    entries.push(e);
    if (!byName.has(name)) byName.set(name, e);
    p += 46 + nlen + xlen + clen;
  }
  return { bytes, entries, centralDirOffset: cdOff, centralDirSize: cdSize, eocdOffset: eocd, comment, byName };
}

/** Offset where the member's data starts, after its local header. */
export function dataOffset(zip: ZipArchive, e: ZipEntry): number {
  const r = new Buf(zip.bytes);
  if (!r.has(e.localOffset, 30) || r.u32(e.localOffset) !== 0x04034b50) throw new ParseError(`bad local header for ${e.name}`);
  return e.localOffset + 30 + r.u16(e.localOffset + 26) + r.u16(e.localOffset + 28);
}

/** Read and inflate one member. Stored and deflate only. */
export async function readEntry(zip: ZipArchive, e: ZipEntry | string, maxBytes = ZIP_LIMITS.maxMemberBytes): Promise<Uint8Array> {
  const entry = typeof e === 'string' ? zip.byName.get(e) : e;
  if (!entry) throw new ParseError(`member not found: ${String(e)}`);
  if (entry.size > maxBytes) throw new ParseError(`member ${entry.name} is ${entry.size} bytes, above the ${maxBytes} byte limit`);
  const start = dataOffset(zip, entry);
  const r = new Buf(zip.bytes);
  const raw = r.slice(start, Math.min(entry.compressedSize, zip.bytes.length - start));
  // Android tolerates a stored method with compressed size equal to size; mirror it.
  if (entry.method === 0) return raw.subarray(0, entry.size || raw.length);
  if (entry.method === 8) return inflateRaw(raw, Math.min(maxBytes, Math.max(entry.size, 1) * 2 + 1024));
  throw new ParseError(`ZIP method ${entry.method} is not supported for ${entry.name}`);
}

export async function inflateRaw(data: Uint8Array, maxOut: number): Promise<Uint8Array> {
  const DS = (globalThis as unknown as { DecompressionStream?: new (f: string) => TransformStream<Uint8Array, Uint8Array> }).DecompressionStream;
  if (!DS) throw new Error('DecompressionStream is not available in this runtime');
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DS('deflate-raw'));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        total += value.length;
        if (total > maxOut) { await reader.cancel().catch(() => undefined); throw new ParseError(`inflated size passed the ${maxOut} byte limit`); }
        chunks.push(value);
      }
    }
  } catch (err) {
    if (err instanceof ParseError) throw err;
    // Truncated or corrupt deflate stream: keep what decoded.
    if (total === 0) throw new ParseError(`deflate stream is corrupt: ${(err as Error).message}`);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/** Find members matching a predicate, capped. */
export function findEntries(zip: ZipArchive, pred: (name: string) => boolean, limit = 10_000): ZipEntry[] {
  const out: ZipEntry[] = [];
  for (const e of zip.entries) {
    if (pred(e.name)) { out.push(e); if (out.length >= limit) break; }
  }
  return out;
}
