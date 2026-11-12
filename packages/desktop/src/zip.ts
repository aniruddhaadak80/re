// Minimal ZIP writer and reader (store and deflate, no ZIP64), used for app state exports and the
// zip typed view of task checks. No Node imports: compression functions are passed in.
import { InputError } from './proc.js';
import { crc32 } from './image.js';

export interface ZipInput { name: string; data: Uint8Array; mtime?: Date }
const enc = new TextEncoder();

function dosTime(d: Date): { time: number; date: number } {
  const y = Math.max(1980, Math.min(2107, d.getFullYear()));
  return { time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), date: ((y - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate() };
}

/** Write a zip. deflateRaw compresses (raw deflate, no zlib header); entries that do not shrink are stored. */
export function writeZip(entries: ZipInput[], deflateRaw?: (b: Uint8Array) => Uint8Array): Uint8Array {
  if (entries.length > 65_000) throw new InputError('too many zip entries');
  const parts: Uint8Array[] = [], central: Uint8Array[] = [];
  let off = 0;
  const names = new Set<string>();
  for (const e of entries) {
    const name = e.name.replace(/\\/g, '/').replace(/^\/+/, '');
    if (!name || name.split('/').includes('..') || names.has(name)) throw new InputError(`bad or duplicate zip entry name ${name}`);
    names.add(name);
    const nb = enc.encode(name);
    const crc = crc32(e.data);
    let method = 0, body = e.data;
    if (deflateRaw && e.data.length > 64) { const c = deflateRaw(e.data); if (c.length < e.data.length) { method = 8; body = c; } }
    if (off + body.length > 0xfffffff0 || e.data.length > 0xfffffff0) throw new InputError('zip over 4 GiB is not supported');
    const { time, date } = dosTime(e.mtime ?? new Date(0x12d687 * 1000));
    const lh = new Uint8Array(30 + nb.length); const lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0x0800, true); lv.setUint16(8, method, true); lv.setUint16(10, time, true); lv.setUint16(12, date, true);
    lv.setUint32(14, crc, true); lv.setUint32(18, body.length, true); lv.setUint32(22, e.data.length, true); lv.setUint16(26, nb.length, true); lh.set(nb, 30);
    const ch = new Uint8Array(46 + nb.length); const cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 0x031e, true); cv.setUint16(6, 20, true); cv.setUint16(8, 0x0800, true); cv.setUint16(10, method, true); cv.setUint16(12, time, true); cv.setUint16(14, date, true);
    cv.setUint32(16, crc, true); cv.setUint32(20, body.length, true); cv.setUint32(24, e.data.length, true); cv.setUint16(28, nb.length, true); cv.setUint32(38, (0o100644 << 16) >>> 0, true); cv.setUint32(42, off, true); ch.set(nb, 46);
    parts.push(lh, body); central.push(ch); off += lh.length + body.length;
  }
  const cdSize = central.reduce((a, c) => a + c.length, 0);
  const end = new Uint8Array(22); const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true); ev.setUint32(12, cdSize, true); ev.setUint32(16, off, true);
  const all = [...parts, ...central, end]; const out = new Uint8Array(all.reduce((a, c) => a + c.length, 0)); let o = 0;
  for (const p of all) { out.set(p, o); o += p.length; }
  return out;
}

export interface ZipEntry { name: string; method: number; compressedSize: number; size: number; crc: number; offset: number }

/** List a zip's central directory (bounded). */
export function listZip(b: Uint8Array, maxEntries = 100_000): ZipEntry[] {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new InputError('not a zip (no end of central directory)');
  const count = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
  if (count > maxEntries) throw new InputError('too many zip entries');
  const out: ZipEntry[] = [];
  let p = cdOff;
  for (let i = 0; i < count; i++) {
    if (p + 46 > b.length || dv.getUint32(p, true) !== 0x02014b50) throw new InputError('zip central directory truncated');
    const nl = dv.getUint16(p + 28, true), xl = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true);
    if (p + 46 + nl > b.length) throw new InputError('zip name runs past the end');
    out.push({ name: new TextDecoder().decode(b.subarray(p + 46, p + 46 + nl)), method: dv.getUint16(p + 10, true), crc: dv.getUint32(p + 16, true), compressedSize: dv.getUint32(p + 20, true), size: dv.getUint32(p + 24, true), offset: dv.getUint32(p + 42, true) });
    p += 46 + nl + xl + cl;
  }
  return out;
}

/** Read one entry's bytes. inflateRaw is needed for deflated entries. The CRC is checked. */
export function readZipEntry(b: Uint8Array, e: ZipEntry, inflateRaw?: (b: Uint8Array, max: number) => Uint8Array, maxSize = 256 * 1024 * 1024): Uint8Array {
  if (e.size > maxSize) throw new InputError(`${e.name} is larger than the read limit`);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (e.offset + 30 > b.length || dv.getUint32(e.offset, true) !== 0x04034b50) throw new InputError(`bad local header for ${e.name}`);
  const start = e.offset + 30 + dv.getUint16(e.offset + 26, true) + dv.getUint16(e.offset + 28, true);
  if (start + e.compressedSize > b.length) throw new InputError(`${e.name} runs past the end`);
  const raw = b.subarray(start, start + e.compressedSize);
  let data: Uint8Array;
  if (e.method === 0) data = raw;
  else if (e.method === 8) { if (!inflateRaw) throw new InputError('deflated entry needs inflateRaw'); data = inflateRaw(raw, maxSize); }
  else throw new InputError(`zip method ${e.method} is not supported`);
  if (data.length !== e.size || crc32(data) !== e.crc) throw new InputError(`${e.name} fails its CRC check`);
  return data;
}
