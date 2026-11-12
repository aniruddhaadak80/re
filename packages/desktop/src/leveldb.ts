// LevelDB write-ahead log reader (the .log files in Chromium and Electron Local Storage,
// Session Storage and IndexedDB folders) and Chromium Local Storage key decoding.
// Table files (.ldb and .sst) are decoded too, with the pure TS Snappy decoder in snappy.ts, and
// readLevelDb merges logs and tables into the current key set by sequence number. No Node imports.
import { InputError } from './proc.js';
import { snappyDecompress, crc32c, unmaskCrc } from './snappy.js';

export interface LevelRecord { seq: string; op: 'put' | 'delete'; key: Uint8Array; value?: Uint8Array }

function varint(b: Uint8Array, p: { i: number }, end: number): number {
  let v = 0, shift = 0;
  for (let n = 0; n < 5; n++) {
    if (p.i >= end) throw new InputError('varint runs past the record');
    const c = b[p.i++]!;
    v += (c & 0x7f) * 2 ** shift;
    if (!(c & 0x80)) return v;
    shift += 7;
  }
  throw new InputError('varint too long');
}

/** Read every write batch in a LevelDB .log file (32 KiB blocks of FULL/FIRST/MIDDLE/LAST fragments). */
export function readLevelLog(b: Uint8Array, opts: { maxRecords?: number } = {}): { records: LevelRecord[]; batches: number; corrupt: number; truncated: boolean } {
  const max = Math.max(1, Math.min(opts.maxRecords ?? 100_000, 1_000_000));
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const records: LevelRecord[] = [];
  let batches = 0, corrupt = 0, truncated = false;
  let pending: Uint8Array[] = [];
  const BLOCK = 32768;
  let pos = 0;
  while (pos + 7 <= b.length) {
    const left = BLOCK - (pos % BLOCK);
    if (left < 7) { pos += left; continue; }
    const len = dv.getUint16(pos + 4, true), type = b[pos + 6]!;
    if (type === 0 && len === 0) { pos += left; continue; } // zero padding
    if (pos + 7 + len > b.length || 7 + len > left) { corrupt++; pos += left; pending = []; continue; }
    const frag = b.subarray(pos + 7, pos + 7 + len);
    pos += 7 + len;
    if (type === 1) pending = [frag];
    else if (type === 2) { pending = [frag]; continue; }
    else if (type === 3) { if (pending.length) pending.push(frag); continue; }
    else if (type === 4) { if (!pending.length) { corrupt++; continue; } pending.push(frag); }
    else { corrupt++; continue; }
    const total = pending.reduce((a, f) => a + f.length, 0);
    const batch = new Uint8Array(total); let o = 0; for (const f of pending) { batch.set(f, o); o += f.length; }
    pending = [];
    try {
      if (batch.length < 12) throw new InputError('short batch');
      const bv = new DataView(batch.buffer, batch.byteOffset, batch.byteLength);
      const seq = bv.getBigUint64(0, true), count = bv.getUint32(8, true);
      const p = { i: 12 };
      for (let k = 0; k < count; k++) {
        if (records.length >= max) { truncated = true; break; }
        const tag = batch[p.i++];
        const kl = varint(batch, p, batch.length); if (p.i + kl > batch.length) throw new InputError('key runs past batch');
        const key = batch.slice(p.i, p.i + kl); p.i += kl;
        if (tag === 1) { const vl = varint(batch, p, batch.length); if (p.i + vl > batch.length) throw new InputError('value runs past batch'); records.push({ seq: (seq + BigInt(k)).toString(), op: 'put', key, value: batch.slice(p.i, p.i + vl) }); p.i += vl; }
        else if (tag === 0) records.push({ seq: (seq + BigInt(k)).toString(), op: 'delete', key });
        else throw new InputError('bad record tag');
      }
      batches++;
    } catch { corrupt++; }
    if (truncated) break;
  }
  return { records, batches, corrupt, truncated };
}

const latin1 = (b: Uint8Array) => { let s = ''; for (let i = 0; i < b.length && i < 100_000; i++) s += String.fromCharCode(b[i]!); return s; };
const utf16 = (b: Uint8Array) => { let s = ''; for (let i = 0; i + 1 < b.length && i < 200_000; i += 2) s += String.fromCharCode(b[i]! | (b[i + 1]! << 8)); return s; };

/** Decode a Chromium Local Storage key/value: "_<origin>\0<1|0><key>" with 1 = Latin-1, 0 = UTF-16LE. META and VERSION keys are kept as is. */
export function decodeLocalStorage(key: Uint8Array, value?: Uint8Array): { origin?: string; key: string; value?: string; meta?: boolean } {
  const k = latin1(key);
  const str = (b?: Uint8Array) => (b && b.length ? (b[0] === 1 ? latin1(b.subarray(1)) : b[0] === 0 ? utf16(b.subarray(1)) : latin1(b)) : undefined);
  if (k.startsWith('_')) {
    const z = k.indexOf('\0');
    if (z > 0) return { origin: k.slice(1, z), key: str(key.subarray(z + 1)) ?? '', value: str(value) };
  }
  return { key: k, value: value ? latin1(value).slice(0, 500) : undefined, meta: true };
}

// ---------------- table files (.ldb / .sst) ----------------

export interface LevelTableRecord extends LevelRecord { /** offset of the data block the entry came from */ block: number }
export interface LevelTableResult { records: LevelTableRecord[]; blocks: number; compressedBlocks: number; badChecksums: number; corrupt: number; truncated: boolean; warnings: string[] }

const TABLE_MAGIC_LO = 0x8b80fb57, TABLE_MAGIC_HI = 0xdb477524;

function varint64(b: Uint8Array, p: { i: number }, end: number): number {
  let v = 0, shift = 0;
  for (let n = 0; n < 10; n++) {
    if (p.i >= end) throw new InputError('varint runs past the block');
    const c = b[p.i++]!;
    v += (c & 0x7f) * 2 ** shift;
    if (!(c & 0x80)) { if (v > Number.MAX_SAFE_INTEGER) throw new InputError('varint too large'); return v; }
    shift += 7;
  }
  throw new InputError('varint too long');
}

/** Read one block (contents plus its 5 byte trailer: compression type and masked CRC-32C). */
function readBlock(b: Uint8Array, offset: number, size: number, st: { compressed: number; badCrc: number }, verify: boolean, maxBlock: number): Uint8Array {
  if (offset < 0 || size < 0 || offset + size + 5 > b.length) throw new InputError(`block at ${offset} (${size} bytes) runs past the file`);
  const raw = b.subarray(offset, offset + size);
  const type = b[offset + size]!;
  if (verify) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const want = unmaskCrc(dv.getUint32(offset + size + 1, true));
    const got = crc32c(b.subarray(offset, offset + size + 1));
    if (want !== got) st.badCrc++;
  }
  if (type === 0) return raw;
  if (type === 1) { st.compressed++; return snappyDecompress(raw, maxBlock); }
  throw new InputError(`block at ${offset} uses compression type ${type} (only none and Snappy are supported)`);
}

/** Iterate the entries of a decoded block (prefix-compressed keys, restart array at the end). */
function blockEntries(blk: Uint8Array, max: number): { key: Uint8Array; value: Uint8Array }[] {
  if (blk.length < 4) throw new InputError('block too short');
  const dv = new DataView(blk.buffer, blk.byteOffset, blk.byteLength);
  const restarts = dv.getUint32(blk.length - 4, true);
  const limit = blk.length - 4 - restarts * 4;
  if (restarts > blk.length / 4 || limit < 0) throw new InputError('bad restart count');
  const out: { key: Uint8Array; value: Uint8Array }[] = [];
  let prev = new Uint8Array(0);
  const p = { i: 0 };
  while (p.i < limit) {
    if (out.length >= max) break;
    const shared = varint64(blk, p, limit), nonShared = varint64(blk, p, limit), vlen = varint64(blk, p, limit);
    if (shared > prev.length || p.i + nonShared + vlen > limit) throw new InputError('block entry runs past the block');
    const key = new Uint8Array(shared + nonShared);
    key.set(prev.subarray(0, shared)); key.set(blk.subarray(p.i, p.i + nonShared), shared);
    p.i += nonShared;
    const value = blk.slice(p.i, p.i + vlen); p.i += vlen;
    out.push({ key, value }); prev = key;
  }
  return out;
}

/** Decode a LevelDB table file: footer, index block, then every data block (Snappy or plain). */
export function readLevelTable(b: Uint8Array, opts: { maxRecords?: number; verifyChecksums?: boolean; maxBlockBytes?: number } = {}): LevelTableResult {
  const max = Math.max(1, Math.min(opts.maxRecords ?? 100_000, 1_000_000));
  const maxBlock = Math.max(1024, Math.min(opts.maxBlockBytes ?? 16 * 1024 * 1024, 256 * 1024 * 1024));
  if (b.length < 48) throw new InputError('not a LevelDB table (shorter than its 48 byte footer)');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (dv.getUint32(b.length - 8, true) !== TABLE_MAGIC_LO || dv.getUint32(b.length - 4, true) !== TABLE_MAGIC_HI) throw new InputError('not a LevelDB table (footer magic missing)');
  const f = { i: b.length - 48 };
  const end = b.length - 8;
  varint64(b, f, end); varint64(b, f, end); // metaindex handle (filter blocks are not needed)
  const idxOff = varint64(b, f, end), idxSize = varint64(b, f, end);
  const st = { compressed: 0, badCrc: 0 };
  const verify = opts.verifyChecksums !== false;
  const index = blockEntries(readBlock(b, idxOff, idxSize, st, verify, maxBlock), 1_000_000);
  const records: LevelTableRecord[] = [];
  const warnings: string[] = [];
  let corrupt = 0, truncated = false, blocks = 0;
  for (const ent of index) {
    if (records.length >= max) { truncated = true; break; }
    try {
      const h = { i: 0 };
      const off = varint64(ent.value, h, ent.value.length), size = varint64(ent.value, h, ent.value.length);
      const blk = readBlock(b, off, size, st, verify, maxBlock);
      blocks++;
      for (const e of blockEntries(blk, max - records.length + 1)) {
        if (records.length >= max) { truncated = true; break; }
        if (e.key.length < 8) { corrupt++; continue; }
        // internal key: user key, then 8 bytes little-endian (sequence << 8 | type)
        const kd = new DataView(e.key.buffer, e.key.byteOffset + e.key.length - 8, 8);
        const tag = kd.getBigUint64(0, true);
        const type = Number(tag & 0xffn), seq = (tag >> 8n).toString();
        const key = e.key.slice(0, e.key.length - 8);
        if (type === 1) records.push({ seq, op: 'put', key, value: e.value, block: off });
        else if (type === 0) records.push({ seq, op: 'delete', key, block: off });
        else corrupt++;
      }
    } catch (err) { corrupt++; if (warnings.length < 20) warnings.push((err as Error).message); }
  }
  if (st.badCrc) warnings.push(`${st.badCrc} block checksum(s) did not match`);
  return { records, blocks, compressedBlocks: st.compressed, badChecksums: st.badCrc, corrupt, truncated, warnings };
}

export interface LevelDbFile { name: string; bytes: Uint8Array }
export interface LevelDbEntry { key: Uint8Array; value: Uint8Array; seq: string; source: string }

const hexKey = (k: Uint8Array) => { let s = ''; for (let i = 0; i < k.length; i++) s += k[i]!.toString(16).padStart(2, '0'); return s; };

/**
 * Merge the .log and .ldb/.sst files of one LevelDB folder into the live key set: for each user
 * key the record with the highest sequence number wins, and a delete removes the key.
 */
export function readLevelDb(files: LevelDbFile[], opts: { maxRecords?: number } = {}): { entries: LevelDbEntry[]; deleted: number; files: { name: string; kind: 'log' | 'table' | 'other'; records: number; corrupt: number; error?: string }[]; truncated: boolean; warnings: string[] } {
  const max = Math.max(1, Math.min(opts.maxRecords ?? 200_000, 2_000_000));
  const best = new Map<string, { rec: LevelRecord; seq: bigint; source: string }>();
  const report: { name: string; kind: 'log' | 'table' | 'other'; records: number; corrupt: number; error?: string }[] = [];
  const warnings: string[] = [];
  let truncated = false, seen = 0;
  const take = (r: LevelRecord, source: string) => {
    const k = hexKey(r.key); const s = BigInt(r.seq);
    const cur = best.get(k);
    if (!cur || s >= cur.seq) best.set(k, { rec: r, seq: s, source });
  };
  for (const f of files.slice(0, 10_000)) {
    const kind = /\.log$/i.test(f.name) ? 'log' : /\.(ldb|sst)$/i.test(f.name) ? 'table' : 'other';
    if (kind === 'other') continue;
    try {
      const left = Math.max(1, max - seen);
      const r = kind === 'log' ? readLevelLog(f.bytes, { maxRecords: left }) : readLevelTable(f.bytes, { maxRecords: left });
      for (const x of r.records) take(x, f.name);
      seen += r.records.length; if (r.truncated) truncated = true;
      if (kind === 'table') warnings.push(...(r as LevelTableResult).warnings.map((w) => `${f.name}: ${w}`));
      report.push({ name: f.name, kind, records: r.records.length, corrupt: r.corrupt });
    } catch (e) { report.push({ name: f.name, kind, records: 0, corrupt: 1, error: (e as Error).message }); }
    if (seen >= max) { truncated = true; break; }
  }
  const entries: LevelDbEntry[] = [];
  let deleted = 0;
  for (const { rec, source } of best.values()) {
    if (rec.op === 'delete') { deleted++; continue; }
    entries.push({ key: rec.key, value: rec.value ?? new Uint8Array(0), seq: rec.seq, source });
  }
  entries.sort((a, b) => { const n = Math.min(a.key.length, b.key.length); for (let i = 0; i < n; i++) if (a.key[i] !== b.key[i]) return a.key[i]! - b.key[i]!; return a.key.length - b.key.length; });
  return { entries, deleted, files: report, truncated, warnings };
}
