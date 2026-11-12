// LevelDB write-ahead log reader (the .log files in Chromium and Electron Local Storage,
// Session Storage and IndexedDB folders) and Chromium Local Storage key decoding.
// SSTable (.ldb) files need Snappy and are listed, not decoded. No Node imports.
import { InputError } from './proc.js';

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
