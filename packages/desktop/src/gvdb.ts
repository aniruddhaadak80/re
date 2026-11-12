// GVDB reader (GLib's "GVariant database" file, used for the binary dconf databases in
// ~/.config/dconf/user and /etc/dconf/db/*, and for compiled GResources), plus a dconf view that
// prints the same text as `dconf dump`. Written from the layout in GLib's gvdb-format.h. Pure TS,
// no Node imports; every pointer is bounds-checked and parent chains are cycle-checked.
import { InputError } from './proc.js';
import { decodeGVariant, printGVariant, type GVar } from './gvariantbin.js';

export interface GvdbItem { index: number; key: string; type: 'v' | 'H' | 'L' | string; hash: number; parent?: number; value?: GVar; table?: GvdbTable; list?: number[]; error?: string }
export interface GvdbTable { items: GvdbItem[]; bloomWords: number; buckets: number }
export interface GvdbFile { littleEndian: boolean; version: number; root: GvdbTable }

const SIG_LE = [0x47, 0x56, 0x61, 0x72, 0x69, 0x61, 0x6e, 0x74]; // "GVariant"
const SIG_BE = [0x72, 0x61, 0x56, 0x47, 0x74, 0x6e, 0x61, 0x69];

/** True when the bytes start with a GVDB header in either byte order. */
export function isGvdb(b: Uint8Array): boolean {
  return b.length >= 24 && (SIG_LE.every((x, i) => b[i] === x) || SIG_BE.every((x, i) => b[i] === x));
}

/** Read a GVDB file: the root hash table with every item, nested tables and lists, and decoded values. */
export function readGvdb(b: Uint8Array, opts: { maxItems?: number; maxDepth?: number } = {}): GvdbFile {
  if (!isGvdb(b)) throw new InputError('not a GVDB file (GVariant signature missing)');
  const le = b[0] === 0x47;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u32 = (o: number) => { if (o < 0 || o + 4 > b.length) throw new InputError(`read past the end at ${o}`); return dv.getUint32(o, le); };
  const u16 = (o: number) => { if (o < 0 || o + 2 > b.length) throw new InputError(`read past the end at ${o}`); return dv.getUint16(o, le); };
  const maxItems = Math.max(1, Math.min(opts.maxItems ?? 200_000, 2_000_000));
  const maxDepth = Math.max(1, Math.min(opts.maxDepth ?? 16, 64));
  let total = 0;
  const pointer = (o: number) => { const start = u32(o), end = u32(o + 4); if (start > end || end > b.length) throw new InputError(`pointer ${start}..${end} outside the file`); return { start, end }; };
  const readTable = (start: number, end: number, depth: number): GvdbTable => {
    if (depth > maxDepth) throw new InputError('GVDB tables nested too deep');
    if (end - start < 8) return { items: [], bloomWords: 0, buckets: 0 };
    const bloomField = u32(start), nBuckets = u32(start + 4);
    const nBloom = bloomField & ((1 << 27) - 1);
    const itemsStart = start + 8 + nBloom * 4 + nBuckets * 4;
    if (itemsStart > end) throw new InputError('GVDB hash table header runs past its data');
    const n = Math.floor((end - itemsStart) / 24);
    if ((end - itemsStart) % 24 !== 0) throw new InputError('GVDB hash items do not fill the table');
    if (total + n > maxItems) throw new InputError(`GVDB holds more than ${maxItems} items`);
    total += n;
    const raw = [] as { hash: number; parent: number; keyStart: number; keySize: number; type: string; ptr: number }[];
    for (let k = 0; k < n; k++) {
      const o = itemsStart + k * 24;
      raw.push({ hash: u32(o), parent: u32(o + 4), keyStart: u32(o + 8), keySize: u16(o + 12), type: String.fromCharCode(b[o + 14]!), ptr: o + 16 });
    }
    const dec = new TextDecoder();
    const own = raw.map((r) => { if (r.keyStart + r.keySize > b.length) throw new InputError('GVDB key outside the file'); return dec.decode(b.subarray(r.keyStart, r.keyStart + r.keySize)); });
    const full = (k: number): string => {
      let key = '', cur = k; const seen = new Set<number>();
      while (cur !== 0xffffffff) {
        if (seen.has(cur) || cur >= n) throw new InputError('GVDB parent chain is broken or loops');
        seen.add(cur); key = own[cur]! + key; cur = raw[cur]!.parent;
        if (key.length > 65536) throw new InputError('GVDB key too long');
      }
      return key;
    };
    const items: GvdbItem[] = raw.map((r, k) => {
      const it: GvdbItem = { index: k, key: '', type: r.type, hash: r.hash };
      if (r.parent !== 0xffffffff) it.parent = r.parent;
      try {
        it.key = full(k);
        const { start: s, end: e } = pointer(r.ptr);
        if (r.type === 'v') it.value = decodeGVariant('v', b.subarray(s, e), { littleEndian: le });
        else if (r.type === 'H') it.table = readTable(s, e, depth + 1);
        else if (r.type === 'L') { if ((e - s) % 4) throw new InputError('GVDB list size is not a multiple of 4'); it.list = []; for (let o = s; o < e && it.list.length < 1_000_000; o += 4) it.list.push(u32(o)); }
      } catch (err) { it.error = (err as Error).message; if (!it.key) it.key = own[k] ?? ''; }
      return it;
    });
    return { items, bloomWords: nBloom, buckets: nBuckets };
  };
  const version = u32(8);
  const root = pointer(16);
  return { littleEndian: le, version, root: readTable(root.start, root.end, 0) };
}

export interface DconfKey { path: string; type: string; value: unknown; text: string; locked?: boolean }

/** Keys of a binary dconf database (the user file or a compiled system db), with values as dconf prints them. */
export function readDconfDb(b: Uint8Array, opts: { maxItems?: number } = {}): { keys: DconfKey[]; locks: string[]; dirs: string[]; warnings: string[] } {
  const f = readGvdb(b, opts);
  const keys: DconfKey[] = [], dirs: string[] = [], warnings: string[] = [];
  let locks: string[] = [];
  for (const it of f.root.items) {
    if (it.error) { warnings.push(`${it.key}: ${it.error}`); continue; }
    if (it.key === '.locks' && it.table) { locks = it.table.items.map((x) => x.key).filter((k) => k.startsWith('/')); continue; }
    if (it.type === 'L' || it.key.endsWith('/')) { if (it.key.startsWith('/')) dirs.push(it.key); continue; }
    if (it.type !== 'v' || !it.value || !it.key.startsWith('/')) continue;
    const inner = it.value.children?.[0];
    if (!inner) continue;
    keys.push({ path: it.key, type: inner.type, value: inner.value, text: printGVariant(inner, true) });
  }
  const ls = new Set(locks);
  for (const k of keys) if (ls.has(k.path)) k.locked = true;
  keys.sort((a, c) => (a.path < c.path ? -1 : a.path > c.path ? 1 : 0));
  return { keys, locks, dirs: dirs.sort(), warnings };
}

/** The text `dconf dump <dir>` prints for a database: one [section] per folder with keys, sorted. */
export function dconfDump(b: Uint8Array, dir = '/'): string {
  if (!dir.startsWith('/') || !dir.endsWith('/')) throw new InputError('dir must start and end with /');
  const { keys } = readDconfDb(b);
  const groups = new Map<string, DconfKey[]>();
  for (const k of keys) {
    if (!k.path.startsWith(dir)) continue;
    const slash = k.path.lastIndexOf('/');
    const d = k.path.slice(0, slash + 1);
    (groups.get(d) ?? groups.set(d, []).get(d)!).push(k);
  }
  // dconf walks folders depth first with each folder's entries in name order, so compare the
  // folder paths segment by segment (with the trailing slash) rather than as plain strings
  const segs = (d: string) => d.slice(dir.length).split('/').filter(Boolean).map((s) => s + '/');
  const order = [...groups.keys()].sort((a, c) => {
    const x = segs(a), y = segs(c);
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! < y[i]! ? -1 : 1;
    return x.length - y.length;
  });
  // sections are separated by one blank line, with none after the last
  return order.map((d) => {
    const rel = d.slice(dir.length).replace(/\/$/, '');
    return `[${rel || '/'}]\n` + groups.get(d)!.map((k) => `${k.path.slice(d.length)}=${k.text}\n`).join('');
  }).join('\n');
}
