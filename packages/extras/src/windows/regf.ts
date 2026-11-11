// Windows registry hive (regf) reader: base block, hive bins, nk keys, vk values,
// lf/lh/li/ri subkey lists and db big data. Read only, every cell offset bounds checked.

import { View, ParseError, filetime, utf8, toHex } from '../util.js';

const BASE = 4096;
export const REG_TYPES: Record<number, string> = {
  0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD', 5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK',
  7: 'REG_MULTI_SZ', 8: 'REG_RESOURCE_LIST', 9: 'REG_FULL_RESOURCE_DESCRIPTOR', 10: 'REG_RESOURCE_REQUIREMENTS_LIST', 11: 'REG_QWORD',
};

export interface RegfHeader {
  primarySequence: number; secondarySequence: number; dirty: boolean; lastWritten: string | null;
  version: string; fileType: number; rootCellOffset: number; hiveBinsSize: number; fileName: string;
  checksum: number; checksumValid: boolean;
}
export interface RegKey {
  path: string; name: string; offset: number; lastWritten: string | null; subkeyCount: number; valueCount: number;
  className?: string; flags: number; securityOffset: number;
}
export interface RegValue {
  name: string; type: string; typeId: number; size: number; offset: number; dataOffset: number | null; inline: boolean;
  value: string | number | string[] | null; hex?: string;
}

/** Parsed registry hive. Construct with `new Regf(bytes)`. */
export class Regf {
  readonly v: View;
  readonly header: RegfHeader;
  private cellsRead = 0;
  constructor(readonly bytes: Uint8Array, readonly opts: { maxCells?: number } = {}) {
    this.v = new View(bytes, true);
    if (bytes.length < BASE || this.v.u32(0) !== 0x66676572) throw new ParseError('not a registry hive (regf signature expected)', 0);
    let x = 0;
    for (let i = 0; i < 508; i += 4) x = (x ^ this.v.u32(i)) >>> 0;
    if (x === 0xffffffff) x = 0xfffffffe; else if (x === 0) x = 1;
    const p = this.v.u32(4), s = this.v.u32(8);
    this.header = {
      primarySequence: p, secondarySequence: s, dirty: p !== s,
      lastWritten: filetime(this.v.u32(12), this.v.u32(16)),
      version: `${this.v.u32(20)}.${this.v.u32(24)}`, fileType: this.v.u32(28),
      rootCellOffset: this.v.u32(36), hiveBinsSize: this.v.u32(40),
      fileName: this.v.utf16z(48, 32).replace(/\0.*$/, ''),
      checksum: this.v.u32(508), checksumValid: x === this.v.u32(508),
    };
  }
  get minor(): number { return this.v.u32(24); }

  /** Cell data (without the size field) at a hive-relative offset. */
  cell(off: number): { at: number; data: Uint8Array } {
    if (++this.cellsRead > (this.opts.maxCells ?? 5_000_000)) throw new ParseError('cell read limit reached');
    const at = BASE + off;
    if (off === 0xffffffff || !this.v.has(at, 4)) throw new ParseError('cell offset out of range', at);
    const raw = this.v.i32(at);
    const size = Math.abs(raw);
    if (size < 4 || !this.v.has(at, size)) throw new ParseError('cell size out of range', at);
    return { at, data: this.v.sub(at + 4, size - 4) };
  }

  key(off: number, parentPath = ''): RegKey {
    const { at, data } = this.cell(off);
    const c = new View(data, true);
    if (c.length < 76 || c.u16(0) !== 0x6b6e) throw new ParseError('nk key cell expected', at);
    const flags = c.u16(2);
    const nameLen = c.u16(72);
    const name = flags & 0x20 ? latin(c.sub(76, Math.min(nameLen, c.length - 76))) : c.utf16(76, Math.min(nameLen, c.length - 76) >> 1);
    let className: string | undefined;
    const clsOff = c.u32(48), clsLen = c.u16(74);
    if (clsOff !== 0xffffffff && clsLen) { try { const cc = this.cell(clsOff).data; className = new View(cc).utf16(0, Math.min(clsLen, cc.length) >> 1); } catch { /* bad class */ } }
    return {
      path: parentPath ? `${parentPath}\\${name}` : name, name, offset: off, lastWritten: filetime(c.u32(4), c.u32(8)),
      subkeyCount: c.u32(20), valueCount: c.u32(36), className, flags, securityOffset: c.u32(44),
    };
  }

  root(): RegKey { return this.key(this.header.rootCellOffset); }

  /** Child keys of a key, following lf, lh, li and ri lists. */
  subkeys(k: RegKey, limit = 100000): RegKey[] {
    const { data } = this.cell(k.offset);
    const listOff = new View(data, true).u32(28);
    const out: RegKey[] = [];
    if (!k.subkeyCount || listOff === 0xffffffff) return out;
    const walk = (off: number, depth: number): void => {
      if (depth > 4 || out.length >= limit) return;
      const { at, data: d } = this.cell(off);
      const c = new View(d, true);
      const sig = c.u16(0), n = c.u16(2);
      if (sig === 0x666c || sig === 0x686c) { for (let i = 0; i < n && out.length < limit && c.has(4 + i * 8, 4); i++) pushKey(c.u32(4 + i * 8)); }
      else if (sig === 0x696c) { for (let i = 0; i < n && out.length < limit && c.has(4 + i * 4, 4); i++) pushKey(c.u32(4 + i * 4)); }
      else if (sig === 0x6972) { for (let i = 0; i < n && c.has(4 + i * 4, 4); i++) walk(c.u32(4 + i * 4), depth + 1); }
      else throw new ParseError('unknown subkey list signature', at);
    };
    const pushKey = (o: number): void => { try { out.push(this.key(o, k.path)); } catch { /* skip broken child */ } };
    walk(listOff, 0);
    return out;
  }

  /** Values of a key with decoded data. */
  values(k: RegKey, opts: { limit?: number; maxData?: number } = {}): RegValue[] {
    if (!k.valueCount) return [];
    const { data } = this.cell(k.offset);
    const listOff = new View(data, true).u32(40);
    if (listOff === 0xffffffff) return [];
    const list = new View(this.cell(listOff).data, true);
    const out: RegValue[] = [];
    const n = Math.min(k.valueCount, opts.limit ?? 10000, list.length >> 2);
    for (let i = 0; i < n; i++) { try { out.push(this.value(list.u32(i * 4), opts.maxData ?? 4096)); } catch { /* skip broken value */ } }
    return out;
  }

  value(off: number, maxData = 4096): RegValue {
    const { at, data } = this.cell(off);
    const c = new View(data, true);
    if (c.length < 20 || c.u16(0) !== 0x6b76) throw new ParseError('vk value cell expected', at);
    const nameLen = c.u16(2);
    const rawSize = c.u32(4);
    const inline = (rawSize & 0x80000000) !== 0;
    const size = rawSize & 0x7fffffff;
    const dataOff = c.u32(8);
    const typeId = c.u32(12);
    const flags = c.u16(16);
    const name = nameLen === 0 ? '(default)' : flags & 1 ? latin(c.sub(20, Math.min(nameLen, c.length - 20))) : c.utf16(20, Math.min(nameLen, c.length - 20) >> 1);
    let raw: Uint8Array;
    if (inline) raw = c.sub(8, Math.min(size, 4));
    else if (size === 0) raw = new Uint8Array(0);
    else raw = this.data(dataOff, size, Math.max(maxData, 16));
    const truncated = raw.length < size;
    const r: RegValue = { name, type: REG_TYPES[typeId] ?? `0x${typeId.toString(16)}`, typeId, size, offset: off, dataOffset: inline ? null : dataOff, inline, value: decodeValue(typeId, raw, truncated) };
    if (typeId === 3 || typeId === 0 || typeId > 11 || (typeId >= 8 && typeId <= 10) || typeof r.value !== 'string' && r.value === null) r.hex = toHex(raw.subarray(0, 256));
    return r;
  }

  private data(off: number, size: number, cap: number): Uint8Array {
    const want = Math.min(size, cap);
    const { data } = this.cell(off);
    if (size > 16344 && this.minor >= 4 && data.length >= 8 && data[0] === 0x64 && data[1] === 0x62) {
      const c = new View(data, true);
      const n = c.u16(2);
      const seg = new View(this.cell(c.u32(4)).data, true);
      const out = new Uint8Array(want);
      let p = 0;
      for (let i = 0; i < n && p < want && seg.has(i * 4, 4); i++) {
        const s = this.cell(seg.u32(i * 4)).data;
        const take = Math.min(s.length, 16344, want - p);
        out.set(s.subarray(0, take), p);
        p += take;
      }
      return out.subarray(0, p);
    }
    return data.subarray(0, Math.min(want, data.length));
  }

  /** Find a key by backslash path relative to the root (root name optional). */
  find(path: string): RegKey | null {
    let k = this.root();
    const parts = path.split(/[\\/]+/).filter(Boolean);
    if (parts.length && parts[0]!.toLowerCase() === k.name.toLowerCase()) parts.shift();
    for (const part of parts) {
      const next = this.subkeys(k).find((s) => s.name.toLowerCase() === part.toLowerCase());
      if (!next) return null;
      k = next;
    }
    return k;
  }

  /** Depth first walk of keys, capped. */
  walk(from?: RegKey, opts: { maxKeys?: number; maxDepth?: number } = {}): { keys: RegKey[]; truncated: boolean } {
    const max = opts.maxKeys ?? 100000, maxDepth = opts.maxDepth ?? 64;
    const keys: RegKey[] = [];
    const stack: [RegKey, number][] = [[from ?? this.root(), 0]];
    const seen = new Set<number>();
    let truncated = false;
    while (stack.length) {
      const [k, d] = stack.pop()!;
      if (seen.has(k.offset)) continue;
      seen.add(k.offset);
      if (keys.length >= max) { truncated = true; break; }
      keys.push(k);
      if (d >= maxDepth) continue;
      const kids = this.subkeys(k);
      for (let i = kids.length - 1; i >= 0; i--) stack.push([kids[i]!, d + 1]);
    }
    return { keys, truncated };
  }
}

function latin(b: Uint8Array): string { let s = ''; for (const c of b) s += String.fromCharCode(c); return s; }
function utf16le(b: Uint8Array): string { let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i]! | (b[i + 1]! << 8)); return s; }

/** Decode registry value data by type. */
export function decodeValue(type: number, raw: Uint8Array, truncated = false): string | number | string[] | null {
  const v = new View(raw, true);
  switch (type) {
    case 1: case 2: case 6: { const s = utf16le(raw); const z = s.indexOf('\0'); return z >= 0 ? s.slice(0, z) : s; }
    case 7: { const s = utf16le(raw); return s.split('\0').filter((x, i, a) => x !== '' || i < a.length - 2).filter((x) => x !== ''); }
    case 4: return raw.length >= 4 ? v.u32(0) : null;
    case 5: return raw.length >= 4 ? v.u32(0, false) : null;
    case 11: return raw.length >= 8 ? v.u64(0).toString() : null;
    default: return truncated ? null : raw.length <= 64 && raw.every((c) => c >= 0x20 && c < 0x7f) && raw.length > 3 ? utf8(raw) : null;
  }
}

/** Summary of a hive: header, root, and key/value totals from a capped walk. */
export function inspectRegf(b: Uint8Array, opts: { maxKeys?: number } = {}): { header: RegfHeader; root: RegKey; keyCount: number; valueCount: number; truncated: boolean; topLevel: string[] } {
  const r = new Regf(b);
  const root = r.root();
  const w = r.walk(root, { maxKeys: opts.maxKeys ?? 200000 });
  let values = 0;
  for (const k of w.keys) values += k.valueCount;
  return { header: r.header, root, keyCount: w.keys.length, valueCount: values, truncated: w.truncated, topLevel: r.subkeys(root).map((k) => k.name) };
}
