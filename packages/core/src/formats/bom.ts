// Apple bill of materials (Bom, BOMStore): the file list a pkg installs, with modes, owners, sizes,
// CRC checksums and link targets, read from the Paths tree like lsbom does.

import { BinView, FormatError } from './util.js';

export interface BomEntry { path: string; type: 'file' | 'dir' | 'link' | 'device' | 'unknown'; mode: number; uid: number; gid: number; mtime: number; size: number; checksum?: number; link?: string }
export interface BomInfo { version: number; blocks: number; vars: string[]; pathCount: number; entries: BomEntry[]; truncated: boolean; warnings: string[] }

const TYPES: Record<number, BomEntry['type']> = { 1: 'file', 2: 'dir', 3: 'link', 4: 'device' };

export function isBom(b: Uint8Array): boolean { return b.length >= 32 && String.fromCharCode(...b.subarray(0, 8)) === 'BOMStore'; }

/** Read the BOMStore and list every path. */
export function parseBom(bytes: Uint8Array, opts: { maxEntries?: number } = {}): BomInfo {
  const maxEntries = opts.maxEntries ?? 100_000;
  const v = new BinView(bytes);
  if (!isBom(bytes)) throw new FormatError('no BOMStore magic', 0);
  const version = v.u32be(8), blocks = v.u32be(12);
  const indexOff = v.u32be(16), varsOff = v.u32be(24);
  const nptr = v.u32be(indexOff);
  if (nptr > 10_000_000 || !v.has(indexOff + 4, nptr * 8)) throw new FormatError('BOM block index is outside the file', indexOff);
  const blk = (i: number): { off: number; len: number } => {
    if (i >= nptr) throw new FormatError(`BOM block ${i} does not exist`);
    const off = v.u32be(indexOff + 4 + i * 8), len = v.u32be(indexOff + 8 + i * 8);
    if (!v.has(off, len)) throw new FormatError(`BOM block ${i} is outside the file`, off);
    return { off, len };
  };
  const nvars = v.u32be(varsOff);
  const vars = new Map<string, number>();
  let p = varsOff + 4;
  for (let i = 0; i < nvars && i < 1024; i++) {
    const idx = v.u32be(p); const nl = v.u8(p + 4);
    vars.set(v.ascii(p + 5, nl), idx);
    p += 5 + nl;
  }
  const warnings: string[] = [];
  const info: BomInfo = { version, blocks, vars: [...vars.keys()], pathCount: 0, entries: [], truncated: false, warnings };
  const pathsVar = vars.get('Paths');
  if (pathsVar === undefined) { warnings.push('no Paths tree'); return info; }
  const tree = blk(pathsVar);
  if (v.ascii(tree.off, 4) !== 'tree') throw new FormatError('Paths is not a BOM tree', tree.off);
  let node = v.u32be(tree.off + 8);
  info.pathCount = v.u32be(tree.off + 16);
  // descend to the first leaf
  for (let depth = 0; depth < 64; depth++) {
    const b = blk(node);
    if (v.u16be(b.off) !== 0) break;
    if (v.u16be(b.off + 2) === 0) break;
    node = v.u32be(b.off + 12);
  }
  const byId = new Map<number, { parent: number; name: string }>();
  const raw: { id: number; e: BomEntry }[] = [];
  const seen = new Set<number>();
  while (node && !seen.has(node)) {
    seen.add(node);
    const b = blk(node);
    const count = v.u16be(b.off + 2), forward = v.u32be(b.off + 4);
    for (let i = 0; i < count; i++) {
      const e0 = b.off + 12 + i * 8;
      const info1 = blk(v.u32be(e0)), file = blk(v.u32be(e0 + 4));
      const id = v.u32be(info1.off), info2 = blk(v.u32be(info1.off + 4));
      const parent = v.u32be(file.off);
      const name = v.ascii(file.off + 4, Math.max(0, file.len - 4));
      byId.set(id, { parent, name });
      const q = info2.off;
      const type = TYPES[v.u8(q)] ?? 'unknown';
      const e: BomEntry = { path: '', type, mode: v.u16be(q + 4), uid: v.u32be(q + 6), gid: v.u32be(q + 10), mtime: v.u32be(q + 14), size: v.u32be(q + 18) };
      if (type === 'file' || type === 'link') e.checksum = v.u32be(q + 23);
      if (type === 'link' && info2.len >= 31) { const ll = v.u32be(q + 27); if (ll && v.has(q + 31, ll)) e.link = v.ascii(q + 31, ll); }
      raw.push({ id, e });
      if (raw.length >= maxEntries) { info.truncated = true; break; }
    }
    if (info.truncated) break;
    node = forward;
  }
  const pathOf = (id: number): string => {
    const parts: string[] = [];
    let cur = id, guard = 0;
    while (cur && guard++ < 512) { const n = byId.get(cur); if (!n) break; parts.push(n.name); cur = n.parent; }
    return parts.reverse().join('/');
  };
  for (const r of raw) { r.e.path = pathOf(r.id); info.entries.push(r.e); }
  return info;
}
