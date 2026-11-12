// HFS+ and HFSX volume reader: volume header and the catalog B-tree, enough to list the folder tree
// with names, kinds, sizes and dates. Read only, bounded, never follows the extents overflow file.

import { BinView, FormatError, isoUtc } from './util.js';

export interface HfsEntry {
  path: string;
  name: string;
  kind: 'folder' | 'file' | 'symlink';
  id: number;
  parentId: number;
  size?: number;
  /** folders only: the item count the catalog records */
  valence?: number;
  created?: string;
  modified?: string;
  /** file type and creator from the Finder info, when set */
  fileType?: string;
  creator?: string;
}

export interface HfsVolume {
  signature: 'H+' | 'HX';
  version: number;
  volumeName: string;
  blockSize: number;
  totalBlocks: number;
  freeBlocks: number;
  fileCount: number;
  folderCount: number;
  created?: string;
  modified?: string;
  journaled: boolean;
  catalog: { nodeSize: number; treeDepth: number; leafRecords: number; extents: number; complete: boolean };
  entries: HfsEntry[];
  truncated: boolean;
  warnings: string[];
}

const HFS_EPOCH = Date.UTC(1904, 0, 1) / 1000;
function hfsDate(v: number): string | undefined { return v ? isoUtc((v + HFS_EPOCH) * 1000) : undefined; }
function fourcc(v: number): string | undefined {
  if (!v) return undefined;
  let s = '';
  for (let k = 24; k >= 0; k -= 8) { const c = (v >>> k) & 0xff; s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '?'; }
  return s;
}

/** True when the bytes look like an HFS+ or HFSX volume (signature at offset 1024). */
export function isHfsPlus(b: Uint8Array): boolean {
  return b.length >= 1536 && b[1024] === 0x48 && (b[1025] === 0x2b || b[1025] === 0x58);
}

/** Read the volume header and walk the catalog leaves. maxEntries caps the listing. */
export function readHfsPlus(bytes: Uint8Array, opts: { maxEntries?: number } = {}): HfsVolume {
  const maxEntries = opts.maxEntries ?? 20_000;
  const v = new BinView(bytes);
  if (!isHfsPlus(bytes)) throw new FormatError('no HFS+ volume header', 1024);
  const h = 1024;
  const sig = v.ascii(h, 2) as 'H+' | 'HX';
  const blockSize = v.u32be(h + 40);
  if (blockSize < 512 || blockSize > 1 << 20 || (blockSize & (blockSize - 1))) throw new FormatError('bad HFS+ block size', h + 40);
  const warnings: string[] = [];
  // catalog fork data at 0x110
  const fork = h + 0x110;
  const logical = v.u64be(fork);
  const extents: { start: number; count: number }[] = [];
  let extBlocks = 0;
  for (let k = 0; k < 8; k++) {
    const start = v.u32be(fork + 16 + k * 8), count = v.u32be(fork + 20 + k * 8);
    if (!count) break;
    extents.push({ start, count }); extBlocks += count;
  }
  const forkBlocks = v.u32be(fork + 12);
  const complete = extBlocks >= forkBlocks;
  if (!complete) warnings.push('the catalog continues in the extents overflow file, which is not read; the listing may be partial');
  // Map a catalog file offset to a volume offset.
  const catOff = (o: number): number => {
    let blk = Math.floor(o / blockSize);
    for (const e of extents) { if (blk < e.count) return (e.start + blk) * blockSize + (o % blockSize); blk -= e.count; }
    return -1;
  };
  const head = catOff(0);
  if (head < 0 || !v.has(head, 512)) throw new FormatError('catalog header node is outside the volume', head);
  const nodeSize = v.u16be(head + 14 + 18);
  if (nodeSize < 512 || nodeSize > 65536) throw new FormatError('bad catalog node size', head + 32);
  const treeDepth = v.u16be(head + 14);
  const leafRecords = v.u32be(head + 14 + 6);
  const firstLeaf = v.u32be(head + 14 + 10);
  const nodeAt = (n: number): number => {
    const o = n * nodeSize;
    if (o + nodeSize > logical) return -1;
    // nodes may straddle allocation blocks only when nodeSize > blockSize; read through the map for each part.
    const p = catOff(o);
    if (p < 0 || !v.has(p, nodeSize)) return -1;
    if (nodeSize > blockSize) { const q = catOff(o + nodeSize - 1); if (q !== p + nodeSize - 1) return -2; }
    return p;
  };
  const raw: HfsEntry[] = [];
  const names = new Map<number, { name: string; parent: number }>();
  let truncated = false;
  let volumeName = '';
  const seen = new Set<number>();
  let node = firstLeaf, guard = 0;
  const maxNodes = Math.ceil(logical / nodeSize) + 1;
  while (node && guard++ < maxNodes) {
    if (seen.has(node)) { warnings.push('catalog leaf chain loops'); break; }
    seen.add(node);
    const p = nodeAt(node);
    if (p === -2) { warnings.push('a catalog node is split across fragments; stopped there'); break; }
    if (p < 0) { warnings.push(`catalog node ${node} is outside the catalog`); break; }
    const fLink = v.u32be(p);
    const kind = v.dv.getInt8(p + 8);
    const nrec = v.u16be(p + 10);
    if (kind !== -1) { warnings.push(`node ${node} is not a leaf node`); break; }
    for (let r = 0; r < nrec; r++) {
      const ro = v.u16be(p + nodeSize - 2 * (r + 1));
      if (ro < 14 || ro >= nodeSize) continue;
      const k = p + ro;
      const keyLen = v.u16be(k);
      const parent = v.u32be(k + 2);
      const nlen = Math.min(v.u16be(k + 6), 255);
      let name = '';
      for (let c = 0; c < nlen; c++) name += String.fromCharCode(v.u16be(k + 8 + c * 2));
      // The hidden hard link folder is named with four NUL characters; show it the way 7-Zip does.
      if (name.charCodeAt(0) === 0) name = `[${name.replace(/\0/g, '')}]`;
      const d = k + 2 + keyLen;
      if (!v.has(d, 2)) continue;
      const type = v.u16be(d);
      if (type === 1 && v.has(d, 88)) {
        const id = v.u32be(d + 8);
        names.set(id, { name, parent });
        if (parent === 1) { volumeName = name; continue; }
        raw.push({ path: '', name, kind: 'folder', id, parentId: parent, valence: v.u32be(d + 4), created: hfsDate(v.u32be(d + 12)), modified: hfsDate(v.u32be(d + 16)) });
      } else if (type === 2 && v.has(d, 248)) {
        const id = v.u32be(d + 8);
        const ftype = v.u32be(d + 48), creator = v.u32be(d + 52);
        const mode = v.u16be(d + 32 + 10);
        const isLink = (mode & 0xf000) === 0xa000 || (ftype === 0x736c6e6b && creator === 0x72686170);
        const e: HfsEntry = { path: '', name, kind: isLink ? 'symlink' : 'file', id, parentId: parent, size: v.u64be(d + 88), created: hfsDate(v.u32be(d + 12)), modified: hfsDate(v.u32be(d + 16)) };
        const ft = fourcc(ftype), cr = fourcc(creator);
        if (ft) e.fileType = ft;
        if (cr) e.creator = cr;
        names.set(id, { name, parent });
        raw.push(e);
      }
      if (raw.length >= maxEntries) { truncated = true; break; }
    }
    if (truncated) break;
    node = fLink;
  }
  const pathOf = (id: number): string => {
    const parts: string[] = [];
    let cur = id, depth = 0;
    while (cur > 2 && depth++ < 256) {
      const n = names.get(cur);
      if (!n) { parts.push(`#${cur}`); break; }
      parts.push(n.name);
      cur = n.parent;
    }
    return parts.reverse().join('/');
  };
  for (const e of raw) e.path = pathOf(e.id);
  raw.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return {
    signature: sig, version: v.u16be(h + 2), volumeName, blockSize, totalBlocks: v.u32be(h + 44), freeBlocks: v.u32be(h + 48),
    fileCount: v.u32be(h + 32), folderCount: v.u32be(h + 36), created: hfsDate(v.u32be(h + 16)), modified: hfsDate(v.u32be(h + 20)),
    journaled: (v.u32be(h + 4) & 0x2000) !== 0,
    catalog: { nodeSize, treeDepth, leafRecords, extents: extents.length, complete },
    entries: raw, truncated, warnings,
  };
}
