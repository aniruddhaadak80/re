// APFS container reader: the NX superblock, the container object map, each volume superblock (name,
// role, counts, encryption flag) and the top level of each unencrypted volume's root directory.
// Read only and bounded. Snapshots, checkpoints beyond block 0 and encrypted metadata are not read.

import { BinView, FormatError } from './util.js';
import { decodeUtf8 } from '../bytes.js';

export interface ApfsTopEntry { name: string; id: number; kind: 'folder' | 'file' | 'symlink' | 'other' }
export interface ApfsVolume {
  index: number;
  oid: number;
  name: string;
  role: number;
  roleName: string;
  uuid: string;
  files: number;
  directories: number;
  symlinks: number;
  snapshots: number;
  encrypted: boolean;
  caseInsensitive: boolean;
  formattedBy: string;
  top?: ApfsTopEntry[];
  warnings: string[];
}
export interface ApfsContainer {
  blockSize: number;
  blockCount: number;
  uuid: string;
  nextXid: number;
  maxFileSystems: number;
  volumes: ApfsVolume[];
  warnings: string[];
}

const ROLES: Record<number, string> = { 0: 'none', 1: 'system', 2: 'user', 4: 'recovery', 8: 'vm', 16: 'preboot', 32: 'installer', 64: 'data', 128: 'baseband', 192: 'update', 256: 'xart', 320: 'hardware', 384: 'backup', 448: 'sidecar', 512: 'reserved', 576: 'enterprise', 640: 'prelogin' };

function uuid(v: BinView, o: number): string {
  const h = v.hex(o, 16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** True when block 0 holds an APFS container superblock. */
export function isApfs(b: Uint8Array): boolean {
  return b.length >= 4096 && b[32] === 0x4e && b[33] === 0x58 && b[34] === 0x53 && b[35] === 0x42;
}

const NODE_ROOT = 1, NODE_LEAF = 2, NODE_FIXED = 4;

interface Ctx { v: BinView; bs: number; budget: number }

function block(c: Ctx, paddr: number): number {
  const o = paddr * c.bs;
  if (!c.v.has(o, c.bs)) throw new FormatError(`APFS block ${paddr} is outside the image`);
  if (--c.budget < 0) throw new FormatError('APFS node budget used up');
  return o;
}

/** Walk a B-tree and call visit for each leaf record. resolve maps a child value to a physical block. */
function walkTree(c: Ctx, rootPaddr: number, resolve: (childOid: number) => number, visit: (k: number, klen: number, val: number, vlen: number) => boolean | void, depth = 0): boolean {
  if (depth > 12) throw new FormatError('APFS tree is too deep');
  const o = block(c, rootPaddr);
  const v = c.v;
  const flags = v.u16le(o + 32), level = v.u16le(o + 34), nkeys = v.u32le(o + 36);
  const tsOff = v.u16le(o + 40), tsLen = v.u16le(o + 42);
  const toc = o + 56 + tsOff;
  const keyStart = o + 56 + tsOff + tsLen;
  const valEnd = o + c.bs - (flags & NODE_ROOT ? 40 : 0);
  const fixed = (flags & NODE_FIXED) !== 0;
  for (let i = 0; i < nkeys && i < 4096; i++) {
    let k: number, klen: number, val: number, vlen: number;
    if (fixed) { k = keyStart + v.u16le(toc + i * 4); klen = 16; val = valEnd - v.u16le(toc + i * 4 + 2); vlen = 16; }
    else { k = keyStart + v.u16le(toc + i * 8); klen = v.u16le(toc + i * 8 + 2); val = valEnd - v.u16le(toc + i * 8 + 4); vlen = v.u16le(toc + i * 8 + 6); }
    if (!v.has(k, klen)) continue;
    if (level > 0 || !(flags & NODE_LEAF)) {
      if (!v.has(val, 8)) continue;
      if (walkTree(c, resolve(v.u64le(val)), resolve, visit, depth + 1) === false) return false;
    } else if (v.has(val, vlen) && visit(k, klen, val, vlen) === false) return false;
  }
  return true;
}

/** Object map lookup: newest physical address of a virtual object id. */
function omapLookup(c: Ctx, omapPaddr: number): (oid: number) => number {
  const o = block(c, omapPaddr);
  const treeOid = c.v.u64le(o + 48);
  const map = new Map<number, { xid: number; paddr: number }>();
  walkTree(c, treeOid, (x) => x, (k, _kl, val) => {
    const oid = c.v.u64le(k), xid = c.v.u64le(k + 8), paddr = c.v.u64le(val + 8);
    const cur = map.get(oid);
    if (!cur || cur.xid < xid) map.set(oid, { xid, paddr });
  });
  return (oid) => { const e = map.get(oid); if (!e) throw new FormatError(`APFS object ${oid} is not in the object map`); return e.paddr; };
}

/** Read the container and its volumes. maxTop caps each root directory listing. */
export function readApfsContainer(bytes: Uint8Array, opts: { maxTop?: number; nodeBudget?: number } = {}): ApfsContainer {
  const v = new BinView(bytes);
  if (!isApfs(bytes)) throw new FormatError('no APFS container superblock', 32);
  const bs = v.u32le(36);
  if (bs < 4096 || bs > 65536 || (bs & (bs - 1))) throw new FormatError('bad APFS block size', 36);
  const c: Ctx = { v, bs, budget: opts.nodeBudget ?? 20_000 };
  const out: ApfsContainer = { blockSize: bs, blockCount: v.u64le(40), uuid: uuid(v, 72), nextXid: v.u64le(96), maxFileSystems: v.u32le(180), volumes: [], warnings: [] };
  let resolve: (oid: number) => number;
  try { resolve = omapLookup(c, v.u64le(160)); } catch (e) { out.warnings.push(`container object map: ${(e as Error).message}`); return out; }
  for (let i = 0; i < Math.min(out.maxFileSystems, 100); i++) {
    const oid = v.u64le(184 + i * 8);
    if (!oid) continue;
    const vol: ApfsVolume = { index: i, oid, name: '', role: 0, roleName: 'none', uuid: '', files: 0, directories: 0, symlinks: 0, snapshots: 0, encrypted: false, caseInsensitive: false, formattedBy: '', warnings: [] };
    out.volumes.push(vol);
    try {
      const s = block(c, resolve(oid));
      if (v.ascii(s + 32, 4) !== 'APSB') { vol.warnings.push('volume superblock magic is wrong'); continue; }
      const incompat = v.u64le(s + 56);
      const fsFlags = v.u64le(s + 264);
      vol.caseInsensitive = (incompat & 1) !== 0;
      vol.encrypted = (fsFlags & 1) === 0; // APFS_FS_UNENCRYPTED is bit 0
      vol.files = v.u64le(s + 184); vol.directories = v.u64le(s + 192); vol.symlinks = v.u64le(s + 200); vol.snapshots = v.u64le(s + 216);
      vol.uuid = uuid(v, s + 240);
      vol.formattedBy = v.ascii(s + 272, 32);
      vol.name = decodeUtf8(v.sub(s + 704, 256)).split('\0')[0] ?? '';
      vol.role = v.u16le(s + 964);
      vol.roleName = ROLES[vol.role] ?? String(vol.role);
      if (vol.encrypted) { vol.warnings.push('volume metadata is encrypted; the root listing is skipped'); continue; }
      const vresolve = omapLookup(c, v.u64le(s + 128));
      const rootTree = vresolve(v.u64le(s + 136));
      const top: ApfsTopEntry[] = [];
      const cap = opts.maxTop ?? 1000;
      walkTree(c, rootTree, vresolve, (k, klen, val) => {
        const hdr = v.u64le(k);
        const type = Math.floor(hdr / 2 ** 60);
        const objId = hdr - type * 2 ** 60;
        if (type !== 9 || objId !== 2) return;
        // j_drec_hashed_key_t: name_len_and_hash then the name, NUL terminated
        const nlen = v.u32le(k + 8) & 0x3ff;
        const name = decodeUtf8(v.sub(k + 12, Math.max(0, Math.min(nlen, klen - 12)))).replace(/\0+$/, '');
        const id = v.u64le(val);
        const dt = v.u16le(val + 16) & 0xf;
        top.push({ name, id, kind: dt === 4 ? 'folder' : dt === 8 ? 'file' : dt === 10 ? 'symlink' : 'other' });
        if (top.length >= cap) return false;
      });
      top.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      vol.top = top;
    } catch (e) { vol.warnings.push((e as Error).message); }
  }
  return out;
}
