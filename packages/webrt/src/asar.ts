// Electron ASAR archive reader. Format: a Chromium Pickle holding the header size, then a Pickle
// holding the JSON header string, then file data. File offsets in the header are relative to the
// end of the header. Files marked "unpacked" live next to the archive in <name>.asar.unpacked/.
import { Reader, InputError, safeRelPath, decodeUtf8 } from './util.js';

export interface AsarEntry {
  path: string;
  type: 'file' | 'dir' | 'link';
  size: number;
  /** absolute offset of file data inside the archive, undefined for unpacked files and dirs */
  offset?: number;
  unpacked?: boolean;
  executable?: boolean;
  link?: string;
  integrity?: { algorithm: string; hash: string; blockSize?: number; blocks?: number };
}

export interface AsarArchive {
  headerSize: number;
  dataOffset: number;
  headerSha256?: string;
  entries: AsarEntry[];
  files: number;
  dirs: number;
  unpackedFiles: number;
  totalSize: number;
  truncated: boolean;
}

interface HeaderNode { files?: Record<string, HeaderNode>; size?: number; offset?: string; unpacked?: boolean; executable?: boolean; link?: string; integrity?: { algorithm?: string; hash?: string; blockSize?: number; blocks?: string[] } }

const MAX_HEADER = 64 * 1024 * 1024;
const MAX_ENTRIES = 500_000;
const MAX_DEPTH = 128;

export function isAsar(bytes: Uint8Array): boolean {
  if (bytes.length < 16) return false;
  const r = new Reader(bytes);
  return r.u32(0, true) === 4 && r.u32(4, true) >= 8 && bytes[16] === 0x7b;
}

/** Parse the ASAR header and list every entry with absolute data offsets. */
export function readAsar(bytes: Uint8Array, opts: { maxEntries?: number } = {}): AsarArchive {
  const r = new Reader(bytes);
  if (bytes.length < 16) throw new InputError('file too small for an ASAR header');
  const sizePickle = r.u32(0, true);
  if (sizePickle !== 4) throw new InputError(`not an ASAR archive (size pickle is ${sizePickle}, expected 4)`);
  const headerSize = r.u32(4, true);
  const payload = r.u32(8, true);
  const strLen = r.u32(12, true);
  if (headerSize > MAX_HEADER || strLen > headerSize || payload > headerSize) throw new InputError(`ASAR header size ${headerSize} out of range`);
  const json = decodeUtf8(r.slice(16, strLen));
  let root: HeaderNode;
  try { root = JSON.parse(json) as HeaderNode; } catch (e) { throw new InputError(`ASAR header is not valid JSON: ${(e as Error).message}`); }
  const dataOffset = 8 + headerSize;
  const max = Math.min(opts.maxEntries ?? MAX_ENTRIES, MAX_ENTRIES);
  const entries: AsarEntry[] = [];
  let files = 0, dirs = 0, unpackedFiles = 0, totalSize = 0, truncated = false;
  const stack: { node: HeaderNode; path: string; depth: number }[] = [{ node: root, path: '', depth: 0 }];
  while (stack.length) {
    const { node, path, depth } = stack.pop()!;
    if (!node.files || typeof node.files !== 'object') continue;
    const names = Object.keys(node.files).sort().reverse();
    for (const name of names) {
      if (entries.length >= max) { truncated = true; break; }
      const child = node.files[name];
      if (!child || typeof child !== 'object') continue;
      const p = path ? `${path}/${name}` : name;
      if (child.files) {
        dirs++;
        entries.push({ path: p, type: 'dir', size: 0, unpacked: child.unpacked || undefined });
        if (depth + 1 < MAX_DEPTH) stack.push({ node: child, path: p, depth: depth + 1 });
        else truncated = true;
        continue;
      }
      if (typeof child.link === 'string') { entries.push({ path: p, type: 'link', size: 0, link: child.link }); continue; }
      const size = Number(child.size ?? 0);
      files++;
      totalSize += Number.isFinite(size) ? size : 0;
      const e: AsarEntry = { path: p, type: 'file', size: Number.isFinite(size) && size >= 0 ? size : 0 };
      if (child.unpacked) { e.unpacked = true; unpackedFiles++; }
      else {
        const off = Number(child.offset ?? 0);
        if (Number.isFinite(off) && off >= 0) e.offset = dataOffset + off;
      }
      if (child.executable) e.executable = true;
      if (child.integrity?.hash) e.integrity = { algorithm: String(child.integrity.algorithm ?? ''), hash: String(child.integrity.hash), blockSize: child.integrity.blockSize, blocks: child.integrity.blocks?.length };
      entries.push(e);
    }
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { headerSize, dataOffset, entries, files, dirs, unpackedFiles, totalSize, truncated };
}

/** Bytes of one packed file. Returns undefined for unpacked files (read them from the .asar.unpacked folder). */
export function readAsarFile(bytes: Uint8Array, archive: AsarArchive, path: string): Uint8Array | undefined {
  const norm = path.replace(/\\/g, '/').replace(/^\/+/, '');
  const e = archive.entries.find((x) => x.path === norm);
  if (!e || e.type !== 'file') throw new InputError(`no file ${path} in archive`);
  if (e.unpacked || e.offset === undefined) return undefined;
  if (e.offset + e.size > bytes.length) throw new InputError(`file ${path} runs past end of archive`);
  return bytes.subarray(e.offset, e.offset + e.size);
}

/** Resolve a link entry inside the archive without leaving it. Returns the safe target path or undefined. */
export function resolveAsarLink(entryPath: string, link: string): string | undefined {
  const base = entryPath.split('/').slice(0, -1);
  for (const part of link.replace(/\\/g, '/').split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') { if (!base.length) return undefined; base.pop(); } else base.push(part);
  }
  const out = base.join('/');
  return safeRelPath(out) === out ? out : undefined;
}
