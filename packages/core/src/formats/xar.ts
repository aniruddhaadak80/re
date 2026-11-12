// xar archives (macOS flat .pkg, .xip, Safari extensions): header, zlib compressed XML table of
// contents, the heap, and per file archived and extracted checksums that are checked when asked.

import { BinView, FormatError, toHex } from './util.js';
import { parseXml, child, childrenNamed, findFirst, type XmlNode } from './xml.js';
import { decompress } from '../archive/inflate.js';
import { bunzip2 } from './bzip2.js';
import { decodeUtf8 } from '../bytes.js';
import { md5, sha1, sha256 } from '../hash.js';
import { base64Decode } from './util.js';

export interface XarFile {
  id: string;
  path: string;
  name: string;
  type: string;
  mode?: string;
  uid?: number;
  gid?: number;
  user?: string;
  group?: string;
  mtime?: string;
  /** stored (archived) length in the heap */
  length: number;
  /** extracted size */
  size: number;
  /** absolute file offset of the stored bytes */
  offset: number;
  encoding: string;
  archivedChecksum?: { style: string; value: string };
  extractedChecksum?: { style: string; value: string };
  link?: string;
}

export interface XarArchive {
  format: 'xar';
  headerSize: number;
  version: number;
  tocCompressed: number;
  tocUncompressed: number;
  checksumAlgorithm: string;
  heapOffset: number;
  tocChecksum?: { style: string; offset: number; size: number; matches: boolean | null };
  signatures: { kind: 'signature' | 'x-signature'; style: string; offset: number; size: number; certificates: number; firstCertificateSha256?: string }[];
  created?: string;
  files: XarFile[];
  truncated: boolean;
  toc: string;
  warnings: string[];
}

const ALGS: Record<number, string> = { 0: 'none', 1: 'sha1', 2: 'md5', 3: 'other' };

export function isXar(b: Uint8Array): boolean { return b.length >= 28 && b[0] === 0x78 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21; }

function num(n: XmlNode | undefined): number { const v = Number(n?.text.trim() ?? ''); return Number.isFinite(v) ? v : 0; }
function txt(n: XmlNode | undefined): string | undefined { const t = n?.text.trim(); return t === undefined || t === '' ? undefined : t; }

/** Hash with the algorithm a xar checksum names. Unknown styles return null. */
export function xarDigest(style: string, b: Uint8Array): string | null {
  const s = style.toLowerCase();
  if (s === 'sha1') return sha1(b);
  if (s === 'md5') return md5(b);
  if (s === 'sha256') return sha256(b);
  return null;
}

/** Parse the header and table of contents. */
export async function parseXar(bytes: Uint8Array, opts: { maxFiles?: number } = {}): Promise<XarArchive> {
  const maxFiles = opts.maxFiles ?? 100_000;
  const v = new BinView(bytes);
  if (!isXar(bytes)) throw new FormatError('no xar! magic', 0);
  const headerSize = v.u16be(4), version = v.u16be(6);
  const tocCompressed = v.u64be(8), tocUncompressed = v.u64be(16);
  const algId = v.u32be(24);
  let checksumAlgorithm = ALGS[algId] ?? String(algId);
  if (algId === 3 && headerSize > 28) checksumAlgorithm = v.ascii(28, Math.min(headerSize - 28, 36));
  if (headerSize < 28 || !v.has(headerSize, tocCompressed)) throw new FormatError('xar table of contents is outside the file', headerSize);
  if (tocUncompressed > 64 * 1024 * 1024) throw new FormatError('xar table of contents is over 64 MiB');
  const tocBytes = await decompress(bytes.subarray(headerSize, headerSize + tocCompressed), 'deflate', Math.max(1024, tocUncompressed + 1024));
  const toc = decodeUtf8(tocBytes);
  const heapOffset = headerSize + tocCompressed;
  const warnings: string[] = [];
  const doc = parseXml(toc);
  const root = findFirst(doc, 'toc');
  if (!root) throw new FormatError('xar table of contents has no <toc> element');
  const out: XarArchive = { format: 'xar', headerSize, version, tocCompressed, tocUncompressed, checksumAlgorithm, heapOffset, signatures: [], files: [], truncated: false, toc: toc.length > 65536 ? toc.slice(0, 65536) : toc, warnings };
  const created = txt(child(root, 'creation-time'));
  if (created) out.created = created;
  const ck = child(root, 'checksum');
  if (ck) {
    const style = ck.attrs.style ?? checksumAlgorithm;
    const off = num(child(ck, 'offset')), size = num(child(ck, 'size'));
    let matches: boolean | null = null;
    if (v.has(heapOffset + off, size)) {
      const d = xarDigest(style, bytes.subarray(headerSize, headerSize + tocCompressed));
      if (d !== null) matches = d === toHex(bytes.subarray(heapOffset + off, heapOffset + off + size));
    }
    out.tocChecksum = { style, offset: off, size, matches };
  }
  for (const kind of ['signature', 'x-signature'] as const) {
    for (const s of childrenNamed(root, kind)) {
      const certs = findFirst(s, 'X509Data')?.children.filter((c) => c.local === 'X509Certificate') ?? [];
      const first = certs[0] ? base64Decode(certs[0].text) : undefined;
      out.signatures.push({ kind, style: s.attrs.style ?? '', offset: num(child(s, 'offset')), size: num(child(s, 'size')), certificates: certs.length, ...(first && first.length ? { firstCertificateSha256: sha256(first) } : {}) });
    }
  }
  const walk = (parent: XmlNode, prefix: string, depth: number): void => {
    if (depth > 64) { warnings.push('xar directory nesting is deeper than 64'); return; }
    for (const f of childrenNamed(parent, 'file')) {
      if (out.files.length >= maxFiles) { out.truncated = true; return; }
      const name = txt(child(f, 'name')) ?? '';
      const path = prefix ? `${prefix}/${name}` : name;
      const data = child(f, 'data');
      const enc = child(data, 'encoding')?.attrs.style ?? '';
      const e: XarFile = {
        id: f.attrs.id ?? '', path, name, type: txt(child(f, 'type')) ?? 'file',
        length: num(child(data, 'length')), size: num(child(data, 'size')),
        offset: data ? heapOffset + num(child(data, 'offset')) : 0, encoding: enc,
      };
      const mode = txt(child(f, 'mode')); if (mode) e.mode = mode;
      const uid = txt(child(f, 'uid')); if (uid) e.uid = Number(uid);
      const gid = txt(child(f, 'gid')); if (gid) e.gid = Number(gid);
      const user = txt(child(f, 'user')); if (user) e.user = user;
      const group = txt(child(f, 'group')); if (group) e.group = group;
      const mtime = txt(child(f, 'mtime')); if (mtime) e.mtime = mtime;
      const link = child(f, 'link'); if (link) e.link = link.text.trim();
      const ac = child(data, 'archived-checksum'); if (ac) e.archivedChecksum = { style: ac.attrs.style ?? '', value: ac.text.trim().toLowerCase() };
      const ec = child(data, 'extracted-checksum'); if (ec) e.extractedChecksum = { style: ec.attrs.style ?? '', value: ec.text.trim().toLowerCase() };
      out.files.push(e);
      walk(f, path, depth + 1);
    }
  };
  walk(root, '', 0);
  return out;
}

/** Read and decode one member. Checks the archived checksum before decoding and the extracted one after. */
export async function readXarFile(bytes: Uint8Array, f: XarFile, opts: { maxBytes?: number } = {}): Promise<{ data: Uint8Array; archivedMatches: boolean | null; extractedMatches: boolean | null }> {
  const maxBytes = opts.maxBytes ?? 256 * 1024 * 1024;
  if (f.type !== 'file') throw new FormatError(`${f.path} is a ${f.type}, not a file`);
  if (f.offset < 0 || f.offset + f.length > bytes.length) throw new FormatError(`${f.path}: stored bytes are outside the file`, f.offset);
  const stored = bytes.subarray(f.offset, f.offset + f.length);
  const am = f.archivedChecksum ? xarDigest(f.archivedChecksum.style, stored) : null;
  const archivedMatches = am === null ? null : am === f.archivedChecksum?.value;
  let data: Uint8Array;
  const enc = f.encoding.toLowerCase();
  if (enc.includes('gzip') || enc.includes('zlib')) data = await decompress(stored, 'deflate', Math.max(f.size, 1) + 16).catch(async () => decompress(stored, 'gzip', maxBytes));
  else if (enc.includes('bzip2')) data = bunzip2(stored, maxBytes);
  else if (enc === '' || enc.includes('octet-stream')) data = stored;
  else throw new FormatError(`${f.path}: encoding ${f.encoding} is not supported`);
  if (data.length > maxBytes) throw new FormatError(`${f.path}: extracted size passes the limit`);
  const em = f.extractedChecksum ? xarDigest(f.extractedChecksum.style, data) : null;
  return { data, archivedMatches, extractedMatches: em === null ? null : em === f.extractedChecksum?.value };
}


