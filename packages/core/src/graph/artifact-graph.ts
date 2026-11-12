// Content addressed artifact graph. Every distinct byte string is one node keyed by its SHA-256;
// every place it occurs is an occurrence with a logical path such as "app.dmg!/1.hfs!/App.app/x".
// Edges say how a node relates to its parent: "contains" for archive and file system members,
// "derived-from" for bytes produced by decoding (a gzip payload, a disk image partition).
// Containers expanded: ZIP family (JAR, APK, IPA, VSIX, XPI, MSIX, APPX), CRX, tar, gzip, ASAR,
// xar and flat pkg (with Scripts and Payload cpio streams), UDIF disk images (partitions and HFS+
// files). Output as JSON or Mermaid.

import { sha256 } from '../hash.js';
import { detectFormat } from '../format.js';
import type { FormatId } from '../types.js';
import { listTar, listAsar, crxZipOffset } from '../archive/containers.js';
import { decompress } from '../archive/inflate.js';
import { readZip, readZipMember } from '../formats/zip.js';
import { parseXar, readXarFile } from '../formats/xar.js';
import { parseDmg, extractDmgPartition } from '../formats/dmg.js';
import { readHfsPlus, readHfsFile, isHfsPlus } from '../formats/hfsplus.js';
import { listCpio, isCpio } from '../formats/cpio.js';
import { bunzip2 } from '../formats/bzip2.js';

export interface GraphNode { id: string; size: number; format: FormatId | 'directory'; names: string[]; occurrences: number; expanded?: boolean; note?: string }
export interface GraphEdge { from: string; to: string; kind: 'contains' | 'derived-from'; path: string; method?: string }
export interface Occurrence { path: string; sha256: string; parent?: string; depth: number; size: number; format: FormatId | 'directory'; kind?: 'file' | 'dir' | 'symlink' }
export interface ArtifactGraph {
  schema: 'revlens/artifact-graph@1';
  root: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  occurrences: Occurrence[];
  truncated: boolean;
  limits: { maxDepth: number; maxNodes: number; maxOccurrences: number; maxMemberBytes: number; maxTotalBytes: number };
  warnings: string[];
}
export interface GraphOptions { maxDepth?: number; maxNodes?: number; maxOccurrences?: number; maxMemberBytes?: number; maxTotalBytes?: number }

export interface Member { path: string; read: () => Promise<Uint8Array>; size: number; kind: 'contains' | 'derived-from'; method?: string; entryKind?: 'file' | 'dir' | 'symlink' }

const ZIPS = new Set(['zip', 'jar', 'apk', 'ipa', 'vsix', 'xpi', 'msix', 'appx']);

/** Members of a container, or null when the bytes are not a container RevLens expands. */
export async function containerMembers(bytes: Uint8Array, format: FormatId, maxMember: number): Promise<Member[] | null> {
  if (ZIPS.has(format)) {
    const z = readZip(bytes);
    return z.members.filter((m) => !m.name.endsWith('/')).map((m) => ({ path: m.name, size: m.size, kind: 'contains' as const, method: m.method === 8 ? 'deflate' : m.method === 0 ? 'stored' : `method ${m.method}`, read: () => readZipMember(bytes, m, maxMember) }));
  }
  if (format === 'crx') {
    const off = crxZipOffset(bytes);
    if (off < 0 || off >= bytes.length) return [];
    const inner = bytes.subarray(off);
    return [{ path: 'extension.zip', size: inner.length, kind: 'derived-from', method: 'crx header stripped', read: async () => inner }];
  }
  if (format === 'tar') return listTar(bytes).map((e) => ({ path: e.name, size: e.size, kind: 'contains' as const, read: e.read }));
  if (format === 'asar') return listAsar(bytes).map((e) => ({ path: e.name, size: e.size, kind: 'contains' as const, read: e.read }));
  if (format === 'gzip' || format === 'npm-tgz') return [{ path: 'payload', size: -1, kind: 'derived-from', method: 'gzip', read: () => decompress(bytes, 'gzip', maxMember) }];
  if (format === 'pkg' || format === 'xar') {
    const x = await parseXar(bytes);
    return x.files.filter((f) => f.type === 'file').map((f) => ({ path: f.path, size: f.size, kind: 'contains' as const, method: f.encoding, read: async () => (await readXarFile(bytes, f, { maxBytes: maxMember })).data }));
  }
  if (format === 'dmg') {
    const info = parseDmg(bytes);
    return info.partitions.filter((p) => p.size > 0 && !(Object.keys(p.methods).length === 1 && p.methods.ignore)).map((p) => ({
      path: `${p.index}.${partitionSuffix(p.name)}`, size: p.size, kind: 'derived-from' as const, method: Object.keys(p.methods).join('+'),
      read: async () => (await extractDmgPartition(bytes, info, p.index, { maxBytes: maxMember })).bytes,
    }));
  }
  if (isHfsPlus(bytes)) {
    const v = readHfsPlus(bytes, { maxEntries: 20_000 });
    return v.entries.map((e) => ({ path: e.path, size: e.size ?? 0, kind: 'contains' as const, entryKind: e.kind === 'folder' ? 'dir' as const : e.kind, read: async () => (e.kind === 'file' ? readHfsFile(bytes, v, e, maxMember) : new Uint8Array(0)) }));
  }
  if (isCpio(bytes)) {
    const l = listCpio(bytes, 100_000);
    return l.entries.filter((e) => e.kind === 'file').map((e) => ({ path: e.name.replace(/^\.\//, ''), size: e.size, kind: 'contains' as const, read: async () => bytes.subarray(e.offset, e.offset + e.size) }));
  }
  // pkg Scripts and Payload streams: gzip or bzip2 around cpio
  if (format === 'unknown' && bytes.length > 3 && bytes[0] === 0x42 && bytes[1] === 0x5a && bytes[2] === 0x68) return [{ path: 'payload', size: -1, kind: 'derived-from', method: 'bzip2', read: async () => bunzip2(bytes, maxMember) }];
  return null;
}

function partitionSuffix(name: string): string {
  if (/Apple_HFSX/i.test(name)) return 'hfsx';
  if (/Apple_HFS/i.test(name)) return 'hfs';
  if (/APFS/i.test(name)) return 'apfs';
  if (/MBR/i.test(name)) return 'mbr';
  if (/GPT Header/i.test(name)) return 'gpt-header';
  if (/GPT Partition/i.test(name)) return 'gpt';
  if (/Apple_Free/i.test(name)) return 'free';
  return 'img';
}

export interface GraphBuilder { graph: ArtifactGraph; add(bytes: Uint8Array, path: string, depth: number, parent?: { id: string; kind: 'contains' | 'derived-from'; member: string; method?: string }, kind?: Occurrence['kind']): Promise<string> }

/** A graph that can take several roots (used for folders). */
export function newGraph(root: string, opts: GraphOptions = {}): GraphBuilder {
  const limits = { maxDepth: opts.maxDepth ?? 4, maxNodes: opts.maxNodes ?? 5000, maxOccurrences: opts.maxOccurrences ?? 20_000, maxMemberBytes: opts.maxMemberBytes ?? 128 * 1024 * 1024, maxTotalBytes: opts.maxTotalBytes ?? 1024 * 1024 * 1024 };
  const graph: ArtifactGraph = { schema: 'revlens/artifact-graph@1', root, nodes: [], edges: [], occurrences: [], truncated: false, limits, warnings: [] };
  const byId = new Map<string, GraphNode>();
  const edgeKeys = new Set<string>();
  let total = 0;
  const add = async (bytes: Uint8Array, path: string, depth: number, parent?: { id: string; kind: 'contains' | 'derived-from'; member: string; method?: string }, kind?: Occurrence['kind']): Promise<string> => {
    const id = sha256(bytes);
    const name = path.slice(path.lastIndexOf('/') + 1).replace(/^.*!/, '') || path;
    const format = detectFormat(bytes, name);
    if (graph.occurrences.length < limits.maxOccurrences) graph.occurrences.push({ path, sha256: id, ...(parent ? { parent: parent.id } : {}), depth, size: bytes.length, format, ...(kind && kind !== 'file' ? { kind } : {}) });
    else graph.truncated = true;
    if (parent) {
      const ek = `${parent.id}>${id}>${parent.member}`;
      if (!edgeKeys.has(ek)) { edgeKeys.add(ek); graph.edges.push({ from: parent.id, to: id, kind: parent.kind, path: parent.member, ...(parent.method ? { method: parent.method } : {}) }); }
    }
    let node = byId.get(id);
    if (node) { node.occurrences++; if (!node.names.includes(name) && node.names.length < 16) node.names.push(name); return id; }
    if (graph.nodes.length >= limits.maxNodes) { graph.truncated = true; return id; }
    node = { id, size: bytes.length, format, names: [name], occurrences: 1 };
    byId.set(id, node);
    graph.nodes.push(node);
    if (depth >= limits.maxDepth) return id;
    let members: Member[] | null = null;
    try { members = await containerMembers(bytes, format, limits.maxMemberBytes); } catch (e) { node.note = `not expanded: ${(e as Error).message}`; return id; }
    if (!members) return id;
    node.expanded = true;
    for (const m of members) {
      if (graph.nodes.length >= limits.maxNodes || graph.occurrences.length >= limits.maxOccurrences) { graph.truncated = true; break; }
      if (m.entryKind === 'dir' || m.entryKind === 'symlink') {
        if (graph.occurrences.length < limits.maxOccurrences) graph.occurrences.push({ path: `${path}!/${m.path}`, sha256: '', parent: id, depth: depth + 1, size: 0, format: 'directory', kind: m.entryKind });
        continue;
      }
      if (m.size > limits.maxMemberBytes) { graph.warnings.push(`${path}!/${m.path}: ${m.size} bytes is over the member limit; not read`); continue; }
      if (total + Math.max(0, m.size) > limits.maxTotalBytes) { graph.truncated = true; graph.warnings.push('total expanded bytes reached the limit'); break; }
      let data: Uint8Array;
      try { data = await m.read(); } catch (e) { graph.warnings.push(`${path}!/${m.path}: ${(e as Error).message}`); continue; }
      total += data.length;
      await add(data, `${path}!/${m.path}`, depth + 1, { id, kind: m.kind, member: m.path, ...(m.method ? { method: m.method } : {}) }, m.entryKind ?? 'file');
    }
    return id;
  };
  return { graph, add };
}

/** Build the graph of one file. */
export async function buildArtifactGraph(bytes: Uint8Array, name = 'input.bin', opts: GraphOptions = {}): Promise<ArtifactGraph> {
  const g = newGraph(name, opts);
  await g.add(bytes, name, 0);
  return g.graph;
}

function mermaidLabel(s: string): string {
  // Mermaid labels inside quotes: replace quotes and control characters, keep it short
  let out = '';
  for (const ch of s.slice(0, 60)) { const c = ch.charCodeAt(0); out += ch === '"' ? "'" : c < 32 ? ' ' : ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch; }
  return out;
}

/** Mermaid flowchart of the graph, capped at maxNodes nodes. */
export function graphToMermaid(g: ArtifactGraph, maxNodes = 200): string {
  const ids = new Map<string, string>();
  const lines = ['graph TD'];
  for (const n of g.nodes.slice(0, maxNodes)) {
    const k = `n${ids.size}`;
    ids.set(n.id, k);
    lines.push(`  ${k}["${mermaidLabel(n.names[0] ?? n.id)}<br/>${n.format} ${n.size} B<br/>${n.id.slice(0, 12)}"]`);
  }
  for (const e of g.edges) {
    const a = ids.get(e.from), b = ids.get(e.to);
    if (!a || !b) continue;
    lines.push(`  ${a} -->|${e.kind === 'contains' ? 'contains' : 'derived'}| ${b}`);
  }
  if (g.nodes.length > maxNodes) lines.push(`  more["${g.nodes.length - maxNodes} more nodes not drawn"]`);
  return lines.join('\n') + '\n';
}

export interface InventoryChange { path: string; before: string; after: string; beforeSize: number; afterSize: number; format: string }
export interface InventoryDiff {
  schema: 'revlens/inventory-diff@1';
  left: { root: string; sha256: string; occurrences: number; nodes: number };
  right: { root: string; sha256: string; occurrences: number; nodes: number };
  added: Occurrence[];
  removed: Occurrence[];
  changed: InventoryChange[];
  moved: { sha256: string; from: string[]; to: string[] }[];
  unchanged: number;
  contentOnlyLeft: number;
  contentOnlyRight: number;
  identical: boolean;
  summary: string;
}

/** Path of an occurrence without its root name, so two roots with different names line up. */
function logical(o: Occurrence, root: string): string {
  if (o.path === root) return '';
  return o.path.startsWith(root + '!/') ? o.path.slice(root.length + 2) : o.path.startsWith(root + '/') ? o.path.slice(root.length + 1) : o.path;
}

/** Compare two inventories by logical occurrence path and by content identity. */
export function compareInventories(a: ArtifactGraph, b: ArtifactGraph, limit = 2000): InventoryDiff {
  const A = new Map<string, Occurrence>(), B = new Map<string, Occurrence>();
  for (const o of a.occurrences) if (o.sha256) A.set(logical(o, a.root), o);
  for (const o of b.occurrences) if (o.sha256) B.set(logical(o, b.root), o);
  const added: Occurrence[] = [], removed: Occurrence[] = [], changed: InventoryChange[] = [];
  let unchanged = 0;
  for (const [p, o] of A) {
    const q = B.get(p);
    if (!q) removed.push(o);
    else if (q.sha256 !== o.sha256) { if (p !== '') changed.push({ path: p, before: o.sha256, after: q.sha256, beforeSize: o.size, afterSize: q.size, format: q.format }); }
    else unchanged++;
  }
  for (const [p, o] of B) if (!A.has(p)) added.push(o);
  // moved: content that disappeared at one path and appeared at another
  const goneBySha = new Map<string, string[]>();
  for (const o of removed) (goneBySha.get(o.sha256) ?? goneBySha.set(o.sha256, []).get(o.sha256)!).push(logical(o, a.root));
  const moved: InventoryDiff['moved'] = [];
  for (const o of added) {
    const from = goneBySha.get(o.sha256);
    if (from) { const m = moved.find((x) => x.sha256 === o.sha256); if (m) m.to.push(logical(o, b.root)); else moved.push({ sha256: o.sha256, from, to: [logical(o, b.root)] }); }
  }
  const movedSha = new Set(moved.map((m) => m.sha256));
  const ids = (g: ArtifactGraph): Set<string> => new Set(g.nodes.map((n) => n.id));
  const ia = ids(a), ib = ids(b);
  let onlyA = 0, onlyB = 0;
  for (const x of ia) if (!ib.has(x)) onlyA++;
  for (const x of ib) if (!ia.has(x)) onlyB++;
  const rootA = a.occurrences.find((o) => o.depth === 0)?.sha256 ?? '', rootB = b.occurrences.find((o) => o.depth === 0)?.sha256 ?? '';
  const addedOut = added.filter((o) => !movedSha.has(o.sha256)), removedOut = removed.filter((o) => !movedSha.has(o.sha256));
  return {
    schema: 'revlens/inventory-diff@1',
    left: { root: a.root, sha256: rootA, occurrences: a.occurrences.length, nodes: a.nodes.length },
    right: { root: b.root, sha256: rootB, occurrences: b.occurrences.length, nodes: b.nodes.length },
    added: addedOut.slice(0, limit), removed: removedOut.slice(0, limit), changed: changed.slice(0, limit), moved: moved.slice(0, limit), unchanged,
    contentOnlyLeft: onlyA, contentOnlyRight: onlyB, identical: rootA !== '' && rootA === rootB,
    summary: `${addedOut.length} added, ${removedOut.length} removed, ${changed.length} changed, ${moved.length} moved, ${unchanged} unchanged occurrences; ${onlyA} contents only on the left, ${onlyB} only on the right`,
  };
}
