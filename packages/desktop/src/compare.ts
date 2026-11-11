// Process snapshot comparison. No Node imports.
import type { ProcessInfo, ModuleInfo, OpenFile, SocketInfo } from './proc.js';

export interface ProcessSnapshot {
  kind: 'revlens-process-snapshot';
  version: 1;
  platform: string;
  takenAt: string;
  process: ProcessInfo;
  modules: ModuleInfo[];
  files: OpenFile[];
  sockets: SocketInfo[];
  children?: number[];
  warnings: string[];
}

export interface SnapshotDiff {
  pidSame: boolean;
  process: { field: string; before: unknown; after: unknown }[];
  modules: { added: string[]; removed: string[]; same: number };
  files: { added: string[]; removed: string[]; same: number };
  sockets: { added: string[]; removed: string[]; same: number };
  children: { added: number[]; removed: number[] };
  rssDeltaKb?: number;
  threadsDelta?: number;
  similarity: number;
}

export const socketKey = (s: SocketInfo) => (s.proto === 'unix' ? `unix ${s.path || s.local || '(unnamed)'} ${s.state ?? ''}` : `${s.proto} ${s.local}:${s.localPort ?? ''}${s.remote && s.remotePort ? ` -> ${s.remote}:${s.remotePort}` : ''} ${s.state ?? ''}`).trim();
const fileKey = (f: OpenFile) => (f.type === 'file' || f.type === 'dir' || f.type === 'device' ? `${f.type} ${f.path}` : '');

function setDiff(a: string[], b: string[], lim: number) {
  const A = new Set(a.filter(Boolean)), B = new Set(b.filter(Boolean));
  let same = 0; for (const x of A) if (B.has(x)) same++;
  return { added: [...B].filter((x) => !A.has(x)).sort().slice(0, lim), removed: [...A].filter((x) => !B.has(x)).sort().slice(0, lim), same, total: new Set([...A, ...B]).size };
}

/** Compare two process snapshots: process fields, loaded modules, open files, sockets and children. */
export function compareSnapshots(a: ProcessSnapshot, b: ProcessSnapshot, opts: { limit?: number } = {}): SnapshotDiff {
  const lim = Math.max(1, Math.min(opts.limit ?? 1000, 50_000));
  const fields: (keyof ProcessInfo)[] = ['name', 'exe', 'ppid', 'user', 'uid', 'state', 'threads'];
  const proc: SnapshotDiff['process'] = [];
  for (const f of fields) { const x = a.process?.[f], y = b.process?.[f]; if (JSON.stringify(x) !== JSON.stringify(y)) proc.push({ field: f, before: x, after: y }); }
  if (JSON.stringify(a.process?.cmdline) !== JSON.stringify(b.process?.cmdline)) proc.push({ field: 'cmdline', before: a.process?.cmdline, after: b.process?.cmdline });
  const m = setDiff((a.modules ?? []).map((x) => x.path), (b.modules ?? []).map((x) => x.path), lim);
  const f = setDiff((a.files ?? []).map(fileKey), (b.files ?? []).map(fileKey), lim);
  const s = setDiff((a.sockets ?? []).map(socketKey), (b.sockets ?? []).map(socketKey), lim);
  const ca = new Set(a.children ?? []), cb = new Set(b.children ?? []);
  const parts = [m, f, s].filter((x) => x.total > 0);
  const similarity = parts.length ? Math.round((parts.reduce((acc, x) => acc + x.same / x.total, 0) / parts.length) * 10_000) / 10_000 : 1;
  return {
    pidSame: a.process?.pid === b.process?.pid,
    process: proc,
    modules: { added: m.added, removed: m.removed, same: m.same },
    files: { added: f.added, removed: f.removed, same: f.same },
    sockets: { added: s.added, removed: s.removed, same: s.same },
    children: { added: [...cb].filter((x) => !ca.has(x)), removed: [...ca].filter((x) => !cb.has(x)) },
    rssDeltaKb: a.process?.rssKb !== undefined && b.process?.rssKb !== undefined ? b.process.rssKb - a.process.rssKb : undefined,
    threadsDelta: a.process?.threads !== undefined && b.process?.threads !== undefined ? b.process.threads - a.process.threads : undefined,
    similarity,
  };
}
