import { useSyncExternalStore } from 'react';
import type { Report, Severity } from '@revlens/core';
import { analyzeInWorker, forgetInWorker, newId, type Progress } from './engine';
import { allFindings, maxSeverity } from './util';

export interface OpenFile {
  id: string;
  name: string;
  size: number;
  bytes: Uint8Array;
  status: 'running' | 'done' | 'error';
  report?: Report;
  error?: string;
  current?: string;
  timings: Record<string, number>;
  startedAt: number;
  finishedAt?: number;
}

export interface HistoryEntry { name: string; size: number; format: string; sha256: string; findings: number; max?: Severity; at: string }

interface State { files: OpenFile[]; activeId: string | null; history: HistoryEntry[] }

const HKEY = 'revlens.history';
const readHistory = (): HistoryEntry[] => { try { return JSON.parse(localStorage.getItem(HKEY) ?? '[]') as HistoryEntry[]; } catch { return []; } };

let state: State = { files: [], activeId: null, history: typeof window === 'undefined' ? [] : readHistory() };
const listeners = new Set<() => void>();
const set = (patch: Partial<State>) => { state = { ...state, ...patch }; listeners.forEach((l) => l()); };
const patchFile = (id: string, patch: Partial<OpenFile>) => set({ files: state.files.map((f) => (f.id === id ? { ...f, ...patch } : f)) });

export function useWorkspace(): State {
  return useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb); }, () => state, () => state);
}
export const getWorkspace = (): State => state;

function remember(r: Report): void {
  const entry: HistoryEntry = {
    name: r.file.name, size: r.file.size, format: r.file.format, sha256: r.file.hashes.sha256,
    findings: allFindings(r).length, max: maxSeverity(r), at: new Date().toISOString(),
  };
  const history = [entry, ...state.history.filter((h) => h.sha256 !== entry.sha256)].slice(0, 25);
  try { localStorage.setItem(HKEY, JSON.stringify(history)); } catch { /* quota or private mode */ }
  set({ history });
}

export function clearHistory(): void { try { localStorage.removeItem(HKEY); } catch { /* ignore */ } set({ history: [] }); }

/** Open bytes as a new workspace tab and analyze them in the worker. Returns the tab id. */
export function openBytes(name: string, bytes: Uint8Array): string {
  const id = newId();
  const f: OpenFile = { id, name, size: bytes.length, bytes, status: 'running', timings: {}, startedAt: performance.now() };
  set({ files: [...state.files, f], activeId: id });
  const onProgress = (p: Progress) => {
    if (p.depth > 0) return;
    const cur = state.files.find((x) => x.id === id);
    if (!cur) return;
    if (p.phase === 'start') patchFile(id, { current: p.analyzer });
    else patchFile(id, { timings: { ...cur.timings, [p.analyzer]: p.ms ?? 0 } });
  };
  analyzeInWorker(id, name, bytes, onProgress)
    .then((report) => { patchFile(id, { status: 'done', report, current: undefined, finishedAt: performance.now() }); remember(report); })
    .catch((err: Error) => patchFile(id, { status: 'error', error: err.message, current: undefined }));
  return id;
}

export async function openFile(file: File): Promise<string> {
  return openBytes(file.name, new Uint8Array(await file.arrayBuffer()));
}

export function setActive(id: string): void { set({ activeId: id }); }
export function closeFile(id: string): void {
  const files = state.files.filter((f) => f.id !== id);
  forgetInWorker(id);
  set({ files, activeId: state.activeId === id ? (files[files.length - 1]?.id ?? null) : state.activeId });
}
