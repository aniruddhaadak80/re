import type { Claim, ClaimResult, Report, RuleMatch } from '@revlens/core';
import type { WorkerRequest, WorkerResponse } from './protocol';

export interface Progress { analyzer: string; phase: 'start' | 'end'; depth: number; file: string; ms?: number }
type Pending = { resolve: (v: never) => void; reject: (e: Error) => void; onProgress?: (p: Progress) => void };

let worker: Worker | null = null;
const pending = new Map<string, Pending>();
let seq = 0;
export const newId = (p = 'f'): string => `${p}${Date.now().toString(36)}${(seq++).toString(36)}`;

function getWorker(): Worker {
  if (worker) return worker;
  worker = new Worker(new URL('./analysis.worker.ts', import.meta.url), { type: 'module', name: 'revlens-analysis' });
  worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
    const m = e.data;
    const p = pending.get(m.id);
    if (!p) return;
    if (m.type === 'progress') { p.onProgress?.(m); return; }
    pending.delete(m.id);
    if (m.type === 'done') p.resolve(m.report as never);
    else if (m.type === 'error') p.reject(new Error(m.message));
    else if (m.type === 'rules-result') m.error ? p.reject(new Error(m.error)) : p.resolve((m.matches ?? []) as never);
    else if (m.type === 'verify-result') m.error || !m.result ? p.reject(new Error(m.error ?? 'No result')) : p.resolve(m.result as never);
    else if (m.type === 'loaded') p.resolve(undefined as never);
    else if (m.type === 'tool-result') m.error ? p.reject(new Error(m.error)) : p.resolve({ result: m.result, ms: m.ms ?? 0 } as never);
  };
  worker.onerror = (e) => {
    for (const [, p] of pending) p.reject(new Error(e.message || 'The analysis worker stopped.'));
    pending.clear();
  };
  return worker;
}

function send<T>(msg: WorkerRequest & { id: string }, onProgress?: (p: Progress) => void, transfer: Transferable[] = []): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    pending.set(msg.id, { resolve: resolve as (v: never) => void, reject, onProgress });
    getWorker().postMessage(msg, transfer);
  });
}

/** Analyze in the worker. The page keeps its own copy of the bytes for the hex view. */
export function analyzeInWorker(id: string, name: string, bytes: Uint8Array, onProgress?: (p: Progress) => void, rules?: string): Promise<Report> {
  const copy = bytes.slice().buffer;
  return send<Report>({ type: 'analyze', id, name, buffer: copy, rules }, onProgress, [copy]);
}
export function rulesInWorker(fileId: string, text: string): Promise<RuleMatch[]> {
  return send<RuleMatch[]>({ type: 'rules', id: newId('r'), fileId, text });
}
export function verifyInWorker(fileId: string, claim: Claim): Promise<ClaimResult> {
  return send<ClaimResult>({ type: 'verify', id: newId('v'), fileId, claim });
}
export function forgetInWorker(fileId: string): void { getWorker().postMessage({ type: 'forget', fileId } satisfies WorkerRequest); }

/** Hand bytes to the worker under a file id, so package tools can run on them. */
export function loadInWorker(fileId: string, bytes: Uint8Array): Promise<void> {
  const copy = bytes.slice().buffer;
  return send<void>({ type: 'load', id: newId('l'), fileId, buffer: copy }, undefined, [copy]);
}
/** Run one package tool in the worker on a file loaded with loadInWorker or analyzeInWorker. */
export function toolInWorker<T = unknown>(fileId: string, tool: string, args: Record<string, unknown> = {}): Promise<{ result: T; ms: number }> {
  return send<{ result: T; ms: number }>({ type: 'tool', id: newId('t'), fileId, tool, args });
}
