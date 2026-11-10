// Runs the RevLens core off the main thread. Bytes stay in this worker and in the page; nothing is uploaded.
import { analyze, scanRules, verifyClaim } from '@revlens/core';
import type { Claim, Report } from '@revlens/core';
import { ANALYZER_LIST } from '@revlens/core/internal/analyzers/index.ts';
import type { WorkerRequest, WorkerResponse } from './protocol';

const scope = self as unknown as { postMessage(m: WorkerResponse): void; onmessage: ((e: MessageEvent<WorkerRequest>) => void) | null };
const post = (m: WorkerResponse) => scope.postMessage(m);
const files = new Map<string, Uint8Array>();
const reports = new Map<string, Report>();
let currentJob: string | null = null;

// Wrap each analyzer once so the page can show live progress and timings.
for (const a of ANALYZER_LIST) {
  const run = a.run.bind(a);
  a.run = async (ctx) => {
    const job = currentJob;
    if (job) post({ type: 'progress', id: job, analyzer: a.id, phase: 'start', depth: ctx.depth, file: ctx.name });
    const t = performance.now();
    try { await run(ctx); } finally {
      if (job) post({ type: 'progress', id: job, analyzer: a.id, phase: 'end', depth: ctx.depth, file: ctx.name, ms: Math.round((performance.now() - t) * 100) / 100 });
    }
  };
}

let queue: Promise<void> = Promise.resolve();
const enqueue = (fn: () => Promise<void>) => { queue = queue.then(fn, fn); };

scope.onmessage = (e) => {
  const msg = e.data;
  if (msg.type === 'analyze') {
    const bytes = new Uint8Array(msg.buffer);
    files.set(msg.id, bytes);
    enqueue(async () => {
      currentJob = msg.id;
      try {
        const report = await analyze(bytes, { name: msg.name, rules: msg.rules });
        reports.set(msg.id, report);
        post({ type: 'done', id: msg.id, report });
      } catch (err) {
        post({ type: 'error', id: msg.id, message: (err as Error).message });
      } finally { currentJob = null; }
    });
  } else if (msg.type === 'rules') {
    const bytes = files.get(msg.fileId);
    if (!bytes) { post({ type: 'rules-result', id: msg.id, error: 'This file is no longer loaded. Open it again.' }); return; }
    try { post({ type: 'rules-result', id: msg.id, matches: scanRules(bytes, msg.text) }); }
    catch (err) { post({ type: 'rules-result', id: msg.id, error: (err as Error).message }); }
  } else if (msg.type === 'verify') {
    const bytes = files.get(msg.fileId);
    if (!bytes) { post({ type: 'verify-result', id: msg.id, error: 'This file is no longer loaded. Open it again.' }); return; }
    try { post({ type: 'verify-result', id: msg.id, result: verifyClaim(bytes, msg.claim as Claim, reports.get(msg.fileId)) }); }
    catch (err) { post({ type: 'verify-result', id: msg.id, error: (err as Error).message }); }
  } else if (msg.type === 'forget') {
    files.delete(msg.fileId); reports.delete(msg.fileId);
  }
};
