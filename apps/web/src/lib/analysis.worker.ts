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

const isStr = (v: unknown, max = 4096): v is string => typeof v === 'string' && v.length <= max;

/**
 * Accepts only well formed requests. A dedicated worker hears only the page that created it,
 * but the shape is still checked so a bad message cannot reach the analyzers.
 */
function parseRequest(data: unknown): WorkerRequest | null {
  if (typeof data !== 'object' || data === null) return null;
  const m = data as Record<string, unknown>;
  switch (m.type) {
    case 'analyze':
      return isStr(m.id) && isStr(m.name) && m.buffer instanceof ArrayBuffer && (m.rules === undefined || isStr(m.rules, 512 * 1024))
        ? { type: 'analyze', id: m.id, name: m.name, buffer: m.buffer, rules: m.rules as string | undefined } : null;
    case 'rules':
      return isStr(m.id) && isStr(m.fileId) && isStr(m.text, 512 * 1024) ? { type: 'rules', id: m.id, fileId: m.fileId, text: m.text } : null;
    case 'verify':
      return isStr(m.id) && isStr(m.fileId) && typeof m.claim === 'object' && m.claim !== null ? { type: 'verify', id: m.id, fileId: m.fileId, claim: m.claim as Claim } : null;
    case 'forget':
      return isStr(m.fileId) ? { type: 'forget', fileId: m.fileId } : null;
    default:
      return null;
  }
}

function runAnalyze(msg: Extract<WorkerRequest, { type: 'analyze' }>): void {
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
}

function runRules(msg: Extract<WorkerRequest, { type: 'rules' }>): void {
  const bytes = files.get(msg.fileId);
  if (!bytes) { post({ type: 'rules-result', id: msg.id, error: 'This file is no longer loaded. Open it again.' }); return; }
  try { post({ type: 'rules-result', id: msg.id, matches: scanRules(bytes, msg.text) }); }
  catch (err) { post({ type: 'rules-result', id: msg.id, error: (err as Error).message }); }
}

function runVerify(msg: Extract<WorkerRequest, { type: 'verify' }>): void {
  const bytes = files.get(msg.fileId);
  if (!bytes) { post({ type: 'verify-result', id: msg.id, error: 'This file is no longer loaded. Open it again.' }); return; }
  try { post({ type: 'verify-result', id: msg.id, result: verifyClaim(bytes, msg.claim, reports.get(msg.fileId)) }); }
  catch (err) { post({ type: 'verify-result', id: msg.id, error: (err as Error).message }); }
}

const ownOrigin = self.location.origin;

scope.onmessage = (e) => {
  // Messages to a dedicated worker carry an empty origin. Anything else is not from our page.
  if (e.origin !== '' && e.origin !== ownOrigin) return;
  const msg = parseRequest(e.data);
  if (!msg) return;
  switch (msg.type) {
    case 'analyze': runAnalyze(msg); break;
    case 'rules': runRules(msg); break;
    case 'verify': runVerify(msg); break;
    case 'forget': files.delete(msg.fileId); reports.delete(msg.fileId); break;
  }
};
