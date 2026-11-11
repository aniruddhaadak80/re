// Runs RevLens off the main thread: the core, every package analyzer and the package tools.
// Bytes stay in this worker and in the page; nothing is uploaded.
import { scanRules, verifyClaim } from '@revlens/core';
import type { Claim, Report } from '@revlens/core';
import { ANALYZER_LIST } from '@revlens/core/internal/analyzers/index.ts';
import { analyzeAll, initDisasm, PACKAGE_ANALYZERS } from '@revlens/engine';
import { TOOLS as MANAGED_TOOLS } from '@revlens/managed';
import { TOOLS as WEB_TOOLS } from '@revlens/webrt';
import { TOOLS as MOBILE_TOOLS } from '@revlens/mobile';
import { TOOLS as DISASM_TOOLS } from '@revlens/disasm';
import capstoneWasmUrl from '@alexaltea/capstone-js/dist/capstone.wasm?url';
import type { WorkerRequest, WorkerResponse } from './protocol';

interface BrowserTool { name: string; run: (input: any) => Promise<unknown> }
const TOOLS = new Map<string, BrowserTool>();
for (const t of [...MANAGED_TOOLS, ...WEB_TOOLS, ...MOBILE_TOOLS, ...DISASM_TOOLS] as unknown as BrowserTool[]) TOOLS.set(t.name, t);

// Capstone needs its wasm bytes in a worker; fetch them once from the bundled asset.
let disasmReady: Promise<unknown> | null = null;
function ensureDisasm(): Promise<unknown> {
  disasmReady ??= fetch(capstoneWasmUrl).then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(new Error(`capstone.wasm HTTP ${r.status}`))))
    .then((buf) => initDisasm({ capstoneWasm: new Uint8Array(buf) }))
    .catch((e: Error) => { disasmReady = null; return { error: e.message }; });
  return disasmReady;
}

const scope = self as unknown as { postMessage(m: WorkerResponse): void; onmessage: ((e: MessageEvent<WorkerRequest>) => void) | null };
const post = (m: WorkerResponse) => scope.postMessage(m);
const files = new Map<string, Uint8Array>();
const reports = new Map<string, Report>();
let currentJob: string | null = null;

// Wrap each analyzer once so the page can show live progress and timings.
for (const a of [...ANALYZER_LIST, ...PACKAGE_ANALYZERS]) {
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
    case 'load':
      return isStr(m.id) && isStr(m.fileId) && m.buffer instanceof ArrayBuffer ? { type: 'load', id: m.id, fileId: m.fileId, buffer: m.buffer } : null;
    case 'tool':
      return isStr(m.id) && isStr(m.fileId) && isStr(m.tool, 64) && TOOLS.has(m.tool) && typeof m.args === 'object' && m.args !== null && !Array.isArray(m.args)
        ? { type: 'tool', id: m.id, fileId: m.fileId, tool: m.tool, args: m.args as Record<string, unknown> } : null;
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
      await ensureDisasm();
      const report = await analyzeAll(bytes, { name: msg.name, rules: msg.rules });
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

function toBase64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Only plain values from the page reach a tool: no paths (there is no file system here) and no output folders. */
function cleanArgs(args: Record<string, unknown>): Record<string, unknown> {
  // Prototype keys are never copied, and the result is built from entries (own data properties only),
  // so page input cannot reach Object.prototype.
  const out: [string, unknown][] = [];
  for (const [k, v] of Object.entries(args)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (k === 'path' || k === 'outDir' || k === 'sourceMapPath' || k === 'binaryPath' || k === 'bytes' || k === 'base64' || k === 'bytesBase64') continue;
    if (typeof v === 'string' ? v.length <= 1_000_000 : typeof v === 'number' || typeof v === 'boolean' || (Array.isArray(v) && v.length <= 64 && v.every((x) => typeof x === 'string'))) out.push([k, v]);
  }
  return Object.fromEntries(out);
}

function runTool(msg: Extract<WorkerRequest, { type: 'tool' }>): void {
  enqueue(async () => {
    const bytes = files.get(msg.fileId);
    if (!bytes) { post({ type: 'tool-result', id: msg.id, error: 'This file is no longer loaded. Open it again.' }); return; }
    const tool = TOOLS.get(msg.tool)!;
    const t = performance.now();
    try {
      if (msg.tool.startsWith('disasm_')) await ensureDisasm();
      const input: Record<string, unknown> = { ...cleanArgs(msg.args), bytes };
      // two file tools (disasm_match_functions, disasm_compare_functions) name the second loaded file
      if (typeof input.secondFileId === 'string') {
        const second = files.get(input.secondFileId);
        delete input.secondFileId;
        if (!second) { post({ type: 'tool-result', id: msg.id, error: 'The second file is no longer loaded. Open it again.' }); return; }
        input.bytes2 = second;
      }
      if (msg.tool.startsWith('managed_')) { delete input.bytes; input.bytesBase64 = toBase64(bytes); }
      const result = await tool.run(input);
      post({ type: 'tool-result', id: msg.id, result, ms: Math.round(performance.now() - t) });
    } catch (err) {
      post({ type: 'tool-result', id: msg.id, error: (err as Error).message });
    }
  });
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
    case 'load': files.set(msg.fileId, new Uint8Array(msg.buffer)); post({ type: 'loaded', id: msg.id }); break;
    case 'tool': runTool(msg); break;
  }
};
