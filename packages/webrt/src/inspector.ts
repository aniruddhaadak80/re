// Attach to a local Node.js process through its inspector and observe it without evaluating code:
// loaded scripts, function call counts (precise coverage), CPU sampling profile, heap usage.
// Gated by allowExecution because it signals and attaches to another process. Node only.
import { CdpClient, cdpTargets, checkDevtoolsEndpoint, type CdpVersion } from './cdp.js';
import { InputError } from './util.js';

export interface InspectorOptions {
  /** must be true (or REVLENS_ALLOW_EXECUTION=1): attaching changes the target process state */
  allowExecution?: boolean;
  /** pid of a local Node process; the inspector is switched on with process._debugProcess or SIGUSR1 */
  pid?: number;
  /** inspector port when it is already listening (default 9229) */
  port?: number;
  host?: string;
  /** a ws:// inspector URL, used as is */
  wsUrl?: string;
  /** how long to observe in ms (default 2000, max 60000) */
  durationMs?: number;
  /** take a CPU sampling profile too (default true) */
  cpuProfile?: boolean;
  /** sampling interval in microseconds (default 1000) */
  samplingIntervalUs?: number;
  maxScripts?: number;
  maxFunctions?: number;
  /** include node:internal scripts (default false) */
  includeInternal?: boolean;
}

export interface InspectorReport {
  target: { wsUrl: string; title?: string; url?: string; id?: string };
  version: CdpVersion;
  attachedVia: 'ws-url' | 'port' | 'pid-signal';
  durationMs: number;
  scripts: { scriptId: string; url: string; length?: number; hash?: string; sourceMapURL?: string; isModule?: boolean }[];
  scriptCount: number;
  calls: { url: string; name: string; offset: number; count: number }[];
  calledFunctions: number;
  totalFunctions: number;
  cpu?: { samples: number; intervalUs: number; top: { name: string; url: string; line: number; selfSamples: number; selfPercent: number }[] };
  heap?: { usedSize: number; totalSize: number };
  executionContexts: { id: number; name: string; origin: string }[];
  warnings: string[];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const executionAllowed = (flag?: boolean) => flag === true || process.env.REVLENS_ALLOW_EXECUTION === '1';

/** Attach to a local Node process inspector, record scripts, function call counts and a CPU profile, then detach. Needs allowExecution. */
export async function attachNodeInspector(opts: InspectorOptions): Promise<InspectorReport> {
  if (!executionAllowed(opts.allowExecution)) throw new InputError('attaching to a Node process needs allowExecution: true (or REVLENS_ALLOW_EXECUTION=1)');
  const host = opts.host ?? '127.0.0.1';
  const duration = Math.max(100, Math.min(opts.durationMs ?? 2_000, 60_000));
  const warnings: string[] = [];
  let wsUrl = opts.wsUrl;
  let version: CdpVersion = {};
  let via: InspectorReport['attachedVia'] = 'ws-url';
  let title: string | undefined, url: string | undefined, id: string | undefined;
  if (wsUrl) {
    checkDevtoolsEndpoint(wsUrl);
  } else {
    const port = opts.port ?? 9229;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new InputError('bad port');
    via = 'port';
    if (opts.pid !== undefined) {
      if (!Number.isInteger(opts.pid) || opts.pid <= 0 || opts.pid === process.pid) throw new InputError('bad pid');
      via = 'pid-signal';
      const dbg = (process as unknown as { _debugProcess?: (pid: number) => void })._debugProcess;
      try { if (dbg) dbg(opts.pid); else process.kill(opts.pid, 'SIGUSR1'); }
      catch (e) { throw new InputError(`could not switch on the inspector in pid ${opts.pid}: ${(e as Error).message}`); }
    }
    let last: unknown;
    for (let i = 0; i < 30; i++) {
      try {
        const t = await cdpTargets(`http://${host}:${port}`, { timeoutMs: 1_000 });
        const node = t.targets.find((x) => x.type === 'node' && x.webSocketDebuggerUrl) ?? t.targets.find((x) => x.webSocketDebuggerUrl);
        if (node?.webSocketDebuggerUrl) { wsUrl = node.webSocketDebuggerUrl; version = t.version; title = node.title; url = node.url; id = node.id; break; }
      } catch (e) { last = e; }
      await sleep(100);
    }
    if (!wsUrl) throw new InputError(`no inspector answered on ${host}:${port}${last ? `: ${(last as Error).message}` : ''}`);
  }
  const client = await CdpClient.connect(wsUrl!, 5_000);
  const t0 = Date.now();
  const scripts = new Map<string, InspectorReport['scripts'][number]>();
  const contexts: InspectorReport['executionContexts'] = [];
  const maxScripts = opts.maxScripts ?? 5_000;
  client.on('Debugger.scriptParsed', (p) => {
    if (scripts.size >= maxScripts) return;
    const u = String(p.url ?? '');
    if (!opts.includeInternal && (u.startsWith('node:') || u === '')) return;
    scripts.set(String(p.scriptId), { scriptId: String(p.scriptId), url: u.slice(0, 4000), length: p.length, hash: p.hash, sourceMapURL: p.sourceMapURL || undefined, isModule: p.isModule });
  });
  client.on('Runtime.executionContextCreated', (p) => { if (contexts.length < 100) contexts.push({ id: p.context?.id, name: String(p.context?.name ?? ''), origin: String(p.context?.origin ?? '') }); });
  const report: InspectorReport = { target: { wsUrl: wsUrl!, title, url, id }, version, attachedVia: via, durationMs: 0, scripts: [], scriptCount: 0, calls: [], calledFunctions: 0, totalFunctions: 0, executionContexts: contexts, warnings };
  try {
    await client.send('Runtime.enable');
    // a process started with --inspect-brk waits for this; harmless otherwise
    await client.send('Runtime.runIfWaitingForDebugger').catch(() => undefined);
    await client.send('Debugger.enable', { maxScriptsCacheSize: 0 });
    await client.send('Profiler.enable');
    await client.send('Profiler.startPreciseCoverage', { callCount: true, detailed: false });
    const cpu = opts.cpuProfile !== false;
    const interval = Math.max(50, Math.min(opts.samplingIntervalUs ?? 1_000, 100_000));
    if (cpu) { await client.send('Profiler.setSamplingInterval', { interval }); await client.send('Profiler.start'); }
    // Debugger.enable makes the target pause on "debugger" statements; resume right away if that happens
    client.on('Debugger.paused', () => { client.send('Debugger.resume').catch(() => undefined); });
    await sleep(duration);
    const cov = await client.send('Profiler.takePreciseCoverage', {}, 30_000);
    const maxFns = opts.maxFunctions ?? 500;
    const all: InspectorReport['calls'] = [];
    for (const s of cov.result ?? []) {
      const u = String(s.url ?? '');
      if (!opts.includeInternal && (u.startsWith('node:') || u === '')) continue;
      for (const f of (s.functions ?? []).slice(0, 200_000)) {
        report.totalFunctions++;
        const c = Number(f.ranges?.[0]?.count ?? 0);
        if (c > 0) { report.calledFunctions++; all.push({ url: u.slice(0, 2000), name: String(f.functionName || '(anonymous)').slice(0, 200), offset: Number(f.ranges?.[0]?.startOffset ?? 0), count: c }); }
      }
    }
    report.calls = all.sort((a, b) => b.count - a.count).slice(0, maxFns);
    if (cpu) {
      const prof = (await client.send('Profiler.stop', {}, 30_000)).profile ?? {};
      const nodes = new Map<number, any>((prof.nodes ?? []).map((n: any) => [n.id, n]));
      const counts = new Map<number, number>();
      for (const sId of (prof.samples ?? []).slice(0, 5_000_000)) counts.set(sId, (counts.get(sId) ?? 0) + 1);
      const total = (prof.samples ?? []).length;
      const agg = new Map<string, { name: string; url: string; line: number; selfSamples: number }>();
      for (const [nid, c] of counts) {
        const cf = nodes.get(nid)?.callFrame ?? {};
        const k = `${cf.functionName}|${cf.url}|${cf.lineNumber}`;
        const a = agg.get(k) ?? { name: String(cf.functionName || '(anonymous)').slice(0, 200), url: String(cf.url ?? '').slice(0, 2000), line: Number(cf.lineNumber ?? -1) + 1, selfSamples: 0 };
        a.selfSamples += c; agg.set(k, a);
      }
      report.cpu = { samples: total, intervalUs: interval, top: [...agg.values()].sort((a, b) => b.selfSamples - a.selfSamples).slice(0, 50).map((a) => ({ ...a, selfPercent: total ? Math.round((a.selfSamples / total) * 10_000) / 100 : 0 })) };
    }
    report.heap = await client.send('Runtime.getHeapUsage').catch(() => undefined);
    await client.send('Profiler.stopPreciseCoverage').catch(() => undefined);
    await client.send('Profiler.disable').catch(() => undefined);
    await client.send('Debugger.disable').catch(() => undefined);
  } finally {
    client.close();
  }
  report.scripts = [...scripts.values()];
  report.scriptCount = report.scripts.length;
  report.durationMs = Date.now() - t0;
  return report;
}
