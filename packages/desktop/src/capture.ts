// Bounded process capture: start a command (or attach to a pid), sample the process tree's
// modules, open files, sockets and children at an interval for a fixed time, record syscalls
// with strace on Linux when it is available, and write one capture file.
import { spawn, type ChildProcess } from 'node:child_process';
import { readFile, readdir, writeFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { InputError } from './proc.js';
import { requireExecution } from './exec.js';
import { toolsEnv, findProgram } from './drivers.js';
import { socketKey } from './compare.js';
import { waitExit, release } from './children.js';
import { parseStrace, compareCaptures, type ProcessCapture } from './strace.js';

export interface CaptureOptions {
  allowExecution?: boolean;
  /** program and arguments to start (never through a shell) */
  command?: string[];
  /** or an existing process to watch */
  pid?: number;
  durationMs?: number; intervalMs?: number;
  /** Linux: record syscalls with strace (default true when strace is found) */
  strace?: boolean;
  /** strace -e trace= classes (default %file,%network,%process) */
  straceTrace?: string;
  cwd?: string; env?: Record<string, string>; stdin?: string;
  /** write the capture here (default a temp file) */
  out?: string;
  /** stop the command when the time is up (default true) */
  kill?: boolean;
  maxItems?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const signalGroup = (p: ChildProcess, sig: NodeJS.Signals) => {
  try { if (p.pid) process.kill(process.platform === 'win32' ? p.pid : -p.pid, sig); else p.kill(sig); } catch { try { p.kill(sig); } catch { /* gone */ } }
};

async function linuxTree(root: number, limit = 500): Promise<number[]> {
  const out: number[] = [], q = [root], seen = new Set<number>();
  while (q.length && out.length < limit) {
    const p = q.shift()!; if (seen.has(p)) continue; seen.add(p);
    try { await stat(`/proc/${p}`); } catch { continue; }
    out.push(p);
    for (const t of (await readdir(`/proc/${p}/task`).catch(() => [] as string[])).slice(0, 2000)) {
      const kids = await readFile(`/proc/${p}/task/${t}/children`, 'utf8').catch(() => '');
      for (const k of kids.trim().split(/\s+/).filter(Boolean)) q.push(Number(k));
    }
  }
  return out;
}

/** Run a bounded capture and write it to a file. */
export async function captureProcess(o: CaptureOptions): Promise<{ path: string; capture: ProcessCapture }> {
  requireExecution(o.allowExecution, 'process capture');
  const hasCmd = Array.isArray(o.command) && o.command.length > 0;
  if (hasCmd === (o.pid !== undefined)) throw new InputError('give exactly one of command (a list: program then arguments) or pid');
  if (hasCmd && (o.command!.length > 512 || o.command!.some((a) => typeof a !== 'string' || a.length > 16384))) throw new InputError('command must be a list of strings');
  const dur = Math.max(100, Math.min(Number(o.durationMs ?? 5000), 600_000));
  const linux = process.platform === 'linux';
  const interval = Math.max(linux ? 50 : 500, Math.min(Number(o.intervalMs ?? (linux ? 200 : 1000)), 60_000));
  const maxItems = Math.max(10, Math.min(Number(o.maxItems ?? 20_000), 200_000));
  const env = toolsEnv({ ...process.env, ...(o.env ?? {}) });
  const warnings: string[] = [];
  const work = await mkdtemp(join(tmpdir(), 'revlens-capture-'));
  const straceOut = join(work, 'strace.txt');
  const straceBin = linux && o.strace !== false ? await findProgram('strace', env) : undefined;
  if (linux && o.strace !== false && !straceBin) warnings.push('strace not found; no syscall record');
  if (!linux && o.strace) warnings.push('syscall tracing is Linux only (dtruss and ETW need administrator rights)');
  const trace = String(o.straceTrace ?? '%file,%network,%process');
  if (!/^[%\w,!-]{1,200}$/.test(trace)) throw new InputError('straceTrace must look like %file,%network or openat,connect');
  const straceArgs = ['-f', '-tt', '-T', '-s', '256', '-qq', '-e', `trace=${trace}`, '-o', straceOut];
  const cap: ProcessCapture = { kind: 'revlens-process-capture', version: 1, platform: process.platform, target: hasCmd ? { command: o.command } : { pid: o.pid }, startedAt: new Date().toISOString(), durationMs: 0, processes: [], modules: [], files: [], sockets: [], timeline: [], samples: 0, warnings };
  let child: ChildProcess | undefined, tracer: ChildProcess | undefined;
  const out = { stdout: [] as Buffer[], stderr: [] as Buffer[], so: 0, se: 0 };
  let exit: { code: number | null; signal: string | null } | undefined;
  let rootPid: number;
  let stdioClosed = false;
  const t0 = Date.now();
  if (hasCmd) {
    const [prog, ...args] = o.command!;
    const exe = (await findProgram(prog!, env)) ?? prog!;
    child = straceBin ? spawn(straceBin, [...straceArgs, '--', exe, ...args], { cwd: o.cwd, env, stdio: ['pipe', 'pipe', 'pipe'], shell: false, windowsHide: true, detached: !!linux })
      : spawn(exe, args, { cwd: o.cwd, env, stdio: ['pipe', 'pipe', 'pipe'], shell: false, windowsHide: true, detached: process.platform !== 'win32' });
    child.on('error', (e) => warnings.push(`start: ${e.message}`));
    child.stdout!.on('data', (d: Buffer) => { out.so += d.length; if (out.so <= 1 << 20) out.stdout.push(d); });
    child.stderr!.on('data', (d: Buffer) => { out.se += d.length; if (out.se <= 1 << 20) out.stderr.push(d); });
    child.on('exit', (code, signal) => { exit = { code, signal }; });
    child.on('close', () => { stdioClosed = true; });
    if (o.stdin !== undefined) child.stdin!.end(String(o.stdin).slice(0, 1 << 20)); else child.stdin!.end();
    if (!child.pid) { await sleep(50); release(child); throw new InputError(`could not start ${prog}: ${warnings.join('; ')}`); }
    rootPid = child.pid;
  } else {
    const n = Number(o.pid);
    if (!Number.isInteger(n) || n <= 0) throw new InputError('bad pid');
    rootPid = n;
    if (straceBin) {
      tracer = spawn(straceBin, [...straceArgs, '-p', String(n)], { env, stdio: ['ignore', 'ignore', 'pipe'], shell: false });
      let err = ''; tracer.stderr!.on('data', (d: Buffer) => { if (err.length < 2000) err += String(d); });
      tracer.on('exit', (c) => { if (c && Date.now() - t0 < dur) warnings.push(`strace could not attach (ptrace not permitted?): ${err.trim().slice(0, 200)}`); });
      tracer.on('error', (e) => warnings.push(`strace: ${e.message}`));
      await sleep(150);
    }
  }
  const procs = new Map<number, ProcessCapture['processes'][number]>();
  const mods = new Map<string, ProcessCapture['modules'][number]>();
  const files = new Map<string, ProcessCapture['files'][number]>();
  const socks = new Map<string, ProcessCapture['sockets'][number]>();
  const addPid = (list: number[], pid: number) => { if (!list.includes(pid) && list.length < 64) list.push(pid); };
  const abort = async () => {
    if (child && o.kill !== false && child.exitCode === null && child.signalCode === null) { signalGroup(child, 'SIGKILL'); await waitExit(child, 2000); }
    if (tracer && tracer.exitCode === null && tracer.signalCode === null) { tracer.kill('SIGKILL'); await waitExit(tracer, 2000); if (process.platform !== 'win32') { try { process.kill(rootPid, 'SIGCONT'); } catch { /* gone */ } } }
    release(child); release(tracer);
    await rm(work, { recursive: true, force: true }).catch(() => undefined);
  };
  try {
  const { snapshotProcess } = await import('./node.js');
  while (Date.now() - t0 < dur) {
    const t = Date.now() - t0;
    let pids: number[];
    if (linux) pids = await linuxTree(rootPid);
    else {
      pids = [rootPid];
      for (let i = 0; i < pids.length && pids.length < 100; i++) { try { const s0 = await snapshotProcess(pids[i]!, { allowExecution: true, modules: false, files: false, sockets: false }); for (const c of s0.children ?? []) if (!pids.includes(c)) pids.push(c); } catch { /* gone */ } }
    }
    // under strace the root is strace itself: watch its traced child, not the tracer
    if (hasCmd && straceBin) pids = pids.filter((p) => p !== rootPid);
    let rss = 0, threads = 0, fds = 0, alive = 0;
    for (const pid of pids.slice(0, 200)) {
      let s;
      try { s = await snapshotProcess(pid, { allowExecution: true, limit: 20_000 }); } catch { continue; }
      alive++;
      rss += s.process.rssKb ?? 0; threads += s.process.threads ?? 0; fds += s.files.length;
      const p = procs.get(pid);
      if (p) { p.lastSeenMs = t; if (s.process.exe) p.exe = s.process.exe; if (s.process.cmdline?.length) p.cmdline = s.process.cmdline; p.name = s.process.name || p.name; }
      else if (procs.size < maxItems) procs.set(pid, { pid, ppid: s.process.ppid, name: s.process.name, exe: s.process.exe, cmdline: s.process.cmdline?.slice(0, 64), firstSeenMs: t, lastSeenMs: t });
      for (const m of s.modules) { if (m.kind === 'file') continue; const x = mods.get(m.path); if (x) addPid(x.pids, pid); else if (mods.size < maxItems) mods.set(m.path, { path: m.path, firstSeenMs: t, pids: [pid] }); }
      for (const f of s.files) { if (f.type === 'socket' || f.type === 'pipe' || f.type === 'anon') continue; const k = `${f.type} ${f.path}`; const x = files.get(k); if (x) { x.lastSeenMs = t; addPid(x.pids, pid); } else if (files.size < maxItems) files.set(k, { path: f.path, type: f.type, firstSeenMs: t, lastSeenMs: t, pids: [pid] }); }
      for (const so of s.sockets) { const k = socketKey(so); const x = socks.get(k); if (x) { x.lastSeenMs = t; addPid(x.pids, pid); } else if (socks.size < maxItems) socks.set(k, { key: k, proto: so.proto, firstSeenMs: t, lastSeenMs: t, pids: [pid] }); }
    }
    cap.samples++;
    if (cap.timeline.length < 5000) cap.timeline.push({ t, processes: alive, rssKb: rss, threads, fds });
    if (hasCmd && exit && !alive) break;
    if (!hasCmd && !alive) { warnings.push(`process ${rootPid} is gone`); break; }
    await sleep(Math.max(0, interval - (Date.now() - t0 - t)));
  }
  cap.durationMs = Date.now() - t0;
  if (child && !exit && o.kill !== false) {
    signalGroup(child, 'SIGTERM');
    if (!(await waitExit(child, 3000))) { signalGroup(child, 'SIGKILL'); await waitExit(child, 2000); }
    warnings.push('the command was still running at the end and was stopped');
  } else if (child && !exit) await waitExit(child, 50);
  if (tracer) {
    // strace detaches on SIGINT. If it does not go in time it is killed; a tracer that dies while
    // attached can leave the target in a stopped state, so the target always gets SIGCONT after.
    if (tracer.exitCode === null && tracer.signalCode === null) {
      tracer.kill('SIGINT');
      if (!(await waitExit(tracer, 3000))) { warnings.push('strace did not detach in time and was killed'); tracer.kill('SIGKILL'); await waitExit(tracer, 2000); }
    }
    if (process.platform !== 'win32') { try { process.kill(rootPid, 'SIGCONT'); } catch { /* gone */ } }
  }
  // the streams were read into out above; close them so leftover grandchildren cannot pin the caller
  // exit can come before the last stdout chunk; wait briefly for the pipes to drain (a grandchild
  // that inherited them keeps them open, so this is bounded) before closing our ends
  if (child) { const t1 = Date.now(); while (!stdioClosed && Date.now() - t1 < 1000) await sleep(20); release(child); }
  release(tracer);
  } catch (e) { await abort(); throw e; }
  cap.exit = exit;
  cap.processes = [...procs.values()];
  cap.modules = [...mods.values()].sort((a, b) => a.path.localeCompare(b.path));
  cap.files = [...files.values()].sort((a, b) => a.path.localeCompare(b.path));
  cap.sockets = [...socks.values()].sort((a, b) => a.key.localeCompare(b.key));
  const excerpt = (bufs: Buffer[], total: number) => { const b = Buffer.concat(bufs); return { bytes: total, sha256: createHash('sha256').update(b).digest('hex'), excerpt: b.subarray(0, 4000).toString('utf8') }; };
  if (child) { cap.stdout = excerpt(out.stdout, out.so); cap.stderr = excerpt(out.stderr, out.se); if (out.so > 1 << 20) warnings.push('stdout over 1 MiB; hash covers the first 1 MiB'); }
  if (straceBin) {
    try { const st = await stat(straceOut); if (st.size > 512 * 1024 * 1024) warnings.push('strace output over 512 MiB; read the first part only'); const txt = (await readFile(straceOut)).subarray(0, 512 * 1024 * 1024).toString('utf8'); cap.syscalls = parseStrace(txt, { maxItems }); }
    catch (e) { warnings.push(`strace output: ${(e as Error).message}`); }
  }
  const path = o.out ?? join(tmpdir(), `revlens-capture-${process.pid}-${Date.now()}.json`);
  await writeFile(path, JSON.stringify(cap, null, 1));
  await rm(work, { recursive: true, force: true });
  return { path, capture: cap };
}

/** Load two capture files and compare them. */
export async function compareCaptureFiles(a: string, b: string, opts: { limit?: number } = {}) {
  const load = async (p: string): Promise<ProcessCapture> => {
    const st = await stat(p);
    if (st.size > 512 * 1024 * 1024) throw new InputError('capture file too large');
    try { return JSON.parse(await readFile(p, 'utf8')); } catch { throw new InputError(`${p} is not a capture JSON file`); }
  };
  return compareCaptures(await load(a), await load(b), opts);
}
