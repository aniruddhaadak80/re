// Persistent radare2 or rizin, gdb and lldb sessions. Node only.
import { copyFile, mkdtemp, open as fsOpen, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { parseMiLines } from '../parsers/mi.js';
import type { Detection, Unavailable } from '../types.js';
import { BridgeInputError, int, need, requireExecution, requireFile, unavailable } from '../providers/common.js';
import { checkGdbCommand, checkLldbCommand, checkR2Command, miQuote } from './guards.js';
import { PipeProcess, SESSIONS, SessionError, type SessionImpl, type SessionInfo } from './manager.js';

const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
const MAX_PROGRAM_ARGS = 64;

function programArgs(a: unknown): string[] {
  if (a === undefined) return [];
  if (!Array.isArray(a) || a.length > MAX_PROGRAM_ARGS || !a.every((x) => typeof x === 'string' && x.length <= 4096 && !/[\0\r\n]/.test(x))) {
    throw new BridgeInputError(`args must be an array of up to ${MAX_PROGRAM_ARGS} strings without newlines`);
  }
  return a as string[];
}

function cap(s: string, max: number): { text: string; truncated: boolean } {
  return s.length > max ? { text: s.slice(0, max), truncated: true } : { text: s, truncated: false };
}

function baseInfo(kind: SessionInfo['kind'], det: Detection, tool: string, target: string, idle: unknown): SessionInfo {
  const now = new Date().toISOString();
  return {
    id: SESSIONS.newId(kind), kind, tool, toolVersion: det.version ?? null, target, pid: null, createdAt: now, lastUsedAt: now,
    idleTimeoutMs: SESSIONS.idle(idle), commands: 0, busy: false, alive: true,
  };
}

/** A temp file the debugged program writes its stdout and stderr to (its stdin reads EOF). */
class ProgramOutput {
  private offset = 0;
  constructor(readonly dir: string, readonly file: string) {}
  static async create(prefix: string): Promise<ProgramOutput> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    const file = join(dir, 'program-output.txt');
    await writeFile(file, '');
    return new ProgramOutput(dir, file);
  }
  /** Text appended since the last call, capped at 1 MiB per call. */
  async readNew(): Promise<string> {
    let fh;
    try { fh = await fsOpen(this.file, 'r'); } catch { return ''; }
    try {
      const st = await fh.stat();
      if (st.size <= this.offset) return '';
      const n = Math.min(st.size - this.offset, 1024 * 1024);
      const b = Buffer.alloc(n);
      await fh.read(b, 0, n, this.offset);
      this.offset = st.size;
      return b.toString('utf8');
    } finally { await fh.close(); }
  }
  async remove(): Promise<void> { await rm(this.dir, { recursive: true, force: true }).catch(() => undefined); }
}

const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

// ---------------- radare2 / rizin ----------------

interface R2Session extends SessionImpl { tmp?: string }

/** Open a radare2 (or rizin) session on a file, static analysis only, sandboxed. */
export async function r2SessionOpen(input: { path: string; engine?: 'radare2' | 'rizin' | 'auto'; analysis?: 'none' | 'aa' | 'aaa'; idleTimeoutMs?: number; timeoutMs?: number }) {
  const { path } = requireFile(input.path);
  const order: ('radare2' | 'rizin')[] = input.engine === 'rizin' ? ['rizin'] : input.engine === 'radare2' ? ['radare2'] : ['radare2', 'rizin'];
  let det: Detection | undefined;
  let id: 'radare2' | 'rizin' = 'radare2';
  for (const o of order) { const n = await need(o); if ('det' in n) { det = n.det; id = o; break; } }
  if (!det) return unavailable(order[0]!, order.length > 1 ? 'Neither radare2 nor rizin was found.' : undefined);
  SESSIONS.reserve();
  // cfg.sandbox only lets r2 open plain names below its working folder, so run from there,
  // copying names that could read as options or URIs.
  let cwd = dirname(path);
  let name = basename(path);
  let tmp: string | undefined;
  if (!/^[A-Za-z0-9_][\w.+-]{0,200}$/.test(name)) {
    tmp = await mkdtemp(join(tmpdir(), 'revlens-r2s-'));
    await copyFile(path, join(tmp, 'input.bin'));
    cwd = tmp; name = 'input.bin';
  }
  const proc = new PipeProcess(det.path!, ['-q0', '-N', '-e', 'scr.color=0', '-e', 'scr.interactive=false', '-e', 'scr.utf8=false', '-e', 'bin.relocs.apply=true', name],
    { cwd, env: { ...process.env, TERM: 'dumb' } });
  const info = baseInfo('r2', det, id, path, input.idleTimeoutMs);
  const s: R2Session = {
    info, proc, tmp,
    close: async () => {
      if (proc.alive) { try { proc.write('q!\n'); } catch { /* gone */ } }
      await proc.shutdown(1500);
      if (tmp) await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    },
  };
  const first = await proc.waitFor((b) => b.indexOf('\0'), 60_000);
  if (first.status !== 'ok') {
    proc.kill();
    if (tmp) await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    return { available: true, tool: id, ok: false, error: `${id} did not start: ${proc.takeErr().replace(ANSI, '').trim().slice(0, 1000) || first.status}` };
  }
  proc.take(first.end + 1);
  const sb = await r2Raw(s, 'e cfg.sandbox=true', 30_000);
  const sandboxed = sb.ok && !/error|invalid/i.test(sb.stderr);
  const added = SESSIONS.add(s);
  let analysis: unknown = null;
  if (input.analysis === 'aa' || input.analysis === 'aaa') {
    const a = await SESSIONS.use(info.id, 'r2', () => r2Raw(s, input.analysis!, int(input.timeoutMs, 600_000, 5000, 7_200_000)));
    analysis = { command: input.analysis, ok: a.ok, durationMs: a.durationMs };
  }
  return { available: true, tool: id, ok: true, session: { ...added, sandboxed }, analysis };
}

async function r2Raw(s: SessionImpl, cmd: string, timeoutMs: number) {
  const t0 = Date.now();
  s.proc.takeErr();
  s.proc.write(cmd + '\n');
  const w = await s.proc.waitFor((b) => b.indexOf('\0'), timeoutMs);
  if (w.status !== 'ok') {
    const partial = s.proc.take(s.proc.stdout.length);
    if (w.status === 'timeout') s.proc.kill(); // the session cannot resync after a lost reply
    return { ok: false, output: partial, stderr: s.proc.takeErr(), durationMs: Date.now() - t0, error: w.status === 'timeout' ? `timed out after ${timeoutMs} ms; session closed` : 'session process exited' };
  }
  const out = s.proc.take(w.end + 1).slice(0, -1);
  return { ok: true, output: out, stderr: s.proc.takeErr(), durationMs: Date.now() - t0 };
}

/** Run one radare2 or rizin command in an open session. JSON commands (ending in j) are parsed. */
export async function r2SessionCmd(input: { sessionId: string; command: string; timeoutMs?: number; maxChars?: number }) {
  const bad = checkR2Command(input.command);
  if (bad) throw new BridgeInputError(bad);
  const max = int(input.maxChars, 200_000, 100, 16_000_000);
  return SESSIONS.use(input.sessionId, 'r2', async (s) => {
    const r = await r2Raw(s, input.command.trim(), int(input.timeoutMs, 120_000, 1000, 3_600_000));
    const { text, truncated } = cap(r.output.replace(ANSI, ''), max);
    let json: unknown;
    if (/j(\s|$|@|~\{)/.test(input.command.trim().split(/\s+/)[0]! + ' ') && !truncated) {
      try { json = JSON.parse(text); } catch { json = undefined; }
    }
    const errText = r.stderr.replace(ANSI, '').trim().slice(0, 4000);
    return { ok: r.ok, sessionId: s.info.id, command: input.command, output: text, truncated, ...(json !== undefined ? { json } : {}), ...(errText ? { stderr: errText } : {}), durationMs: r.durationMs, ...(r.error ? { error: r.error } : {}) };
  });
}

// ---------------- gdb (MI) ----------------

/** Open a gdb session over MI on a program (with arguments) or attached to a pid. Needs allowExecution. */
export async function gdbSessionOpen(input: { path?: string; args?: string[]; pid?: number; idleTimeoutMs?: number; allowExecution?: boolean }) {
  const n = await need('gdb');
  if ('missing' in n) return n.missing;
  const gate = requireExecution(input, 'A gdb session');
  if (gate) return { available: true, tool: 'gdb', ok: false, blocked: true, error: gate };
  if ((input.path === undefined) === (input.pid === undefined)) throw new BridgeInputError('give exactly one of path or pid');
  const pre = ['-q', '-nx', '-nh', '--interpreter=mi3', '-iex', 'set startup-with-shell off', '-iex', 'set confirm off', '-iex', 'set pagination off',
    '-iex', 'set width 0', '-iex', 'set height 0', '-iex', 'set auto-load safe-path /nonexistent', '-iex', 'set debuginfod enabled off', '-iex', 'set mi-async on'];
  let args: string[];
  let target: string;
  if (input.pid !== undefined) {
    if (!Number.isSafeInteger(input.pid) || input.pid <= 0) throw new BridgeInputError('pid must be a positive integer');
    args = [...pre, '-p', String(input.pid)];
    target = `pid ${input.pid}`;
  } else {
    const { path } = requireFile(input.path);
    args = [...pre, '--args', path, ...programArgs(input.args)];
    target = path;
  }
  SESSIONS.reserve();
  // The program gets a regular file as its terminal: output lands there, stdin reads EOF, so it
  // can never swallow the MI commands on gdb's own stdin.
  const po = process.platform === 'win32' ? undefined : await ProgramOutput.create('revlens-gdbs-');
  if (po) args.splice(args.indexOf('-iex'), 0, '-iex', `set inferior-tty ${po.file}`);
  const proc = new PipeProcess(n.det.path!, args, { env: { ...process.env, TERM: 'dumb' } });
  const info = baseInfo('gdb', n.det, 'gdb', target, input.idleTimeoutMs);
  let tok = 100;
  const s: SessionImpl & { next: () => string; po?: ProgramOutput; inferiorPid?: number } = {
    info, proc, next: () => String(++tok), po, inferiorPid: input.pid,
    close: async () => {
      if (proc.alive) { try { proc.write('-gdb-exit\n'); } catch { /* gone */ } }
      await proc.shutdown(2000);
      await po?.remove();
    },
  };
  const ready = await proc.waitFor((b) => { const i = b.indexOf('(gdb) \n'); return i >= 0 ? i + 7 : -1; }, 60_000);
  if (ready.status !== 'ok') {
    const text = proc.take(proc.stdout.length);
    proc.kill();
    await po?.remove();
    return { available: true, tool: 'gdb', ok: false, error: `gdb did not start: ${(parseMiLines(text).log + proc.takeErr()).trim().slice(0, 1500) || ready.status}` };
  }
  const banner = parseMiLines(proc.take(ready.end));
  const added = SESSIONS.add(s);
  return { available: true, tool: 'gdb', toolVersion: n.det.version ?? null, ok: true, session: added, banner: banner.console.trim().slice(0, 4000), ...(banner.stopped ? { stopped: banner.stopped } : {}) };
}

/** Run one gdb console command. Commands that resume the program wait for the next stop (or timeout, then interrupt). */
export async function gdbSessionCmd(input: { sessionId: string; command: string; timeoutMs?: number; maxChars?: number }) {
  const bad = checkGdbCommand(input.command);
  if (bad) throw new BridgeInputError(bad);
  const max = int(input.maxChars, 200_000, 100, 16_000_000);
  const timeoutMs = int(input.timeoutMs, 60_000, 500, 3_600_000);
  return SESSIONS.use(input.sessionId, 'gdb', async (si) => {
    const s = si as SessionImpl & { next: () => string; po?: ProgramOutput; inferiorPid?: number };
    const t0 = Date.now();
    const trackPid = (t: string) => { const m = /=thread-group-started,id="[^"]*",pid="(\d+)"/.exec(t); if (m) s.inferiorPid = Number(m[1]); };
    const token = s.next();
    s.proc.write(`${token}-interpreter-exec console ${miQuote(input.command.trim())}\n`);
    const resultRe = new RegExp(`^${token}\\^(done|running|connected|error|exit)`, 'm');
    let w = await s.proc.waitFor((b) => { const m = resultRe.exec(b); if (!m) return -1; const e = b.indexOf('\n', m.index); return e >= 0 ? e + 1 : -1; }, timeoutMs);
    if (w.status !== 'ok') {
      const text = s.proc.take(s.proc.stdout.length);
      return { ok: false, sessionId: s.info.id, command: input.command, ...shape(parseMiLines(text, token), max), durationMs: Date.now() - t0, error: w.status === 'exit' ? 'gdb exited' : `no reply within ${timeoutMs} ms` };
    }
    let text = s.proc.take(w.end);
    trackPid(text);
    let interrupted = false;
    if (new RegExp(`^${token}\\^running`, 'm').test(text)) {
      const stopRe = /^\*stopped.*$/m;
      const stopAt = (b: string) => { const m = stopRe.exec(b); if (!m) return -1; const e = b.indexOf('\n', m.index); return e >= 0 ? e + 1 : -1; };
      const left = Math.max(500, timeoutMs - (Date.now() - t0));
      w = await s.proc.waitFor(stopAt, left);
      if (w.status === 'timeout') {
        interrupted = true;
        trackPid(s.proc.stdout);
        s.proc.write(`${s.next()}-exec-interrupt\n`);
        w = await s.proc.waitFor(stopAt, 2000);
        // Some ptrace layers (gVisor) ignore gdb's own interrupt; a SIGINT to the program works.
        if (w.status === 'timeout' && s.inferiorPid) {
          try { process.kill(s.inferiorPid, 'SIGINT'); } catch { /* already gone */ }
          w = await s.proc.waitFor(stopAt, 8000);
        }
      }
      text += w.status === 'ok' ? s.proc.take(w.end) : s.proc.take(s.proc.stdout.length);
      // let trailing "(gdb)" and late console lines arrive
      await s.proc.waitFor((b) => (b.includes('(gdb) \n') ? b.indexOf('(gdb) \n') + 7 : -1), 300);
      text += s.proc.take(s.proc.stdout.length);
    }
    const parsed = parseMiLines(text, token);
    if (s.po) parsed.target += (await s.po.readNew()).replace(/^&"warning: GDB: Failed to set controlling terminal[^\n]*\n/m, '');
    parsed.log = parsed.log.replace(/^warning: GDB: Failed to set controlling terminal: Inappropriate ioctl for device\n?/m, '');
    return {
      ok: parsed.result !== 'error', sessionId: s.info.id, command: input.command, ...shape(parsed, max), ...(interrupted ? { interrupted: true } : {}),
      alive: s.proc.alive, durationMs: Date.now() - t0, ...(parsed.error ? { error: parsed.error } : {}),
    };
  });
}

function shape(p: ReturnType<typeof parseMiLines>, max: number) {
  const out = cap(p.console, max);
  const tgt = cap(p.target, Math.min(max, 1_000_000));
  return {
    output: out.text, truncated: out.truncated || tgt.truncated, programOutput: tgt.text,
    ...(p.log.trim() ? { log: p.log.trim().slice(0, 8000) } : {}), ...(p.result ? { result: p.result } : {}), ...(p.stopped ? { stopped: p.stopped } : {}),
  };
}

// ---------------- lldb ----------------

/** Open an lldb session on a program (with arguments) or attached to a pid. Needs allowExecution. */
export async function lldbSessionOpen(input: { path?: string; args?: string[]; pid?: number; idleTimeoutMs?: number; allowExecution?: boolean }) {
  const n = await need('lldb');
  if ('missing' in n) return n.missing;
  const gate = requireExecution(input, 'An lldb session');
  if (gate) return { available: true, tool: 'lldb', ok: false, blocked: true, error: gate };
  if ((input.path === undefined) === (input.pid === undefined)) throw new BridgeInputError('give exactly one of path or pid');
  let args: string[];
  let target: string;
  const po = await ProgramOutput.create('revlens-lldbs-');
  // stdin from the null device and output to a file: lldb then never forwards its own stdin
  // (our command channel) to the program.
  const pre = ['--no-lldbinit', '--no-use-colors', '-O', 'settings set auto-confirm true', '-O', 'settings set use-color false',
    '-O', 'settings set target.load-script-from-symbol-file false', '-O', 'settings set target.load-cwd-lldbinit false',
    '-O', `settings set target.input-path ${NULL_DEVICE}`, '-O', `settings set target.output-path ${po.file}`, '-O', `settings set target.error-path ${po.file}`];
  if (input.pid !== undefined) {
    if (!Number.isSafeInteger(input.pid) || input.pid <= 0) throw new BridgeInputError('pid must be a positive integer');
    args = [...pre, '-p', String(input.pid)];
    target = `pid ${input.pid}`;
  } else {
    const { path } = requireFile(input.path);
    args = [...pre, '--', path, ...programArgs(input.args)];
    target = path;
  }
  SESSIONS.reserve();
  const proc = new PipeProcess(n.det.path!, args, { env: { ...process.env, TERM: 'dumb' } });
  const info = baseInfo('lldb', n.det, 'lldb', target, input.idleTimeoutMs);
  const nonce = `rvlend${Math.random().toString(36).slice(2, 10)}`;
  let seq = 0;
  const s: SessionImpl & { mark: () => string; po: ProgramOutput } = {
    info, proc, mark: () => `${nonce}x${++seq}`, po,
    close: async () => {
      if (proc.alive) { try { proc.write('process kill\nquit\n'); } catch { /* gone */ } }
      await proc.shutdown(2000);
      await po.remove();
    },
  };
  const first = await lldbRaw(s, undefined, 60_000);
  if (!first.ok) { proc.kill(); await po.remove(); return { available: true, tool: 'lldb', ok: false, error: `lldb did not start: ${first.error}: ${(first.output + first.stderr).trim().slice(0, 1500)}` }; }
  const added = SESSIONS.add(s);
  return { available: true, tool: 'lldb', toolVersion: n.det.version ?? null, ok: true, session: added, banner: first.output.trim().slice(0, 4000), ...(first.stderr.trim() ? { stderr: first.stderr.trim().slice(0, 2000) } : {}) };
}

/**
 * Send one command (or none, to sync at startup) followed by an `apropos <marker>` line; lldb
 * answers that with a fixed sentence on stdout, which marks the end of the reply.
 */
async function lldbRaw(s: SessionImpl & { mark: () => string }, cmd: string | undefined, timeoutMs: number) {
  const t0 = Date.now();
  const mark = s.mark();
  s.proc.takeErr();
  s.proc.write(`${cmd !== undefined ? cmd + '\n' : ''}apropos ${mark}\n`);
  const sentence = `No commands found pertaining to '${mark}'`;
  const w = await s.proc.waitFor((b) => { const i = b.indexOf(sentence); if (i < 0) return -1; const e = b.indexOf('\n', i); return e >= 0 ? e + 1 : -1; }, timeoutMs);
  if (w.status !== 'ok') {
    const partial = s.proc.take(s.proc.stdout.length);
    if (w.status === 'timeout') s.proc.kill();
    return { ok: false, output: partial, stderr: s.proc.takeErr(), durationMs: Date.now() - t0, error: w.status === 'timeout' ? `timed out after ${timeoutMs} ms; session closed` : 'lldb exited' };
  }
  const raw = s.proc.take(w.end);
  const kept = raw.split(/\r?\n/).filter((l) => !l.includes(mark) && !/^\(lldb\) ?$/.test(l))
    .map((l) => (l.startsWith('(lldb) ') ? l.slice(7) : l));
  // drop the echoed command line
  if (cmd !== undefined && kept[0]?.trim() === cmd.trim()) kept.shift();
  return { ok: true, output: kept.join('\n').replace(ANSI, ''), stderr: s.proc.takeErr().replace(ANSI, ''), durationMs: Date.now() - t0 };
}

const LLDB_RUNNING = /^Process \d+ (is )?(running|launching|stepping|attaching|resuming)/m;

/**
 * Run one lldb command in an open session. lldb fed through a pipe resumes the program
 * asynchronously, so after the command this polls `process status` until the program stops or
 * exits (or the time runs out, then it interrupts), which makes run, continue and step behave
 * like they do at a terminal.
 */
export async function lldbSessionCmd(input: { sessionId: string; command: string; timeoutMs?: number; maxChars?: number }) {
  const bad = checkLldbCommand(input.command);
  if (bad) throw new BridgeInputError(bad);
  const max = int(input.maxChars, 200_000, 100, 16_000_000);
  const timeoutMs = int(input.timeoutMs, 60_000, 500, 3_600_000);
  return SESSIONS.use(input.sessionId, 'lldb', async (si) => {
    const s = si as SessionImpl & { mark: () => string; po: ProgramOutput };
    const t0 = Date.now();
    const r = await lldbRaw(s, input.command.trim(), timeoutMs);
    let output = r.output;
    let stderr = r.stderr;
    let interrupted = false;
    let state: string | undefined;
    if (r.ok) {
      let st = await lldbRaw(s, 'process status', 10_000);
      while (st.ok && LLDB_RUNNING.test(st.output) && Date.now() - t0 < timeoutMs) {
        await new Promise((res) => setTimeout(res, 100));
        st = await lldbRaw(s, 'process status', 10_000);
      }
      if (st.ok && LLDB_RUNNING.test(st.output)) {
        interrupted = true;
        await lldbRaw(s, 'process interrupt', 10_000);
        await new Promise((res) => setTimeout(res, 200));
        st = await lldbRaw(s, 'process status', 10_000);
      }
      if (st.ok) {
        state = st.output.trim();
        // stop reports printed while polling belong to this command
        const extra = st.output.trim();
        if (extra && !output.includes(extra) && /stopped|exited|crashed/.test(extra)) output = `${output.replace(/\s+$/, '')}\n${extra}`;
        if (st.stderr.trim() && !/invalid process|no process/i.test(st.stderr)) stderr += st.stderr;
      }
    }
    const { text, truncated } = cap(output, max);
    const err = stderr.trim();
    const programOutput = await s.po.readNew();
    return {
      ok: r.ok && !/^error:/m.test(err), sessionId: s.info.id, command: input.command, output: text, truncated, programOutput,
      ...(state ? { state: state.split('\n')[0]!.slice(0, 500) } : {}), ...(err ? { stderr: err.slice(0, 8000) } : {}),
      ...(interrupted ? { interrupted: true } : {}), alive: s.proc.alive, durationMs: Date.now() - t0, ...(r.error ? { error: r.error } : {}),
    };
  });
}

// ---------------- shared ----------------

/** List open sessions. */
export async function sessionList() {
  return { ok: true, max: SESSIONS.maxSessions, defaultIdleMs: SESSIONS.defaultIdleMs(), sessions: SESSIONS.list() };
}

/** Close one session, or all with all: true. */
export async function sessionClose(input: { sessionId?: string; all?: boolean }) {
  if (input.all === true) return { ok: true, closed: await SESSIONS.closeAll() };
  if (typeof input.sessionId !== 'string') throw new BridgeInputError('sessionId is required (or all: true)');
  const closed = await SESSIONS.close(input.sessionId);
  return { ok: closed, sessionId: input.sessionId, ...(closed ? {} : { error: `no open session ${input.sessionId}` }) };
}

export { SessionError, type Unavailable };
