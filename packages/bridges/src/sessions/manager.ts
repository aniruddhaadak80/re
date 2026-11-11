// Long lived tool sessions (radare2 or rizin, gdb, lldb, Frida) kept across tool calls.
// Each session has an id, an idle timeout, a cap on how many may be open, a command queue so
// two calls never interleave on one process, and clean shutdown. Node only.
//
// Sessions live in the memory of the process that opened them (the MCP server or a script).
// They do not survive a restart, and separate CLI invocations do not share them.
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { checkArgs } from '../exec.js';

export type SessionKind = 'r2' | 'gdb' | 'lldb' | 'frida';

export interface SessionInfo {
  id: string;
  kind: SessionKind;
  tool: string;
  toolVersion: string | null;
  /** file path, pid or process name the session works on */
  target: string;
  pid: number | null;
  createdAt: string;
  lastUsedAt: string;
  idleTimeoutMs: number;
  commands: number;
  busy: boolean;
  alive: boolean;
}

export class SessionError extends Error {}

export const SESSION_LIMITS = {
  defaultMaxSessions: 8,
  hardMaxSessions: 64,
  defaultIdleMs: 15 * 60_000,
  minIdleMs: 1_000,
  maxIdleMs: 24 * 60 * 60_000,
  /** cap on what one command may return before it is cut */
  maxCommandOutput: 16 * 1024 * 1024,
} as const;

function envInt(name: string, def: number, min: number, max: number): number {
  const v = Number(process.env[name]);
  if (!Number.isFinite(v) || v <= 0) return def;
  return Math.max(min, Math.min(Math.floor(v), max));
}

/** A child process with piped stdio, a growing stdout buffer and waiters on it. */
export class PipeProcess {
  readonly child: ChildProcess;
  private out = '';
  private err = '';
  private waiters: { check: () => boolean }[] = [];
  private exited = false;
  exitCode: number | null = null;
  exitSignal: string | null = null;
  outDropped = 0;

  constructor(file: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
    checkArgs([file, ...args]);
    this.child = spawn(file, args, {
      shell: false, windowsHide: true, detached: process.platform !== 'win32', cwd: opts.cwd, env: opts.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child.stdout!.setEncoding('utf8');
    this.child.stderr!.setEncoding('utf8');
    this.child.stdout!.on('data', (c: string) => { this.out += c; this.trim(); this.wake(); });
    this.child.stderr!.on('data', (c: string) => { this.err = (this.err + c).slice(-256 * 1024); this.wake(); });
    this.child.stdin!.on('error', () => { /* closed */ });
    this.child.on('error', (e) => { this.err += `\n${e.message}`; this.exited = true; this.wake(); });
    this.child.on('exit', (code, sig) => { this.exited = true; this.exitCode = code; this.exitSignal = sig; this.wake(); });
  }

  private trim(): void {
    if (this.out.length > SESSION_LIMITS.maxCommandOutput * 2) {
      const cut = this.out.length - SESSION_LIMITS.maxCommandOutput;
      this.outDropped += cut;
      this.out = this.out.slice(cut);
    }
  }

  private wake(): void {
    this.waiters = this.waiters.filter((w) => !w.check());
  }

  get alive(): boolean { return !this.exited; }
  get pid(): number | null { return this.child.pid ?? null; }
  get stdout(): string { return this.out; }

  /** Remove and return the first n characters of the stdout buffer. */
  take(n: number): string {
    const s = this.out.slice(0, n);
    this.out = this.out.slice(n);
    return s;
  }

  /** Return and clear what stderr has collected. */
  takeErr(): string {
    const s = this.err;
    this.err = '';
    return s;
  }

  write(s: string): void {
    if (this.exited) throw new SessionError('session process has exited');
    this.child.stdin!.write(s);
  }

  /**
   * Wait until `find` returns an index into the stdout buffer (the end of a reply) or the process
   * exits or the time runs out. Resolves with what happened; never rejects.
   */
  waitFor(find: (buf: string) => number, timeoutMs: number): Promise<{ status: 'ok' | 'timeout' | 'exit'; end: number }> {
    return new Promise((resolve) => {
      let done = false;
      const finish = (status: 'ok' | 'timeout' | 'exit', end: number) => {
        if (done) return true;
        done = true;
        clearTimeout(timer);
        resolve({ status, end });
        return true;
      };
      const check = () => {
        const i = find(this.out);
        if (i >= 0) return finish('ok', i);
        if (this.exited) return finish('exit', -1);
        return false;
      };
      const timer = setTimeout(() => finish('timeout', -1), timeoutMs);
      if (!check()) this.waiters.push({ check });
    });
  }

  /** Kill the whole process group. */
  kill(): void {
    if (this.exited) return;
    try {
      if (process.platform !== 'win32' && this.child.pid) process.kill(-this.child.pid, 'SIGKILL');
      else this.child.kill('SIGKILL');
    } catch {
      try { this.child.kill('SIGKILL'); } catch { /* gone */ }
    }
  }

  /** Close stdin, wait a little for a clean exit, then kill. */
  async shutdown(graceMs = 2000): Promise<void> {
    if (this.exited) return;
    try { this.child.stdin!.end(); } catch { /* ignore */ }
    await this.waitFor(() => -1, graceMs);
    this.kill();
  }
}

/** What every session type implements. */
export interface SessionImpl {
  info: SessionInfo;
  proc: PipeProcess;
  /** polite close: quit command, then shutdown */
  close(): Promise<void>;
}

/** Holds every open session of this process. */
export class SessionManager {
  private sessions = new Map<string, SessionImpl>();
  private timers = new Map<string, ReturnType<typeof setTimeout>>();
  private queues = new Map<string, Promise<unknown>>();

  get maxSessions(): number {
    return envInt('REVLENS_MAX_SESSIONS', SESSION_LIMITS.defaultMaxSessions, 1, SESSION_LIMITS.hardMaxSessions);
  }

  defaultIdleMs(): number {
    return envInt('REVLENS_SESSION_IDLE_MS', SESSION_LIMITS.defaultIdleMs, SESSION_LIMITS.minIdleMs, SESSION_LIMITS.maxIdleMs);
  }

  /** Clamp a requested idle timeout. */
  idle(ms: unknown): number {
    const n = typeof ms === 'number' && Number.isFinite(ms) && ms > 0 ? Math.floor(ms) : this.defaultIdleMs();
    return Math.max(SESSION_LIMITS.minIdleMs, Math.min(n, SESSION_LIMITS.maxIdleMs));
  }

  /** Throw when no slot is free. Call before starting a process. */
  reserve(): void {
    this.sweepDead();
    if (this.sessions.size >= this.maxSessions) {
      throw new SessionError(`session limit reached (${this.maxSessions} open). Close one with bridge_session_close, or raise REVLENS_MAX_SESSIONS.`);
    }
  }

  newId(kind: SessionKind): string {
    return `${kind}-${randomBytes(6).toString('hex')}`;
  }

  add(s: SessionImpl): SessionInfo {
    this.sessions.set(s.info.id, s);
    this.arm(s.info.id);
    installExitHook();
    s.proc.child.on('exit', () => { s.info.alive = false; });
    return this.snapshot(s);
  }

  private arm(id: string): void {
    const s = this.sessions.get(id);
    if (!s) return;
    const old = this.timers.get(id);
    if (old) clearTimeout(old);
    const t = setTimeout(() => { void this.close(id, 'idle'); }, s.info.idleTimeoutMs);
    t.unref?.();
    this.timers.set(id, t);
  }

  private sweepDead(): void {
    for (const [id, s] of this.sessions) if (!s.proc.alive && !s.info.busy) this.drop(id);
  }

  private drop(id: string): void {
    const t = this.timers.get(id);
    if (t) clearTimeout(t);
    this.timers.delete(id);
    this.sessions.delete(id);
    this.queues.delete(id);
  }

  snapshot(s: SessionImpl): SessionInfo {
    return { ...s.info, alive: s.proc.alive, pid: s.proc.pid };
  }

  /** Find a session by id and optional kind. Throws SessionError when missing. */
  get(id: unknown, kind?: SessionKind): SessionImpl {
    if (typeof id !== 'string' || !/^[a-z0-9]{1,8}-[0-9a-f]{12}$/.test(id)) throw new SessionError('sessionId is missing or malformed');
    const s = this.sessions.get(id);
    if (!s) throw new SessionError(`no open session ${id} (it may have been closed after being idle)`);
    if (kind && s.info.kind !== kind) throw new SessionError(`session ${id} is a ${s.info.kind} session, not ${kind}`);
    if (!s.proc.alive && !s.info.busy) {
      this.drop(id);
      throw new SessionError(`session ${id} has exited (code ${s.proc.exitCode ?? 'none'}${s.proc.exitSignal ? `, signal ${s.proc.exitSignal}` : ''})`);
    }
    return s;
  }

  /** Run fn with exclusive use of the session, refreshing its idle timer. */
  async use<T>(id: unknown, kind: SessionKind | undefined, fn: (s: SessionImpl) => Promise<T>): Promise<T> {
    const s = this.get(id, kind);
    const prev = this.queues.get(s.info.id) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => { release = r; });
    const chain = prev.then(() => mine);
    this.queues.set(s.info.id, chain);
    await prev.catch(() => undefined);
    try {
      s.info.busy = true;
      return await fn(s);
    } finally {
      s.info.busy = false;
      s.info.commands++;
      s.info.lastUsedAt = new Date().toISOString();
      release();
      if (this.queues.get(s.info.id) === chain) this.queues.delete(s.info.id);
      if (this.sessions.has(s.info.id)) this.arm(s.info.id);
    }
  }

  list(): SessionInfo[] {
    this.sweepDead();
    return [...this.sessions.values()].map((s) => this.snapshot(s));
  }

  /** Close one session. Returns false when it was not open. */
  async close(id: string, why: 'request' | 'idle' | 'shutdown' = 'request'): Promise<boolean> {
    const s = this.sessions.get(id);
    if (!s) return false;
    this.drop(id);
    try { await s.close(); } catch { /* fall through to kill */ }
    s.proc.kill();
    if (why === 'idle' && process.env.REVLENS_SESSION_DEBUG) process.stderr.write(`[revlens] closed idle session ${id}\n`);
    return true;
  }

  async closeAll(): Promise<number> {
    const ids = [...this.sessions.keys()];
    await Promise.all(ids.map((id) => this.close(id, 'shutdown')));
    return ids.length;
  }

  /** Synchronous kill of every session process, for process exit. */
  killAll(): void {
    for (const s of this.sessions.values()) s.proc.kill();
  }
}

export const SESSIONS = new SessionManager();

let hooked = false;
function installExitHook(): void {
  if (hooked) return;
  hooked = true;
  // On exit every session process group is killed. Children also see EOF on stdin if this
  // process dies without running exit handlers, and every session tool quits on EOF.
  process.once('exit', () => SESSIONS.killAll());
}
