// Child process runner used by every bridge. No shell, argument arrays only,
// hard timeouts, output caps, and process group kill on POSIX.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RunResult } from './types.js';

export interface RunOptions {
  /** wall clock limit, default 60 s, capped at 2 h */
  timeoutMs?: number;
  /** cap per stream (stdout and stderr each), default 8 MiB, capped at 256 MiB */
  maxOutputBytes?: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** text written to stdin, then stdin is closed */
  input?: string;
}

export const EXEC_LIMITS = {
  defaultTimeoutMs: 60_000,
  maxTimeoutMs: 2 * 60 * 60 * 1000,
  defaultMaxOutputBytes: 8 * 1024 * 1024,
  maxMaxOutputBytes: 256 * 1024 * 1024,
  maxArgs: 4096,
  maxArgLength: 32 * 1024,
} as const;

/** Characters cmd.exe treats specially. Arguments holding them are refused for .bat/.cmd launchers. */
const CMD_META = /["&|<>^%!\r\n]/;

export class UnsafeArgumentError extends Error {}

function clamp(v: number | undefined, def: number, max: number): number {
  if (v === undefined || !Number.isFinite(v) || v <= 0) return def;
  return Math.min(Math.floor(v), max);
}

/** Validate an argument list. Throws on NUL bytes, absurd sizes or counts. */
export function checkArgs(args: readonly string[]): void {
  if (args.length > EXEC_LIMITS.maxArgs) throw new UnsafeArgumentError(`too many arguments (${args.length})`);
  for (const a of args) {
    if (typeof a !== 'string') throw new UnsafeArgumentError('arguments must be strings');
    if (a.includes('\0')) throw new UnsafeArgumentError('argument contains a NUL byte');
    if (a.length > EXEC_LIMITS.maxArgLength) throw new UnsafeArgumentError('argument too long');
  }
}

/**
 * Build the real spawn call. On Windows, .bat and .cmd launchers (jadx.bat, analyzeHeadless.bat)
 * cannot be spawned without cmd.exe, so we go through `cmd.exe /d /s /c` with every argument quoted
 * and refuse arguments that carry cmd metacharacters.
 */
export function spawnPlan(command: string, args: readonly string[], platform: NodeJS.Platform = process.platform):
  { file: string; args: string[]; verbatim: boolean } {
  checkArgs([command, ...args]);
  if (platform === 'win32' && /\.(bat|cmd)$/i.test(command)) {
    for (const a of [command, ...args]) {
      if (CMD_META.test(a)) throw new UnsafeArgumentError(`argument not allowed for a .bat launcher: ${JSON.stringify(a)}`);
    }
    const line = [command, ...args].map((a) => `"${a}"`).join(' ');
    return { file: process.env.ComSpec || 'cmd.exe', args: ['/d', '/s', '/c', `"${line}"`], verbatim: true };
  }
  return { file: command, args: [...args], verbatim: false };
}

/** Run a program with an argument array. Never uses a shell. Never throws for process failures. */
export function runTool(command: string, args: readonly string[], opts: RunOptions = {}): Promise<RunResult> {
  const timeoutMs = clamp(opts.timeoutMs, EXEC_LIMITS.defaultTimeoutMs, EXEC_LIMITS.maxTimeoutMs);
  const maxOut = clamp(opts.maxOutputBytes, EXEC_LIMITS.defaultMaxOutputBytes, EXEC_LIMITS.maxMaxOutputBytes);
  const started = Date.now();
  let plan: ReturnType<typeof spawnPlan>;
  try {
    plan = spawnPlan(command, args);
  } catch (e) {
    return Promise.resolve({ command, args: [...args], code: null, signal: null, stdout: '', stderr: '', timedOut: false,
      truncated: false, durationMs: 0, error: (e as Error).message });
  }
  return new Promise((resolve) => {
    const posix = process.platform !== 'win32';
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(plan.file, plan.args, {
        shell: false,
        windowsHide: true,
        windowsVerbatimArguments: plan.verbatim,
        detached: posix,
        cwd: opts.cwd,
        env: opts.env ?? process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (e) {
      resolve({ command, args: [...args], code: null, signal: null, stdout: '', stderr: '', timedOut: false, truncated: false,
        durationMs: Date.now() - started, error: (e as Error).message });
      return;
    }
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let outLen = 0;
    let errLen = 0;
    let truncated = false;
    let timedOut = false;
    let spawnError: string | undefined;
    let settled = false;

    const kill = () => {
      try {
        if (posix && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
      }
    };
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);

    const take = (bucket: Buffer[], chunk: Buffer, which: 'out' | 'err') => {
      const used = which === 'out' ? outLen : errLen;
      const room = maxOut - used;
      if (room <= 0) { truncated = true; return; }
      const part = chunk.length > room ? chunk.subarray(0, room) : chunk;
      if (part.length < chunk.length) truncated = true;
      bucket.push(part);
      if (which === 'out') outLen += part.length; else errLen += part.length;
    };
    child.stdout?.on('data', (c: Buffer) => take(out, c, 'out'));
    child.stderr?.on('data', (c: Buffer) => take(err, c, 'err'));
    child.on('error', (e) => { spawnError = e.message; });
    child.stdin?.on('error', () => { /* program closed stdin early */ });
    if (opts.input !== undefined) child.stdin?.end(opts.input);
    else child.stdin?.end();

    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        command, args: [...args], code, signal: signal ?? null,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
        timedOut, truncated, durationMs: Date.now() - started,
        ...(spawnError ? { error: spawnError } : {}),
      });
    });
  });
}

/** Create a private temp dir, run fn, and always remove the dir afterwards. */
export async function withTempDir<T>(fn: (dir: string) => Promise<T>, prefix = 'revlens-bridge-'): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
  }
}

/** Short text describing a failed run, for error fields. */
export function describeFailure(r: RunResult): string {
  if (r.error) return r.error;
  if (r.timedOut) return `timed out after ${r.durationMs} ms`;
  const tail = (r.stderr || r.stdout).trim().split(/\r?\n/).slice(-6).join('\n');
  return `exit code ${r.code}${r.signal ? ` signal ${r.signal}` : ''}${tail ? `: ${tail.slice(0, 1200)}` : ''}`;
}
