// Child process helper: execFile with an argument array, no shell, a timeout and an output cap.
import { execFile } from 'node:child_process';
import { InputError } from './proc.js';

export interface RunResult { code: number; stdout: string; stderr: string; timedOut: boolean }

/** Run a program with arguments (never through a shell). Rejects only when the program cannot be started. */
export function run(cmd: string, args: string[], opts: { timeoutMs?: number; maxBytes?: number; env?: NodeJS.ProcessEnv } = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: Math.max(500, Math.min(opts.timeoutMs ?? 15_000, 300_000)), maxBuffer: opts.maxBytes ?? 64 * 1024 * 1024, windowsHide: true, shell: false, encoding: 'utf8', env: opts.env ?? process.env }, (err, stdout, stderr) => {
      const e = err as (NodeJS.ErrnoException & { killed?: boolean; signal?: string; code?: number | string }) | null;
      if (e && e.code === 'ENOENT') { reject(new InputError(`${cmd} is not installed or not on PATH`)); return; }
      resolve({ code: e ? (typeof e.code === 'number' ? e.code : 1) : 0, stdout: String(stdout ?? ''), stderr: String(stderr ?? '').slice(0, 4000), timedOut: !!e?.killed && e?.signal === 'SIGTERM' });
    });
  });
}

/** True when the caller opted in to touching other processes. */
export const executionAllowed = (flag?: boolean) => flag === true || process.env.REVLENS_ALLOW_EXECUTION === '1';

export function requireExecution(flag: boolean | undefined, what: string): void {
  if (!executionAllowed(flag)) throw new InputError(`${what} touches other processes; pass allowExecution: true (or set REVLENS_ALLOW_EXECUTION=1)`);
}

/** Quote a string as a PowerShell single-quoted literal (only ' needs doubling). Control characters are dropped. */
export function psQuote(s: string): string {
  return `'${s.replace(/[\u0000-\u001f]/g, '').replace(/'/g, "''").slice(0, 500)}'`;
}

export function powershell(script: string, timeoutMs = 30_000): Promise<RunResult> {
  return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], { timeoutMs });
}
