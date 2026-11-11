// Shared helpers for provider operations: input checks, results, caching. Node only.
import { createHash } from 'node:crypto';
import { createReadStream, statSync } from 'node:fs';
import { mkdir, readdir, rm, stat } from 'node:fs/promises';
import { homedir, tmpdir, userInfo } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { detect } from '../detect.js';
import { installFor, TOOL_META } from '../catalog.js';
import type { Detection, ToolId, Unavailable } from '../types.js';

export const MAX_INPUT_BYTES = 4 * 1024 * 1024 * 1024;

export class BridgeInputError extends Error {}

/** Resolve and check a path to an existing regular file. Throws BridgeInputError otherwise. */
export function requireFile(p: unknown, label = 'path'): { path: string; size: number } {
  if (typeof p !== 'string' || !p.trim()) throw new BridgeInputError(`${label} is required`);
  if (p.includes('\0')) throw new BridgeInputError(`${label} contains a NUL byte`);
  const abs = resolve(p);
  let st;
  try { st = statSync(abs); } catch { throw new BridgeInputError(`${label} does not exist: ${abs}`); }
  if (!st.isFile()) throw new BridgeInputError(`${label} is not a regular file: ${abs}`);
  if (st.size > MAX_INPUT_BYTES) throw new BridgeInputError(`${label} is larger than 4 GiB`);
  return { path: abs, size: st.size };
}

/** Clamp an integer input. */
export function int(v: unknown, def: number, min: number, max: number): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN;
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(Math.floor(n), max));
}

export function unavailable(id: ToolId, reason?: string): Unavailable {
  return { available: false, tool: id, reason: reason ?? `${TOOL_META[id].name} was not found on this machine.`, install: installFor(id) };
}

/** Detect a tool and return it, or an Unavailable result explaining what to install. */
export async function need(id: ToolId): Promise<{ det: Detection } | { missing: Unavailable }> {
  const det = await detect(id);
  if (!det.available || !det.path) {
    const why = det.problems?.length ? det.problems.join(' ') : undefined;
    return { missing: unavailable(id, why) };
  }
  return { det };
}

export function isUnavailable(v: unknown): v is Unavailable {
  return !!v && typeof v === 'object' && (v as Unavailable).available === false;
}

/** SHA-256 of a file, streamed. */
export function sha256File(path: string): Promise<string> {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    createReadStream(path).on('data', (c) => h.update(c)).on('error', rej).on('end', () => res(h.digest('hex')));
  });
}

/** Root folder for reusable outputs (Ghidra projects, jadx and apktool output). */
export function cacheRoot(custom?: unknown): string {
  if (typeof custom === 'string' && custom.trim()) return resolve(custom);
  if (process.env.REVLENS_CACHE_DIR) return resolve(process.env.REVLENS_CACHE_DIR);
  return defaultCacheRoot();
}

/**
 * The per user cache folder: $XDG_CACHE_HOME/revlens, ~/.cache/revlens, %LOCALAPPDATA%\revlens\cache or
 * ~/Library/Caches/revlens. A shared temp folder is used only when there is no home folder, and then with
 * the user id in its name, so another user cannot plant files in it first.
 */
function defaultCacheRoot(): string {
  if (process.platform === 'win32' && process.env.LOCALAPPDATA) return join(process.env.LOCALAPPDATA, 'revlens', 'cache');
  if (process.env.XDG_CACHE_HOME) return join(process.env.XDG_CACHE_HOME, 'revlens');
  let home = '';
  try { home = homedir(); } catch { /* no home */ }
  if (home) return process.platform === 'darwin' ? join(home, 'Library', 'Caches', 'revlens') : join(home, '.cache', 'revlens');
  let uid = 'user';
  try { uid = String(userInfo().uid); } catch { /* unknown */ }
  return join(tmpdir(), `revlens-cache-${uid}`);
}

export async function ensureDir(d: string): Promise<string> {
  await mkdir(d, { recursive: true, mode: 0o700 });
  return d;
}

/** Delete the RevLens bridge cache (or one tool's part of it). */
export async function clearCache(tool?: string, custom?: string): Promise<string> {
  const root = cacheRoot(custom);
  const target = tool ? join(root, tool.replace(/[^a-z0-9-]/gi, '')) : root;
  await rm(target, { recursive: true, force: true });
  return target;
}

/** Recursively list files under a folder, bounded by count and depth. Paths are relative with / separators. */
export async function listFiles(root: string, opts: { maxFiles?: number; maxDepth?: number; filter?: (rel: string) => boolean } = {}):
  Promise<{ files: { path: string; size: number }[]; truncated: boolean }> {
  const maxFiles = opts.maxFiles ?? 100_000;
  const maxDepth = opts.maxDepth ?? 32;
  const files: { path: string; size: number }[] = [];
  let truncated = false;
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > maxDepth || truncated) return;
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (truncated) return;
      const full = join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) await walk(full, depth + 1);
      else if (e.isFile()) {
        const rel = relative(root, full).split(sep).join('/');
        if (opts.filter && !opts.filter(rel)) continue;
        if (files.length >= maxFiles) { truncated = true; return; }
        let size = 0;
        try { size = (await stat(full)).size; } catch { /* vanished */ }
        files.push({ path: rel, size });
      }
    }
  };
  await walk(root, 0);
  return { files, truncated };
}

/** Make sure `child` resolves inside `root`. */
export function inside(root: string, child: string): boolean {
  const r = resolve(root);
  const c = resolve(r, child);
  return c === r || c.startsWith(r + sep);
}

/** Per key async mutex so two runs never share one Ghidra project or output folder at once. */
const locks = new Map<string, Promise<unknown>>();
export async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((r) => { release = r; });
  const chain = prev.then(() => mine);
  locks.set(key, chain);
  try {
    await prev.catch(() => undefined);
    return await fn();
  } finally {
    release();
    if (locks.get(key) === chain) locks.delete(key);
  }
}

/** Printed by every dynamic operation before it starts the target. */
export const EXECUTION_WARNING =
  'RevLens is about to run the target program under a debugger or instrumentation tool. Only do this with files you trust or inside a sandbox, VM or disposable container.';

/** Dynamic operations refuse to run unless the caller opts in. */
export function requireExecution(input: { allowExecution?: unknown } | undefined, what: string): string | undefined {
  if (input?.allowExecution === true) {
    process.stderr.write(`[revlens] warning: ${EXECUTION_WARNING}\n`);
    return undefined;
  }
  return `${what} runs code. Pass allowExecution: true to confirm you trust the target or are inside a sandbox. ${EXECUTION_WARNING}`;
}
