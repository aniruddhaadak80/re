// JEB bridge (PNF Software's commercial decompiler). Finds a JEB install and runs it headless with the
// RevLens script (scripts/jeb/RevLensJeb.py) to open a file, list units and decompile one item.
// JEB is never bundled; without it every call answers { available: false, install }. Node only.
import { existsSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runTool, describeFailure } from './exec.js';
import { BridgeInputError, int, requireFile } from './providers/common.js';

export interface JebDetection {
  id: 'jeb';
  name: 'JEB';
  available: boolean;
  /** install root */
  home?: string;
  /** headless launcher: jeb_linux.sh, jeb_macos.sh or jeb_wincli.bat */
  launcher?: string;
  version?: string;
  via?: 'env' | 'dir';
  problems?: string[];
}

export const JEB_INSTALL = {
  homepage: 'https://www.pnfsoftware.com/jeb/', license: 'Commercial (JEB Pro or Community; headless scripting needs an edition that allows it)',
  note: 'Download JEB from pnfsoftware.com, unpack it, then set JEB_HOME (or REVLENS_JEB_PATH) to the folder holding jeb_linux.sh, jeb_macos.sh or jeb_wincli.bat.',
};

const LAUNCHERS: Record<string, string> = { linux: 'jeb_linux.sh', darwin: 'jeb_macos.sh', win32: 'jeb_wincli.bat' };

/** Version from an install folder name such as jeb-pro-5.12.0.202405301617 or JEB 4.30. */
export function jebVersionFromName(name: string): string | undefined {
  return /jeb[\w-]*?[-_ ]v?(\d+\.\d+(?:\.\d+)?)/i.exec(name)?.[1];
}

function isFile(p: string): boolean { try { return statSync(p).isFile(); } catch { return false; } }

function candidates(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): { dir: string; via: 'env' | 'dir' }[] {
  const h = env.HOME || env.USERPROFILE || homedir();
  const out: { dir: string; via: 'env' | 'dir' }[] = [];
  for (const k of ['REVLENS_JEB_PATH', 'JEB_HOME']) {
    const v = env[k];
    if (v) out.push({ dir: isFile(v) ? dirname(v) : v, via: 'env' });
  }
  const roots = platform === 'win32'
    ? ['C:/', join(env.ProgramFiles || 'C:/Program Files'), join(h, 'Downloads'), join(h, 'tools'), h]
    : platform === 'darwin' ? ['/Applications', join(h, 'Applications'), h, join(h, 'Downloads'), '/opt'] : [h, join(h, 'tools'), join(h, 'Downloads'), '/opt', '/usr/local'];
  for (const r of roots) {
    let names: string[] = [];
    try { names = readdirSync(r).filter((n) => /^jeb/i.test(n)).sort().reverse().slice(0, 16); } catch { continue; }
    for (const n of names) {
      out.push({ dir: join(r, n), via: 'dir' });
      if (platform === 'darwin' && n.endsWith('.app')) out.push({ dir: join(r, n, 'Contents', 'Resources'), via: 'dir' });
    }
  }
  return out;
}

/** Find JEB without starting it. */
export function detectJebSync(opts: { env?: NodeJS.ProcessEnv; platform?: NodeJS.Platform } = {}): JebDetection {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const want = LAUNCHERS[platform] ?? 'jeb_linux.sh';
  const problems: string[] = [];
  for (const c of candidates(env, platform)) {
    const launcher = join(c.dir, want);
    if (isFile(launcher)) {
      const jar = ['bin/app/jeb.jar', 'bin/app/jebc.jar', 'bin/jeb.jar'].map((p) => join(c.dir, p)).find(isFile);
      const p = jar ? [] : ['no bin/app/jeb.jar next to the launcher; the install may be incomplete'];
      return { id: 'jeb', name: 'JEB', available: true, home: c.dir, launcher, version: jebVersionFromName(basename(c.dir)), via: c.via, ...(p.length ? { problems: p } : {}) };
    }
    if (c.via === 'env') problems.push(`${c.dir} has no ${want}`);
  }
  return { id: 'jeb', name: 'JEB', available: false, ...(problems.length ? { problems } : {}) };
}

/** Find JEB (async form for tool lists). */
export async function detectJeb(opts: { env?: NodeJS.ProcessEnv; platform?: NodeJS.Platform } = {}): Promise<JebDetection> {
  return detectJebSync(opts);
}

/** Path of the RevLens JEB script shipped with this package. */
export function jebScriptPath(): string {
  const here = typeof __filename === 'string' ? dirname(__filename) : dirname(fileURLToPath(import.meta.url));
  const c = [join(here, '..', 'scripts', 'jeb', 'RevLensJeb.py'), join(here, '..', '..', 'scripts', 'jeb', 'RevLensJeb.py')];
  return c.find((p) => existsSync(p)) ?? c[0]!;
}
declare const __filename: string | undefined;

const BEGIN = '@@REVLENS_JSON_BEGIN@@';
const END = '@@REVLENS_JSON_END@@';

/** Pull the JSON document the RevLens script printed out of JEB's console output. */
export function parseJebOutput(stdout: string): { ok: true; value: any } | { ok: false; error: string } {
  const a = stdout.lastIndexOf(BEGIN);
  if (a < 0) return { ok: false, error: 'JEB did not print the RevLens result' };
  const b = stdout.indexOf(END, a);
  const body = stdout.slice(a + BEGIN.length, b < 0 ? undefined : b).trim();
  try { return { ok: true, value: JSON.parse(body) }; } catch { return { ok: false, error: 'the RevLens result from JEB is not valid JSON' }; }
}

/** Argument list for one headless run: -c --script=<script> -- <action> <file> [item] [maxChars]. */
export function jebArgs(script: string, action: string, file: string, item?: string, maxChars?: number): string[] {
  const args = ['-c', `--script=${script}`, '--', action, file];
  if (item !== undefined) args.push(item);
  if (maxChars !== undefined) { if (item === undefined) args.push(''); args.push(String(maxChars)); }
  return args;
}

const ITEM_RE = /^[\w$/;:<>()[\]\-.@+]{1,512}$/;

export interface JebInput { path: string; item?: string; maxChars?: number; timeoutMs?: number }

async function run(action: 'info' | 'units' | 'decompile', input: JebInput): Promise<unknown> {
  const det = detectJebSync();
  if (!det.available) return { available: false, tool: 'jeb', reason: 'JEB was not found on this machine.', problems: det.problems ?? [], install: JEB_INSTALL };
  const { path } = requireFile(input?.path);
  if (action === 'decompile') {
    if (typeof input.item !== 'string' || !ITEM_RE.test(input.item)) throw new BridgeInputError('item must be a class or method signature (Lcom/a/B; or Lcom/a/B;->m()V) or an address, without spaces');
  }
  const maxChars = int(input.maxChars, 200_000, 1_000, 4_000_000);
  const timeoutMs = int(input.timeoutMs, 600_000, 5_000, 2 * 60 * 60_000);
  const args = jebArgs(jebScriptPath(), action, path, action === 'decompile' ? input.item : undefined, action === 'decompile' ? maxChars : undefined);
  const r = await runTool(det.launcher!, args, { timeoutMs, maxOutputBytes: 64 << 20, cwd: det.home });
  const parsed = parseJebOutput(r.stdout);
  const base = { available: true, tool: 'jeb', version: det.version ?? null, home: det.home, file: path, durationMs: r.durationMs };
  if (!parsed.ok) return { ...base, ok: false, error: `${parsed.error}. ${describeFailure(r)}`, stderr: r.stderr.slice(-2000) };
  return { ...base, ...parsed.value };
}

/** Open a file in JEB headless and report the project and artifacts. */
export const jebInfo = (i: JebInput) => run('info', i);
/** List the units JEB creates for a file (DEX, APK resources, native code, ...). */
export const jebUnits = (i: JebInput) => run('units', i);
/** Decompile one class, method or address with the unit's JEB decompiler. */
export const jebDecompile = (i: JebInput) => run('decompile', i);
