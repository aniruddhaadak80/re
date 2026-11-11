// Ghidra headless bridge. Runs analyzeHeadless with the RevLens export script.
// One Ghidra project is kept per input SHA-256 so later calls skip auto analysis.
import { existsSync } from 'node:fs';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { describeFailure, runTool, withTempDir } from '../exec.js';
import { parseGhidraExport, type GhidraExport } from '../parsers/ghidra.js';
import { GHIDRA_EXPORT_SCRIPT, GHIDRA_SCRIPT_NAME } from '../scripts.js';
import type { Detection, Unavailable } from '../types.js';
import { BridgeInputError, cacheRoot, ensureDir, int, need, requireFile, sha256File, withLock, writeMarker } from './common.js';

export interface GhidraInput {
  path: string;
  /** total wall clock limit, default 15 minutes */
  timeoutMs?: number;
  /** folder for cached Ghidra projects, default the per user RevLens cache folder */
  cacheDir?: string;
  /** reuse the cached project for this file (default true) */
  useCache?: boolean;
}

const PROJECT = 'revlens';
const SELECTOR_RE = /^(0x[0-9a-fA-F]{1,16}|[A-Za-z_.$?@][\w.$?@:<>~-]{0,511})$/;

interface Marker { programName: string; sha256: string; createdAt: string; ghidraVersion: string | null }

function headlessEnv(det: Detection): NodeJS.ProcessEnv {
  const env = { ...process.env };
  const jh = det.details?.javaHome;
  if (typeof jh === 'string' && jh) env.JAVA_HOME = jh;
  return env;
}

type ExportResult =
  | { ok: true; export: GhidraExport; cached: boolean; projectDir: string; det: Detection; durationMs: number }
  | { ok: false; error: string; det?: Detection }
  | { missing: Unavailable };

/** Run the export script in a given mode. Imports and analyzes on first use, then reuses the project. */
export async function ghidraExport(input: GhidraInput & { mode: 'info' | 'functions' | 'decompile'; limit?: number; offset?: number; selectors?: string[]; perFunctionTimeoutSec?: number }): Promise<ExportResult> {
  const { path } = requireFile(input.path);
  const n = await need('ghidra');
  if ('missing' in n) return n;
  const det = n.det;
  const headless = String(det.details?.analyzeHeadless ?? '');
  if (!headless) return { ok: false, error: 'analyzeHeadless not found', det };
  const selectors = (input.selectors ?? []).slice(0, 64).map((s) => {
    if (typeof s !== 'string' || !SELECTOR_RE.test(s)) throw new BridgeInputError(`bad function selector ${JSON.stringify(s)}`);
    return s;
  });
  if (input.mode === 'decompile' && det.details?.decompiler === false) {
    return { ok: false, error: (det.problems ?? []).join(' ') || 'Ghidra native decompiler is missing for this platform', det };
  }
  const sha = await sha256File(path);
  const projectDir = join(cacheRoot(input.cacheDir), 'ghidra', sha.slice(0, 32));
  const timeoutMs = int(input.timeoutMs, 15 * 60_000, 10_000, 2 * 60 * 60_000);
  const limit = int(input.limit, input.mode === 'decompile' ? 16 : 500, 0, 100_000);
  const offset = int(input.offset, 0, 0, 1e9);
  const perFn = int(input.perFunctionTimeoutSec, 60, 1, 3600);
  const started = Date.now();

  return withLock(projectDir, () => withTempDir(async (tmp): Promise<ExportResult> => {
    await writeFile(join(tmp, GHIDRA_SCRIPT_NAME), GHIDRA_EXPORT_SCRIPT, 'utf8');
    const outJson = join(tmp, 'export.json');
    const markerPath = join(projectDir, 'revlens-project.json');
    let marker: Marker | undefined;
    if (input.useCache !== false && existsSync(markerPath) && existsSync(join(projectDir, `${PROJECT}.gpr`))) {
      try { marker = JSON.parse(await readFile(markerPath, 'utf8')) as Marker; } catch { marker = undefined; }
    }
    const scriptArgs = ['-scriptPath', tmp, '-postScript', GHIDRA_SCRIPT_NAME, outJson, input.mode, String(limit), String(offset), String(perFn), ...selectors];
    const run = async (cached: boolean) => {
      await ensureDir(projectDir);
      const args = cached && marker
        ? [projectDir, PROJECT, '-process', marker.programName, '-noanalysis', '-readOnly', ...scriptArgs]
        : [projectDir, PROJECT, '-import', path, '-overwrite', '-analysisTimeoutPerFile', String(Math.max(60, Math.floor(timeoutMs / 1000) - 60)), ...scriptArgs];
      return runTool(headless, args, { timeoutMs, maxOutputBytes: 16 * 1024 * 1024, env: headlessEnv(det), cwd: tmp });
    };
    let cached = !!marker;
    let r = await run(cached);
    if (cached && !existsSync(outJson)) {
      // Project unusable (moved Ghidra, version change). Rebuild once.
      await rm(projectDir, { recursive: true, force: true });
      marker = undefined;
      cached = false;
      r = await run(false);
    }
    if (!existsSync(outJson)) {
      const log = `${r.stdout}\n${r.stderr}`;
      const errLine = log.split(/\r?\n/).filter((l) => /ERROR|Exception|not supported|Unable/.test(l)).slice(-8).join('\n');
      return { ok: false, error: `Ghidra did not produce output (${describeFailure(r)})${errLine ? `\n${errLine.slice(0, 3000)}` : ''}`, det };
    }
    if (!cached) {
      const m: Marker = { programName: basename(path), sha256: sha, createdAt: new Date().toISOString(), ghidraVersion: det.version ?? null };
      await writeMarker(markerPath, JSON.stringify(m));
    }
    const parsed = parseGhidraExport(await readFile(outJson, 'utf8'));
    if (!parsed) return { ok: false, error: 'Ghidra export JSON was not valid', det };
    return { ok: true, export: parsed, cached, projectDir, det, durationMs: Date.now() - started };
  }));
}

function head(det: Detection, path: string) {
  return { available: true as const, tool: 'ghidra', toolVersion: det.version ?? null, file: path };
}

/** List functions with Ghidra (address, size, signature, calling convention), paged. */
export async function ghidraFunctions(input: GhidraInput & { limit?: number; offset?: number }) {
  const r = await ghidraExport({ ...input, mode: 'functions' });
  if ('missing' in r) return r.missing;
  const path = requireFile(input.path).path;
  if (!r.ok) return { available: true, tool: 'ghidra', file: path, ok: false, error: r.error };
  const e = r.export;
  const fns = e.functions ?? [];
  const limit = int(input.limit, 500, 0, 100_000);
  return {
    ...head(r.det, path), ok: true, cached: r.cached, durationMs: r.durationMs,
    program: { name: e.program, language: e.language, compiler: e.compiler, format: e.format, imageBase: e.imageBase },
    /** Ghidra's count, which also includes external (imported) functions that are not listed */
    functionCount: e.functionCount ?? null,
    offset: int(input.offset, 0, 0, 1e9), limit, returned: fns.length, more: fns.length >= limit && limit > 0, functions: fns,
  };
}

/** Decompile functions to C with Ghidra. `functions` takes names or 0x addresses. */
export async function ghidraDecompile(input: GhidraInput & { functions: string[] | string; maxCharsPerFunction?: number; perFunctionTimeoutSec?: number }) {
  const sel = Array.isArray(input.functions) ? input.functions : typeof input.functions === 'string' ? [input.functions] : [];
  if (sel.length === 0) throw new BridgeInputError('functions is required: names or 0x addresses');
  const r = await ghidraExport({ ...input, mode: 'decompile', selectors: sel, limit: sel.length });
  if ('missing' in r) return r.missing;
  const path = requireFile(input.path).path;
  if (!r.ok) return { available: true, tool: 'ghidra', file: path, ok: false, error: r.error };
  const max = int(input.maxCharsPerFunction, 200_000, 1000, 4_000_000);
  const e = r.export;
  const results = (e.decompiled ?? []).map((d) => ({ ...d, truncated: (d.c?.length ?? 0) > max, c: d.c?.slice(0, max) }));
  const covered = (s: string) => results.some((d) => d.function.name === s || d.function.address === s.toLowerCase() ||
    (s.startsWith('0x') && parseInt(s, 16) >= parseInt(d.function.address, 16) && parseInt(s, 16) < parseInt(d.function.address, 16) + Math.max(1, d.function.size)));
  return {
    ...head(r.det, path), ok: !e.error, cached: r.cached, durationMs: r.durationMs,
    program: { name: e.program, language: e.language, compiler: e.compiler, format: e.format, imageBase: e.imageBase },
    ...(e.error ? { error: e.error } : {}),
    results, notFound: sel.filter((s) => !covered(s)),
  };
}

/**
 * The cached RevLens Ghidra project for a file (the one bridge_ghidra_functions and
 * bridge_ghidra_decompile use), importing and analyzing the file first when it is not there yet.
 */
export async function ghidraCachedProject(input: GhidraInput): Promise<{ ok: true; projectDir: string; projectName: string; programName: string; det: Detection } | { ok: false; error: string } | { missing: Unavailable }> {
  const { path } = requireFile(input.path);
  const sha = await sha256File(path);
  const projectDir = join(cacheRoot(input.cacheDir), 'ghidra', sha.slice(0, 32));
  const markerPath = join(projectDir, 'revlens-project.json');
  if (!existsSync(markerPath) || !existsSync(join(projectDir, `${PROJECT}.gpr`))) {
    const r = await ghidraExport({ ...input, mode: 'info' });
    if ('missing' in r) return r;
    if (!r.ok) return { ok: false, error: r.error };
  }
  const n = await need('ghidra');
  if ('missing' in n) return n;
  try {
    const m = JSON.parse(await readFile(markerPath, 'utf8')) as Marker;
    return { ok: true, projectDir, projectName: PROJECT, programName: m.programName, det: n.det };
  } catch {
    return { ok: false, error: 'cached Ghidra project marker is unreadable' };
  }
}

/** Environment for analyzeHeadless (JAVA_HOME from detection). */
export { headlessEnv as ghidraHeadlessEnv };
