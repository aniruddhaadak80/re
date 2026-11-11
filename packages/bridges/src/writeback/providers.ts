// Write-back: apply a RevLens names file to Ghidra projects, IDA databases and radare2 or rizin
// projects, and export names back out of each. Node only.
import { existsSync } from 'node:fs';
import { copyFile, open, readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { describeFailure, runTool, withTempDir } from '../exec.js';
import { extractJson } from '../parsers/common.js';
import { declaredImageBase, mapAddress, NAME_RE, validateNames, type RevLensNames } from '../names.js';
import { ghidraCachedProject, ghidraHeadlessEnv } from '../providers/ghidra.js';
import { BridgeInputError, cacheRoot, ensureDir, int, need, requireFile, sha256File, unavailable, withLock } from '../providers/common.js';
import type { Detection } from '../types.js';
import {
  GHIDRA_APPLY_SCRIPT, GHIDRA_APPLY_SCRIPT_NAME, GHIDRA_NAMES_EXPORT_SCRIPT, GHIDRA_NAMES_EXPORT_SCRIPT_NAME, IDA_APPLY_SCRIPT, IDA_NAMES_EXPORT_SCRIPT,
} from './scripts.js';

const PROJECT_NAME_RE = /^[A-Za-z0-9_][\w.-]{0,127}$/;

/** Load names from an inline object or JSON text, or from a file path. */
export async function loadNames(input: { names?: unknown; namesPath?: string }): Promise<RevLensNames> {
  if (input.names !== undefined && input.namesPath !== undefined) throw new BridgeInputError('give names or namesPath, not both');
  if (input.namesPath !== undefined) {
    const { path, size } = requireFile(input.namesPath, 'namesPath');
    if (size > 256 * 1024 * 1024) throw new BridgeInputError('namesPath is larger than 256 MiB');
    return validateNames(await readFile(path, 'utf8'));
  }
  if (input.names === undefined) throw new BridgeInputError('names (object) or namesPath is required');
  return validateNames(input.names);
}

async function fileBase(path: string): Promise<bigint> {
  const fh = await open(path, 'r');
  try {
    const b = Buffer.alloc(64 * 1024);
    const { bytesRead } = await fh.read(b, 0, b.length, 0);
    return declaredImageBase(b.subarray(0, bytesRead)) ?? 0n;
  } finally { await fh.close(); }
}

const hex = (n: bigint) => '0x' + n.toString(16);

// ---------------- Ghidra ----------------

interface GhidraTarget { path: string; projectDir?: string; projectName?: string; programName?: string; cacheDir?: string; timeoutMs?: number }

async function ghidraTarget(input: GhidraTarget): Promise<{ ok: true; projectDir: string; projectName: string; programName: string; det: Detection; cached: boolean } | { ok: false; error: string } | { missing: ReturnType<typeof unavailable> }> {
  if (input.projectDir !== undefined) {
    const n = await need('ghidra');
    if ('missing' in n) return n;
    const dir = resolve(String(input.projectDir));
    const name = input.projectName;
    const prog = input.programName;
    if (typeof name !== 'string' || !PROJECT_NAME_RE.test(name)) throw new BridgeInputError('projectName must be a Ghidra project name (letters, digits, _ . -)');
    if (typeof prog !== 'string' || !prog || prog.length > 255 || /[\0\r\n/\\]/.test(prog) || prog.startsWith('-')) throw new BridgeInputError('programName must be the program file name inside the project');
    if (!existsSync(join(dir, `${name}.gpr`))) throw new BridgeInputError(`no Ghidra project ${name}.gpr in ${dir}`);
    return { ok: true, projectDir: dir, projectName: name, programName: prog, det: n.det, cached: false };
  }
  const r = await ghidraCachedProject({ path: input.path, cacheDir: input.cacheDir, timeoutMs: input.timeoutMs });
  if ('missing' in r) return r;
  if (!r.ok) return r;
  return { ...r, cached: true };
}

async function runGhidraScript(t: { projectDir: string; projectName: string; programName: string; det: Detection }, scriptName: string, script: string, scriptArgs: string[], tmp: string, timeoutMs: number, readOnly: boolean) {
  const headless = String(t.det.details?.analyzeHeadless ?? '');
  if (!headless) return { error: 'analyzeHeadless not found' };
  await writeFile(join(tmp, scriptName), script, 'utf8');
  const args = [t.projectDir, t.projectName, '-process', t.programName, '-noanalysis', ...(readOnly ? ['-readOnly'] : []), '-scriptPath', tmp, '-postScript', scriptName, ...scriptArgs];
  const r = await runTool(headless, args, { timeoutMs, maxOutputBytes: 16 * 1024 * 1024, env: ghidraHeadlessEnv(t.det), cwd: tmp });
  return { r };
}

/** Apply a names file to a Ghidra project: the cached RevLens project for the file (default) or your own project. */
export async function ghidraApplyNames(input: GhidraTarget & { names?: unknown; namesPath?: string }) {
  const names = await loadNames(input);
  const { path } = requireFile(input.path);
  const t = await ghidraTarget(input);
  if ('missing' in t) return t.missing;
  if (!t.ok) return { available: true, tool: 'ghidra', ok: false, error: t.error };
  const base = await fileBase(path);
  const timeoutMs = int(input.timeoutMs, 15 * 60_000, 10_000, 7_200_000);
  return withLock(t.projectDir, () => withTempDir(async (tmp) => {
    const namesFile = join(tmp, 'names.json');
    const report = join(tmp, 'report.json');
    await writeFile(namesFile, JSON.stringify(names), 'utf8');
    const res = await runGhidraScript(t, GHIDRA_APPLY_SCRIPT_NAME, GHIDRA_APPLY_SCRIPT, [namesFile, report, hex(base)], tmp, timeoutMs, false);
    if ('error' in res) return { available: true, tool: 'ghidra', ok: false, error: res.error };
    if (!existsSync(report)) {
      const log = `${res.r.stdout}\n${res.r.stderr}`.split(/\r?\n/).filter((l) => /ERROR|Exception|error:/.test(l)).slice(-10).join('\n');
      return { available: true, tool: 'ghidra', ok: false, error: `Ghidra did not write a report (${describeFailure(res.r)})${log ? `\n${log.slice(0, 3000)}` : ''}` };
    }
    const rep = extractJson(await readFile(report, 'utf8')) as Record<string, unknown> | undefined;
    const errors = Array.isArray(rep?.errors) ? rep!.errors as unknown[] : [];
    return {
      available: true, tool: 'ghidra', toolVersion: t.det.version ?? null, ok: !!rep && errors.length === 0, file: path,
      project: { dir: t.projectDir, name: t.projectName, program: t.programName, cached: t.cached }, fileImageBase: hex(base), report: rep ?? null,
    };
  }));
}

/** Export names (user defined by default, every non default name with all) from a Ghidra project. */
export async function ghidraExportNames(input: GhidraTarget & { all?: boolean; outPath?: string }) {
  const { path } = requireFile(input.path);
  const t = await ghidraTarget(input);
  if ('missing' in t) return t.missing;
  if (!t.ok) return { available: true, tool: 'ghidra', ok: false, error: t.error };
  const timeoutMs = int(input.timeoutMs, 15 * 60_000, 10_000, 7_200_000);
  return withLock(t.projectDir, () => withTempDir(async (tmp) => {
    const out = join(tmp, 'names.json');
    const res = await runGhidraScript(t, GHIDRA_NAMES_EXPORT_SCRIPT_NAME, GHIDRA_NAMES_EXPORT_SCRIPT, [out, input.all === true ? 'true' : 'false'], tmp, timeoutMs, true);
    if ('error' in res) return { available: true, tool: 'ghidra', ok: false, error: res.error };
    if (!existsSync(out)) return { available: true, tool: 'ghidra', ok: false, error: `Ghidra did not write names (${describeFailure(res.r)})` };
    const names = validateNames(await readFile(out, 'utf8'));
    names.binary = { sha256: await sha256File(path), name: basename(path) };
    const saved = await saveNames(names, input.outPath);
    return { available: true, tool: 'ghidra', toolVersion: t.det.version ?? null, ok: true, file: path, project: { dir: t.projectDir, name: t.projectName, program: t.programName, cached: t.cached }, ...counts(names), ...(saved ? { savedTo: saved } : {}), names };
  }));
}

function counts(n: RevLensNames) {
  return { counts: { functions: n.functions.length, comments: n.comments.length, labels: n.labels.length, types: n.types.length } };
}

async function saveNames(n: RevLensNames, outPath: unknown): Promise<string | undefined> {
  if (outPath === undefined) return undefined;
  if (typeof outPath !== 'string' || !outPath.trim() || outPath.includes('\0')) throw new BridgeInputError('outPath must be a file path');
  const p = resolve(outPath);
  await ensureDir(dirname(p));
  await writeFile(p, JSON.stringify(n, null, 2), 'utf8');
  return p;
}

// ---------------- IDA ----------------

function isIdaDb(p: string): boolean {
  return /^\.(i64|idb)$/i.test(extname(p));
}

async function runIda(det: Detection, script: string, env: Record<string, unknown>, target: string, dir: string, timeoutMs: number, extra: string[] = []) {
  const scriptPath = join(dir, 'revlens_ida_names.py');
  await writeFile(scriptPath, script, 'utf8');
  const quoted = /\s/.test(scriptPath) ? `"${scriptPath}"` : scriptPath;
  return runTool(det.path!, ['-A', `-L${join(dir, 'ida.log')}`, `-S${quoted}`, ...extra, target], {
    timeoutMs, cwd: dir, maxOutputBytes: 16 * 1024 * 1024, env: { ...process.env, TVHEADLESS: '1', REVLENS_IDA_ARGS: JSON.stringify(env) },
  });
}

async function idaLog(dir: string): Promise<string> {
  const p = join(dir, 'ida.log');
  return existsSync(p) ? (await readFile(p, 'utf8')).slice(-3000) : '';
}

/**
 * Apply a names file with IDA (idat batch mode). Give an existing .i64/.idb to update it in place,
 * or a binary plus outDatabase to create a new database with the names applied. The original
 * binary is never written to.
 */
export async function idaApplyNames(input: { path: string; names?: unknown; namesPath?: string; outDatabase?: string; binaryForBase?: string; timeoutMs?: number }) {
  const names = await loadNames(input);
  const { path } = requireFile(input.path);
  const n = await need('ida');
  if ('missing' in n) return n.missing;
  const db = isIdaDb(path);
  if (!db && (typeof input.outDatabase !== 'string' || !isIdaDb(input.outDatabase))) throw new BridgeInputError('for a binary give outDatabase ending in .i64 or .idb; to update a database pass its path');
  const baseFrom = input.binaryForBase !== undefined ? requireFile(input.binaryForBase, 'binaryForBase').path : db ? undefined : path;
  const base = baseFrom ? await fileBase(baseFrom) : names.imageBase !== undefined ? BigInt(names.imageBase) : 0n;
  const timeoutMs = int(input.timeoutMs, 15 * 60_000, 10_000, 7_200_000);
  return withTempDir(async (dir) => {
    const namesFile = join(dir, 'names.json');
    const report = join(dir, 'report.json');
    await writeFile(namesFile, JSON.stringify(names), 'utf8');
    let target: string;
    let save: string;
    if (db) { target = path; save = path; }
    else {
      target = join(dir, 'input.bin');
      await copyFile(path, target);
      save = resolve(input.outDatabase!);
      await ensureDir(dirname(save));
    }
    const r = await runIda(n.det, IDA_APPLY_SCRIPT, { names: namesFile, report, fileBase: hex(base), save }, target, dir, timeoutMs);
    if (!existsSync(report)) return { available: true, tool: 'ida', ok: false, error: `IDA wrote no report (${describeFailure(r)})\n${await idaLog(dir)}` };
    const rep = extractJson(await readFile(report, 'utf8')) as Record<string, unknown> | undefined;
    const errors = Array.isArray(rep?.errors) ? rep!.errors as unknown[] : [];
    return { available: true, tool: 'ida', toolVersion: n.det.version ?? null, ok: !!rep && errors.length === 0, database: save, report: rep ?? null };
  });
}

/** Export names from an IDA database (.i64/.idb) or a binary (analyzed in a temp folder). */
export async function idaExportNames(input: { path: string; all?: boolean; outPath?: string; timeoutMs?: number }) {
  const { path } = requireFile(input.path);
  const n = await need('ida');
  if ('missing' in n) return n.missing;
  const timeoutMs = int(input.timeoutMs, 15 * 60_000, 10_000, 7_200_000);
  return withTempDir(async (dir) => {
    const out = join(dir, 'names.json');
    let target: string;
    if (isIdaDb(path)) { target = join(dir, `db${extname(path)}`); await copyFile(path, target); }
    else { target = join(dir, 'input.bin'); await copyFile(path, target); }
    const r = await runIda(n.det, IDA_NAMES_EXPORT_SCRIPT, { out, all: input.all === true }, target, dir, timeoutMs);
    if (!existsSync(out)) return { available: true, tool: 'ida', ok: false, error: `IDA wrote no names (${describeFailure(r)})\n${await idaLog(dir)}` };
    const names = validateNames(await readFile(out, 'utf8'));
    const saved = await saveNames(names, input.outPath);
    return { available: true, tool: 'ida', toolVersion: n.det.version ?? null, ok: true, file: path, ...counts(names), ...(saved ? { savedTo: saved } : {}), names };
  });
}

// ---------------- radare2 / rizin ----------------

/** r2 safe name: radare2 treats ~ @ > < ; | and spaces as operators, so other characters become _. */
export function r2Name(name: string): string {
  const s = name.replace(/[^\w.:$-]/g, '_');
  return /^[A-Za-z_]/.test(s) ? s : `_${s}`;
}

/**
 * Turn names into an r2 or rizin script. Every value is validated by validateNames first, then
 * names are reduced to r2 safe characters, comments go through base64, and types and signatures
 * use r2's quoted command form (validation keeps quotes out of them). Pure.
 */
export function namesToR2Script(names: RevLensNames, fileBase: bigint, toolBase: bigint, engine: 'radare2' | 'rizin' = 'radare2'): { script: string; renamed: { from: string; to: string }[] } {
  const L: string[] = [];
  const renamed: { from: string; to: string }[] = [];
  const at = (a: string) => hex(mapAddress(a, names, fileBase, toolBase));
  const b64 = (t: string) => Buffer.from(t, 'utf8').toString('base64');
  for (const t of names.types) L.push(`"td ${t.c.replace(/\s+/g, ' ')}"`);
  for (const f of names.functions) {
    const a = at(f.address);
    L.push(`s ${a}`);
    L.push(engine === 'rizin' ? 'af' : 'af');
    if (f.name) {
      const nm = r2Name(f.name);
      if (nm !== f.name) renamed.push({ from: f.name, to: nm });
      L.push(`afn ${nm}`);
    }
    if (f.signature) {
      let sig = f.signature;
      if (f.name) sig = sig.replace(new RegExp(`\\b${f.name.replace(/[^\w]/g, '\\$&')}\\s*\\(`), `${r2Name(f.name)}(`);
      L.push(`"afs ${sig}"`);
    }
    if (f.comment) L.push(engine === 'rizin' ? `CC base64:${b64(f.comment)}` : `CCu base64:${b64(f.comment)}`);
  }
  for (const c of names.comments) {
    L.push(`s ${at(c.address)}`);
    L.push(engine === 'rizin' ? `CC base64:${b64(c.text)}` : `CCu base64:${b64(c.text)}`);
  }
  if (names.labels.length) L.push('fs revlens');
  for (const l of names.labels) {
    const nm = r2Name(l.name);
    if (nm !== l.name) renamed.push({ from: l.name, to: nm });
    L.push(`f ${nm} 1 ${at(l.address)}`);
  }
  return { script: L.join('\n') + '\n', renamed };
}

async function pickR2(engine: unknown): Promise<{ det: Detection; id: 'radare2' | 'rizin' } | ReturnType<typeof unavailable>> {
  const order: ('radare2' | 'rizin')[] = engine === 'rizin' ? ['rizin'] : engine === 'radare2' ? ['radare2'] : ['radare2', 'rizin'];
  for (const id of order) { const r = await need(id); if ('det' in r) return { det: r.det, id }; }
  return unavailable(order[0]!, order.length > 1 ? 'Neither radare2 nor rizin was found.' : undefined);
}

function projectsDir(custom: unknown): string {
  return typeof custom === 'string' && custom.trim() ? resolve(custom) : join(cacheRoot(), 'r2-projects');
}

async function defaultProject(path: string): Promise<string> {
  return `revlens_${(await sha256File(path)).slice(0, 16)}`;
}

/** Run an r2/rizin script file against a binary (no sandbox: the script is generated by RevLens). */
async function runR2Script(det: Detection, file: string, scriptText: string, timeoutMs: number) {
  return withTempDir(async (dir) => {
    const sc = join(dir, 'revlens.r2');
    await writeFile(sc, scriptText, 'utf8');
    return runTool(det.path!, ['-q', '-N', '-e', 'scr.color=0', '-e', 'scr.interactive=false', '-e', 'bin.relocs.apply=true', '-i', sc, file],
      { timeoutMs, maxOutputBytes: 64 * 1024 * 1024, env: { ...process.env, TERM: 'dumb' } });
  });
}

function prjOpen(id: 'radare2' | 'rizin', dir: string, name: string, exists: boolean): string[] {
  if (id === 'rizin') return exists ? [`Po ${join(dir, `${name}.rzdb`)}`] : [];
  return [`e dir.projects=${dir}`, 'e prj.vc=false', ...(exists ? [`P ${name}`] : [])];
}

function prjSave(id: 'radare2' | 'rizin', dir: string, name: string): string {
  return id === 'rizin' ? `Ps ${join(dir, `${name}.rzdb`)}` : `Ps ${name}`;
}

function prjExists(id: 'radare2' | 'rizin', dir: string, name: string): boolean {
  return id === 'rizin' ? existsSync(join(dir, `${name}.rzdb`)) : existsSync(join(dir, name, 'rc.r2'));
}

/**
 * Apply names to a radare2 project (dir.projects/<project>/rc.r2) or a rizin project
 * (<projectsDir>/<project>.rzdb), creating it from the binary when it does not exist yet.
 * Also returns the generated script so it can be run by hand with r2 -i.
 */
export async function r2ApplyNames(input: { path: string; names?: unknown; namesPath?: string; engine?: string; project?: string; projectsDir?: string; analysis?: 'none' | 'aa' | 'aaa'; timeoutMs?: number }) {
  const names = await loadNames(input);
  const { path } = requireFile(input.path);
  const eng = await pickR2(input.engine);
  if ('available' in eng) return eng;
  const project = input.project ?? await defaultProject(path);
  if (typeof project !== 'string' || !PROJECT_NAME_RE.test(project)) throw new BridgeInputError('project must be letters, digits, _ . -');
  const dir = await ensureDir(projectsDir(input.projectsDir));
  const base = await fileBase(path);
  // radare2 and rizin keep the file's own addresses (no rebasing) unless told otherwise
  const { script, renamed } = namesToR2Script(names, base, base, eng.id);
  const exists = prjExists(eng.id, dir, project);
  const analysis = input.analysis ?? 'aa';
  if (!['none', 'aa', 'aaa'].includes(analysis)) throw new BridgeInputError('analysis must be none, aa or aaa');
  const full = [...prjOpen(eng.id, dir, project, exists), ...(!exists && analysis !== 'none' ? [analysis] : []), script.trimEnd(), prjSave(eng.id, dir, project), ''].join('\n');
  return withLock(join(dir, project), async () => {
    const r = await runR2Script(eng.det, path, full, int(input.timeoutMs, 600_000, 5000, 7_200_000));
    const saved = prjExists(eng.id, dir, project);
    const errLines = `${r.stdout}\n${r.stderr}`.split(/\r?\n/).filter((l) => /^ERROR/.test(l)).slice(0, 50);
    return {
      available: true, tool: eng.id, toolVersion: eng.det.version ?? null, ok: saved && !r.timedOut, file: path,
      project: { name: project, dir, created: !exists, path: eng.id === 'rizin' ? join(dir, `${project}.rzdb`) : join(dir, project, 'rc.r2') },
      applied: { functions: names.functions.length, comments: names.comments.length, labels: names.labels.length, types: names.types.length },
      ...(renamed.length ? { renamed } : {}), ...(errLines.length ? { warnings: errLines } : {}), script,
      ...(saved ? {} : { error: `project was not saved (${describeFailure(r)})` }),
    };
  });
}

/**
 * Export what was added to a radare2 or rizin project: function names and comments that differ
 * from a fresh analysis of the same binary (all: true exports every function name), and flags in
 * the revlens flag space that r2ApplyNames writes labels to.
 */
export async function r2ExportNames(input: { path: string; engine?: string; project?: string; projectsDir?: string; all?: boolean; analysis?: 'none' | 'aa' | 'aaa'; outPath?: string; timeoutMs?: number }) {
  const { path } = requireFile(input.path);
  const eng = await pickR2(input.engine);
  if ('available' in eng) return eng;
  const project = input.project ?? await defaultProject(path);
  if (typeof project !== 'string' || !PROJECT_NAME_RE.test(project)) throw new BridgeInputError('project must be letters, digits, _ . -');
  const dir = projectsDir(input.projectsDir);
  if (!prjExists(eng.id, dir, project)) return { available: true, tool: eng.id, ok: false, error: `no ${eng.id} project ${project} in ${dir}` };
  const analysis = input.analysis ?? 'aa';
  if (!['none', 'aa', 'aaa'].includes(analysis)) throw new BridgeInputError('analysis must be none, aa or aaa');
  const SEP = '__RVLN_NAMES_SEP__';
  const query = ['e scr.color=0', 'aflj', `?e ${SEP}`, 'CCj', `?e ${SEP}`, 'fs revlens', 'fj', `?e ${SEP}`, 'ij', ''];
  const timeoutMs = int(input.timeoutMs, 300_000, 5000, 3_600_000);
  const r = await runR2Script(eng.det, path, [...prjOpen(eng.id, dir, project, true), ...query].join('\n'), timeoutMs);
  const base = await runR2Script(eng.det, path, [...(analysis !== 'none' ? [analysis] : []), ...query].join('\n'), timeoutMs);
  const split = (t: string) => t.split(SEP).map((x) => extractJson(x) as any);
  const [fns, cms, flags, info] = split(r.stdout);
  const [bfns, bcms, bflags] = split(base.stdout);
  if (!Array.isArray(fns) || fns.length === 0) return { available: true, tool: eng.id, ok: false, error: `could not read functions from the project (${describeFailure(r)})` };
  const baseFn = new Map<number, string>((Array.isArray(bfns) ? bfns : []).map((f: any) => [f.addr, f.name]));
  const baseCm = new Set<string>((Array.isArray(bcms) ? bcms : []).map((c: any) => `${c.offset}:${c.name}`));
  const off = (f: any): number | undefined => (typeof f?.offset === 'number' ? f.offset : typeof f?.addr === 'number' ? f.addr : undefined);
  const baseFlag = new Set<string>((Array.isArray(bflags) ? bflags : []).map((f: any) => `${off(f)}:${f.name}`));
  const fnNames = new Set<string>(fns.map((f: any) => f.name));
  const baddr = typeof info?.bin?.baddr === 'number' ? BigInt(info.bin.baddr) : 0n;
  const names = validateNames({
    schema: 'revlens/names@1', source: eng.id, imageBase: hex(baddr), addressing: 'va',
    functions: fns.filter((f: any) => typeof f?.name === 'string' && typeof f?.addr === 'number' && NAME_RE.test(f.name) && (input.all === true || baseFn.get(f.addr) !== f.name))
      .slice(0, 200_000).map((f: any) => ({ address: hex(BigInt(f.addr)), name: f.name })),
    comments: (Array.isArray(cms) ? cms : []).filter((c: any) => typeof c?.offset === 'number' && typeof c?.name === 'string' && c.name && !baseCm.has(`${c.offset}:${c.name}`))
      .slice(0, 200_000).map((c: any) => ({ address: hex(BigInt(c.offset)), text: String(c.name).slice(0, 4096), kind: 'eol' })),
    labels: (Array.isArray(flags) ? flags : []).filter((f: any) => off(f) !== undefined && typeof f?.name === 'string' && NAME_RE.test(f.name) && !fnNames.has(f.name) && !baseFlag.has(`${off(f)}:${f.name}`) && !/^(fcn|sub|loc|case|str|sym|section|segment|reloc|obj)\./.test(f.name))
      .slice(0, 200_000).map((f: any) => ({ address: hex(BigInt(off(f)!)), name: f.name })),
  });
  names.binary = { sha256: await sha256File(path), name: basename(path) };
  const saved = await saveNames(names, input.outPath);
  return { available: true, tool: eng.id, toolVersion: eng.det.version ?? null, ok: true, file: path, project: { name: project, dir }, ...counts(names), ...(saved ? { savedTo: saved } : {}), names };
}
