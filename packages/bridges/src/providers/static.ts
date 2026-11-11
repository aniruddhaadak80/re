// Static bridges that do not need a full analysis framework: objdump or llvm-objdump, binwalk,
// adb (devices, packages, pull APK, logcat), IDA batch mode and Binary Ninja headless. Node only.
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { existsSync } from 'node:fs';
import { describeFailure, runTool, withTempDir } from '../exec.js';
import { parseAdbDevices, parseAdbPackages, parseAdbPmPath, isPackageName } from '../parsers/adb.js';
import { parseBinwalkJson, parseBinwalkTable } from '../parsers/binwalk.js';
import { extractJson, lines } from '../parsers/common.js';
import { parseObjdumpDisasm, parseObjdumpSections, parseObjdumpSymbols } from '../parsers/objdump.js';
import { IDA_EXPORT_SCRIPT } from '../scripts.js';
import type { Detection, Unavailable } from '../types.js';
import { BridgeInputError, cacheRoot, ensureDir, int, need, requireFile, unavailable } from './common.js';

function head(tool: string, det: Detection, file?: string) {
  return { available: true as const, tool, toolVersion: det.version ?? null, ...(file ? { file } : {}) };
}

// ---------------- objdump ----------------

const SYM_RE = /^[A-Za-z_.$][\w.$@]{0,511}$/;
const ADDR_RE = /^0x[0-9a-fA-F]{1,16}$/;

async function pickObjdump(engine?: string): Promise<{ det: Detection; id: 'objdump' | 'llvm-objdump' } | Unavailable> {
  const order: ('objdump' | 'llvm-objdump')[] = engine === 'llvm-objdump' ? ['llvm-objdump'] : engine === 'objdump' ? ['objdump'] : ['objdump', 'llvm-objdump'];
  for (const id of order) {
    const r = await need(id);
    if ('det' in r) return { det: r.det, id };
  }
  return unavailable(order[0]!, 'Neither GNU objdump nor llvm-objdump was found.');
}

export interface ObjdumpInput {
  path: string;
  /** disasm (default), sections or symbols */
  mode?: 'disasm' | 'sections' | 'symbols';
  /** disassemble only this symbol */
  function?: string;
  startAddress?: string;
  stopAddress?: string;
  engine?: 'objdump' | 'llvm-objdump' | 'auto';
  /** max instructions returned in disasm mode, default 5000 */
  limit?: number;
  timeoutMs?: number;
}

/** Disassemble, list sections or list symbols with GNU objdump (or llvm-objdump as a fallback). */
export async function objdump(input: ObjdumpInput) {
  const { path } = requireFile(input.path);
  const eng = await pickObjdump(input.engine);
  if ('available' in eng) return eng;
  const mode = input.mode ?? 'disasm';
  const args: string[] = [];
  if (mode === 'sections') args.push('-h');
  else if (mode === 'symbols') args.push('-t');
  else {
    args.push('-d');
    if (input.function !== undefined) {
      if (typeof input.function !== 'string' || !SYM_RE.test(input.function)) throw new BridgeInputError('function must be a symbol name');
      args.push(eng.id === 'llvm-objdump' ? `--disassemble-symbols=${input.function}` : `--disassemble=${input.function}`);
    }
    for (const [k, v] of [['start', input.startAddress], ['stop', input.stopAddress]] as const) {
      if (v === undefined) continue;
      if (typeof v !== 'string' || !ADDR_RE.test(v)) throw new BridgeInputError(`${k}Address must be a 0x address`);
      args.push(`--${k}-address=${v}`);
    }
  }
  // The path is absolute, so it can never be read as an option. llvm-objdump rejects a bare --.
  if (eng.id === 'objdump') args.push('--');
  args.push(path);
  const r = await runTool(eng.det.path!, args, { timeoutMs: int(input.timeoutMs, 120_000, 2000, 3_600_000), maxOutputBytes: 128 * 1024 * 1024 });
  if (r.code !== 0 && !r.stdout.trim()) return { ...head(eng.id, eng.det, path), ok: false, error: describeFailure(r) };
  if (mode === 'sections') return { ...head(eng.id, eng.det, path), ok: true, mode, sections: parseObjdumpSections(r.stdout) };
  if (mode === 'symbols') {
    const syms = parseObjdumpSymbols(r.stdout);
    const limit = int(input.limit, 5000, 1, 200_000);
    return { ...head(eng.id, eng.det, path), ok: true, mode, total: syms.length, more: syms.length > limit, symbols: syms.slice(0, limit) };
  }
  const d = parseObjdumpDisasm(r.stdout);
  const limit = int(input.limit, 5000, 1, 200_000);
  let left = limit;
  let truncated = r.truncated;
  const functions = [];
  for (const f of d.functions) {
    if (left <= 0) { truncated = true; break; }
    const ins = f.instructions.slice(0, left);
    if (ins.length < f.instructions.length) truncated = true;
    left -= ins.length;
    functions.push({ ...f, instructions: ins });
  }
  return { ...head(eng.id, eng.det, path), ok: true, mode, format: d.format ?? null, functionCount: functions.length, truncated, functions };
}

// ---------------- binwalk ----------------

/** Signature scan with binwalk (v2 text table or v3 JSON log). Never extracts. */
export async function binwalkScan(input: { path: string; timeoutMs?: number; limit?: number }) {
  const { path } = requireFile(input.path);
  const n = await need('binwalk');
  if ('missing' in n) return n.missing;
  const major = Number((n.det.version ?? '').split('.')[0]) || 0;
  const timeoutMs = int(input.timeoutMs, 300_000, 2000, 3_600_000);
  const limit = int(input.limit, 2000, 1, 100_000);
  if (major >= 3) {
    return withTempDir(async (dir) => {
      const log = join(dir, 'binwalk.json');
      const r = await runTool(n.det.path!, ['-q', '-l', log, path], { timeoutMs, maxOutputBytes: 16 * 1024 * 1024, cwd: dir });
      if (!existsSync(log)) return { ...head('binwalk', n.det, path), ok: false, error: describeFailure(r) };
      const hits = parseBinwalkJson(await readFile(log, 'utf8'));
      return { ...head('binwalk', n.det, path), ok: true, format: 'v3-json', total: hits.length, more: hits.length > limit, hits: hits.slice(0, limit) };
    });
  }
  const r = await runTool(n.det.path!, [path], { timeoutMs, maxOutputBytes: 32 * 1024 * 1024 });
  const hits = parseBinwalkTable(r.stdout);
  if (r.code !== 0 && hits.length === 0) return { ...head('binwalk', n.det, path), ok: false, error: describeFailure(r) };
  return { ...head('binwalk', n.det, path), ok: true, format: 'v2-table', total: hits.length, more: hits.length > limit, hits: hits.slice(0, limit) };
}

// ---------------- adb ----------------

const SERIAL_RE = /^[\w.:\-[\]%]{1,256}$/;
const TAG_RE = /^[\w.:-]{1,128}$/;

function serialArgs(serial: unknown): string[] {
  if (serial === undefined || serial === null || serial === '') return [];
  if (typeof serial !== 'string' || !SERIAL_RE.test(serial)) throw new BridgeInputError('serial has characters that are not allowed');
  return ['-s', serial];
}

/** List connected Android devices and emulators. */
export async function adbDevices(input: { timeoutMs?: number } = {}) {
  const n = await need('adb');
  if ('missing' in n) return n.missing;
  const r = await runTool(n.det.path!, ['devices', '-l'], { timeoutMs: int(input.timeoutMs, 30_000, 2000, 300_000), maxOutputBytes: 1024 * 1024 });
  if (r.code !== 0) return { ...head('adb', n.det), ok: false, error: describeFailure(r) };
  const devices = parseAdbDevices(r.stdout);
  return { ...head('adb', n.det), ok: true, count: devices.length, devices };
}

/** List installed packages with their APK paths (`pm list packages -f`). */
export async function adbPackages(input: { serial?: string; filter?: string; thirdPartyOnly?: boolean; limit?: number; timeoutMs?: number } = {}) {
  const n = await need('adb');
  if ('missing' in n) return n.missing;
  const args = [...serialArgs(input.serial), 'shell', 'pm', 'list', 'packages', '-f', ...(input.thirdPartyOnly ? ['-3'] : [])];
  const r = await runTool(n.det.path!, args, { timeoutMs: int(input.timeoutMs, 60_000, 2000, 600_000), maxOutputBytes: 16 * 1024 * 1024 });
  let pkgs = parseAdbPackages(r.stdout);
  if (r.code !== 0 && pkgs.length === 0) return { ...head('adb', n.det), ok: false, error: describeFailure(r) };
  const f = typeof input.filter === 'string' ? input.filter.toLowerCase().slice(0, 256) : '';
  if (f) pkgs = pkgs.filter((p) => p.name.toLowerCase().includes(f));
  const limit = int(input.limit, 1000, 1, 100_000);
  return { ...head('adb', n.det), ok: true, total: pkgs.length, more: pkgs.length > limit, packages: pkgs.slice(0, limit) };
}

/** Pull every APK (base and splits) of an installed package to a local folder. */
export async function adbPullApk(input: { package: string; serial?: string; outDir?: string; timeoutMs?: number }) {
  if (typeof input.package !== 'string' || !isPackageName(input.package)) throw new BridgeInputError('package must be an Android package name like com.example.app');
  const n = await need('adb');
  if ('missing' in n) return n.missing;
  const s = serialArgs(input.serial);
  const timeoutMs = int(input.timeoutMs, 300_000, 2000, 3_600_000);
  const pm = await runTool(n.det.path!, [...s, 'shell', 'pm', 'path', input.package], { timeoutMs: 60_000, maxOutputBytes: 1024 * 1024 });
  const remote = parseAdbPmPath(pm.stdout);
  if (remote.length === 0) return { ...head('adb', n.det), ok: false, error: `package ${input.package} not found on the device (${describeFailure(pm)})` };
  const outDir = await ensureDir(typeof input.outDir === 'string' && input.outDir ? input.outDir : join(cacheRoot(), 'adb', input.package));
  const pulled: { remote: string; local: string; ok: boolean; error?: string }[] = [];
  for (const rp of remote) {
    const name = basename(rp).replace(/[^\w.+-]/g, '_') || 'base.apk';
    const local = join(outDir, name);
    const r = await runTool(n.det.path!, [...s, 'pull', rp, local], { timeoutMs, maxOutputBytes: 1024 * 1024 });
    pulled.push({ remote: rp, local, ok: r.code === 0 && existsSync(local), ...(r.code === 0 ? {} : { error: describeFailure(r) }) });
  }
  return { ...head('adb', n.det), ok: pulled.every((p) => p.ok), package: input.package, outDir, files: pulled };
}

/** Dump recent logcat lines (`logcat -d -t N`), optionally only one tag. */
export async function adbLogcat(input: { serial?: string; lines?: number; tag?: string; timeoutMs?: number } = {}) {
  const n = await need('adb');
  if ('missing' in n) return n.missing;
  const count = int(input.lines, 500, 1, 50_000);
  const args = [...serialArgs(input.serial), 'logcat', '-d', '-t', String(count)];
  if (input.tag !== undefined) {
    if (typeof input.tag !== 'string' || !TAG_RE.test(input.tag)) throw new BridgeInputError('tag has characters that are not allowed');
    args.push('-s', input.tag);
  }
  const r = await runTool(n.det.path!, args, { timeoutMs: int(input.timeoutMs, 60_000, 2000, 600_000), maxOutputBytes: 16 * 1024 * 1024 });
  if (r.code !== 0) return { ...head('adb', n.det), ok: false, error: describeFailure(r) };
  const ls = lines(r.stdout).filter((l) => l.trim()).slice(-count).map((l) => l.slice(0, 4000));
  return { ...head('adb', n.det), ok: true, count: ls.length, lines: ls };
}

// ---------------- IDA ----------------

const IDA_SEL_RE = /^(0x[0-9a-fA-F]{1,16}|[A-Za-z_.$?@][\w.$?@:]{0,511})$/;

/**
 * Run IDA (idat) in batch mode with the RevLens IDAPython script: list functions or decompile
 * selected ones with Hex-Rays when licensed. The input is copied to a temp folder so IDA's
 * database files never land next to the original.
 */
export async function idaRun(input: { path: string; mode?: 'functions' | 'decompile'; functions?: string[]; limit?: number; offset?: number; timeoutMs?: number }) {
  const { path } = requireFile(input.path);
  const n = await need('ida');
  if ('missing' in n) return n.missing;
  const mode = input.mode ?? 'functions';
  const selectors = (input.functions ?? []).slice(0, 64);
  for (const s of selectors) if (typeof s !== 'string' || !IDA_SEL_RE.test(s)) throw new BridgeInputError(`bad function selector ${JSON.stringify(s)}`);
  if (mode === 'decompile' && selectors.length === 0) throw new BridgeInputError('functions is required for decompile');
  return withTempDir(async (dir) => {
    const input2 = join(dir, 'input.bin');
    await copyFile(path, input2);
    const script = join(dir, 'revlens_ida.py');
    await writeFile(script, IDA_EXPORT_SCRIPT, 'utf8');
    const out = join(dir, 'out.json');
    const env = { ...process.env, REVLENS_IDA_ARGS: JSON.stringify({ out, mode, limit: int(input.limit, 500, 0, 100_000), offset: int(input.offset, 0, 0, 1e9), selectors }), TVHEADLESS: '1' };
    const quoted = /\s/.test(script) ? `"${script}"` : script;
    const r = await runTool(n.det.path!, ['-A', `-L${join(dir, 'ida.log')}`, `-S${quoted}`, input2], { timeoutMs: int(input.timeoutMs, 15 * 60_000, 10_000, 7_200_000), env, cwd: dir, maxOutputBytes: 16 * 1024 * 1024 });
    if (!existsSync(out)) {
      const log = existsSync(join(dir, 'ida.log')) ? (await readFile(join(dir, 'ida.log'), 'utf8')).slice(-3000) : '';
      return { ...head('ida', n.det, path), ok: false, error: `IDA produced no output (${describeFailure(r)})${log ? `\n${log}` : ''}` };
    }
    const data = extractJson(await readFile(out, 'utf8'));
    return { ...head('ida', n.det, path), ok: !!data, result: data ?? null };
  });
}

// ---------------- Binary Ninja ----------------

/** Built-in headless script: lists functions with address, size and symbol type. Original code, MIT. */
export const BINJA_EXPORT_SCRIPT = String.raw`# RevLens Binary Ninja headless export. Original code, MIT licensed, part of @revlens/bridges.
import json, os, sys
import binaryninja
args = json.loads(os.environ.get("REVLENS_BN_ARGS", "{}"))
limit = max(0, min(int(args.get("limit", 500)), 100000))
offset = max(0, int(args.get("offset", 0)))
with binaryninja.load(args["path"], update_analysis=True) as bv:
    fns = list(bv.functions)
    res = {"schema": "revlens/binja-export@1", "arch": str(bv.arch), "platform": str(bv.platform), "start": "0x%x" % bv.start,
           "functionCount": len(fns),
           "functions": [{"name": f.name, "address": "0x%x" % f.start, "size": f.total_bytes, "symbolType": str(f.symbol.type)} for f in fns[offset:offset + limit]]}
with open(args["out"], "w", encoding="utf-8") as fh:
    json.dump(res, fh)
`;

/** List functions with Binary Ninja's headless Python API. Needs a license that allows headless use. */
export async function binjaFunctions(input: { path: string; python?: string; limit?: number; offset?: number; timeoutMs?: number }) {
  const { path } = requireFile(input.path);
  const n = await need('binja');
  if ('missing' in n) return n.missing;
  const pyPath = String(n.det.details?.pythonPath ?? '');
  const py = typeof input.python === 'string' && input.python ? requireFile(input.python, 'python').path : process.platform === 'win32' ? 'python' : 'python3';
  return withTempDir(async (dir) => {
    const script = join(dir, 'revlens_binja.py');
    await writeFile(script, BINJA_EXPORT_SCRIPT, 'utf8');
    const out = join(dir, 'out.json');
    const env = { ...process.env, PYTHONPATH: pyPath + (process.env.PYTHONPATH ? (process.platform === 'win32' ? ';' : ':') + process.env.PYTHONPATH : ''),
      REVLENS_BN_ARGS: JSON.stringify({ path, out, limit: int(input.limit, 500, 0, 100_000), offset: int(input.offset, 0, 0, 1e9) }) };
    const r = await runTool(py, [script], { timeoutMs: int(input.timeoutMs, 15 * 60_000, 10_000, 7_200_000), env, cwd: dir });
    if (!existsSync(out)) {
      const lic = /license/i.test(r.stderr) ? ' Binary Ninja headless use needs a Commercial or Ultimate license.' : '';
      return { ...head('binja', n.det, path), ok: false, error: `Binary Ninja produced no output (${describeFailure(r)}).${lic}` };
    }
    return { ...head('binja', n.det, path), ok: true, result: extractJson(await readFile(out, 'utf8')) ?? null };
  });
}
