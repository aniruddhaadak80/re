// radare2 and rizin bridge: analysis, functions, disassembly, decompilation, xrefs, strings, imports.
import { copyFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { describeFailure, runTool, withTempDir } from '../exec.js';
import { page } from '../parsers/common.js';
import {
  parseR2Decompile, parseR2Disasm, parseR2Functions, parseR2Imports, parseR2Info, parseR2Strings, parseR2Xrefs,
  type R2Function,
} from '../parsers/r2.js';
import type { Detection, Unavailable } from '../types.js';
import { BridgeInputError, int, need, requireFile, unavailable } from './common.js';

export type R2Engine = 'radare2' | 'rizin' | 'auto';
export type R2Analysis = 'none' | 'aa' | 'aaa';

export interface R2BaseInput {
  /** file to analyze */
  path: string;
  /** which tool to use, default auto (radare2 first, then rizin) */
  engine?: R2Engine;
  /** analysis depth before the query, default aa */
  analysis?: R2Analysis;
  timeoutMs?: number;
}

/** Separator echoed between commands. No `@`, `~`, `|` or `>`, which r2 would treat as operators. */
const SEP = '__RVLN_SEP_7F3A__';
/** Function names or addresses. No spaces, quotes, `;`, `!`, `|`, `>`, `<`, `` ` ``, `~` or `@`, so nothing can chain r2 commands. */
const TARGET_RE = /^(0x[0-9a-fA-F]{1,16}|[A-Za-z_.$][\w.$:-]{0,511})$/;

export function checkR2Target(t: unknown): string {
  if (typeof t !== 'string' || !TARGET_RE.test(t)) throw new BridgeInputError('function must be a 0x address or a symbol name made of letters, digits, _ . $ : -');
  return t;
}

async function pickEngine(engine: R2Engine | undefined): Promise<{ det: Detection; id: 'radare2' | 'rizin' } | Unavailable> {
  const order: ('radare2' | 'rizin')[] = engine === 'rizin' ? ['rizin'] : engine === 'radare2' ? ['radare2'] : ['radare2', 'rizin'];
  for (const id of order) {
    const r = await need(id);
    if ('det' in r) return { det: r.det, id };
  }
  return unavailable(order[0]!, engine === 'auto' || !engine ? 'Neither radare2 nor rizin was found.' : undefined);
}

function analysisCmd(a: R2Analysis | undefined): string[] {
  if (a === 'none') return [];
  if (a === 'aaa') return ['aaa'];
  return ['aa'];
}

/**
 * Run a list of r2/rizin commands in one session and return each command's output.
 * The commands are fixed strings built by this module; targets pass TARGET_RE first.
 * r2 runs with cfg.sandbox=true (no shell, no file writes) and -N (no user rc scripts).
 */
export async function r2Batch(det: Detection, id: 'radare2' | 'rizin', file: string, analysis: R2Analysis | undefined, cmds: string[], timeoutMs?: number):
  Promise<{ parts: string[]; error?: string; durationMs: number }> {
  const script = [...analysisCmd(analysis)];
  cmds.forEach((c, i) => {
    if (i > 0) script.push(`?e ${SEP}`);
    script.push(c);
  });
  // cfg.sandbox only lets r2 open a plain relative name below its working folder, so run from the
  // file's folder. Names that could be read as options or URIs are copied to a safe name first.
  const name = basename(file);
  const plain = /^[A-Za-z0-9_][\w.+-]{0,200}$/.test(name);
  const go = async (cwd: string, target: string) => {
    const args = ['-2', '-q', '-N', '-e', 'scr.color=0', '-e', 'scr.interactive=false', '-e', 'cfg.sandbox=true', '-e', 'bin.relocs.apply=true',
      '-c', script.join(';'), target];
    return runTool(det.path!, args, { timeoutMs: timeoutMs ?? 180_000, maxOutputBytes: 64 * 1024 * 1024, cwd });
  };
  const r = plain ? await go(dirname(file), name) : await withTempDir(async (tmp) => {
    await copyFile(file, join(tmp, 'input.bin'));
    return go(tmp, 'input.bin');
  });
  const ok = !r.error && !r.timedOut && (r.code === 0 || r.stdout.length > 0);
  const parts = r.stdout.split(SEP).map((p) => p.replace(/^\r?\n/, ''));
  return { parts, durationMs: r.durationMs, ...(ok ? {} : { error: describeFailure(r) }) };
}

function header(det: Detection, id: string, file: string) {
  return { available: true as const, tool: id, toolVersion: det.version ?? null, file };
}

/** List functions found by radare2 or rizin, with paging and an optional substring filter. */
export async function r2Functions(input: R2BaseInput & { limit?: number; offset?: number; filter?: string }) {
  const { path } = requireFile(input.path);
  const eng = await pickEngine(input.engine);
  if ('available' in eng) return eng;
  const res = await r2Batch(eng.det, eng.id, path, input.analysis, ['aflj'], input.timeoutMs);
  if (res.error && !res.parts[0]?.trim()) return { ...header(eng.det, eng.id, path), ok: false, error: res.error };
  let fns = parseR2Functions(res.parts[0] ?? '');
  const filter = typeof input.filter === 'string' ? input.filter.toLowerCase().slice(0, 256) : '';
  if (filter) fns = fns.filter((f) => f.name.toLowerCase().includes(filter));
  const pg = page(fns, int(input.offset, 0, 0, 1e9), int(input.limit, 200, 0, 10_000));
  return { ...header(eng.det, eng.id, path), ok: true, analysis: input.analysis ?? 'aa', total: pg.total, offset: pg.offset, limit: pg.limit, more: pg.more, functions: pg.items };
}

/** Candidate r2 flag names for a user supplied function name. */
function candidates(t: string): string[] {
  if (t.startsWith('0x')) return [t];
  const out = [t];
  if (!/^(sym|fcn|imp|loc|entry|main|sub)\b/.test(t)) out.push(`sym.${t}`, `sym.imp.${t}`, `fcn.${t}`);
  return out;
}

async function resolveTarget(det: Detection, id: 'radare2' | 'rizin', file: string, input: R2BaseInput & { function?: string; address?: string }):
  Promise<{ target: string; fn?: R2Function } | { error: string }> {
  const raw = checkR2Target(input.function ?? input.address);
  const res = await r2Batch(det, id, file, input.analysis, ['aflj'], input.timeoutMs);
  const fns = parseR2Functions(res.parts[0] ?? '');
  if (raw.startsWith('0x')) {
    const a = parseInt(raw, 16);
    const fn = fns.find((f) => { const s = parseInt(f.address, 16); return a >= s && a < s + Math.max(1, f.size); });
    return { target: raw.toLowerCase(), ...(fn ? { fn } : {}) };
  }
  for (const c of candidates(raw)) {
    const fn = fns.find((f) => f.name === c);
    if (fn) return { target: fn.address, fn };
  }
  const loose = fns.filter((f) => f.name.endsWith('.' + raw));
  if (loose.length === 1) return { target: loose[0]!.address, fn: loose[0]! };
  const near = fns.filter((f) => f.name.toLowerCase().includes(raw.toLowerCase())).slice(0, 10).map((f) => `${f.name} ${f.address}`);
  return { error: `function "${raw}" not found${near.length ? `; close matches: ${near.join(', ')}` : ''}` };
}

/** Disassemble one function (pdfj), or N instructions at an address when it is not inside a known function. */
export async function r2Disasm(input: R2BaseInput & { function?: string; address?: string; maxInstructions?: number }) {
  const { path } = requireFile(input.path);
  const eng = await pickEngine(input.engine);
  if ('available' in eng) return eng;
  const t = await resolveTarget(eng.det, eng.id, path, input);
  if ('error' in t) return { ...header(eng.det, eng.id, path), ok: false, error: t.error };
  const max = int(input.maxInstructions, 2000, 1, 20_000);
  const cmd = t.fn ? `pdfj @ ${t.target}` : `pdj ${max} @ ${t.target}`;
  const res = await r2Batch(eng.det, eng.id, path, input.analysis, [cmd], input.timeoutMs);
  const dis = parseR2Disasm(res.parts[0] ?? '');
  if (dis.instructions.length === 0) return { ...header(eng.det, eng.id, path), ok: false, error: res.error ?? `no instructions at ${t.target}` };
  return {
    ...header(eng.det, eng.id, path), ok: true,
    function: t.fn ? { name: t.fn.name, address: t.fn.address, size: t.fn.size } : null,
    address: t.target,
    instructionCount: Math.min(dis.instructions.length, max),
    truncated: dis.instructions.length > max,
    instructions: dis.instructions.slice(0, max),
  };
}

/** Decompile one function with r2ghidra / rz-ghidra (pdg) when installed, else radare2's pseudo code (pdc). */
export async function r2Decompile(input: R2BaseInput & { function?: string; address?: string; maxChars?: number }) {
  const { path } = requireFile(input.path);
  const eng = await pickEngine(input.engine);
  if ('available' in eng) return eng;
  const t = await resolveTarget(eng.det, eng.id, path, input);
  if ('error' in t) return { ...header(eng.det, eng.id, path), ok: false, error: t.error };
  const maxChars = int(input.maxChars, 200_000, 1000, 4_000_000);
  const fnInfo = t.fn ? { name: t.fn.name, address: t.fn.address, size: t.fn.size } : { address: t.target };
  if (eng.det.details?.ghidraPlugin === true) {
    const res = await r2Batch(eng.det, eng.id, path, input.analysis, [`pdgj @ ${t.target}`], input.timeoutMs);
    const code = parseR2Decompile(res.parts[0] ?? '');
    if (code) {
      return { ...header(eng.det, eng.id, path), ok: true, decompiler: eng.id === 'rizin' ? 'rz-ghidra' : 'r2ghidra',
        function: fnInfo, truncated: code.length > maxChars, code: code.slice(0, maxChars) };
    }
  }
  if (eng.id === 'radare2') {
    const res = await r2Batch(eng.det, eng.id, path, input.analysis, [`pdc @ ${t.target}`], input.timeoutMs);
    const code = (res.parts[0] ?? '').trim();
    if (code) {
      return { ...header(eng.det, eng.id, path), ok: true, decompiler: 'pdc',
        note: 'r2ghidra is not installed, this is radare2 pseudo code. Install it with: r2pm -ci r2ghidra',
        function: fnInfo, truncated: code.length > maxChars, code: code.slice(0, maxChars) };
    }
    return { ...header(eng.det, eng.id, path), ok: false, error: res.error ?? 'decompiler produced no output' };
  }
  return { ...header(eng.det, eng.id, path), ok: false, error: 'rz-ghidra is not installed. Install it with: rz-pm install rz-ghidra' };
}

/** Cross references to a function or address (axtj). */
export async function r2Xrefs(input: R2BaseInput & { function?: string; address?: string }) {
  const { path } = requireFile(input.path);
  const eng = await pickEngine(input.engine);
  if ('available' in eng) return eng;
  const t = await resolveTarget(eng.det, eng.id, path, input);
  if ('error' in t) return { ...header(eng.det, eng.id, path), ok: false, error: t.error };
  const res = await r2Batch(eng.det, eng.id, path, input.analysis === 'none' ? 'aa' : input.analysis, [`axtj @ ${t.target}`], input.timeoutMs);
  const xrefs = parseR2Xrefs(res.parts[0] ?? '');
  return { ...header(eng.det, eng.id, path), ok: true, target: t.target, function: t.fn?.name ?? null, count: xrefs.length, xrefs: xrefs.slice(0, 5000) };
}

/** Strings from data sections (izj), paged. */
export async function r2Strings(input: R2BaseInput & { limit?: number; offset?: number; minLength?: number }) {
  const { path } = requireFile(input.path);
  const eng = await pickEngine(input.engine);
  if ('available' in eng) return eng;
  const res = await r2Batch(eng.det, eng.id, path, 'none', ['izj'], input.timeoutMs);
  const min = int(input.minLength, 4, 1, 1000);
  const all = parseR2Strings(res.parts[0] ?? '').filter((s) => s.value.length >= min);
  const pg = page(all, int(input.offset, 0, 0, 1e9), int(input.limit, 500, 0, 10_000));
  return { ...header(eng.det, eng.id, path), ok: true, total: pg.total, offset: pg.offset, limit: pg.limit, more: pg.more, strings: pg.items };
}

/** Imports (iij) and binary info (ij). */
export async function r2Info(input: R2BaseInput) {
  const { path } = requireFile(input.path);
  const eng = await pickEngine(input.engine);
  if ('available' in eng) return eng;
  const res = await r2Batch(eng.det, eng.id, path, 'none', ['ij', 'iij'], input.timeoutMs);
  if (res.error && !res.parts[0]?.trim()) return { ...header(eng.det, eng.id, path), ok: false, error: res.error };
  return { ...header(eng.det, eng.id, path), ok: true, info: parseR2Info(res.parts[0] ?? ''), imports: parseR2Imports(res.parts[1] ?? '').slice(0, 5000) };
}
