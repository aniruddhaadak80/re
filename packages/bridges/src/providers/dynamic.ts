// Dynamic analysis bridges: Frida (processes, devices, attach or spawn with hook templates) and
// gdb or lldb in batch mode (breakpoints, registers, backtraces, memory). Node only.
// Everything that starts or touches a live process needs allowExecution: true.
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describeFailure, runTool, withTempDir } from '../exec.js';
import { buildHookScript, HOOK_TEMPLATES, HookParamError, type HookTemplateId } from '../hooks.js';
import { parseGdbBatch, parseLldbBatch, STOP_MARKER, type DebugSession } from '../parsers/debugger.js';
import { parseFridaDevices, parseFridaOutput, parseFridaPs } from '../parsers/frida.js';
import type { Detection } from '../types.js';
import { BridgeInputError, int, need, requireExecution, requireFile } from './common.js';

// ---------------- shared input checks ----------------

/** Frida device selector: usb, remote, or a device id from frida-ls-devices. */
const DEVICE_RE = /^[\w.:@-]{1,128}$/;
/** Process names for attach by name. */
const PROC_NAME_RE = /^[\w .+@-]{1,255}$/;
/** gdb and lldb breakpoint locations: a symbol, or *0xADDR / 0xADDR. */
const BREAK_RE = /^(\*?0x[0-9a-fA-F]{1,16}|[A-Za-z_.$][\w.$:]{0,255})$/;
/** Register names. */
const REG_RE = /^[a-z][a-z0-9_]{0,15}$/;
/** Memory dump base: a register like $sp or a hex address. */
const MEM_BASE_RE = /^(\$[a-z][a-z0-9_]{0,15}|0x[0-9a-fA-F]{1,16})$/;
/** Program arguments may not start with a dash for the debugger itself; they are passed after --. */
const MAX_PROGRAM_ARGS = 64;

function deviceArgs(device: unknown): string[] {
  if (device === undefined || device === null || device === '' || device === 'local') return [];
  if (typeof device !== 'string' || !DEVICE_RE.test(device)) throw new BridgeInputError('device must be usb, remote, local or a device id');
  if (device === 'usb') return ['-U'];
  if (device === 'remote') return ['-R'];
  return ['-D', device];
}

function programArgs(a: unknown): string[] {
  if (a === undefined) return [];
  if (!Array.isArray(a) || a.length > MAX_PROGRAM_ARGS || !a.every((x) => typeof x === 'string' && x.length <= 4096 && !x.includes('\0') && !/[\r\n]/.test(x))) {
    throw new BridgeInputError(`args must be an array of up to ${MAX_PROGRAM_ARGS} strings without newlines`);
  }
  return a as string[];
}

function head(tool: string, det: Detection) {
  return { available: true as const, tool, toolVersion: det.version ?? null };
}

function sibling(det: Detection, key: 'fridaPs' | 'fridaLsDevices'): string | undefined {
  const p = det.details?.[key];
  return typeof p === 'string' ? p : undefined;
}

// ---------------- Frida ----------------

/** List processes (or installed apps with `applications: true`) on a Frida device. Read only. */
export async function fridaPs(input: { device?: string; applications?: boolean; limit?: number; filter?: string; timeoutMs?: number } = {}) {
  const n = await need('frida');
  if ('missing' in n) return n.missing;
  const exe = sibling(n.det, 'fridaPs');
  if (!exe) return { ...head('frida', n.det), ok: false, error: 'frida-ps was not found next to frida' };
  const args = ['--json', ...(input.applications ? ['-a', '-i'] : []), ...deviceArgs(input.device)];
  const r = await runTool(exe, args, { timeoutMs: int(input.timeoutMs, 30_000, 2000, 300_000), maxOutputBytes: 16 * 1024 * 1024 });
  let procs = parseFridaPs(r.stdout);
  if (procs.length === 0 && r.code !== 0) return { ...head('frida', n.det), ok: false, error: describeFailure(r) };
  const f = typeof input.filter === 'string' ? input.filter.toLowerCase().slice(0, 256) : '';
  if (f) procs = procs.filter((p) => p.name.toLowerCase().includes(f) || (p.identifier ?? '').toLowerCase().includes(f));
  procs.sort((a, b) => a.pid - b.pid);
  const limit = int(input.limit, 500, 1, 20_000);
  return { ...head('frida', n.det), ok: true, device: input.device ?? 'local', total: procs.length, more: procs.length > limit, processes: procs.slice(0, limit) };
}

/** List Frida devices (local, USB, remote). Read only. */
export async function fridaDevices(input: { timeoutMs?: number } = {}) {
  const n = await need('frida');
  if ('missing' in n) return n.missing;
  const exe = sibling(n.det, 'fridaLsDevices');
  if (!exe) return { ...head('frida', n.det), ok: false, error: 'frida-ls-devices was not found next to frida' };
  const r = await runTool(exe, [], { timeoutMs: int(input.timeoutMs, 30_000, 2000, 300_000), maxOutputBytes: 1024 * 1024 });
  const devices = parseFridaDevices(r.stdout);
  if (devices.length === 0 && r.code !== 0) return { ...head('frida', n.det), ok: false, error: describeFailure(r) };
  return { ...head('frida', n.det), ok: true, devices };
}

export interface FridaRunInput {
  /** hook template id, see HOOK_TEMPLATES */
  template: HookTemplateId;
  params?: Record<string, unknown>;
  /** attach to this pid */
  pid?: number;
  /** attach to a process by name */
  name?: string;
  /** spawn this program (or Android package with a device) and instrument it from the start */
  spawn?: string;
  args?: string[];
  device?: string;
  /** how long to collect events, default 5 s, max 10 min */
  durationMs?: number;
  maxEvents?: number;
  /** required: this runs code inside a live process */
  allowExecution?: boolean;
}

/**
 * Inject a RevLens hook template into a process with the frida CLI and collect its events for a while.
 * Attach by pid or name, or spawn a program. The target keeps running after Frida detaches,
 * except spawned programs, which are killed on exit.
 */
export async function fridaRun(input: FridaRunInput) {
  const gate = requireExecution(input, 'Frida instrumentation');
  if (gate) return { available: true, tool: 'frida', ok: false, blocked: true, error: gate };
  const tpl = HOOK_TEMPLATES.find((t) => t.id === input.template);
  if (!tpl) throw new BridgeInputError(`template must be one of ${HOOK_TEMPLATES.map((t) => t.id).join(', ')}`);
  const n = await need('frida');
  if ('missing' in n) return n.missing;
  const maxEvents = int(input.maxEvents, 2000, 1, 100_000);
  let script: string;
  try { script = buildHookScript(tpl.id, input.params ?? {}, maxEvents); } catch (e) {
    if (e instanceof HookParamError) throw new BridgeInputError(e.message);
    throw e;
  }
  const targets = [input.pid !== undefined, input.name !== undefined, input.spawn !== undefined].filter(Boolean).length;
  if (targets !== 1) throw new BridgeInputError('give exactly one of pid, name or spawn');
  const target: string[] = [];
  let mode: 'attach' | 'spawn';
  if (input.pid !== undefined) {
    if (!Number.isSafeInteger(input.pid) || input.pid <= 0) throw new BridgeInputError('pid must be a positive integer');
    target.push('-p', String(input.pid)); mode = 'attach';
  } else if (input.name !== undefined) {
    if (typeof input.name !== 'string' || !PROC_NAME_RE.test(input.name) || input.name.startsWith('-')) throw new BridgeInputError('name has characters that are not allowed');
    target.push('-n', input.name); mode = 'attach';
  } else {
    const s = input.spawn!;
    if (typeof s !== 'string' || !s || s.startsWith('-') || s.includes('\0') || s.length > 4096) throw new BridgeInputError('spawn must be a program path or package name');
    const isLocal = deviceArgs(input.device).length === 0;
    const prog = isLocal ? requireFile(s, 'spawn').path : s;
    target.push('-f', prog, '--kill-on-exit');
    const extra = programArgs(input.args);
    if (extra.length && !isLocal) throw new BridgeInputError('args are only supported when spawning a local program');
    mode = 'spawn';
    if (extra.length) target.push('--', ...extra);
  }
  const durationMs = int(input.durationMs, 5000, 500, 600_000);
  return withTempDir(async (dir) => {
    const file = join(dir, 'revlens-hook.js');
    await writeFile(file, script, 'utf8');
    // -q quits after loading in quiet mode; -t keeps the session alive for the duration first.
    const dev = deviceArgs(input.device);
    const spawnTail = target.indexOf('--');
    const before = spawnTail >= 0 ? target.slice(0, spawnTail) : target;
    const after = spawnTail >= 0 ? target.slice(spawnTail) : [];
    const args = [...dev, '-q', '-t', String(Math.ceil(durationMs / 1000)), '-l', file, ...before, ...after];
    const r = await runTool(n.det.path!, args, { timeoutMs: durationMs + 60_000, maxOutputBytes: 32 * 1024 * 1024, cwd: dir });
    const parsed = parseFridaOutput(`${r.stdout}\n${r.stderr}`, maxEvents);
    const ok = parsed.events.length > 0 || (r.code === 0 && parsed.errors.length === 0);
    return {
      ...head('frida', n.det), ok, mode, template: tpl.id, durationMs: r.durationMs,
      eventCount: parsed.events.length, dropped: parsed.dropped, events: parsed.events,
      errors: parsed.errors.slice(0, 50), logs: parsed.logs.slice(0, 200),
      ...(ok ? {} : { error: parsed.errors[0] ?? describeFailure(r) }),
      ...(mode === 'spawn' && !ok && /ptrace|Operation not permitted|unable to access process/i.test(`${r.stderr}${r.stdout}`)
        ? { hint: 'Spawning needs ptrace. In containers run with --cap-add=SYS_PTRACE or attach to an already running process instead.' } : {}),
    };
  });
}

// ---------------- gdb and lldb ----------------

export interface DebugRunInput {
  /** program to run */
  path: string;
  args?: string[];
  /** symbols or 0x addresses */
  breakpoints: string[];
  /** register names to read at each stop; empty or omitted means all general registers */
  registers?: string[];
  /** frames per backtrace, default 16 */
  backtrace?: number;
  /** dump bytes at each stop, for example { base: '$sp', count: 32 } */
  memory?: { base: string; count?: number };
  /** stops to inspect before letting the program finish, default 8, max 64 */
  maxStops?: number;
  timeoutMs?: number;
  /** required: this runs the target program */
  allowExecution?: boolean;
}

interface DebugPlan { breakpoints: string[]; registers: string[]; bt: number; mem?: { base: string; count: number }; stops: number; args: string[] }

function planDebug(input: DebugRunInput): DebugPlan {
  const bps = Array.isArray(input.breakpoints) ? input.breakpoints : [];
  if (bps.length === 0 || bps.length > 64) throw new BridgeInputError('breakpoints must list 1 to 64 symbols or 0x addresses');
  for (const b of bps) if (typeof b !== 'string' || !BREAK_RE.test(b)) throw new BridgeInputError(`bad breakpoint ${JSON.stringify(b)}`);
  const regs = Array.isArray(input.registers) ? input.registers : [];
  if (regs.length > 128) throw new BridgeInputError('too many registers');
  for (const r of regs) if (typeof r !== 'string' || !REG_RE.test(r)) throw new BridgeInputError(`bad register ${JSON.stringify(r)}`);
  let mem: DebugPlan['mem'];
  if (input.memory) {
    if (typeof input.memory.base !== 'string' || !MEM_BASE_RE.test(input.memory.base)) throw new BridgeInputError('memory.base must be a $register or 0x address');
    mem = { base: input.memory.base, count: int(input.memory.count, 32, 1, 4096) };
  }
  return { breakpoints: bps, registers: regs, bt: int(input.backtrace, 16, 0, 256), mem, stops: int(input.maxStops, 8, 1, 64), args: programArgs(input.args) };
}

/** Build the gdb argument list. Exported for tests. */
export function gdbArgs(path: string, p: DebugPlan): string[] {
  const ex = (c: string) => ['-ex', c];
  const out = ['-nx', '-batch', ...ex('set pagination off'), ...ex('set confirm off'), ...ex('set width 0'), ...ex('set print pretty off')];
  for (const b of p.breakpoints) out.push(...ex(`break ${b.startsWith('0x') ? '*' + b : b}`));
  out.push(...ex('run'));
  for (let i = 0; i < p.stops; i++) {
    out.push(...ex(`echo ${STOP_MARKER} ${i}\\n`));
    out.push(...ex(p.registers.length ? `info registers ${p.registers.join(' ')}` : 'info registers'));
    if (p.bt > 0) out.push(...ex(`bt ${p.bt}`));
    if (p.mem) out.push(...ex(`x/${p.mem.count}xb ${p.mem.base}`));
    out.push(...ex('continue'));
  }
  out.push(...ex('kill'));
  out.push('--args', path, ...p.args);
  return out;
}

/** Build the lldb argument list. Exported for tests. */
export function lldbArgs(path: string, p: DebugPlan): string[] {
  const o = (c: string) => ['-o', c];
  const out = ['--batch', '--no-lldbinit'];
  for (const b of p.breakpoints) {
    const addr = b.replace(/^\*/, '');
    out.push(...o(addr.startsWith('0x') ? `breakpoint set -a ${addr}` : `breakpoint set -n ${b}`));
  }
  // Program arguments go after `--` on lldb's own command line, so lldb never parses them as commands.
  out.push(...o('process launch'));
  for (let i = 0; i < p.stops; i++) {
    out.push(...o(p.registers.length ? `register read ${p.registers.join(' ')}` : 'register read'));
    if (p.bt > 0) out.push(...o(`bt ${p.bt}`));
    if (p.mem) out.push(...o(`memory read -s1 -fx -c${p.mem.count} ${p.mem.base}`));
    out.push(...o('process continue'));
  }
  out.push('--', path, ...p.args);
  return out;
}

function summarize(s: DebugSession) {
  return { stopCount: s.stops.length, stops: s.stops, exitCode: s.exitCode ?? null, signal: s.signal ?? null, notes: s.notes };
}

/** Run a program under gdb in batch mode and report registers, backtrace and memory at each breakpoint. */
export async function gdbRun(input: DebugRunInput) {
  const gate = requireExecution(input, 'gdb');
  if (gate) return { available: true, tool: 'gdb', ok: false, blocked: true, error: gate };
  const { path } = requireFile(input.path);
  const plan = planDebug(input);
  const n = await need('gdb');
  if ('missing' in n) return n.missing;
  const r = await runTool(n.det.path!, gdbArgs(path, plan), { timeoutMs: int(input.timeoutMs, 60_000, 2000, 3_600_000), maxOutputBytes: 16 * 1024 * 1024 });
  const s = parseGdbBatch(`${r.stdout}\n${r.stderr}`);
  const ok = !r.error && !r.timedOut;
  return { ...head('gdb', n.det), file: path, ok, ...summarize(s), timedOut: r.timedOut, ...(ok ? {} : { error: describeFailure(r) }) };
}

/** Run a program under lldb in batch mode (the gdb alternative, default on macOS). */
export async function lldbRun(input: DebugRunInput) {
  const gate = requireExecution(input, 'lldb');
  if (gate) return { available: true, tool: 'lldb', ok: false, blocked: true, error: gate };
  const { path } = requireFile(input.path);
  const plan = planDebug(input);
  const n = await need('lldb');
  if ('missing' in n) return n.missing;
  const r = await runTool(n.det.path!, lldbArgs(path, plan), { timeoutMs: int(input.timeoutMs, 60_000, 2000, 3_600_000), maxOutputBytes: 16 * 1024 * 1024 });
  const s = parseLldbBatch(`${r.stdout}\n${r.stderr}`);
  const ok = !r.error && !r.timedOut;
  return { ...head('lldb', n.det), file: path, ok, ...summarize(s), timedOut: r.timedOut, ...(ok ? {} : { error: describeFailure(r) }) };
}

/** Use gdb when present, else lldb. */
export async function debugRun(input: DebugRunInput & { debugger?: 'gdb' | 'lldb' | 'auto' }) {
  if (input.debugger === 'lldb') return lldbRun(input);
  if (input.debugger === 'gdb') return gdbRun(input);
  const g = await need('gdb');
  return 'det' in g ? gdbRun(input) : lldbRun(input);
}
