// Parsers for gdb and lldb batch output. RevLens prints a marker line before each stop so the
// output can be split into stops reliably: "@@REVLENS_STOP <n>".
import { lines, PARSE_LIMITS } from './common.js';

export interface DebugFrame {
  index: number;
  address?: string;
  function: string;
  location?: string;
}

export interface DebugMemoryLine {
  address: string;
  values: string[];
}

export interface DebugStop {
  index: number;
  /** breakpoint number or signal name when known */
  reason?: string;
  pc?: string;
  function?: string;
  registers: Record<string, string>;
  backtrace: DebugFrame[];
  memory: DebugMemoryLine[];
}

export interface DebugSession {
  stops: DebugStop[];
  exitCode?: number;
  signal?: string;
  /** lines that did not belong to any stop, kept short for context */
  notes: string[];
}

export const STOP_MARKER = '@@REVLENS_STOP';

const RE_GDB_REG = /^([a-z][a-z0-9_]{0,15})\s+(0x[0-9a-f]{1,32}|-?[0-9]{1,40})\s+(.{0,200})$/;
const RE_LLDB_REG = /^\s{0,8}([a-z][a-z0-9_]{0,15}) = (0x[0-9a-f]{1,32})(?:\s.{0,200})?$/;
const RE_GDB_FRAME = /^#(\d{1,5})\s+(?:(0x[0-9a-f]{1,16}) in )?([^\s(]{1,1024}) \((.{0,2048}?)\)(?: (?:at|from) (.{1,2048}))?$/;
const RE_LLDB_FRAME = /^\s*\*?\s*frame #(\d{1,5}): (0x[0-9a-f]{1,16}) ([^`\s]{1,1024})`([^\s+]{1,1024})(.{0,2048})$/;
const RE_MEM = /^(0x[0-9a-f]{1,16})(?: <[^>]{0,512}>)?:\s+(.{1,2048})$/;

function newStop(index: number): DebugStop {
  return { index, registers: {}, backtrace: [], memory: [] };
}

/** Parse gdb batch output produced by `gdbRun`. */
export function parseGdbBatch(text: string): DebugSession {
  const session: DebugSession = { stops: [], notes: [] };
  let cur: DebugStop | undefined;
  // gdbRun prints a marker after each stop and before the commands that inspect it.
  // Data after a marker belongs to the stop seen since the previous marker, if any.
  let stopSinceMarker = false;
  for (const raw of lines(text)) {
    const l = raw.slice(0, 8192).trimEnd();
    if (l.startsWith(STOP_MARKER)) {
      cur = stopSinceMarker ? session.stops[session.stops.length - 1] : undefined;
      stopSinceMarker = false;
      continue;
    }
    const bp = /^(?:Thread \S+ .{0,200} hit )?Breakpoint (\d{1,6}), (?:(0x[0-9a-f]{1,16}) in )?([^\s(]{1,1024})/.exec(l);
    if (bp) {
      if (session.stops.length >= 1000) break;
      cur = newStop(session.stops.length);
      cur.reason = `breakpoint ${bp[1]}`;
      if (bp[2]) cur.pc = bp[2];
      cur.function = bp[3]!;
      session.stops.push(cur);
      stopSinceMarker = true;
      continue;
    }
    const sig = /^Program received signal (SIG[A-Z0-9]{1,16})/.exec(l);
    if (sig) {
      cur = newStop(session.stops.length);
      cur.reason = sig[1]!;
      session.stops.push(cur);
      stopSinceMarker = true;
      continue;
    }
    const ex = /^\[Inferior \d+ \(process \d+\) exited (?:normally|with code (\d{1,3}))\]/.exec(l);
    if (ex) { session.exitCode = ex[1] ? parseInt(ex[1], 8) : 0; cur = undefined; continue; }
    const term = /^Program terminated with signal (SIG[A-Z0-9]{1,16})/.exec(l);
    if (term) { session.signal = term[1]!; cur = undefined; continue; }
    if (cur) {
      const reg = RE_GDB_REG.exec(l);
      if (reg && Object.keys(cur.registers).length < 512) {
        cur.registers[reg[1]!] = reg[2]!;
        if ((reg[1] === 'pc' || reg[1] === 'rip' || reg[1] === 'eip') && !cur.pc) cur.pc = reg[2]!;
        continue;
      }
      const fr = RE_GDB_FRAME.exec(l);
      if (fr && cur.backtrace.length < 256) {
        const f: DebugFrame = { index: Number(fr[1]), function: fr[3]! };
        if (fr[2]) f.address = fr[2];
        if (fr[5]) f.location = fr[5];
        cur.backtrace.push(f);
        continue;
      }
      const mem = RE_MEM.exec(l);
      if (mem && cur.memory.length < 4096) {
        cur.memory.push({ address: mem[1]!, values: mem[2]!.trim().split(/\s+/).slice(0, 64) });
        continue;
      }
    }
    if (l && session.notes.length < 40 && !/^(Breakpoint \d+ at|Kill the program|\[Inferior \d+ \(process \d+\) killed\])/.test(l)) {
      session.notes.push(l.slice(0, 300));
    }
  }
  return session;
}

/** Parse lldb batch output produced by `lldbRun`. */
export function parseLldbBatch(text: string): DebugSession {
  const session: DebugSession = { stops: [], notes: [] };
  let cur: DebugStop | undefined;
  let count = 0;
  // lldb repeats the "stop reason" thread line in every backtrace, so a stop only starts after "Process N stopped".
  let pending = false;
  for (const raw of lines(text)) {
    if (++count > PARSE_LIMITS.maxLines) break;
    const l = raw.slice(0, 8192).trimEnd();
    if (/^Process \d+ stopped$/.test(l)) { pending = true; continue; }
    const stop = pending ? /stop reason = (.{1,200})$/.exec(l) : null;
    if (stop) {
      pending = false;
      if (session.stops.length >= 1000) break;
      cur = newStop(session.stops.length);
      cur.reason = stop[1]!.trim();
      session.stops.push(cur);
      continue;
    }
    const ex = /^Process \d+ exited with status = (-?\d{1,4})/.exec(l);
    if (ex) { session.exitCode = Number(ex[1]); cur = undefined; continue; }
    if (!cur) { if (l && session.notes.length < 40) session.notes.push(l.slice(0, 300)); continue; }
    const fr = RE_LLDB_FRAME.exec(l);
    if (fr) {
      const f: DebugFrame = { index: Number(fr[1]), address: fr[2]!, function: fr[4]!, location: fr[3]! };
      // The stop header repeats frame #0; keep one entry per frame index.
      if (cur.backtrace.length < 256 && !cur.backtrace.some((b) => b.index === f.index)) cur.backtrace.push(f);
      if (f.index === 0 && !cur.pc) { cur.pc = f.address; cur.function = f.function; }
      continue;
    }
    const reg = RE_LLDB_REG.exec(l);
    if (reg && Object.keys(cur.registers).length < 512) {
      cur.registers[reg[1]!] = reg[2]!;
      continue;
    }
    const mem = RE_MEM.exec(l);
    if (mem && cur.memory.length < 4096) cur.memory.push({ address: mem[1]!, values: mem[2]!.trim().split(/\s+/).slice(0, 64) });
  }
  return session;
}
