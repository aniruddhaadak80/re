// Parsers for frida-ps --json, frida-ls-devices tables, and RevLens hook script output lines.
import { extractJson, lines, num, str, PARSE_LIMITS } from './common.js';

export interface FridaProcess {
  pid: number;
  name: string;
  identifier?: string;
}

export interface FridaDevice {
  id: string;
  type: string;
  name: string;
  os?: string;
}

export interface FridaEvent {
  /** milliseconds since the session started, as reported by the hook script */
  t?: number;
  type: string;
  [k: string]: unknown;
}

/** RevLens hook templates print one JSON object per line after this prefix. */
export const FRIDA_EVENT_PREFIX = '@@revlens ';

/** Parse `frida-ps --json` (optionally with -a / -i, which add `identifier`). */
export function parseFridaPs(input: string | unknown): FridaProcess[] {
  const data = typeof input === 'string' ? extractJson(input) : input;
  if (!Array.isArray(data)) return [];
  const out: FridaProcess[] = [];
  for (const it of data.slice(0, PARSE_LIMITS.maxItems)) {
    const o = (it && typeof it === 'object' ? it : {}) as Record<string, unknown>;
    const pid = num(o.pid);
    const name = str(o.name, 1024);
    if (pid === undefined || name === undefined) continue;
    const p: FridaProcess = { pid, name };
    const id = str(o.identifier, 1024); if (id) p.identifier = id;
    out.push(p);
  }
  return out;
}

/**
 * Parse the `frida-ls-devices` table. Columns are located from the dashed rule line so names with
 * spaces survive.
 */
export function parseFridaDevices(text: string): FridaDevice[] {
  const ls = lines(text, 10_000);
  const ruleIdx = ls.findIndex((l) => /^-+(\s+-+)+\s*$/.test(l));
  if (ruleIdx < 1) return [];
  const rule = ls[ruleIdx]!;
  const cols: [number, number][] = [];
  const re = /-+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rule)) && cols.length < 8) cols.push([m.index, m.index + m[0].length]);
  const header = ls[ruleIdx - 1]!;
  const names = cols.map(([a], i) => header.slice(a, i + 1 < cols.length ? cols[i + 1]![0] : undefined).trim().toLowerCase());
  const out: FridaDevice[] = [];
  for (const l of ls.slice(ruleIdx + 1)) {
    if (!l.trim()) continue;
    const vals = cols.map(([a], i) => l.slice(a, i + 1 < cols.length ? cols[i + 1]![0] : undefined).trim());
    const get = (k: string) => vals[names.indexOf(k)] ?? '';
    const d: FridaDevice = { id: get('id'), type: get('type'), name: get('name') };
    const os = get('os'); if (os) d.os = os;
    if (d.id) out.push(d);
  }
  return out;
}

/** Split frida CLI output into RevLens events, plain log lines and error lines. */
export function parseFridaOutput(text: string, maxEvents = 5000): { events: FridaEvent[]; logs: string[]; errors: string[]; dropped: number } {
  const events: FridaEvent[] = [];
  const logs: string[] = [];
  const errors: string[] = [];
  let dropped = 0;
  for (const raw of lines(text)) {
    const l = raw.slice(0, 65536).trimEnd();
    const i = l.indexOf(FRIDA_EVENT_PREFIX);
    if (i >= 0) {
      if (events.length >= maxEvents) { dropped++; continue; }
      try {
        const v = JSON.parse(l.slice(i + FRIDA_EVENT_PREFIX.length)) as unknown;
        if (v && typeof v === 'object' && !Array.isArray(v) && typeof (v as FridaEvent).type === 'string') events.push(v as FridaEvent);
        else logs.push(l.slice(0, 2000));
      } catch {
        logs.push(l.slice(0, 2000));
      }
      continue;
    }
    if (!l.trim()) continue;
    if (/^(Error|Failed to|\{"type":"error"|TypeError|ReferenceError)|Process terminated|Unable to/.test(l)) {
      if (errors.length < 200) errors.push(l.slice(0, 2000));
    } else if (logs.length < 2000) logs.push(l.slice(0, 2000));
  }
  return { events, logs, errors, dropped };
}
