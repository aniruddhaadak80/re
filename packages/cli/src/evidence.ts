// Per command evidence bundles (--evidence-out) and their import (evidence-import).
//
// A bundle records what ran and what it saw: the command and its arguments, start and end time,
// exit code, the SHA-256 and size of every input file named on the command line, and the command's
// JSON result with its SHA-256 over a canonical form (object keys sorted). Anyone can later check
// that the result was not edited and that the inputs on disk are still the same bytes.
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readSync, statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

export const EVIDENCE_SCHEMA = 'revlens/evidence@1';
const MAX_HASH_BYTES = 4 * 1024 * 1024 * 1024;

export interface EvidenceInput { arg: string; path: string; size: number; sha256: string }
export interface EvidenceBundle {
  schema: typeof EVIDENCE_SCHEMA;
  tool: { name: string; version: string };
  command: string;
  argv: string[];
  cwd: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  exitCode: number;
  inputs: EvidenceInput[];
  output: { kind: 'json'; sha256: string; value: unknown } | { kind: 'text'; sha256: string; text: string };
}

/** JSON with object keys sorted at every level, so the same data always hashes the same. */
export function canonicalJson(v: unknown): string {
  return JSON.stringify(sortKeys(v));
}
function sortKeys(v: unknown, depth = 0): unknown {
  if (depth > 512) throw new RangeError('value is nested too deeply');
  if (Array.isArray(v)) return v.map((x) => sortKeys(x, depth + 1));
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys((v as Record<string, unknown>)[k], depth + 1);
    return out;
  }
  return v;
}
export const sha256Text = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

/** SHA-256 of a file read in chunks through one descriptor. */
export function hashFile(path: string): { size: number; sha256: string } {
  const fd = openSync(path, 'r');
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${path} is not a file`);
    if (st.size > MAX_HASH_BYTES) throw new Error(`${path} is larger than 4 GiB`);
    const h = createHash('sha256');
    const buf = Buffer.allocUnsafe(1 << 20);
    let pos = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, pos);
      if (n <= 0) break;
      h.update(buf.subarray(0, n));
      pos += n;
    }
    return { size: pos, sha256: h.digest('hex') };
  } finally { closeSync(fd); }
}

/** Positional arguments that name existing regular files, hashed. At most 64 files. */
export function inputsFromArgs(args: string[], cwd = process.cwd()): EvidenceInput[] {
  const out: EvidenceInput[] = [];
  const seen = new Set<string>();
  for (const a of args) {
    if (out.length >= 64) break;
    if (!a || a.startsWith('-')) continue;
    const p = isAbsolute(a) ? a : resolve(cwd, a);
    if (seen.has(p)) continue;
    let st;
    try { st = statSync(p); } catch { continue; }
    if (!st.isFile()) continue;
    seen.add(p);
    try { out.push({ arg: a, path: p, ...hashFile(p) }); } catch { /* unreadable, skip */ }
  }
  return out;
}

export function makeBundle(o: { tool: { name: string; version: string }; command: string; argv: string[]; startedAt: Date; finishedAt: Date; exitCode: number; positional: string[]; json?: { ok: true; value: unknown } | { ok: false }; text: string; cwd?: string }): EvidenceBundle {
  const cwd = o.cwd ?? process.cwd();
  const output: EvidenceBundle['output'] = o.json && o.json.ok
    ? { kind: 'json', sha256: sha256Text(canonicalJson(o.json.value)), value: o.json.value }
    : { kind: 'text', sha256: sha256Text(o.text), text: o.text };
  return {
    schema: EVIDENCE_SCHEMA, tool: o.tool, command: o.command, argv: o.argv, cwd,
    startedAt: o.startedAt.toISOString(), finishedAt: o.finishedAt.toISOString(), durationMs: o.finishedAt.getTime() - o.startedAt.getTime(),
    exitCode: o.exitCode, inputs: inputsFromArgs(o.positional, cwd), output,
  };
}

/** Where to write a bundle: the path itself, or `<dir>/<command>-<time>.evidence.json` when it is a folder. */
export function bundlePath(target: string, command: string, at: Date): string {
  const dirLike = target.endsWith('/') || target.endsWith('\\') || (existsSync(target) && statSync(target).isDirectory());
  if (!dirLike) return target;
  const safe = command.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 40) || 'command';
  return resolve(target, `${safe}-${at.toISOString().replace(/[:.]/g, '-')}.evidence.json`);
}

export interface BundleCheck {
  schema: string;
  command: string;
  outputIntact: boolean;
  inputs: { path: string; status: 'same' | 'changed' | 'missing' | 'unreadable'; want: string; got?: string }[];
  problems: string[];
}

/** Check a bundle: schema, the output hash, and each input file against its recorded hash. */
export function checkBundle(b: unknown): BundleCheck {
  const problems: string[] = [];
  const o = (b && typeof b === 'object' ? b : {}) as Partial<EvidenceBundle>;
  if (o.schema !== EVIDENCE_SCHEMA) problems.push(`schema is ${JSON.stringify(o.schema)}, expected ${EVIDENCE_SCHEMA}`);
  let outputIntact = false;
  const out = o.output as EvidenceBundle['output'] | undefined;
  if (!out || typeof out !== 'object' || typeof out.sha256 !== 'string') problems.push('output is missing');
  else if (out.kind === 'json') outputIntact = sha256Text(canonicalJson(out.value)) === out.sha256;
  else if (out.kind === 'text' && typeof out.text === 'string') outputIntact = sha256Text(out.text) === out.sha256;
  else problems.push('output kind is not json or text');
  if (out && !outputIntact && !problems.length) problems.push('the output does not match its sha256: the bundle was edited');
  const inputs: BundleCheck['inputs'] = [];
  const list = Array.isArray(o.inputs) ? o.inputs.slice(0, 64) : [];
  if (!Array.isArray(o.inputs)) problems.push('inputs is not a list');
  for (const i of list) {
    if (!i || typeof i.path !== 'string' || typeof i.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(i.sha256)) { problems.push('an input entry is malformed'); continue; }
    if (!existsSync(i.path)) { inputs.push({ path: i.path, status: 'missing', want: i.sha256 }); continue; }
    try {
      const h = hashFile(i.path);
      inputs.push({ path: i.path, status: h.sha256 === i.sha256 ? 'same' : 'changed', want: i.sha256, got: h.sha256 });
    } catch { inputs.push({ path: i.path, status: 'unreadable', want: i.sha256 }); }
  }
  return { schema: String(o.schema), command: String(o.command ?? ''), outputIntact, inputs, problems };
}
