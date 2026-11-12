// Append-only audit log for computer sessions: one JSON line per action, each line carrying the
// SHA-256 of the line before it, so a removed, reordered or edited line is detected on verify.
import { appendFile, readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { InputError } from './proc.js';

export interface AuditEntry {
  seq: number; time: string; session: string; action: string;
  args?: Record<string, unknown>; ok: boolean; error?: string; result?: Record<string, unknown>; ms?: number;
  prev: string; hash: string;
}

/** JSON with sorted keys, so the hash does not depend on key order. */
export function canonicalJson(v: unknown, depth = 0): string {
  if (depth > 50) throw new InputError('value nested too deep');
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map((x) => canonicalJson(x, depth + 1)).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k], depth + 1)}`).join(',')}}`;
}
export const sha256Hex = (b: string | Uint8Array) => createHash('sha256').update(b).digest('hex');
const GENESIS = '0'.repeat(64);

export class AuditLog {
  private seq = 0; private last = GENESIS; private chain: Promise<void> = Promise.resolve();
  constructor(public path: string, public session: string) {}
  /** Append one entry; returns it with its hash. Writes are serialised. */
  record(e: Omit<AuditEntry, 'seq' | 'time' | 'session' | 'prev' | 'hash'>): Promise<AuditEntry> {
    const entry = { seq: ++this.seq, time: new Date().toISOString(), session: this.session, ...e, prev: this.last } as Omit<AuditEntry, 'hash'>;
    const hash = sha256Hex(canonicalJson(entry));
    this.last = hash;
    const full: AuditEntry = { ...entry, hash };
    const line = JSON.stringify(full) + '\n';
    const p = this.chain.then(() => appendFile(this.path, line, { mode: 0o600 }));
    this.chain = p.catch(() => undefined);
    return p.then(() => full);
  }
  get head() { return this.last; }
  get count() { return this.seq; }
}

/** Mask what an action types when it is marked secret: keep the length and a hash only. */
export function redactArgs(action: string, a: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...a };
  if (typeof a.text === 'string' && (a.secret === true || action === 'type_secret')) out.text = { redacted: true, length: a.text.length, sha256: sha256Hex(a.text) };
  else if (typeof a.text === 'string' && a.text.length > 2000) out.text = `${a.text.slice(0, 2000)}... (${a.text.length} chars)`;
  return out;
}

/** Check an audit log file: every line parses, sequence numbers run 1..n, each prev matches the hash before it and each hash matches its line. */
export async function verifyAuditLog(path: string): Promise<{ ok: boolean; entries: number; head: string; problems: { line: number; problem: string }[]; actions: Record<string, number>; failures: number }> {
  const st = await stat(path);
  if (st.size > 256 * 1024 * 1024) throw new InputError('audit log too large');
  const lines = (await readFile(path, 'utf8')).split('\n').filter((l) => l.trim());
  const problems: { line: number; problem: string }[] = [];
  const actions: Record<string, number> = {};
  let prev = GENESIS, failures = 0;
  lines.forEach((l, i) => {
    let e: AuditEntry;
    try { e = JSON.parse(l); } catch { problems.push({ line: i + 1, problem: 'not JSON' }); return; }
    if (e.seq !== i + 1) problems.push({ line: i + 1, problem: `sequence ${e.seq}, expected ${i + 1}` });
    if (e.prev !== prev) problems.push({ line: i + 1, problem: 'prev does not match the hash of the line before' });
    const { hash, ...rest } = e;
    const h = sha256Hex(canonicalJson(rest));
    if (h !== hash) problems.push({ line: i + 1, problem: 'hash does not match the line content' });
    prev = hash;
    actions[e.action] = (actions[e.action] ?? 0) + 1;
    if (!e.ok) failures++;
  });
  return { ok: problems.length === 0, entries: lines.length, head: prev, problems: problems.slice(0, 200), actions, failures };
}
