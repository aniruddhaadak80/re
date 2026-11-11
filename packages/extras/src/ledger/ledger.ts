// Evidence and claims ledger. An append-only, hash-chained log of what an agent or a
// person asserted about a file, each claim bound to byte ranges by SHA-256, plus open
// unknowns. Anyone holding the file can re-verify every claim without the original session.

import { sha256, verifyClaim, type Claim } from '@revlens/core';
import { ParseError, toHex } from '../util.js';

export const LEDGER_SCHEMA = 'revlens/ledger@1';
const GENESIS = '0'.repeat(64);

export interface EvidenceRef {
  /** label for the file, normally its path; verification looks the bytes up by this or by fileSha256 */
  path?: string;
  fileSha256: string;
  offset: number;
  length: number;
  /** SHA-256 of bytes[offset, offset+length) */
  sha256: string;
  /** first 32 bytes as hex, for humans */
  preview: string;
  note?: string;
}

export type EntryKind = 'claim' | 'unknown' | 'update';
export type Status = 'asserted' | 'verified' | 'refuted' | 'stale' | 'open' | 'resolved' | 'rejected';

export interface LedgerEntry {
  seq: number;
  id: string;
  kind: EntryKind;
  at: string;
  author?: string;
  tool?: string;
  statement?: string;
  /** structured check run on verify, any byte-level @revlens/core Claim */
  check?: Claim;
  evidence?: EvidenceRef[];
  links?: string[];
  /** for kind update: the entry it changes */
  target?: string;
  status?: Status;
  reason?: string;
  prev: string;
  hash: string;
}

export interface LedgerItem { id: string; kind: 'claim' | 'unknown'; statement: string; status: Status; evidence: EvidenceRef[]; links: string[]; check?: Claim; author?: string; tool?: string; history: { seq: number; status: Status; reason?: string; at: string }[] }

export interface LedgerExport { schema: typeof LEDGER_SCHEMA; created: string; head: string; count: number; entries: LedgerEntry[] }

/** Canonical JSON: sorted keys, no whitespace, so hashes are stable across runtimes. */
export function canonical(x: unknown): string {
  if (x === null || typeof x !== 'object') return JSON.stringify(x ?? null);
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  const o = x as Record<string, unknown>;
  return '{' + Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(o[k])).join(',') + '}';
}
const enc = new TextEncoder();
function entryHash(e: Omit<LedgerEntry, 'hash'>): string { return sha256(enc.encode(canonical(e))); }

/** Build an evidence reference for a byte range of a file. */
export function evidenceFor(bytes: Uint8Array, offset: number, length: number, path?: string, note?: string, fileSha?: string): EvidenceRef {
  if (!Number.isInteger(offset) || !Number.isInteger(length) || offset < 0 || length < 0 || offset + length > bytes.length) throw new ParseError(`range ${offset}+${length} is outside the file (${bytes.length} bytes)`);
  if (length > 16 << 20) throw new ParseError('evidence ranges are capped at 16 MiB');
  const sub = bytes.subarray(offset, offset + length);
  return { path, fileSha256: fileSha ?? sha256(bytes), offset, length, sha256: sha256(sub), preview: toHex(sub.subarray(0, 32)), ...(note ? { note } : {}) };
}

export type BytesResolver = (ref: { path?: string; fileSha256: string }) => Promise<Uint8Array | undefined>;

export interface VerifyResult {
  id: string;
  verdict: 'VERIFIED' | 'REFUTED' | 'UNVERIFIABLE';
  checks: { evidence: number; ok: boolean | null; reason: string }[];
  claimCheck?: { verdict: string; reason: string };
}

export class Ledger {
  readonly entries: LedgerEntry[] = [];
  private ids = new Set<string>();
  constructor(readonly maxEntries = 100_000) {}

  get head(): string { return this.entries.length ? (this.entries[this.entries.length - 1] as LedgerEntry).hash : GENESIS; }

  private append(e: Omit<LedgerEntry, 'seq' | 'prev' | 'hash' | 'at'> & { at?: string }): LedgerEntry {
    if (this.entries.length >= this.maxEntries) throw new ParseError(`ledger is capped at ${this.maxEntries} entries`);
    const base = { ...e, seq: this.entries.length, at: e.at ?? new Date().toISOString(), prev: this.head } as Omit<LedgerEntry, 'hash'>;
    const full: LedgerEntry = { ...base, hash: entryHash(base) };
    this.entries.push(full);
    this.ids.add(full.id);
    return full;
  }
  private newId(prefix: string): string {
    let i = this.entries.length + 1;
    while (this.ids.has(`${prefix}${i}`)) i++;
    return `${prefix}${i}`;
  }

  /** Record a claim with byte evidence. */
  claim(c: { statement: string; evidence: EvidenceRef[]; check?: Claim; links?: string[]; author?: string; tool?: string; id?: string }): LedgerEntry {
    if (!c.statement || c.statement.length > 4000) throw new ParseError('statement must be 1 to 4000 characters');
    if (!c.evidence?.length && !c.check) throw new ParseError('a claim needs evidence or a check');
    if ((c.evidence?.length ?? 0) > 64) throw new ParseError('at most 64 evidence ranges per claim');
    const id = c.id ?? this.newId('C');
    if (this.ids.has(id)) throw new ParseError(`id ${id} already exists`);
    for (const l of c.links ?? []) if (!this.ids.has(l)) throw new ParseError(`link ${l} does not exist`);
    return this.append({ id, kind: 'claim', statement: c.statement, evidence: c.evidence ?? [], check: c.check, links: c.links, author: c.author, tool: c.tool, status: 'asserted' });
  }

  /** Record an open question that still needs evidence. */
  unknown(u: { statement: string; links?: string[]; author?: string; evidence?: EvidenceRef[]; id?: string }): LedgerEntry {
    if (!u.statement || u.statement.length > 4000) throw new ParseError('statement must be 1 to 4000 characters');
    const id = u.id ?? this.newId('U');
    if (this.ids.has(id)) throw new ParseError(`id ${id} already exists`);
    return this.append({ id, kind: 'unknown', statement: u.statement, links: u.links, author: u.author, evidence: u.evidence, status: 'open' });
  }

  /** Change the status of a claim or unknown: resolve an unknown, reject a claim, and so on. */
  update(target: string, status: Status, reason?: string, links?: string[], author?: string): LedgerEntry {
    const item = this.items().find((x) => x.id === target);
    if (!item) throw new ParseError(`no claim or unknown ${target}`);
    for (const l of links ?? []) if (!this.ids.has(l)) throw new ParseError(`link ${l} does not exist`);
    return this.append({ id: this.newId('E'), kind: 'update', target, status, reason, links, author });
  }

  /** Current state of every claim and unknown, after all updates. */
  items(): LedgerItem[] {
    const map = new Map<string, LedgerItem>();
    for (const e of this.entries) {
      if (e.kind === 'claim' || e.kind === 'unknown') {
        map.set(e.id, { id: e.id, kind: e.kind, statement: e.statement ?? '', status: e.status ?? 'asserted', evidence: e.evidence ?? [], links: [...(e.links ?? [])], check: e.check, author: e.author, tool: e.tool, history: [{ seq: e.seq, status: e.status ?? 'asserted', at: e.at }] });
      } else if (e.kind === 'update' && e.target) {
        const it = map.get(e.target);
        if (!it) continue;
        it.status = e.status ?? it.status;
        for (const l of e.links ?? []) if (!it.links.includes(l)) it.links.push(l);
        it.history.push({ seq: e.seq, status: it.status, reason: e.reason, at: e.at });
      }
    }
    return [...map.values()];
  }

  /** Counts by kind and status, plus how much of the ledger is backed by verified evidence. */
  summary(): { claims: number; unknowns: number; byStatus: Record<string, number>; openUnknowns: number; verifiedShare: number; head: string; entries: number } {
    const it = this.items();
    const byStatus: Record<string, number> = {};
    for (const x of it) byStatus[x.status] = (byStatus[x.status] ?? 0) + 1;
    const claims = it.filter((x) => x.kind === 'claim');
    const verified = claims.filter((x) => x.status === 'verified').length;
    return { claims: claims.length, unknowns: it.length - claims.length, byStatus, openUnknowns: it.filter((x) => x.kind === 'unknown' && x.status === 'open').length, verifiedShare: claims.length ? Math.round((verified / claims.length) * 1000) / 1000 : 0, head: this.head, entries: this.entries.length };
  }

  /**
   * Re-read the bytes behind each claim and check every evidence hash and the structured check.
   * Appends an update entry for every claim whose status changes, unless `record` is false.
   */
  async verify(resolve: BytesResolver, opts: { ids?: string[]; record?: boolean } = {}): Promise<VerifyResult[]> {
    const out: VerifyResult[] = [];
    const cache = new Map<string, Uint8Array | undefined>();
    const get = async (ref: { path?: string; fileSha256: string }): Promise<Uint8Array | undefined> => {
      const key = `${ref.path ?? ''}|${ref.fileSha256}`;
      if (!cache.has(key)) cache.set(key, await resolve(ref).catch(() => undefined));
      return cache.get(key);
    };
    for (const it of this.items()) {
      if (it.kind !== 'claim' || (opts.ids && !opts.ids.includes(it.id))) continue;
      if (it.status === 'rejected') continue;
      const checks: VerifyResult['checks'] = [];
      let refuted = false, missing = false;
      let firstBytes: Uint8Array | undefined;
      for (let i = 0; i < it.evidence.length; i++) {
        const ev = it.evidence[i] as EvidenceRef;
        const b = await get(ev);
        if (!b) { missing = true; checks.push({ evidence: i, ok: null, reason: 'file not available' }); continue; }
        firstBytes ??= b;
        const fh = sha256(b);
        if (fh !== ev.fileSha256) { refuted = true; checks.push({ evidence: i, ok: false, reason: `file hash is ${fh.slice(0, 16)}..., claim was made on ${ev.fileSha256.slice(0, 16)}...` }); continue; }
        if (ev.offset + ev.length > b.length) { refuted = true; checks.push({ evidence: i, ok: false, reason: 'range is outside the file' }); continue; }
        const rh = sha256(b.subarray(ev.offset, ev.offset + ev.length));
        if (rh !== ev.sha256) { refuted = true; checks.push({ evidence: i, ok: false, reason: 'bytes in the range changed' }); continue; }
        checks.push({ evidence: i, ok: true, reason: `bytes ${ev.offset}..${ev.offset + ev.length} match` });
      }
      let claimCheck: VerifyResult['claimCheck'];
      if (it.check) {
        const target = firstBytes ?? (it.evidence[0] ? await get(it.evidence[0]) : undefined);
        if (!target) missing = true;
        else {
          const r = verifyClaim(target, it.check);
          claimCheck = { verdict: r.verdict, reason: r.reason };
          if (r.verdict === 'REFUTED') refuted = true;
          if (r.verdict === 'UNKNOWN') missing = true;
        }
      }
      const verdict: VerifyResult['verdict'] = refuted ? 'REFUTED' : missing ? 'UNVERIFIABLE' : 'VERIFIED';
      out.push({ id: it.id, verdict, checks, claimCheck });
      const next: Status = verdict === 'VERIFIED' ? 'verified' : verdict === 'REFUTED' ? 'refuted' : 'stale';
      if (opts.record !== false && next !== it.status) this.update(it.id, next, `verify: ${verdict.toLowerCase()}`);
    }
    return out;
  }

  /** Check the hash chain. Returns the first broken sequence number, or -1 when intact. */
  static checkChain(entries: LedgerEntry[]): number {
    let prev = GENESIS;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i] as LedgerEntry;
      const { hash, ...rest } = e;
      if (e.seq !== i || e.prev !== prev || entryHash(rest) !== hash) return i;
      prev = hash;
    }
    return -1;
  }

  export(): LedgerExport { return { schema: LEDGER_SCHEMA, created: new Date().toISOString(), head: this.head, count: this.entries.length, entries: this.entries.map((e) => ({ ...e })) }; }

  /** Load an exported ledger. Throws when the schema or hash chain does not check out. */
  static import(data: unknown): Ledger {
    const d = (typeof data === 'string' ? JSON.parse(data) : data) as LedgerExport;
    if (!d || d.schema !== LEDGER_SCHEMA || !Array.isArray(d.entries)) throw new ParseError(`not a ${LEDGER_SCHEMA} export`);
    const bad = Ledger.checkChain(d.entries);
    if (bad >= 0) throw new ParseError(`hash chain broken at entry ${bad}`);
    if (d.entries.length && d.head !== (d.entries[d.entries.length - 1] as LedgerEntry).hash) throw new ParseError('head does not match the last entry');
    const l = new Ledger();
    for (const e of d.entries) { l.entries.push(e); l.ids.add(e.id); }
    return l;
  }

  /** Markdown report of the current state, for humans. */
  toMarkdown(): string {
    const s = this.summary();
    const lines = ['# RevLens evidence ledger', '', `Head ${s.head}. ${s.claims} claims, ${s.unknowns} unknowns (${s.openUnknowns} open), ${Math.round(s.verifiedShare * 100)}% of claims verified.`, '', '| id | kind | status | statement | evidence |', '|---|---|---|---|---|'];
    for (const it of this.items()) {
      const ev = it.evidence.map((e) => `${e.path ?? e.fileSha256.slice(0, 12)}@${e.offset}+${e.length}`).join('<br>') || (it.check ? `check ${it.check.kind}` : '');
      lines.push(`| ${it.id} | ${it.kind} | ${it.status} | ${it.statement.replace(/\|/g, '\\|').replace(/\n/g, ' ')} | ${ev} |`);
    }
    return lines.join('\n') + '\n';
  }
}
