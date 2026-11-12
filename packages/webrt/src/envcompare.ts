// Fidelity of a replay environment against the application it came from (the job of rea
// environment-compare, written from scratch): each probe is a HAR or capture of one call sequence
// recorded against the live application after a reset. The environment is reset before each probe,
// every request to the probe's application origin is answered the way the replay server would answer
// it, and that answer is compared with what the application said. Ids are mapped between the two sides
// (identifier fields of paired answers, one to one, first pair wins) and translated in later requests;
// timestamps are normalised. Reads files only, never calls the network. Browser safe.
import { EnvMatcher, type EnvManifest, type EnvRoute } from './env.js';
import { InputError, sha256Hex, decodeUtf8, base64ToBytes, encodeUtf8 } from './util.js';

export interface ProbeCall {
  index: number;
  method: string;
  path: string;
  status: { app: number; env?: number };
  outcome: 'agree' | 'disagree' | 'no-tool' | 'not-compared';
  rule?: string;
  route?: number;
  template?: string;
  /** first JSON path where the bodies differ, with both values */
  difference?: { path: string; app: string; env: string };
  reason?: string;
}
export interface ProbeReport { name: string; origin?: string; calls: ProbeCall[]; skipped: { index: number; url: string; reason: string }[]; agreed: number; compared: number; agreement: number; mappedIds: number }
export interface EnvComparison {
  environment: { name: string; origin: string; routes: number };
  probes: ProbeReport[];
  summary: { probes: number; calls: number; compared: number; agreed: number; agreement: number; noTool: number; byTemplate: { template: string; method: string; compared: number; agreed: number }[] };
  warnings: string[];
}

const ID_KEY = /^(?:id|uuid|guid)$|(?:_id|Id|ID|_uuid|Uuid)$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?$/;

function harEntries(capture: any): any[] {
  const e = capture?.har?.log?.entries ?? capture?.log?.entries;
  if (!Array.isArray(e)) throw new InputError('probe is not a HAR, scenario capture or browser capture');
  // probe order: start time then position; position alone when a start time is missing
  const list = e.slice(0, 100_000).map((x: any, i: number) => ({ x, i, t: Date.parse(String(x?.startedDateTime ?? '')) }));
  if (list.every((y: any) => Number.isFinite(y.t))) list.sort((a: any, b: any) => a.t - b.t || a.i - b.i);
  return list.map((y: any) => y.x);
}

function bodyText(content: any): string | undefined {
  if (typeof content?.text !== 'string') return undefined;
  if (content.encoding === 'base64') { try { return decodeUtf8(base64ToBytes(content.text)); } catch { return undefined; } }
  return content.text;
}

function parseJson(s: string | undefined): { ok: true; v: unknown } | { ok: false } {
  if (s === undefined) return { ok: false };
  const t = s.trim();
  if (!t || (t[0] !== '{' && t[0] !== '[')) return { ok: false };
  try { return { ok: true, v: JSON.parse(t) }; } catch { return { ok: false }; }
}

/** One to one id map, first pair wins; a pair that conflicts is not used. */
class IdMap {
  live = new Map<string, string>();
  env = new Map<string, string>();
  bad = new Set<string>();
  learn(a: unknown, b: unknown): void {
    if ((typeof a !== 'string' && typeof a !== 'number') || (typeof b !== 'string' && typeof b !== 'number')) return;
    const la = String(a), lb = String(b);
    if (this.bad.has(la)) return;
    const prevEnv = this.live.get(la), prevLive = this.env.get(lb);
    if (prevEnv === undefined && prevLive === undefined) { if (this.live.size < 100_000) { this.live.set(la, lb); this.env.set(lb, la); } return; }
    if (prevEnv !== lb || prevLive !== la) { this.bad.add(la); }
  }
  map(v: string): string { return this.bad.has(v) ? v : this.live.get(v) ?? v; }
  get mapped(): number { let n = 0; for (const [k, v] of this.live) if (k !== v && !this.bad.has(k)) n++; return n; }
}

/** Walk two JSON values side by side and learn id pairs; arrays of objects pair by a shared unique key. */
function learnIds(app: unknown, env: unknown, ids: IdMap, depth = 0): void {
  if (depth > 40 || app === null || env === null || typeof app !== 'object' || typeof env !== 'object') return;
  if (Array.isArray(app) && Array.isArray(env)) {
    const pairs = pairArrays(app, env);
    for (const [x, y] of pairs) learnIds(x, y, ids, depth + 1);
    return;
  }
  if (Array.isArray(app) || Array.isArray(env)) return;
  const a = app as Record<string, unknown>, b = env as Record<string, unknown>;
  for (const k of Object.keys(a).slice(0, 2000)) {
    if (!(k in b)) continue;
    if (ID_KEY.test(k)) ids.learn(a[k], b[k]);
    else learnIds(a[k], b[k], ids, depth + 1);
  }
}

/** Pair array elements: by a natural key (a field on every element with unique string values shared by both sides), else by position. */
function pairArrays(a: unknown[], b: unknown[]): [unknown, unknown][] {
  const objs = (xs: unknown[]) => xs.length > 0 && xs.every((x) => x && typeof x === 'object' && !Array.isArray(x));
  if (objs(a) && objs(b)) {
    const keys = Object.keys(a[0] as object).filter((k) => !ID_KEY.test(k));
    for (const k of keys) {
      const va = a.map((x) => (x as Record<string, unknown>)[k]);
      const vb = b.map((x) => (x as Record<string, unknown>)[k]);
      if (!va.every((v) => typeof v === 'string') || !vb.every((v) => typeof v === 'string')) continue;
      if (new Set(va).size !== va.length || new Set(vb).size !== vb.length) continue;
      const ib = new Map(vb.map((v, i) => [v as string, i]));
      const out: [unknown, unknown][] = [];
      va.forEach((v, i) => { const j = ib.get(v as string); if (j !== undefined) out.push([a[i], b[j]]); });
      if (out.length) return out;
    }
  }
  const n = Math.min(a.length, b.length);
  return Array.from({ length: n }, (_, i) => [a[i], b[i]] as [unknown, unknown]);
}

/** Normalise an application value into the environment's terms for comparison. */
function normalise(v: unknown, ids: IdMap, key = '', depth = 0): unknown {
  if (depth > 60) return '<deep>';
  if (typeof v === 'string') { if (ISO_TIME.test(v)) return '<time>'; return ID_KEY.test(key) ? ids.map(v) : v; }
  if (typeof v === 'number') return ID_KEY.test(key) ? numOrStr(ids.map(String(v))) : v;
  if (Array.isArray(v)) return v.slice(0, 10_000).map((x) => normalise(x, ids, key, depth + 1));
  if (v && typeof v === 'object') { const o: Record<string, unknown> = {}; for (const [k, x] of Object.entries(v).slice(0, 5000)) o[k] = normalise(x, ids, k, depth + 1); return o; }
  return v;
}
const numOrStr = (s: string) => (/^-?\d+(?:\.\d+)?$/.test(s) ? Number(s) : s);
const normEnv = (v: unknown, depth = 0): unknown => {
  if (depth > 60) return '<deep>';
  if (typeof v === 'string') return ISO_TIME.test(v) ? '<time>' : v;
  if (Array.isArray(v)) return v.slice(0, 10_000).map((x) => normEnv(x, depth + 1));
  if (v && typeof v === 'object') { const o: Record<string, unknown> = {}; for (const [k, x] of Object.entries(v).slice(0, 5000)) o[k] = normEnv(x, depth + 1); return o; }
  return v;
};

/** First difference between two JSON values, with arrays of objects paired the same way ids are learned. */
function firstDiff(a: unknown, b: unknown, path = '$', depth = 0): { path: string; app: string; env: string } | undefined {
  const show = (x: unknown) => { const s = JSON.stringify(x); return s === undefined ? 'undefined' : s.slice(0, 200); };
  if (depth > 60) return undefined;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return { path: `${path}.length`, app: String(a.length), env: String(b.length) };
    for (let i = 0; i < a.length; i++) { const d = firstDiff(a[i], b[i], `${path}[${i}]`, depth + 1); if (d) return d; }
    return undefined;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    const ka = Object.keys(a), kb = Object.keys(b);
    for (const k of [...new Set([...ka, ...kb])].sort()) {
      if (!(k in (a as object))) return { path: `${path}.${k}`, app: 'missing', env: show((b as Record<string, unknown>)[k]) };
      if (!(k in (b as object))) return { path: `${path}.${k}`, app: show((a as Record<string, unknown>)[k]), env: 'missing' };
      const d = firstDiff((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}.${k}`, depth + 1); if (d) return d;
    }
    return undefined;
  }
  return Object.is(a, b) ? undefined : { path, app: show(a), env: show(b) };
}

/** Translate path segments and query values equal to a mapped live id into the environment id. */
function translate(path: string, ids: IdMap): string {
  const q = path.indexOf('?');
  const p = q < 0 ? path : path.slice(0, q);
  let out = p.split('/').map((s) => { let d = s; try { d = decodeURIComponent(s); } catch { /* raw */ } const m = ids.map(d); return m === d ? s : encodeURIComponent(m); }).join('/');
  if (q >= 0) {
    const sp = new URLSearchParams(path.slice(q + 1));
    const next = new URLSearchParams();
    for (const [k, v] of sp) next.append(k, /^(?:limit|offset|page|per_page|page_size|size|count|skip|take|cursor)$/i.test(k) ? v : ids.map(v));
    const s = next.toString();
    out += s ? `?${s}` : '';
  }
  return out;
}

function probeOrigin(entries: any[]): string | undefined {
  const score = new Map<string, number>();
  for (const e of entries) {
    try {
      const u = new URL(String(e?.request?.url ?? ''));
      const json = /json/i.test(String(e?.response?.content?.mimeType ?? '')) || parseJson(bodyText(e?.response?.content)).ok;
      score.set(u.origin, (score.get(u.origin) ?? 0) + (json ? 1 : 0));
    } catch { /* skip */ }
  }
  return [...score.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
}

/** Compare an environment with probe captures of its application. `body` returns a recorded body file. */
export async function compareEnvironmentWithProbes(manifest: EnvManifest, body: (file: string) => Promise<Uint8Array | undefined> | Uint8Array | undefined, probes: { name: string; capture: unknown }[], opts: { limit?: number } = {}): Promise<EnvComparison> {
  if (!probes.length) throw new InputError('give at least one probe capture');
  const matcher = new EnvMatcher(manifest);
  const warnings: string[] = [];
  const byTpl = new Map<string, { template: string; method: string; compared: number; agreed: number }>();
  const reports: ProbeReport[] = [];
  const lim = Math.max(1, Math.min(opts.limit ?? 5000, 100_000));
  for (const probe of probes.slice(0, 200)) {
    matcher.reset();
    const ids = new IdMap();
    const entries = harEntries(probe.capture);
    const origin = probeOrigin(entries);
    const calls: ProbeCall[] = [];
    const skipped: ProbeReport['skipped'] = [];
    let agreed = 0, compared = 0;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      let u: URL;
      try { u = new URL(String(e?.request?.url ?? '')); } catch { skipped.push({ index: i, url: String(e?.request?.url ?? '').slice(0, 300), reason: 'no-request-line' }); continue; }
      const method = String(e?.request?.method ?? '').toUpperCase();
      if (!method) { skipped.push({ index: i, url: u.href.slice(0, 300), reason: 'no-request-line' }); continue; }
      // the probe's application origin stands for the recorded origin (a fresh app often runs on another port)
      if (u.origin !== origin) { skipped.push({ index: i, url: u.href.slice(0, 300), reason: 'other-origin' }); continue; }
      const raw = u.pathname + u.search;
      const path = translate(raw, ids);
      const post = typeof e?.request?.postData?.text === 'string' && e.request.postData.text.length ? e.request.postData.text : undefined;
      // the request body in the environment's terms, so a create replays the recorded create
      let envPost = post;
      const pj = parseJson(post);
      if (pj.ok) envPost = JSON.stringify(normalise(pj.v, ids));
      const m = matcher.match(method, path, { bodySha256: envPost ? sha256Hex(encodeUtf8(envPost)) : undefined });
      const appStatus = Number(e?.response?.status ?? 0);
      const call: ProbeCall = { index: i, method, path: raw.slice(0, 2000), status: { app: appStatus }, outcome: 'no-tool', rule: m.rule };
      if (!m.route) { call.reason = 'no recorded route fits'; if (calls.length < lim) calls.push(call); continue; }
      const r: EnvRoute = m.route;
      call.route = r.id; call.template = r.template; call.status.env = r.status;
      const appText = bodyText(e?.response?.content);
      if (!appStatus || (appText === undefined && appStatus !== 204 && appStatus !== 304 && !(appStatus >= 300 && appStatus < 400))) { call.outcome = 'not-compared'; call.reason = 'the probe has no recorded answer'; if (calls.length < lim) calls.push(call); continue; }
      const envBytes = r.body ? await body(r.body.file) : undefined;
      const envText = envBytes ? decodeUtf8(envBytes) : '';
      const a = parseJson(appText), b = parseJson(envText);
      let diff: ProbeCall['difference'];
      if (r.status !== appStatus) diff = { path: 'status', app: String(appStatus), env: String(r.status) };
      else if (a.ok && b.ok) { learnIds(a.v, b.v, ids); diff = firstDiff(normalise(a.v, ids), normEnv(b.v)); }
      else if ((appText ?? '') !== envText) diff = { path: 'body', app: `${(appText ?? '').length} chars sha256 ${sha256Hex(appText ?? '').slice(0, 16)}`, env: `${envText.length} chars sha256 ${sha256Hex(envText).slice(0, 16)}` };
      compared++;
      const k = `${method} ${r.template}`;
      const t = byTpl.get(k) ?? { template: r.template, method, compared: 0, agreed: 0 };
      t.compared++;
      if (!diff) { agreed++; t.agreed++; call.outcome = 'agree'; } else { call.outcome = 'disagree'; call.difference = diff; }
      byTpl.set(k, t);
      if (calls.length < lim) calls.push(call);
    }
    if (!origin) warnings.push(`${probe.name}: no requests`);
    reports.push({ name: probe.name, origin, calls, skipped: skipped.slice(0, lim), agreed, compared, agreement: compared ? Math.round((agreed / compared) * 1000) / 1000 : 0, mappedIds: ids.mapped });
  }
  const compared = reports.reduce((s, r) => s + r.compared, 0);
  const agreed = reports.reduce((s, r) => s + r.agreed, 0);
  return {
    environment: { name: manifest.name, origin: manifest.origin, routes: manifest.routes.length },
    probes: reports,
    summary: { probes: reports.length, calls: reports.reduce((s, r) => s + r.calls.length, 0), compared, agreed, agreement: compared ? Math.round((agreed / compared) * 1000) / 1000 : 0, noTool: reports.reduce((s, r) => s + r.calls.filter((c) => c.outcome === 'no-tool').length, 0), byTemplate: [...byTpl.values()].sort((x, y) => (x.agreed / x.compared) - (y.agreed / y.compared)) },
    warnings,
  };
}
