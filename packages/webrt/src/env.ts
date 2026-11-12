// Replay environments from recorded traffic. buildEnvironment turns a HAR, a RevLens scenario capture
// (recorded with recordBodies) or a browser capture into a manifest of routes with recorded responses,
// deduplicated body files, matching rules, the scenario to re-run, and eval tasks in the shape the
// extras x_eval_score harness scores. EnvMatcher answers a request from the manifest with deterministic
// rules. Browser safe: serving and zip export live in env-node.ts.
import { base64ToBytes, encodeUtf8, sha256Hex, InputError } from './util.js';
import { compareStaticAndObservedEndpoints } from './endpointjoin.js';

export interface EnvRoute {
  id: number;
  method: string;
  host: string;
  path: string;
  /** decoded query pairs in request order */
  query: [string, string][];
  /** path template with ids folded to {id}, used when nothing matches exactly */
  template: string;
  requestBodySha256?: string;
  /** 0-based position among routes with the same method, host, path and query */
  sequence: number;
  status: number;
  statusText?: string;
  headers: [string, string][];
  body?: { file: string; size: number; sha256: string };
  /** response body was not recorded (redirect, opaque, too large) */
  bodyMissing?: boolean;
  entry: number;
  step?: number;
}

export interface EvalTaskFile {
  id: string;
  question: string;
  file: string;
  tags: string[];
  answerType: 'exact' | 'hex' | 'int' | 'set' | 'contains';
  answer: string | number | string[];
  reference: string;
  hint?: string[];
}

export interface EnvManifest {
  kind: 'revlens-env';
  version: 1;
  name: string;
  source: { kind: 'har' | 'scenario' | 'browser-capture'; sha256: string; entries: number; creator?: string };
  origin: string;
  origins: string[];
  routes: EnvRoute[];
  rules: { order: string[]; sequence: 'in-order-then-last'; unmatched: number; hostPrefix: string };
  scenario?: unknown;
  /** values the original run produced, for checking a re-run against the replay */
  expected?: { steps: { index: number; ok: boolean; url?: string; requests: string[] }[]; requests: string[] };
  tasks: EvalTaskFile[];
  warnings: string[];
}

export interface BuiltEnvironment { manifest: EnvManifest; files: { path: string; bytes: Uint8Array }[] }

const HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-length', 'content-encoding', 'upgrade', 'proxy-connection', 'te', 'trailer', 'set-cookie', 'alt-svc', 'strict-transport-security', 'report-to', 'nel', 'date']);
const ID_SEG = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$/i;
export const ENV_HOST_PREFIX = '/__host/';

export function templateOf(path: string): string { return path.split('/').map((s) => (ID_SEG.test(s) ? '{id}' : s)).join('/'); }
const qKey = (q: [string, string][]) => q.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).sort().join('&');
const routeKey = (method: string, host: string, path: string, q: [string, string][], bodySha?: string) => `${method} ${host}${path}?${qKey(q)}#${bodySha ?? ''}`;

function slug(s: string): string { return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63) || 'env'; }

/** Build a replay environment from a capture object (HAR, scenario capture or browser capture). */
export function buildEnvironment(capture: unknown, opts: { name?: string; sourceText?: string; scenario?: unknown; tasks?: boolean; maxRoutes?: number } = {}): BuiltEnvironment {
  const root = capture as Record<string, any>;
  const kind: EnvManifest['source']['kind'] = root?.kind === 'revlens-scenario' ? 'scenario' : root?.har?.log ? 'browser-capture' : 'har';
  const entries: any[] = root?.har?.log?.entries ?? root?.log?.entries;
  if (!Array.isArray(entries)) throw new InputError('not a HAR, scenario capture or browser capture (no log.entries)');
  const warnings: string[] = [];
  const files = new Map<string, Uint8Array>();
  const routes: EnvRoute[] = [];
  const seq = new Map<string, number>();
  const origins = new Map<string, number>();
  let docOrigin: string | undefined;
  let noBody = 0;
  const maxRoutes = Math.max(1, Math.min(opts.maxRoutes ?? 50_000, 200_000));
  entries.slice(0, maxRoutes).forEach((e, i) => {
    let u: URL;
    try { u = new URL(String(e?.request?.url ?? '')); } catch { return; }
    if (!/^https?:$/.test(u.protocol)) return;
    const status = Number(e?.response?.status ?? 0);
    if (!status || e?._failed) return; // failed requests have nothing to replay
    const method = String(e?.request?.method ?? 'GET').toUpperCase();
    origins.set(u.origin, (origins.get(u.origin) ?? 0) + 1);
    if (!docOrigin && (e?._resourceType === 'document' || /text\/html/i.test(String(e?.response?.content?.mimeType ?? '')))) docOrigin = u.origin;
    const query = [...u.searchParams].slice(0, 200) as [string, string][];
    const post = e?.request?.postData?.text;
    const reqSha = typeof post === 'string' && post.length ? sha256Hex(post) : undefined;
    const key = routeKey(method, u.host, u.pathname, query, reqSha);
    const sequence = seq.get(key) ?? 0;
    seq.set(key, sequence + 1);
    const headers: [string, string][] = [];
    const hs = Array.isArray(e?.response?.headers) ? e.response.headers : [];
    for (const h of hs.slice(0, 100)) {
      const n = String(h?.name ?? '').toLowerCase();
      if (!n || n.startsWith(':') || HOP.has(n)) continue;
      const v = String(h?.value ?? '');
      if (v === '[redacted]' || v === 'REDACTED') continue;
      headers.push([n, v.slice(0, 4000)]);
    }
    const c = e?.response?.content ?? {};
    let body: EnvRoute['body'];
    let bodyMissing: boolean | undefined;
    if (typeof c.text === 'string') {
      let bytes: Uint8Array;
      try { bytes = c.encoding === 'base64' ? base64ToBytes(c.text) : encodeUtf8(c.text); } catch { bytes = encodeUtf8(c.text); }
      const sha = sha256Hex(bytes);
      const file = `bodies/${sha}.bin`;
      if (!files.has(file)) files.set(file, bytes);
      body = { file, size: bytes.length, sha256: sha };
    } else if (status !== 204 && status !== 304 && !(status >= 300 && status < 400) && method !== 'HEAD') { bodyMissing = true; noBody++; }
    if (!headers.some(([n]) => n === 'content-type') && c.mimeType) headers.push(['content-type', String(c.mimeType).slice(0, 200)]);
    routes.push({ id: routes.length, method, host: u.host, path: u.pathname, query, template: templateOf(u.pathname), requestBodySha256: reqSha, sequence, status, statusText: e?.response?.statusText || undefined, headers, body, bodyMissing, entry: i, step: typeof e?._step === 'number' ? e._step : undefined });
  });
  if (!routes.length) throw new InputError('the capture has no replayable http(s) responses');
  if (noBody) warnings.push(`${noBody} responses have no recorded body and replay as empty; record with recordBodies (scenario) or a HAR with embedded content`);
  const origin = docOrigin ?? [...origins.entries()].sort((a, b) => b[1] - a[1])[0]![0];
  const name = slug(opts.name ?? root?.name ?? (() => { try { return new URL(origin).hostname; } catch { return 'env'; } })());
  const sourceText = opts.sourceText ?? JSON.stringify(capture);
  const manifest: EnvManifest = {
    kind: 'revlens-env', version: 1, name,
    source: { kind, sha256: sha256Hex(sourceText), entries: entries.length, creator: root?.log?.creator?.name ?? root?.har?.log?.creator?.name },
    origin, origins: [...origins.keys()].slice(0, 500),
    routes,
    rules: { order: ['method+host+path+query+body (sequence)', 'method+host+path+query names', 'method+host+path', 'method+host+template', '404'], sequence: 'in-order-then-last', unmatched: 404, hostPrefix: ENV_HOST_PREFIX },
    tasks: [], warnings,
  };
  // the scenario that made the capture, so the replay can be checked by running it again
  const scen = opts.scenario ?? (kind === 'scenario' ? root?.scenario : undefined);
  if (scen) manifest.scenario = scen;
  if (kind === 'scenario' && Array.isArray(root?.steps)) {
    const reqLabel = (idx: number) => { const e = entries[idx]; if (!e) return '?'; let p = ''; try { const u = new URL(e.request.url); p = u.origin === origin ? u.pathname + u.search : u.href; } catch { p = String(e.request?.url); } return `${String(e.request?.method ?? 'GET').toUpperCase()} ${p} ${e.response?.status ?? 0}`; };
    manifest.expected = {
      steps: root.steps.slice(0, 500).map((s: any) => ({ index: s.index, ok: !!s.ok, url: typeof s.url === 'string' ? s.url.replace(origin, '') : undefined, requests: (s.requests ?? []).map(reqLabel).sort() })),
      requests: entries.map((_: unknown, i: number) => reqLabel(i)).sort(),
    };
  }
  if (opts.tasks !== false) manifest.tasks = makeTasks(manifest, capture, files);
  files.set('manifest.json', encodeUtf8(JSON.stringify(manifest, null, 1)));
  files.set('tasks/tasks.json', encodeUtf8(JSON.stringify(manifest.tasks, null, 1)));
  return { manifest, files: [...files.entries()].map(([path, bytes]) => ({ path, bytes })) };
}

/** Eval tasks with ground truth taken from the recording, in the x_eval_score task shape. */
function makeTasks(m: EnvManifest, capture: unknown, files: Map<string, Uint8Array>): EvalTaskFile[] {
  const tasks: EvalTaskFile[] = [];
  const ref = `recorded ${m.source.kind} sha256 ${m.source.sha256.slice(0, 16)}`;
  const own = m.routes.filter((r) => `${r.host}` === new URL(m.origin).host);
  let join: ReturnType<typeof compareStaticAndObservedEndpoints> | undefined;
  try { join = compareStaticAndObservedEndpoints({ capture }); } catch { join = undefined; }
  const api = own.filter((r) => r.path.startsWith('/api') || r.headers.some(([n, v]) => n === 'content-type' && /json/i.test(v)));
  if (api.length) {
    const set = [...new Set(api.map((r) => `${r.method} ${r.template}`))].sort();
    tasks.push({ id: `${m.name}-api-endpoints`, question: `Which API endpoints does the app at ${m.origin} call during the recorded session? Answer as METHOD path, with numeric ids written as {id}.`, file: 'manifest.json', tags: ['env', 'web', m.name], answerType: 'set', answer: set, reference: ref, hint: ['web_env_serve', 'web_browser_scenario', 'web_har_summary'] });
  }
  if (join?.staticOnly.length) tasks.push({ id: `${m.name}-dead-endpoints`, question: 'Which endpoints are named in the app JavaScript but never requested in the recorded session? Answer as METHOD path or host/path.', file: 'manifest.json', tags: ['env', 'web', 'static', m.name], answerType: 'set', answer: join.staticOnly.map((s) => `${s.method ?? '*'} ${s.host ?? ''}${s.template}`).sort(), reference: `${ref}, static analysis of the captured scripts`, hint: ['web_endpoint_join'] });
  if (join?.observedOnly.some((o) => o.reason === 'no-static-source')) tasks.push({ id: `${m.name}-runtime-endpoints`, question: 'Which requests in the session have no endpoint written in the JavaScript, so the path must be built at run time? Answer as METHOD path.', file: 'manifest.json', tags: ['env', 'web', 'runtime', m.name], answerType: 'set', answer: join.observedOnly.filter((o) => o.reason === 'no-static-source').map((o) => `${o.method} ${o.template}`).sort(), reference: ref, hint: ['web_endpoint_join', 'web_trace_semantics'] });
  for (const r of api.filter((x) => x.method !== 'GET').slice(0, 10)) tasks.push({ id: `${m.name}-status-${r.method.toLowerCase()}-${slug(r.path)}-${r.sequence}`, question: `What HTTP status does ${r.method} ${r.path} answer with in the recorded session${r.sequence ? ` (call ${r.sequence + 1})` : ''}?`, file: 'manifest.json', tags: ['env', 'web', m.name], answerType: 'int', answer: r.status, reference: ref });
  // a field of each distinct JSON object response
  const seen = new Set<string>();
  for (const r of api) {
    if (!r.body || seen.has(r.body.sha256) || tasks.length > 60) continue;
    seen.add(r.body.sha256);
    let v: unknown;
    try { v = JSON.parse(new TextDecoder().decode(files.get(r.body.file))); } catch { continue; }
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    const pick = Object.entries(v as Record<string, unknown>).find(([, x]) => typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean');
    if (!pick) continue;
    const q = r.query.length ? `?${r.query.map(([k, x]) => `${k}=${x}`).join('&')}` : '';
    tasks.push({ id: `${m.name}-field-${r.method.toLowerCase()}-${slug(r.path + q)}-${r.sequence}-${pick[0]}`, question: `In the recorded session, what is "${pick[0]}" in the JSON answer to ${r.method} ${r.path}${q}${r.sequence ? ` (call ${r.sequence + 1})` : ''}?`, file: 'manifest.json', tags: ['env', 'web', 'replay', m.name], answerType: typeof pick[1] === 'number' ? 'int' : 'exact', answer: typeof pick[1] === 'number' && Number.isInteger(pick[1]) ? pick[1] : String(pick[1]), reference: ref, hint: ['web_env_serve'] });
  }
  // assertions the scenario checked with exact text
  const root = capture as Record<string, any>;
  for (const s of (Array.isArray(root?.steps) ? root.steps : []).slice(0, 200)) for (const a of (s.assertions ?? []).slice(0, 20)) {
    const as = a?.assertion;
    if (a?.pass && as && typeof as.selector === 'string' && typeof as.textEquals === 'string') tasks.push({ id: `${m.name}-text-step${s.index}-${slug(as.selector)}`, question: `After step ${s.index} (${s.action}${s.target ? ' ' + s.target : ''}) of the recorded scenario, what text does ${as.selector} show?`, file: 'manifest.json', tags: ['env', 'web', 'scenario', m.name], answerType: 'exact', answer: as.textEquals, reference: `${ref}, scenario assertion` , hint: ['web_env_serve', 'web_browser_scenario'] });
  }
  const ids = new Set<string>();
  return tasks.filter((t) => (ids.has(t.id) ? false : (ids.add(t.id), true)));
}

export interface EnvMatch { route?: EnvRoute; rule: 'exact' | 'query-names' | 'path' | 'template' | 'none'; sequence?: number }

/** Deterministic request matcher over a manifest. Repeated identical requests get the recorded responses in order, then the last one again. */
export class EnvMatcher {
  private counters = new Map<string, number>();
  private byPath = new Map<string, EnvRoute[]>();
  private byTemplate = new Map<string, EnvRoute[]>();
  readonly originHost: string;
  constructor(readonly manifest: EnvManifest) {
    if (manifest?.kind !== 'revlens-env' || !Array.isArray(manifest.routes)) throw new InputError('not a RevLens environment manifest');
    this.originHost = new URL(manifest.origin).host;
    for (const r of manifest.routes) {
      const k = `${r.method} ${r.host}${r.path}`;
      (this.byPath.get(k) ?? this.byPath.set(k, []).get(k)!).push(r);
      const t = `${r.method} ${r.host}${r.template}`;
      (this.byTemplate.get(t) ?? this.byTemplate.set(t, []).get(t)!).push(r);
    }
  }
  reset(): void { this.counters.clear(); }

  /** Match a request. `host` defaults to the recorded origin; a path under /__host/<host>/ selects another recorded origin. */
  match(method: string, rawPath: string, opts: { host?: string; bodySha256?: string } = {}): EnvMatch {
    let host = opts.host ?? this.originHost;
    let pathAndQuery = rawPath;
    if (pathAndQuery.startsWith(ENV_HOST_PREFIX)) {
      const rest = pathAndQuery.slice(ENV_HOST_PREFIX.length);
      const slash = rest.indexOf('/');
      host = decodeURIComponent(slash < 0 ? rest : rest.slice(0, slash));
      pathAndQuery = slash < 0 ? '/' : rest.slice(slash);
    }
    let u: URL;
    try { u = new URL(pathAndQuery, 'http://replay.invalid'); } catch { return { rule: 'none' }; }
    const m = method.toUpperCase();
    const query = [...u.searchParams] as [string, string][];
    const cands = this.byPath.get(`${m} ${host}${u.pathname}`) ?? [];
    const take = (list: EnvRoute[], rule: EnvMatch['rule'], key: string): EnvMatch => {
      const n = this.counters.get(key) ?? 0;
      this.counters.set(key, n + 1);
      const ordered = [...list].sort((a, b) => a.sequence - b.sequence || a.id - b.id);
      const route = ordered[Math.min(n, ordered.length - 1)]!;
      return { route, rule, sequence: n };
    };
    if (cands.length) {
      const q = qKey(query);
      const exactQ = cands.filter((r) => qKey(r.query) === q);
      if (exactQ.length) {
        const withBody = opts.bodySha256 ? exactQ.filter((r) => r.requestBodySha256 === opts.bodySha256) : exactQ.filter((r) => !r.requestBodySha256);
        if (withBody.length) return take(withBody, 'exact', routeKey(m, host, u.pathname, query, opts.bodySha256));
        // same request line, other body: keep the recorded order of that request line
        return take(exactQ, 'exact', routeKey(m, host, u.pathname, query, '*'));
      }
      const names = query.map(([k]) => k).sort().join('&');
      const sameNames = cands.filter((r) => r.query.map(([k]) => k).sort().join('&') === names);
      if (sameNames.length) return take(sameNames, 'query-names', `${m} ${host}${u.pathname}?names=${names}`);
      return take(cands, 'path', `${m} ${host}${u.pathname}?any`);
    }
    const t = this.byTemplate.get(`${m} ${host}${templateOf(u.pathname)}`);
    if (t?.length) return take(t, 'template', `${m} ${host}${templateOf(u.pathname)}?tpl`);
    return { rule: 'none' };
  }
}
