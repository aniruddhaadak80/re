// Join the endpoints JavaScript names statically with the requests a HAR or scenario capture observed.
// Static templates (`${API}/items/${id}`) are matched against observed URLs segment by segment, so the
// result says which endpoints the app used (matched, with the values seen for each parameter), which
// ones the code names but never called (dead, gated or hidden), and which requests have no static
// source (paths built at run time, third-party scripts, server redirects). Browser safe.
import { findEndpoints, type EndpointReport } from './js/endpoints.js';
import { base64ToBytes, decodeUtf8, InputError } from './util.js';

export interface StaticEndpoint {
  key: string;
  method?: string;
  /** host when the template is absolute */
  host?: string;
  /** path template with {p1}, {p2} for the dynamic parts */
  template: string;
  query: string[];
  /** the template started with a dynamic base (unknown origin) */
  dynamicBase: boolean;
  sites: { script: string; line: number; column: number; api: string }[];
}
export interface ObservedEndpoint {
  key: string;
  method: string;
  host: string;
  /** path template inferred from the requests: ids, uuids, hashes and sibling variance become {id} or {param} */
  template: string;
  query: string[];
  count: number;
  statuses: number[];
  entries: number[];
  initiators: string[];
  resourceTypes: string[];
}
export interface JoinedEndpoint {
  static: StaticEndpoint;
  observed: ObservedEndpoint[];
  /** values seen for each static parameter, in order {p1}, {p2}, ... (at most 5 each) */
  params: Record<string, string[]>;
  queryObserved: string[];
  queryOnlyStatic: string[];
}
export interface EndpointJoin {
  summary: { static: number; observed: number; matched: number; staticOnly: number; observedOnly: number; staticCoverage: number; observedExplained: number };
  matched: JoinedEndpoint[];
  staticOnly: (StaticEndpoint & { reason: 'never-requested' | 'other-host' | 'method-differs' })[];
  observedOnly: (ObservedEndpoint & { reason: 'no-static-source' | 'document-or-asset' })[];
  warnings: string[];
}

interface Entry { method: string; url: URL; status: number; type?: string; mime?: string; initiator?: string; index: number }

const ASSET = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map|html?)$/i;
const ID_SEG = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|[A-Za-z0-9_-]{24,})$/i;

function splitPath(p: string): string[] { return p.split('/').filter((s, i, a) => s !== '' || (i > 0 && i === a.length - 1 && false)); }

/** Static endpoint templates from scripts. Literal URLs found outside calls count too when they look like API paths. */
export function staticEndpoints(scripts: { url?: string; code: string }[], opts: { maxScripts?: number } = {}): { endpoints: StaticEndpoint[]; warnings: string[] } {
  const byKey = new Map<string, StaticEndpoint>();
  const warnings: string[] = [];
  for (const s of scripts.slice(0, opts.maxScripts ?? 500)) {
    let r: EndpointReport;
    try { r = findEndpoints(s.code, { maxItems: 5000 }); } catch (e) { warnings.push(`${s.url ?? 'script'}: ${(e as Error).message.slice(0, 160)}`); continue; }
    const add = (url: string | undefined, method: string | undefined, site: { line: number; column: number }, api: string) => {
      if (!url || !/[/]/.test(url)) return;
      if (/^(?:data|blob|javascript|about|chrome-extension):/i.test(url)) return;
      const t = toTemplate(url);
      if (!t) return;
      const key = `${method ?? '*'} ${t.host ?? ''}${t.template}`;
      const e = byKey.get(key) ?? byKey.set(key, { key, method, host: t.host, template: t.template, query: t.query, dynamicBase: t.dynamicBase, sites: [] }).get(key)!;
      for (const q of t.query) if (!e.query.includes(q)) e.query.push(q);
      if (e.sites.length < 20) e.sites.push({ script: s.url ?? 'inline', line: site.line, column: site.column, api });
    };
    const inCalls = new Set<number>();
    for (const c of r.calls) { if (c.kind === 'websocket' || c.kind === 'worker' || c.kind === 'script') continue; add(c.url, c.method, c, c.api); inCalls.add(c.offset); }
    for (const u of r.urls) {
      // literals that are also call arguments were added with their method above
      if (r.calls.some((c) => c.url === u.value)) continue;
      if (u.kind === 'websocket') continue;
      add(u.value, undefined, u, 'literal');
    }
  }
  // a bare literal that is only the base of other templates ("/api" in `${API}/items`) is not an endpoint
  const all = [...byKey.values()];
  const endpoints = all.filter((e) => !(e.sites.every((x) => x.api === 'literal') && all.some((o) => o !== e && (o.host ?? '') === (e.host ?? '') && o.template.startsWith(e.template === '/' ? '/' : e.template + '/'))));
  return { endpoints, warnings };
}

/** Turn a static URL shape with ${} holes into a host, a path template with {p1}.. and query names. */
function toTemplate(url: string): { host?: string; template: string; query: string[]; dynamicBase: boolean } | undefined {
  let rest = url.trim();
  let host: string | undefined;
  let dynamicBase = false;
  const abs = /^(?:https?|wss?):\/\/([^/?#]*)/i.exec(rest);
  if (abs) { host = abs[1]!.toLowerCase(); rest = rest.slice(abs[0].length) || '/'; if (host.includes('${}')) { host = undefined; dynamicBase = true; } }
  else if (rest.startsWith('${}')) { dynamicBase = true; rest = rest.slice(3); }
  else if (rest.startsWith('//')) { const h = /^\/\/([^/?#]*)/.exec(rest); host = h?.[1]; rest = rest.slice((h?.[0].length ?? 2)) || '/'; }
  else if (!rest.startsWith('/')) { if (!/^[\w.-]+\//.test(rest)) return undefined; rest = '/' + rest; dynamicBase = true; }
  const qi = rest.indexOf('?');
  const path = (qi >= 0 ? rest.slice(0, qi) : rest).split('#')[0]!;
  const query = qi >= 0 ? rest.slice(qi + 1).split('&').map((kv) => kv.split('=')[0]!).filter((k) => k && !k.includes('${}')).slice(0, 50) : [];
  let n = 0;
  const segs = path.split('/').map((seg) => (seg.includes('${}') ? (seg === '${}' ? `{p${++n}}` : seg.replace(/\$\{\}/g, () => `{p${++n}}`)) : seg));
  let template = segs.join('/') || '/';
  if (!template.startsWith('/')) template = '/' + template;
  if (template.length > 1 && template.endsWith('/')) template = template.slice(0, -1);
  return { host, template, query: [...new Set(query)], dynamicBase };
}

function entriesOf(input: unknown): { entries: Entry[]; scripts: { url: string; code: string }[] } {
  const root = input as Record<string, any>;
  const list: any[] = Array.isArray(root?.har?.log?.entries) ? root.har.log.entries : Array.isArray(root?.log?.entries) ? root.log.entries : Array.isArray(root?.entries) ? root.entries : [];
  if (!list.length && !root?.log && !root?.har) throw new InputError('not a HAR or capture (no log.entries)');
  const entries: Entry[] = [];
  const scripts: { url: string; code: string }[] = [];
  list.slice(0, 200_000).forEach((e, index) => {
    const raw = String(e?.request?.url ?? '');
    let url: URL;
    try { url = new URL(raw); } catch { return; }
    if (!/^https?:$/.test(url.protocol)) return;
    const mime = String(e?.response?.content?.mimeType ?? '');
    const init = e?._initiator;
    const initiator = typeof init === 'string' ? init : init?.type ? `${init.type}${init.url ? ' ' + init.url : ''}${init.lineNumber !== undefined ? ':' + (Number(init.lineNumber) + 1) : ''}` : undefined;
    entries.push({ method: String(e?.request?.method ?? 'GET').toUpperCase(), url, status: Number(e?.response?.status ?? 0), type: e?._resourceType, mime, initiator, index });
    const text = e?.response?.content?.text;
    if (typeof text === 'string' && (/javascript|ecmascript/i.test(mime) || /\.m?js$/i.test(url.pathname)) && scripts.length < 200) {
      try { scripts.push({ url: url.href, code: e.response.content.encoding === 'base64' ? decodeUtf8(base64ToBytes(text)) : text }); } catch { /* skip */ }
    }
  });
  return { entries, scripts };
}

/** Group observed requests into templates: id-like segments and segments that vary among siblings become parameters. */
export function observedEndpoints(entries: Entry[]): ObservedEndpoint[] {
  const groups = new Map<string, { method: string; host: string; segs: string[][]; entries: Entry[] }>();
  for (const e of entries) {
    const segs = e.url.pathname.split('/').slice(1, 41);
    const shape = segs.map((s) => (ID_SEG.test(s) ? '{id}' : s));
    const key = `${e.method} ${e.url.host} ${shape.length}`;
    const g = groups.get(key) ?? groups.set(key, { method: e.method, host: e.url.host, segs: [], entries: [] }).get(key)!;
    g.segs.push(segs); g.entries.push(e);
  }
  const out = new Map<string, ObservedEndpoint>();
  for (const g of groups.values()) {
    // sibling variance: within one method, host and depth, a position whose other positions agree but whose value varies is a parameter
    const n = g.segs[0]!.length;
    const templ = g.segs.map((segs) => segs.map((s) => (ID_SEG.test(s) ? '{id}' : s)));
    for (let pos = 0; pos < n; pos++) {
      const byRest = new Map<string, Set<string>>();
      templ.forEach((t, i) => { const k = t.filter((_, j) => j !== pos).join('/'); const set = byRest.get(k) ?? byRest.set(k, new Set()).get(k)!; set.add(g.segs[i]![pos]!); });
      // only when the values look like data (digits or long tokens), so /api/items and /api/session stay apart
      const dataLike = (v: Set<string>) => [...v].filter((x) => /\d/.test(x) || x.length >= 12).length * 2 >= v.size;
      for (const [k, vals] of byRest) if (vals.size >= 3 && pos > 0 && dataLike(vals)) templ.forEach((t, i) => { if (t.filter((_, j) => j !== pos).join('/') === k && t[pos] !== '{id}') templ[i]![pos] = '{param}'; });
    }
    templ.forEach((t, i) => {
      const e = g.entries[i]!;
      const template = '/' + t.join('/');
      const key = `${g.method} ${g.host}${template}`;
      const o = out.get(key) ?? out.set(key, { key, method: g.method, host: g.host, template, query: [], count: 0, statuses: [], entries: [], initiators: [], resourceTypes: [] }).get(key)!;
      o.count++;
      if (!o.statuses.includes(e.status)) o.statuses.push(e.status);
      if (o.entries.length < 50) o.entries.push(e.index);
      for (const q of e.url.searchParams.keys()) if (!o.query.includes(q) && o.query.length < 50) o.query.push(q);
      if (e.initiator && o.initiators.length < 10 && !o.initiators.includes(e.initiator)) o.initiators.push(e.initiator);
      if (e.type && !o.resourceTypes.includes(e.type)) o.resourceTypes.push(e.type);
    });
  }
  return [...out.values()];
}

/** Does a static template match a concrete path? Returns the values bound to {pN}, or undefined. */
export function matchTemplate(template: string, path: string, dynamicBase: boolean): string[] | undefined {
  const t = template.split('/').slice(1), p = path.split('/').slice(1);
  if (t.length === 1 && t[0] === '' && p.length === 1 && p[0] === '') return [];
  const off = p.length - t.length;
  if (off < 0 || (!dynamicBase && off !== 0)) return undefined;
  const vals: string[] = [];
  for (let i = 0; i < t.length; i++) {
    const ts = t[i]!, ps = p[i + off]!;
    if (!ts.includes('{p')) { if (ts !== ps) return undefined; continue; }
    // a segment like "user-{p1}.json": literal pieces must line up, holes take the rest and are never empty
    const parts = ts.split(/\{p\d+\}/);
    if (!ps.startsWith(parts[0]!)) return undefined;
    let at = parts[0]!.length;
    for (let k = 1; k < parts.length; k++) {
      const lit = parts[k]!;
      let j: number;
      if (k === parts.length - 1) { if (!ps.endsWith(lit) || ps.length - lit.length <= at) return undefined; j = ps.length - lit.length; }
      else { j = lit ? ps.indexOf(lit, at + 1) : at + 1; if (j < 0 || j > ps.length) return undefined; }
      if (j <= at) return undefined;
      vals.push(decodeURIComponentSafe(ps.slice(at, j)));
      at = j + lit.length;
    }
    if (at !== ps.length) return undefined;
  }
  return vals;
}
function decodeURIComponentSafe(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }

/**
 * Join static endpoints with observed requests. `capture` is a HAR, a RevLens scenario or browser capture.
 * Without `scripts`, the JavaScript bodies stored in the capture are analysed.
 */
export function compareStaticAndObservedEndpoints(input: { capture: unknown; scripts?: { url?: string; code: string }[]; origin?: string; includeAssets?: boolean; limit?: number }): EndpointJoin {
  const { entries, scripts: harScripts } = entriesOf(input.capture);
  const scripts = input.scripts?.length ? input.scripts : harScripts;
  const warnings: string[] = [];
  if (!scripts.length) warnings.push('no scripts given and none stored in the capture; every observed request is observed-only');
  const st = staticEndpoints(scripts);
  warnings.push(...st.warnings);
  const pageHost = input.origin ? (() => { try { return new URL(input.origin!).host; } catch { return undefined; } })() : entries.find((e) => /html/i.test(e.mime ?? '') || e.type === 'document')?.url.host ?? entries[0]?.url.host;
  const apiLike = (e: Entry) => input.includeAssets || !(e.type === 'document' || e.type === 'stylesheet' || e.type === 'script' || e.type === 'image' || e.type === 'font' || ((!e.type || e.type === 'other') && ASSET.test(e.url.pathname) && !/json/i.test(e.mime ?? '')) || (e.url.pathname === '/' && /html/i.test(e.mime ?? '')));
  const obs = observedEndpoints(entries);
  const matched: JoinedEndpoint[] = [];
  const usedObs = new Set<string>();
  const staticOnly: EndpointJoin['staticOnly'] = [];
  for (const s of st.endpoints) {
    const hits: ObservedEndpoint[] = [];
    const params: Record<string, string[]> = {};
    let otherHost = false, otherMethod = false;
    for (const o of obs) {
      const hostOk = s.host ? s.host === o.host : s.dynamicBase || !pageHost || o.host === pageHost;
      // check every concrete request in the group, so template values are real
      const group = entries.filter((e) => o.entries.includes(e.index));
      let any = false;
      for (const e of group) {
        const vals = matchTemplate(s.template, e.url.pathname, s.dynamicBase);
        if (!vals) continue;
        if (!hostOk) { otherHost = true; continue; }
        if (s.method && s.method !== e.method) { otherMethod = true; continue; }
        any = true;
        vals.forEach((v, i) => { const k = `p${i + 1}`; const l = params[k] ?? (params[k] = []); if (l.length < 5 && !l.includes(v)) l.push(v); });
      }
      if (any) { hits.push(o); usedObs.add(o.key); }
    }
    if (hits.length) {
      const seenQ = new Set(hits.flatMap((h) => h.query));
      matched.push({ static: s, observed: hits, params, queryObserved: [...seenQ].sort(), queryOnlyStatic: s.query.filter((q) => !seenQ.has(q)) });
    } else staticOnly.push({ ...s, reason: otherMethod ? 'method-differs' : otherHost ? 'other-host' : 'never-requested' });
  }
  const observedOnly: EndpointJoin['observedOnly'] = [];
  for (const o of obs) {
    if (usedObs.has(o.key)) continue;
    const group = entries.filter((e) => o.entries.includes(e.index));
    const isAsset = group.every((e) => !apiLike(e));
    if (isAsset && !input.includeAssets) continue;
    observedOnly.push({ ...o, reason: isAsset ? 'document-or-asset' : 'no-static-source' });
  }
  const apiObserved = obs.filter((o) => usedObs.has(o.key) || observedOnly.some((x) => x.key === o.key));
  const lim = Math.max(1, Math.min(input.limit ?? 500, 10_000));
  return {
    summary: {
      static: st.endpoints.length, observed: apiObserved.length, matched: matched.length, staticOnly: staticOnly.length, observedOnly: observedOnly.length,
      staticCoverage: st.endpoints.length ? Math.round((matched.length / st.endpoints.length) * 1000) / 1000 : 0,
      observedExplained: apiObserved.length ? Math.round((usedObs.size / apiObserved.length) * 1000) / 1000 : 0,
    },
    matched: matched.slice(0, lim), staticOnly: staticOnly.slice(0, lim), observedOnly: observedOnly.slice(0, lim), warnings: warnings.slice(0, 100),
  };
}
void splitPath;
