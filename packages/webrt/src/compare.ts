// Compare two runtime captures (a scenario capture, a browser capture or a plain HAR): endpoints, headers,
// scripts, console output and screenshots, with a numeric similarity score. No Node imports.
import { decodePng, diffImages, type Inflate, type PixelDiff } from './png.js';

type AnyObj = Record<string, any>;

export interface CaptureLike {
  har?: { log?: { entries?: AnyObj[] } };
  log?: { entries?: AnyObj[] };
  scripts?: { url: string; sha256?: string; size?: number; inline?: boolean }[];
  console?: { type?: string; text: string }[];
  steps?: { index: number; name?: string; action?: string; screenshot?: { path?: string; sha256?: string } }[];
}

export interface EndpointKey { key: string; method: string; host: string; path: string; count: number; statuses: number[] }

export interface CaptureComparison {
  score: number;
  parts: { name: string; weight: number; similarity: number }[];
  endpoints: { added: EndpointKey[]; removed: EndpointKey[]; common: number; statusChanged: { key: string; before: number[]; after: number[] }[] };
  headers: { key: string; side: 'request' | 'response'; added: string[]; removed: string[]; changed: { name: string; before: string; after: string }[] }[];
  scripts: { added: string[]; removed: string[]; changed: { url: string; before?: string; after?: string; sizeBefore?: number; sizeAfter?: number }[]; same: number; inlineAdded: number; inlineRemoved: number };
  console: { added: string[]; removed: string[] };
  screenshots: { step: number; a?: string; b?: string; diff?: Omit<PixelDiff, 'mask'>; error?: string }[];
}

const SEGMENT_ID = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|[A-Za-z0-9_-]{24,})$/i;
const COMPARED_HEADERS = new Set(['server', 'content-type', 'cache-control', 'content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'access-control-allow-origin', 'access-control-allow-credentials', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'x-powered-by', 'via', 'alt-svc', 'content-encoding', 'accept', 'content-language']);

/** Turn a URL into a stable endpoint pattern: ids, uuids and long tokens become {id}, the query keeps only key names. */
export function endpointPattern(url: string): { host: string; path: string } {
  let u: URL;
  try { u = new URL(url); } catch { return { host: '', path: url.slice(0, 300) }; }
  const path = u.pathname.split('/').slice(0, 40).map((s) => (SEGMENT_ID.test(s) ? '{id}' : s.slice(0, 100))).join('/');
  const keys = [...new Set([...u.searchParams.keys()])].sort().slice(0, 30);
  return { host: u.host.toLowerCase(), path: path + (keys.length ? `?${keys.join('&')}` : '') };
}

function entriesOf(c: CaptureLike): AnyObj[] {
  const e = c.har?.log?.entries ?? c.log?.entries ?? [];
  return Array.isArray(e) ? e.slice(0, 50_000) : [];
}

function headerMap(list: unknown): Map<string, string> {
  const m = new Map<string, string>();
  if (Array.isArray(list)) for (const h of list.slice(0, 300)) if (h && typeof h.name === 'string') m.set(h.name.toLowerCase(), String(h.value ?? '').slice(0, 500));
  return m;
}

function endpointIndex(c: CaptureLike): Map<string, EndpointKey & { req: Map<string, string>; res: Map<string, string> }> {
  const idx = new Map<string, EndpointKey & { req: Map<string, string>; res: Map<string, string> }>();
  for (const e of entriesOf(c)) {
    const url = String(e?.request?.url ?? '');
    if (!/^(?:https?|wss?):/i.test(url)) continue;
    const method = String(e?.request?.method ?? 'GET').toUpperCase().slice(0, 16);
    const { host, path } = endpointPattern(url);
    const key = `${method} ${host}${path}`;
    let rec = idx.get(key);
    if (!rec) { rec = { key, method, host, path, count: 0, statuses: [], req: headerMap(e?.request?.headers), res: headerMap(e?.response?.headers) }; idx.set(key, rec); }
    rec.count++;
    const st = Number(e?.response?.status ?? 0);
    if (!rec.statuses.includes(st) && rec.statuses.length < 10) rec.statuses.push(st);
  }
  return idx;
}

const stripQuery = (u: string) => u.replace(/[?#].*$/, '');
const jaccard = (a: number, b: number, common: number) => (a + b - common === 0 ? 1 : common / (a + b - common));
const pub = (e: EndpointKey): EndpointKey => ({ key: e.key, method: e.method, host: e.host, path: e.path, count: e.count, statuses: e.statuses });

/**
 * Compare two captures. loadImage returns PNG bytes for a screenshot path (Node passes a file reader);
 * without it screenshots are compared by sha256 only.
 */
export async function compareCaptures(a: CaptureLike, b: CaptureLike, opts: { loadImage?: (path: string, side: 'a' | 'b') => Promise<Uint8Array>; inflate?: Inflate; threshold?: number; limit?: number } = {}): Promise<CaptureComparison> {
  const lim = Math.max(1, Math.min(opts.limit ?? 500, 10_000));
  const ea = endpointIndex(a), eb = endpointIndex(b);
  const added = [...eb.values()].filter((e) => !ea.has(e.key));
  const removed = [...ea.values()].filter((e) => !eb.has(e.key));
  const commonKeys = [...ea.keys()].filter((k) => eb.has(k));
  const statusChanged: CaptureComparison['endpoints']['statusChanged'] = [];
  const headers: CaptureComparison['headers'] = [];
  let headerChecks = 0, headerSame = 0;
  for (const k of commonKeys) {
    const x = ea.get(k)!, y = eb.get(k)!;
    const sx = [...x.statuses].sort().join(','), sy = [...y.statuses].sort().join(',');
    if (sx !== sy) statusChanged.push({ key: k, before: x.statuses, after: y.statuses });
    for (const side of ['request', 'response'] as const) {
      const hx = side === 'request' ? x.req : x.res, hy = side === 'request' ? y.req : y.res;
      const addedH = [...hy.keys()].filter((n) => !hx.has(n) && !n.startsWith(':')).sort();
      const removedH = [...hx.keys()].filter((n) => !hy.has(n) && !n.startsWith(':')).sort();
      const changed: { name: string; before: string; after: string }[] = [];
      for (const n of COMPARED_HEADERS) if (hx.has(n) && hy.has(n) && hx.get(n) !== hy.get(n)) changed.push({ name: n, before: hx.get(n)!, after: hy.get(n)! });
      const names = new Set([...hx.keys(), ...hy.keys()]);
      headerChecks += names.size; headerSame += names.size - addedH.length - removedH.length - changed.length;
      if (addedH.length || removedH.length || changed.length) headers.push({ key: k, side, added: addedH, removed: removedH, changed });
    }
  }
  // scripts
  const sa = new Map<string, { sha?: string; size?: number }>(), sb = new Map<string, { sha?: string; size?: number }>();
  const ia = new Set<string>(), ib = new Set<string>();
  for (const s of a.scripts ?? []) { if (s.inline) ia.add(s.sha256 ?? ''); else sa.set(stripQuery(s.url), { sha: s.sha256, size: s.size }); }
  for (const s of b.scripts ?? []) { if (s.inline) ib.add(s.sha256 ?? ''); else sb.set(stripQuery(s.url), { sha: s.sha256, size: s.size }); }
  const sAdded = [...sb.keys()].filter((u) => !sa.has(u));
  const sRemoved = [...sa.keys()].filter((u) => !sb.has(u));
  const changed: CaptureComparison['scripts']['changed'] = [];
  let same = 0;
  for (const [u, x] of sa) { const y = sb.get(u); if (!y) continue; if (x.sha && y.sha && x.sha !== y.sha) changed.push({ url: u, before: x.sha, after: y.sha, sizeBefore: x.size, sizeAfter: y.size }); else same++; }
  let inlineSame = 0; for (const h of ia) if (ib.has(h)) inlineSame++;
  // console
  const ca = new Set((a.console ?? []).map((m) => `${m.type ?? 'log'}: ${m.text}`.slice(0, 500)));
  const cb = new Set((b.console ?? []).map((m) => `${m.type ?? 'log'}: ${m.text}`.slice(0, 500)));
  // screenshots by step index
  const shots: CaptureComparison['screenshots'] = [];
  const stepsA = new Map((a.steps ?? []).map((s) => [s.index, s] as const));
  const stepsB = new Map((b.steps ?? []).map((s) => [s.index, s] as const));
  const shotSims: number[] = [];
  for (const i of [...new Set([...stepsA.keys(), ...stepsB.keys()])].sort((x, y) => x - y).slice(0, 200)) {
    const x = stepsA.get(i)?.screenshot, y = stepsB.get(i)?.screenshot;
    if (!x?.path && !y?.path) continue;
    const rec: CaptureComparison['screenshots'][number] = { step: i, a: x?.path, b: y?.path };
    if (!x?.path || !y?.path) { rec.error = 'screenshot only on one side'; shotSims.push(0); shots.push(rec); continue; }
    if (x.sha256 && y.sha256 && x.sha256 === y.sha256) {
      rec.diff = { widthA: 0, heightA: 0, widthB: 0, heightB: 0, sizeMatches: true, totalPixels: 0, diffPixels: 0, similarity: 1, meanAbsDiff: 0, threshold: opts.threshold ?? 0, bbox: null };
      shotSims.push(1); shots.push(rec); continue;
    }
    if (!opts.loadImage) { rec.error = 'screenshots differ by sha256; pass an image loader for a pixel diff'; shotSims.push(0); shots.push(rec); continue; }
    try {
      const [ia2, ib2] = await Promise.all([opts.loadImage(x.path, 'a'), opts.loadImage(y.path, 'b')]);
      const d = diffImages(await decodePng(ia2, opts.inflate), await decodePng(ib2, opts.inflate), { threshold: opts.threshold });
      const { mask: _m, ...rest } = d;
      rec.diff = rest; shotSims.push(d.similarity);
    } catch (e) { rec.error = (e as Error).message.slice(0, 200); }
    shots.push(rec);
  }
  const parts: CaptureComparison['parts'] = [];
  if (ea.size || eb.size) parts.push({ name: 'endpoints', weight: 0.35, similarity: jaccard(ea.size, eb.size, commonKeys.length) });
  if (headerChecks) parts.push({ name: 'headers', weight: 0.15, similarity: headerSame / headerChecks });
  if (sa.size || sb.size || ia.size || ib.size) parts.push({ name: 'scripts', weight: 0.25, similarity: jaccard(sa.size + ia.size, sb.size + ib.size, same + inlineSame) });
  if (ca.size || cb.size) parts.push({ name: 'console', weight: 0.05, similarity: jaccard(ca.size, cb.size, [...ca].filter((m) => cb.has(m)).length) });
  if (shotSims.length) parts.push({ name: 'screenshots', weight: 0.2, similarity: shotSims.reduce((s, x) => s + x, 0) / shotSims.length });
  const wsum = parts.reduce((s, p) => s + p.weight, 0);
  const score = wsum ? Math.round((parts.reduce((s, p) => s + p.weight * p.similarity, 0) / wsum) * 10_000) / 10_000 : 1;
  for (const p of parts) p.similarity = Math.round(p.similarity * 10_000) / 10_000;
  return {
    score, parts,
    endpoints: { added: added.slice(0, lim).map(pub), removed: removed.slice(0, lim).map(pub), common: commonKeys.length, statusChanged: statusChanged.slice(0, lim) },
    headers: headers.slice(0, lim),
    scripts: { added: sAdded.slice(0, lim), removed: sRemoved.slice(0, lim), changed: changed.slice(0, lim), same, inlineAdded: [...ib].filter((h) => !ia.has(h)).length, inlineRemoved: [...ia].filter((h) => !ib.has(h)).length },
    console: { added: [...cb].filter((m) => !ca.has(m)).slice(0, lim), removed: [...ca].filter((m) => !cb.has(m)).slice(0, lim) },
    screenshots: shots,
  };
}
