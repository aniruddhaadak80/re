// HAR 1.2 analysis: hosts, endpoints, status and type breakdowns, redirects, auth and cookies
// (values redacted), missing security headers, mixed content, and JavaScript found in responses.
import { InputError, base64ToBytes, decodeUtf8 } from './util.js';
import { findEndpoints } from './js/endpoints.js';

interface HarHeader { name: string; value: string }
interface HarEntry {
  startedDateTime?: string; time?: number; serverIPAddress?: string; _resourceType?: string;
  request?: { method?: string; url?: string; httpVersion?: string; headers?: HarHeader[]; cookies?: { name: string }[]; postData?: { mimeType?: string; text?: string }; bodySize?: number };
  response?: { status?: number; statusText?: string; headers?: HarHeader[]; cookies?: { name: string }[]; redirectURL?: string; bodySize?: number; _transferSize?: number; content?: { size?: number; mimeType?: string; text?: string; encoding?: string } };
  timings?: Record<string, number>;
  _webSocketMessages?: { type: string; time: number; opcode: number; data: string }[];
}
interface Har { log?: { version?: string; creator?: { name?: string; version?: string }; browser?: { name?: string; version?: string }; pages?: { id: string; title?: string; startedDateTime?: string }[]; entries?: HarEntry[] } }

export interface HarSummary {
  version?: string;
  creator?: string;
  browser?: string;
  pages: { id: string; title?: string }[];
  entries: number;
  timeRange?: { first: string; last: string };
  totalResponseBytes: number;
  methods: Record<string, number>;
  statuses: Record<string, number>;
  mimeTypes: Record<string, number>;
  hosts: { host: string; requests: number; bytes: number; thirdParty: boolean }[];
  endpoints: { method: string; pattern: string; host: string; count: number; statuses: number[]; firstEntry: number }[];
  redirects: { from: string; to: string; status: number; entry: number }[];
  slowest: { url: string; time: number; entry: number }[];
  authHeaders: { entry: number; header: string; scheme?: string }[];
  cookiesSet: { name: string; host: string; flags: string[] }[];
  missingSecurityHeaders: { url: string; entry: number; missing: string[] }[];
  mixedContent: { url: string; entry: number }[];
  webSockets: { url: string; entry: number; messages: number }[];
  scripts: { url: string; entry: number; size: number; endpoints?: { calls: number; urls: string[]; dynamicCode: number } }[];
  warnings: string[];
}

const SENSITIVE = /^(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|api-key|apikey|x-amz-security-token)$/i;

function hostOf(u: string): string { try { return new URL(u).host; } catch { return ''; } }
function siteOf(host: string): string { const parts = host.replace(/:\d+$/, '').split('.'); return parts.slice(-2).join('.'); }
function pattern(u: string): string {
  try {
    const url = new URL(u);
    const path = url.pathname.split('/').map((seg) => (/^\d+$/.test(seg) ? '{id}' : /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) ? '{uuid}' : /^[0-9a-f]{24,}$/i.test(seg) ? '{hex}' : seg)).join('/');
    return path + (url.search ? '?' + [...url.searchParams.keys()].sort().join('&') : '');
  } catch { return u.slice(0, 200); }
}
const hdr = (hs: HarHeader[] | undefined, name: string) => hs?.find((h) => h.name.toLowerCase() === name)?.value;

/** Summarize a HAR file. Header and cookie values are never returned, only names and schemes. */
export function analyzeHar(input: string | Uint8Array | Har, opts: { analyzeScripts?: boolean; maxScripts?: number; limit?: number } = {}): HarSummary {
  let har: Har;
  if (typeof input === 'object' && !(input instanceof Uint8Array)) har = input;
  else {
    const text = typeof input === 'string' ? input : decodeUtf8(input);
    try { har = JSON.parse(text.replace(/^\uFEFF/, '')) as Har; } catch (e) { throw new InputError(`HAR is not valid JSON: ${(e as Error).message}`); }
  }
  if (!har.log || !Array.isArray(har.log.entries)) throw new InputError('not a HAR file (missing log.entries)');
  const L = opts.limit ?? 200;
  const entries = har.log.entries.slice(0, 200_000);
  const s: HarSummary = { version: har.log.version, creator: har.log.creator ? `${har.log.creator.name ?? ''} ${har.log.creator.version ?? ''}`.trim() : undefined, browser: har.log.browser ? `${har.log.browser.name ?? ''} ${har.log.browser.version ?? ''}`.trim() : undefined, pages: (har.log.pages ?? []).slice(0, 100).map((p) => ({ id: p.id, title: p.title })), entries: entries.length, totalResponseBytes: 0, methods: {}, statuses: {}, mimeTypes: {}, hosts: [], endpoints: [], redirects: [], slowest: [], authHeaders: [], cookiesSet: [], missingSecurityHeaders: [], mixedContent: [], webSockets: [], scripts: [], warnings: [] };
  const firstUrl = entries.find((e) => e.request?.url)?.request?.url ?? '';
  const mainSite = siteOf(hostOf(firstUrl));
  const pageHttps = /^https:/i.test(entries.find((e) => (e.response?.content?.mimeType ?? '').includes('html') && e.response?.status === 200)?.request?.url ?? firstUrl);
  const hosts = new Map<string, { requests: number; bytes: number }>();
  const eps = new Map<string, HarSummary['endpoints'][number]>();
  let first: string | undefined, last: string | undefined;
  const bump = (o: Record<string, number>, k: string) => { o[k] = (o[k] ?? 0) + 1; };
  let scriptsAnalyzed = 0;
  entries.forEach((e, i) => {
    const req = e.request ?? {}, res = e.response ?? {};
    const url = String(req.url ?? '');
    const method = String(req.method ?? 'GET').toUpperCase();
    const host = hostOf(url);
    const status = Number(res.status ?? 0);
    const mime = (res.content?.mimeType ?? '').split(';')[0]?.trim() || 'unknown';
    const size = Math.max(0, Number(res.content?.size ?? 0) || 0);
    if (e.startedDateTime) { if (!first || e.startedDateTime < first) first = e.startedDateTime; if (!last || e.startedDateTime > last) last = e.startedDateTime; }
    bump(s.methods, method); bump(s.statuses, String(status)); bump(s.mimeTypes, mime);
    s.totalResponseBytes += size;
    const h = hosts.get(host) ?? { requests: 0, bytes: 0 }; h.requests++; h.bytes += size; hosts.set(host, h);
    const isApi = /json|xml|graphql|protobuf|grpc/i.test(mime) || e._resourceType === 'xhr' || e._resourceType === 'fetch' || (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS');
    if (isApi) {
      const key = `${method} ${host}${pattern(url)}`;
      const ep = eps.get(key) ?? { method, pattern: pattern(url), host, count: 0, statuses: [], firstEntry: i };
      ep.count++; if (!ep.statuses.includes(status)) ep.statuses.push(status);
      eps.set(key, ep);
    }
    if (status >= 300 && status < 400) {
      const loc = res.redirectURL || hdr(res.headers, 'location') || '';
      s.redirects.push({ from: url, to: loc, status, entry: i });
    }
    if (typeof e.time === 'number' && e.time >= 0) s.slowest.push({ url, time: e.time, entry: i });
    for (const hh of req.headers ?? []) {
      if (SENSITIVE.test(hh.name) && hh.name.toLowerCase() !== 'cookie') s.authHeaders.push({ entry: i, header: hh.name, scheme: /^(Bearer|Basic|Digest|Negotiate|AWS4-HMAC-SHA256|Token)\b/i.exec(hh.value ?? '')?.[1] });
    }
    for (const hh of res.headers ?? []) {
      if (hh.name.toLowerCase() !== 'set-cookie') continue;
      for (const line of String(hh.value ?? '').split('\n')) {
        const name = line.split('=')[0]?.trim();
        if (!name) continue;
        const flags = line.split(';').slice(1).map((x) => x.trim().split('=')[0]?.toLowerCase() ?? '').filter((x) => ['secure', 'httponly', 'samesite', 'domain', 'path', 'max-age', 'expires', 'partitioned'].includes(x));
        s.cookiesSet.push({ name, host, flags });
      }
    }
    if (mime === 'text/html' && status === 200) {
      const missing = ['content-security-policy', 'x-content-type-options', 'strict-transport-security', 'x-frame-options'].filter((n) => !hdr(res.headers, n) && !(n === 'x-frame-options' && /frame-ancestors/i.test(hdr(res.headers, 'content-security-policy') ?? '')) && !(n === 'strict-transport-security' && !/^https:/i.test(url)));
      if (missing.length) s.missingSecurityHeaders.push({ url, entry: i, missing });
    }
    if (pageHttps && /^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.)/i.test(url) && !(status >= 300 && status < 400)) s.mixedContent.push({ url, entry: i });
    if (e._webSocketMessages || /^wss?:/i.test(url) || hdr(req.headers, 'upgrade')?.toLowerCase() === 'websocket') s.webSockets.push({ url, entry: i, messages: e._webSocketMessages?.length ?? 0 });
    if (/javascript|ecmascript/i.test(mime) || /\.m?js(\?|$)/.test(url)) {
      const sc: HarSummary['scripts'][number] = { url, entry: i, size };
      const text = res.content?.text;
      if (opts.analyzeScripts !== false && typeof text === 'string' && scriptsAnalyzed < (opts.maxScripts ?? 50)) {
        try {
          const code = res.content?.encoding === 'base64' ? decodeUtf8(base64ToBytes(text)) : text;
          if (code.length < 8 * 1024 * 1024) {
            const ep = findEndpoints(code, { maxItems: 500 });
            sc.endpoints = { calls: ep.calls.length, urls: [...new Set([...ep.calls.map((c) => c.url).filter((x): x is string => !!x), ...ep.urls.map((u) => u.value)])].slice(0, 100), dynamicCode: ep.dynamicCode.length };
            scriptsAnalyzed++;
          }
        } catch (err) { s.warnings.push(`script ${url}: ${(err as Error).message.slice(0, 200)}`); }
      }
      s.scripts.push(sc);
    }
  });
  if (first && last) s.timeRange = { first, last };
  s.hosts = [...hosts.entries()].map(([host, v]) => ({ host, ...v, thirdParty: !!mainSite && siteOf(host) !== mainSite })).sort((a, b) => b.requests - a.requests).slice(0, L);
  s.endpoints = [...eps.values()].sort((a, b) => b.count - a.count).slice(0, L);
  s.slowest = s.slowest.sort((a, b) => b.time - a.time).slice(0, 20);
  s.redirects = s.redirects.slice(0, L); s.authHeaders = s.authHeaders.slice(0, L); s.cookiesSet = s.cookiesSet.slice(0, L); s.missingSecurityHeaders = s.missingSecurityHeaders.slice(0, L); s.mixedContent = s.mixedContent.slice(0, L); s.webSockets = s.webSockets.slice(0, L); s.scripts = s.scripts.slice(0, L);
  return s;
}

export function looksLikeHar(text: string): boolean {
  return /^\s*\{\s*"log"\s*:\s*\{/.test(text.slice(0, 200)) && text.includes('"entries"');
}
