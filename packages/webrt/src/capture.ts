// Browser runtime capture with Playwright (optional peer dependency, Node only).
// Records network requests as HAR 1.2 entries, loaded scripts with source, console messages, cookie and
// storage key names, WebSocket frames and service workers, then runs the static JS analysis on the scripts.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findEndpoints, type EndpointReport } from './js/endpoints.js';
import { unpackBundle } from './js/bundle.js';
import { analyzeHar, type HarSummary } from './har.js';
import { InputError } from './util.js';

export interface CaptureOptions {
  /** total budget for the whole capture in ms (default 45000, max 300000) */
  timeoutMs?: number;
  /** extra time to wait after load for late requests (default 2000) */
  settleMs?: number;
  browser?: 'chromium' | 'firefox' | 'webkit';
  headless?: boolean;
  executablePath?: string;
  userAgent?: string;
  maxRequests?: number;
  maxScripts?: number;
  maxScriptBytes?: number;
  maxConsole?: number;
  maxFrames?: number;
  /** run endpoint and bundle analysis over captured scripts (default true) */
  analyze?: boolean;
  /** allow non-http(s) URLs such as file: (default false) */
  allowFileUrls?: boolean;
}

export interface CapturedScript { url: string; inline: boolean; size: number; sha256?: string; truncated: boolean; source?: string; endpoints?: Pick<EndpointReport, 'counts' | 'hosts' | 'envNames' | 'featureFlags'> & { calls: { api: string; url?: string; method?: string; line: number }[]; dynamicCode: { api: string; line: number }[] }; bundler?: string; modules?: number }

export interface CaptureResult {
  url: string;
  finalUrl?: string;
  title?: string;
  browser: string;
  browserVersion?: string;
  startedAt: string;
  durationMs: number;
  har: { log: { version: string; creator: { name: string; version: string }; pages: unknown[]; entries: unknown[] } };
  scripts: CapturedScript[];
  console: { type: string; text: string; location?: string }[];
  pageErrors: string[];
  cookies: { name: string; domain: string; path: string; secure: boolean; httpOnly: boolean; sameSite: string; session: boolean }[];
  storage: { localStorage: string[]; sessionStorage: string[]; indexedDB: string[] };
  webSockets: { url: string; frames: { dir: 'sent' | 'received'; at: number; size: number; preview: string }[] }[];
  serviceWorkers: string[];
  failedRequests: { url: string; error: string }[];
  summary?: HarSummary;
  warnings: string[];
}

const SENSITIVE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;
const redact = (headers: Record<string, string>) => Object.entries(headers).slice(0, 200).map(([name, value]) => ({ name, value: SENSITIVE.test(name) ? '[redacted]' : String(value).slice(0, 2000) }));

async function sha256Hex(s: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(s).digest('hex');
}

/** Open a URL in a real browser through Playwright and record what the page loads and does. Node only. */
export async function browserCapture(url: string, opts: CaptureOptions = {}): Promise<CaptureResult> {
  let parsed: URL;
  try { parsed = new URL(url); } catch { throw new InputError(`not a valid URL: ${url}`); }
  if (!/^https?:$/.test(parsed.protocol) && !(opts.allowFileUrls && parsed.protocol === 'file:')) throw new InputError('only http and https URLs can be captured');
  let pw: any;
  try { pw = await import('playwright' as string); }
  catch { throw new InputError('browser capture needs the optional "playwright" package: npm i playwright && npx playwright install chromium'); }
  const budget = Math.max(5_000, Math.min(opts.timeoutMs ?? 45_000, 300_000));
  const t0 = Date.now();
  const deadline = t0 + budget;
  const left = () => Math.max(500, deadline - Date.now());
  const maxReq = opts.maxRequests ?? 2000, maxScripts = opts.maxScripts ?? 100, maxScriptBytes = opts.maxScriptBytes ?? 4 * 1024 * 1024, maxConsole = opts.maxConsole ?? 500, maxFrames = opts.maxFrames ?? 500;
  const tmp = await mkdtemp(join(tmpdir(), 'revlens-webrt-'));
  const kind = opts.browser ?? 'chromium';
  const res: CaptureResult = { url, browser: kind, startedAt: new Date(t0).toISOString(), durationMs: 0, har: { log: { version: '1.2', creator: { name: 'RevLens webrt', version: '1.0.0' }, pages: [], entries: [] } }, scripts: [], console: [], pageErrors: [], cookies: [], storage: { localStorage: [], sessionStorage: [], indexedDB: [] }, webSockets: [], serviceWorkers: [], failedRequests: [], warnings: [] };
  let browser: any;
  const hardTimer = setTimeout(() => { res.warnings.push('hard timeout reached, closing browser'); browser?.close().catch(() => undefined); }, budget + 5_000);
  try {
    browser = await pw[kind].launch({ headless: opts.headless ?? true, executablePath: opts.executablePath, downloadsPath: tmp, timeout: left(), args: kind === 'chromium' ? ['--disable-dev-shm-usage', '--no-first-run'] : undefined });
    res.browserVersion = browser.version();
    const context = await browser.newContext({ acceptDownloads: false, userAgent: opts.userAgent, serviceWorkers: 'allow', ignoreHTTPSErrors: false });
    const pageObj = await context.newPage();
    pageObj.setDefaultTimeout(left());
    const pending: Promise<unknown>[] = [];
    const reqStart = new Map<unknown, number>();
    pageObj.on('request', (rq: any) => { reqStart.set(rq, Date.now()); });
    pageObj.on('requestfailed', (rq: any) => { if (res.failedRequests.length < 500) res.failedRequests.push({ url: rq.url().slice(0, 2000), error: String(rq.failure()?.errorText ?? 'failed') }); });
    pageObj.on('response', (resp: any) => {
      if (res.har.log.entries.length >= maxReq) return;
      const rq = resp.request();
      const started = reqStart.get(rq) ?? Date.now();
      const p = (async () => {
        const rtype: string = rq.resourceType();
        const headers: Record<string, string> = await resp.allHeaders().catch(() => resp.headers());
        const reqHeaders: Record<string, string> = await rq.allHeaders().catch(() => rq.headers());
        const mime = headers['content-type'] ?? '';
        let text: string | undefined; let size = Number(headers['content-length'] ?? -1);
        const isScript = rtype === 'script' || /javascript|ecmascript/i.test(mime);
        if (isScript && res.scripts.length < maxScripts) {
          try {
            const body: Buffer = await resp.body();
            size = body.length;
            const truncated = body.length > maxScriptBytes;
            const src = body.subarray(0, maxScriptBytes).toString('utf8');
            text = src;
            res.scripts.push({ url: resp.url(), inline: false, size: body.length, sha256: await sha256Hex(src), truncated, source: src });
          } catch (e) { res.warnings.push(`script body unavailable for ${resp.url()}: ${(e as Error).message.slice(0, 120)}`); }
        }
        const timing = rq.timing?.() ?? {};
        res.har.log.entries.push({
          startedDateTime: new Date(started).toISOString(), time: Math.max(0, Date.now() - started), _resourceType: rtype,
          request: { method: rq.method(), url: rq.url(), httpVersion: 'HTTP/1.1', headers: redact(reqHeaders), cookies: [], queryString: [], headersSize: -1, bodySize: rq.postDataBuffer()?.length ?? 0, postData: rq.postData() ? { mimeType: reqHeaders['content-type'] ?? '', text: String(rq.postData()).slice(0, 10_000) } : undefined },
          response: { status: resp.status(), statusText: resp.statusText(), httpVersion: 'HTTP/1.1', headers: redact(headers), cookies: [], content: { size, mimeType: mime, text: isScript ? text : undefined }, redirectURL: headers.location ?? '', headersSize: -1, bodySize: size },
          serverIPAddress: (await resp.serverAddr().catch(() => null))?.ipAddress, cache: {},
          timings: { blocked: -1, dns: timing.domainLookupEnd >= 0 ? timing.domainLookupEnd - timing.domainLookupStart : -1, connect: timing.connectEnd >= 0 ? timing.connectEnd - timing.connectStart : -1, ssl: timing.secureConnectionStart >= 0 ? timing.connectEnd - timing.secureConnectionStart : -1, send: 0, wait: timing.responseStart >= 0 ? timing.responseStart - timing.requestStart : -1, receive: timing.responseEnd >= 0 ? timing.responseEnd - timing.responseStart : -1 },
        });
      })().catch((e) => res.warnings.push(`response record failed: ${(e as Error).message.slice(0, 120)}`));
      pending.push(p);
    });
    pageObj.on('console', (m: any) => { if (res.console.length < maxConsole) { const loc = m.location?.(); res.console.push({ type: m.type(), text: String(m.text()).slice(0, 2000), location: loc?.url ? `${loc.url}:${loc.lineNumber}` : undefined }); } });
    pageObj.on('pageerror', (e: Error) => { if (res.pageErrors.length < 200) res.pageErrors.push(String(e.message).slice(0, 2000)); });
    pageObj.on('websocket', (ws: any) => {
      const rec = { url: String(ws.url()), frames: [] as CaptureResult['webSockets'][number]['frames'] };
      if (res.webSockets.length < 50) res.webSockets.push(rec);
      const add = (dir: 'sent' | 'received') => (f: { payload: string | Buffer }) => {
        if (rec.frames.length >= maxFrames) return;
        const pl = f.payload;
        rec.frames.push({ dir, at: Date.now() - t0, size: pl.length, preview: typeof pl === 'string' ? pl.slice(0, 500) : `<${pl.length} binary bytes>` });
      };
      ws.on('framesent', add('sent'));
      ws.on('framereceived', add('received'));
    });
    context.on('serviceworker', (w: any) => { if (res.serviceWorkers.length < 50) res.serviceWorkers.push(String(w.url())); });
    const nav = await pageObj.goto(url, { waitUntil: 'load', timeout: left() }).catch((e: Error) => { res.warnings.push(`navigation: ${e.message.slice(0, 300)}`); return null; });
    if (nav) res.har.log.pages.push({ id: 'page_1', title: '', startedDateTime: res.startedAt, pageTimings: {} });
    await pageObj.waitForLoadState('networkidle', { timeout: Math.min(left(), 10_000) }).catch(() => undefined);
    await pageObj.waitForTimeout(Math.min(opts.settleMs ?? 2_000, left()));
    res.finalUrl = pageObj.url();
    res.title = await pageObj.title().catch(() => undefined);
    // inline scripts and storage key names (our own read-only snippet runs in the page; the page's code is not touched)
    const inline: string[] = await pageObj.$$eval('script:not([src])', (els: Element[]) => els.map((e) => e.textContent ?? '').slice(0, 200)).catch(() => []);
    for (const s of inline) {
      if (!s.trim() || res.scripts.length >= maxScripts) continue;
      res.scripts.push({ url: `${res.finalUrl}#inline-${res.scripts.length}`, inline: true, size: s.length, sha256: await sha256Hex(s), truncated: s.length > maxScriptBytes, source: s.slice(0, maxScriptBytes) });
    }
    const storage = await pageObj.evaluate(async () => {
      const keys = (st: Storage | undefined) => { try { return st ? Object.keys(st).slice(0, 500) : []; } catch { return []; } };
      let idb: string[] = [];
      try { const dbs = await (indexedDB as unknown as { databases?: () => Promise<{ name?: string }[]> }).databases?.(); idb = (dbs ?? []).map((d) => String(d.name ?? '')).slice(0, 200); } catch { /* not supported */ }
      return { localStorage: keys(window.localStorage), sessionStorage: keys(window.sessionStorage), indexedDB: idb };
    }).catch(() => ({ localStorage: [], sessionStorage: [], indexedDB: [] }));
    res.storage = storage;
    const cookies = await context.cookies().catch(() => []);
    res.cookies = cookies.slice(0, 500).map((c: any) => ({ name: c.name, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, session: c.expires === -1 }));
    for (const w of context.serviceWorkers?.() ?? []) if (!res.serviceWorkers.includes(w.url())) res.serviceWorkers.push(w.url());
    await Promise.race([Promise.allSettled(pending), new Promise((r) => setTimeout(r, Math.min(left(), 5_000)))]);
  } finally {
    clearTimeout(hardTimer);
    await browser?.close().catch(() => undefined);
    await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
  }
  if (opts.analyze !== false) {
    for (const s of res.scripts) {
      if (!s.source) continue;
      try {
        const ep = findEndpoints(s.source, { maxItems: 300 });
        s.endpoints = { counts: ep.counts, hosts: ep.hosts, envNames: ep.envNames, featureFlags: ep.featureFlags, calls: ep.calls.map((c) => ({ api: c.api, url: c.url, method: c.method, line: c.line })), dynamicCode: ep.dynamicCode.map((d) => ({ api: d.api, line: d.line })) };
        const b = unpackBundle(s.source);
        if (b.bundler !== 'unknown') { s.bundler = b.bundler; s.modules = b.modules.length; }
      } catch (e) { res.warnings.push(`analysis of ${s.url}: ${(e as Error).message.slice(0, 160)}`); }
    }
    try { res.summary = analyzeHar(res.har as never, { analyzeScripts: false }); } catch { /* ignore */ }
  }
  res.durationMs = Date.now() - t0;
  return res;
}
