// Work on a page that is already open behind a Chrome DevTools Protocol endpoint (a browser started
// with --remote-debugging-port, an Electron window, a WebView): pick the target without navigating it,
// inspect it passively (frames, resources, scripts with hashes, DOM counts, CSP, cookies, metrics),
// list DOM event listeners, take a screenshot, watch it for a time window while a person drives it,
// record execution coverage with UTF-16 ranges, analyze its live bundles (bundler, modules, chunks,
// endpoints, vendor libraries with versions, routes) and export its scripts to a folder with a
// manifest. Nothing here navigates, reloads or runs page-supplied text. Loopback only unless
// allowRemote. Node only.
import { createHash } from 'node:crypto';
import { mkdir, writeFile, lstat, realpath } from 'node:fs/promises';
import { join, resolve, dirname, sep } from 'node:path';
import { CdpClient, cdpTargets, type CdpTarget } from './cdp.js';
import { decodePng } from './png.js';
import { unpackBundle } from './js/bundle.js';
import { findEndpoints } from './js/endpoints.js';
import { InputError, safeRelPath } from './util.js';

export interface PageSelect {
  /** target id from web_cdp_targets */
  targetId?: string;
  /** first page whose URL contains this text */
  urlContains?: string;
  titleContains?: string;
  allowRemote?: boolean;
  /** prefer file:// and app:// pages (Electron windows) */
  preferFileUrls?: boolean;
}
export interface PageInspectOptions extends PageSelect {
  includeSources?: boolean;
  maxSourceChars?: number;
  listeners?: boolean;
  screenshot?: boolean;
  limit?: number;
}

const sha = (s: string | Uint8Array) => createHash('sha256').update(s).digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const INTERNAL = (u: string) => u.startsWith('pptr:') || u.startsWith('__playwright') || u.startsWith('extensions::') || u.startsWith('chrome-extension:') || u.startsWith('devtools:');

/** Pick a page target without touching it. */
export async function selectTarget(endpoint: string, sel: PageSelect = {}): Promise<{ target: CdpTarget; endpoint: string; userAgent?: string; browser?: string }> {
  const t = await cdpTargets(endpoint, { allowRemote: sel.allowRemote, timeoutMs: 5_000 });
  const pages = t.targets.filter((x) => (x.type === 'page' || x.type === 'webview' || x.type === 'iframe') && x.webSocketDebuggerUrl && !x.url.startsWith('devtools:'));
  let target: CdpTarget | undefined;
  if (sel.targetId) target = t.targets.find((x) => x.id === sel.targetId);
  else if (sel.urlContains) target = pages.find((x) => x.url.includes(sel.urlContains!));
  else if (sel.titleContains) target = pages.find((x) => x.title.includes(sel.titleContains!));
  else target = (sel.preferFileUrls ? pages.find((x) => /^(?:file|app):/.test(x.url)) : undefined) ?? pages.find((x) => x.type === 'page') ?? pages[0];
  if (!target) throw new InputError(`no matching page target on ${t.endpoint} (${t.targets.length} targets: ${t.targets.slice(0, 5).map((x) => `${x.type} ${x.url}`).join(', ')})`);
  if (!target.webSocketDebuggerUrl) throw new InputError(`target ${target.id} is attached elsewhere and offers no WebSocket`);
  // a page WebSocket on another host than the endpoint is refused (same loopback rule)
  const ws = new URL(target.webSocketDebuggerUrl);
  const ep = new URL(t.endpoint);
  if (ws.hostname !== ep.hostname && !sel.allowRemote) throw new InputError(`target WebSocket host ${ws.hostname} differs from the endpoint`);
  return { target, endpoint: t.endpoint, userAgent: t.version.userAgent, browser: t.version.browser };
}

async function connect(endpoint: string, sel: PageSelect) {
  const picked = await selectTarget(endpoint, sel);
  const client = await CdpClient.connect(picked.target.webSocketDebuggerUrl!, 5_000);
  return { ...picked, client };
}

export interface LiveScript { scriptId: string; url: string; sha256: string; length: number; sourceMapURL?: string; isModule?: boolean; executionContextId?: number; inline: boolean; source?: string }

/** Every script the page has parsed so far, with its source. Debugger.enable replays scriptParsed for existing scripts. */
async function liveScripts(c: CdpClient, opts: { max?: number; maxChars?: number; keepSource?: boolean } = {}): Promise<LiveScript[]> {
  const parsed: any[] = [];
  c.on('Debugger.scriptParsed', (p) => { if (parsed.length < 20_000) parsed.push(p); });
  await c.send('Debugger.enable', { maxScriptsCacheSize: 100_000_000 });
  await sleep(150);
  const out: LiveScript[] = [];
  const max = Math.max(1, Math.min(opts.max ?? 2000, 20_000));
  for (const p of parsed) {
    const url = String(p.url ?? '');
    if (INTERNAL(url)) continue;
    if (out.length >= max) break;
    let src = '';
    try { src = String((await c.send('Debugger.getScriptSource', { scriptId: p.scriptId })).scriptSource ?? ''); } catch { continue; }
    if (!url && !src.trim()) continue;
    out.push({ scriptId: String(p.scriptId), url: url.slice(0, 4000), sha256: sha(src), length: src.length, sourceMapURL: p.sourceMapURL ? String(p.sourceMapURL).slice(0, 4000) : undefined, isModule: p.isModule || undefined, executionContextId: p.executionContextId, inline: !url || p.hasSourceURL === false && /^https?:|^file:/.test(url) === false, source: opts.keepSource ? src.slice(0, opts.maxChars ?? 16 * 1024 * 1024) : undefined });
  }
  await c.send('Debugger.disable').catch(() => undefined);
  return out;
}

interface DomNode { nodeId: number; backendNodeId: number; nodeType: number; nodeName: string; localName?: string; attributes?: string[]; children?: DomNode[]; contentDocument?: DomNode; shadowRoots?: DomNode[]; frameId?: string; nodeValue?: string }

function walkDom(root: DomNode, visit: (n: DomNode) => void, max = 500_000): void {
  const stack: DomNode[] = [root];
  let n = 0;
  while (stack.length && n++ < max) {
    const x = stack.pop()!;
    visit(x);
    for (const k of [...(x.children ?? []), ...(x.shadowRoots ?? []), ...(x.contentDocument ? [x.contentDocument] : [])]) stack.push(k);
  }
}
const attr = (n: DomNode, k: string) => { const a = n.attributes ?? []; for (let i = 0; i + 1 < a.length; i += 2) if (a[i] === k) return a[i + 1]; return undefined; };
const nodeLabel = (n: DomNode) => { const id = attr(n, 'id'); const cls = attr(n, 'class'); return `${(n.localName || n.nodeName).toLowerCase()}${id ? '#' + id : ''}${!id && cls ? '.' + cls.trim().split(/\s+/).slice(0, 2).join('.') : ''}`; };

export interface EventListenerRow { type: string; node: string; count: number; useCapture?: boolean; passive?: boolean; once?: boolean; scriptId?: string; url?: string; line?: number; column?: number; handler?: string }

/** DOM event listeners of the whole document (with shadow roots and frames) and of window. */
export async function eventListenersOf(c: CdpClient, scriptUrls?: Map<string, string>): Promise<{ listeners: EventListenerRow[]; total: number; byType: Record<string, number> }> {
  const doc = await c.send('DOM.getDocument', { depth: -1, pierce: true });
  const labels = new Map<number, string>();
  walkDom(doc.root, (n) => { if (n.nodeType === 1) labels.set(n.backendNodeId, nodeLabel(n)); });
  const docObj = await c.send('DOM.resolveNode', { backendNodeId: doc.root.backendNodeId, objectGroup: 'revlens-listeners' });
  const dl = await c.send('DOMDebugger.getEventListeners', { objectId: docObj.object.objectId, depth: -1, pierce: true }, 30_000);
  const rows = new Map<string, EventListenerRow>();
  let total = 0;
  const add = (node: string, ls: any[]) => {
    for (const l of ls.slice(0, 50_000)) {
      total++;
      const k = `${node}|${l.type}|${l.scriptId}:${l.lineNumber}:${l.columnNumber}|${l.useCapture}`;
      const r = rows.get(k);
      if (r) { r.count++; continue; }
      if (rows.size >= 10_000) continue;
      rows.set(k, { type: String(l.type), node, count: 1, useCapture: l.useCapture || undefined, passive: l.passive || undefined, once: l.once || undefined, scriptId: l.scriptId, url: scriptUrls?.get(String(l.scriptId)), line: typeof l.lineNumber === 'number' ? l.lineNumber + 1 : undefined, column: l.columnNumber, handler: l.handler?.description ? String(l.handler.description).slice(0, 160) : undefined });
    }
  };
  const byNode = new Map<string, any[]>();
  for (const l of dl.listeners ?? []) { const nm = l.backendNodeId === doc.root.backendNodeId ? '#document' : labels.get(l.backendNodeId) ?? `node ${l.backendNodeId}`; (byNode.get(nm) ?? byNode.set(nm, []).get(nm)!).push(l); }
  for (const [nm, ls] of byNode) add(nm, ls);
  // window has no DOM node: the global object is reached by a constant expression, no page text is run
  const win = await c.send('Runtime.evaluate', { expression: 'globalThis', objectGroup: 'revlens-listeners', returnByValue: false, silent: true }).catch(() => undefined);
  if (win?.result?.objectId) add('window', (await c.send('DOMDebugger.getEventListeners', { objectId: win.result.objectId }).catch(() => ({ listeners: [] }))).listeners ?? []);
  await c.send('Runtime.releaseObjectGroup', { objectGroup: 'revlens-listeners' }).catch(() => undefined);
  const listeners = [...rows.values()].sort((a, b) => a.node.localeCompare(b.node) || a.type.localeCompare(b.type));
  const byType: Record<string, number> = {};
  for (const r of listeners) byType[r.type] = (byType[r.type] ?? 0) + r.count;
  return { listeners, total, byType };
}

export interface PageInspection {
  target: { id: string; type: string; url: string; title: string; userAgent?: string; browser?: string };
  frames: { id: string; parentId?: string; url: string; name?: string; securityOrigin?: string; mimeType?: string }[];
  resources: { url: string; type: string; mimeType: string; frameId: string; contentSize?: number; failed?: boolean }[];
  scripts: LiveScript[];
  dom: { elements: number; tags: Record<string, number>; forms: { action?: string; method?: string; inputs: string[] }[]; links: string[]; iframes: string[]; scriptSrcs: string[]; inlineScripts: number; shadowRoots: number; csp?: string; title?: string };
  cookies: { name: string; domain: string; path: string; secure: boolean; httpOnly: boolean; sameSite?: string; session: boolean }[];
  metrics: Record<string, number>;
  layout?: { width: number; height: number; contentWidth: number; contentHeight: number };
  listeners?: { listeners: EventListenerRow[]; total: number; byType: Record<string, number> };
  screenshot?: { base64: string; width: number; height: number; sha256: string };
  warnings: string[];
}

/** Passive inspection of an existing page: nothing navigates, reloads or runs page text. */
export async function inspectCdpPage(endpoint: string, o: PageInspectOptions = {}): Promise<PageInspection> {
  const { client: c, target, userAgent, browser } = await connect(endpoint, o);
  const warnings: string[] = [];
  const lim = Math.max(1, Math.min(o.limit ?? 2000, 50_000));
  try {
    const out: PageInspection = { target: { id: target.id, type: target.type, url: target.url, title: target.title, userAgent, browser }, frames: [], resources: [], scripts: [], dom: { elements: 0, tags: {}, forms: [], links: [], iframes: [], scriptSrcs: [], inlineScripts: 0, shadowRoots: 0 }, cookies: [], metrics: {}, warnings };
    try {
      const rt = await c.send('Page.getResourceTree');
      const walkF = (ft: any) => {
        const f = ft.frame;
        if (out.frames.length < lim) out.frames.push({ id: f.id, parentId: f.parentId, url: String(f.url ?? '').slice(0, 4000), name: f.name || undefined, securityOrigin: f.securityOrigin, mimeType: f.mimeType });
        for (const r of ft.resources ?? []) if (out.resources.length < lim) out.resources.push({ url: String(r.url).slice(0, 4000), type: r.type, mimeType: r.mimeType, frameId: f.id, contentSize: r.contentSize, failed: r.failed || undefined });
        for (const ch of ft.childFrames ?? []) walkF(ch);
      };
      walkF(rt.frameTree);
    } catch (e) { warnings.push(`frames: ${(e as Error).message.slice(0, 120)}`); }
    out.scripts = await liveScripts(c, { keepSource: o.includeSources, maxChars: o.maxSourceChars ?? 200_000, max: lim });
    try {
      const doc = await c.send('DOM.getDocument', { depth: -1, pierce: true }, 30_000);
      const d = out.dom;
      walkDom(doc.root, (n) => {
        if (n.shadowRoots?.length) d.shadowRoots += n.shadowRoots.length;
        if (n.nodeType !== 1) return;
        d.elements++;
        const tag = (n.localName || n.nodeName).toLowerCase();
        d.tags[tag] = (d.tags[tag] ?? 0) + 1;
        if (tag === 'a' && attr(n, 'href') && d.links.length < lim) d.links.push(attr(n, 'href')!.slice(0, 2000));
        if ((tag === 'iframe' || tag === 'frame' || tag === 'webview') && d.iframes.length < lim) d.iframes.push(String(attr(n, 'src') ?? '').slice(0, 2000));
        if (tag === 'script') { const src = attr(n, 'src'); if (src) { if (d.scriptSrcs.length < lim) d.scriptSrcs.push(src.slice(0, 2000)); } else d.inlineScripts++; }
        if (tag === 'meta' && String(attr(n, 'http-equiv') ?? '').toLowerCase() === 'content-security-policy') d.csp = String(attr(n, 'content') ?? '').slice(0, 4000);
        if (tag === 'title' && !d.title) d.title = n.children?.find((x) => x.nodeType === 3)?.nodeValue?.slice(0, 500);
        if (tag === 'form' && d.forms.length < 500) {
          const inputs: string[] = [];
          walkDom(n, (x) => { const t = (x.localName || '').toLowerCase(); if (x.nodeType === 1 && (t === 'input' || t === 'select' || t === 'textarea' || t === 'button') && inputs.length < 100) inputs.push(`${t}${attr(x, 'type') ? '[' + attr(x, 'type') + ']' : ''}${attr(x, 'name') ? ' ' + attr(x, 'name') : attr(x, 'id') ? ' #' + attr(x, 'id') : ''}`); }, 20_000);
          d.forms.push({ action: attr(n, 'action'), method: attr(n, 'method'), inputs });
        }
      });
    } catch (e) { warnings.push(`dom: ${(e as Error).message.slice(0, 120)}`); }
    try { const ck = await c.send('Network.getCookies'); out.cookies = (ck.cookies ?? []).slice(0, lim).map((k: any) => ({ name: String(k.name).slice(0, 200), domain: k.domain, path: k.path, secure: !!k.secure, httpOnly: !!k.httpOnly, sameSite: k.sameSite, session: !!k.session })); } catch (e) { warnings.push(`cookies: ${(e as Error).message.slice(0, 120)}`); }
    try { await c.send('Performance.enable'); const m = await c.send('Performance.getMetrics'); for (const x of m.metrics ?? []) out.metrics[String(x.name)] = Number(x.value); await c.send('Performance.disable').catch(() => undefined); } catch { /* optional */ }
    try { const l = await c.send('Page.getLayoutMetrics'); const v = l.cssVisualViewport ?? l.visualViewport; const cs = l.cssContentSize ?? l.contentSize; out.layout = { width: Math.round(v.clientWidth), height: Math.round(v.clientHeight), contentWidth: Math.round(cs.width), contentHeight: Math.round(cs.height) }; } catch { /* optional */ }
    if (o.listeners) {
      try { out.listeners = await eventListenersOf(c, new Map(out.scripts.map((s) => [s.scriptId, s.url]))); } catch (e) { warnings.push(`listeners: ${(e as Error).message.slice(0, 120)}`); }
    }
    if (o.screenshot) {
      try { const s = await screenshotOn(c, {}); out.screenshot = { base64: Buffer.from(s.png).toString('base64'), width: s.width, height: s.height, sha256: s.sha256 }; } catch (e) { warnings.push(`screenshot: ${(e as Error).message.slice(0, 120)}`); }
    }
    return out;
  } finally { c.close(); }
}

/** DOM event listener inventory of an existing page. */
export async function cdpEventListeners(endpoint: string, o: PageSelect = {}): Promise<{ target: { id: string; url: string; title: string }; listeners: EventListenerRow[]; total: number; byType: Record<string, number> }> {
  const { client: c, target } = await connect(endpoint, o);
  try {
    const scripts = await liveScripts(c, { max: 5000 });
    const r = await eventListenersOf(c, new Map(scripts.map((s) => [s.scriptId, s.url])));
    return { target: { id: target.id, url: target.url, title: target.title }, ...r };
  } finally { c.close(); }
}

async function screenshotOn(c: CdpClient, o: { fullPage?: boolean; clip?: { x: number; y: number; width: number; height: number } }): Promise<{ png: Uint8Array; width: number; height: number; sha256: string }> {
  const params: Record<string, unknown> = { format: 'png', fromSurface: true };
  if (o.clip) params.clip = { ...o.clip, scale: 1 };
  else if (o.fullPage) {
    const l = await c.send('Page.getLayoutMetrics');
    const cs = l.cssContentSize ?? l.contentSize;
    params.clip = { x: 0, y: 0, width: Math.min(Math.ceil(cs.width), 16_384), height: Math.min(Math.ceil(cs.height), 16_384), scale: 1 };
    params.captureBeyondViewport = true;
  }
  const r = await c.send('Page.captureScreenshot', params, 30_000);
  const png = new Uint8Array(Buffer.from(String(r.data ?? ''), 'base64'));
  const img = decodePng(png);
  return { png, width: img.width, height: img.height, sha256: sha(png) };
}

/** One screenshot of an existing page, without navigating. Written to outPath when given (must not exist as a link). */
export async function cdpScreenshot(endpoint: string, o: PageSelect & { fullPage?: boolean; clip?: { x: number; y: number; width: number; height: number }; outPath?: string } = {}): Promise<{ target: { id: string; url: string; title: string }; width: number; height: number; bytes: number; sha256: string; path?: string; base64?: string }> {
  const { client: c, target } = await connect(endpoint, o);
  try {
    const s = await screenshotOn(c, o);
    let path: string | undefined;
    if (o.outPath) {
      path = resolve(o.outPath);
      try { if ((await lstat(path)).isSymbolicLink()) throw new InputError('refusing to write through a symlink'); } catch (e) { if (e instanceof InputError) throw e; }
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, s.png);
    }
    return { target: { id: target.id, url: target.url, title: target.title }, width: s.width, height: s.height, bytes: s.png.length, sha256: s.sha256, path, base64: path ? undefined : Buffer.from(s.png).toString('base64') };
  } finally { c.close(); }
}

export interface ObservedRequest { requestId: string; method: string; url: string; type?: string; status?: number; mimeType?: string; encodedBytes?: number; failed?: string; initiator?: string; startedMs: number; durationMs?: number; requestHeaders?: Record<string, string>; responseHeaders?: Record<string, string>; postData?: string; body?: { text?: string; base64?: string; truncated?: boolean } }
export interface PageObservation {
  target: { id: string; url: string; title: string };
  durationMs: number;
  requests: ObservedRequest[];
  navigations: { t: number; url: string; frameId: string }[];
  console: { t: number; type: string; text: string; url?: string; line?: number }[];
  exceptions: { t: number; text: string; url?: string; line?: number }[];
  scripts: { t: number; url: string; length: number; sourceMapURL?: string }[];
  webSockets: { url: string; sent: number; received: number; frames: { t: number; dir: 'sent' | 'received'; text: string }[] }[];
  har: { log: { version: string; creator: { name: string; version: string }; entries: unknown[] } };
  warnings: string[];
}

const SECRET_HEADERS = /^(?:authorization|cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|x-csrf-token)$/i;
const headersOf = (h: any, redact: boolean): Record<string, string> => { const o: Record<string, string> = {}; for (const [k, v] of Object.entries(h ?? {}).slice(0, 200)) o[k] = redact && SECRET_HEADERS.test(k) ? '[redacted]' : String(v).slice(0, 4000); return o; };

/** Watch an existing page for a time window while a person (or another program) drives it. Nothing is clicked or navigated. */
export async function observeCdpPage(endpoint: string, o: PageSelect & { durationMs?: number; recordBodies?: boolean; maxBodyBytes?: number; maxRequests?: number; redact?: boolean; until?: () => boolean } = {}): Promise<PageObservation> {
  const { client: c, target } = await connect(endpoint, o);
  const duration = Math.max(100, Math.min(o.durationMs ?? 10_000, 30 * 60_000));
  const maxReq = Math.max(1, Math.min(o.maxRequests ?? 5000, 100_000));
  const maxBody = Math.max(0, Math.min(o.maxBodyBytes ?? 1024 * 1024, 32 * 1024 * 1024));
  const redact = o.redact !== false;
  const t0 = Date.now();
  const now = () => Date.now() - t0;
  const reqs = new Map<string, ObservedRequest>();
  const out: PageObservation = { target: { id: target.id, url: target.url, title: target.title }, durationMs: 0, requests: [], navigations: [], console: [], exceptions: [], scripts: [], webSockets: [], har: { log: { version: '1.2', creator: { name: 'RevLens webrt', version: '1.0.0' }, entries: [] } }, warnings: [] };
  const ws = new Map<string, PageObservation['webSockets'][number]>();
  const pendingBodies: Promise<unknown>[] = [];
  let seenScripts = 0;
  try {
    c.on('Network.requestWillBeSent', (p) => {
      if (reqs.size >= maxReq) return;
      const prev = reqs.get(p.requestId);
      if (prev && p.redirectResponse) { prev.status = p.redirectResponse.status; prev.durationMs = now() - prev.startedMs; reqs.set(`${p.requestId}:r${reqs.size}`, prev); }
      const st = p.initiator?.stack?.callFrames?.[0];
      reqs.set(p.requestId, { requestId: p.requestId, method: String(p.request?.method ?? 'GET'), url: String(p.request?.url ?? '').slice(0, 4000), type: p.type, startedMs: now(), initiator: st ? `${st.functionName || '(anonymous)'} ${st.url}:${st.lineNumber + 1}:${st.columnNumber + 1}` : p.initiator?.url ? `${p.initiator.type} ${p.initiator.url}` : p.initiator?.type, requestHeaders: headersOf(p.request?.headers, redact), postData: typeof p.request?.postData === 'string' ? p.request.postData.slice(0, maxBody) : undefined });
    });
    c.on('Network.responseReceived', (p) => { const r = reqs.get(p.requestId); if (r) { r.status = p.response?.status; r.mimeType = p.response?.mimeType; r.responseHeaders = headersOf(p.response?.headers, redact); } });
    c.on('Network.loadingFinished', (p) => {
      const r = reqs.get(p.requestId); if (!r) return;
      r.encodedBytes = p.encodedDataLength; r.durationMs = now() - r.startedMs;
      if (o.recordBodies && maxBody > 0 && (r.encodedBytes ?? 0) <= maxBody * 4) pendingBodies.push(c.send('Network.getResponseBody', { requestId: p.requestId }).then((b: any) => { const s = String(b.body ?? ''); r.body = b.base64Encoded ? { base64: s.slice(0, Math.ceil(maxBody / 3) * 4), truncated: s.length > Math.ceil(maxBody / 3) * 4 || undefined } : { text: s.slice(0, maxBody), truncated: s.length > maxBody || undefined }; }).catch(() => undefined));
    });
    c.on('Network.loadingFailed', (p) => { const r = reqs.get(p.requestId); if (r) { r.failed = String(p.errorText ?? 'failed'); r.durationMs = now() - r.startedMs; } });
    c.on('Network.webSocketCreated', (p) => { if (ws.size < 200) ws.set(p.requestId, { url: String(p.url).slice(0, 2000), sent: 0, received: 0, frames: [] }); });
    const frame = (dir: 'sent' | 'received') => (p: any) => { const w = ws.get(p.requestId); if (!w) return; w[dir]++; if (w.frames.length < 500) w.frames.push({ t: now(), dir, text: String(p.response?.payloadData ?? '').slice(0, 2000) }); };
    c.on('Network.webSocketFrameSent', frame('sent'));
    c.on('Network.webSocketFrameReceived', frame('received'));
    c.on('Page.frameNavigated', (p) => { if (out.navigations.length < 1000) out.navigations.push({ t: now(), url: String(p.frame?.url ?? '').slice(0, 4000), frameId: p.frame?.id }); });
    c.on('Runtime.consoleAPICalled', (p) => { if (out.console.length < 5000) { const f = p.stackTrace?.callFrames?.[0]; out.console.push({ t: now(), type: p.type, text: (p.args ?? []).map((a: any) => (a.value !== undefined ? String(a.value) : a.description ?? a.type)).join(' ').slice(0, 2000), url: f?.url, line: f ? f.lineNumber + 1 : undefined }); } });
    c.on('Runtime.exceptionThrown', (p) => { if (out.exceptions.length < 1000) { const d = p.exceptionDetails ?? {}; out.exceptions.push({ t: now(), text: String(d.exception?.description ?? d.text ?? '').slice(0, 2000), url: d.url, line: typeof d.lineNumber === 'number' ? d.lineNumber + 1 : undefined }); } });
    c.on('Debugger.scriptParsed', (p) => { if (seenScripts++ < 0) return; const url = String(p.url ?? ''); if (!INTERNAL(url) && out.scripts.length < 5000 && p.__revlensNew !== false) out.scripts.push({ t: now(), url: url.slice(0, 4000), length: p.length, sourceMapURL: p.sourceMapURL || undefined }); });
    await c.send('Network.enable', { maxPostDataSize: maxBody });
    await c.send('Page.enable');
    await c.send('Runtime.enable');
    // scripts parsed before the window are replayed on enable; mark where the window starts
    await c.send('Debugger.enable').catch(() => undefined);
    await sleep(150);
    const before = out.scripts.length;
    out.scripts.splice(0, before);
    out.console.splice(0, out.console.length);
    const end = Date.now() + duration;
    while (Date.now() < end && !(o.until?.())) await sleep(50);
    await Promise.race([Promise.all(pendingBodies), sleep(5_000)]);
    await c.send('Debugger.disable').catch(() => undefined);
  } finally { c.close(); }
  out.durationMs = now();
  out.requests = [...new Set(reqs.values())].sort((a, b) => a.startedMs - b.startedMs);
  out.webSockets = [...ws.values()];
  const base = t0;
  out.har.log.entries = out.requests.map((r) => ({ startedDateTime: new Date(base + r.startedMs).toISOString(), time: r.durationMs ?? 0, _resourceType: String(r.type ?? '').toLowerCase(), _initiator: r.initiator, request: { method: r.method, url: r.url, headers: Object.entries(r.requestHeaders ?? {}).map(([name, value]) => ({ name, value })), postData: r.postData !== undefined ? { mimeType: r.requestHeaders?.['Content-Type'] ?? r.requestHeaders?.['content-type'] ?? '', text: r.postData } : undefined }, response: { status: r.status ?? 0, statusText: r.failed ?? '', headers: Object.entries(r.responseHeaders ?? {}).map(([name, value]) => ({ name, value })), content: { mimeType: r.mimeType ?? '', size: r.encodedBytes ?? 0, ...(r.body?.text !== undefined ? { text: r.body.text } : r.body?.base64 !== undefined ? { text: r.body.base64, encoding: 'base64' } : {}) } } }));
  return out;
}

export interface CoverageScript { scriptId: string; url: string; length?: number; functions: number; calledFunctions: number; usedChars: number; ranges: { start: number; end: number; count: number }[]; top: { name: string; start: number; end: number; count: number }[] }

/** Execution coverage window on an existing page: precise call counts with block ranges (UTF-16 offsets). */
export async function cdpExecutionCoverage(endpoint: string, o: PageSelect & { durationMs?: number; detailed?: boolean; limit?: number; until?: () => boolean } = {}): Promise<{ target: { id: string; url: string; title: string }; durationMs: number; scripts: CoverageScript[]; totals: { scripts: number; functions: number; calledFunctions: number; chars: number; usedChars: number }; offsets: 'utf16' }> {
  const { client: c, target } = await connect(endpoint, o);
  const duration = Math.max(50, Math.min(o.durationMs ?? 5_000, 30 * 60_000));
  const lim = Math.max(1, Math.min(o.limit ?? 200, 10_000));
  const t0 = Date.now();
  try {
    const lengths = new Map<string, { url: string; length: number }>();
    c.on('Debugger.scriptParsed', (p) => { if (lengths.size < 50_000) lengths.set(String(p.scriptId), { url: String(p.url ?? ''), length: Number(p.endOffset ?? p.length ?? 0) || Number(p.length ?? 0) }); });
    await c.send('Debugger.enable').catch(() => undefined);
    await c.send('Profiler.enable');
    await c.send('Profiler.startPreciseCoverage', { callCount: true, detailed: o.detailed !== false, allowTriggeredUpdates: false });
    const end = Date.now() + duration;
    while (Date.now() < end && !(o.until?.())) await sleep(50);
    const cov = await c.send('Profiler.takePreciseCoverage', {}, 30_000);
    await c.send('Profiler.stopPreciseCoverage').catch(() => undefined);
    await c.send('Profiler.disable').catch(() => undefined);
    await c.send('Debugger.disable').catch(() => undefined);
    const scripts: CoverageScript[] = [];
    const totals = { scripts: 0, functions: 0, calledFunctions: 0, chars: 0, usedChars: 0 };
    for (const s of cov.result ?? []) {
      const url = String(s.url ?? '');
      if (INTERNAL(url)) continue;
      const len = lengths.get(String(s.scriptId))?.length;
      // block coverage: nested ranges, the innermost wins; count used characters with a sweep
      const ranges: { start: number; end: number; count: number }[] = [];
      let called = 0;
      const top: CoverageScript['top'] = [];
      for (const f of (s.functions ?? []).slice(0, 200_000)) {
        const r0 = f.ranges?.[0];
        if (r0 && r0.count > 0) { called++; if (top.length < 5000) top.push({ name: String(f.functionName || '(anonymous)').slice(0, 200), start: r0.startOffset, end: r0.endOffset, count: r0.count }); }
        for (const r of (f.ranges ?? []).slice(0, 10_000)) if (ranges.length < 500_000) ranges.push({ start: r.startOffset, end: r.endOffset, count: r.count });
      }
      const total = len ?? Math.max(0, ...ranges.map((r) => r.end));
      const used = usedChars(ranges, total);
      totals.scripts++; totals.functions += (s.functions ?? []).length; totals.calledFunctions += called; totals.chars += total; totals.usedChars += used;
      if (scripts.length < lim) scripts.push({ scriptId: String(s.scriptId), url: url.slice(0, 4000), length: len, functions: (s.functions ?? []).length, calledFunctions: called, usedChars: used, ranges: ranges.slice(0, 5000), top: top.sort((a, b) => b.count - a.count).slice(0, 200) });
    }
    return { target: { id: target.id, url: target.url, title: target.title }, durationMs: Date.now() - t0, scripts, totals, offsets: 'utf16' };
  } finally { c.close(); }
}

/** Characters inside ranges with count > 0, where a nested range overrides the one around it (V8 block coverage rules). */
export function usedChars(ranges: { start: number; end: number; count: number }[], total: number): number {
  if (!ranges.length || total <= 0) return 0;
  // sort outer first (start asc, end desc); later (inner) ranges paint over earlier ones
  const sorted = [...ranges].filter((r) => r.end > r.start).sort((a, b) => a.start - b.start || b.end - a.end);
  // boundaries sweep with a stack
  const points = new Set<number>([0, total]);
  for (const r of sorted) { points.add(Math.max(0, Math.min(total, r.start))); points.add(Math.max(0, Math.min(total, r.end))); }
  const xs = [...points].sort((a, b) => a - b);
  let used = 0;
  let i = 0;
  const stack: { end: number; count: number }[] = [];
  for (let k = 0; k + 1 < xs.length; k++) {
    const a = xs[k]!, b = xs[k + 1]!;
    while (stack.length && stack[stack.length - 1]!.end <= a) stack.pop();
    while (i < sorted.length && sorted[i]!.start <= a) { const r = sorted[i++]!; if (r.end > a) { while (stack.length && stack[stack.length - 1]!.end <= a) stack.pop(); stack.push({ end: r.end, count: r.count }); } }
    const top = stack[stack.length - 1];
    if (top && top.count > 0) used += b - a;
  }
  return used;
}

// --- live bundle analysis ---
interface VendorSig { name: string; test: RegExp; version?: RegExp }
const VENDORS: VendorSig[] = [
  { name: 'react', test: /\breact\.(?:production|development)\b|__SECRET_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_WILL_BE_FIRED|ReactCurrentOwner/, version: /\bReactVersion\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']|\bversion\s*:\s*["'](1[5-9]\.\d+\.\d+[^"']*)["']\s*,\s*__SECRET/ },
  { name: 'react-dom', test: /react-dom\.(?:production|development)|ReactDOM|__reactContainer\$|__reactFiber\$/ },
  { name: 'vue', test: /__VUE__|__vue_app__|Vue\.version|\bcreateApp\b[\s\S]{0,40}\bmount\b/, version: /\bversion\s*=\s*["'](\d+\.\d+\.\d+)["'][\s\S]{0,20}(?:Vue|__VUE)/ },
  { name: 'angular', test: /\bɵcmp\b|\bng-version\b|@angular\/core/, version: /new\s+\w+\(\s*["'](\d+\.\d+\.\d+)["']\s*\)[\s\S]{0,40}VERSION/ },
  { name: 'jquery', test: /\bjQuery\b[\s\S]{0,40}\bfn\b|\bjquery:\s*["']\d/, version: /\bjquery:\s*["'](\d+\.\d+\.\d+)["']|jQuery v(\d+\.\d+\.\d+)/ },
  { name: 'lodash', test: /\blodash\b|__lodash_hash_undefined__/, version: /\bVERSION\s*=\s*["'](\d+\.\d+\.\d+)["'][\s\S]{0,200}lodash|lodash[^\n]{0,40}v?(\d+\.\d+\.\d+)/ },
  { name: 'axios', test: /\baxios\b[\s\S]{0,80}(?:interceptors|CancelToken)|AxiosError/, version: /VERSION\s*=\s*["'](1\.\d+\.\d+|0\.\d+\.\d+)["'][\s\S]{0,100}axios/ },
  { name: 'moment', test: /\bmoment\b[\s\S]{0,40}(?:locale|duration)|hooks\.version/, version: /\.version\s*=\s*["'](2\.\d+\.\d+)["']/ },
  { name: 'core-js', test: /core-js(?:-pure)?|__core-js_shared__/, version: /version:\s*["'](3\.\d+\.\d+)["'][\s\S]{0,60}core-js/ },
  { name: 'zone.js', test: /\bZone\b[\s\S]{0,40}__symbol__|__zone_symbol__/ },
  { name: 'svelte', test: /\bsvelte\b|SvelteComponent/ },
  { name: 'preact', test: /\bpreact\b|__PREACT_DEVTOOLS__/ },
  { name: 'next.js', test: /__NEXT_DATA__|next\/dist|__next_f/ },
  { name: 'nuxt', test: /__NUXT__|\$nuxt/ },
  { name: 'sentry', test: /@sentry\/|Sentry\.init|__SENTRY__/, version: /SDK_VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']/ },
  { name: 'google-analytics', test: /google-analytics\.com|googletagmanager\.com|\bgtag\(/ },
  { name: 'electron-preload-bridge', test: /contextBridge|ipcRenderer/ },
];
const ROUTE_LITERAL = /\bpath\s*:\s*["'`](\/[\w\-/:.*?]{0,120})["'`]/g;

export interface LiveBundleScript { url: string; sha256: string; length: number; bundler: string; confidence: number; modules: number; chunkIds: (string | number)[]; entryIds: (string | number)[]; sourceMapURL?: string; vendors: { name: string; version?: string }[]; routes: string[]; endpoints: { calls: number; hosts: string[]; sample: string[] }; dynamicImports: string[] }
export interface LiveBundleAnalysis { target: { id: string; url: string; title: string }; scripts: LiveBundleScript[]; vendors: { name: string; version?: string; scripts: string[] }[]; routes: string[]; hosts: string[]; graph: { nodes: { id: string; kind: 'script' | 'vendor' | 'host' | 'chunk' }[]; edges: { from: string; to: string; kind: 'uses' | 'calls' | 'loads' }[] }; warnings: string[] }

/** Analyze the bundles a live page has loaded: bundler, modules, chunks, endpoints, vendor libraries with versions, routes, and a graph. */
export function analyzeBundleScripts(scripts: { url: string; source: string }[], target: LiveBundleAnalysis['target'] = { id: '', url: '', title: '' }): LiveBundleAnalysis {
  const out: LiveBundleAnalysis = { target, scripts: [], vendors: [], routes: [], hosts: [], graph: { nodes: [], edges: [] }, warnings: [] };
  const vend = new Map<string, { name: string; version?: string; scripts: string[] }>();
  const nodes = new Map<string, LiveBundleAnalysis['graph']['nodes'][number]>();
  const node = (id: string, kind: LiveBundleAnalysis['graph']['nodes'][number]['kind']) => { if (!nodes.has(id) && nodes.size < 20_000) nodes.set(id, { id, kind }); };
  for (const s of scripts.slice(0, 2000)) {
    const src = s.source;
    if (src.length > 32 * 1024 * 1024) { out.warnings.push(`${s.url}: too large, skipped`); continue; }
    let b: ReturnType<typeof unpackBundle> | undefined;
    try { b = unpackBundle(src); } catch (e) { out.warnings.push(`${s.url}: ${(e as Error).message.slice(0, 120)}`); }
    let ep: ReturnType<typeof findEndpoints> | undefined;
    try { ep = findEndpoints(src, { maxItems: 2000 }); } catch { /* unparsable */ }
    const vendors: { name: string; version?: string }[] = [];
    const head = src.length > 4_000_000 ? src.slice(0, 2_000_000) + src.slice(-2_000_000) : src;
    for (const v of VENDORS) {
      if (!v.test.test(head)) continue;
      const m = v.version?.exec(head);
      const version = m ? m.slice(1).find(Boolean) : undefined;
      vendors.push({ name: v.name, version });
    }
    const routes = new Set<string>();
    ROUTE_LITERAL.lastIndex = 0;
    let rm: RegExpExecArray | null;
    let guard = 0;
    while ((rm = ROUTE_LITERAL.exec(head)) && guard++ < 5000) routes.add(rm[1]!);
    const dyn = (b?.imports ?? []).filter((i: any) => i.kind === 'dynamic' || i.dynamic).map((i: any) => String(i.source)).slice(0, 200);
    const label = s.url || `inline:${sha(src).slice(0, 12)}`;
    const row: LiveBundleScript = { url: label, sha256: sha(src), length: src.length, bundler: b?.bundler ?? 'unknown', confidence: b?.confidence ?? 0, modules: b?.modules.length ?? 0, chunkIds: (b?.chunkIds ?? []).slice(0, 200), entryIds: (b?.entryIds ?? []).slice(0, 50), sourceMapURL: /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/.exec(src.slice(-2000))?.[1], vendors, routes: [...routes].slice(0, 500), endpoints: { calls: ep?.calls.length ?? 0, hosts: ep?.hosts ?? [], sample: (ep?.calls ?? []).filter((c) => c.url).slice(0, 20).map((c) => `${c.method ?? c.api} ${c.url}`) }, dynamicImports: dyn };
    out.scripts.push(row);
    node(label, 'script');
    for (const v of vendors) { const k = v.name; const e = vend.get(k) ?? { name: k, version: v.version, scripts: [] }; if (!e.version && v.version) e.version = v.version; e.scripts.push(label); vend.set(k, e); node(`vendor:${k}`, 'vendor'); out.graph.edges.push({ from: label, to: `vendor:${k}`, kind: 'uses' }); }
    for (const h of row.endpoints.hosts) { node(`host:${h}`, 'host'); out.graph.edges.push({ from: label, to: `host:${h}`, kind: 'calls' }); }
    for (const ch of row.chunkIds) { node(`chunk:${ch}`, 'chunk'); out.graph.edges.push({ from: label, to: `chunk:${ch}`, kind: 'loads' }); }
    for (const d of dyn) { node(d, 'script'); out.graph.edges.push({ from: label, to: d, kind: 'loads' }); }
  }
  out.vendors = [...vend.values()];
  out.routes = [...new Set(out.scripts.flatMap((s) => s.routes))].sort();
  out.hosts = [...new Set(out.scripts.flatMap((s) => s.endpoints.hosts))].sort();
  out.graph.nodes = [...nodes.values()];
  out.graph.edges = out.graph.edges.slice(0, 50_000);
  return out;
}

/** Live bundle analysis of an existing page (scripts read through the debugger, no navigation). */
export async function analyzeLiveBundles(endpoint: string, o: PageSelect & { maxScripts?: number } = {}): Promise<LiveBundleAnalysis> {
  const { client: c, target } = await connect(endpoint, o);
  try {
    const scripts = await liveScripts(c, { keepSource: true, max: o.maxScripts ?? 500, maxChars: 32 * 1024 * 1024 });
    return analyzeBundleScripts(scripts.map((s) => ({ url: s.url, source: s.source ?? '' })), { id: target.id, url: target.url, title: target.title });
  } finally { c.close(); }
}

/** Write scripts to a folder with manifest.json (url, sha256, size, path, source map URL). Paths come from the URLs, made safe. */
export async function exportScriptsToFolder(scripts: { url: string; source: string; sourceMapURL?: string }[], outDir: string, opts: { maxFiles?: number; maxTotalBytes?: number } = {}): Promise<{ outDir: string; manifest: string; files: { path: string; url: string; sha256: string; bytes: number; sourceMapURL?: string }[]; skipped: { url: string; reason: string }[] }> {
  const root = resolve(outDir);
  await mkdir(root, { recursive: true });
  const realRoot = await realpath(root);
  const used = new Set<string>(['manifest.json']);
  const files: { path: string; url: string; sha256: string; bytes: number; sourceMapURL?: string }[] = [];
  const skipped: { url: string; reason: string }[] = [];
  let total = 0;
  const maxFiles = Math.max(1, Math.min(opts.maxFiles ?? 5000, 50_000));
  const maxTotal = Math.max(1, Math.min(opts.maxTotalBytes ?? 512 * 1024 * 1024, 4 * 1024 * 1024 * 1024));
  const seen = new Set<string>();
  for (const s of scripts) {
    const digest = sha(s.source);
    if (seen.has(`${s.url}|${digest}`)) continue;
    seen.add(`${s.url}|${digest}`);
    if (files.length >= maxFiles) { skipped.push({ url: s.url, reason: 'file limit' }); continue; }
    const bytes = Buffer.byteLength(s.source);
    if (total + bytes > maxTotal) { skipped.push({ url: s.url, reason: 'size limit' }); continue; }
    let rel: string;
    try {
      const u = new URL(s.url);
      rel = `${u.protocol === 'file:' ? 'file' : u.host.replace(/[^\w.-]/g, '_')}/${u.pathname.replace(/^\/+/, '') || 'index'}`;
      if (u.search) rel += `_${sha(u.search).slice(0, 8)}`;
    } catch { rel = `inline/${digest.slice(0, 16)}`; }
    if (!/\.(?:m?js|cjs|jsx?|ts)$/i.test(rel)) rel += '.js';
    let clean = safeRelPath(rel);
    if (!clean) { skipped.push({ url: s.url, reason: 'unsafe path' }); continue; }
    if (used.has(clean)) clean = clean.replace(/(\.[^./]+)$/, `.${digest.slice(0, 8)}$1`);
    used.add(clean);
    const target = resolve(root, clean);
    if (!target.startsWith(root + sep)) { skipped.push({ url: s.url, reason: 'escapes folder' }); continue; }
    await mkdir(dirname(target), { recursive: true });
    const rp = await realpath(dirname(target));
    if (rp !== realRoot && !rp.startsWith(realRoot + sep)) { skipped.push({ url: s.url, reason: 'escapes folder through a link' }); continue; }
    try { if ((await lstat(target)).isSymbolicLink()) { skipped.push({ url: s.url, reason: 'symlink in the way' }); continue; } } catch { /* absent */ }
    await writeFile(target, s.source);
    total += bytes;
    files.push({ path: clean.split(sep).join('/'), url: s.url, sha256: digest, bytes, sourceMapURL: s.sourceMapURL });
  }
  const manifest = join(root, 'manifest.json');
  await writeFile(manifest, JSON.stringify({ kind: 'revlens-scripts', version: 1, created: new Date().toISOString(), files, skipped }, null, 2));
  return { outDir: root, manifest, files, skipped };
}

/** Export the scripts of an existing page to a folder. */
export async function exportLiveScripts(endpoint: string, outDir: string, o: PageSelect & { maxFiles?: number } = {}): Promise<Awaited<ReturnType<typeof exportScriptsToFolder>> & { target: { id: string; url: string; title: string } }> {
  const { client: c, target } = await connect(endpoint, o);
  try {
    const scripts = await liveScripts(c, { keepSource: true, max: o.maxFiles ?? 5000, maxChars: 64 * 1024 * 1024 });
    const r = await exportScriptsToFolder(scripts.map((s) => ({ url: s.url || `inline:${s.sha256}`, source: s.source ?? '', sourceMapURL: s.sourceMapURL })), outDir, o);
    return { ...r, target: { id: target.id, url: target.url, title: target.title } };
  } finally { c.close(); }
}
