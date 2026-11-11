// WebMCP and MCP-over-web discovery for a live site. Node only. Fetches the page, its same-origin
// scripts and the well-known discovery paths, and optionally opens the page in Chromium with the
// CDP WebMCP domain on to record tools the browser itself registers. Page tools are never invoked.
import { scanHtmlForMcp, scanWebMcpScript, classifyWellKnown, agentHeaderHints, WELL_KNOWN_PATHS, type WebMcpTool, type WellKnownDoc, type HtmlMcpHints } from './webmcp.js';
import { InputError } from './util.js';

export interface WebMcpDiscoveryOptions {
  timeoutMs?: number;
  /** also open the page in Chromium and record CDP WebMCP.toolsAdded events (needs playwright) */
  browser?: boolean;
  executablePath?: string;
  maxScripts?: number;
  /** probe the well-known paths (default true) */
  wellKnown?: boolean;
}

export interface WebMcpDiscovery {
  url: string;
  finalUrl?: string;
  status?: number;
  headers: { name: string; value: string }[];
  html: Omit<HtmlMcpHints, 'inlineScripts' | 'scriptSrcs'> & { scripts: number };
  staticTools: WebMcpTool[];
  modelContextUses: { api: string; line: number; source: string }[];
  polyfills: { name: string; line: number; source: string }[];
  wellKnown: WellKnownDoc[];
  runtime?: { supported: boolean; browserVersion?: string; tools: { name: string; description?: string; inputSchema?: unknown; frameId?: string }[]; error?: string };
  summary: { hasWebMcp: boolean; declarativeTools: number; imperativeTools: number; runtimeTools: number; discoveryDocs: string[] };
  warnings: string[];
}

async function fetchCapped(url: string, timeoutMs: number, maxBytes: number): Promise<{ status: number; url: string; headers: Record<string, string>; body: string }> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal, redirect: 'follow', headers: { 'user-agent': 'RevLens-webrt/1.0 (+https://github.com/aniruddhaadak80/re)', accept: '*/*' } });
    const headers: Record<string, string> = {};
    r.headers.forEach((v, k) => { headers[k] = v; });
    const reader = r.body?.getReader();
    const chunks: Uint8Array[] = [];
    let n = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.length; chunks.push(value);
        if (n > maxBytes) { await reader.cancel().catch(() => undefined); break; }
      }
    }
    const buf = Buffer.concat(chunks).subarray(0, maxBytes);
    return { status: r.status, url: r.url || url, headers, body: buf.toString('utf8') };
  } finally { clearTimeout(timer); }
}

/** Discover WebMCP tools and MCP-over-web endpoints for a URL: HTML hints, script registrations, well-known documents and, optionally, live CDP registrations. */
export async function discoverWebMcp(url: string, opts: WebMcpDiscoveryOptions = {}): Promise<WebMcpDiscovery> {
  let u: URL;
  try { u = new URL(url); } catch { throw new InputError(`not a valid URL: ${url}`); }
  if (!/^https?:$/.test(u.protocol)) throw new InputError('only http and https URLs can be checked');
  const to = Math.max(1_000, Math.min(opts.timeoutMs ?? 15_000, 120_000));
  const out: WebMcpDiscovery = { url, headers: [], html: { links: [], meta: [], forms: [], scripts: 0 }, staticTools: [], modelContextUses: [], polyfills: [], wellKnown: [], summary: { hasWebMcp: false, declarativeTools: 0, imperativeTools: 0, runtimeTools: 0, discoveryDocs: [] }, warnings: [] };
  const page = await fetchCapped(url, to, 8 * 1024 * 1024).catch((e) => { out.warnings.push(`page fetch: ${(e as Error).message.slice(0, 200)}`); return undefined; });
  if (page) {
    out.finalUrl = page.url; out.status = page.status;
    out.headers = agentHeaderHints(page.headers);
    const h = scanHtmlForMcp(page.body);
    out.html = { links: h.links, meta: h.meta, forms: h.forms, scripts: h.scriptSrcs.length + h.inlineScripts.length };
    const scan = (code: string, source: string) => {
      try {
        const s = scanWebMcpScript(code, { source });
        out.staticTools.push(...s.tools);
        out.modelContextUses.push(...s.uses.slice(0, 200).map((x) => ({ api: x.api, line: x.line, source })));
        out.polyfills.push(...s.polyfills.map((p) => ({ ...p, source })));
      } catch (e) { out.warnings.push(`scan ${source}: ${(e as Error).message.slice(0, 160)}`); }
    };
    h.inlineScripts.forEach((s, i) => scan(s, `${page.url}#inline-${i}`));
    const origin = new URL(page.url).origin;
    const maxScripts = Math.max(0, Math.min(opts.maxScripts ?? 30, 200));
    const srcs = h.scriptSrcs.map((s) => { try { return new URL(s, page.url); } catch { return undefined; } }).filter((x): x is URL => !!x && x.origin === origin).slice(0, maxScripts);
    if (h.scriptSrcs.length > srcs.length) out.warnings.push(`${h.scriptSrcs.length - srcs.length} cross-origin or extra scripts were not fetched`);
    await Promise.all(srcs.map(async (s) => {
      const r = await fetchCapped(s.href, to, 4 * 1024 * 1024).catch(() => undefined);
      if (r && r.status === 200) scan(r.body, s.href);
    }));
  }
  if (opts.wellKnown !== false) {
    const origin = u.origin;
    await Promise.all(WELL_KNOWN_PATHS.map(async (p) => {
      const r = await fetchCapped(origin + p, Math.min(to, 8_000), 512 * 1024).catch(() => undefined);
      if (!r) return;
      const d = classifyWellKnown(p, r.status, r.headers['content-type'], r.status === 200 ? r.body : '');
      if (r.status === 200 && d.kind !== 'other') out.wellKnown.push(d);
      else if (r.status === 401 && (r.headers['www-authenticate'] ?? '').includes('resource_metadata')) out.wellKnown.push({ ...d, kind: 'oauth-protected-resource' });
    }));
    out.wellKnown.sort((a, b) => a.path.localeCompare(b.path));
  }
  if (opts.browser) {
    out.runtime = { supported: false, tools: [] };
    try {
      const pw: any = await import('playwright' as string);
      const b = await pw.chromium.launch({ executablePath: opts.executablePath, timeout: to, args: ['--enable-blink-features=WebMCP', '--enable-features=WebMCPTesting', '--disable-dev-shm-usage'] });
      try {
        out.runtime.browserVersion = b.version();
        const ctx = await b.newContext({ acceptDownloads: false, serviceWorkers: 'block' });
        const p = await ctx.newPage();
        const cdp = await ctx.newCDPSession(p);
        cdp.on('WebMCP.toolsAdded', (e: any) => { for (const t of (e?.tools ?? []).slice(0, 500)) if (out.runtime!.tools.length < 500) out.runtime!.tools.push({ name: String(t.name ?? '').slice(0, 200), description: t.description ? String(t.description).slice(0, 1000) : undefined, inputSchema: t.inputSchema, frameId: t.frameId }); });
        await cdp.send('WebMCP.enable').then(() => { out.runtime!.supported = true; }).catch(() => undefined);
        await p.goto(url, { waitUntil: 'load', timeout: to }).catch((e: Error) => { out.runtime!.error = e.message.slice(0, 200); });
        await p.waitForTimeout(Math.min(1_500, to));
        if (!out.runtime.tools.length) for (const t of await pageWebMcpTools(p)) out.runtime.tools.push(t);
      } finally { await b.close().catch(() => undefined); }
    } catch (e) { out.runtime.error = (e as Error).message.split('\n')[0]!.slice(0, 300); }
  }
  out.summary = {
    hasWebMcp: out.staticTools.length > 0 || out.html.forms.length > 0 || (out.runtime?.tools.length ?? 0) > 0 || out.modelContextUses.length > 0,
    declarativeTools: out.html.forms.length,
    imperativeTools: out.staticTools.filter((t) => !/unregister|remove/i.test(t.api)).length,
    runtimeTools: out.runtime?.tools.length ?? 0,
    discoveryDocs: out.wellKnown.map((d) => `${d.path} (${d.kind})`),
  };
  return out;
}

/** Page side fallback for Chromium builds that accept WebMCP.enable but send no toolsAdded events: the testing API lists registered tools. */
export async function pageWebMcpTools(page: any): Promise<{ name: string; description?: string; inputSchema?: unknown }[]> {
  const raw = await page.evaluate(async () => {
    const n: any = (globalThis as any).navigator;
    const api = n?.modelContextTesting ?? n?.modelContext;
    if (!api) return [];
    const fn = api.listTools ?? api.getTools;
    if (typeof fn !== 'function') return [];
    const list = await fn.call(api);
    return (Array.isArray(list) ? list : []).slice(0, 500).map((t: any) => ({ name: String(t?.name ?? ''), description: t?.description == null ? undefined : String(t.description), inputSchema: typeof t?.inputSchema === 'string' ? (() => { try { return JSON.parse(t.inputSchema); } catch { return t.inputSchema; } })() : t?.inputSchema }));
  }).catch(() => []);
  return (raw as any[]).filter((t) => t.name).map((t) => ({ name: t.name.slice(0, 200), description: t.description?.slice(0, 1000), inputSchema: t.inputSchema }));
}
