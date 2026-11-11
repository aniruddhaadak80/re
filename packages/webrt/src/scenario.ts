// Scripted browser scenarios with Playwright (optional peer dependency, Node only).
// A scenario is a JSON list of steps (goto, click, type, press, select, hover, scroll, wait, assert,
// screenshot). Assertions are evaluate-free: they use Playwright locators and recorded events, never
// page.evaluate of user text. Each step records network, console, a DOM snapshot, an ARIA snapshot,
// a screenshot and a Playwright trace chunk. On Chromium it also records JavaScript function call
// counts (precise coverage), DOM event listeners and passive WebMCP tool registrations through CDP.
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { InputError } from './util.js';
import { redactHeaders } from './capture.js';
import { pageWebMcpTools } from './webmcp-node.js';

export type ScenarioAssertion =
  | { selector: string; exists?: boolean; visible?: boolean; count?: number; text?: string; textEquals?: string; value?: string }
  | { url: string; mode?: 'contains' | 'equals' | 'regex' }
  | { title: string; mode?: 'contains' | 'equals' | 'regex' }
  | { request: string; method?: string; status?: number; present?: boolean }
  | { console: string; type?: string; present?: boolean }
  | { noPageErrors: true };

export type ScenarioStep = {
  action: 'goto' | 'click' | 'type' | 'fill' | 'press' | 'select' | 'check' | 'hover' | 'scroll' | 'wait' | 'assert' | 'screenshot' | 'reload' | 'back';
  name?: string;
  url?: string;
  selector?: string;
  text?: string;
  key?: string;
  value?: string;
  ms?: number;
  state?: 'attached' | 'detached' | 'visible' | 'hidden';
  waitUrl?: string;
  networkIdle?: boolean;
  x?: number;
  y?: number;
  timeoutMs?: number;
  expect?: ScenarioAssertion[];
  /** override per-step screenshot (default true) */
  screenshot?: boolean;
  fullPage?: boolean;
};

export interface ScenarioSpec {
  name?: string;
  startUrl?: string;
  viewport?: { width: number; height: number };
  userAgent?: string;
  steps: ScenarioStep[];
}

export interface ScenarioOptions {
  /** folder for capture.json, screenshots, DOM snapshots and traces (default: a new temp folder that is kept) */
  outDir?: string;
  timeoutMs?: number;
  stepTimeoutMs?: number;
  browser?: 'chromium' | 'firefox' | 'webkit';
  executablePath?: string;
  headless?: boolean;
  screenshots?: boolean;
  traces?: boolean;
  dom?: boolean;
  /** Chromium only: precise coverage call counts (default true) */
  coverage?: boolean;
  /** Chromium only: DOM event listener inventory after the last step (default true) */
  listeners?: boolean;
  /** Chromium only: passive WebMCP discovery through the CDP WebMCP domain (default true) */
  webmcp?: boolean;
  allowFileUrls?: boolean;
  maxRequests?: number;
  maxSteps?: number;
  launchArgs?: string[];
}

export interface AssertionResult { assertion: ScenarioAssertion; pass: boolean; actual?: unknown; error?: string }

export interface ScenarioStepResult {
  index: number;
  name?: string;
  action: string;
  target?: string;
  ok: boolean;
  error?: string;
  durationMs: number;
  url: string;
  title?: string;
  assertions: AssertionResult[];
  requests: number[];
  console: number[];
  dom?: { path: string; sha256: string; bytes: number; elements: number; links: number; forms: number; scripts: number; aria?: string };
  screenshot?: { path: string; sha256: string; bytes: number };
  trace?: { path: string };
}

export interface FunctionCount { name: string; /** character offset of the function start in its script */ offset: number; count: number }
export interface ScenarioCapture {
  kind: 'revlens-scenario';
  version: 1;
  name?: string;
  browser: string;
  browserVersion?: string;
  startedAt: string;
  durationMs: number;
  outDir: string;
  passed: boolean;
  steps: ScenarioStepResult[];
  har: { log: { version: string; creator: { name: string; version: string }; entries: Record<string, unknown>[] } };
  scripts: { url: string; sha256: string; size: number; inline: false }[];
  console: { type: string; text: string; location?: string; step: number }[];
  pageErrors: { message: string; step: number }[];
  coverage?: { scripts: { url: string; functions: number; calledFunctions: number; top: FunctionCount[] }[]; totalFunctions: number; calledFunctions: number };
  listeners?: { type: string; node: string; count: number; scriptId?: string; line?: number; column?: number }[];
  webmcp?: { tools: { name: string; description?: string; inputSchema?: unknown; frameId?: string; backendNodeId?: number; step: number }[]; removed: string[]; supported: boolean };
  warnings: string[];
}

const sha = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex');
const ACTIONS = new Set(['goto', 'click', 'type', 'fill', 'press', 'select', 'check', 'hover', 'scroll', 'wait', 'assert', 'screenshot', 'reload', 'back']);

function textMatch(actual: string, expected: string, mode: 'contains' | 'equals' | 'regex' = 'contains'): boolean {
  if (mode === 'equals') return actual === expected;
  if (mode === 'regex') {
    if (expected.length > 200 || /(\([^)]*[+*][^)]*\))[+*{]/.test(expected)) throw new InputError('regex too long or nested quantifier');
    return new RegExp(expected).test(actual);
  }
  return actual.includes(expected);
}

/** Check a scenario spec and return a clean copy. Throws InputError on bad input. */
export function validateScenario(spec: unknown, maxSteps = 200): ScenarioSpec {
  if (!spec || typeof spec !== 'object') throw new InputError('scenario must be an object with a steps array');
  const s = spec as ScenarioSpec;
  if (!Array.isArray(s.steps) || s.steps.length === 0) throw new InputError('scenario.steps must be a non-empty array');
  if (s.steps.length > maxSteps) throw new InputError(`scenario has ${s.steps.length} steps, over the ${maxSteps} limit`);
  s.steps.forEach((st, i) => {
    if (!st || typeof st !== 'object' || !ACTIONS.has(st.action)) throw new InputError(`step ${i}: unknown action ${(st as { action?: unknown })?.action}`);
    if (['click', 'type', 'fill', 'select', 'check', 'hover'].includes(st.action) && typeof st.selector !== 'string') throw new InputError(`step ${i}: ${st.action} needs a selector`);
    if (st.action === 'goto' && typeof st.url !== 'string') throw new InputError(`step ${i}: goto needs a url`);
    if ((st.action === 'type' || st.action === 'fill') && typeof st.text !== 'string') throw new InputError(`step ${i}: ${st.action} needs text`);
    if (st.action === 'press' && typeof st.key !== 'string') throw new InputError(`step ${i}: press needs a key`);
    if (st.expect !== undefined && !Array.isArray(st.expect)) throw new InputError(`step ${i}: expect must be an array`);
    if ((st.expect?.length ?? 0) > 50) throw new InputError(`step ${i}: too many assertions`);
  });
  return s;
}

function checkUrl(u: string, allowFile?: boolean): void {
  let p: URL;
  try { p = new URL(u); } catch { throw new InputError(`not a valid URL: ${u}`); }
  if (!/^https?:$/.test(p.protocol) && !(allowFile && p.protocol === 'file:') && p.protocol !== 'about:') throw new InputError(`only http and https URLs can be opened: ${u}`);
}

/** Run a scripted browser scenario and record network, console, DOM, screenshots and traces per step. Node only. */
export async function runScenario(specIn: unknown, opts: ScenarioOptions = {}): Promise<ScenarioCapture> {
  const spec = validateScenario(specIn, opts.maxSteps ?? 200);
  const steps: ScenarioStep[] = spec.startUrl ? [{ action: 'goto', url: spec.startUrl }, ...spec.steps] : [...spec.steps];
  for (const st of steps) if (st.action === 'goto') checkUrl(st.url!, opts.allowFileUrls);
  let pw: any;
  try { pw = await import('playwright' as string); }
  catch { throw new InputError('scenarios need the optional "playwright" package: npm i playwright && npx playwright install chromium'); }
  const outDir = resolve(opts.outDir ?? await mkdtemp(join(tmpdir(), 'revlens-scenario-')));
  await mkdir(outDir, { recursive: true });
  const budget = Math.max(5_000, Math.min(opts.timeoutMs ?? 120_000, 900_000));
  const stepBudget = Math.max(500, Math.min(opts.stepTimeoutMs ?? 15_000, 120_000));
  const t0 = Date.now();
  const left = () => Math.max(250, t0 + budget - Date.now());
  const kind = opts.browser ?? 'chromium';
  const maxReq = opts.maxRequests ?? 5000;
  const cap: ScenarioCapture = { kind: 'revlens-scenario', version: 1, name: spec.name, browser: kind, startedAt: new Date(t0).toISOString(), durationMs: 0, outDir, passed: false, steps: [], har: { log: { version: '1.2', creator: { name: 'RevLens webrt', version: '1.0.0' }, entries: [] } }, scripts: [], console: [], pageErrors: [], warnings: [] };
  let browser: any;
  let stepNo = 0;
  const hard = setTimeout(() => { cap.warnings.push('hard timeout reached, closing browser'); browser?.close().catch(() => undefined); }, budget + 10_000);
  const traces = opts.traces !== false, shots = opts.screenshots !== false, dom = opts.dom !== false;
  try {
    const args = [...(kind === 'chromium' ? ['--disable-dev-shm-usage', '--no-first-run', '--enable-blink-features=WebMCP', '--enable-features=WebMCPTesting'] : []), ...(opts.launchArgs ?? [])];
    browser = await pw[kind].launch({ headless: opts.headless ?? true, executablePath: opts.executablePath, timeout: left(), args: args.length ? args : undefined });
    cap.browserVersion = browser.version();
    const context = await browser.newContext({ acceptDownloads: false, viewport: spec.viewport ?? { width: 1280, height: 800 }, userAgent: spec.userAgent, serviceWorkers: 'block', deviceScaleFactor: 1 });
    if (traces) await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
    const page = await context.newPage();
    page.setDefaultTimeout(stepBudget);
    const pending: Promise<unknown>[] = [];
    const reqStart = new Map<unknown, number>();
    const scriptSeen = new Set<string>();
    page.on('request', (rq: any) => reqStart.set(rq, Date.now()));
    page.on('response', (resp: any) => {
      if (cap.har.log.entries.length >= maxReq) return;
      const rq = resp.request();
      const step = stepNo;
      const started = reqStart.get(rq) ?? Date.now();
      const entry: Record<string, any> = { _step: step, _resourceType: rq.resourceType(), startedDateTime: new Date(started).toISOString(), time: Math.max(0, Date.now() - started), request: { method: rq.method(), url: String(rq.url()).slice(0, 4000), headers: [] }, response: { status: resp.status(), statusText: resp.statusText(), headers: [], content: { mimeType: '' } } };
      const idx = cap.har.log.entries.push(entry) - 1;
      cap.steps.find((s) => s.index === step)?.requests.push(idx);
      pending.push((async () => {
        const rh: Record<string, string> = await resp.allHeaders().catch(() => resp.headers());
        const qh: Record<string, string> = await rq.allHeaders().catch(() => rq.headers());
        entry.request.headers = redactHeaders(qh); entry.response.headers = redactHeaders(rh);
        entry.response.content.mimeType = rh['content-type'] ?? '';
        if ((rq.resourceType() === 'script' || /javascript|ecmascript/i.test(rh['content-type'] ?? '')) && !scriptSeen.has(resp.url()) && cap.scripts.length < 500) {
          scriptSeen.add(resp.url());
          const body: Buffer | undefined = await resp.body().catch(() => undefined);
          if (body) cap.scripts.push({ url: String(resp.url()).slice(0, 4000), sha256: sha(body), size: body.length, inline: false });
        }
      })().catch(() => undefined));
    });
    page.on('requestfailed', (rq: any) => { if (cap.har.log.entries.length < maxReq) { const idx = cap.har.log.entries.push({ _step: stepNo, _failed: String(rq.failure()?.errorText ?? 'failed'), request: { method: rq.method(), url: String(rq.url()).slice(0, 4000), headers: [] }, response: { status: 0, headers: [], content: {} } }) - 1; cap.steps.find((s) => s.index === stepNo)?.requests.push(idx); } });
    page.on('console', (m: any) => { if (cap.console.length < 2000) { const loc = m.location?.(); const i = cap.console.push({ type: m.type(), text: String(m.text()).slice(0, 2000), location: loc?.url ? `${loc.url}:${loc.lineNumber}` : undefined, step: stepNo }) - 1; cap.steps.find((s) => s.index === stepNo)?.console.push(i); } });
    page.on('pageerror', (e: Error) => { if (cap.pageErrors.length < 500) cap.pageErrors.push({ message: String(e.message).slice(0, 2000), step: stepNo }); });
    // Chromium CDP extras
    let cdp: any;
    if (kind === 'chromium') {
      try {
        cdp = await context.newCDPSession(page);
        if (opts.coverage !== false) { await cdp.send('Profiler.enable'); await cdp.send('Profiler.startPreciseCoverage', { callCount: true, detailed: false, allowTriggeredUpdates: false }); }
        if (opts.webmcp !== false) {
          cap.webmcp = { tools: [], removed: [], supported: false };
          cdp.on('WebMCP.toolsAdded', (e: any) => { for (const tl of (e?.tools ?? []).slice(0, 500)) if (cap.webmcp!.tools.length < 500) cap.webmcp!.tools.push({ name: String(tl.name ?? '').slice(0, 200), description: tl.description ? String(tl.description).slice(0, 1000) : undefined, inputSchema: tl.inputSchema, frameId: tl.frameId, backendNodeId: tl.backendNodeId, step: stepNo }); });
          cdp.on('WebMCP.toolsRemoved', (e: any) => { for (const tl of (e?.tools ?? []).slice(0, 500)) cap.webmcp!.removed.push(String(tl.name ?? tl).slice(0, 200)); });
          await cdp.send('WebMCP.enable').then(() => { cap.webmcp!.supported = true; }).catch(() => undefined);
        }
      } catch (e) { cap.warnings.push(`CDP session: ${(e as Error).message.slice(0, 200)}`); }
    }
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i]!;
      stepNo = i;
      const r: ScenarioStepResult = { index: i, name: st.name, action: st.action, target: st.selector ?? st.url ?? st.key, ok: true, durationMs: 0, url: '', assertions: [], requests: [], console: [] };
      cap.steps.push(r);
      const ts = Date.now();
      const to = Math.min(st.timeoutMs ?? stepBudget, left());
      if (traces) await context.tracing.startChunk({ title: `step ${i} ${st.action}` }).catch((e: Error) => cap.warnings.push(`trace chunk: ${e.message.slice(0, 120)}`));
      try {
        switch (st.action) {
          case 'goto': await page.goto(st.url, { waitUntil: 'load', timeout: to }); break;
          case 'click': await page.locator(st.selector).first().click({ timeout: to }); break;
          case 'type': await page.locator(st.selector).first().pressSequentially(st.text, { timeout: to, delay: 5 }); break;
          case 'fill': await page.locator(st.selector).first().fill(st.text, { timeout: to }); break;
          case 'press': if (st.selector) await page.locator(st.selector).first().press(st.key, { timeout: to }); else await page.keyboard.press(st.key); break;
          case 'select': await page.locator(st.selector).first().selectOption(st.value ?? st.text ?? '', { timeout: to }); break;
          case 'check': await page.locator(st.selector).first().check({ timeout: to }); break;
          case 'hover': await page.locator(st.selector).first().hover({ timeout: to }); break;
          case 'scroll': await page.mouse.wheel(st.x ?? 0, st.y ?? 600); break;
          case 'reload': await page.reload({ waitUntil: 'load', timeout: to }); break;
          case 'back': await page.goBack({ waitUntil: 'load', timeout: to }); break;
          case 'wait':
            if (st.selector) await page.locator(st.selector).first().waitFor({ state: st.state ?? 'visible', timeout: to });
            else if (st.waitUrl) await page.waitForURL(st.waitUrl, { timeout: to });
            else if (st.networkIdle) await page.waitForLoadState('networkidle', { timeout: to });
            else await page.waitForTimeout(Math.max(0, Math.min(st.ms ?? 500, to, 60_000)));
            break;
          default: break;
        }
        if (st.action !== 'wait' && st.action !== 'assert') await page.waitForLoadState('domcontentloaded', { timeout: Math.min(to, 5_000) }).catch(() => undefined);
      } catch (e) { r.ok = false; r.error = (e as Error).message.split('\n')[0]!.slice(0, 500); }
      await page.waitForTimeout(Math.min(150, left())).catch(() => undefined);
      await Promise.race([Promise.allSettled(pending.splice(0)), new Promise((res) => setTimeout(res, Math.min(3_000, left())))]);
      r.url = page.url(); r.title = await page.title().catch(() => undefined);
      for (const a of st.expect ?? []) r.assertions.push(await checkAssertion(page, a, cap, i, Math.min(to, 5_000)));
      if (r.assertions.some((a) => !a.pass)) r.ok = false;
      const base = join(outDir, `step-${String(i).padStart(3, '0')}`);
      if (dom) {
        try {
          const html = String(await page.content()).slice(0, 5 * 1024 * 1024);
          await writeFile(`${base}.html`, html);
          const count = (sel: string) => page.locator(sel).count().catch(() => -1);
          const aria = await page.locator('body').ariaSnapshot({ timeout: 3_000 }).catch(() => undefined);
          r.dom = { path: `${base}.html`, sha256: sha(html), bytes: Buffer.byteLength(html), elements: await count('*'), links: await count('a[href]'), forms: await count('form'), scripts: await count('script'), aria: aria ? String(aria).slice(0, 20_000) : undefined };
        } catch (e) { cap.warnings.push(`dom snapshot step ${i}: ${(e as Error).message.slice(0, 160)}`); }
      }
      if (shots && st.screenshot !== false) {
        try {
          const png: Buffer = await page.screenshot({ path: `${base}.png`, fullPage: !!st.fullPage, animations: 'disabled', caret: 'hide', timeout: Math.min(10_000, left()) });
          r.screenshot = { path: `${base}.png`, sha256: sha(png), bytes: png.length };
        } catch (e) { cap.warnings.push(`screenshot step ${i}: ${(e as Error).message.slice(0, 160)}`); }
      }
      if (traces) await context.tracing.stopChunk({ path: `${base}.trace.zip` }).then(() => { r.trace = { path: `${base}.trace.zip` }; }).catch((e: Error) => cap.warnings.push(`trace step ${i}: ${e.message.slice(0, 120)}`));
      r.durationMs = Date.now() - ts;
      if (Date.now() - t0 > budget) { cap.warnings.push(`time budget used up after step ${i}`); break; }
    }
    if (cap.webmcp && !cap.webmcp.tools.length) for (const t of await pageWebMcpTools(page)) cap.webmcp.tools.push({ ...t, step: stepNo });
    if (cdp) {
      if (opts.coverage !== false) {
        try {
          const cov = await cdp.send('Profiler.takePreciseCoverage');
          cap.coverage = { scripts: [], totalFunctions: 0, calledFunctions: 0 };
          for (const s of (cov.result ?? []).slice(0, 1000)) {
            if (!s.url || s.url.startsWith('pptr:') || s.url.startsWith('__playwright')) continue;
            const fns: FunctionCount[] = [];
            let called = 0;
            for (const f of (s.functions ?? []).slice(0, 100_000)) {
              const cnt = Number(f.ranges?.[0]?.count ?? 0);
              if (cnt > 0) called++;
              fns.push({ name: String(f.functionName || '(anonymous)').slice(0, 200), offset: Number(f.ranges?.[0]?.startOffset ?? 0), count: cnt });
            }
            cap.coverage.totalFunctions += fns.length; cap.coverage.calledFunctions += called;
            cap.coverage.scripts.push({ url: String(s.url).slice(0, 4000), functions: fns.length, calledFunctions: called, top: fns.filter((f) => f.count > 0).sort((a, b) => b.count - a.count).slice(0, 100) });
          }
          await cdp.send('Profiler.stopPreciseCoverage').catch(() => undefined);
        } catch (e) { cap.warnings.push(`coverage: ${(e as Error).message.slice(0, 200)}`); }
      }
      if (opts.listeners !== false) {
        try {
          const counts = new Map<string, { type: string; node: string; count: number; scriptId?: string; line?: number; column?: number }>();
          const add = (node: string, ls: any[]) => { for (const l of ls.slice(0, 20_000)) { const k = `${node}|${l.type}|${l.scriptId}:${l.lineNumber}:${l.columnNumber}`; const c = counts.get(k); if (c) c.count++; else if (counts.size < 5000) counts.set(k, { type: String(l.type), node, count: 1, scriptId: l.scriptId, line: l.lineNumber, column: l.columnNumber }); } };
          const doc = await cdp.send('DOM.getDocument', { depth: 0 });
          const docObj = await cdp.send('DOM.resolveNode', { nodeId: doc.root.nodeId });
          const dl = await cdp.send('DOMDebugger.getEventListeners', { objectId: docObj.object.objectId, depth: -1, pierce: true });
          const nodeNames = new Map<number, string>();
          const flat = await cdp.send('DOM.getFlattenedDocument', { depth: -1, pierce: true }).catch(() => ({ nodes: [] }));
          for (const n of (flat.nodes ?? []).slice(0, 200_000)) {
            const at: string[] = n.attributes ?? []; const id = at[at.indexOf('id') + 1];
            nodeNames.set(n.backendNodeId, `${String(n.nodeName).toLowerCase()}${at.includes('id') && id ? '#' + id : ''}`);
          }
          const byNode = new Map<string, any[]>();
          for (const l of dl.listeners ?? []) { const nm = nodeNames.get(l.backendNodeId) ?? (l.backendNodeId ? `node ${l.backendNodeId}` : '#document'); (byNode.get(nm) ?? byNode.set(nm, []).get(nm)!).push(l); }
          for (const [nm, ls] of byNode) add(nm, ls);
          const win = await cdp.send('Runtime.evaluate', { expression: 'window', objectGroup: 'revlens', returnByValue: false, silent: true });
          if (win?.result?.objectId) add('window', (await cdp.send('DOMDebugger.getEventListeners', { objectId: win.result.objectId })).listeners ?? []);
          await cdp.send('Runtime.releaseObjectGroup', { objectGroup: 'revlens' }).catch(() => undefined);
          cap.listeners = [...counts.values()];
        } catch (e) { cap.warnings.push(`listeners: ${(e as Error).message.slice(0, 200)}`); }
      }
    }
    if (traces) await context.tracing.stop().catch(() => undefined);
  } finally {
    clearTimeout(hard);
    await browser?.close().catch(() => undefined);
  }
  cap.durationMs = Date.now() - t0;
  cap.passed = cap.steps.length === steps.length && cap.steps.every((s) => s.ok);
  await writeFile(join(outDir, 'capture.json'), JSON.stringify(cap, null, 2));
  return cap;
}

async function checkAssertion(page: any, a: ScenarioAssertion, cap: ScenarioCapture, step: number, to: number): Promise<AssertionResult> {
  try {
    if ('selector' in a) {
      const loc = page.locator(a.selector);
      const n: number = await loc.count();
      if (a.exists !== undefined && (n > 0) !== a.exists) return { assertion: a, pass: false, actual: { count: n } };
      if (a.count !== undefined && n !== a.count) return { assertion: a, pass: false, actual: { count: n } };
      if (a.exists === false) return { assertion: a, pass: true, actual: { count: n } };
      if (n === 0) return { assertion: a, pass: false, actual: { count: 0 } };
      const first = loc.first();
      if (a.visible !== undefined) { const v = await first.isVisible(); if (v !== a.visible) return { assertion: a, pass: false, actual: { visible: v } }; }
      if (a.text !== undefined || a.textEquals !== undefined) {
        const txt = String((await first.textContent({ timeout: to })) ?? '').trim();
        const pass = a.textEquals !== undefined ? txt === a.textEquals : txt.includes(a.text!);
        if (!pass) return { assertion: a, pass, actual: { text: txt.slice(0, 500) } };
      }
      if (a.value !== undefined) { const v = await first.inputValue({ timeout: to }); if (v !== a.value) return { assertion: a, pass: false, actual: { value: v.slice(0, 500) } }; }
      return { assertion: a, pass: true, actual: { count: n } };
    }
    if ('url' in a) { const u = page.url(); return { assertion: a, pass: textMatch(u, a.url, a.mode), actual: u }; }
    if ('title' in a) { const tt = await page.title(); return { assertion: a, pass: textMatch(tt, a.title, a.mode), actual: tt }; }
    if ('request' in a) {
      const hits = cap.har.log.entries.filter((e: any) => String(e.request?.url).includes(a.request) && (!a.method || e.request.method === a.method.toUpperCase()) && (a.status === undefined || e.response?.status === a.status));
      const want = a.present ?? true;
      return { assertion: a, pass: (hits.length > 0) === want, actual: { matches: hits.length } };
    }
    if ('console' in a) {
      const hits = cap.console.filter((m) => m.text.includes(a.console) && (!a.type || m.type === a.type));
      const want = a.present ?? true;
      return { assertion: a, pass: (hits.length > 0) === want, actual: { matches: hits.length } };
    }
    if ('noPageErrors' in a) { const errs = cap.pageErrors.filter((e) => e.step <= step); return { assertion: a, pass: errs.length === 0, actual: errs.slice(0, 5).map((e) => e.message) }; }
    return { assertion: a, pass: false, error: 'unknown assertion' };
  } catch (e) { return { assertion: a, pass: false, error: (e as Error).message.split('\n')[0]!.slice(0, 300) }; }
}
