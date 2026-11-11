// Real browser and real Node process tests. They need a Chromium that Playwright can launch: either
// the Playwright download (npx playwright install chromium, used in CI) or REVLENS_CHROMIUM pointing at
// a system Chromium. They skip when no browser starts.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { createServer as netServer, type AddressInfo } from 'node:net';
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScenario, compareCaptureFiles, inspectPlaywrightTrace, cdpTargets, discoverWebMcp, attachNodeInspector } from '../src/node.js';

const exe = process.env.REVLENS_CHROMIUM || undefined;
const fixtures = new URL('../../../samples/webrt/runtime/', import.meta.url);
let pw: any;
let available = false;

async function canLaunch(): Promise<boolean> {
  try { pw = await import('playwright' as string); const b = await pw.chromium.launch({ executablePath: exe, timeout: 20_000 }); await b.close(); return true; } catch { return false; }
}

const page = (v: 1 | 2) => `<!doctype html><html><head><title>Counter v${v}</title><style>body{margin:0;font:16px sans-serif}input{caret-color:transparent}#box{position:absolute;left:20px;top:200px;width:120px;height:60px;background:${v === 1 ? '#c33' : '#36c'}}</style></head><body>
<h1>Counter</h1><button id="inc">Increment</button> <span id="count">0</span>
<input id="name" aria-label="Name"><div id="box"></div>
<form toolname="search_todos" tooldescription="Search the todo list by text"><input name="q"></form>
<script src="/v${v}/app.js"></script></body></html>`;
const app = (v: 1 | 2) => `let count = 0;
function bump() { count++; document.getElementById('count').textContent = String(count); fetch('/api/count/' + count); }
document.getElementById('inc').addEventListener('click', bump);
console.log('ready v${v}');
${v === 2 ? "fetch('/api/v2/track', { method: 'POST', body: '{}' });" : ''}`;

let server: Server; let base = '';
before(async () => {
  available = await canLaunch();
  server = createServer((req, res) => {
    const u = req.url ?? '/';
    const m = /^\/v([12])\/$/.exec(u);
    if (m) { res.setHeader('content-type', 'text/html'); if (m[1] === '1') res.setHeader('x-frame-options', 'DENY'); res.end(page(Number(m[1]) as 1 | 2)); return; }
    const a = /^\/v([12])\/app\.js$/.exec(u);
    if (a) { res.setHeader('content-type', 'text/javascript'); res.end(app(Number(a[1]) as 1 | 2)); return; }
    if (u.startsWith('/api/')) { res.setHeader('content-type', 'application/json'); res.end('{"ok":true}'); return; }
    if (u === '/webmcp/') { res.setHeader('content-type', 'text/html'); res.setHeader('link', '</.well-known/mcp.json>; rel="mcp"'); res.end(readFileSync(new URL('webmcp-page.html', fixtures))); return; }
    if (u === '/webmcp-app.js') { res.setHeader('content-type', 'text/javascript'); res.end(readFileSync(new URL('webmcp-app.js', fixtures))); return; }
    if (u === '/.well-known/mcp.json') { res.setHeader('content-type', 'application/json'); res.end(readFileSync(new URL('mcp.json', fixtures))); return; }
    res.statusCode = 404; res.end('not found');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => server?.close());

const scenario = (v: 1 | 2) => ({
  name: `counter v${v}`,
  startUrl: `${base}/v${v}/`,
  viewport: { width: 400, height: 300 },
  steps: [
    { action: 'click', selector: '#inc' },
    { action: 'click', selector: '#inc' },
    { action: 'click', selector: '#inc', expect: [{ selector: '#count', textEquals: '3' }, { request: '/api/count/3', status: 200 }] },
    { action: 'fill', selector: '#name', text: 'abc', expect: [{ selector: '#name', value: 'abc' }, { console: `ready v${v}` }, { url: `/v${v}/` }, { title: `Counter v${v}`, mode: 'equals' }, { noPageErrors: true }] },
  ],
});

let capA: any, capA2: any, capB: any;

test('scenario: steps, assertions, network per step, DOM, screenshots, traces, coverage, listeners, WebMCP', async (t) => {
  if (!available) { t.skip('no Chromium available'); return; }
  capA = await runScenario(scenario(1), { executablePath: exe, outDir: await mkdtemp(join(tmpdir(), 'rl-a-')) });
  assert.equal(capA.passed, true, JSON.stringify(capA.steps.map((s: any) => [s.error, s.assertions.filter((a: any) => !a.pass)])));
  assert.equal(capA.steps.length, 5); // goto + 4
  assert.deepEqual(capA.steps.map((s: any) => s.action), ['goto', 'click', 'click', 'click', 'fill']);
  // the request for /api/count/3 belongs to step 3 (third click)
  const s3 = capA.steps[3];
  assert.ok(s3.requests.map((i: number) => capA.har.log.entries[i].request.url).some((u: string) => u.endsWith('/api/count/3')));
  assert.equal(capA.steps[0].requests.map((i: number) => capA.har.log.entries[i].request.url).filter((u: string) => u.includes('/v1/')).length, 2);
  // DOM snapshot and ARIA snapshot
  const dom = capA.steps[4].dom;
  assert.ok(existsSync(dom.path));
  assert.ok(readFileSync(dom.path, 'utf8').includes('<span id="count">3</span>'));
  assert.equal(dom.forms, 1); assert.equal(dom.scripts, 1);
  assert.match(dom.aria, /button "Increment"/);
  // screenshots are real PNGs of the viewport size
  const png = readFileSync(capA.steps[4].screenshot.path);
  assert.equal(png.readUInt32BE(16), 400); assert.equal(png.readUInt32BE(20), 300);
  // precise coverage: bump ran exactly three times
  const appCov = capA.coverage.scripts.find((s: any) => s.url.endsWith('/v1/app.js'));
  assert.equal(appCov.top.find((f: any) => f.name === 'bump').count, 3);
  // listener inventory: the click handler on button#inc
  assert.ok(capA.listeners.some((l: any) => l.type === 'click' && l.node === 'button#inc'), JSON.stringify(capA.listeners));
  // Chromium's own WebMCP domain reports the declarative form tool
  assert.equal(capA.webmcp.supported, true);
  assert.deepEqual(capA.webmcp.tools.map((x: any) => [x.name, x.description]), [['search_todos', 'Search the todo list by text']]);
  assert.deepEqual(Object.keys(capA.webmcp.tools[0].inputSchema.properties), ['q']);
  assert.ok(existsSync(join(capA.outDir, 'capture.json')));
});

test('Playwright trace chunk of a click step is readable', async (t) => {
  if (!capA) { t.skip('no scenario capture'); return; }
  const tr = await inspectPlaywrightTrace(capA.steps[1].trace.path);
  assert.equal(tr.browserName, 'chromium');
  const click = tr.actions.items.find((a) => /click/i.test(a.api));
  assert.ok(click, JSON.stringify(tr.actions.items.map((a) => a.api)));
  assert.match(click!.selector!, /^#inc( >> nth=0)?$/);
  assert.equal(tr.actions.failed, 0);
  assert.ok(tr.network.items.some((n) => n.url.endsWith('/api/count/1') && n.status === 200), JSON.stringify(tr.network.items));
});

test('a failing assertion fails the step with the actual value', async (t) => {
  if (!available) { t.skip('no Chromium available'); return; }
  const r = await runScenario({ startUrl: `${base}/v1/`, steps: [{ action: 'click', selector: '#inc', expect: [{ selector: '#count', textEquals: '99' }, { request: '/api/nothing' }] }, { action: 'click', selector: '#missing', timeoutMs: 800 }] }, { executablePath: exe, traces: false, outDir: await mkdtemp(join(tmpdir(), 'rl-f-')) });
  assert.equal(r.passed, false);
  assert.deepEqual(r.steps[1]!.assertions.map((a) => [a.pass, a.actual]), [[false, { text: '1' }], [false, { matches: 0 }]]);
  assert.equal(r.steps[2]!.ok, false);
  assert.match(r.steps[2]!.error!, /Timeout|timeout/);
});

test('capture compare: same app twice is identical, v1 vs v2 shows the endpoint, header, script and pixel changes', async (t) => {
  if (!capA) { t.skip('no scenario capture'); return; }
  capA2 = await runScenario(scenario(1), { executablePath: exe, traces: false, outDir: await mkdtemp(join(tmpdir(), 'rl-a2-')) });
  capB = await runScenario(scenario(2), { executablePath: exe, traces: false, outDir: await mkdtemp(join(tmpdir(), 'rl-b-')) });
  const same = await compareCaptureFiles(join(capA.outDir, 'capture.json'), join(capA2.outDir, 'capture.json'));
  assert.equal(same.endpoints.added.length + same.endpoints.removed.length, 0);
  // two runs of the same app render the same pixels apart from a few antialiased ones
  for (const s of same.screenshots) assert.ok(s.diff!.similarity >= 0.999, JSON.stringify(s));
  const d = await compareCaptureFiles(join(capA.outDir, 'capture.json'), join(capB.outDir, 'capture.json'));
  const host = new URL(base).host;
  assert.deepEqual(d.endpoints.added.map((e) => e.key).sort(), [`GET ${host}/v2/`, `GET ${host}/v2/app.js`, `POST ${host}/api/v2/track`]);
  assert.deepEqual(d.endpoints.removed.map((e) => e.key).sort(), [`GET ${host}/v1/`, `GET ${host}/v1/app.js`]);
  assert.deepEqual(d.scripts.added, [`${base}/v2/app.js`]);
  assert.ok(d.console.added.includes('log: ready v2'));
  // last step: only the 120x60 box at (20,200) changed colour (the input caret is hidden, it blinks)
  const last = d.screenshots.find((s) => s.step === 4)!;
  assert.deepEqual(last.diff!.bbox, { x: 20, y: 200, width: 120, height: 60 });
  assert.equal(last.diff!.diffPixels, 120 * 60);
  assert.ok(d.score < 1 && d.score > 0);
  // cross-check the pixel count with Pillow when python3 and PIL exist
  try {
    const out = execFileSync('python3', ['-c', 'import sys;from PIL import Image,ImageChops;a=Image.open(sys.argv[1]).convert("RGBA");b=Image.open(sys.argv[2]).convert("RGBA");d=ImageChops.difference(a,b);print(sum(1 for p in d.getdata() if max(p)>0), ImageChops.difference(a.convert("RGB"),b.convert("RGB")).getbbox())', capA.steps[4].screenshot.path, capB.steps[4].screenshot.path], { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'] });
    assert.equal(out.trim(), `${120 * 60} (20, 200, 140, 260)`);
  } catch (e) { if ((e as Error).name === 'AssertionError') throw e; }
});

test('WebMCP discovery: static, well-known and the live Chromium WebMCP domain agree', async (t) => {
  const r = await discoverWebMcp(`${base}/webmcp/`, { browser: available, executablePath: exe, timeoutMs: 20_000 });
  assert.deepEqual(r.html.forms.map((f) => f.toolName), ['search_todos']);
  assert.deepEqual(r.staticTools.map((x) => x.name).sort(), ['add_todo', 'clear_done', 'legacy_tool', 'list_todos']);
  assert.equal(r.summary.imperativeTools, 3);
  assert.deepEqual(r.headers, [{ name: 'link', value: '</.well-known/mcp.json>; rel="mcp"' }]);
  assert.deepEqual(r.wellKnown.map((d) => [d.path, d.kind, d.name]), [['/.well-known/mcp.json', 'mcp-server-card', 'todo-mcp']]);
  if (available) {
    assert.equal(r.runtime!.supported, true);
    assert.deepEqual(r.runtime!.tools.map((x) => x.name), r.html.forms.map((f) => f.toolName));
  }
});

async function freePort(): Promise<number> {
  const s = netServer(); await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const p = (s.address() as AddressInfo).port; await new Promise((r) => s.close(r)); return p;
}

test('CDP target listing on a real remote debugging port', async (t) => {
  if (!available) { t.skip('no Chromium available'); return; }
  const port = await freePort();
  const b = await pw.chromium.launch({ executablePath: exe, args: [`--remote-debugging-port=${port}`] });
  try {
    const p = await b.newPage(); await p.goto(`${base}/v1/`);
    const r = await cdpTargets(String(port));
    // full Chromium reports Chrome/<version>, the headless shell HeadlessChrome/<version>
    assert.equal(r.version.browser.replace(/^HeadlessChrome\//, 'Chrome/'), `Chrome/${b.version().replace(/^HeadlessChrome\//, '')}`);
    const pg = r.targets.find((x) => x.type === 'page' && x.url === `${base}/v1/`);
    assert.ok(pg, JSON.stringify(r.targets));
    assert.equal(pg!.title, 'Counter v1');
    assert.match(pg!.webSocketDebuggerUrl!, /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/page\//);
  } finally { await b.close(); }
});

function spawnTarget(args: string[]): Promise<{ child: ReturnType<typeof spawn>; port?: number }> {
  const script = fileURLToPath(new URL('node-target.mjs', fixtures));
  const child = spawn(process.execPath, [...args, script, '30000'], { stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    let err = '', out = '';
    const timer = setTimeout(() => reject(new Error(`target did not start: ${err}`)), 15_000);
    const check = () => { const m = /ws:\/\/127\.0\.0\.1:(\d+)\//.exec(err); if (out.includes('ready') && (m || !args.length)) { clearTimeout(timer); resolve({ child, port: m ? Number(m[1]) : undefined }); } };
    child.stderr!.on('data', (d) => { err += d; check(); });
    child.stdout!.on('data', (d) => { out += d; check(); });
  });
}

test('Node inspector attach by port records scripts, call counts and a CPU profile', async () => {
  const { child, port } = await spawnTarget(['--inspect=127.0.0.1:0']);
  try {
    const r = await attachNodeInspector({ allowExecution: true, port, durationMs: 800 });
    assert.equal(r.attachedVia, 'port');
    const script = fileURLToPath(new URL('node-target.mjs', fixtures));
    assert.ok(r.scripts.some((s) => s.url.endsWith('node-target.mjs')), JSON.stringify(r.scripts.map((s) => s.url)));
    const tick = r.calls.find((c) => c.name === 'tick' && c.url.endsWith('node-target.mjs'));
    assert.ok(tick && tick.count > 10, JSON.stringify(r.calls.slice(0, 5)));
    assert.equal(tick!.offset, readFileSync(script, 'utf8').indexOf('function tick'));
    assert.ok(r.cpu!.samples > 50);
    assert.ok(r.cpu!.top.some((f) => f.name === 'tick' || f.name === 'hotLoop'), JSON.stringify(r.cpu!.top.slice(0, 5)));
    assert.ok(r.heap!.usedSize > 0);
  } finally { child.kill(); }
});

test('Node inspector attach by pid switches the inspector on with a signal', async (t) => {
  if (process.platform === 'win32') { t.skip('signal path is POSIX'); return; }
  const port = 9229;
  const busy = await new Promise<boolean>((r) => { const s = netServer(); s.once('error', () => r(true)); s.listen(port, '127.0.0.1', () => s.close(() => r(false))); });
  if (busy) { t.skip('port 9229 in use'); return; }
  const { child } = await spawnTarget([]);
  try {
    const r = await attachNodeInspector({ allowExecution: true, pid: child.pid, durationMs: 400, cpuProfile: false });
    assert.equal(r.attachedVia, 'pid-signal');
    assert.ok(r.calls.some((c) => c.name === 'tick'));
  } finally { child.kill(); }
});
