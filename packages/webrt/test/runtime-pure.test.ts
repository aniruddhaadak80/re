// Pure logic for the runtime features: PNG decode and pixel diff (checked against Pillow), capture
// comparison, WebMCP static scans and well-known classification, scenario validation, hostile inputs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { inflateSync, deflateSync } from 'node:zlib';
import fc from 'fast-check';
import { decodePng, encodePng, diffImages, compareCaptures, endpointPattern, scanWebMcpScript, scanHtmlForMcp, classifyWellKnown, agentHeaderHints, TOOLS } from '../src/index.js';
import { validateScenario } from '../src/scenario.js';
import { listZip } from '../src/trace.js';
import { checkDevtoolsEndpoint } from '../src/cdp.js';
import { attachNodeInspector } from '../src/inspector.js';

const dir = new URL('../../../samples/webrt/runtime/', import.meta.url);
const read = (f: string) => new Uint8Array(readFileSync(new URL(f, dir)));
const ref = JSON.parse(readFileSync(new URL('png-reference.json', dir), 'utf8'));
const inflate = (d: Uint8Array) => new Uint8Array(inflateSync(d));

test('PNG decode matches Pillow for RGB, RGBA, 2-bit palette, grey, grey+alpha and 16-bit grey', async () => {
  for (const f of ['a-rgb.png', 'b-rgb.png', 'a-rgba.png', 'a-palette.png', 'a-grey.png', 'a-greyalpha.png', 'a-grey16.png']) {
    const img = await decodePng(read(f), inflate);
    const r = ref[f];
    assert.deepEqual([img.width, img.height], r.size, f);
    assert.equal(createHash('sha256').update(img.data).digest('hex'), r.sha256_rgba, `${f} pixels`);
    if (r.px_10_10) { const o = (10 * img.width + 10) * 4; assert.deepEqual([...img.data.subarray(o, o + 4)], r.px_10_10); }
  }
});

test('PNG decode works with the browser DecompressionStream path too', async () => {
  const img = await decodePng(read('a-rgb.png'));
  assert.equal(createHash('sha256').update(img.data).digest('hex'), ref['a-rgb.png'].sha256_rgba);
});

test('pixel diff count and bounding box match Pillow ImageChops', async () => {
  const a = await decodePng(read('a-rgb.png'), inflate), b = await decodePng(read('b-rgb.png'), inflate);
  const d = diffImages(a, b, { mask: true });
  assert.equal(d.diffPixels, ref.diff_a_b.diffPixels); // 256
  const [x0, y0, x1, y1] = ref.diff_a_b.bbox; // Pillow bbox is exclusive on the right and bottom
  assert.deepEqual(d.bbox, { x: x0, y: y0, width: x1 - x0, height: y1 - y0 });
  assert.equal(d.similarity, Math.round((1 - 256 / (64 * 48)) * 1e6) / 1e6);
  // encode the mask, decode again: white pixels equal the diff count
  const png = await encodePng(d.mask!, (r) => new Uint8Array(deflateSync(r)));
  const m = await decodePng(png, inflate);
  let white = 0; for (let i = 0; i < m.data.length; i += 4) if (m.data[i] === 255) white++;
  assert.equal(white, 256);
  assert.equal(diffImages(a, a).diffPixels, 0);
});

test('endpoint patterns normalise ids and keep query keys only', () => {
  assert.deepEqual(endpointPattern('https://api.x.com/v1/users/12345/posts/550e8400-e29b-41d4-a716-446655440000?b=2&a=1'), { host: 'api.x.com', path: '/v1/users/{id}/posts/{id}?a&b' });
});

test('compareCaptures reports endpoint, header, script, console changes and a score', async () => {
  const entry = (method: string, url: string, status: number, rh: Record<string, string>) => ({ request: { method, url, headers: [] }, response: { status, headers: Object.entries(rh).map(([name, value]) => ({ name, value })) } });
  const a = { har: { log: { entries: [entry('GET', 'https://a.test/api/items/1', 200, { server: 'nginx', 'x-frame-options': 'DENY' }), entry('GET', 'https://a.test/api/old', 200, {})] } }, scripts: [{ url: 'https://a.test/app.js?v=1', sha256: 'aa', size: 10 }, { url: 'https://a.test/vendor.js', sha256: 'vv' }], console: [{ type: 'log', text: 'boot' }] };
  const b = { har: { log: { entries: [entry('GET', 'https://a.test/api/items/2', 500, { server: 'envoy' }), entry('POST', 'https://a.test/api/new', 201, {})] } }, scripts: [{ url: 'https://a.test/app.js?v=2', sha256: 'bb', size: 12 }, { url: 'https://a.test/vendor.js', sha256: 'vv' }], console: [{ type: 'log', text: 'boot' }, { type: 'error', text: 'boom' }] };
  const r = await compareCaptures(a, b);
  assert.deepEqual(r.endpoints.added.map((e) => e.key), ['POST a.test/api/new']);
  assert.deepEqual(r.endpoints.removed.map((e) => e.key), ['GET a.test/api/old']);
  assert.equal(r.endpoints.common, 1);
  assert.deepEqual(r.endpoints.statusChanged, [{ key: 'GET a.test/api/items/{id}', before: [200], after: [500] }]);
  const h = r.headers.find((x) => x.side === 'response')!;
  assert.deepEqual(h.removed, ['x-frame-options']);
  assert.deepEqual(h.changed, [{ name: 'server', before: 'nginx', after: 'envoy' }]);
  assert.deepEqual(r.scripts.changed.map((s) => s.url), ['https://a.test/app.js']);
  assert.equal(r.scripts.same, 1);
  assert.deepEqual(r.console.added, ['error: boom']);
  // endpoints 1/3, headers 0/2 (server changed, x-frame-options removed), scripts 1/3, console 1/2
  assert.deepEqual(r.parts.map((p) => [p.name, p.similarity]), [['endpoints', 0.3333], ['headers', 0], ['scripts', 0.3333], ['console', 0.5]]);
  assert.ok(Math.abs(r.score - (0.35 / 3 + 0.25 / 3 + 0.05 / 2) / 0.8) < 1e-4);
  const same = await compareCaptures(a, a);
  assert.equal(same.score, 1);
});

test('WebMCP static scan finds registerTool, provideContext through an alias, and unregisterTool', () => {
  const js = new TextDecoder().decode(read('webmcp-app.js'));
  const r = scanWebMcpScript(js, { source: 'webmcp-app.js' });
  assert.deepEqual(r.tools.map((t) => `${t.api}:${t.name}`), ['modelContext.provideContext:list_todos', 'modelContext.provideContext:clear_done', 'modelContext.unregisterTool:legacy_tool']);
  const clear = r.tools.find((t) => t.name === 'clear_done')!;
  assert.deepEqual(clear.inputProperties, ['confirm']);
  assert.deepEqual(clear.required, ['confirm']);
  assert.equal(clear.description, 'Remove finished todos');
  assert.equal(clear.line, 7);
});

test('HTML scan finds the declarative tool form, MCP link, meta and inline registerTool', () => {
  const html = new TextDecoder().decode(read('webmcp-page.html'));
  const h = scanHtmlForMcp(html);
  assert.deepEqual(h.forms, [{ toolName: 'search_todos', toolDescription: 'Search the todo list by text', action: '/search', fields: ['q', 'status'] }]);
  assert.deepEqual(h.links, [{ rel: 'mcp', href: '/.well-known/mcp.json', type: 'application/mcp+json' }]);
  assert.deepEqual(h.meta, [{ name: 'webmcp', content: 'enabled' }]);
  assert.deepEqual(h.scriptSrcs, ['/webmcp-app.js']);
  const inline = scanWebMcpScript(h.inlineScripts[0]!);
  assert.equal(inline.tools[0]!.name, 'add_todo');
  assert.deepEqual(inline.tools[0]!.inputProperties, ['title', 'due']);
  assert.deepEqual(inline.tools[0]!.required, ['title']);
});

test('well-known documents are classified', () => {
  const mcp = classifyWellKnown('/.well-known/mcp.json', 200, 'application/json', new TextDecoder().decode(read('mcp.json')));
  assert.equal(mcp.kind, 'mcp-server-card'); assert.equal(mcp.name, 'todo-mcp');
  assert.deepEqual(mcp.endpoints, ['https://todo.example/mcp']); assert.deepEqual(mcp.tools, ['add_todo', 'list_todos']);
  const a2a = classifyWellKnown('/.well-known/agent-card.json', 200, 'application/json', new TextDecoder().decode(read('agent-card.json')));
  assert.equal(a2a.kind, 'a2a-agent-card'); assert.deepEqual(a2a.tools, ['manage_todos']);
  const prm = classifyWellKnown('/.well-known/oauth-protected-resource', 200, 'application/json', '{"resource":"https://x.test/mcp","authorization_servers":["https://auth.x.test"]}');
  assert.equal(prm.kind, 'oauth-protected-resource'); assert.deepEqual(prm.endpoints, ['https://x.test/mcp', 'https://auth.x.test']);
  assert.equal(classifyWellKnown('/llms.txt', 200, 'text/plain', '# Site\n\n- [Docs](https://x.test/docs)').kind, 'llms-txt');
  assert.equal(classifyWellKnown('/llms.txt', 200, 'text/html', '<html># x').kind, 'other');
  assert.deepEqual(agentHeaderHints({ 'mcp-session-id': 'secret', link: '</.well-known/mcp>; rel="mcp"', server: 'x' }).map((h) => h.value), ['[present]', '</.well-known/mcp>; rel="mcp"']);
});

test('web_webmcp_scan and web_capture_compare tools work from text (browser entry)', async () => {
  const scan = TOOLS.find((t) => t.name === 'web_webmcp_scan')!;
  const r = (await scan.run({ text: new TextDecoder().decode(read('webmcp-page.html')) })) as any;
  assert.equal(r.kind, 'html'); assert.equal(r.forms[0].toolName, 'search_todos'); assert.equal(r.tools[0].name, 'add_todo');
  const cmp = TOOLS.find((t) => t.name === 'web_capture_compare')!;
  const har = readFileSync(new URL('../../../samples/webrt/har-redirect.har', import.meta.url), 'utf8');
  assert.equal(((await cmp.run({ aText: har, bText: har })) as any).score, 1);
});

test('scenario validation rejects bad specs', () => {
  assert.throws(() => validateScenario({}), /steps/);
  assert.throws(() => validateScenario({ steps: [{ action: 'eval' }] }), /unknown action/);
  assert.throws(() => validateScenario({ steps: [{ action: 'click' }] }), /selector/);
  assert.throws(() => validateScenario({ steps: [{ action: 'type', selector: '#a' }] }), /text/);
  assert.throws(() => validateScenario({ steps: Array.from({ length: 300 }, () => ({ action: 'wait' })) }), /limit/);
  assert.ok(validateScenario({ steps: [{ action: 'wait', ms: 1 }] }));
});

test('DevTools endpoints must be loopback unless allowed, inspector attach needs allowExecution', async () => {
  assert.throws(() => checkDevtoolsEndpoint('http://10.0.0.5:9222'), /loopback/);
  assert.equal(checkDevtoolsEndpoint('9222').host, '127.0.0.1:9222');
  assert.ok(checkDevtoolsEndpoint('http://10.0.0.5:9222', true));
  const prev = process.env.REVLENS_ALLOW_EXECUTION; delete process.env.REVLENS_ALLOW_EXECUTION;
  await assert.rejects(attachNodeInspector({ port: 1 }), /allowExecution/);
  if (prev !== undefined) process.env.REVLENS_ALLOW_EXECUTION = prev;
});

test('hostile inputs: random bytes never crash the PNG, zip and WebMCP parsers', async () => {
  await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 2000 }), async (b) => {
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...b]);
    try { await decodePng(png, inflate); } catch (e) { assert.ok(e instanceof Error); }
    try { listZip(b); } catch (e) { assert.ok(e instanceof Error); }
  }), { numRuns: 300 });
  fc.assert(fc.property(fc.string({ maxLength: 3000 }), (s) => { scanHtmlForMcp(s); try { scanWebMcpScript('navigator.modelContext;' + s); } catch (e) { assert.ok(e instanceof Error); } }), { numRuns: 300 });
  // a huge declared size is refused before allocating
  const ihdr = read('a-rgb.png').slice();
  new DataView(ihdr.buffer).setUint32(16, 100_000); new DataView(ihdr.buffer).setUint32(20, 100_000);
  await assert.rejects(decodePng(ihdr, inflate), /pixel limit|truncated|IHDR/);
  // deep HTML and unterminated tags stay linear
  const t0 = Date.now(); scanHtmlForMcp('<form toolname=a '.repeat(50_000)); assert.ok(Date.now() - t0 < 3000);
});

test('capture-compare CLI prints a score for two HAR files', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const runner = fileURLToPath(new URL('./cli-runner.ts', import.meta.url));
  const S = fileURLToPath(new URL('../../../samples/webrt/', import.meta.url));
  const r = spawnSync(process.execPath, ['--import', 'tsx', runner, 'capture-compare', S + 'har-redirect.har', S + 'har-fulfill.har'], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^similarity score 0(\.\d+)? \(endpoints=/);
  const j = spawnSync(process.execPath, ['--import', 'tsx', runner, 'capture-compare', S + 'har-redirect.har', S + 'har-redirect.har', '--json'], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(JSON.parse(j.stdout).score, 1);
});
