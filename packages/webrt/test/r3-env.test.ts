// Round 3 runtime tests with a real Chromium against the envapp fixture server: record a scenario with
// bodies, join static and observed endpoints, build a replay environment, serve it, run the same
// scenario against the replay and compare, export the zip and score its tasks with extras x_eval_score.
// They skip when no browser starts (REVLENS_CHROMIUM or the Playwright download).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { mkdtemp, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import { runScenario, TOOLS } from '../src/node.js';
import { compareStaticAndObservedEndpoints, buildEnvironment, EnvMatcher, matchTemplate } from '../src/index.js';
import { buildEnvironmentFromFile, serveEnvironment, exportEnvironment, loadEnvironment, crc32 } from '../src/env-node.js';
import { listZip, readZipEntry } from '../src/trace.js';
import { scoreAnswers } from '../../extras/src/eval/harness.js';
// @ts-expect-error plain JavaScript fixture server
import { createEnvApp } from '../../../samples/webrt/envapp/server.mjs';

const exe = process.env.REVLENS_CHROMIUM || undefined;
const S = fileURLToPath(new URL('../../../samples/webrt/', import.meta.url));
let available = false;
let server: Server; let base = '';
let work = '';
let recorded: any;

before(async () => {
  try { const pw = await import('playwright' as string); const b = await pw.chromium.launch({ executablePath: exe, timeout: 20_000 }); await b.close(); available = true; } catch { available = false; }
  server = createEnvApp();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
  work = await mkdtemp(join(tmpdir(), 'revlens-r3-env-'));
});
after(() => { server?.close(); });

const spec = () => JSON.parse(readFileSync(join(S, 'envapp/scenario.json'), 'utf8'));

test('matchTemplate binds holes and refuses partial matches', () => {
  assert.deepEqual(matchTemplate('/api/items/{p1}', '/api/items/42', false), ['42']);
  assert.deepEqual(matchTemplate('/u/{p1}.json', '/u/ann%20b.json', false), ['ann b']);
  assert.equal(matchTemplate('/api/items/{p1}', '/api/items', false), undefined);
  assert.equal(matchTemplate('/api/items/{p1}', '/api/items/', false), undefined);
  assert.deepEqual(matchTemplate('/items/{p1}', '/v2/items/7', true), ['7']);
  assert.equal(matchTemplate('/items/{p1}', '/v2/items/7', false), undefined);
});

test('record the envapp scenario in Chromium with request and response bodies', { timeout: 120_000 }, async (t) => {
  if (!available) return t.skip('no browser');
  recorded = await runScenario({ ...spec(), startUrl: base }, { outDir: join(work, 'rec'), executablePath: exe, recordBodies: true, traces: false, screenshots: false });
  assert.equal(recorded.passed, true, JSON.stringify(recorded.steps.filter((s: any) => !s.ok)));
  const byPath = (p: string, m = 'GET') => recorded.har.log.entries.filter((e: any) => e.request.method === m && new URL(e.request.url).pathname === p);
  // bodies are exactly what the fixture server sends
  assert.equal(byPath('/api/items')[0].response.content.text, JSON.stringify({ items: [{ id: 1, name: 'alpha', price: 3 }, { id: 2, name: 'beta', price: 4 }], total: 2 }));
  assert.equal(byPath('/api/items')[1].response.content.text.includes('"gamma"'), true);
  assert.equal(byPath('/api/items', 'POST')[0].request.postData.text, '{"name":"gamma"}');
  // a response the page never reads is still recorded (CDP Fetch at the response stage)
  assert.equal(byPath('/api/ping')[0].response.content.text, '{"pong":true}');
  assert.equal(byPath('/app.js')[0].response.content.text, readFileSync(join(S, 'envapp/public/app.js'), 'utf8'));
});

test('compare_static_and_observed_endpoints on the recorded session', (t) => {
  if (!recorded) return t.skip('no recording');
  const j = compareStaticAndObservedEndpoints({ capture: recorded });
  assert.deepEqual(j.matched.map((m) => m.static.key).sort(), ['GET /api/items', 'GET /api/items/{p1}', 'GET /api/ping', 'GET /api/search', 'GET /api/session', 'POST /api/items']);
  assert.deepEqual(j.matched.find((m) => m.static.key === 'GET /api/items/{p1}')!.params, { p1: ['1'] });
  assert.deepEqual(j.matched.find((m) => m.static.key === 'GET /api/search')!.queryObserved, ['page', 'q']);
  assert.deepEqual(j.staticOnly.map((s) => s.key).sort(), ['POST /api/admin/export', 'POST telemetry.envapp.example/collect']);
  assert.deepEqual(j.observedOnly.map((o) => `${o.method} ${o.template} ${o.reason}`), ['GET /api/dyn/part-7 no-static-source']);
  assert.equal(j.summary.staticCoverage, 0.75);
  // the static side points at app.js lines
  const site = j.matched.find((m) => m.static.key === 'POST /api/items')!.static.sites[0]!;
  assert.equal(readFileSync(join(S, 'envapp/public/app.js'), 'utf8').split('\n')[site.line - 1]!.includes("fetch('/api/items'"), true);
});

test('env build, serve on localhost, replay the scenario with equal results', { timeout: 120_000 }, async (t) => {
  if (!recorded) return t.skip('no recording');
  const b = await buildEnvironmentFromFile(join(work, 'rec', 'capture.json'), join(work, 'env'), { name: 'envapp' });
  assert.equal(b.manifest.name, 'envapp');
  assert.equal(b.manifest.origin, base.slice(0, -1));
  assert.ok(b.manifest.routes.length >= 11);
  assert.deepEqual(b.manifest.warnings, []);
  await assert.rejects(buildEnvironmentFromFile(join(work, 'rec', 'capture.json'), join(work, 'env')), /not empty/);
  await assert.rejects(serveEnvironment(join(work, 'env'), { host: '0.0.0.0' }), /loopback/);
  const env = await serveEnvironment(join(work, 'env'), { ttlMs: 90_000 });
  try {
    const replay = await runScenario({ ...spec(), startUrl: env.url }, { outDir: join(work, 'replay'), executablePath: exe, recordBodies: true, traces: false, screenshots: false });
    assert.equal(replay.passed, true);
    const label = (c: any) => c.har.log.entries.filter((e: any) => !e._failed && !e.request.url.endsWith('/favicon.ico')).map((e: any) => `${e.request.method} ${new URL(e.request.url).pathname}${new URL(e.request.url).search} ${e.response.status} ${e.response.content.text ?? ''}`).sort();
    assert.deepEqual(label(replay), label(recorded));
    recorded.steps.forEach((s: any, i: number) => {
      assert.equal(replay.steps[i]!.ok, s.ok);
      assert.deepEqual(replay.steps[i]!.assertions.map((a: any) => a.actual), s.assertions.map((a: any) => a.actual), `step ${i}`);
      // step 0 is a snapshot right after load, before late fetches settle; later steps wait on selectors
      if (i > 0) assert.equal(replay.steps[i]!.dom?.sha256, s.dom?.sha256, `dom step ${i}`);
    });
    assert.ok(env.log.filter((l) => l.rule === 'exact').length >= 11);
    // the second GET /api/items gets the second recording (three items), as in the live app
    const items = env.log.filter((l) => l.path === '/api/items' && l.method === 'GET');
    assert.deepEqual(items.map((l) => l.sequence), [0, 1]);
    const log = await (await fetch(env.url + '__revlens/log')).json();
    assert.ok(log.served >= 11);
    const miss = await fetch(env.url + 'api/nothing');
    assert.equal(miss.status, 404);
  } finally { await env.close(); }
});

test('env matching rules: sequence, query names, template, hosts and request bodies', () => {
  const har = { log: { entries: [
    { request: { method: 'GET', url: 'https://a.example/' }, response: { status: 200, headers: [{ name: 'content-type', value: 'text/html' }], content: { mimeType: 'text/html', text: '<p>hi' } }, _resourceType: 'document' },
    { request: { method: 'GET', url: 'https://a.example/n' }, response: { status: 200, headers: [], content: { text: '1' } } },
    { request: { method: 'GET', url: 'https://a.example/n' }, response: { status: 200, headers: [], content: { text: '2' } } },
    { request: { method: 'GET', url: 'https://a.example/s?q=x&p=1' }, response: { status: 200, headers: [], content: { text: 'sx' } } },
    { request: { method: 'GET', url: 'https://a.example/u/17' }, response: { status: 200, headers: [], content: { text: 'u17' } } },
    { request: { method: 'POST', url: 'https://a.example/f', postData: { text: 'A' } }, response: { status: 201, headers: [], content: { text: 'fa' } } },
    { request: { method: 'POST', url: 'https://a.example/f', postData: { text: 'B' } }, response: { status: 202, headers: [], content: { text: 'fb' } } },
    { request: { method: 'GET', url: 'https://cdn.example/lib.js' }, response: { status: 200, headers: [], content: { text: 'x()' } } },
  ] } };
  const env = buildEnvironment(har, { name: 'Rules Test!' });
  assert.equal(env.manifest.name, 'rules-test');
  assert.equal(env.manifest.origin, 'https://a.example');
  const m = new EnvMatcher(env.manifest);
  const body = (r: any) => r.route ? new TextDecoder().decode(env.files.find((f) => f.path === r.route.body.file)!.bytes) : undefined;
  assert.deepEqual([m.match('GET', '/n'), m.match('GET', '/n'), m.match('GET', '/n')].map(body), ['1', '2', '2']);
  assert.equal(m.match('GET', '/s?p=1&q=x').rule, 'exact');
  const qn = m.match('GET', '/s?q=y&p=9'); assert.equal(qn.rule, 'query-names'); assert.equal(body(qn), 'sx');
  const tp = m.match('GET', '/u/99'); assert.equal(tp.rule, 'template'); assert.equal(body(tp), 'u17');
  const sha = (s: string) => require256(s);
  assert.equal(m.match('POST', '/f', { bodySha256: sha('B') }).route?.status, 202);
  assert.equal(m.match('POST', '/f', { bodySha256: sha('A') }).route?.status, 201);
  assert.equal(body(m.match('GET', '/__host/cdn.example/lib.js')), 'x()');
  assert.equal(m.match('GET', '/missing').rule, 'none');
  m.reset();
  assert.equal(body(m.match('GET', '/n')), '1');
});
import { createHash } from 'node:crypto';
function require256(s: string): string { return createHash('sha256').update(s).digest('hex'); }

test('env export: deterministic zip with manifest first, CRCs that unzip checks, tasks scored by extras x_eval_score', { timeout: 60_000 }, async (t) => {
  if (!existsSync(join(work, 'env', 'manifest.json'))) return t.skip('no environment built');
  const a = await exportEnvironment(join(work, 'env'), join(work, 'env-a.zip'));
  const b = await exportEnvironment(join(work, 'env'), join(work, 'env-b.zip'));
  assert.equal(a.sha256, b.sha256);
  const zip = new Uint8Array(readFileSync(a.zip));
  const entries = listZip(zip);
  assert.equal(entries[0]!.name, 'manifest.json');
  assert.ok(entries.some((e) => e.name === 'tasks/tasks.json') && entries.some((e) => e.name === 'scenario.json') && entries.some((e) => e.name === 'README.md'));
  for (const e of entries) assert.equal(crc32(readZipEntry(zip, e)), new DataView(zip.buffer, zip.byteOffset + e.localOffset + 14, 4).getUint32(0, true), e.name);
  // the system unzip agrees when it is installed
  const { execFileSync } = await import('node:child_process');
  try { const out = execFileSync('unzip', ['-t', a.zip], { encoding: 'utf8', timeout: 20_000 }); assert.match(out, /No errors detected/); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  // the zip serves like the folder
  const env = await serveEnvironment(a.zip, { ttlMs: 10_000 });
  try { assert.equal(await (await fetch(env.url + 'api/session')).text(), '{"user":"demo","roles":["reader"]}'); } finally { await env.close(); }
  const { manifest } = await loadEnvironment(a.zip);
  const tasks = manifest.tasks as any[];
  assert.ok(tasks.length >= 10);
  const ids = tasks.map((x) => x.id);
  assert.ok(ids.includes('envapp-api-endpoints') && ids.includes('envapp-dead-endpoints') && ids.includes('envapp-runtime-endpoints'));
  assert.deepEqual(tasks.find((x) => x.id === 'envapp-runtime-endpoints').answer, ['GET /api/dyn/part-7']);
  // perfect answers score 1 with the extras harness; one wrong answer lowers it
  const perfect = Object.fromEntries(tasks.map((x) => [x.id, x.answer]));
  const s1 = scoreAnswers(perfect, { tasks, agent: 'oracle' });
  assert.equal(s1.correct, tasks.length);
  const s2 = scoreAnswers({ ...perfect, 'envapp-text-step6-detail': 'beta costs 4' }, { tasks });
  assert.equal(s2.correct, tasks.length - 1);
  assert.equal((await readdir(join(work, 'env', 'bodies'))).length, new Set(manifest.routes.filter((r) => r.body).map((r) => r.body!.sha256)).size);
});

test('env tools are registered in the Node TOOLS list', () => {
  for (const n of ['web_env_build', 'web_env_serve', 'web_env_stop', 'web_env_export', 'web_endpoint_join']) assert.ok(TOOLS.some((x) => x.name === n), n);
});
