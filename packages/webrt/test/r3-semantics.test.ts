// Semantic runtime tracing and runtime to bundle reconciliation, checked against the real programs:
// argument and return values must equal what the traced program itself prints, line numbers must equal
// a plain text search of the source, request URLs must equal what the fixture server saw, and the
// reconciler must place semver calls in the esbuild module that esbuild itself named in its source map.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import fc from 'fast-check';
import { traceNodeSemantics, traceBrowserSemantics, findFunctions, TOOLS } from '../src/node.js';
import { reconcileJavaScriptRuntime } from '../src/index.js';
// @ts-expect-error plain JavaScript fixture server
import { createEnvApp } from '../../../samples/webrt/envapp/server.mjs';

const S = fileURLToPath(new URL('../../../samples/webrt/', import.meta.url));
const R = join(S, 'runtime');
const exe = process.env.REVLENS_CHROMIUM || undefined;
const lineOf = (file: string, needle: string) => readFileSync(file, 'utf8').split('\n').findIndex((l) => l.includes(needle)) + 1;
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
let work = '';
before(() => { work = mkdtempSync(join(tmpdir(), 'revlens-sem-')); });
after(() => { rmSync(work, { recursive: true, force: true }); });

test('Node inspector: entries, arguments, returns, timers and requests of trace-target.mjs', { timeout: 60_000 }, async () => {
  const r = await traceNodeSemantics({ allowExecution: true, script: join(R, 'trace-target.mjs'), functions: ['add', 'Calc.mul', 'describe'], durationMs: 8_000 });
  assert.equal(r.exitCode, 0, r.stderr);
  const printed = JSON.parse(r.stdout!.trim().split('\n').pop()!);
  assert.deepEqual(printed.out, [3, 15, 24, 0, 'ann (2 tags)']);
  const ev = r.events.filter((e) => e.kind === 'enter' || e.kind === 'exit');
  assert.deepEqual(ev.map((e) => `${e.kind} ${e.fn}`), ['enter add', 'exit add', 'enter add', 'exit add', 'enter Calc.mul', 'exit Calc.mul', 'enter Calc.mul', 'exit Calc.mul', 'enter describe', 'exit describe']);
  // arguments as passed, the default parameter as bound
  assert.deepEqual(ev.filter((e) => e.kind === 'enter').map((e) => e.args), [{ a: '1', b: '2' }, { a: '5', b: '10' }, { x: '3', y: '4' }, { x: '0', y: '9' }, { user: '{name: "ann", tags: Array(2)}' }]);
  // return values equal what the program printed, including the early return of mul(0, 9)
  assert.deepEqual(ev.filter((e) => e.kind === 'exit').map((e) => e.returnValue), ['3', '15', '24', '0', JSON.stringify('ann (2 tags)')]);
  const file = join(R, 'trace-target.mjs');
  const fns = Object.fromEntries(r.functions.map((f) => [f.name, f]));
  assert.equal(fns.add!.line, lineOf(file, 'export function add'));
  assert.equal(fns['Calc.mul']!.line, lineOf(file, 'mul(x, y)'));
  assert.equal(fns['Calc.mul']!.returnPoints, 2, 'two return statements');
  assert.equal(r.summary.calls.add, 2);
  assert.ok((r.summary.timers.setTimeout ?? 0) >= 1);
  const req = r.events.find((e) => e.kind === 'request')!;
  assert.match(req.request!.url, /^http:\/\/127\.0\.0\.1:\d+\/ping\?x=1$/);
  assert.ok(req.stack!.some((s) => s.includes('trace-target.mjs')), 'request stack starts in the program');
  assert.deepEqual(r.summary.unmatchedSelectors, []);
});

test('logpoint mode never pauses and records the same calls and arguments', { timeout: 60_000 }, async () => {
  const r = await traceNodeSemantics({ allowExecution: true, script: join(R, 'trace-target.mjs'), functions: ['add', 'Calc.mul', 'describe'], mode: 'logpoint', durationMs: 8_000 });
  assert.equal(r.mode, 'logpoint');
  assert.equal(r.exitCode, 0);
  // the logpoint markers do not leak into the program output
  assert.deepEqual(JSON.parse(r.stdout!.trim()).out, [3, 15, 24, 0, 'ann (2 tags)']);
  assert.equal(r.events.filter((e) => e.kind === 'exit').length, 0, 'no return breakpoints in logpoint mode');
  assert.deepEqual(r.events.filter((e) => e.kind === 'enter').map((e) => `${e.fn} ${JSON.stringify(e.args)}`), ['add {"a":"1","b":"2"}', 'add {"a":"5","b":"10"}', 'Calc.mul {"x":"3","y":"4"}', 'Calc.mul {"x":"0","y":"9"}', 'describe {"user":"[object Object]"}']);
  assert.deepEqual(r.summary.calls, { add: 2, 'Calc.mul': 2, describe: 1 });
});

test('semver 7.7.1 esbuild bundle: trace calls, then reconcile with the bundle and its source map', { timeout: 90_000 }, async (t) => {
  let esbuild: any;
  try { esbuild = await import('esbuild' as string); } catch { return t.skip('esbuild not installed'); }
  const pkg = join(S, 'shapes/semver-7.7.1');
  const outfile = join(work, 'semver.bundle.cjs');
  await esbuild.build({ entryPoints: [join(pkg, 'index.js')], bundle: true, format: 'cjs', platform: 'node', outfile, sourcemap: true, sourcesContent: true, logLevel: 'silent' });
  const runner = join(work, 'runner.cjs');
  writeFileSync(runner, "const s = require('./semver.bundle.cjs');\nconsole.log(JSON.stringify([s.satisfies('1.2.3', '^1.0.0'), s.satisfies('2.0.0', '~1.2'), s.compare('1.2.3', '1.10.0'), s.parse('2.0.0-rc.1').prerelease.join('.')]));\n");
  const trace = await traceNodeSemantics({ allowExecution: true, script: runner, functions: ['satisfies', 'compare'], durationMs: 8_000 });
  // reference: the real semver package called in this process
  const real = createRequire(import.meta.url)(pkg);
  const expected = [real.satisfies('1.2.3', '^1.0.0'), real.satisfies('2.0.0', '~1.2'), real.compare('1.2.3', '1.10.0'), real.parse('2.0.0-rc.1').prerelease.join('.')];
  assert.deepEqual(JSON.parse(trace.stdout!.trim()), expected);
  const sat = trace.events.filter((e) => e.fn === 'satisfies');
  assert.deepEqual(sat.filter((e) => e.kind === 'enter').map((e) => [e.args!.version, e.args!.range]), [['"1.2.3"', '"^1.0.0"'], ['"2.0.0"', '"~1.2"']]);
  assert.deepEqual(sat.filter((e) => e.kind === 'exit').map((e) => e.returnValue), [String(expected[0]), String(expected[1])]);
  assert.deepEqual(trace.summary.unmatchedSelectors, [], 'esbuild renamed satisfies2 is found by its plain name');

  const code = readFileSync(outfile, 'utf8');
  const rec = reconcileJavaScriptRuntime(trace, [{ name: 'semver.bundle.cjs', code, sourceMap: readFileSync(outfile + '.map', 'utf8') }, { name: 'unused.js', code: 'var x = 1;' }]);
  const s = rec.scripts.find((x) => x.bundle === 'semver.bundle.cjs')!;
  assert.equal(s.matchedBy, 'sha256');
  assert.deepEqual(rec.unusedBundles, ['unused.js']);
  const satMod = s.modules.find((m) => m.path?.endsWith('functions/satisfies.js'))!;
  assert.equal(satMod.enter, 2);
  assert.deepEqual(satMod.functions, ['satisfies']);
  const loc = s.locations.find((l) => l.label === 'enter satisfies')!;
  assert.ok(loc.original!.source.endsWith('functions/satisfies.js'), loc.original!.source);
  // first statement of the arrow body, found by text in the original file
  assert.equal(loc.original!.line, lineOf(join(pkg, 'functions/satisfies.js'), 'range = new Range(range, options)'));
  assert.ok(s.coldModules.some((m) => m.path?.endsWith('functions/inc.js')), 'inc never ran');
  assert.ok(!s.coldModules.some((m) => m.path?.endsWith('functions/compare.js')));
  assert.ok(rec.summary.mappedToSource >= 4);
});

test('reconcile the shipped semver bundle (no map) through the tool: modules named by the __commonJS keys', { timeout: 90_000 }, async () => {
  const runtime = await tool('web_trace_semantics').run({ allowExecution: true, script: join(R, 'semver-runner.cjs'), functions: ['satisfies', 'compare', 'parse'], durationMs: 6_000 }) as any;
  const rec = await tool('web_reconcile_runtime').run({ runtime, bundlePaths: [join(S, 'shapes/semver-7.7.1.bundle.cjs'), join(S, 'shapes/semver-6.3.1.bundle.cjs')] }) as any;
  const s = rec.scripts.find((x: any) => x.bundle.endsWith('semver-7.7.1.bundle.cjs'));
  assert.equal(s.matchedBy, 'sha256');
  assert.equal(s.bundler, 'esbuild');
  const bundle = readFileSync(join(S, 'shapes/semver-7.7.1.bundle.cjs'), 'utf8');
  // every module path the reconciler names is a __commonJS key esbuild wrote into the bundle
  for (const m of s.modules) assert.ok(bundle.includes(`"${m.path}"(exports`), m.path);
  assert.ok(s.modules.some((m: any) => m.path.endsWith('functions/satisfies.js') && m.enter === 1));
  assert.ok(rec.unusedBundles.some((b: string) => b.endsWith('semver-6.3.1.bundle.cjs')));
});

test('Chromium: trace the envapp page, with an action, through CDP', { timeout: 120_000 }, async (t) => {
  try { const pw = await import('playwright' as string); const b = await pw.chromium.launch({ executablePath: exe, timeout: 20_000 }); await b.close(); } catch { return t.skip('no browser'); }
  const server: Server = createEnvApp();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
  try {
    const r = await traceBrowserSemantics(base, { functions: ['computeTotal', 'renderItems', 'loadItems', 'search'], executablePath: exe, durationMs: 1_500, actions: [{ action: 'fill', selector: '#q', text: 'al' }, { action: 'click', selector: '#search' }] });
    assert.equal(r.target.kind, 'chromium');
    const ct = r.events.filter((e) => e.fn === 'computeTotal');
    // the fixture server sends prices 3 and 4: total 7 with the default tax rate 0
    assert.equal(ct.find((e) => e.kind === 'exit')!.returnValue, '7');
    assert.equal(ct.find((e) => e.kind === 'enter')!.args!.taxRate, '0');
    assert.equal(r.events.find((e) => e.kind === 'enter' && e.fn === 'search')!.args!.q, '"al"');
    const app = join(S, 'envapp/public/app.js');
    assert.equal(r.functions.find((f) => f.name === 'computeTotal')!.line, lineOf(app, 'function computeTotal'));
    const reqs = r.events.filter((e) => e.kind === 'request').map((e) => new URL(e.request!.url).pathname + new URL(e.request!.url).search);
    for (const p of ['/api/items', '/api/session', '/api/search?q=al&page=1', '/api/dyn/part-7']) assert.ok(reqs.includes(p), `${p} in ${reqs}`);
    const items = r.events.find((e) => e.kind === 'request' && e.request!.url.endsWith('/api/items'))!;
    assert.ok([...(items.stack ?? []), ...(items.asyncStack ?? [])].some((s) => s.startsWith('loadItems ')), 'initiator stack names loadItems');
    assert.ok((r.summary.timers.setTimeout ?? 0) >= 1);
    // reconcile against the file the server sent
    const rec = reconcileJavaScriptRuntime(r, [{ name: 'app.js', code: readFileSync(app, 'utf8') }]);
    assert.equal(rec.scripts[0]!.matchedBy, 'sha256');
  } finally { server.close(); }
});

test('hostile input: selectors, gating and random code', { timeout: 60_000 }, async () => {
  await assert.rejects(tool('web_trace_semantics').run({ functions: ['x'], script: join(R, 'trace-target.mjs') }), /allowExecution/);
  await assert.rejects(tool('web_trace_semantics').run({ functions: [], allowExecution: true, script: join(R, 'trace-target.mjs') }), /at least one function/);
  await assert.rejects(tool('web_trace_semantics').run({ functions: ['x'], url: 'file:///etc/passwd' }), /only http/);
  await assert.rejects(tool('web_reconcile_runtime').run({ runtimeText: '{', bundles: [{ name: 'a', code: '' }] }), /not JSON/);
  await assert.rejects(tool('web_reconcile_runtime').run({ runtime: {} }), /at least one/);
  fc.assert(fc.property(fc.string({ maxLength: 2000 }), (s) => { const t0 = Date.now(); findFunctions(s); return Date.now() - t0 < 2000; }), { numRuns: 200 });
  fc.assert(fc.property(fc.anything(), (rt) => { const t0 = Date.now(); reconcileJavaScriptRuntime(rt, [{ name: 'a.js', code: 'function a(){}' }]); return Date.now() - t0 < 2000; }), { numRuns: 300 });
  // deep nesting and many functions stay bounded
  const many = Array.from({ length: 30_000 }, (_, i) => `function f${i}(){}`).join('\n');
  assert.equal(findFunctions(many).length, 20_000);
});
