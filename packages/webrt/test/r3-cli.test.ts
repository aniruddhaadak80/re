// Every round 3 tool has a CLI command; each command is run in a child process on real fixtures and
// its --json output must equal the tool called directly, and its text output must carry the key facts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TOOLS, CLI_COMMANDS, CLI_COMMANDS_R3 } from '../src/node.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const runner = join(dirname(fileURLToPath(import.meta.url)), 'cli-runner.ts');
const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', runner, ...args], { encoding: 'utf8', timeout: 90_000 });
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const R1_TOOLS = ['web_js_beautify', 'web_js_deobfuscate', 'web_bundle_modules', 'web_js_endpoints', 'web_sourcemap_recover', 'web_asar_list', 'web_asar_extract', 'web_electron_audit', 'web_browser_capture', 'web_pcap_summary', 'web_pcap_flows', 'web_sqlite_tables', 'web_sqlite_query', 'web_har_summary', 'web_webmcp_scan', 'web_wellknown_classify', 'web_capture_compare', 'web_browser_scenario', 'web_trace_inspect', 'web_cdp_targets', 'web_webmcp_discover', 'web_node_inspect'];

test('every round 3 tool has a CLI command', () => {
  const covered = new Set(CLI_COMMANDS.map((c) => c.summary));
  const r3 = TOOLS.filter((t) => !R1_TOOLS.includes(t.name));
  for (const t of r3) assert.ok([...covered].some((s) => s.startsWith(t.description.split('. ')[0]!)), `no command for ${t.name}`);
  for (const c of CLI_COMMANDS_R3) assert.match(c.usage, new RegExp(`^revlens ${c.name}\\b`));
  for (const a of ['environment-build', 'environment-serve', 'environment-export', 'environment-compare', 'trace-web-module-imports', 'compare-source-to-bundle', 'compare-javascript-export-shapes', 'reconcile-javascript-runtime', 'trace-javascript-semantics']) assert.ok(CLI_COMMANDS.some((c) => c.name === a), a);
});

test('module-imports, source-compare, export-shapes and export-shapes-compare: JSON equals the tool, text has the facts', { timeout: 120_000 }, async () => {
  const a = run('module-imports', join(S, 'graph-app'), '--json');
  assert.equal(a.status, 0, a.stderr);
  const direct = await tool('web_trace_module_imports').run({ path: join(S, 'graph-app') }) as any;
  assert.deepEqual(JSON.parse(a.stdout).stats, direct.stats);
  const at = run('trace-web-module-imports', join(S, 'graph-app'));
  assert.equal(at.status, 0, at.stderr);
  assert.match(at.stdout, /entry src\/index\.js \(package-main\)/);
  assert.match(at.stdout, /cycle src\/a\.js -> /);
  const b = run('source-compare', join(S, 'graph-dist/bundle.cjs.js'), join(S, 'graph-app'));
  assert.equal(b.status, 0, b.stderr);
  assert.match(b.stdout, /8 bundle sources: same=8/);
  const c = run('export-shapes', join(S, 'shapes/semver-7.7.1'));
  assert.equal(c.status, 0, c.stderr);
  assert.match(c.stdout, /^ {2}satisfies: function\/3/m);
  const d = run('export-shapes-compare', join(S, 'shapes/semver-6.3.1'), join(S, 'shapes/semver-7.7.1'), '--json');
  const dd = await tool('web_compare_export_shapes').run({ a: { path: join(S, 'shapes/semver-6.3.1') }, b: { path: join(S, 'shapes/semver-7.7.1') } }) as any;
  assert.deepEqual(JSON.parse(d.stdout).added, dd.added);
  assert.equal(JSON.parse(d.stdout).score, dd.score);
});

test('source-location maps --pos and --original through the esbuild source map', async () => {
  const map = join(S, 'graph-dist/bundle.cjs.js.map');
  const direct = await tool('web_trace_source_location').run({ sourceMapPath: map, original: { source: '../graph-app/src/a.js', line: 1 } }) as any;
  assert.ok(direct.generated.length > 0);
  const g = direct.generated[0];
  const r = run('source-location', map, '--pos', `${g.line}:${g.column}`, '--original', '../graph-app/src/a.js:1', '--json');
  assert.equal(r.status, 0, r.stderr);
  const o = JSON.parse(r.stdout);
  assert.equal(o.locations[0].original.source.endsWith('graph-app/src/a.js'), true);
  assert.equal(o.locations[0].original.line, 1);
  assert.deepEqual(o.generated, direct.generated);
  const bad = run('source-location', map, '--pos', 'x');
  assert.equal(bad.status, 2);
});

test('env-build, env-export, env-compare, endpoint-join and reconcile-runtime run end to end', { timeout: 120_000 }, async () => {
  const work = mkdtempSync(join(tmpdir(), 'revlens-r3cli-'));
  try {
    const har = join(S, 'har-fulfill.har');
    const b = run('environment-build', har, '--out', join(work, 'env'));
    assert.equal(b.status, 0, b.stderr);
    assert.match(b.stdout, /environment .* routes/);
    const e = run('env-export', join(work, 'env'), join(work, 'env.zip'));
    assert.equal(e.status, 0, e.stderr);
    assert.ok(existsSync(join(work, 'env.zip')));
    const c = run('env-compare', join(work, 'env.zip'), '--probe', har, '--json');
    assert.equal(c.status, 0, c.stderr);
    const direct = await tool('web_env_compare').run({ path: join(work, 'env.zip'), probes: [har] }) as any;
    assert.deepEqual(JSON.parse(c.stdout).summary, direct.summary);
    const missing = run('env-compare', join(work, 'env'));
    assert.equal(missing.status, 2);
    const j = run('endpoint-join', har);
    assert.equal(j.status, 0, j.stderr);
    assert.match(j.stdout, /^static \d+, observed \d+/);
    // a Node inspector report style runtime: one call at an offset inside the semver bundle
    const bundle = join(S, 'shapes/semver-7.7.1.bundle.cjs');
    const off = (await import('node:fs')).readFileSync(bundle, 'utf8').indexOf('var satisfies2 = ');
    writeFileSync(join(work, 'rt.json'), JSON.stringify({ calls: [{ url: 'file:///x/semver-7.7.1.bundle.cjs', offset: off, name: 'satisfies2', count: 3 }] }));
    const r = run('reconcile-runtime', join(work, 'rt.json'), bundle);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /hot {2}samples\/webrt\/shapes\/semver-7\.7\.1\/functions\/satisfies\.js {2}enter 0 covered 3/);
  } finally { rmSync(work, { recursive: true, force: true }); }
});

test('trace-semantics runs a Node script and refuses without --allow-execution', { timeout: 60_000 }, () => {
  const r = run('trace-semantics', '--script', join(S, 'runtime/trace-target.mjs'), '--fn', 'add,Calc.mul', '--allow-execution', '--duration', '6000');
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /-> add\(a=1, b=2\)/);
  assert.match(r.stdout, /<- Calc\.mul = 24/);
  assert.match(r.stdout, /exit code 0/);
  const no = run('trace-semantics', '--script', join(S, 'runtime/trace-target.mjs'), '--fn', 'add');
  assert.equal(no.status, 2);
  assert.match(no.stderr, /allowExecution/);
});
