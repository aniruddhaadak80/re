import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TOOLS as WEB_TOOLS, ANALYZERS } from '../src/index.js';
import { TOOLS, CLI_COMMANDS } from '../src/node.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;

const EXPECTED = ['web_js_beautify', 'web_js_deobfuscate', 'web_bundle_modules', 'web_js_endpoints', 'web_sourcemap_recover', 'web_asar_list', 'web_asar_extract', 'web_electron_audit', 'web_browser_capture', 'web_pcap_summary', 'web_pcap_flows', 'web_sqlite_tables', 'web_sqlite_query', 'web_har_summary', 'web_webmcp_scan', 'web_wellknown_classify', 'web_capture_compare', 'web_browser_scenario', 'web_trace_inspect', 'web_cdp_targets', 'web_webmcp_discover', 'web_node_inspect'];
const NODE_ONLY = ['web_browser_capture', 'web_browser_scenario', 'web_trace_inspect', 'web_cdp_targets', 'web_webmcp_discover', 'web_node_inspect'];

test('TOOLS: names, schemas and platform split', () => {
  assert.deepEqual(TOOLS.map((t) => t.name).sort(), [...EXPECTED].sort());
  assert.deepEqual(WEB_TOOLS.map((t) => t.name).sort(), EXPECTED.filter((n) => !NODE_ONLY.includes(n)).sort());
  for (const t of TOOLS) {
    assert.match(t.name, /^web_[a-z0-9_]+$/);
    assert.ok(t.description.length > 40);
    for (const [k, v] of Object.entries(t.inputSchema)) assert.ok(['string', 'number', 'boolean', 'array', 'object'].includes(v.type) && v.description, `${t.name}.${k}`);
  }
});

test('tools run on real files through paths (Node) and base64 (browser entry)', async () => {
  const pcap = await tool('web_pcap_summary').run({ path: join(S, 'chrome-34-google.pcap') }) as any;
  assert.deepEqual(pcap.sniNames, ['google.de']);
  const b64 = readFileSync(join(S, 'dns_udp.pcap')).toString('base64');
  const web = await WEB_TOOLS.find((t) => t.name === 'web_pcap_summary')!.run({ base64: b64 }) as any;
  assert.deepEqual(web.dnsNames, ['www.tcpdump.org']);
  await assert.rejects(WEB_TOOLS.find((t) => t.name === 'web_pcap_summary')!.run({ path: '/etc/passwd' }), /only supported in Node/);
  const flows = await tool('web_pcap_flows').run({ path: join(S, 'pcapng-multi-interface.pcapng'), proto: 'udp', limit: 2 }) as any;
  assert.equal(flows.flows.total, 3); assert.equal(flows.flows.items.length, 2);
  const q = await tool('web_sqlite_query').run({ path: join(S, 'fixture.sqlite'), sql: 'SELECT id, avatar FROM users WHERE id = 10' }) as any;
  assert.deepEqual(q.rows, [[10, { blob: '0aab', size: 2 }]]);
  const tables = await tool('web_sqlite_tables').run({ path: join(S, 'fixture.sqlite'), samples: 1 }) as any;
  assert.equal(tables.tables.length, 4);
  const deob = await tool('web_js_deobfuscate').run({ path: join(S, 'obfuscated.js'), maxChars: 50 }) as any;
  assert.equal(deob.code.length, 50); assert.ok(deob.truncated); assert.ok(deob.decodedStrings.includes('RL-LICENSE-SALT-2026'));
  const bundle = await tool('web_bundle_modules').run({ path: join(S, 'webpack-dist/bundle.prod.js') }) as any;
  assert.deepEqual(bundle.modules.items.map((m: any) => m.path).sort(), ['api.js', 'util/format.js'], 'sibling .map is picked up from sourceMappingURL');
  const asar = await tool('web_asar_extract').run({ path: join(S, 'electron/app.asar'), file: 'package.json' }) as any;
  assert.equal(JSON.parse(asar.text).name, 'revlens-fixture-electron');
  const out = mkdtempSync(join(tmpdir(), 'webrt-sm-'));
  try {
    const sm = await tool('web_sourcemap_recover').run({ path: join(S, 'webpack-dist/bundle.prod.js.map'), outDir: out }) as any;
    assert.equal(sm.written.written, 11);
    assert.equal(readFileSync(join(out, 'util/format.js'), 'utf8'), readFileSync(join(S, 'webpack-src/util/format.js'), 'utf8'));
    assert.ok(readdirSync(out).includes('webpack'));
  } finally { rmSync(out, { recursive: true, force: true }); }
});

test('CLI commands print human text and JSON', () => {
  assert.equal(CLI_COMMANDS.length, 20);
  const runner = join(dirname(fileURLToPath(import.meta.url)), 'cli-runner.ts');
  const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', runner, ...args], { encoding: 'utf8', timeout: 60_000 });
  const a = run('pcap-summary', join(S, 'dns_udp.pcap'));
  assert.equal(a.status, 0, a.stderr);
  assert.ok(a.stdout.includes('A? www.tcpdump.org'));
  const b = run('asar-list', join(S, 'electron/app.asar'), '--json');
  assert.equal(b.status, 0, b.stderr);
  assert.equal(JSON.parse(b.stdout).files, 4);
  const c = run('sqlite-query', join(S, 'fixture.sqlite'), 'DROP TABLE users');
  assert.equal(c.status, 2);
  assert.match(c.stderr, /only plain SELECT/);
});

test('analyzers fill report.meta.webrt and findings for owned formats', async () => {
  const mk = (bytes: Uint8Array, format: string, name: string, text?: string) => ({ bytes, name, format, text, depth: 0, options: { maxStrings: 100, recurse: false, maxDepth: 1 }, report: { findings: [], meta: {} } as any });
  const run = async (file: string, format: string, asText = false) => {
    const bytes = new Uint8Array(readFileSync(join(S, file)));
    const ctx = mk(bytes, format, file, asText ? readFileSync(join(S, file), 'utf8') : undefined);
    for (const a of ANALYZERS) if (a.applies(ctx as any)) await a.run(ctx as any);
    return ctx.report;
  };
  const js = await run('obfuscated.js', 'js', true);
  assert.ok(js.findings.some((f: any) => f.id === 'webrt.js.obfuscated' && f.attack.includes('T1027')));
  assert.equal(js.meta.webrt.js.deobfuscation.stringArray.encoding, 'rc4');
  const el = await run('electron/app.asar', 'asar');
  assert.ok(el.findings.some((f: any) => f.id === 'webrt.electron.node-integration'));
  const pc = await run('chrome-34-google.pcap', 'unknown');
  assert.equal(pc.meta.webrt.pcap.tls[0].ja3Hash, 'a607f3a5c94c2ee592af1456f36c8367');
  const db = await run('fixture.sqlite', 'unknown');
  assert.equal(db.meta.webrt.sqlite.tables.length, 4);
  const har = await run('har-fulfill.har', 'json', true);
  assert.equal(har.meta.webrt.har.entries, 5);
  const sm = await run('webpack-dist/bundle.prod.js.map', 'sourcemap', true);
  assert.equal(sm.meta.webrt.sourcemap.coverage, 100);
  JSON.stringify([js.meta, el.meta, pc.meta, db.meta, har.meta, sm.meta]); // JSON-serializable
});

test('the main entry bundles for the browser without Node built-ins', async (t) => {
  let esbuild: any;
  try { esbuild = await import('esbuild' as string); } catch { t.skip('esbuild not installed'); return; }
  const r = await esbuild.build({ entryPoints: [join(dirname(fileURLToPath(import.meta.url)), '../src/index.ts')], bundle: true, platform: 'browser', format: 'esm', write: false, logLevel: 'silent' });
  const out = new TextDecoder().decode(r.outputFiles[0].contents);
  assert.ok(out.length > 10_000);
  assert.ok(!/from\s*["']node:/.test(out) && !/require\(["']node:/.test(out));
});
