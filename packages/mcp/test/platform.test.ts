// Platform tools: guidance corpus, progressive catalog, tool profiles, call_tool and per-session settings.
// Servers run in process over the SDK in-memory transport, with the SDK client on the other end.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import fc from 'fast-check';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer, engineLoaded, staticToolNames, type ServerOptions } from '../src/app.ts';
import { tokenize, buildIndex, searchIndex, splitMarkdown, stem } from '../src/guidance/bm25.ts';
import { WORKFLOWS } from '../src/guidance/workflows.ts';
import { MINIMAL_TOOLS, profileFromArgv } from '../src/catalog.ts';
import { TOOL_MANIFEST } from '../src/generated/tool-manifest.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const S = (p: string) => join(root, 'samples', p);

async function connect(opts: ServerOptions = {}) {
  const made = createServer(opts);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'platform-test', version: '1.0.0' });
  await made.server.connect(a);
  await client.connect(b);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args }) as { isError?: boolean; content: { text: string }[] };
    const t = r.content.map((c) => c.text).join('\n');
    let json: any;
    try { json = JSON.parse(t); } catch { json = undefined; }
    return { error: !!r.isError, text: t, json };
  };
  return { ...made, client, call, close: () => client.close() };
}

test('startup lists every tool without loading the analysis packages', async () => {
  const s = await connect();
  const { tools } = await s.client.listTools();
  assert.equal(engineLoaded(), false, 'engine must stay unloaded until a tool needs it');
  const names = tools.map((t) => t.name);
  assert.equal(new Set(names).size, names.length);
  for (const n of ['guidance', 'search_guidance', 'read_guidance_section', 'guided_workflows', 'discover_tools', 'capabilities', 'providers', 'inspect_input_contract', 'call_tool', 'inspect_analysis_settings', 'update_analysis_settings']) assert.ok(names.includes(n), n);
  assert.equal(tools.length, staticToolNames().length);
  assert.match(s.client.getInstructions() ?? '', /discover_tools/);
  await s.close();
});

test('the tool manifest matches the packages (rebuild it with scripts/build-tool-manifest.mjs)', async () => {
  const eng = await import('@revlens/engine/node');
  assert.deepEqual(TOOL_MANIFEST.tools.map((t) => t.name).sort(), eng.PACKAGE_TOOLS.map((t) => t.name).sort());
  for (const t of eng.PACKAGE_TOOLS) assert.deepEqual(TOOL_MANIFEST.tools.find((x) => x.name === t.name)?.inputSchema, t.inputSchema, t.name);
  assert.deepEqual(TOOL_MANIFEST.effects, eng.TOOL_EFFECTS);
});

test('the guidance bundle is in sync with docs/', () => {
  execFileSync(process.execPath, ['--import', 'tsx', join(root, 'scripts/build-guidance.mjs'), '--check'], { cwd: root, stdio: 'pipe' });
});

test('guidance: overview, playbooks for all 11 formats, and topics', async () => {
  const s = await connect();
  const o = (await s.call('guidance')).json;
  const files = o.playbooks.map((p: { file: string }) => p.file).sort();
  assert.deepEqual(files, readdirSync(join(root, 'docs/playbooks')).filter((f) => f !== 'README.md').map((f) => `playbooks/${f}`).sort());
  assert.equal(files.length, 11);
  for (const [fmt, file] of [['elf', 'elf'], ['pe', 'pe'], ['macho-fat', 'macho'], ['apk', 'apk'], ['ipa', 'ipa'], ['dotnet', 'dotnet'], ['pyc', 'python'], ['js', 'js-bundle'], ['electron', 'electron'], ['firmware', 'firmware'], ['pcapng', 'pcap']]) {
    const g = (await s.call('guidance', { format: fmt! })).json;
    assert.equal(g.playbook, `playbooks/${file}.md`, fmt);
    const first = readFileSync(join(root, 'docs', g.playbook), 'utf8').split('\n')[0]!.replace(/^# /, '');
    assert.ok(g.text.startsWith(`# ${first}`), fmt);
  }
  assert.equal((await s.call('guidance', { format: 'zzz' })).json.found, false);
  const t = (await s.call('guidance', { topic: 'security-model' })).json;
  assert.equal(t.page, 'security-model.md');
  await s.close();
});

test('search_guidance ranks the right playbook section first and read_guidance_section pages it', async () => {
  const s = await connect();
  const r = (await s.call('search_guidance', { query: 'exported activities without permission' })).json;
  assert.equal(r.results[0].id, 'playbooks/apk.md#first-pass');
  const tls = (await s.call('search_guidance', { query: 'TLS callbacks', kind: 'playbook' })).json;
  assert.equal(tls.results[0].file, 'playbooks/pe.md');
  const sec = (await s.call('read_guidance_section', { id: 'playbooks/elf.md#elf-playbook', includeChildren: true, maxChars: 400 })).json;
  assert.equal(sec.ok, true);
  assert.deepEqual(sec.children, ['playbooks/elf.md#recognise', 'playbooks/elf.md#first-pass', 'playbooks/elf.md#code', 'playbooks/elf.md#bridges-that-help', 'playbooks/elf.md#verify']);
  assert.equal(sec.text.length, 400);
  assert.ok(sec.nextOffset === 400);
  const next = (await s.call('read_guidance_section', { id: 'playbooks/elf.md#elf-playbook', includeChildren: true, offset: 400, maxChars: 60000 })).json;
  assert.equal(next.nextOffset, null);
  const flat = (x: string) => x.replace(/\s+/g, ' ').trim();
  assert.equal(flat(sec.text + next.text), flat(readFileSync(join(root, 'docs/playbooks/elf.md'), 'utf8')));
  const stale = (await s.call('read_guidance_section', { id: 'playbooks/elf.md#code', hash: '00000000' })).json;
  assert.equal(stale.stale, true);
  const missing = (await s.call('read_guidance_section', { id: 'playbooks/elf.md#nope' })).json;
  assert.equal(missing.found, false);
  assert.ok(missing.sectionsInFile.includes('playbooks/elf.md#code'));
  await s.close();
});

test('BM25 scores match the textbook formula on a hand built corpus', () => {
  const secs = splitMarkdown('t.md', '# T\n\n## a\n\ncat cat dog\n\n## b\n\ndog bird\n\n## c\n\nfish\n');
  assert.deepEqual(secs.map((x) => x.title), ['T', 'a', 'b', 'c']);
  const body = secs.slice(1);
  const idx = buildIndex(body);
  // each doc's tokens: body + path (T, title) + title twice
  const docs = [['cat', 'cat', 'dog', 't', 'a', 'a', 'a'], ['dog', 'bird', 't', 'b', 'b', 'b'], ['fish', 't', 'c', 'c', 'c']].map((d) => d.filter((w) => w.length >= 2 || /\d/.test(w)));
  assert.deepEqual(idx.lengths, docs.map((d) => d.length));
  const avg = docs.reduce((a, d) => a + d.length, 0) / 3;
  const k1 = 1.2, b = 0.75;
  const score = (q: string, d: string[]) => {
    const df = docs.filter((x) => x.includes(q)).length;
    const tf = d.filter((x) => x === q).length;
    if (!tf) return 0;
    return Math.log(1 + (3 - df + 0.5) / (df + 0.5)) * tf * (k1 + 1) / (tf + k1 * (1 - b + b * d.length / avg));
  };
  const r = searchIndex(idx, 'dog');
  assert.deepEqual(r.hits.map((h) => h.index), [0, 1].sort((x, y) => score('dog', docs[y]!) - score('dog', docs[x]!)));
  for (const h of r.hits) assert.ok(Math.abs(h.score - score('dog', docs[h.index]!)) < 0.002);
  assert.deepEqual(searchIndex(idx, 'cat dog', { require: 'all' }).hits.map((h) => h.index), [0]);
  assert.deepEqual(searchIndex(idx, 'unicorn').unknown, ['unicorn']);
  assert.equal(stem('permissions'), 'permission');
  assert.deepEqual(tokenize('disasm_pseudocode The DLLs'), ['disasm_pseudocode', 'disasm', 'pseudocode', 'dll']);
});

test('guided workflows: every step names a real tool and real input fields', async () => {
  const s = await connect();
  const list = (await s.call('guided_workflows', { action: 'list' })).json;
  assert.equal(list.workflows.length, WORKFLOWS.length);
  const known = new Set(staticToolNames());
  for (const w of WORKFLOWS) for (const st of w.steps) {
    if (st.tool.startsWith('bridge_cutter') || st.tool.endsWith('cutter_sessions') || st.tool === 'cutter_command') continue; // added by the bridges package
    assert.ok(known.has(st.tool), `${w.id}: ${st.tool}`);
    const c = (await s.call('inspect_input_contract', { name: st.tool })).json;
    for (const k of Object.keys(st.input ?? {})) assert.ok(k in c.inputSchema.properties, `${w.id}: ${st.tool}.${k}`);
  }
  const r = (await s.call('guided_workflows', { action: 'render', workflow: 'native_function_deep_dive', arguments: { path: '/x/a.out', function: 'main' } })).json;
  assert.deepEqual(r.missing, []);
  assert.deepEqual(r.steps[1].input, { path: '/x/a.out', function: 'main' });
  const miss = (await s.call('guided_workflows', { action: 'render', workflow: 'native_function_deep_dive', arguments: { path: '/x' } })).json;
  assert.deepEqual(miss.missing, ['function']);
  assert.equal((await s.call('guided_workflows', { action: 'render', workflow: 'nope' })).json.ok, false);
  await s.close();
});

test('discover_tools ranks by format, goal and keyword and returns input contracts', async () => {
  const s = await connect();
  const apk = (await s.call('discover_tools', { format: 'apk', limit: 6 })).json;
  assert.equal(apk.tools.length, 6);
  assert.ok(apk.tools.every((t: { name: string }) => /^(mobile_|bridge_(jadx|apktool|adb))/.test(t.name)), JSON.stringify(apk.tools.map((t: { name: string }) => t.name)));
  const goal = (await s.call('discover_tools', { goal: 'decompile a native function to pseudo code', limit: 8 })).json;
  const names = goal.tools.map((t: { name: string }) => t.name);
  assert.ok(names.includes('disasm_pseudocode'), names.join(','));
  const kw = (await s.call('discover_tools', { keyword: 'hexdump' })).json;
  assert.equal(kw.tools[0].name, 'hexdump');
  assert.deepEqual(kw.tools[0].contract.required, ['path: string', 'offset: integer']);
  const pcap = (await s.call('discover_tools', { format: 'pcap', limit: 2 })).json;
  assert.deepEqual(pcap.tools.map((t: { name: string }) => t.name).sort(), ['web_pcap_flows', 'web_pcap_summary']);
  await s.close();
});

test('inspect_input_contract gives a JSON schema and an example the tool accepts', async () => {
  const s = await connect();
  for (const name of ['disasm_pseudocode', 'verify_claim', 'mobile_manifest', 'update_analysis_settings']) {
    const c = (await s.call('inspect_input_contract', { name })).json;
    assert.equal(c.found, true);
    assert.equal(c.inputSchema.type, 'object');
    const r = await s.call('call_tool', { name, arguments: c.example });
    assert.doesNotMatch(r.text, /arguments do not match/, `${name}: ${r.text.slice(0, 200)}`);
  }
  const miss = (await s.call('inspect_input_contract', { name: 'disasm_pseudo' })).json;
  assert.equal(miss.found, false);
  assert.ok(miss.suggestions.includes('disasm_pseudocode'));
  await s.close();
});

test('minimal profile lists 12 tools, call_tool reaches hidden ones, discover_tools load lists them', async () => {
  const s = await connect({ profile: 'minimal' });
  let changed = 0;
  s.client.setNotificationHandler(ToolListChangedNotificationSchema, () => { changed++; });
  const { tools } = await s.client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), [...MINIMAL_TOOLS].sort());
  const hidden = await s.call('mobile_manifest', { path: S('mobile/apk/org.rayg.streaktracker_12.apk') });
  assert.equal(hidden.error, true);
  const via = await s.call('call_tool', { name: 'mobile_manifest', arguments: { path: S('mobile/apk/org.rayg.streaktracker_12.apk') } });
  assert.equal(via.error, false, via.text);
  assert.match(via.text, /org\.rayg\.streaktracker/);
  const bad = await s.call('call_tool', { name: 'hexdump', arguments: { path: 1 } });
  assert.equal(bad.error, true);
  assert.match(bad.text, /arguments do not match hexdump/);
  const d = (await s.call('discover_tools', { format: 'pcap', limit: 2, load: true })).json;
  assert.deepEqual(d.loaded.sort(), ['web_pcap_flows', 'web_pcap_summary']);
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(changed >= 1, 'client is told the list changed');
  const after = (await s.client.listTools()).tools.map((t) => t.name);
  assert.ok(after.includes('web_pcap_summary'));
  assert.match(s.client.getInstructions() ?? '', /minimal/);
  await s.close();
  const std = await connect({ profile: 'standard' });
  const n = (await std.client.listTools()).tools.length;
  assert.ok(n > 12 && n < 80, String(n));
  await std.close();
  assert.equal(profileFromArgv(['--tool-profile', 'minimal']), 'minimal');
  assert.equal(profileFromArgv(['--tool-profile=standard']), 'standard');
  assert.equal(profileFromArgv([], {}), 'full');
  assert.throws(() => profileFromArgv(['--tool-profile', 'huge']));
});

test('settings: inspect, atomic update, revision guard, output cap, persistence', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'rl-settings-'));
  const file = join(dir, 'settings.json');
  const s = await connect({ file, env: {} });
  const i = (await s.call('inspect_analysis_settings')).json;
  const get = (o: any, k: string) => o.settings.find((x: { setting: string }) => x.setting === k);
  assert.equal(get(i, 'allowExecution').value, false);
  assert.equal(get(i, 'maxOutputChars').value, 60000);
  assert.equal(i.revision, 0);
  const bad = (await s.call('update_analysis_settings', { changes: [{ setting: 'maxStrings', value: 50 }, { setting: 'maxOutputChars', value: 5 }] })).json;
  assert.equal(bad.ok, false);
  assert.equal(get((await s.call('inspect_analysis_settings')).json, 'maxStrings').value, 400, 'nothing applied when one change is bad');
  const ok = (await s.call('update_analysis_settings', { changes: [{ setting: 'maxOutputChars', value: 4000 }, { setting: 'maxStrings', value: 50 }], expectedRevision: 0, persist: true })).json;
  assert.equal(ok.changed, true);
  assert.equal(ok.revision, 1);
  assert.equal(ok.persisted, file);
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).maxOutputChars, 4000);
  const race = (await s.call('update_analysis_settings', { changes: [{ setting: 'maxStrings', value: 60 }], expectedRevision: 0 })).json;
  assert.match(race.error, /revision is 1/);
  const big = await s.call('list_analyzers');
  assert.match(big.text, /output cut at 4000 of/, big.text.slice(-300));
  assert.ok(big.text.length < 4400, String(big.text.length));
  const strings = (await s.call('analyze_file', { path: S('disasm/hello-x64.elf') }));
  assert.equal(strings.error, false);
  await s.close();
  const s2 = await connect({ file, env: {} });
  const j = (await s2.call('inspect_analysis_settings', { settings: ['maxOutputChars'] })).json;
  assert.equal(j.settings[0].value, 4000);
  assert.equal(j.settings[0].source, 'file');
  await s2.call('update_analysis_settings', { changes: [{ setting: 'maxOutputChars', value: 9000 }] });
  const reset = (await s2.call('update_analysis_settings', { changes: [{ setting: 'maxOutputChars', action: 'reset' }] })).json;
  assert.equal(reset.values.maxOutputChars, 4000, 'reset goes back to the launch value');
  await s2.close();
  writeFileSync(file, '{"maxFileMB": "lots"}');
  const s3 = await connect({ file, env: { REVLENS_ALLOW_EXECUTION: '1' } });
  const k = (await s3.call('inspect_analysis_settings')).json;
  assert.match(k.launchProblems.join(' '), /maxFileMB/);
  assert.equal(get(k, 'allowExecution').value, true);
  await s3.close();
});

test('settings gates: denyExecution, allowNetwork and maxFileMB', async () => {
  const s = await connect({ env: {} });
  await s.call('update_analysis_settings', { changes: [{ setting: 'denyExecution', value: true }, { setting: 'allowNetwork', value: false }, { setting: 'maxFileMB', value: 1 }] });
  const r2 = await s.call('bridge_r2_session_open', { path: S('disasm/hello-x64.elf') });
  assert.equal(r2.error, true);
  assert.match(r2.text, /denyExecution/);
  const net = await s.call('check_vulns', { path: S('disasm/hello-x64.elf') });
  assert.match(net.text, /allowNetwork/);
  const large = await s.call('get_sections', { path: S('extras/go-hello-stripped.elf') });
  assert.equal(large.error, true);
  assert.match(large.text, /maxFileMB/);
  await s.close();
});

test('capabilities and providers', async () => {
  const s = await connect();
  const c = (await s.call('capabilities')).json;
  assert.equal(c.totalTools, staticToolNames().length);
  assert.ok(c.playbookFormats.includes('apk'));
  const p = (await s.call('providers', { includeBridges: false })).json;
  assert.deepEqual(p.internal.map((x: { id: string }) => x.id).sort(), TOOL_MANIFEST.packages.map((x) => x.id).sort());
  await s.close();
});

test('hostile input: random queries and ids never throw and stay fast', async () => {
  const s = await connect();
  await fc.assert(fc.asyncProperty(fc.string({ maxLength: 3000 }), fc.string({ maxLength: 300 }), async (q, id) => {
    const t0 = Date.now();
    const a = await s.call('search_guidance', { query: q.length ? q : 'x' });
    const b = await s.call('read_guidance_section', { id: id || 'x' });
    const c = await s.call('discover_tools', { goal: q, keyword: id.slice(0, 200) });
    for (const r of [a, b, c]) assert.doesNotMatch(r.text, /TypeError|RangeError|Cannot read/);
    assert.ok(Date.now() - t0 < 2000);
  }), { numRuns: 60 });
  fc.assert(fc.property(fc.string({ maxLength: 20000 }), (t) => { const toks = tokenize(t); assert.ok(toks.every((x) => x.length <= 40)); }), { numRuns: 200 });
  const huge = 'a_'.repeat(200_000);
  const t0 = Date.now();
  tokenize(huge);
  assert.ok(Date.now() - t0 < 3000);
  await s.close();
});
