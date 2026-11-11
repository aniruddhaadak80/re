// Starts the real MCP server over stdio with the SDK client and calls tools from every area on real fixtures.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const S = (p: string) => join(root, 'samples', p);
let client: Client;

before(async () => {
  client = new Client({ name: 'revlens-test', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: ['--import', 'tsx', join(root, 'packages/mcp/src/index.ts')], cwd: root, stderr: 'inherit' });
  await client.connect(transport);
});
after(async () => { await client?.close(); });

async function call(name: string, args: Record<string, unknown>): Promise<string> {
  const r = await client.callTool({ name, arguments: args }) as { isError?: boolean; content: { type: string; text: string }[] };
  const t = r.content.map((c) => c.text).join('\n');
  assert.ok(!r.isError, `${name} failed: ${t}`);
  return t;
}

test('lists the 13 core tools plus every package tool, with annotations', async () => {
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  assert.equal(new Set(names).size, names.length, 'tool names are unique');
  for (const n of ['analyze_file', 'list_findings', 'get_strings', 'get_sections', 'get_imports', 'sbom', 'check_vulns', 'scan_rules', 'diff_files', 'verify_claim', 'hexdump', 'report_markdown', 'list_analyzers']) assert.ok(names.includes(n), n);
  assert.ok(names.filter((n) => n.startsWith('managed_')).length >= 11);
  assert.ok(names.filter((n) => n.startsWith('web_')).length >= 14);
  assert.ok(names.filter((n) => n.startsWith('mobile_')).length >= 12);
  assert.ok(names.filter((n) => n.startsWith('disasm_')).length >= 10);
  assert.ok(tools.length >= 60, `got ${tools.length}`);
  const ex = tools.find((t) => t.name === 'web_asar_extract');
  assert.equal(ex?.annotations?.destructiveHint, true);
  assert.equal(tools.find((t) => t.name === 'disasm_pseudocode')?.annotations?.readOnlyHint, true);
});

test('prompts and resources are listed', async () => {
  const { prompts } = await client.listPrompts();
  assert.ok(prompts.some((p) => p.name === 'triage_file'));
  const { resources } = await client.listResources();
  assert.ok(resources.some((r) => r.uri === 'revlens://analyzers'));
  const p = await client.getPrompt({ name: 'triage_file', arguments: { path: 'x.bin' } });
  assert.match(JSON.stringify(p.messages), /verify_claim/);
});

test('analyze_file returns one combined report (core plus disasm)', async () => {
  const o = JSON.parse(await call('analyze_file', { path: S('disasm/hello-x64.elf') }));
  assert.equal(o.file.format, 'elf');
  assert.ok(o.deep.some((d: string) => d.startsWith('disasm: x86_64')), JSON.stringify(o.deep));
  assert.match(o.next, /disasm_pseudocode/);
});

test('disasm tool: pseudocode for main', async () => {
  const t = await call('disasm_pseudocode', { path: S('disasm/hello-x64.elf'), function: 'main' });
  assert.match(t, /main/);
});

test('managed tool: .NET info', async () => {
  const o = JSON.parse(await call('managed_dotnet_info', { path: S('managed/dotnet/System.IO.Compression.Brotli.dll') }));
  assert.equal(o.assembly?.name ?? o.assemblyName ?? o.name, 'System.IO.Compression.Brotli');
});

test('mobile tool: APK manifest', async () => {
  const t = await call('mobile_manifest', { path: S('mobile/apk/org.rayg.streaktracker_12.apk') });
  assert.match(t, /org\.rayg\.streaktracker/);
});

test('web tool: pcap summary', async () => {
  const o = JSON.parse(await call('web_pcap_summary', { path: S('webrt/dns_udp.pcap') }));
  assert.ok(o.packetCount > 0);
});

test('verify_claim checks a .NET file is a kind of PE', async () => {
  const o = JSON.parse(await call('verify_claim', { path: S('managed/dotnet/System.IO.Compression.Brotli.dll'), claims: [{ kind: 'format-is', format: 'pe' }] }));
  assert.equal(o[0].verdict, 'VERIFIED');
});

test('large answers are capped', async () => {
  const t = await call('report_markdown', { path: S('mobile/java/commons-cli-1.6.0.jar') });
  assert.ok(t.length <= 61_000);
});
