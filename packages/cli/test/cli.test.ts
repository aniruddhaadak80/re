// Runs the revlens CLI as a process on real fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const S = (p: string) => join(root, 'samples', p);
const runIn = (cwd: string, ...args: string[]) => execFileSync(process.execPath, ['--import', import.meta.resolve('tsx'), join(root, 'packages/cli/src/index.ts'), ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' }, maxBuffer: 64 * 1024 * 1024, timeout: 90_000 });
const run = (...args: string[]) => runIn(root, ...args);

test('help shows core commands and every area', () => {
  const h = run('--help');
  for (const s of ['revlens analyze', 'revlens tools', 'revlens setup', 'revlens mobile', 'revlens managed', 'revlens web', 'revlens disasm']) assert.ok(h.includes(s), s);
  assert.match(run('help', 'disasm'), /revlens disasm decompile/);
});

test('tools lists every MCP tool', () => {
  const tools = JSON.parse(run('tools', '--json')) as { name: string; group: string }[];
  assert.ok(tools.length >= 60);
  assert.equal(tools.filter((t) => t.group === 'core').length, 13);
});

test('namespaced commands resolve clashing names', () => {
  const d = JSON.parse(run('disasm', 'xrefs', S('disasm/hello-x64.elf'), 'main', '--direction', 'from', '--json'));
  assert.ok(d);
  const m = run('mobile', 'xrefs', S('mobile/java/hello-035.dex'), '--target', 'println', '--json');
  assert.ok(m.length > 0);
});

test('a unique package command works without its area', () => {
  const out = run('javap', S('mobile/java/Hello.class'));
  assert.match(out, /class/);
});

test('analyze gives one combined report', () => {
  const r = JSON.parse(run('analyze', S('webrt/dns_udp.pcap'), '--json'));
  assert.equal(r.file.format, 'pcap');
  assert.ok(r.meta.webrt.pcap.packetCount > 0);
  const e = JSON.parse(run('analyze', S('disasm/hello-arm64.elf'), '--json'));
  assert.ok(e.meta.disasm.functions > 0);
  assert.equal(JSON.parse(run('analyze', S('disasm/hello-arm64.elf'), '--json', '--packages', 'mobile')).meta.disasm, undefined);
});

test('setup writes a project Cursor config, doctor and bridge list run at the top level', () => {
  const dir = mkdtempSync(join(tmpdir(), 'revlens-setup-'));
  runIn(dir, 'setup', 'cursor', '--scope', 'project', '--write');
  const cfg = JSON.parse(readFileSync(join(dir, '.cursor/mcp.json'), 'utf8'));
  assert.ok(JSON.stringify(cfg.mcpServers.revlens.args).includes('@revlens/mcp'));
  assert.ok(JSON.parse(run('doctor', '--json')));
  assert.match(run('bridge', 'list'), /r2_functions/);
  assert.match(run('--help'), /revlens doctor/);
});
