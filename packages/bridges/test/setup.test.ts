// MCP client setup: dry run by default, merges with existing config, backs up before writing, TOML for Codex.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configPath, mergeJsonConfig, mergeTomlServer, planSetup, setupClient, stripJsonc, tomlString, defaultServer, MCP_CLIENTS } from '../src/setup.ts';
import { CLI_COMMANDS, parseArgv, toolInput } from '../src/cli.ts';
import { TOOLS } from '../src/tools.ts';

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'rl-setup-'));
  const home = join(root, 'home');
  const cwd = join(root, 'proj');
  mkdirSync(home, { recursive: true });
  mkdirSync(cwd, { recursive: true });
  return { root, home, cwd, env: { HOME: home } as NodeJS.ProcessEnv, done: () => rmSync(root, { recursive: true, force: true }) };
}

test('config paths per client and scope', () => {
  const o = { home: '/h', cwd: '/p', platform: 'linux' as const, env: {} };
  assert.equal(configPath('claude-code', 'user', o).path, '/h/.claude.json');
  assert.equal(configPath('claude-code', 'project', o).path, '/p/.mcp.json');
  assert.equal(configPath('codex', 'user', o).path, '/h/.codex/config.toml');
  assert.equal(configPath('codex', 'user', { ...o, env: { CODEX_HOME: '/c' } }).path, '/c/config.toml');
  assert.equal(configPath('cursor', 'user', o).path, '/h/.cursor/mcp.json');
  assert.equal(configPath('cursor', 'project', o).path, '/p/.cursor/mcp.json');
  assert.equal(configPath('vscode', 'project', o).key, 'servers');
  assert.equal(configPath('vscode', 'user', o).path, '/h/.config/Code/User/mcp.json');
  assert.equal(configPath('vscode', 'user', { ...o, platform: 'darwin' }).path, '/h/Library/Application Support/Code/User/mcp.json');
  assert.equal(configPath('windsurf', 'user', o).path, '/h/.codeium/windsurf/mcp_config.json');
  assert.deepEqual(defaultServer('win32'), { command: 'cmd', args: ['/c', 'npx', '-y', '@revlens/mcp'] });
  assert.deepEqual(defaultServer('linux'), { command: 'npx', args: ['-y', '@revlens/mcp'] });
});

test('dry run writes nothing', async () => {
  const s = sandbox();
  try {
    for (const client of MCP_CLIENTS) {
      const r = await setupClient({ client, home: s.home, cwd: s.cwd, env: s.env, platform: 'linux' });
      assert.equal(r.dryRun, true);
      assert.equal(r.changed, true);
      assert.equal(existsSync(r.path), false, client);
      assert.match(r.after, /@revlens\/mcp/);
    }
    assert.deepEqual(readdirSync(s.home), []);
  } finally { s.done(); }
});

test('JSON merge keeps other servers and settings, and is idempotent', async () => {
  const s = sandbox();
  try {
    const p = join(s.home, '.cursor', 'mcp.json');
    mkdirSync(join(s.home, '.cursor'));
    const original = JSON.stringify({ mcpServers: { other: { command: 'other-mcp', args: [] } }, theme: 'dark' }, null, 2);
    writeFileSync(p, original);
    const r = await setupClient({ client: 'cursor', home: s.home, cwd: s.cwd, env: s.env, platform: 'linux', write: true });
    assert.equal(r.dryRun, false);
    const now = JSON.parse(readFileSync(p, 'utf8'));
    assert.deepEqual(now.mcpServers.other, { command: 'other-mcp', args: [] });
    assert.deepEqual(now.mcpServers.revlens, { type: 'stdio', command: 'npx', args: ['-y', '@revlens/mcp'] });
    assert.equal(now.theme, 'dark');
    const backups = readdirSync(join(s.home, '.cursor')).filter((f) => f.startsWith('mcp.json.revlens-backup-'));
    assert.equal(backups.length, 1);
    assert.equal(readFileSync(join(s.home, '.cursor', backups[0]!), 'utf8'), original);
    const again = await planSetup({ client: 'cursor', home: s.home, cwd: s.cwd, env: s.env, platform: 'linux' });
    assert.equal(again.changed, false);
  } finally { s.done(); }
});

test('VS Code JSONC with comments and trailing commas is merged, invalid JSON is refused', async () => {
  const jsonc = '{\n  // my servers\n  "servers": {\n    "a": { "command": "x", "args": ["//not a comment"], },\n  },\n  /* block */\n}\n';
  assert.deepEqual(JSON.parse(stripJsonc(jsonc)), { servers: { a: { command: 'x', args: ['//not a comment'] } } });
  const merged = JSON.parse(mergeJsonConfig(jsonc, 'servers', 'revlens', { command: 'npx', args: ['-y', '@revlens/mcp'] }));
  assert.deepEqual(Object.keys(merged.servers), ['a', 'revlens']);
  assert.throws(() => mergeJsonConfig('{ not json', 'servers', 'revlens', { command: 'n', args: [] }), /not valid JSON/);
  assert.throws(() => mergeJsonConfig('[1]', 'servers', 'revlens', { command: 'n', args: [] }), /not a JSON object/);
  const s = sandbox();
  try {
    mkdirSync(join(s.cwd, '.vscode'));
    writeFileSync(join(s.cwd, '.vscode', 'mcp.json'), '{ broken');
    await assert.rejects(() => setupClient({ client: 'vscode', scope: 'project', home: s.home, cwd: s.cwd, env: s.env, write: true }), /not valid JSON/);
    assert.equal(readFileSync(join(s.cwd, '.vscode', 'mcp.json'), 'utf8'), '{ broken');
  } finally { s.done(); }
});

test('Codex TOML: replaces only our table and its sub tables', () => {
  const before = [
    'model = "o4"',
    '',
    '[mcp_servers.other]',
    'command = "other"',
    '',
    '[mcp_servers.revlens]',
    'command = "old"',
    'args = []',
    '',
    '[mcp_servers.revlens.env]',
    'X = "1"',
    '',
    '[profiles.fast]',
    'model = "mini"',
  ].join('\n');
  const after = mergeTomlServer(before, 'revlens', { command: 'npx', args: ['-y', '@revlens/mcp'], env: { REVLENS_CACHE_DIR: 'C:\\cache "x"' } });
  assert.match(after, /^model = "o4"/);
  assert.match(after, /\[mcp_servers\.other\]\ncommand = "other"/);
  assert.match(after, /\[profiles\.fast\]\nmodel = "mini"/);
  assert.doesNotMatch(after, /command = "old"/);
  assert.doesNotMatch(after, /X = "1"/);
  assert.equal(after.match(/\[mcp_servers\.revlens\]/g)?.length, 1);
  assert.match(after, /args = \["-y", "@revlens\/mcp"\]/);
  assert.match(after, /env = \{ REVLENS_CACHE_DIR = "C:\\\\cache \\"x\\"" \}/);
  assert.equal(mergeTomlServer(after, 'revlens', { command: 'npx', args: ['-y', '@revlens/mcp'], env: { REVLENS_CACHE_DIR: 'C:\\cache "x"' } }), after);
  assert.equal(mergeTomlServer('', 'revlens', { command: 'npx', args: [] }), '[mcp_servers.revlens]\ncommand = "npx"\nargs = []\n');
  assert.equal(tomlString('a\u0001\n'), '"a\\u0001\\n"');
  // quoted header form is recognized too
  assert.doesNotMatch(mergeTomlServer('[mcp_servers."revlens"]\ncommand = "old"\n', 'revlens', { command: 'n', args: [] }), /old/);
});

test('Codex write creates the file and a backup on change', async () => {
  const s = sandbox();
  try {
    const r1 = await setupClient({ client: 'codex', home: s.home, cwd: s.cwd, env: s.env, write: true });
    assert.equal((r1 as { backup?: string | null }).backup, null);
    const p = join(s.home, '.codex', 'config.toml');
    assert.match(readFileSync(p, 'utf8'), /\[mcp_servers\.revlens\]/);
    writeFileSync(p, 'model = "x"\n');
    const r2 = await setupClient({ client: 'codex', home: s.home, cwd: s.cwd, env: s.env, write: true });
    assert.ok((r2 as { backup?: string | null }).backup);
    assert.equal(readFileSync((r2 as { backup: string }).backup, 'utf8'), 'model = "x"\n');
  } finally { s.done(); }
});

test('bad names and clients are refused', async () => {
  await assert.rejects(() => planSetup({ client: 'cursor', name: 'a b', home: '/tmp/x', cwd: '/tmp/x' }), /name may only/);
  await assert.rejects(() => planSetup({ client: 'notepad' as never, home: '/tmp/x', cwd: '/tmp/x' }), /client must be/);
});

test('CLI exports doctor, setup and bridge; argv parsing maps flags to tool inputs', () => {
  assert.deepEqual(CLI_COMMANDS.map((c) => c.name), ['doctor', 'setup', 'bridge']);
  const p = parseArgv(['app.elf', '--function', 'main', '--limit=5', '--json', '--breakpoints', 'a,b', '--breakpoints', 'c', '--allow-execution']);
  const t = TOOLS.find((x) => x.name === 'bridge_gdb_run')!;
  assert.deepEqual(toolInput(t, p), { breakpoints: ['a', 'b', 'c'], allowExecution: true, path: 'app.elf' });
  const r = TOOLS.find((x) => x.name === 'bridge_r2_disasm')!;
  assert.deepEqual(toolInput(r, p), { function: 'main', path: 'app.elf' });
  assert.deepEqual(toolInput(TOOLS.find((x) => x.name === 'bridge_r2_functions')!, p), { limit: 5, path: 'app.elf' });
});

test('TOOLS: unique bridge_ names, required fields present', () => {
  const names = TOOLS.map((t) => t.name);
  assert.equal(new Set(names).size, names.length);
  for (const t of TOOLS) {
    assert.match(t.name, /^bridge_[a-z0-9_]+$/);
    assert.ok(t.description.length > 20);
    for (const [k, v] of Object.entries(t.inputSchema)) assert.ok(['string', 'number', 'boolean', 'array', 'object'].includes(v.type), `${t.name}.${k}`);
  }
  for (const n of ['bridge_doctor', 'bridge_r2_functions', 'bridge_r2_disasm', 'bridge_r2_decompile', 'bridge_ghidra_decompile', 'bridge_ghidra_functions',
    'bridge_jadx_decompile', 'bridge_jadx_search', 'bridge_ilspy_decompile', 'bridge_frida_ps', 'bridge_frida_run', 'bridge_gdb_run', 'bridge_objdump',
    'bridge_binwalk', 'bridge_adb_devices', 'bridge_adb_pull_apk']) assert.ok(names.includes(n), n);
});
