// `revlens setup`: show or write MCP client config so agents can use RevLens.
// It only writes when asked with --write, only to the project folder (or a path you give),
// and it merges into an existing file instead of replacing it.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

type Flags = Record<string, string | boolean>;

const SERVER = { command: 'npx', args: ['-y', '@revlens/mcp@latest'] };

interface Client { id: string; title: string; file?: string; key?: string; show(): string; extra?: Record<string, unknown> }

const json = (v: unknown) => JSON.stringify(v, null, 2);

const CLIENTS: Client[] = [
  { id: 'claude', title: 'Claude Code', show: () => 'claude mcp add revlens -- npx -y @revlens/mcp@latest\n\nOr install the plugin: /plugin marketplace add aniruddhaadak80/re then /plugin install revlens' },
  { id: 'codex', title: 'Codex CLI', show: () => '# ~/.codex/config.toml\n[mcp_servers.revlens]\ncommand = "npx"\nargs = ["-y", "@revlens/mcp@latest"]\nstartup_timeout_sec = 30' },
  { id: 'cursor', title: 'Cursor', file: '.cursor/mcp.json', key: 'mcpServers', show: () => json({ mcpServers: { revlens: SERVER } }) },
  { id: 'vscode', title: 'VS Code', file: '.vscode/mcp.json', key: 'servers', extra: { type: 'stdio' }, show: () => json({ servers: { revlens: { type: 'stdio', ...SERVER } } }) },
  { id: 'gemini', title: 'Gemini CLI', file: '.gemini/settings.json', key: 'mcpServers', show: () => json({ mcpServers: { revlens: SERVER } }) },
  { id: 'claude-project', title: 'Claude Code (project .mcp.json)', file: '.mcp.json', key: 'mcpServers', show: () => json({ mcpServers: { revlens: SERVER } }) },
];

export const SETUP_HELP = `revlens setup [client] [--write] [--dir <folder>]

Shows the MCP config that connects an agent to RevLens. Clients: ${CLIENTS.map((c) => c.id).join(', ')}.
With --write, RevLens adds a "revlens" server entry to the client's project config file
(${CLIENTS.filter((c) => c.file).map((c) => c.file).join(', ')}) in the current folder or --dir,
keeping every other entry. Codex and Claude Code user configs are only printed, never edited.`;

function writeConfig(c: Client, dir: string): string {
  if (!c.file || !c.key) throw new Error(`${c.title} config is printed only. Run the command shown above.`);
  const path = resolve(dir, c.file);
  let doc: Record<string, unknown> = {};
  if (existsSync(path)) {
    try { doc = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>; } catch { throw new Error(`${path} is not valid JSON, so it was left alone`); }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error(`${path} is not a JSON object, so it was left alone`);
  }
  const servers = (doc[c.key] && typeof doc[c.key] === 'object' ? doc[c.key] : {}) as Record<string, unknown>;
  servers.revlens = { ...(c.extra ?? {}), ...SERVER };
  doc[c.key] = servers;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, json(doc) + '\n');
  return path;
}

export async function runSetup(args: string[], flags: Flags): Promise<number> {
  if (flags.help) { console.log(SETUP_HELP); return 0; }
  const nodeMajor = Number(process.versions.node.split('.')[0]);
  const pick = args[0] ? CLIENTS.filter((c) => c.id === args[0]) : CLIENTS;
  if (!pick.length) { console.error(`unknown client "${args[0]}". Clients: ${CLIENTS.map((c) => c.id).join(', ')}`); return 2; }
  if (flags.json) { console.log(json(pick.map((c) => ({ id: c.id, title: c.title, file: c.file, config: c.show() })))); return 0; }
  console.log(`Node ${process.versions.node} ${nodeMajor >= 20 ? 'is fine' : 'is too old, RevLens needs Node 20.10 or newer'}`);
  console.log('RevLens needs nothing else installed. Optional tools such as Ghidra or radare2 are used by the bridges package when present.\n');
  for (const c of pick) {
    console.log(`${c.title}${c.file ? `  (${c.file})` : ''}`);
    console.log(c.show().split('\n').map((l) => '  ' + l).join('\n'));
    if (flags.write && c.file) {
      try { console.log(`  wrote ${writeConfig(c, typeof flags.dir === 'string' ? flags.dir : process.cwd())}`); } catch (e) { console.error(`  ${(e as Error).message}`); }
    }
    console.log('');
  }
  if (!flags.write) console.log('Add --write with a client name to save its project config, for example: revlens setup cursor --write');
  return 0;
}
