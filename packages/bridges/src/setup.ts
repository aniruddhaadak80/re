// Writes the RevLens MCP server into the config of common agent clients: Claude Code, Codex,
// Cursor, VS Code and Windsurf. Dry run by default; `write: true` saves with a timestamped backup.
// The merge functions are pure so they can be tested without touching the disk.
import { existsSync } from 'node:fs';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export type McpClient = 'claude-code' | 'codex' | 'cursor' | 'vscode' | 'windsurf';
export const MCP_CLIENTS: McpClient[] = ['claude-code', 'codex', 'cursor', 'vscode', 'windsurf'];

export interface McpServerEntry {
  command: string;
  args: string[];
  env?: Record<string, string>;
}

export interface SetupOptions {
  client: McpClient;
  /** user (global) or project (current folder). Codex and Windsurf only have a user config. */
  scope?: 'user' | 'project';
  /** server name in the config, default revlens */
  name?: string;
  /** override the launch command, default `npx -y @revlens/mcp` */
  server?: McpServerEntry;
  home?: string;
  cwd?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}

export interface SetupPlan {
  client: McpClient;
  scope: 'user' | 'project';
  path: string;
  format: 'json' | 'toml';
  exists: boolean;
  changed: boolean;
  before: string;
  after: string;
  entry: McpServerEntry;
  name: string;
}

export class SetupError extends Error {}

const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Default launch command. On Windows npx is a .cmd shim, which most clients can only start through cmd /c. */
export function defaultServer(platform: NodeJS.Platform = process.platform): McpServerEntry {
  return platform === 'win32' ? { command: 'cmd', args: ['/c', 'npx', '-y', '@revlens/mcp'] } : { command: 'npx', args: ['-y', '@revlens/mcp'] };
}

/** Where each client keeps its MCP config. */
export function configPath(client: McpClient, scope: 'user' | 'project', o: { home: string; cwd: string; platform: NodeJS.Platform; env: NodeJS.ProcessEnv }): { path: string; format: 'json' | 'toml'; key: string } {
  const { home, cwd, platform, env } = o;
  switch (client) {
    case 'claude-code':
      return scope === 'project' ? { path: join(cwd, '.mcp.json'), format: 'json', key: 'mcpServers' } : { path: join(home, '.claude.json'), format: 'json', key: 'mcpServers' };
    case 'codex':
      return { path: join(env.CODEX_HOME || join(home, '.codex'), 'config.toml'), format: 'toml', key: 'mcp_servers' };
    case 'cursor':
      return { path: scope === 'project' ? join(cwd, '.cursor', 'mcp.json') : join(home, '.cursor', 'mcp.json'), format: 'json', key: 'mcpServers' };
    case 'vscode': {
      if (scope === 'project') return { path: join(cwd, '.vscode', 'mcp.json'), format: 'json', key: 'servers' };
      const base = platform === 'win32' ? (env.APPDATA || join(home, 'AppData', 'Roaming'))
        : platform === 'darwin' ? join(home, 'Library', 'Application Support') : (env.XDG_CONFIG_HOME || join(home, '.config'));
      return { path: join(base, 'Code', 'User', 'mcp.json'), format: 'json', key: 'servers' };
    }
    case 'windsurf':
      return { path: join(home, '.codeium', 'windsurf', 'mcp_config.json'), format: 'json', key: 'mcpServers' };
    default:
      throw new SetupError(`unknown client ${String(client)}`);
  }
}

/** Remove // and /* *\/ comments and trailing commas outside strings, for JSONC files like VS Code's. Linear time. */
export function stripJsonc(text: string): string {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? n : end + 2;
    } else if (c === ',') {
      let j = i + 1;
      while (j < n && (text[j] === ' ' || text[j] === '\t' || text[j] === '\r' || text[j] === '\n')) j++;
      if (text[j] === '}' || text[j] === ']') { i++; continue; }
      out += c; i++;
    } else { out += c; i++; }
  }
  return out;
}

/** Merge one server into a JSON config under `key`, keeping everything else. */
export function mergeJsonConfig(text: string, key: string, name: string, entry: McpServerEntry): string {
  let data: Record<string, unknown> = {};
  if (text.trim()) {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch {
      try { parsed = JSON.parse(stripJsonc(text)); } catch { throw new SetupError('the existing config is not valid JSON, refusing to overwrite it'); }
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new SetupError('the existing config is not a JSON object');
    data = parsed as Record<string, unknown>;
  }
  const cur = data[key];
  const servers = cur && typeof cur === 'object' && !Array.isArray(cur) ? { ...(cur as Record<string, unknown>) } : {};
  servers[name] = { type: 'stdio', command: entry.command, args: entry.args, ...(entry.env && Object.keys(entry.env).length ? { env: entry.env } : {}) };
  return JSON.stringify({ ...data, [key]: servers }, null, 2) + '\n';
}

/** TOML basic string. */
export function tomlString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20 || c === 0x7f) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

function tomlKey(k: string): string {
  return /^[A-Za-z0-9_-]+$/.test(k) ? k : tomlString(k);
}

/** Header path of a TOML table line like `[mcp_servers.revlens]` or `[ "mcp_servers" . "revlens" ]`, or undefined. */
function tableHeader(line: string): string[] | undefined {
  const t = line.trim();
  if (!t.startsWith('[') || t.startsWith('[[')) return t.startsWith('[[') ? ['[['] : undefined;
  const close = t.indexOf(']');
  if (close < 0) return undefined;
  const inner = t.slice(1, close);
  const parts: string[] = [];
  let i = 0;
  while (i < inner.length) {
    while (inner[i] === ' ' || inner[i] === '\t') i++;
    if (inner[i] === '"' || inner[i] === "'") {
      const q = inner[i]!;
      const end = inner.indexOf(q, i + 1);
      if (end < 0) return undefined;
      parts.push(inner.slice(i + 1, end));
      i = end + 1;
    } else {
      let j = i;
      while (j < inner.length && inner[j] !== '.' && inner[j] !== ' ' && inner[j] !== '\t') j++;
      parts.push(inner.slice(i, j));
      i = j;
    }
    while (inner[i] === ' ' || inner[i] === '\t') i++;
    if (inner[i] === '.') i++;
  }
  return parts;
}

/** Replace (or add) `[mcp_servers.<name>]` and its sub tables in a Codex config.toml, keeping everything else. */
export function mergeTomlServer(text: string, name: string, entry: McpServerEntry): string {
  const src = text.split(/\r?\n/);
  const kept: string[] = [];
  let skipping = false;
  for (const line of src) {
    const h = tableHeader(line);
    if (h) skipping = h.length >= 2 && h[0] === 'mcp_servers' && h[1] === name;
    if (!skipping) kept.push(line);
  }
  while (kept.length && kept[kept.length - 1]!.trim() === '') kept.pop();
  const block = [`[mcp_servers.${tomlKey(name)}]`, `command = ${tomlString(entry.command)}`, `args = [${entry.args.map(tomlString).join(', ')}]`];
  if (entry.env && Object.keys(entry.env).length) {
    block.push(`env = { ${Object.entries(entry.env).map(([k, v]) => `${tomlKey(k)} = ${tomlString(v)}`).join(', ')} }`);
  }
  return (kept.length ? kept.join('\n') + '\n\n' : '') + block.join('\n') + '\n';
}

/** Work out what would change, without writing anything. */
export async function planSetup(o: SetupOptions): Promise<SetupPlan> {
  if (!MCP_CLIENTS.includes(o.client)) throw new SetupError(`client must be one of ${MCP_CLIENTS.join(', ')}`);
  const name = o.name ?? 'revlens';
  if (!NAME_RE.test(name)) throw new SetupError('name may only use letters, digits, _ and -');
  const platform = o.platform ?? process.platform;
  const env = o.env ?? process.env;
  const home = o.home ?? env.HOME ?? env.USERPROFILE ?? homedir();
  const cwd = o.cwd ?? process.cwd();
  let scope = o.scope ?? 'user';
  if (o.client === 'codex' || o.client === 'windsurf') scope = 'user';
  const entry = o.server ?? defaultServer(platform);
  if (typeof entry.command !== 'string' || !entry.command || !Array.isArray(entry.args) || !entry.args.every((a) => typeof a === 'string')) throw new SetupError('server must have a command and string args');
  const { path, format, key } = configPath(o.client, scope, { home, cwd, platform, env });
  const exists = existsSync(path);
  const before = exists ? await readFile(path, 'utf8') : '';
  if (before.length > 16 * 1024 * 1024) throw new SetupError('config file is larger than 16 MiB, refusing to edit it');
  const after = format === 'toml' ? mergeTomlServer(before, name, entry) : mergeJsonConfig(before, key, name, entry);
  return { client: o.client, scope, path, format, exists, changed: after !== before, before, after, entry, name };
}

/** Write a plan to disk. Existing files are copied to `<file>.revlens-backup-<timestamp>` first. */
export async function applySetup(plan: SetupPlan, now: Date = new Date()): Promise<{ path: string; backup: string | null; written: boolean }> {
  if (!plan.changed) return { path: plan.path, backup: null, written: false };
  await mkdir(dirname(plan.path), { recursive: true });
  let backup: string | null = null;
  if (existsSync(plan.path)) {
    backup = `${plan.path}.revlens-backup-${now.toISOString().replace(/[:.]/g, '-')}`;
    await copyFile(plan.path, backup);
  }
  await writeFile(plan.path, plan.after, 'utf8');
  return { path: plan.path, backup, written: true };
}

/** Plan and, when `write` is true, apply. */
export async function setupClient(o: SetupOptions & { write?: boolean }) {
  const plan = await planSetup(o);
  if (!o.write) return { dryRun: true, ...plan };
  const res = await applySetup(plan);
  return { dryRun: false, ...plan, ...res };
}
