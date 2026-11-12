// Writes the RevLens MCP server into the config of common agent clients: Claude Code, Codex,
// Cursor, VS Code and Windsurf. Dry run by default; `write: true` saves with a timestamped backup.
// The merge functions are pure so they can be tested without touching the disk.
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, writeFile, type FileHandle } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, join, posix, win32 } from 'node:path';

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
  // Join with the separator of the target platform, not the host, so paths match what that client expects.
  const join = platform === 'win32' ? win32.join : posix.join;
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

/** Walk text outside JSON strings. Linear time. */
function scanJson(text: string, onChar: (c: string, i: number, out: string[]) => number): string {
  const out: string[] = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out.push(text.slice(i, j + 1));
      i = j + 1;
    } else i = onChar(c, i, out);
  }
  return out.join('');
}

/** Remove // and /* *\/ comments, then trailing commas, outside strings, for JSONC files like VS Code's. Linear time. */
export function stripJsonc(text: string): string {
  const noComments = scanJson(text, (c, i, out) => {
    if (c === '/' && text[i + 1] === '/') { let j = i; while (j < text.length && text[j] !== '\n') j++; return j; }
    if (c === '/' && text[i + 1] === '*') { const end = text.indexOf('*/', i + 2); return end < 0 ? text.length : end + 2; }
    out.push(c);
    return i + 1;
  });
  const t = noComments;
  return scanJson(t, (c, i, out) => {
    if (c === ',') {
      let j = i + 1;
      while (j < t.length && (t[j] === ' ' || t[j] === '\t' || t[j] === '\r' || t[j] === '\n')) j++;
      if (t[j] === '}' || t[j] === ']') return i + 1;
    }
    out.push(c);
    return i + 1;
  });
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

/**
 * Write a plan to disk. An existing file is copied to `<file>.revlens-backup-<timestamp>` first (read
 * through one descriptor, the backup created exclusively). The new content goes to a fresh temp file in
 * the same folder, opened exclusively with the old file's permissions, and is renamed over the config, so
 * the config is replaced in one step and never left half written.
 */
export async function applySetup(plan: SetupPlan, now: Date = new Date()): Promise<{ path: string; backup: string | null; written: boolean }> {
  if (!plan.changed) return { path: plan.path, backup: null, written: false };
  const dir = dirname(plan.path);
  await mkdir(dir, { recursive: true });
  let backup: string | null = null;
  let mode = 0o644;
  let fh: FileHandle | undefined;
  try { fh = await open(plan.path, 'r'); } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  if (fh) {
    try {
      const st = await fh.stat();
      mode = st.mode & 0o777;
      backup = `${plan.path}.revlens-backup-${now.toISOString().replace(/[:.]/g, '-')}`;
      await writeFile(backup, await fh.readFile(), { flag: 'wx', mode });
    } finally { await fh.close(); }
  }
  const tmp = join(dir, `.${basename(plan.path)}.revlens-${process.pid}-${randomBytes(6).toString('hex')}.tmp`);
  await writeFile(tmp, plan.after, { encoding: 'utf8', flag: 'wx', mode });
  try { await rename(tmp, plan.path); } catch (e) { await rm(tmp, { force: true }); throw e; }
  return { path: plan.path, backup, written: true };
}

/** Plan and, when `write` is true, apply. */
export async function setupClient(o: SetupOptions & { write?: boolean }) {
  const plan = await planSetup(o);
  if (!o.write) return { dryRun: true, ...plan };
  const res = await applySetup(plan);
  return { dryRun: false, ...plan, ...res };
}

// ---------------------------------------------------------------- uninstall

/** Remove one server entry from a JSON or JSONC config. Returns the text unchanged when it is not there. */
export function removeJsonServer(text: string, key: string, name: string): string {
  if (!text.trim()) return text;
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch {
    try { parsed = JSON.parse(stripJsonc(text)); } catch { throw new SetupError('the existing config is not valid JSON, refusing to edit it'); }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new SetupError('the existing config is not a JSON object');
  const data = parsed as Record<string, unknown>;
  const cur = data[key];
  if (!cur || typeof cur !== 'object' || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, name)) return text;
  const servers = { ...(cur as Record<string, unknown>) };
  delete servers[name];
  return JSON.stringify({ ...data, [key]: servers }, null, 2) + '\n';
}

/** Remove `[mcp_servers.<name>]` and its sub tables from a Codex config.toml. */
export function removeTomlServer(text: string, name: string): string {
  const src = text.split(/\r?\n/);
  const kept: string[] = [];
  let skipping = false;
  let found = false;
  for (const line of src) {
    const h = tableHeader(line);
    if (h) { skipping = h.length >= 2 && h[0] === 'mcp_servers' && h[1] === name; if (skipping) found = true; }
    if (!skipping) kept.push(line);
  }
  if (!found) return text;
  while (kept.length && kept[kept.length - 1]!.trim() === '') kept.pop();
  return kept.length ? kept.join('\n') + '\n' : '';
}

export interface UninstallOptions {
  /** one client, or every client when left out */
  client?: McpClient;
  /** user, project or both (default both) */
  scope?: 'user' | 'project' | 'both';
  /** server name in the configs, default revlens */
  name?: string;
  /** skill folder names to remove from the agents' skill folders, default `<name>-reverse-engineer` */
  skills?: string[];
  /** also remove the data folder (~/.<name>: Cutter plugin announcements, caches) */
  purge?: boolean;
  home?: string;
  cwd?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}

export interface UninstallStep { kind: 'config' | 'skill' | 'data'; client?: McpClient; scope?: 'user' | 'project'; path: string; before?: string; after?: string; changed: boolean }

/** Folders where agents look for skills, user and project level. */
export function skillRoots(home: string, cwd: string, platform: NodeJS.Platform): string[] {
  const join = platform === 'win32' ? win32.join : posix.join;
  return [join(home, '.agents', 'skills'), join(home, '.claude', 'skills'), join(home, '.codex', 'skills'), join(cwd, '.agents', 'skills'), join(cwd, '.claude', 'skills')];
}

/** True when a folder holds a SKILL.md whose front matter name matches; only such folders are removed. */
async function isOurSkill(dir: string, skill: string): Promise<boolean> {
  try {
    const text = await readFile(join(dir, 'SKILL.md'), 'utf8');
    const fm = /^---\r?\n([\s\S]{0,4000}?)\r?\n---/.exec(text);
    const m = fm ? /^name:\s*["']?([^"'\r\n]+)["']?\s*$/m.exec(fm[1]!) : null;
    return !!m && m[1]!.trim() === skill;
  } catch { return false; }
}

/** Work out what uninstall would remove, without changing anything. */
export async function planUninstall(o: UninstallOptions = {}): Promise<UninstallStep[]> {
  const name = o.name ?? 'revlens';
  if (!NAME_RE.test(name)) throw new SetupError('name may only use letters, digits, _ and -');
  const platform = o.platform ?? process.platform;
  const env = o.env ?? process.env;
  const home = o.home ?? env.HOME ?? env.USERPROFILE ?? homedir();
  const cwd = o.cwd ?? process.cwd();
  const clients = o.client ? [o.client] : MCP_CLIENTS;
  if (o.client && !MCP_CLIENTS.includes(o.client)) throw new SetupError(`client must be one of ${MCP_CLIENTS.join(', ')}`);
  const scopes: ('user' | 'project')[] = o.scope === 'user' ? ['user'] : o.scope === 'project' ? ['project'] : ['user', 'project'];
  const steps: UninstallStep[] = [];
  const seen = new Set<string>();
  for (const client of clients) for (const scope of scopes) {
    const s = (client === 'codex' || client === 'windsurf') ? 'user' : scope;
    const { path, format, key } = configPath(client, s, { home, cwd, platform, env });
    if (seen.has(path) || !existsSync(path)) continue;
    seen.add(path);
    const before = await readFile(path, 'utf8');
    if (before.length > 16 * 1024 * 1024) throw new SetupError(`${path} is larger than 16 MiB, refusing to edit it`);
    let after: string;
    try { after = format === 'toml' ? removeTomlServer(before, name) : removeJsonServer(before, key, name); } catch (e) { throw new SetupError(`${path}: ${(e as Error).message}`); }
    if (after !== before) steps.push({ kind: 'config', client, scope: s, path, before, after, changed: true });
  }
  const join = platform === 'win32' ? win32.join : posix.join;
  for (const skill of o.skills ?? [`${name}-reverse-engineer`]) {
    if (!NAME_RE.test(skill)) throw new SetupError(`bad skill name ${skill}`);
    for (const rootDir of skillRoots(home, cwd, platform)) {
      const dir = join(rootDir, skill);
      if (existsSync(dir) && await isOurSkill(dir, skill)) steps.push({ kind: 'skill', path: dir, changed: true });
    }
  }
  if (o.purge) {
    const dir = join(home, `.${name}`);
    if (existsSync(dir)) steps.push({ kind: 'data', path: dir, changed: true });
  }
  return steps;
}

/** Apply an uninstall plan: configs are rewritten with a backup (like setup), skill and data folders removed. */
export async function applyUninstall(steps: UninstallStep[], now: Date = new Date()): Promise<{ path: string; kind: string; backup: string | null }[]> {
  const done: { path: string; kind: string; backup: string | null }[] = [];
  for (const s of steps) {
    if (s.kind === 'config') {
      const r = await applySetup({ client: s.client!, scope: s.scope!, path: s.path, format: s.path.endsWith('.toml') ? 'toml' : 'json', exists: true, changed: true, before: s.before!, after: s.after!, entry: { command: '', args: [] }, name: '' }, now);
      done.push({ path: s.path, kind: s.kind, backup: r.backup });
    } else {
      await rm(s.path, { recursive: true, force: true });
      done.push({ path: s.path, kind: s.kind, backup: null });
    }
  }
  return done;
}

/** Plan and, when `write` is true, apply. */
export async function uninstall(o: UninstallOptions & { write?: boolean } = {}) {
  const steps = await planUninstall(o);
  if (!o.write) return { dryRun: true, steps: steps.map(({ before, after, ...rest }) => { void before; void after; return rest; }) };
  const done = await applyUninstall(steps);
  return { dryRun: false, steps: done };
}
