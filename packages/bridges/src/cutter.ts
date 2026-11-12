// Cutter bridge. Finds running Cutter windows and the files and projects they have open, then runs
// rizin commands on the same file: live inside Cutter through the RevLens Cutter plugin when it is
// loaded (scripts/cutter/revlens_cutter_bridge.py), or in a separate rizin (Cutter's bundled rizin
// first) against the same file and project. Node only. Never uses a shell.
import { readdirSync, readFileSync, readlinkSync, statSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, join, resolve, dirname } from 'node:path';
import { request } from 'node:http';
import { fileURLToPath } from 'node:url';
import { bundledScriptPath } from './assets.js';
import { runTool, withTempDir, describeFailure } from './exec.js';
import { copyFile } from 'node:fs/promises';
import { detect } from './detect.js';
import { installFor } from './catalog.js';
import { checkR2Command } from './sessions/guards.js';
import { BridgeInputError, int, requireExecution, requireFile } from './providers/common.js';

export interface CutterSession {
  pid: number;
  /** executable or AppImage the process runs */
  exe: string | null;
  /** command line as the OS reports it, capped */
  argv: string[];
  /** binaries the window has open: command line arguments and open file descriptors */
  files: string[];
  /** rizin project (.rzdb) given on the command line, if any */
  project: string | null;
  cwd: string | null;
  /** how the process was found */
  source: 'proc' | 'ps' | 'windows' | 'plugin';
  /** live plugin bridge, when the RevLens Cutter plugin runs in this window */
  bridge: { port: number; file: string | null; startedAt: string | null } | null;
}

const MAX_PROCS = 4096;
const MAX_ARGS = 64;
const SKIP_DIRS = ['/usr/', '/lib/', '/lib64/', '/proc/', '/sys/', '/dev/', '/etc/', '/opt/cutter', '/tmp/.mount_', '/snap/', '/System/', '/Library/'];
const SKIP_EXT = /\.(so(\.\d+)*|dylib|py[co]?|qm|ttf|otf|ini|conf|json|log|sqlite|db|cache|lock|desktop)$/i;

/** True when an argv[0] or process name looks like Cutter (binary, AppImage, app bundle, Flatpak). */
export function isCutterProcess(argv0: string, comm = ''): boolean {
  const base = basename(argv0.replace(/\\/g, '/')).toLowerCase();
  const c = comm.toLowerCase();
  if (base === 'cutter' || base === 'cutter.exe' || c === 'cutter' || c === 'cutter.exe') return true;
  if (/^cutter[-_ ]?v?\d[\w.-]*\.appimage$/.test(base) || base === 'cutter.appimage') return true;
  if (argv0.includes('/Cutter.app/Contents/MacOS/')) return true;
  if (argv0.includes('re.rizin.cutter')) return true;
  return false;
}

/** Split a /proc/<pid>/cmdline buffer. */
export function parseCmdline(buf: Buffer | string): string[] {
  const s = typeof buf === 'string' ? buf : buf.toString('utf8');
  return s.split('\0').filter((x, i, a) => x !== '' || i < a.length - 1).slice(0, MAX_ARGS).map((x) => x.slice(0, 4096));
}

/**
 * Files and project named on a Cutter command line. Cutter takes `[options] [filename]`, with
 * -p/--project <file.rzdb>, -A/--analysis <level>, -a/-b/-c/-i/-F/-e taking a value.
 */
export function filesFromArgs(args: string[], cwd: string | null): { files: string[]; project: string | null } {
  const valued = new Set(['-A', '--analysis', '-a', '--arch', '-b', '--bits', '-c', '--cpu', '-o', '--os', '-F', '--format', '-B', '--base', '-i', '-e', '--endian', '--pythonhome', '-p', '--project']);
  const files: string[] = [];
  let project: string | null = null;
  const abs = (p: string) => (isAbsolute(p) || /^[A-Za-z]:[\\/]/.test(p) ? p : cwd ? resolve(cwd, p) : p);
  for (let i = 1; i < args.length; i++) {
    const a = args[i]!;
    if (a === '-p' || a === '--project') { const v = args[++i]; if (v) project = abs(v); continue; }
    if (a.startsWith('--project=')) { project = abs(a.slice(10)); continue; }
    if (valued.has(a)) { i++; continue; }
    if (a.startsWith('-')) continue;
    if (/\.rzdb$/i.test(a)) project = abs(a);
    else files.push(abs(a));
  }
  return { files, project };
}

function readText(p: string, max = 1 << 20): string | null {
  try { const b = readFileSync(p); return b.subarray(0, max).toString('utf8'); } catch { return null; }
}

/** Regular files a process holds open, from /proc/<pid>/fd, without libraries and system files. */
export function openFilesFromProc(procRoot: string, pid: number, limit = 64): string[] {
  const out = new Set<string>();
  let fds: string[] = [];
  try { fds = readdirSync(join(procRoot, String(pid), 'fd')).slice(0, 4096); } catch { return []; }
  for (const fd of fds) {
    let target: string;
    try { target = readlinkSync(join(procRoot, String(pid), 'fd', fd)); } catch { continue; }
    if (!target.startsWith('/') || target.endsWith(' (deleted)')) continue;
    if (SKIP_DIRS.some((d) => target.startsWith(d)) || SKIP_EXT.test(target)) continue;
    try { if (!statSync(target).isFile()) continue; } catch { continue; }
    out.add(target);
    if (out.size >= limit) break;
  }
  return [...out];
}

/** Cutter processes on Linux, from a proc file system (procRoot is for tests). */
export function cutterFromProc(procRoot = '/proc'): CutterSession[] {
  let pids: string[] = [];
  try { pids = readdirSync(procRoot).filter((x) => /^\d{1,10}$/.test(x)).slice(0, MAX_PROCS); } catch { return []; }
  const out: CutterSession[] = [];
  for (const p of pids) {
    const pid = Number(p);
    const raw = readText(join(procRoot, p, 'cmdline'), 64 * 1024);
    if (!raw) continue;
    const argv = parseCmdline(raw);
    const comm = (readText(join(procRoot, p, 'comm'), 256) ?? '').trim();
    if (!argv.length || !isCutterProcess(argv[0]!, comm)) continue;
    let cwd: string | null = null;
    try { cwd = readlinkSync(join(procRoot, p, 'cwd')); } catch { cwd = null; }
    let exe: string | null = null;
    try { exe = readlinkSync(join(procRoot, p, 'exe')); } catch { exe = argv[0] ?? null; }
    const fromArgs = filesFromArgs(argv, cwd);
    const open = openFilesFromProc(procRoot, pid).filter((f) => f !== exe && !f.toLowerCase().endsWith('.appimage'));
    const files = [...new Set([...fromArgs.files, ...open])];
    out.push({ pid, exe, argv, files, project: fromArgs.project ?? (open.find((f) => /\.rzdb$/i.test(f)) ?? null), cwd, source: 'proc', bridge: null });
  }
  return out;
}

/** Parse `ps -axww -o pid=,args=` output (macOS and other Unix without /proc). */
export function parsePs(text: string): { pid: number; args: string }[] {
  const out: { pid: number; args: string }[] = [];
  for (const line of text.split('\n').slice(0, MAX_PROCS * 2)) {
    const t = line.trim();
    const sp = t.indexOf(' ');
    if (sp < 1) continue;
    const pid = Number(t.slice(0, sp));
    if (!Number.isInteger(pid) || pid <= 0) continue;
    out.push({ pid, args: t.slice(sp + 1).trim().slice(0, 8192) });
  }
  return out;
}

/** Parse `lsof -Fn -p <pid>` output into regular file paths. */
export function parseLsof(text: string): string[] {
  return [...new Set(text.split('\n').filter((l) => l.startsWith('n/')).map((l) => l.slice(1)))]
    .filter((f) => !SKIP_DIRS.some((d) => f.startsWith(d)) && !SKIP_EXT.test(f)).slice(0, 64);
}

/** Parse PowerShell ConvertTo-Json output of Win32_Process rows. */
export function parseWindowsProcesses(json: string): { pid: number; commandLine: string; exe: string | null }[] {
  let v: unknown;
  try { v = JSON.parse(json); } catch { return []; }
  const rows = Array.isArray(v) ? v : v ? [v] : [];
  return rows.slice(0, MAX_PROCS).flatMap((r: any) => (Number.isInteger(r?.ProcessId) ? [{ pid: r.ProcessId as number, commandLine: String(r.CommandLine ?? '').slice(0, 8192), exe: typeof r.ExecutablePath === 'string' ? r.ExecutablePath : null }] : []));
}

/** Split a command line the way the Microsoft C runtime does, for Windows process listings. */
export function splitWindowsCommandLine(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  let have = false;
  for (let i = 0; i < s.length && out.length < MAX_ARGS; i++) {
    const c = s[i]!;
    if (c === '"') { quoted = !quoted; have = true; continue; }
    if ((c === ' ' || c === '\t') && !quoted) { if (have) { out.push(cur); cur = ''; have = false; } continue; }
    cur += c; have = true;
  }
  if (have) out.push(cur);
  return out;
}

/** Folder where the RevLens Cutter plugin announces live windows. */
export function pluginDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.REVLENS_CUTTER_BRIDGE_DIR || join(env.HOME || env.USERPROFILE || homedir(), '.revlens', 'cutter');
}

interface PluginAnnouncement { pid: number; port: number; token: string; file: string | null; startedAt: string | null; protocol: number }

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === 'EPERM'; }
}

/** Announcements written by the plugin, for processes that are still alive. */
export function readAnnouncements(dir = pluginDir()): PluginAnnouncement[] {
  let names: string[] = [];
  try { names = readdirSync(dir).filter((n) => /^\d{1,10}\.json$/.test(n)).slice(0, 256); } catch { return []; }
  const out: PluginAnnouncement[] = [];
  for (const n of names) {
    const t = readText(join(dir, n), 64 * 1024);
    if (!t) continue;
    try {
      const j = JSON.parse(t);
      if (!Number.isInteger(j.pid) || !Number.isInteger(j.port) || j.port <= 0 || j.port > 65535 || typeof j.token !== 'string' || j.token.length < 16) continue;
      if (!alive(j.pid)) continue;
      out.push({ pid: j.pid, port: j.port, token: j.token, file: typeof j.file === 'string' ? j.file : null, startedAt: typeof j.startedAt === 'string' ? j.startedAt : null, protocol: Number(j.protocol) || 1 });
    } catch { /* ignore broken files */ }
  }
  return out;
}

export interface ListOptions { procRoot?: string; platform?: NodeJS.Platform; pluginDir?: string; timeoutMs?: number }

/** Running Cutter windows with their open files, projects and live plugin bridges. */
export async function listCutterSessions(opts: ListOptions = {}): Promise<{ platform: string; sessions: CutterSession[]; plugin: { dir: string; script: string }; notes: string[] }> {
  const platform = opts.platform ?? process.platform;
  const notes: string[] = [];
  let sessions: CutterSession[] = [];
  const timeoutMs = opts.timeoutMs ?? 10_000;
  if (platform === 'linux' || opts.procRoot) sessions = cutterFromProc(opts.procRoot ?? '/proc');
  else if (platform === 'win32') {
    const r = await runTool('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "Get-CimInstance Win32_Process -Filter \"Name like 'cutter%'\" | Select-Object ProcessId,CommandLine,ExecutablePath | ConvertTo-Json -Compress"], { timeoutMs, maxOutputBytes: 4 << 20 });
    if (r.error || r.code !== 0) notes.push(`process listing failed: ${describeFailure(r)}`);
    for (const p of parseWindowsProcesses(r.stdout)) {
      const argv = splitWindowsCommandLine(p.commandLine);
      if (!isCutterProcess(p.exe ?? argv[0] ?? '')) continue;
      const f = filesFromArgs(argv, null);
      sessions.push({ pid: p.pid, exe: p.exe, argv, files: f.files, project: f.project, cwd: null, source: 'windows', bridge: null });
    }
  } else {
    const r = await runTool('ps', ['-axww', '-o', 'pid=,args='], { timeoutMs, maxOutputBytes: 8 << 20 });
    if (r.error || r.code !== 0) notes.push(`process listing failed: ${describeFailure(r)}`);
    for (const p of parsePs(r.stdout)) {
      const exeEnd = p.args.indexOf('/Contents/MacOS/');
      const argv0 = exeEnd > 0 ? p.args.slice(0, p.args.indexOf(' ', exeEnd) > 0 ? p.args.indexOf(' ', exeEnd) : undefined) : p.args.split(' ')[0]!;
      if (!isCutterProcess(argv0)) continue;
      const rest = p.args.slice(argv0.length).trim();
      const argv = [argv0, ...(rest ? rest.split(/ (?=[-/~])/) : [])];
      const f = filesFromArgs(argv, null);
      const l = await runTool('lsof', ['-Fn', '-p', String(p.pid)], { timeoutMs, maxOutputBytes: 4 << 20 });
      const open = l.code === 0 ? parseLsof(l.stdout) : [];
      if (l.error) notes.push('lsof is not available, so only command line files are listed');
      sessions.push({ pid: p.pid, exe: argv0, argv, files: [...new Set([...f.files, ...open.filter((x) => !x.includes('/Cutter.app/'))])], project: f.project, cwd: null, source: 'ps', bridge: null });
    }
  }
  const dir = opts.pluginDir ?? pluginDir();
  for (const a of readAnnouncements(dir)) {
    const s = sessions.find((x) => x.pid === a.pid);
    const bridge = { port: a.port, file: a.file, startedAt: a.startedAt };
    if (s) { s.bridge = bridge; if (a.file && !s.files.includes(a.file)) s.files.unshift(a.file); }
    else sessions.push({ pid: a.pid, exe: null, argv: [], files: a.file ? [a.file] : [], project: null, cwd: null, source: 'plugin', bridge });
  }
  if (!sessions.some((s) => s.bridge)) notes.push(`For live commands inside Cutter, load the RevLens plugin: copy ${pluginScriptPath()} into Cutter's plugins/python folder and restart Cutter.`);
  return { platform, sessions, plugin: { dir, script: pluginScriptPath() }, notes };
}

/** Path of the RevLens Cutter plugin shipped with this package. */
export function pluginScriptPath(): string {
  const here = typeof __filename === 'string' ? dirname(__filename) : dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, '..', 'scripts', 'cutter', 'revlens_cutter_bridge.py'), join(here, '..', '..', 'scripts', 'cutter', 'revlens_cutter_bridge.py')];
  return bundledScriptPath('bridges/cutter/revlens_cutter_bridge.py', candidates);
}
declare const __filename: string | undefined;

/** Send one command to a live plugin over loopback HTTP with its token. */
export function pluginCommand(port: number, token: string, command: string, timeoutMs = 60_000, maxBytes = 16 << 20): Promise<{ ok: boolean; output?: string; error?: string; status?: number }> {
  return new Promise((resolveP) => {
    const body = JSON.stringify({ command });
    const req = request({ host: '127.0.0.1', port, path: '/cmd', method: 'POST', timeout: timeoutMs, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), authorization: `Bearer ${token}` } }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => { size += c.length; if (size <= maxBytes) chunks.push(c); else req.destroy(); });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try {
          const j = JSON.parse(text);
          resolveP({ ok: res.statusCode === 200 && j.ok !== false, output: typeof j.output === 'string' ? j.output : undefined, error: j.error, status: res.statusCode });
        } catch { resolveP({ ok: false, error: `bad reply from the Cutter plugin (HTTP ${res.statusCode})`, status: res.statusCode }); }
      });
    });
    req.on('timeout', () => { req.destroy(new Error(`no reply from the Cutter plugin within ${timeoutMs} ms`)); });
    req.on('error', (e) => resolveP({ ok: false, error: e.message }));
    req.end(body);
  });
}

export interface CutterCommandInput {
  /** pid of a Cutter window from list_cutter_sessions */
  session?: string | number;
  /** file to run on when no session is given, or to pick one of several files in the session */
  file?: string;
  /** rizin project (.rzdb) to load instead of the session's */
  project?: string;
  command: string;
  allowExecution?: boolean;
  /** live (plugin, default when available), rizin (separate process) */
  mode?: 'auto' | 'live' | 'rizin';
  analysis?: 'none' | 'aa' | 'aaa';
  maxChars?: number;
  timeoutMs?: number;
}

/**
 * Run one rizin command for a Cutter window. With the plugin loaded the command runs inside that
 * Cutter (sees the user's renames and comments). Otherwise a separate rizin opens the same file (and
 * project), runs the command and exits. Commands pass the same guard as radare2 sessions.
 */
export async function cutterCommand(input: CutterCommandInput, opts: ListOptions = {}): Promise<unknown> {
  const deny = requireExecution(input, 'cutter_command');
  if (deny) return { ok: false, needsAllowExecution: true, error: deny };
  const bad = checkR2Command(input.command);
  if (bad) throw new BridgeInputError(bad.replace('r2 sessions', 'cutter_command'));
  const maxChars = int(input.maxChars, 200_000, 1_000, 4_000_000);
  const timeoutMs = int(input.timeoutMs, 120_000, 1_000, 30 * 60_000);
  let session: CutterSession | undefined;
  if (input.session !== undefined && input.session !== '') {
    const pid = Number(input.session);
    if (!Number.isInteger(pid) || pid <= 0) throw new BridgeInputError('session must be a Cutter pid from list_cutter_sessions');
    session = (await listCutterSessions(opts)).sessions.find((s) => s.pid === pid);
    if (!session) return { ok: false, error: `no running Cutter with pid ${pid}. Call list_cutter_sessions again.` };
  }
  const mode = input.mode ?? 'auto';
  if (session?.bridge && mode !== 'rizin') {
    const ann = readAnnouncements(opts.pluginDir ?? pluginDir()).find((a) => a.pid === session!.pid);
    if (ann) {
      const r = await pluginCommand(ann.port, ann.token, input.command.trim(), timeoutMs);
      if (r.ok) { const out = r.output ?? ''; return { ok: true, mode: 'live', pid: session.pid, file: ann.file, command: input.command, output: out.slice(0, maxChars), truncated: out.length > maxChars }; }
      if (mode === 'live') return { ok: false, mode: 'live', pid: session.pid, error: r.error ?? 'plugin call failed' };
    }
  } else if (mode === 'live') return { ok: false, mode: 'live', error: 'no live RevLens plugin in this Cutter window', plugin: pluginScriptPath() };

  const file = input.file ? requireFile(input.file).path : session?.files[0];
  if (!file) throw new BridgeInputError('give session (a Cutter pid) or file');
  if (session && input.file && !session.files.includes(file)) throw new BridgeInputError(`file is not open in Cutter ${session.pid}; it has ${session.files.join(', ') || 'no files'}`);
  requireFile(file);
  const project = input.project ? requireFile(input.project, 'project').path : session?.project && existsSync(session.project) ? session.project : null;
  const engine = await pickRizin();
  if ('missing' in engine) return engine.missing;
  const pre = ['-2', '-q', '-N', '-e', 'scr.color=0', '-e', 'scr.interactive=false'];
  const analysis = input.analysis === 'aaa' ? 'aaa' : input.analysis === 'none' || project ? '' : 'aa';
  const script = [analysis, input.command.trim()].filter(Boolean).join(';');
  const name = basename(file);
  const plain = /^[A-Za-z0-9_][\w.+-]{0,200}$/.test(name);
  const run = (cwd: string, target: string) => runTool(engine.path, project && engine.id === 'rizin'
    ? [...pre, '-p', project, '-c', script, target]
    : [...pre, '-e', 'cfg.sandbox=true', '-c', script, target], { timeoutMs, maxOutputBytes: Math.min(maxChars * 4, 64 << 20), cwd });
  const r = plain ? await run(dirname(file), name) : await withTempDir(async (tmp) => { await copyFile(file, join(tmp, 'input.bin')); return run(tmp, 'input.bin'); });
  const ok = !r.error && !r.timedOut && (r.code === 0 || r.stdout.length > 0);
  return {
    ok, mode: 'rizin', engine: engine.id, engineVersion: engine.version, enginePath: engine.path, pid: session?.pid ?? null, file, project: project && engine.id === 'rizin' ? project : null,
    command: input.command, output: r.stdout.slice(0, maxChars), truncated: r.stdout.length > maxChars || r.truncated, durationMs: r.durationMs,
    ...(ok ? {} : { error: describeFailure(r) }),
    note: 'This ran in a separate rizin on the same file. Renames made in the Cutter window are only seen with the RevLens Cutter plugin (mode live) or after saving the project.',
  };
}

/** Cutter's bundled rizin, then rizin, then radare2 (same command language for common commands). */
async function pickRizin(): Promise<{ id: 'rizin' | 'radare2'; path: string; version: string | null } | { missing: unknown }> {
  const cutter = await detect('cutter');
  const bundled = typeof cutter.details?.bundledRizin === 'string' ? cutter.details.bundledRizin : null;
  if (bundled && existsSync(bundled)) return { id: 'rizin', path: bundled, version: cutter.version ?? null };
  const rz = await detect('rizin');
  if (rz.available && rz.path) return { id: 'rizin', path: rz.path, version: rz.version ?? null };
  const r2 = await detect('radare2');
  if (r2.available && r2.path) return { id: 'radare2', path: r2.path, version: r2.version ?? null };
  return { missing: { available: false, tool: 'rizin', reason: 'Neither Cutter\'s bundled rizin, rizin nor radare2 was found.', install: installFor('rizin') } };
}
