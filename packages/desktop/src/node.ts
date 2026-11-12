// Node entry for @revlens/desktop: live process inspection and comparison, installed app discovery and
// native UI tree capture on Linux, macOS and Windows. Import as '@revlens/desktop/node'.
import { open, readFile, readdir, readlink, stat, writeFile, realpath, access } from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import { join, delimiter, isAbsolute, basename } from 'node:path';
import { homedir } from 'node:os';
import { parseProcStatus, parseCmdline, parseProcMaps, classifyFdTarget, parseProcNet, parseProcNetUnix, parseLsofF, parsePs, parseWinProcesses, parseWinProcessDetail, InputError, type ProcessInfo, type ModuleInfo, type OpenFile, type SocketInfo } from './proc.js';
import { parsePlist } from './plist.js';
import { parseDesktopFile, desktopEntryToApp, infoPlistToApp, parseRegQuery, uninstallKeysToApps, type AppRecord } from './apps.js';
import { replyValue, parseAccessibleRefs, type UiNode } from './gvariant.js';
import { compareSnapshots, type ProcessSnapshot } from './compare.js';
import { run, powershell, requireExecution, psQuote } from './exec.js';
import { BROWSER_TOOLS, type ToolDef } from './tools.js';
import { Atspi } from './atspi.js';

export * from './index.js';
export { run, executionAllowed, psQuote } from './exec.js';

const PLATFORM = process.platform;
const MAX_FILE = 64 * 1024 * 1024;
const readText = async (p: string, max = MAX_FILE) => { const b = await readFile(p); return b.subarray(0, max).toString('utf8'); };
const checkPid = (pid: unknown): number => { const n = Number(pid); if (!Number.isInteger(n) || n <= 0 || n > 0x7fffffff) throw new InputError(`bad pid ${pid}`); return n; };
const gate = (pid: number | undefined, allow: boolean | undefined, what: string) => { if (pid !== process.pid) requireExecution(allow, what); };

let users: Map<number, string> | undefined;
async function userName(uid?: number): Promise<string | undefined> {
  if (uid === undefined) return undefined;
  if (!users) { users = new Map(); try { for (const l of (await readText('/etc/passwd', 4 << 20)).split('\n')) { const p = l.split(':'); if (p.length > 3) users.set(Number(p[2]), p[0]!); } } catch { /* none */ } }
  return users.get(uid);
}

// ---------------- process list ----------------

export interface ListOptions { allowExecution?: boolean; filter?: string; limit?: number; offset?: number }

/** List running processes (pid, parent, name, executable, command line, user, threads, memory). Needs allowExecution. */
export async function listProcesses(opts: ListOptions = {}): Promise<{ platform: string; total: number; offset: number; processes: ProcessInfo[] }> {
  requireExecution(opts.allowExecution, 'listing processes');
  let procs: ProcessInfo[] = [];
  if (PLATFORM === 'linux') {
    const ents = (await readdir('/proc')).filter((n) => /^\d+$/.test(n)).slice(0, 100_000);
    await Promise.all(ents.map(async (n) => {
      try {
        const st = parseProcStatus(await readText(`/proc/${n}/status`, 1 << 20));
        const info: ProcessInfo = { ...st.info, pid: Number(n), name: st.info.name };
        info.cmdline = parseCmdline(await readText(`/proc/${n}/cmdline`, 1 << 20).catch(() => ''));
        info.exe = await readlink(`/proc/${n}/exe`).catch(() => undefined);
        info.user = await userName(info.uid);
        procs.push(info);
      } catch { /* process exited */ }
    }));
  } else if (PLATFORM === 'darwin') {
    const r = await run('ps', ['-axo', 'pid=,ppid=,uid=,rss=,vsz=,pcpu=,comm='], { timeoutMs: 15_000 });
    procs = parsePs(r.stdout);
  } else if (PLATFORM === 'win32') {
    const r = await powershell('Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,ThreadCount,WorkingSetSize | ConvertTo-Json -Compress');
    procs = parseWinProcesses(r.stdout);
  } else throw new InputError(`process listing is not supported on ${PLATFORM}`);
  procs.sort((a, b) => a.pid - b.pid);
  if (opts.filter) { const f = opts.filter.toLowerCase(); procs = procs.filter((p) => p.name.toLowerCase().includes(f) || (p.exe ?? '').toLowerCase().includes(f) || (p.cmdline ?? []).join(' ').toLowerCase().includes(f)); }
  const off = Math.max(0, Math.floor(opts.offset ?? 0)), lim = Math.max(1, Math.min(Math.floor(opts.limit ?? 500), 100_000));
  return { platform: PLATFORM, total: procs.length, offset: off, processes: procs.slice(off, off + lim) };
}

// ---------------- process detail ----------------

export interface InspectOptions { allowExecution?: boolean; modules?: boolean; files?: boolean; sockets?: boolean; limit?: number }

async function linuxSockets(pid: number, inodes: Map<number, string>): Promise<SocketInfo[]> {
  const out: SocketInfo[] = [];
  for (const proto of ['tcp', 'tcp6', 'udp', 'udp6'] as const) {
    const t = await readText(`/proc/${pid}/net/${proto}`).catch(() => '');
    for (const s of parseProcNet(t, proto)) if (s.inode && inodes.has(s.inode)) out.push({ ...s, fd: inodes.get(s.inode) });
  }
  const u = await readText(`/proc/${pid}/net/unix`).catch(() => '');
  for (const s of parseProcNetUnix(u)) if (s.inode && inodes.has(s.inode)) out.push({ ...s, fd: inodes.get(s.inode) });
  return out;
}

/** Take a full snapshot of one process: info, loaded modules, open files and sockets, child pids. Needs allowExecution unless it is this process. */
export async function snapshotProcess(pidIn: number, opts: InspectOptions = {}): Promise<ProcessSnapshot> {
  const pid = checkPid(pidIn);
  gate(pid, opts.allowExecution, 'inspecting another process');
  const snap: ProcessSnapshot = { kind: 'revlens-process-snapshot', version: 1, platform: PLATFORM, takenAt: new Date().toISOString(), process: { pid, name: '' }, modules: [], files: [], sockets: [], warnings: [] };
  const wantM = opts.modules !== false, wantF = opts.files !== false, wantS = opts.sockets !== false;
  if (PLATFORM === 'linux') {
    let st;
    try { st = parseProcStatus(await readText(`/proc/${pid}/status`, 1 << 20)); } catch { throw new InputError(`no process with pid ${pid}`); }
    snap.process = { ...st.info, pid, name: st.info.name };
    snap.process.cmdline = parseCmdline(await readText(`/proc/${pid}/cmdline`, 1 << 20).catch(() => ''));
    snap.process.exe = await readlink(`/proc/${pid}/exe`).catch(() => { snap.warnings.push('exe link not readable (permission)'); return undefined; });
    snap.process.user = await userName(snap.process.uid);
    if (wantM) snap.modules = parseProcMaps(await readText(`/proc/${pid}/maps`).catch(() => { snap.warnings.push('maps not readable (permission)'); return ''; }), snap.process.exe);
    const inodes = new Map<number, string>();
    if (wantF || wantS) {
      try {
        const fds = (await readdir(`/proc/${pid}/fd`)).slice(0, 100_000);
        for (const fd of fds) {
          const target = await readlink(`/proc/${pid}/fd/${fd}`).catch(() => undefined);
          if (!target) continue;
          const f = classifyFdTarget(fd, target);
          if (f.socketInode) inodes.set(f.socketInode, fd);
          if (wantF) snap.files.push(f);
        }
        snap.files.sort((a, b) => Number(a.fd) - Number(b.fd));
      } catch { snap.warnings.push('fd folder not readable (permission)'); }
    }
    if (wantS) snap.sockets = await linuxSockets(pid, inodes);
    try {
      const kids = await readText(`/proc/${pid}/task/${pid}/children`, 1 << 20);
      snap.children = kids.trim().split(/\s+/).filter(Boolean).map(Number);
    } catch { /* kernel without children file */ }
  } else if (PLATFORM === 'darwin') {
    const ps = await run('ps', ['-o', 'pid=,ppid=,uid=,rss=,vsz=,pcpu=,comm=', '-p', String(pid)], { timeoutMs: 10_000 });
    const info = parsePs(ps.stdout)[0];
    if (!info) throw new InputError(`no process with pid ${pid}`);
    snap.process = info;
    const args = await run('ps', ['-o', 'args=', '-p', String(pid)], { timeoutMs: 10_000 });
    snap.process.cmdline = [args.stdout.trim().slice(0, 8000)];
    const kids = await run('pgrep', ['-P', String(pid)], { timeoutMs: 10_000 }).catch(() => undefined);
    if (kids) snap.children = kids.stdout.trim().split(/\s+/).filter(Boolean).map(Number);
    try {
      const l = await run('lsof', ['-nP', '-w', '-p', String(pid), '-F', 'pcuftnPT'], { timeoutMs: 30_000 });
      const p = parseLsofF(l.stdout)[0];
      if (p) { snap.modules = wantM ? p.modules : []; snap.files = wantF ? p.files : []; snap.sockets = wantS ? p.sockets : []; snap.process.exe = p.modules.find((m) => m.kind === 'executable')?.path ?? snap.process.exe; }
      else snap.warnings.push(`lsof returned nothing (${l.stderr.slice(0, 200)})`);
    } catch (e) { snap.warnings.push(`lsof: ${(e as Error).message}`); }
    if (wantM) {
      // vmmap lists every mapped image, including the dyld shared cache libraries lsof cannot see
      const vm = await run('vmmap', ['-w', '-noCoalesce', String(pid)], { timeoutMs: 60_000 }).catch(() => undefined);
      if (vm && vm.code === 0) {
        const seen = new Set(snap.modules.map((m) => m.path));
        for (const l of vm.stdout.split('\n', 500_000)) {
          const m = /^\S.*?\s([0-9a-f]+)-([0-9a-f]+)\s.*?\s(\/\S.*)$/i.exec(l);
          if (m && /\.(?:dylib)$|\.framework\/|\/usr\/lib\//.test(m[3]!) && !seen.has(m[3]!.trim())) { seen.add(m[3]!.trim()); snap.modules.push({ path: m[3]!.trim(), base: '0x' + m[1], kind: 'library' }); }
          if (snap.modules.length > 20_000) break;
        }
      } else snap.warnings.push('vmmap not available or not permitted; modules come from lsof only');
    }
  } else if (PLATFORM === 'win32') {
    const r = await powershell(`$ErrorActionPreference='SilentlyContinue'; $p = Get-Process -Id ${pid} -ErrorAction Stop; $c = Get-CimInstance Win32_Process -Filter "ProcessId=${pid}"; $mods = @($p.Modules | Select-Object ModuleName,FileName,@{n='BaseAddress';e={[int64]$_.BaseAddress}},ModuleMemorySize); $tcp = @(Get-NetTCPConnection -OwningProcess ${pid} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={[string]$_.State}}); $udp = @(Get-NetUDPEndpoint -OwningProcess ${pid} | Select-Object LocalAddress,LocalPort); $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=${pid}" | ForEach-Object { $_.ProcessId }); [pscustomobject]@{ Name=$p.ProcessName; Path=$p.Path; Ppid=$c.ParentProcessId; CommandLine=$c.CommandLine; Threads=$p.Threads.Count; Handles=$p.HandleCount; WorkingSet=$p.WorkingSet64; Modules=$mods; Tcp=$tcp; Udp=$udp; Children=$kids } | ConvertTo-Json -Depth 4 -Compress`, 60_000);
    if (!r.stdout.trim()) throw new InputError(`no process with pid ${pid} (${r.stderr.slice(0, 200)})`);
    const d = parseWinProcessDetail(r.stdout);
    const j = JSON.parse(r.stdout.replace(/^\uFEFF/, ''));
    snap.process = { pid, ppid: j.Ppid, name: String(j.Name ?? ''), exe: j.Path ?? undefined, cmdline: j.CommandLine ? [String(j.CommandLine)] : undefined, threads: d.threads, rssKb: j.WorkingSet ? Math.round(j.WorkingSet / 1024) : undefined };
    snap.modules = wantM ? d.modules : []; snap.sockets = wantS ? d.sockets : [];
    snap.children = Array.isArray(j.Children) ? j.Children.map(Number) : j.Children ? [Number(j.Children)] : [];
    if (wantF) snap.warnings.push('open file handles are not listed on Windows without Sysinternals handle.exe');
  } else throw new InputError(`process inspection is not supported on ${PLATFORM}`);
  const lim = Math.max(1, Math.min(opts.limit ?? 20_000, 100_000));
  snap.modules = snap.modules.slice(0, lim); snap.files = snap.files.slice(0, lim); snap.sockets = snap.sockets.slice(0, lim);
  return snap;
}

/** Compare two process snapshots, given as objects or snapshot JSON file paths. */
export async function compareProcessSnapshots(a: ProcessSnapshot | string, b: ProcessSnapshot | string, opts: { limit?: number } = {}) {
  const load = async (x: ProcessSnapshot | string): Promise<ProcessSnapshot> => {
    if (typeof x !== 'string') return x;
    const st = await stat(x);
    if (st.size > 256 * 1024 * 1024) throw new InputError('snapshot file too large');
    try { return JSON.parse(await readText(x)); } catch { throw new InputError(`${x} is not a snapshot JSON file`); }
  };
  const [sa, sb] = await Promise.all([load(a), load(b)]);
  if (sa?.kind !== 'revlens-process-snapshot' || sb?.kind !== 'revlens-process-snapshot') throw new InputError('both inputs must be process snapshots');
  return compareSnapshots(sa, sb, opts);
}

// ---------------- installed apps ----------------

async function which(cmd: string): Promise<string | undefined> {
  if (isAbsolute(cmd)) return cmd;
  for (const d of (process.env.PATH ?? '').split(delimiter).slice(0, 100)) {
    if (!d) continue;
    const p = join(d, cmd);
    try { await access(p, FS.X_OK); return p; } catch { /* next */ }
  }
  return undefined;
}

async function exists(p: string): Promise<boolean> { try { await stat(p); return true; } catch { return false; } }

/** Default folders scanned for installed apps on this platform. */
export function defaultAppDirs(platform: string = PLATFORM): string[] {
  const home = homedir();
  if (platform === 'linux') {
    const data = (process.env.XDG_DATA_DIRS || '/usr/local/share:/usr/share').split(':').filter(Boolean);
    return [...new Set([join(process.env.XDG_DATA_HOME || join(home, '.local/share'), 'applications'), ...data.map((d) => join(d, 'applications')), '/var/lib/flatpak/exports/share/applications', join(home, '.local/share/flatpak/exports/share/applications'), '/var/lib/snapd/desktop/applications'])];
  }
  if (platform === 'darwin') return ['/Applications', '/Applications/Utilities', '/System/Applications', '/System/Applications/Utilities', join(home, 'Applications')];
  return [];
}

/** Read one .desktop file, .app bundle or Info.plist into an AppRecord with runtime hints (Electron, resolved executable). */
export async function inspectApp(path: string): Promise<AppRecord & { resolvedExecutable?: string; electron?: boolean; asar?: string }> {
  const st = await stat(path);
  let app: AppRecord | undefined;
  if (st.isDirectory() && /\.app\/?$/.test(path)) {
    const bundle = path.replace(/\/$/, '');
    const plistPath = join(bundle, 'Contents', 'Info.plist');
    app = infoPlistToApp(parsePlist(new Uint8Array(await readFile(plistPath))), bundle);
    const electron = await exists(join(bundle, 'Contents', 'Frameworks', 'Electron Framework.framework'));
    const asar = join(bundle, 'Contents', 'Resources', 'app.asar');
    return { ...app, resolvedExecutable: app.executable, electron, asar: (await exists(asar)) ? asar : undefined };
  }
  const bytes = await readRegularFile(path, 16 * 1024 * 1024, `${path} is not a file or .app bundle`);
  if (/\.desktop$/.test(path)) {
    app = desktopEntryToApp(parseDesktopFile(new TextDecoder().decode(bytes)), path);
    if (!app) throw new InputError(`${path} is not an Application desktop entry`);
  } else if (/\.plist$/.test(path) || basename(path) === 'Info.plist') {
    const bundle = path.replace(/\/Contents\/Info\.plist$/, '');
    app = infoPlistToApp(parsePlist(bytes), bundle);
  } else throw new InputError('give a .desktop file, an .app bundle or an Info.plist');
  const resolved = app.executable ? await which(app.executable) : undefined;
  let real: string | undefined;
  if (resolved) real = await realpath(resolved).catch(() => resolved);
  let electron = false, asar: string | undefined;
  if (real) {
    const dir = real.replace(/[\\/][^\\/]+$/, '');
    for (const c of [join(dir, 'resources', 'app.asar'), join(dir, '..', 'Resources', 'app.asar')]) if (await exists(c)) { electron = true; asar = c; break; }
  }
  return { ...app, resolvedExecutable: real, electron, asar };
}

export interface AppListOptions { dirs?: string[]; filter?: string; includeHidden?: boolean; limit?: number; offset?: number; resolve?: boolean }

/** Discover installed applications: .desktop entries (Linux), .app bundles (macOS), uninstall registry keys (Windows). */
export async function listApps(opts: AppListOptions = {}): Promise<{ platform: string; dirs: string[]; total: number; apps: AppRecord[]; warnings: string[] }> {
  const warnings: string[] = [];
  let apps: AppRecord[] = [];
  const dirs = opts.dirs ?? defaultAppDirs();
  if (PLATFORM === 'win32' && !opts.dirs) {
    for (const key of ['HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall']) {
      try { const r = await run('reg', ['query', key, '/s'], { timeoutMs: 60_000 }); apps.push(...uninstallKeysToApps(parseRegQuery(r.stdout))); }
      catch (e) { warnings.push(`${key}: ${(e as Error).message}`); }
    }
  } else {
    for (const d of dirs) {
      let ents: string[];
      try { ents = (await readdir(d)).slice(0, 20_000); } catch { continue; }
      for (const n of ents) {
        const p = join(d, n);
        try {
          if (n.endsWith('.desktop')) { const a = opts.resolve ? await inspectApp(p) : desktopEntryToApp(parseDesktopFile(await readText(p, 1 << 20)), p); if (a) apps.push(a); }
          else if (n.endsWith('.app')) apps.push(opts.resolve ? await inspectApp(p) : infoPlistToApp(parsePlist(new Uint8Array(await readFile(join(p, 'Contents', 'Info.plist')))), p));
        } catch (e) { if (warnings.length < 200) warnings.push(`${p}: ${(e as Error).message.slice(0, 160)}`); }
      }
    }
  }
  // the same desktop id in a user folder overrides the system one
  const seen = new Set<string>();
  apps = apps.filter((a) => { const k = `${a.platform}:${a.id ?? a.source}`; if (a.platform === 'linux' && seen.has(k)) return false; seen.add(k); return true; });
  if (!opts.includeHidden) apps = apps.filter((a) => !a.hidden);
  if (opts.filter) { const f = opts.filter.toLowerCase(); apps = apps.filter((a) => `${a.name} ${a.id ?? ''} ${a.exec ?? ''} ${a.publisher ?? ''}`.toLowerCase().includes(f)); }
  apps.sort((a, b) => a.name.localeCompare(b.name));
  const off = Math.max(0, opts.offset ?? 0), lim = Math.max(1, Math.min(opts.limit ?? 500, 50_000));
  return { platform: PLATFORM, dirs, total: apps.length, apps: apps.slice(off, off + lim), warnings };
}

// ---------------- native UI tree ----------------

export interface UiTreeOptions { allowExecution?: boolean; app?: string; pid?: number; maxNodes?: number; maxDepth?: number; timeoutMs?: number; /** Linux: AT-SPI bus address; default AT_SPI_BUS_ADDRESS or org.a11y.Bus on the session bus */ busAddress?: string; /** Linux: also read states, actions, text and values of each element */ details?: boolean; /** Linux: 'dbus' (built-in D-Bus client, default) or 'gdbus' (one gdbus process per call, the older path) */ transport?: 'dbus' | 'gdbus' }
export interface UiTree { platform: string; backend: 'at-spi' | 'macos-ax' | 'uia'; app?: string; pid?: number; nodes: UiNode[]; truncated: boolean; warnings: string[] }

async function atspiTree(o: Required<Pick<UiTreeOptions, 'maxNodes' | 'maxDepth'>> & UiTreeOptions): Promise<UiTree> {
  if (o.transport === 'gdbus') return atspiTreeGdbus(o);
  let a: Atspi;
  try { a = await Atspi.open(o.busAddress); }
  catch (e) { if (e instanceof InputError && /no accessibility bus/.test(e.message)) throw e; return atspiTreeGdbus(o); }
  try {
    const r = await a.tree({ app: o.app, pid: o.pid, maxNodes: o.maxNodes, maxDepth: o.maxDepth, details: o.details });
    const tree: UiTree = { platform: PLATFORM, backend: 'at-spi', app: o.app, pid: o.pid, nodes: r.nodes, truncated: r.truncated, warnings: [] };
    if (!r.apps) tree.warnings.push('the accessibility registry lists no applications');
    return tree;
  } finally { a.close(); }
}

async function atspiTreeGdbus(o: Required<Pick<UiTreeOptions, 'maxNodes' | 'maxDepth'>> & UiTreeOptions): Promise<UiTree> {
  const tree: UiTree = { platform: PLATFORM, backend: 'at-spi', app: o.app, pid: o.pid, nodes: [], truncated: false, warnings: [] };
  let address = o.busAddress ?? process.env.AT_SPI_BUS_ADDRESS;
  if (!address) {
    const a = await run('gdbus', ['call', '--session', '--dest', 'org.a11y.Bus', '--object-path', '/org/a11y/bus', '--method', 'org.a11y.Bus.GetAddress'], { timeoutMs: 5_000 });
    if (a.code !== 0) throw new InputError(`no accessibility bus: ${a.stderr.trim().slice(0, 300)}`);
    address = String(replyValue(a.stdout));
  }
  if (!/^[a-z]+:[\w=,./%-]+$/i.test(address)) throw new InputError('bad AT-SPI bus address');
  const call = async (bus: string, path: string, method: string, ...args: string[]) => {
    const r = await run('gdbus', ['call', '--address', address, '--dest', bus, '--object-path', path, '--method', method, ...args], { timeoutMs: 3_000 });
    if (r.code !== 0) throw new Error(r.stderr.trim().slice(0, 200));
    return r.stdout;
  };
  const prop = async (bus: string, path: string, name: string) => { try { return String(replyValue(await call(bus, path, 'org.freedesktop.DBus.Properties.Get', 'org.a11y.atspi.Accessible', name))); } catch { return undefined; } };
  const apps = parseAccessibleRefs(await call('org.a11y.atspi.Registry', '/org/a11y/atspi/accessible/root', 'org.a11y.atspi.Accessible.GetChildren'));
  const queue: { bus: string; path: string; parent: number | null; depth: number }[] = [];
  for (const ap of apps) {
    const name = (await prop(ap.bus, ap.path, 'Name')) ?? '';
    if (o.app && !name.toLowerCase().includes(o.app.toLowerCase())) continue;
    if (o.pid) {
      try { const p = Number(replyValue(await call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus.GetConnectionUnixProcessID', ap.bus))); if (p !== o.pid) continue; } catch { continue; }
    }
    queue.push({ ...ap, parent: null, depth: 0 });
  }
  // breadth first, a batch of nodes at a time (each node costs three gdbus calls)
  while (queue.length && tree.nodes.length < o.maxNodes) {
    const batch = queue.splice(0, Math.min(16, o.maxNodes - tree.nodes.length));
    const results = await Promise.all(batch.map(async (cur) => {
      const [role, props, kids, ext] = await Promise.all([
        call(cur.bus, cur.path, 'org.a11y.atspi.Accessible.GetRoleName').then((x) => String(replyValue(x))).catch(() => ''),
        call(cur.bus, cur.path, 'org.freedesktop.DBus.Properties.GetAll', 'org.a11y.atspi.Accessible').then((x) => replyValue(x) as Record<string, unknown>).catch(() => ({} as Record<string, unknown>)),
        cur.depth < o.maxDepth ? call(cur.bus, cur.path, 'org.a11y.atspi.Accessible.GetChildren').then(parseAccessibleRefs).catch(() => []) : Promise.resolve([] as { bus: string; path: string }[]),
        call(cur.bus, cur.path, 'org.a11y.atspi.Component.GetExtents', '0').then((x) => replyValue(x)).catch(() => undefined),
      ]);
      return { cur, role, props: props && typeof props === 'object' ? props : {}, kids, ext };
    }));
    for (const { cur, role, props, kids, ext } of results) {
      const id = tree.nodes.length;
      const node: UiNode = { id, parent: cur.parent, depth: cur.depth, role, name: String(props.Name ?? ''), description: props.Description ? String(props.Description) : undefined, ref: `${cur.bus}${cur.path}`, childCount: kids.length };
      if (Array.isArray(ext) && ext.length === 4) node.bounds = { x: Number(ext[0]), y: Number(ext[1]), width: Number(ext[2]), height: Number(ext[3]) };
      tree.nodes.push(node);
      for (const k of kids) queue.push({ ...k, parent: id, depth: cur.depth + 1 });
    }
  }
  tree.truncated = queue.length > 0;
  if (!apps.length) tree.warnings.push('the accessibility registry lists no applications');
  return tree;
}

const JXA = `function run(argv) {
  var name = argv[0] || '', pid = Number(argv[1] || 0), maxNodes = Number(argv[2] || 300), maxDepth = Number(argv[3] || 8);
  var se = Application('System Events');
  var procs = pid ? se.processes.whose({ unixId: pid })() : name ? se.processes.whose({ name: name })() : se.processes.whose({ frontmost: true })();
  if (!procs.length) return JSON.stringify({ error: 'process not found' });
  var p = procs[0], out = [];
  function safe(f) { try { return f(); } catch (e) { return undefined; } }
  function walk(el, parent, depth) {
    if (out.length >= maxNodes) return;
    var id = out.length, pos = safe(function () { return el.position(); }), size = safe(function () { return el.size(); }), v = safe(function () { return el.value(); });
    out.push({ id: id, parent: parent, depth: depth, role: String(safe(function () { return el.role(); }) || ''), name: String(safe(function () { return el.name(); }) || ''), description: safe(function () { return el.description(); }) || undefined, value: v == null ? undefined : String(v).slice(0, 500), bounds: pos && size ? { x: pos[0], y: pos[1], width: size[0], height: size[1] } : undefined });
    if (depth >= maxDepth) return;
    var kids = safe(function () { return el.uiElements(); }) || [];
    for (var i = 0; i < kids.length && out.length < maxNodes; i++) walk(kids[i], id, depth + 1);
  }
  walk(p, null, 0);
  return JSON.stringify({ process: safe(function () { return p.name(); }), pid: safe(function () { return p.unixId(); }), nodes: out });
}`;

function uiaScript(o: { pid?: number; app?: string; maxNodes: number; maxDepth: number }): string {
  return `$ErrorActionPreference='Stop'; Add-Type -AssemblyName UIAutomationClient; Add-Type -AssemblyName UIAutomationTypes;
$max=${o.maxNodes}; $maxDepth=${o.maxDepth}; $pidF=${o.pid ?? 0}; $nameF=${psQuote(o.app ?? '')};
$walker=[System.Windows.Automation.TreeWalker]::ControlViewWalker; $out=New-Object System.Collections.ArrayList;
function Num($v){ if([double]::IsInfinity($v) -or [double]::IsNaN($v)){ return $null }; return [math]::Round($v) }
function Visit($el,$parent,$depth){ if($out.Count -ge $max){return}; $c=$el.Current; $r=$c.BoundingRectangle; $id=$out.Count;
 [void]$out.Add([pscustomobject]@{id=$id;parent=$parent;depth=$depth;role=$c.ControlType.ProgrammaticName;name=$c.Name;automationId=$c.AutomationId;className=$c.ClassName;pid=$c.ProcessId;x=(Num $r.X);y=(Num $r.Y);w=(Num $r.Width);h=(Num $r.Height)});
 if($depth -ge $maxDepth){return}; $ch=$walker.GetFirstChild($el); while($ch -ne $null -and $out.Count -lt $max){ Visit $ch $id ($depth+1); $ch=$walker.GetNextSibling($ch) } }
$top=$walker.GetFirstChild([System.Windows.Automation.AutomationElement]::RootElement);
while($top -ne $null -and $out.Count -lt $max){ $c=$top.Current; if(($pidF -eq 0 -or $c.ProcessId -eq $pidF) -and ($nameF -eq '' -or $c.Name -like ('*'+$nameF+'*'))){ Visit $top $null 0 }; $top=$walker.GetNextSibling($top) }
ConvertTo-Json -InputObject @($out) -Compress -Depth 3`;
}

/** Capture the native accessibility tree of an app (AT-SPI on Linux, System Events on macOS, UIAutomation on Windows). Needs allowExecution. */
export async function captureUiTree(opts: UiTreeOptions = {}): Promise<UiTree> {
  requireExecution(opts.allowExecution, 'reading another app\'s UI tree');
  const maxNodes = Math.max(1, Math.min(Math.floor(opts.maxNodes ?? 300), 5000));
  const maxDepth = Math.max(0, Math.min(Math.floor(opts.maxDepth ?? 8), 64));
  if (opts.pid !== undefined) checkPid(opts.pid);
  if (PLATFORM === 'linux') return atspiTree({ ...opts, maxNodes, maxDepth });
  if (PLATFORM === 'darwin') {
    const r = await run('osascript', ['-l', 'JavaScript', '-e', JXA, opts.app ?? '', String(opts.pid ?? 0), String(maxNodes), String(maxDepth)], { timeoutMs: opts.timeoutMs ?? 60_000 });
    if (r.code !== 0) throw new InputError(`osascript failed (grant Accessibility access to the terminal or app running RevLens): ${r.stderr.trim().slice(0, 300)}`);
    const j = JSON.parse(r.stdout);
    if (j.error) throw new InputError(j.error);
    return { platform: PLATFORM, backend: 'macos-ax', app: j.process, pid: j.pid, nodes: j.nodes, truncated: j.nodes.length >= maxNodes, warnings: [] };
  }
  if (PLATFORM === 'win32') {
    const r = await powershell(uiaScript({ pid: opts.pid, app: opts.app, maxNodes, maxDepth }), opts.timeoutMs ?? 60_000);
    if (r.code !== 0 || !r.stdout.trim()) throw new InputError(`UIAutomation failed: ${r.stderr.trim().slice(0, 300)}`);
    const arr: any[] = JSON.parse(r.stdout.replace(/^\uFEFF/, ''));
    const nodes: UiNode[] = arr.map((n) => ({ id: n.id, parent: n.parent ?? null, depth: n.depth, role: String(n.role ?? '').replace(/^ControlType\./, ''), name: String(n.name ?? ''), automationId: n.automationId || undefined, className: n.className || undefined, bounds: n.x !== null && n.x !== undefined ? { x: n.x, y: n.y, width: n.w, height: n.h } : undefined }));
    return { platform: PLATFORM, backend: 'uia', app: opts.app, pid: opts.pid ?? arr[0]?.pid, nodes, truncated: nodes.length >= maxNodes, warnings: [] };
  }
  throw new InputError(`UI tree capture is not supported on ${PLATFORM}`);
}

// ---------------- tools and CLI ----------------

const NODE_TOOLS: ToolDef[] = [
  {
    name: 'desktop_process_list',
    description: 'List running processes with pid, parent pid, name, executable, command line, user, threads and memory (Linux /proc, macOS ps, Windows Win32_Process). Needs allowExecution.',
    inputSchema: { allowExecution: { type: 'boolean', description: 'Must be true: reads other processes.' }, filter: { type: 'string', description: 'Only processes whose name, path or command line contains this.', optional: true }, limit: { type: 'number', description: 'Max processes (default 500).', optional: true }, offset: { type: 'number', description: 'Skip this many (paging).', optional: true } },
    run: async (i) => listProcesses(i),
  },
  {
    name: 'desktop_process_inspect',
    description: 'Inspect one process: identity, command line, loaded modules and libraries with base addresses (Linux /proc maps, macOS lsof and vmmap, Windows Get-Process modules), open files (Linux /proc fd, macOS lsof), and TCP, UDP and Unix sockets (Linux /proc net, macOS lsof, Windows Get-NetTCPConnection), plus child pids. Optionally saves the snapshot to a JSON file for later comparison. Needs allowExecution unless it is this process.',
    inputSchema: { pid: { type: 'number', description: 'Process id.' }, allowExecution: { type: 'boolean', description: 'Must be true for another process.', optional: true }, saveTo: { type: 'string', description: 'Write the snapshot JSON here.', optional: true }, modules: { type: 'boolean', description: 'Include modules (default true).', optional: true }, files: { type: 'boolean', description: 'Include open files (default true).', optional: true }, sockets: { type: 'boolean', description: 'Include sockets (default true).', optional: true }, limit: { type: 'number', description: 'Max items per list (default 20000).', optional: true } },
    run: async (i) => { const s = await snapshotProcess(i.pid, i); if (i.saveTo) await writeFile(i.saveTo, JSON.stringify(s, null, 2)); return { ...s, savedTo: i.saveTo }; },
  },
  {
    name: 'desktop_process_compare',
    description: 'Compare two process snapshots (JSON files from desktop_process_inspect saveTo): changed process fields, modules loaded or unloaded, files opened or closed, sockets opened or closed, child processes, memory and thread deltas, and a 0 to 1 similarity.',
    inputSchema: { a: { type: 'string', description: 'First snapshot file.' }, b: { type: 'string', description: 'Second snapshot file.' }, limit: { type: 'number', description: 'Max items per list.', optional: true } },
    run: async (i) => compareProcessSnapshots(String(i.a), String(i.b), i),
  },
  {
    name: 'desktop_apps_list',
    description: 'Discover installed applications: Linux .desktop entries in the XDG, Flatpak and Snap folders, macOS .app bundles in /Applications with Info.plist details, Windows uninstall registry keys (reg query). Gives name, id, version, publisher, executable, install location, packaging, categories and MIME types.',
    inputSchema: { filter: { type: 'string', description: 'Only apps whose name, id, command or publisher contains this.', optional: true }, dirs: { type: 'array', description: 'Folders to scan instead of the defaults.', optional: true }, includeHidden: { type: 'boolean', description: 'Include NoDisplay entries.', optional: true }, resolve: { type: 'boolean', description: 'Resolve executables on PATH and detect Electron apps (slower).', optional: true }, limit: { type: 'number', description: 'Max apps (default 500).', optional: true }, offset: { type: 'number', description: 'Skip this many.', optional: true } },
    run: async (i) => listApps(i),
  },
  {
    name: 'desktop_app_inspect',
    description: 'Read one installed app: a .desktop file, an .app bundle or an Info.plist. Resolves the executable on PATH and flags Electron apps with the app.asar path, ready for web_electron_audit.',
    inputSchema: { path: { type: 'string', description: '.desktop file, .app folder or Info.plist.' } },
    run: async (i) => inspectApp(String(i.path)),
  },
  {
    name: 'desktop_ui_tree',
    description: 'Capture the native accessibility tree of a running app: AT-SPI over gdbus on Linux, System Events (osascript JXA) on macOS, UIAutomation through PowerShell on Windows. Gives role, name, description, value, automation id and screen bounds per element with parent links. Needs allowExecution; macOS needs Accessibility permission.',
    inputSchema: { allowExecution: { type: 'boolean', description: 'Must be true: reads another app.' }, busAddress: { type: 'string', description: 'Linux AT-SPI bus address (default: AT_SPI_BUS_ADDRESS or the session a11y bus).', optional: true }, app: { type: 'string', description: 'App name filter (macOS: process name; default frontmost).', optional: true }, pid: { type: 'number', description: 'Process id filter.', optional: true }, maxNodes: { type: 'number', description: 'Node cap (default 300, max 5000).', optional: true }, maxDepth: { type: 'number', description: 'Depth cap (default 8).', optional: true } },
    run: async (i) => captureUiTree(i),
  },
];

/** Read a regular file of at most max bytes; the type and size checks and the read use one descriptor. */
async function readRegularFile(path: string, max: number, notFile = `${path} is not a regular file`): Promise<Uint8Array> {
  const fh = await open(path, 'r');
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new InputError(notFile);
    if (st.size > max) throw new InputError('file too large');
    return new Uint8Array(await fh.readFile());
  } finally { await fh.close(); }
}

const readerIO = (path: string, max: number) => readRegularFile(path, max);

/** All desktop tools for Node (file paths supported). */
export const TOOLS: ToolDef[] = [...BROWSER_TOOLS(readerIO), ...NODE_TOOLS];

export interface CliCommand { name: string; usage: string; summary: string; run(argv: string[]): Promise<number> }

function parseArgs(argv: string[]) {
  const pos: string[] = []; const flags: Record<string, string | boolean> = {};
  const BOOL = new Set(['json', 'allow-execution', 'hidden', 'resolve', 'no-modules', 'no-files', 'no-sockets']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) { const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined]; if (v !== undefined) flags[k] = v; else if (!BOOL.has(k) && i + 1 < argv.length && !argv[i + 1]!.startsWith('--')) flags[k] = argv[++i]!; else flags[k] = true; }
    else pos.push(a);
  }
  return { pos, flags };
}
const num = (v: unknown) => (v === undefined || v === true ? undefined : Number(v));
const str = (v: unknown) => (typeof v === 'string' ? v : undefined);

function cmd(name: string, toolName: string, usage: string, build: (p: string[], f: Record<string, string | boolean>) => Record<string, unknown>, human: (o: any) => string): CliCommand {
  const t = TOOLS.find((x) => x.name === toolName)!;
  return {
    name, usage, summary: t.description.split('. ')[0] + '.',
    async run(argv) {
      const { pos, flags } = parseArgs(argv);
      if (flags.help) { process.stdout.write(`${usage}\n\n${t.description}\n`); return 0; }
      try { const out = await t.run(build(pos, flags)); process.stdout.write((flags.json ? JSON.stringify(out, null, 2) : human(out)) + '\n'); return 0; }
      catch (e) { process.stderr.write(`${name}: ${(e as Error).message}\n`); return e instanceof InputError ? 2 : 1; }
    },
  };
}
const L = (xs: (string | undefined | false)[]) => xs.filter((x): x is string => typeof x === 'string').join('\n');
const need = (p: string[], what = 'argument') => { if (!p[0]) throw new InputError(`missing ${what}`); return p[0]; };

export const CLI_COMMANDS: CliCommand[] = [
  cmd('ps', 'desktop_process_list', 'revlens ps --allow-execution [--filter text] [--limit N] [--json]', (_p, f) => ({ allowExecution: !!f['allow-execution'], filter: str(f.filter), limit: num(f.limit), offset: num(f.offset) }), (o) => L([`${o.total} processes on ${o.platform}`, ...o.processes.map((p: ProcessInfo) => `${String(p.pid).padStart(7)} ${String(p.ppid ?? '').padStart(7)} ${(p.user ?? String(p.uid ?? '')).padEnd(10)} ${String(p.rssKb ?? '').padStart(8)}K ${p.name}  ${(p.cmdline ?? []).join(' ').slice(0, 120)}`)])),
  cmd('proc-inspect', 'desktop_process_inspect', 'revlens proc-inspect <pid> --allow-execution [--save snap.json] [--no-modules] [--no-files] [--no-sockets] [--json]', (p, f) => ({ pid: Number(need(p, 'pid')), allowExecution: !!f['allow-execution'], saveTo: str(f.save), modules: !f['no-modules'], files: !f['no-files'], sockets: !f['no-sockets'], limit: num(f.limit) }), (o) => L([`${o.process.pid} ${o.process.name} (parent ${o.process.ppid ?? '?'}) ${o.process.exe ?? ''}`, `  cmdline: ${(o.process.cmdline ?? []).join(' ').slice(0, 400)}`, `  modules: ${o.modules.length}`, ...o.modules.filter((m: ModuleInfo) => m.kind !== 'file').slice(0, 200).map((m: ModuleInfo) => `    ${m.base ?? ''} ${m.kind.padEnd(10)} ${m.path}`), `  open files: ${o.files.length}`, ...o.files.slice(0, 200).map((f: OpenFile) => `    fd ${f.fd.padEnd(5)} ${f.type.padEnd(7)} ${f.path}`), `  sockets: ${o.sockets.length}`, ...o.sockets.map((s: SocketInfo) => `    ${s.proto.padEnd(5)} ${s.proto === 'unix' ? s.path ?? s.local : `${s.local}:${s.localPort}${s.remotePort ? ` -> ${s.remote}:${s.remotePort}` : ''}`} ${s.state ?? ''}`), o.children?.length ? `  children: ${o.children.join(', ')}` : undefined, o.savedTo ? `  saved to ${o.savedTo}` : undefined, ...o.warnings.map((w: string) => `  warning: ${w}`)])),
  cmd('proc-compare', 'desktop_process_compare', 'revlens proc-compare <a.json> <b.json> [--json]', (p) => { if (!p[1]) throw new InputError('give two snapshot files'); return { a: p[0], b: p[1] }; }, (o) => L([`similarity ${o.similarity}${o.pidSame ? '' : ' (different pids)'}${o.rssDeltaKb !== undefined ? `, rss ${o.rssDeltaKb >= 0 ? '+' : ''}${o.rssDeltaKb} KB` : ''}${o.threadsDelta ? `, threads ${o.threadsDelta >= 0 ? '+' : ''}${o.threadsDelta}` : ''}`, ...o.process.map((c: any) => `  ~ ${c.field}: ${JSON.stringify(c.before)} -> ${JSON.stringify(c.after)}`), ...o.modules.added.map((x: string) => `  + module ${x}`), ...o.modules.removed.map((x: string) => `  - module ${x}`), ...o.files.added.map((x: string) => `  + ${x}`), ...o.files.removed.map((x: string) => `  - ${x}`), ...o.sockets.added.map((x: string) => `  + ${x}`), ...o.sockets.removed.map((x: string) => `  - ${x}`), ...o.children.added.map((x: number) => `  + child ${x}`)])),
  cmd('apps', 'desktop_apps_list', 'revlens apps [--filter text] [--hidden] [--resolve] [--dir path] [--json]', (_p, f) => ({ filter: str(f.filter), includeHidden: !!f.hidden, resolve: !!f.resolve, dirs: str(f.dir) ? [str(f.dir)] : undefined, limit: num(f.limit) }), (o) => L([`${o.total} apps on ${o.platform}`, ...o.apps.map((a: any) => `  ${a.name}${a.version ? ' ' + a.version : ''}  [${a.packaging ?? ''}] ${a.executable ?? ''}${a.electron ? ' (Electron)' : ''}${a.publisher ? '  ' + a.publisher : ''}`), ...o.warnings.slice(0, 20).map((w: string) => `  warning: ${w}`)])),
  cmd('app-inspect', 'desktop_app_inspect', 'revlens app-inspect <file.desktop|App.app|Info.plist> [--json]', (p) => ({ path: need(p, 'path') }), (o) => L([`${o.name}${o.version ? ' ' + o.version : ''} (${o.id ?? '?'})`, `  executable: ${o.resolvedExecutable ?? o.executable ?? '?'}`, o.exec ? `  exec: ${o.exec}` : undefined, `  packaging: ${o.packaging ?? '?'}${o.electron ? `, Electron app.asar at ${o.asar}` : ''}`, o.categories ? `  categories: ${o.categories.join(', ')}` : undefined, o.mimeTypes ? `  mime: ${o.mimeTypes.join(', ')}` : undefined, ...Object.entries(o.extra ?? {}).map(([k, v]) => `  ${k}: ${v}`)])),
  cmd('ui-tree', 'desktop_ui_tree', 'revlens ui-tree --allow-execution [--app name] [--pid N] [--max-nodes N] [--max-depth N] [--json]', (_p, f) => ({ allowExecution: !!f['allow-execution'], app: str(f.app), pid: num(f.pid), maxNodes: num(f['max-nodes']), maxDepth: num(f['max-depth']) }), (o) => L([`${o.backend} tree, ${o.nodes.length} nodes${o.truncated ? ' (truncated)' : ''}`, ...o.nodes.map((n: UiNode) => `${'  '.repeat(n.depth + 1)}${n.role}${n.name ? ` "${n.name}"` : ''}${n.automationId ? ` #${n.automationId}` : ''}${n.bounds ? ` [${n.bounds.x},${n.bounds.y} ${n.bounds.width}x${n.bounds.height}]` : ''}`), ...o.warnings.map((w: string) => `  warning: ${w}`)])),
];
