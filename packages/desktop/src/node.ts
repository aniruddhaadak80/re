// Node entry for @revlens/desktop: live process inspection and comparison, installed app discovery and
// native UI tree capture on Linux, macOS and Windows. Import as '@revlens/desktop/node'.
import { open, readFile, readdir, readlink, stat, writeFile, realpath, access } from 'node:fs/promises';
import { constants as FS, readFileSync, statSync } from 'node:fs';
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
import { startComputer, actOnComputer, checkpointComputer, closeComputer, listComputers, type ComputerAction } from './computer.js';
import { verifyAuditLog } from './audit.js';
import { traceUi, runUiScenario } from './uiscenario.js';
import { captureProcess, compareCaptureFiles } from './capture.js';
import { appState, appExport, checkTaskFile } from './appstate.js';

export * from './index.js';
export { run, executionAllowed, psQuote } from './exec.js';
export { startComputer, actOnComputer, checkpointComputer, closeComputer, listComputers, type ComputerAction, type ComputerStartOptions } from './computer.js';
export { verifyAuditLog, canonicalJson } from './audit.js';
export { traceUi, runUiScenario, diffToEvents, type TraceOptions, type ScenarioOptions, type ScenarioStep } from './uiscenario.js';
export { captureProcess, compareCaptureFiles, type CaptureOptions } from './capture.js';
export { appState, appExport, checkTaskFile, stateCandidates, homeSource, nodeViewHelpers, type AppStateOptions } from './appstate.js';
export { Atspi, resolveA11yAddress } from './atspi.js';
export { DBusClient, parseAddress } from './dbus.js';
export { XdotoolDriver, YdotoolDriver, MacDriver, WindowsDriver, toolsEnv, findProgram } from './drivers.js';

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
    inputSchema: { allowExecution: { type: 'boolean', description: 'Must be true: reads another app.' }, busAddress: { type: 'string', description: 'Linux AT-SPI bus address (default: AT_SPI_BUS_ADDRESS or the session a11y bus).', optional: true }, app: { type: 'string', description: 'App name filter (macOS: process name; default frontmost).', optional: true }, pid: { type: 'number', description: 'Process id filter.', optional: true }, maxNodes: { type: 'number', description: 'Node cap (default 300, max 5000).', optional: true }, maxDepth: { type: 'number', description: 'Depth cap (default 8).', optional: true }, details: { type: 'boolean', description: 'Linux: also read states, actions, text and values.', optional: true }, transport: { type: 'string', description: 'Linux: dbus (built-in client, default) or gdbus.', optional: true }, saveTo: { type: 'string', description: 'Also write the tree JSON here (for desktop_ui_compare).', optional: true } },
    run: async (i) => { const t = await captureUiTree(i); if (i.saveTo) await writeFile(i.saveTo, JSON.stringify(t, null, 1)); return t; },
  },
];


const B = (d: string, optional = true) => ({ type: 'boolean' as const, description: d, optional });
const N = (d: string, optional = true) => ({ type: 'number' as const, description: d, optional });
const S = (d: string, optional = true) => ({ type: 'string' as const, description: d, optional });
const A = (d: string, optional = true) => ({ type: 'array' as const, description: d, optional });
const O = (d: string, optional = true) => ({ type: 'object' as const, description: d, optional });

const COMPUTER_TOOLS: ToolDef[] = [
  {
    name: 'desktop_computer_start',
    description: 'Start a computer an agent can drive. Linux default: an isolated private Xvfb display with a window manager and a private accessibility bus (so desktop_ui_* tools see its apps), optionally launching an app. mode attach with attachCurrentDisplay: true drives the current display instead (X11 xdotool, Wayland ydotool, macOS cliclick or CoreGraphics, Windows SendInput). Needs consent: true and allowExecution: true. Every action goes to a hash-chained audit log.',
    inputSchema: { consent: B('Must be true: a person agreed to let the agent drive a desktop.', false), allowExecution: B('Must be true: starts and drives programs.', false), mode: S('isolated (Linux, default) or attach.'), attachCurrentDisplay: B('Must be true for mode attach.'), width: N('Screen width (isolated, default 1280).'), height: N('Screen height (isolated, default 800).'), windowManager: S('true, false or a window manager name (isolated).'), accessibility: B('Start a private AT-SPI bus (isolated, default true).'), launch: A('Program and arguments to start in the session.'), env: O('Extra environment for programs in the session.'), workDir: S('Folder for the audit log, screenshots and checkpoints.'), idleTimeoutMs: N('Close after this long without actions (default 30 minutes).') },
    run: async (i) => startComputer({ ...i, windowManager: i.windowManager === 'true' ? true : i.windowManager === 'false' ? false : i.windowManager }),
  },
  {
    name: 'desktop_computer_act',
    description: 'Send one action to a computer session: move, click, double_click, right_click, drag, type (secret: true keeps the text out of the log), key (ctrl+s, Enter, cmd+q), scroll, wait (ms, untilWindow title or untilElement selector), screenshot (PNG file, includeImage for base64), cursor, windows or launch. Returns the result and the audit entry hash.',
    inputSchema: { session: S('Session id from desktop_computer_start.', false), action: S('move, click, double_click, right_click, drag, type, key, scroll, wait, screenshot, cursor, windows or launch.', false), x: N('X.'), y: N('Y.'), toX: N('Drag end x.'), toY: N('Drag end y.'), button: S('left, right or middle.'), count: N('Click count.'), text: S('Text to type.'), secret: B('Do not record the typed text.'), delayMs: N('Delay between typed keys.'), key: S('Key combo for key.'), dx: N('Scroll steps right.'), dy: N('Scroll steps down.'), ms: N('Wait time.'), untilWindow: S('Wait until a window title contains this.'), untilElement: O('Wait until an element matching this selector exists.'), timeoutMs: N('Wait limit.'), argv: A('Program and arguments for launch.'), includeImage: B('Return the screenshot as base64 too.'), screenshotAfter: B('Take a screenshot after the action.') },
    run: async (i) => { const { session, ...a } = i; return actOnComputer(String(session), a as ComputerAction); },
  },
  {
    name: 'desktop_computer_checkpoint',
    description: 'Save a checkpoint of a computer session: screenshot, accessibility tree with states and text, window list and process snapshots (modules, files, sockets) of every program the session started and their children, with a manifest of SHA-256 digests tied to the audit log head.',
    inputSchema: { session: S('Session id.', false), label: S('Checkpoint label.'), maxNodes: N('UI tree node cap (default 2000).'), processes: B('Include process snapshots (default true).'), uiTree: B('Include the UI tree (default true).') },
    run: async (i) => checkpointComputer(String(i.session), i),
  },
  {
    name: 'desktop_computer_close',
    description: 'Close a computer session: stop the programs it started, its window manager, buses and display, and seal the audit log. Returns the audit log path and head hash.',
    inputSchema: { session: S('Session id.', false), reason: S('Why it is closed.') },
    run: async (i) => closeComputer(String(i.session), i),
  },
  {
    name: 'desktop_computer_list',
    description: 'List open computer sessions with their display, driver, action and checkpoint counts and the programs they run.',
    inputSchema: {},
    run: async () => ({ sessions: listComputers() }),
  },
  {
    name: 'desktop_audit_verify',
    description: 'Verify a computer session audit log: every line parses, sequence numbers run in order and each line hash chains to the one before, so edits, removals and reordering are found. Also counts actions and failures.',
    inputSchema: { path: S('audit.jsonl path.', false) },
    run: async (i) => verifyAuditLog(String(i.path)),
  },
  {
    name: 'desktop_ui_trace',
    description: 'Watch accessibility events for a bounded time: AT-SPI signals on Linux (object state, text, property and children changes, window and focus events) through RevLens\'s own D-Bus client, UIAutomation event handlers on Windows, and tree polling on macOS (or mode poll anywhere). Can perform computer actions (during) or an accessibility action on an element while listening, and diffs the tree before and after. Filters by pid or app name. Needs allowExecution.',
    inputSchema: { allowExecution: B('Must be true.', false), session: S('Computer session id (uses its bus and lets during drive it).'), busAddress: S('Linux AT-SPI bus address.'), pid: N('Only this process.'), app: S('Only apps whose name contains this.'), durationMs: N('How long to listen (default 3000, max 120000).'), mode: S('events or poll.'), intervalMs: N('Poll interval.'), classes: A('AT-SPI event classes (default object:, window:, focus:).'), maxEvents: N('Event cap (default 2000).'), during: A('Computer actions to run while listening.'), elementAction: O('{selector, action} to run while listening.'), treeDiff: B('Diff the tree before and after (default true).'), maxNodes: N('Tree node cap.') },
    run: async (i) => traceUi(i),
  },
  {
    name: 'desktop_ui_scenario',
    description: 'Run a scripted UI scenario on a live app. Steps: find (selector), click (selector; method action, pointer or auto), type (text, into selector; EditableText or keys), key, wait (ms), waitFor (selector, gone), assert (selector with exists, count, name, states, notStates, text, textContains, value), screenshot, computer (any computer action). Selectors match role (platform spellings folded), name, nameContains, namePrefix, automationId, states and index, with no regular expressions. Each step saves the UI tree, a screenshot and the change from the step before. Needs allowExecution.',
    inputSchema: { allowExecution: B('Must be true.', false), steps: A('Scenario steps.', false), session: S('Computer session id (needed for pointer clicks, keys and screenshots).'), busAddress: S('Linux AT-SPI bus address.'), pid: N('Only this process.'), app: S('Only apps whose name contains this.'), stopOnFailure: B('Skip the rest after a failure (default true).'), outDir: S('Folder for step evidence.'), maxNodes: N('Tree node cap.'), capture: B('Save tree and screenshot per step (default true).') },
    run: async (i) => runUiScenario(i),
  },
  {
    name: 'desktop_process_capture',
    description: 'Bounded process capture: start a command (argument list, no shell) or attach to a pid, sample the process tree every intervalMs for durationMs (modules, open files, sockets, child processes, memory, threads, fd counts), record syscalls with strace on Linux when available (files, execs, network endpoints, process tree, errors per syscall), keep stdout and stderr hashes, and write one capture file for desktop_capture_compare. Needs allowExecution.',
    inputSchema: { allowExecution: B('Must be true.', false), command: A('Program and arguments to start.'), pid: N('Or a running process to watch.'), durationMs: N('Capture time (default 5000, max 600000).'), intervalMs: N('Sample interval (default 200 Linux, 1000 elsewhere).'), strace: B('Linux: record syscalls (default true when strace exists).'), straceTrace: S('strace trace classes (default %file,%network,%process).'), cwd: S('Working folder.'), env: O('Extra environment.'), stdin: S('Text for standard input.'), out: S('Capture file path.'), kill: B('Stop the command at the end (default true).'), maxItems: N('Cap per list.') },
    run: async (i) => { const r = await captureProcess(i); const c = r.capture; return { path: r.path, exit: c.exit, durationMs: c.durationMs, samples: c.samples, processes: c.processes.length, modules: c.modules.length, files: c.files.length, sockets: c.sockets.length, syscalls: c.syscalls ? { calls: c.syscalls.calls, files: c.syscalls.files.length, execs: c.syscalls.execs.slice(0, 50), network: c.syscalls.network.slice(0, 50), top: Object.entries(c.syscalls.bySyscall).sort((a, b) => b[1].calls - a[1].calls).slice(0, 20).map(([n, v]) => ({ syscall: n, ...v })) } : undefined, stdout: c.stdout, stderr: c.stderr, warnings: c.warnings }; },
  },
  {
    name: 'desktop_app_state',
    description: 'Find and list an installed app\'s state: Linux XDG config, data, state and cache folders, dotfolders, Flatpak and Snap data and dconf settings; macOS preference plists, Application Support, containers, caches and saved state; Windows AppData folders and HKCU registry keys; Electron userData with Local Storage keys read from its LevelDB log. Each file gets format, size, SHA-256, a summary and a secret flag.',
    inputSchema: { path: S('.desktop file, .app bundle or Info.plist of the app.'), name: S('App name.'), id: S('App id (desktop id, package id).'), bundleId: S('macOS bundle id.'), publisher: S('Publisher (Windows folders and registry).'), electron: B('Treat as Electron.'), paths: A('More absolute paths to include.'), home: S('Home folder to look in (default this user).'), maxFiles: N('File cap (default 5000).'), maxDepth: N('Folder depth cap (default 12).'), localStorage: B('Read Electron Local Storage (default true).') },
    run: async (i) => appState(i),
  },
  {
    name: 'desktop_app_export',
    description: 'Export an app\'s state as a zip with manifest.json (source path, size, SHA-256, format of every file, roots, Electron markers, registry and dconf). Files named like secrets (Cookies, Login Data, Local State, keys, tokens, passwords, credentials) are withheld and secret-looking keys in JSON, plist and key=value files are masked; the manifest records what was redacted.',
    inputSchema: { out: S('Zip file to write.', false), path: S('.desktop file, .app bundle or Info.plist.'), name: S('App name.'), id: S('App id.'), bundleId: S('macOS bundle id.'), publisher: S('Publisher.'), electron: B('Treat as Electron.'), paths: A('More absolute paths.'), home: S('Home folder.'), redact: B('Redact secrets (default true).'), maxBytes: N('Total size cap.') },
    run: async (i) => { const r = await appExport(i); return { ...r, manifest: undefined }; },
  },
  {
    name: 'desktop_task_check',
    description: 'Evaluate a desktop task file ({name, prompt, checks}) against a home folder: file_present, file_absent, lines_present, lines_absent, line_count, value_equals, value_absent, text_equals, text_contains, member_count, row_present, row_absent, row_count on typed views (text, JSON, key files, XML, plist, SQLite, zip, gzip) with JSON pointers and [key=value] selectors, plus ui_element checks on a saved UI tree. Returns per-check results and the answers map for desktop_task_score or x_eval_score.',
    inputSchema: { task: S('Task JSON file.', false), home: S('Home folder the file paths are under (default this user).'), uiTree: S('Saved UI tree JSON for ui_element checks.') },
    run: async (i) => checkTaskFile(i),
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
export const TOOLS: ToolDef[] = [...BROWSER_TOOLS(readerIO), ...NODE_TOOLS, ...COMPUTER_TOOLS];

export interface CliCommand { name: string; usage: string; summary: string; run(argv: string[]): Promise<number> }

function parseArgs(argv: string[]) {
  const pos: string[] = []; const flags: Record<string, string | boolean> = {};
  const BOOL = new Set(['json', 'allow-execution', 'hidden', 'resolve', 'no-modules', 'no-files', 'no-sockets', 'consent', 'attach', 'no-strace', 'no-redact', 'details', 'local-storage']);
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
  cmd('ui-compare', 'desktop_ui_compare', 'revlens ui-compare <a.json> <b.json> [--ignore bounds] [--json]', (p, f) => { if (!p[1]) throw new InputError('give two UI tree files'); return { a: p[0], b: p[1], ignore: str(f.ignore)?.split(',') }; }, (o) => L([`similarity ${o.similarity}: ${o.nodesBefore} -> ${o.nodesAfter} elements, ${o.added.length} added, ${o.removed.length} removed, ${o.changed.length} changed`, ...o.added.slice(0, 100).map((x: any) => `  + ${x.role} "${x.name}"`), ...o.removed.slice(0, 100).map((x: any) => `  - ${x.role} "${x.name}"`), ...o.changed.slice(0, 100).map((c: any) => `  ~ ${c.role} "${c.name}": ${c.changes.map((ch: any) => `${ch.field} ${JSON.stringify(ch.before)} -> ${JSON.stringify(ch.after)}`).join('; ').slice(0, 300)}`)])),
  cmd('ui-trace', 'desktop_ui_trace', 'revlens ui-trace --allow-execution [--pid N] [--app name] [--duration ms] [--mode events|poll] [--json]', (_p, f) => ({ allowExecution: !!f['allow-execution'], pid: num(f.pid), app: str(f.app), durationMs: num(f.duration), mode: str(f.mode), busAddress: str(f.bus) }), (o) => L([`${o.backend} ${o.mode}: ${o.events.length} events in ${o.durationMs} ms${o.truncated ? ' (truncated)' : ''}`, ...Object.entries(o.summary.byType).map(([k, v]) => `  ${String(v).padStart(5)} ${k}`), ...o.events.slice(0, 200).map((e: any) => `  ${String(e.t).padStart(6)}ms ${e.type} ${e.source.role ?? ''} "${e.source.name ?? ''}"${e.data !== undefined ? ' ' + JSON.stringify(e.data).slice(0, 80) : ''}`), ...o.warnings.map((w: string) => `  warning: ${w}`)])),
  cmd('ui-scenario', 'desktop_ui_scenario', 'revlens ui-scenario <steps.json> --allow-execution [--pid N] [--app name] [--out dir] [--json]', (p, f) => ({ steps: JSON.parse(readFileSyncSafe(need(p, 'steps file'))), allowExecution: !!f['allow-execution'], pid: num(f.pid), app: str(f.app), outDir: str(f.out), busAddress: str(f.bus) }), (o) => L([`${o.ok ? 'PASS' : 'FAIL'}: ${o.passed} passed, ${o.failed} failed, ${o.skipped} skipped; evidence in ${o.outDir}`, ...o.steps.map((x: any) => `  ${x.ok ? 'ok  ' : 'FAIL'} ${String(x.index + 1).padStart(3)} ${x.kind}${x.element ? ` ${x.element.role} "${x.element.name}"` : ''}${x.how ? ` (${x.how})` : ''}${x.error ? `: ${x.error}` : ''}`)])),
  {
    name: 'proc-capture', usage: 'revlens proc-capture --allow-execution [--duration ms] [--interval ms] [--no-strace] [--out file.json] [--json] (--pid N | -- program args...)', summary: 'Bounded process capture: sample a command or pid and record syscalls with strace.',
    async run(argv) {
      const dd = argv.indexOf('--');
      const { flags } = parseArgs(dd >= 0 ? argv.slice(0, dd) : argv);
      const t = TOOLS.find((x) => x.name === 'desktop_process_capture')!;
      if (flags.help) { process.stdout.write(`${this.usage}\n\n${t.description}\n`); return 0; }
      try {
        const o: any = await t.run({ allowExecution: !!flags['allow-execution'], command: dd >= 0 ? argv.slice(dd + 1) : undefined, pid: num(flags.pid), durationMs: num(flags.duration), intervalMs: num(flags.interval), strace: flags['no-strace'] ? false : undefined, out: str(flags.out) });
        process.stdout.write((flags.json ? JSON.stringify(o, null, 2) : L([`capture written to ${o.path}`, `  exit ${JSON.stringify(o.exit ?? null)}, ${o.durationMs} ms, ${o.samples} samples, ${o.processes} processes, ${o.modules} modules, ${o.files} files, ${o.sockets} sockets`, o.syscalls ? `  ${o.syscalls.calls} syscalls; top: ${o.syscalls.top.slice(0, 8).map((x: any) => `${x.syscall} ${x.calls}`).join(', ')}` : undefined, ...(o.syscalls?.execs ?? []).map((e: any) => `  exec ${e.argv.join(' ').slice(0, 200)}`), ...(o.syscalls?.network ?? []).map((n: any) => `  ${n.op} ${n.family} ${n.address}${n.port !== undefined ? ':' + n.port : ''}`), ...o.warnings.map((w: string) => `  warning: ${w}`)])) + '\n');
        return 0;
      } catch (e) { process.stderr.write(`proc-capture: ${(e as Error).message}\n`); return e instanceof InputError ? 2 : 1; }
    },
  },
  cmd('capture-compare', 'desktop_capture_compare', 'revlens capture-compare <a.json> <b.json> [--json]', (p) => { if (!p[1]) throw new InputError('give two capture files'); return { a: p[0], b: p[1] }; }, (o) => L([`similarity ${o.similarity}; exit ${JSON.stringify(o.exit.before)} -> ${JSON.stringify(o.exit.after)}`, ...['modules', 'files', 'sockets', 'processes', 'execs', 'network', 'syscallFiles'].flatMap((k) => o[k] ? [...o[k].added.slice(0, 50).map((x: string) => `  + ${k} ${x}`), ...o[k].removed.slice(0, 50).map((x: string) => `  - ${k} ${x}`)] : []), ...(o.syscalls?.changed ?? []).slice(0, 30).map((c: any) => `  ~ ${c.syscall} ${c.before} -> ${c.after}`)])),
  cmd('app-state', 'desktop_app_state', 'revlens app-state (<file.desktop|App.app> | --name N | --id ID | --bundle-id ID) [--home dir] [--json]', (p, f) => ({ path: p[0], name: str(f.name), id: str(f.id), bundleId: str(f['bundle-id']), publisher: str(f.publisher), home: str(f.home), maxFiles: num(f['max-files']) }), (o) => L([`${o.app.name ?? o.app.id ?? o.app.bundleId}: ${o.files.length} files, ${o.totalBytes} bytes${o.truncated ? ' (truncated)' : ''}`, ...o.roots.filter((r: any) => r.exists).map((r: any) => `  ${r.role}: ${r.path}`), ...o.files.slice(0, 300).map((f: any) => `    ${f.format.padEnd(9)} ${String(f.size).padStart(9)} ${f.secret ? 'secret ' : ''}${f.rel}`), ...(o.electron ?? []).flatMap((e: any) => [`  Electron userData ${e.userData} (${e.markers.join(', ')})`, ...(e.localStorage ?? []).slice(0, 50).map((x: any) => `    localStorage ${x.origin} ${x.key} = ${String(x.value ?? '').slice(0, 80)}`)]), ...(o.registry ?? []).slice(0, 50).map((r: any) => `  registry ${r.key}`), ...(o.dconf ?? []).map((d: any) => `  dconf ${d.path}`), ...o.warnings.slice(0, 20).map((w: string) => `  warning: ${w}`)])),
  cmd('app-export', 'desktop_app_export', 'revlens app-export (<file.desktop|App.app> | --name N | --id ID | --bundle-id ID) --out state.zip [--no-redact] [--home dir] [--json]', (p, f) => ({ path: p[0], name: str(f.name), id: str(f.id), bundleId: str(f['bundle-id']), publisher: str(f.publisher), home: str(f.home), out: str(f.out), redact: !f['no-redact'] }), (o) => L([`wrote ${o.out} (${o.bytes} bytes, sha256 ${o.sha256})`, `  ${o.files} files, ${o.withheld} withheld, ${o.redactedFiles} with masked values`])),
  cmd('task-check', 'desktop_task_check', 'revlens task-check <task.json> [--home dir] [--ui-tree tree.json] [--json]', (p, f) => ({ task: need(p, 'task file'), home: str(f.home), uiTree: str(f['ui-tree']) }), (o) => L([o.problems.length ? `invalid task: ${o.problems.join('; ')}` : `${o.task}: ${o.pass ? 'PASS' : 'FAIL'} (${o.passed} passed, ${o.failed} failed${o.undecided ? `, ${o.undecided} undecided` : ''})`, ...o.results.map((r: any) => `  ${r.pass ? 'pass' : 'fail'} ${r.id} ${r.kind}${r.file ? ` ${r.file}` : ''}: ${r.detail}`)])),
  cmd('audit-verify', 'desktop_audit_verify', 'revlens audit-verify <audit.jsonl> [--json]', (p) => ({ path: need(p, 'audit log') }), (o) => L([`${o.ok ? 'intact' : 'BROKEN'}: ${o.entries} entries, head ${o.head}, ${o.failures} failed actions`, ...Object.entries(o.actions).map(([k, v]) => `  ${String(v).padStart(5)} ${k}`), ...o.problems.map((p: any) => `  line ${p.line}: ${p.problem}`)])),
  {
    name: 'computer-run', usage: 'revlens computer-run <script.json> --consent --allow-execution [--json]', summary: 'Start a computer, run a list of actions, checkpoints, traces and scenario steps from a JSON script, then close it.',
    async run(argv) {
      const { pos, flags } = parseArgs(argv);
      if (flags.help || !pos[0]) { process.stdout.write(`${this.usage}\n\nScript: {"start": {start options}, "steps": [{"act": {action}}, {"checkpoint": {"label": "x"}}, {"trace": {trace options}}, {"scenario": [steps]}]}\n`); return pos[0] ? 0 : 2; }
      let id: string | undefined;
      const log: unknown[] = [];
      try {
        const script = JSON.parse(readFileSyncSafe(pos[0]));
        const st: any = await startComputer({ ...(script.start ?? {}), consent: !!flags.consent, allowExecution: !!flags['allow-execution'] });
        id = st.id; log.push({ start: st });
        for (const s of (script.steps ?? []).slice(0, 1000)) {
          if (s.act) log.push({ act: await actOnComputer(id!, s.act) });
          else if (s.checkpoint) log.push({ checkpoint: await checkpointComputer(id!, s.checkpoint) });
          else if (s.trace) log.push({ trace: await traceUi({ ...s.trace, session: id, allowExecution: true }) });
          else if (s.scenario) log.push({ scenario: await runUiScenario({ steps: s.scenario, session: id, allowExecution: true }) });
          else throw new InputError('each step needs act, checkpoint, trace or scenario');
        }
        const c = await closeComputer(id!); id = undefined; log.push({ close: c });
        process.stdout.write((flags.json ? JSON.stringify(log, null, 2) : L(log.map((x: any) => { const [k, v] = Object.entries(x)[0] as [string, any]; return `${k}: ${JSON.stringify(v).slice(0, 300)}`; }))) + '\n');
        return 0;
      } catch (e) {
        if (id) await closeComputer(id, { reason: 'script failed' }).catch(() => undefined);
        process.stderr.write(`computer-run: ${(e as Error).message}\n`); return e instanceof InputError ? 2 : 1;
      }
    },
  },
];

function readFileSyncSafe(p: string): string {
  const st = statSync(p);
  if (!st.isFile() || st.size > 16 * 1024 * 1024) throw new InputError(`${p} is not a JSON file under 16 MiB`);
  return readFileSync(p, 'utf8');
}
