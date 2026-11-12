// Build computer: an isolated desktop session an agent can drive (Linux: private Xvfb display,
// optional window manager, private D-Bus session bus and AT-SPI registry), or the current
// display after explicit consent (Linux X11 or Wayland, macOS, Windows). Every action is
// written to a hash-chained audit log. Checkpoints save a screenshot, the accessibility tree,
// the window list and process snapshots with SHA-256 digests in a manifest.
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdir, mkdtemp, writeFile, readFile, readdir, symlink, rm, lstat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { InputError } from './proc.js';
import { run } from './exec.js';
import { waitExit, release } from './children.js';
import { AuditLog, redactArgs, sha256Hex } from './audit.js';
import { XdotoolDriver, YdotoolDriver, MacDriver, WindowsDriver, toolsEnv, findProgram, type Driver, type Button } from './drivers.js';
import { parseKeyCombo } from './keys.js';
import { findNode, checkSelector, type UiSelector } from './uimodel.js';
import type { UiNode } from './gvariant.js';

export interface ComputerStartOptions {
  consent?: boolean; allowExecution?: boolean;
  /** isolated (Linux: a private Xvfb display) or attach (the display this process already sees) */
  mode?: 'isolated' | 'attach';
  /** must be true to attach to the current display: the agent will move the real pointer and type into real windows */
  attachCurrentDisplay?: boolean;
  width?: number; height?: number; depth?: number;
  /** true (default) starts the first window manager found; a name or path picks one; false starts none */
  windowManager?: boolean | string;
  /** private session bus and AT-SPI registry so desktop_ui_* tools see the apps (default true on Linux isolated) */
  accessibility?: boolean;
  /** program and arguments to start inside the session */
  launch?: string[];
  env?: Record<string, string>;
  /** where the audit log, screenshots and checkpoints go (default a new temp folder) */
  workDir?: string;
  /** close the session after this long without actions (default 30 minutes) */
  idleTimeoutMs?: number;
}

interface Owned { role: string; proc: ChildProcess; argv: string[] }
export interface ComputerSession {
  id: string; platform: string; mode: 'isolated' | 'attach'; display?: string; width?: number; height?: number;
  workDir: string; auditPath: string; startedAt: string; a11yAddress?: string; windowManager?: string;
  env: NodeJS.ProcessEnv; driver: Driver; audit: AuditLog; owned: Owned[]; checkpoints: number; shots: number; idle?: ReturnType<typeof setTimeout>; idleMs: number; closed: boolean;
}

const SESSIONS = new Map<string, ComputerSession>();
const MAX_SESSIONS = 4;

export function requireConsent(o: { consent?: boolean; allowExecution?: boolean }, what: string) {
  if (o.consent !== true) throw new InputError(`${what} controls a desktop; pass consent: true to confirm a person agreed to it`);
  if (o.allowExecution !== true && process.env.REVLENS_ALLOW_EXECUTION !== '1') throw new InputError(`${what} starts and drives programs; pass allowExecution: true`);
}

function getSession(id: unknown): ComputerSession {
  const s = SESSIONS.get(String(id));
  if (!s || s.closed) throw new InputError(`no open computer session ${String(id).slice(0, 40)}`);
  return s;
}

function touch(s: ComputerSession) {
  if (s.idle) clearTimeout(s.idle);
  s.idle = setTimeout(() => { void closeComputer(s.id, { reason: 'idle timeout' }).catch(() => undefined); }, s.idleMs);
  s.idle.unref?.();
}

function own(s: { owned: Owned[] }, role: string, cmd: string, args: string[], env: NodeJS.ProcessEnv, stdio: ('ignore' | 'pipe')[] = ['ignore', 'ignore', 'pipe']): ChildProcess {
  const p = spawn(cmd, args, { env, stdio: stdio as never, detached: process.platform !== 'win32', windowsHide: true, shell: false });
  p.on('error', () => undefined);
  const errs: string[] = [];
  p.stderr?.on('data', (d: Buffer) => { if (errs.join('').length < 8000) errs.push(String(d)); });
  (p as ChildProcess & { errText?: () => string }).errText = () => errs.join('').slice(-2000);
  s.owned.push({ role, proc: p, argv: [cmd, ...args] });
  return p;
}

function killTree(p: ChildProcess, sig: NodeJS.Signals = 'SIGTERM') {
  if (p.exitCode !== null || p.signalCode !== null || !p.pid) return;
  try { if (process.platform !== 'win32') process.kill(-p.pid, sig); else p.kill(sig); } catch { try { p.kill(sig); } catch { /* gone */ } }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function readLine(p: ChildProcess, stream: NodeJS.ReadableStream, timeoutMs: number, what: string): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => { cleanup(); reject(new InputError(`${what} did not start within ${timeoutMs} ms: ${((p as ChildProcess & { errText?: () => string }).errText?.() ?? '').slice(-400)}`)); }, timeoutMs);
    const onData = (d: Buffer) => { buf += String(d); const i = buf.indexOf('\n'); if (i >= 0) { cleanup(); resolve(buf.slice(0, i).trim()); } else if (buf.length > 4096) { cleanup(); reject(new InputError(`${what} printed too much`)); } };
    const onExit = (c: number | null) => { cleanup(); reject(new InputError(`${what} exited with ${c}: ${((p as ChildProcess & { errText?: () => string }).errText?.() ?? '').slice(-400)}`)); };
    const cleanup = () => { clearTimeout(t); stream.off('data', onData); p.off('exit', onExit); };
    stream.on('data', onData); p.on('exit', onExit);
  });
}

/** Locate Xvfb. A copy patched by scripts/fetch-desktop-tools.py (Xvfb-revlens) is used when /usr/bin/xkbcomp is missing. */
async function findXvfb(env: NodeJS.ProcessEnv): Promise<{ path: string; patched: boolean } | undefined> {
  if (env.REVLENS_XVFB) return { path: env.REVLENS_XVFB, patched: basename(env.REVLENS_XVFB).includes('revlens') };
  if (!existsSync('/usr/bin/xkbcomp')) { const p = await findProgram('Xvfb-revlens', env); if (p) return { path: p, patched: true }; }
  const p = await findProgram('Xvfb', env);
  return p ? { path: p, patched: false } : undefined;
}

async function prepareXkbcomp(xvfb: string, env: NodeJS.ProcessEnv) {
  const xkbcomp = (await findProgram('xkbcomp', env, [join(dirname(xvfb), 'xkbcomp')]));
  if (!xkbcomp) throw new InputError('xkbcomp not found next to the patched Xvfb');
  await mkdir('/tmp/.xb', { recursive: true });
  const link = '/tmp/.xb/xkbcomp';
  try { const st = await lstat(link); if (st.isSymbolicLink()) await rm(link); } catch { /* none */ }
  if (!existsSync(link)) await symlink(xkbcomp, link);
}

const WMS = ['matchbox-window-manager', 'openbox', 'xfwm4', 'metacity', 'fluxbox', 'icewm', 'twm'];

/** Start a computer session. Returns its id, display, audit log path and a first screenshot path. */
export async function startComputer(o: ComputerStartOptions = {}): Promise<Record<string, unknown>> {
  requireConsent(o, 'desktop_computer_start');
  if ([...SESSIONS.values()].filter((s) => !s.closed).length >= MAX_SESSIONS) throw new InputError(`at most ${MAX_SESSIONS} computer sessions at once; close one first`);
  const platform = process.platform;
  const mode = o.mode ?? (platform === 'linux' && !o.attachCurrentDisplay ? 'isolated' : 'attach');
  if (mode === 'attach' && o.attachCurrentDisplay !== true) throw new InputError('attaching to the current display needs attachCurrentDisplay: true (the agent will drive the real pointer and keyboard)');
  if (mode === 'isolated' && platform !== 'linux') throw new InputError(`isolated sessions need Linux and Xvfb; on ${platform} use mode: attach with attachCurrentDisplay: true, or run RevLens in a Linux VM`);
  const width = Math.max(320, Math.min(Math.floor(o.width ?? 1280), 7680)), height = Math.max(200, Math.min(Math.floor(o.height ?? 800), 4320));
  const depth = [16, 24].includes(o.depth ?? 24) ? (o.depth ?? 24) : 24;
  const id = `computer-${randomBytes(6).toString('hex')}`;
  const workDir = o.workDir ?? await mkdtemp(join(tmpdir(), 'revlens-computer-'));
  await mkdir(workDir, { recursive: true });
  const auditPath = join(workDir, 'audit.jsonl');
  const audit = new AuditLog(auditPath, id);
  const env: NodeJS.ProcessEnv = toolsEnv({ ...process.env, ...(o.env ?? {}) });
  const partial: { owned: Owned[] } = { owned: [] };
  const t0 = Date.now();
  let display: string | undefined, a11yAddress: string | undefined, wmName: string | undefined;
  let driver: Driver;
  try {
    if (mode === 'isolated') {
      const xv = await findXvfb(env);
      if (!xv) throw new InputError('Xvfb not found: install the xvfb package, or run packages/desktop/scripts/fetch-desktop-tools.py and set REVLENS_DESKTOP_TOOLS');
      if (xv.patched) await prepareXkbcomp(xv.path, env);
      await mkdir('/tmp/.X11-unix', { recursive: true, mode: 0o1777 }).catch(() => undefined);
      const x = own(partial, 'xvfb', xv.path, ['-displayfd', '3', '-screen', '0', `${width}x${height}x${depth}`, '-nolisten', 'tcp', '-noreset', '+extension', 'XTEST', '-dpi', '96'], env, ['ignore', 'ignore', 'pipe', 'pipe']);
      const num = await readLine(x, x.stdio[3] as NodeJS.ReadableStream, 15_000, 'Xvfb');
      if (!/^\d+$/.test(num)) throw new InputError(`Xvfb reported display ${num}`);
      display = `:${num}`;
      env.DISPLAY = display;
      delete env.WAYLAND_DISPLAY;
      const xdotool = await findProgram('xdotool', env);
      const xwd = await findProgram('xwd', env);
      if (!xdotool || !xwd) throw new InputError('xdotool and xwd are needed for an isolated session (packages xdotool and x11-apps)');
      driver = new XdotoolDriver(env, xdotool, xwd);
      if (o.accessibility !== false) {
        const daemon = await findProgram('dbus-daemon', env);
        const registryd = await findProgram('at-spi2-registryd', env, ['/usr/libexec/at-spi2-registryd', '/usr/lib/at-spi2-core/at-spi2-registryd', ...(env.REVLENS_DESKTOP_TOOLS ? [join(env.REVLENS_DESKTOP_TOOLS, 'usr/libexec/at-spi2-registryd')] : [])]);
        if (daemon && registryd) {
          const conf = join(workDir, 'bus.conf');
          await writeFile(conf, `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd"><busconfig><type>session</type><listen>unix:path=${join(workDir, 'bus')}</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>`);
          const bus = own(partial, 'dbus-daemon', daemon, [`--config-file=${conf}`, '--nofork', '--print-address'], env, ['ignore', 'pipe', 'pipe']);
          a11yAddress = await readLine(bus, bus.stdout!, 10_000, 'dbus-daemon');
          Object.assign(env, { DBUS_SESSION_BUS_ADDRESS: a11yAddress, AT_SPI_BUS_ADDRESS: a11yAddress, ACCESSIBILITY_ENABLED: '1', GTK_MODULES: 'gail:atk-bridge', QT_ACCESSIBILITY: '1', QT_LINUX_ACCESSIBILITY_ALWAYS_ON: '1', NO_AT_BRIDGE: '0', GNOME_ACCESSIBILITY: '1' });
          own(partial, 'at-spi2-registryd', registryd, ['--use-gnome-session'], env);
          const xprop = await findProgram('xprop', env);
          if (xprop) await run(xprop, ['-root', '-f', 'AT_SPI_BUS', '8s', '-set', 'AT_SPI_BUS', a11yAddress], { env, timeoutMs: 5000 }).catch(() => undefined);
          await sleep(300);
        }
      }
      if (o.windowManager !== false) {
        const names = typeof o.windowManager === 'string' ? [o.windowManager] : WMS;
        for (const n of names) {
          const p = await findProgram(n, env);
          if (!p) continue;
          own(partial, 'window-manager', p, basename(p) === 'matchbox-window-manager' ? ['-use_titlebar', 'no', '-use_cursor', 'yes'] : [], env);
          wmName = basename(p); break;
        }
      }
    } else {
      if (platform === 'linux') {
        if (env.DISPLAY) { const xdotool = await findProgram('xdotool', env); const xwd = await findProgram('xwd', env); if (!xdotool || !xwd) throw new InputError('attaching to an X display needs xdotool and xwd'); driver = new XdotoolDriver(env, xdotool, xwd); display = env.DISPLAY; }
        else if (env.WAYLAND_DISPLAY) { const y = await findProgram('ydotool', env); if (!y) throw new InputError('attaching to Wayland needs ydotool (with ydotoold running)'); driver = new YdotoolDriver(env, y); display = env.WAYLAND_DISPLAY; }
        else throw new InputError('no DISPLAY or WAYLAND_DISPLAY to attach to');
        a11yAddress = env.AT_SPI_BUS_ADDRESS;
      } else if (platform === 'darwin') driver = new MacDriver(await findProgram('cliclick', env));
      else if (platform === 'win32') driver = new WindowsDriver();
      else throw new InputError(`computer sessions are not supported on ${platform}`);
    }
    const s: ComputerSession = { id, platform, mode, display, width: mode === 'isolated' ? width : undefined, height: mode === 'isolated' ? height : undefined, workDir, auditPath, startedAt: new Date().toISOString(), a11yAddress, windowManager: wmName, env, driver: driver!, audit, owned: partial.owned, checkpoints: 0, shots: 0, idleMs: Math.max(10_000, Math.min(o.idleTimeoutMs ?? 30 * 60_000, 24 * 3600_000)), closed: false };
    SESSIONS.set(id, s);
    touch(s);
    const launched = o.launch?.length ? await launchIn(s, o.launch) : undefined;
    await audit.record({ action: 'start', args: { mode, display, width, height, windowManager: wmName ?? null, accessibility: !!a11yAddress, launch: o.launch ?? null, consent: true }, ok: true, ms: Date.now() - t0, result: { driver: s.driver.kind, pid: launched?.pid } });
    return { id, platform, mode, display, width: s.width, height: s.height, driver: s.driver.kind, windowManager: wmName, accessibilityBus: a11yAddress, workDir, auditLog: auditPath, launched };
  } catch (e) {
    for (const p of partial.owned.reverse()) killTree(p.proc);
    await audit.record({ action: 'start', args: { mode }, ok: false, error: (e as Error).message.slice(0, 500), ms: Date.now() - t0 }).catch(() => undefined);
    throw e;
  }
}

async function launchIn(s: ComputerSession, argv: string[]): Promise<{ pid?: number; argv: string[] }> {
  if (!Array.isArray(argv) || !argv.length || argv.length > 256 || argv.some((a) => typeof a !== 'string' || a.length > 8192)) throw new InputError('launch must be a list of strings: program then arguments');
  const prog = await findProgram(argv[0]!, s.env) ?? argv[0]!;
  const p = own(s, 'app', prog, argv.slice(1), s.env);
  await sleep(200);
  if (p.exitCode !== null) throw new InputError(`${argv[0]} exited at once with ${p.exitCode}: ${((p as ChildProcess & { errText?: () => string }).errText?.() ?? '').slice(-300)}`);
  return { pid: p.pid, argv };
}

export interface ComputerAction {
  action: 'move' | 'click' | 'double_click' | 'right_click' | 'drag' | 'type' | 'key' | 'scroll' | 'wait' | 'screenshot' | 'cursor' | 'windows' | 'launch';
  x?: number; y?: number; toX?: number; toY?: number; button?: Button; count?: number;
  text?: string; secret?: boolean; delayMs?: number; key?: string; dx?: number; dy?: number;
  ms?: number; untilWindow?: string; untilElement?: UiSelector; timeoutMs?: number;
  argv?: string[]; includeImage?: boolean;
  /** take a screenshot after the action and return its path */
  screenshotAfter?: boolean;
}

async function saveShot(s: ComputerSession, label: string): Promise<{ path: string; sha256: string; width: number; height: number; bytes: number; png: Uint8Array }> {
  const shot = await s.driver.screenshot();
  const dir = join(s.workDir, 'screenshots'); await mkdir(dir, { recursive: true });
  const path = join(dir, `${String(++s.shots).padStart(4, '0')}-${label.replace(/[^\w.-]+/g, '_').slice(0, 40)}.png`);
  await writeFile(path, shot.png);
  return { path, sha256: sha256Hex(shot.png), width: shot.width, height: shot.height, bytes: shot.png.length, png: shot.png };
}

/** Find an element by selector in the session's accessibility tree (Linux sessions with a bus). */
async function findElement(s: ComputerSession, sel: UiSelector): Promise<UiNode | undefined> {
  const { captureUiTree } = await import('./node.js');
  const t = await captureUiTree({ allowExecution: true, busAddress: s.a11yAddress, maxNodes: 3000, maxDepth: 40 });
  return findNode(t.nodes, sel);
}

/** Run one action on a session. Every call, success or failure, is written to the audit log. */
export async function actOnComputer(id: string, a: ComputerAction): Promise<Record<string, unknown>> {
  const s = getSession(id);
  touch(s);
  const t0 = Date.now();
  const args = redactArgs(a.action, { ...a, includeImage: undefined } as Record<string, unknown>);
  try {
    const result = await doAction(s, a);
    if (a.screenshotAfter && a.action !== 'screenshot') { const sh = await saveShot(s, `after-${a.action}`); result.screenshot = { path: sh.path, sha256: sh.sha256, width: sh.width, height: sh.height }; }
    const image = result.image as string | undefined; delete result.image;
    const entry = await s.audit.record({ action: a.action, args, ok: true, ms: Date.now() - t0, result });
    return { ...result, ...(image ? { image } : {}), audit: { seq: entry.seq, hash: entry.hash } };
  } catch (e) {
    await s.audit.record({ action: a.action, args, ok: false, error: (e as Error).message.slice(0, 500), ms: Date.now() - t0 });
    throw e;
  }
}

async function doAction(s: ComputerSession, a: ComputerAction): Promise<Record<string, unknown>> {
  const d = s.driver;
  const btn: Button = a.button === 'right' || a.button === 'middle' ? a.button : 'left';
  const xy = () => { if (typeof a.x !== 'number' || typeof a.y !== 'number') throw new InputError(`${a.action} needs x and y`); return { x: a.x, y: a.y }; };
  switch (a.action) {
    case 'move': { const p = xy(); await d.move(p.x, p.y); return { moved: p }; }
    case 'click': case 'double_click': case 'right_click': {
      const count = a.action === 'double_click' ? 2 : Math.max(1, Math.min(Number(a.count ?? 1), 5));
      const b = a.action === 'right_click' ? 'right' : btn;
      await d.click({ x: a.x, y: a.y, button: b, count });
      return { clicked: { x: a.x, y: a.y, button: b, count } };
    }
    case 'drag': { const p = xy(); if (typeof a.toX !== 'number' || typeof a.toY !== 'number') throw new InputError('drag needs toX and toY'); await d.drag(p, { x: a.toX, y: a.toY }, btn); return { dragged: { from: p, to: { x: a.toX, y: a.toY } } }; }
    case 'type': {
      if (typeof a.text !== 'string' || a.text.length > 100_000) throw new InputError('type needs text (at most 100000 characters)');
      await d.type(a.text, Math.max(0, Math.min(Number(a.delayMs ?? 12), 500)));
      return { typed: a.secret ? { length: a.text.length } : a.text.length > 200 ? `${a.text.slice(0, 200)}...` : a.text };
    }
    case 'key': { const c = parseKeyCombo(String(a.key ?? '')); await d.key(c); return { key: [...c.mods, c.key].join('+') }; }
    case 'scroll': { const dx = Number(a.dx ?? 0), dy = Number(a.dy ?? 0); if (!Number.isFinite(dx) || !Number.isFinite(dy) || Math.abs(dx) > 1000 || Math.abs(dy) > 1000) throw new InputError('scroll needs dx and/or dy within 1000'); await d.scroll(dx, dy, typeof a.x === 'number' && typeof a.y === 'number' ? { x: a.x, y: a.y } : undefined); return { scrolled: { dx, dy } }; }
    case 'wait': {
      const timeout = Math.max(0, Math.min(Number(a.timeoutMs ?? a.ms ?? 1000), 120_000));
      if (a.untilWindow !== undefined || a.untilElement !== undefined) {
        const sel = a.untilElement ? checkSelector(a.untilElement) : undefined;
        const end = Date.now() + timeout;
        for (;;) {
          if (a.untilWindow !== undefined) { const w = (await d.windows()).find((x) => x.title.toLowerCase().includes(String(a.untilWindow).toLowerCase())); if (w) return { waitedMs: timeout - (end - Date.now()), window: w }; }
          if (sel) { const n = await findElement(s, sel).catch(() => undefined); if (n) return { waitedMs: timeout - (end - Date.now()), element: { role: n.role, name: n.name, ref: n.ref, bounds: n.bounds } }; }
          if (Date.now() >= end) throw new InputError(`wait timed out after ${timeout} ms`);
          await sleep(250);
        }
      }
      await sleep(timeout); return { waitedMs: timeout };
    }
    case 'screenshot': {
      const sh = await saveShot(s, 'shot');
      return { path: sh.path, sha256: sh.sha256, width: sh.width, height: sh.height, bytes: sh.bytes, ...(a.includeImage ? { image: Buffer.from(sh.png).toString('base64') } : {}) };
    }
    case 'cursor': return { cursor: await d.cursor() };
    case 'windows': return { windows: await d.windows() };
    case 'launch': {
      if (s.mode !== 'isolated') throw new InputError('launch is only for isolated sessions; start the program yourself on the attached desktop');
      return { launched: await launchIn(s, a.argv ?? []) };
    }
    default: throw new InputError(`unknown action ${String((a as { action?: string }).action)}; use move, click, double_click, right_click, drag, type, key, scroll, wait, screenshot, cursor, windows or launch`);
  }
}

/** Linux: pid and every descendant (through /proc children lists). */
async function descendants(pid: number, limit = 200): Promise<number[]> {
  const out: number[] = [], queue = [pid];
  while (queue.length && out.length < limit) {
    const p = queue.shift()!; out.push(p);
    try {
      for (const t of (await readdir(`/proc/${p}/task`)).slice(0, 1000)) {
        const kids = await readFile(`/proc/${p}/task/${t}/children`, 'utf8').catch(() => '');
        for (const k of kids.trim().split(/\s+/).filter(Boolean)) queue.push(Number(k));
      }
    } catch { /* gone or not Linux */ }
  }
  return out;
}

/** Save a checkpoint: screenshot, accessibility tree, window list and process snapshots, with a manifest of SHA-256 digests. */
export async function checkpointComputer(id: string, o: { label?: string; maxNodes?: number; processes?: boolean; uiTree?: boolean } = {}): Promise<Record<string, unknown>> {
  const s = getSession(id);
  touch(s);
  const t0 = Date.now();
  const n = ++s.checkpoints;
  const label = String(o.label ?? `checkpoint-${n}`).replace(/[^\w.-]+/g, '_').slice(0, 60);
  const dir = join(s.workDir, 'checkpoints', `${String(n).padStart(3, '0')}-${label}`);
  await mkdir(dir, { recursive: true });
  const files: { name: string; sha256: string; bytes: number }[] = [];
  const warnings: string[] = [];
  const put = async (name: string, data: Uint8Array | string) => { const b = typeof data === 'string' ? Buffer.from(data) : data; await writeFile(join(dir, name), b); files.push({ name, sha256: sha256Hex(b), bytes: b.length }); };
  try {
    const shot = await s.driver.screenshot().catch((e) => { warnings.push(`screenshot: ${(e as Error).message}`); return undefined; });
    if (shot) await put('screenshot.png', shot.png);
    const windows = await s.driver.windows().catch((e) => { warnings.push(`windows: ${(e as Error).message}`); return []; });
    await put('windows.json', JSON.stringify(windows, null, 1));
    let nodes = 0;
    if (o.uiTree !== false) {
      const { captureUiTree } = await import('./node.js');
      if (s.platform === 'linux' && !s.a11yAddress) warnings.push('no accessibility bus in this session; UI tree skipped');
      else {
        try { const t = await captureUiTree({ allowExecution: true, busAddress: s.a11yAddress, maxNodes: Math.max(1, Math.min(o.maxNodes ?? 2000, 5000)), maxDepth: 40, details: true }); nodes = t.nodes.length; await put('ui-tree.json', JSON.stringify(t, null, 1)); }
        catch (e) { warnings.push(`ui tree: ${(e as Error).message}`); }
      }
    }
    let procs = 0;
    if (o.processes !== false) {
      const { snapshotProcess } = await import('./node.js');
      const roots = s.owned.filter((x) => x.role === 'app' && x.proc.exitCode === null && x.proc.pid).map((x) => x.proc.pid!);
      const pids = s.platform === 'linux' ? [...new Set((await Promise.all(roots.map((p) => descendants(p)))).flat())] : roots;
      const snaps = [];
      for (const p of pids.slice(0, 50)) { try { snaps.push(await snapshotProcess(p, { allowExecution: true, limit: 5000 })); } catch (e) { warnings.push(`process ${p}: ${(e as Error).message}`); } }
      procs = snaps.length;
      await put('processes.json', JSON.stringify(snaps, null, 1));
    }
    const manifest = { kind: 'revlens-computer-checkpoint', version: 1, session: s.id, checkpoint: n, label, takenAt: new Date().toISOString(), display: s.display, auditHead: s.audit.head, files, warnings };
    await writeFile(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 1));
    const entry = await s.audit.record({ action: 'checkpoint', args: { label }, ok: true, ms: Date.now() - t0, result: { dir, files: files.map((f) => `${f.name} ${f.sha256}`), nodes, processes: procs } });
    return { dir, manifest: join(dir, 'manifest.json'), files, uiNodes: nodes, processes: procs, windows: windows.length, warnings, audit: { seq: entry.seq, hash: entry.hash } };
  } catch (e) {
    await s.audit.record({ action: 'checkpoint', args: { label }, ok: false, error: (e as Error).message.slice(0, 500), ms: Date.now() - t0 });
    throw e;
  }
}

/** Stop everything the session started (apps, window manager, buses, Xvfb) and seal the audit log. */
export async function closeComputer(id: string, o: { reason?: string; keepFiles?: boolean } = {}): Promise<Record<string, unknown>> {
  const s = getSession(id);
  s.closed = true;
  if (s.idle) clearTimeout(s.idle);
  const stopped: { role: string; pid?: number; exit: number | string | null }[] = [];
  // Linux: note every descendant first. Programs that start their own session or process group
  // (some helpers do) are not reached by the group signal and would keep running, holding the
  // pipes this process reads, which keeps the caller's event loop alive.
  const extra = new Set<number>();
  if (process.platform === 'linux') for (const p of s.owned) if (p.proc.pid && p.proc.exitCode === null && p.proc.signalCode === null) for (const d of await descendants(p.proc.pid)) if (d !== p.proc.pid) extra.add(d);
  for (const p of [...s.owned].reverse()) {
    killTree(p.proc);
    if (!(await waitExit(p.proc, 2000))) { killTree(p.proc, 'SIGKILL'); await waitExit(p.proc, 2000); }
    stopped.push({ role: p.role, pid: p.proc.pid, exit: p.proc.exitCode ?? p.proc.signalCode ?? null });
  }
  for (const d of extra) { try { process.kill(d, 'SIGKILL'); } catch { /* already gone */ } }
  for (const p of s.owned) release(p.proc);
  const entry = await s.audit.record({ action: 'close', args: { reason: o.reason ?? 'requested' }, ok: true, result: { stopped: stopped.length } });
  SESSIONS.delete(id);
  return { id, closed: true, stopped, auditLog: s.auditPath, auditEntries: entry.seq, auditHead: entry.hash, workDir: s.workDir };
}

export function listComputers(): Record<string, unknown>[] {
  return [...SESSIONS.values()].filter((s) => !s.closed).map((s) => ({ id: s.id, platform: s.platform, mode: s.mode, display: s.display, driver: s.driver.kind, startedAt: s.startedAt, actions: s.audit.count, checkpoints: s.checkpoints, workDir: s.workDir, accessibilityBus: s.a11yAddress, processes: s.owned.map((p) => ({ role: p.role, pid: p.proc.pid, running: p.proc.exitCode === null && p.proc.signalCode === null })) }));
}

/** Internal: the session's driver, environment and bus, for the UI trace and scenario runners. */
export function sessionHandle(id: string): { driver: Driver; env: NodeJS.ProcessEnv; a11yAddress?: string; workDir: string; audit: AuditLog; appPids: number[]; platform: string } {
  const s = getSession(id);
  touch(s);
  return { driver: s.driver, env: s.env, a11yAddress: s.a11yAddress, workDir: s.workDir, audit: s.audit, appPids: s.owned.filter((x) => x.role === 'app' && x.proc.pid).map((x) => x.proc.pid!), platform: s.platform };
}

// tear sessions down when the host process exits
let hooked = false;
export function hookExit() {
  if (hooked) return; hooked = true;
  process.once('exit', () => { for (const s of SESSIONS.values()) for (const p of s.owned) killTree(p.proc, 'SIGKILL'); });
}
hookExit();
