// Live Electron: launch an Electron app with remote debugging (behind allowExecution), list its
// targets (windows, webviews, workers, the main process inspector), inspect a window page passively over
// CDP, and drive a window with the scenario runner in attach mode. On Linux without a display a private
// Xvfb is started (REVLENS_XVFB, the patched Xvfb-revlens under REVLENS_DESKTOP_TOOLS, or Xvfb on PATH).
// Extra Electron arguments come from REVLENS_ELECTRON_CAPTURE_ARGV (JSON array; rea's
// REA_ELECTRON_CAPTURE_ARGV is read too). Node only. No shell, argument arrays, timeouts, output caps.
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm, mkdir, lstat, symlink, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve, delimiter } from 'node:path';
import { randomBytes } from 'node:crypto';
import { cdpTargets, type CdpTarget, type CdpVersion } from './cdp.js';
import { executionAllowed } from './inspector.js';
import { inspectCdpPage, type PageInspection, type PageInspectOptions } from './cdppage.js';
import { runScenario, type ScenarioOptions, type ScenarioCapture } from './scenario.js';
import { InputError } from './util.js';

export interface ElectronLaunchOptions {
  allowExecution?: boolean;
  /** the Electron executable (default: REVLENS_ELECTRON) */
  executable?: string;
  /** app folder, app.asar or main script; omit when the executable is a packaged app */
  app?: string;
  args?: string[];
  env?: Record<string, string>;
  /** also open the main process Node inspector (default true) */
  inspectMain?: boolean;
  /** pass --no-sandbox (default: REVLENS_BROWSER_NO_SANDBOX=1, or running as root) */
  noSandbox?: boolean;
  /** 'auto' (default: Xvfb when Linux has no DISPLAY), 'xvfb', 'inherit' */
  display?: 'auto' | 'xvfb' | 'inherit';
  /** wait for this many page targets (default 1) */
  waitForPages?: number;
  timeoutMs?: number;
  /** session lifetime before it is closed on its own (default 600000, max 3600000) */
  ttlMs?: number;
}

export interface ElectronSession {
  id: string;
  pid?: number;
  endpoint: string;
  browserWsUrl?: string;
  mainInspectorWsUrl?: string;
  display?: string;
  version: CdpVersion;
  targets: CdpTarget[];
  argv: string[];
  expiresAt: string;
  close: () => Promise<{ exitCode: number | null; signal: string | null }>;
  stderrTail: () => string;
}

const SESSIONS = new Map<string, ElectronSession>();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Extra Electron arguments from the environment (a JSON array of strings). */
export function captureArgvFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.REVLENS_ELECTRON_CAPTURE_ARGV ?? env.REA_ELECTRON_CAPTURE_ARGV;
  if (!raw) return [];
  let v: unknown;
  try { v = JSON.parse(raw); } catch { throw new InputError('REVLENS_ELECTRON_CAPTURE_ARGV must be a JSON array of strings'); }
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string') || v.length > 64) throw new InputError('REVLENS_ELECTRON_CAPTURE_ARGV must be a JSON array of at most 64 strings');
  // the debugging switches are RevLens's own
  for (const a of v as string[]) if (/^--(?:remote-debugging|inspect)/.test(a)) throw new InputError(`REVLENS_ELECTRON_CAPTURE_ARGV may not set ${a.split('=')[0]}`);
  return v as string[];
}

/** Whether to pass --no-sandbox: an explicit choice, REVLENS_BROWSER_NO_SANDBOX (or REA_BROWSER_NO_SANDBOX) = 1/true, or root. */
export function noSandboxFromEnv(explicit?: boolean, env: NodeJS.ProcessEnv = process.env): boolean {
  if (explicit !== undefined) return explicit;
  const v = String(env.REVLENS_BROWSER_NO_SANDBOX ?? env.REA_BROWSER_NO_SANDBOX ?? '').toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes') return true;
  if (v === '0' || v === 'false' || v === 'no') return false;
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

function readLineMatching(stream: NodeJS.ReadableStream, re: RegExp, timeoutMs: number, onText: (s: string) => void): Promise<RegExpExecArray> {
  return new Promise((ok, bad) => {
    let buf = '';
    const timer = setTimeout(() => { stream.off('data', on); bad(new InputError(`timed out after ${timeoutMs} ms waiting for ${re.source.slice(0, 40)}`)); }, timeoutMs);
    const on = (d: Buffer) => { const s = String(d); onText(s); if (buf.length < 1_000_000) buf += s; const m = re.exec(buf); if (m) { clearTimeout(timer); stream.off('data', on); ok(m); } };
    stream.on('data', on);
  });
}

async function startXvfb(env: NodeJS.ProcessEnv): Promise<{ display: string; proc: ChildProcess; env: NodeJS.ProcessEnv }> {
  const tools = env.REVLENS_DESKTOP_TOOLS;
  let xvfb = env.REVLENS_XVFB;
  let patched = false;
  const xenv: NodeJS.ProcessEnv = { ...env };
  if (!xvfb && tools && existsSync(join(tools, 'usr/bin/Xvfb-revlens')) && !existsSync('/usr/bin/xkbcomp')) { xvfb = join(tools, 'usr/bin/Xvfb-revlens'); patched = true; }
  if (!xvfb && tools && existsSync(join(tools, 'usr/bin/Xvfb'))) xvfb = join(tools, 'usr/bin/Xvfb');
  if (!xvfb) for (const d of String(env.PATH ?? '').split(delimiter)) if (d && existsSync(join(d, 'Xvfb'))) { xvfb = join(d, 'Xvfb'); break; }
  if (!xvfb) throw new InputError('no display and no Xvfb: set DISPLAY, install xvfb, or set REVLENS_XVFB / REVLENS_DESKTOP_TOOLS');
  if (tools) xenv.LD_LIBRARY_PATH = [join(tools, 'usr/lib/aarch64-linux-gnu'), join(tools, 'usr/lib/x86_64-linux-gnu'), env.LD_LIBRARY_PATH].filter(Boolean).join(':');
  if (patched) {
    // the patched Xvfb runs xkbcomp from /tmp/.xb
    const kb = join(dirname(xvfb), 'xkbcomp');
    await mkdir('/tmp/.xb', { recursive: true });
    try { const st = await lstat('/tmp/.xb/xkbcomp'); if (st.isSymbolicLink() && !existsSync('/tmp/.xb/xkbcomp')) await rm('/tmp/.xb/xkbcomp'); } catch { /* none */ }
    if (!existsSync('/tmp/.xb/xkbcomp')) await symlink(kb, '/tmp/.xb/xkbcomp');
  }
  await mkdir('/tmp/.X11-unix', { recursive: true, mode: 0o1777 }).catch(() => undefined);
  const proc = spawn(xvfb, ['-displayfd', '3', '-screen', '0', '1280x800x24', '-nolisten', 'tcp', '-noreset'], { env: xenv, stdio: ['ignore', 'ignore', 'pipe', 'pipe'] });
  let err = '';
  proc.stderr!.on('data', (d) => { if (err.length < 20_000) err += d; });
  const m = await readLineMatching(proc.stdio[3] as NodeJS.ReadableStream, /^(\d+)\n/, 15_000, () => undefined).catch((e) => { proc.kill('SIGKILL'); throw new InputError(`Xvfb did not start: ${(e as Error).message} ${err.slice(-300)}`); });
  return { display: `:${m[1]}`, proc, env: xenv };
}

/** Launch an Electron app with remote debugging on a free loopback port. */
export async function launchElectron(o: ElectronLaunchOptions): Promise<ElectronSession> {
  if (!executionAllowed(o.allowExecution)) throw new InputError('launching an Electron app needs allowExecution: true (or REVLENS_ALLOW_EXECUTION=1)');
  const exe = o.executable ?? process.env.REVLENS_ELECTRON;
  if (!exe) throw new InputError('give executable (the Electron binary or a packaged app) or set REVLENS_ELECTRON');
  if (!existsSync(exe)) throw new InputError(`${exe} does not exist`);
  const timeout = Math.max(2_000, Math.min(o.timeoutMs ?? 45_000, 300_000));
  const ttl = Math.max(5_000, Math.min(o.ttlMs ?? 600_000, 3_600_000));
  const userData = await mkdtemp(join(tmpdir(), 'revlens-electron-'));
  let env: NodeJS.ProcessEnv = { ...process.env, ...(o.env ?? {}), ELECTRON_ENABLE_LOGGING: '0', ELECTRON_NO_ATTACH_CONSOLE: '1' };
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.NODE_OPTIONS;
  let xvfb: ChildProcess | undefined;
  let display: string | undefined;
  const mode = o.display ?? 'auto';
  if (process.platform === 'linux' && (mode === 'xvfb' || (mode === 'auto' && !env.DISPLAY && !env.WAYLAND_DISPLAY))) {
    const x = await startXvfb(env);
    xvfb = x.proc; display = x.display;
    env = { ...env, DISPLAY: display };
    delete env.WAYLAND_DISPLAY;
  } else display = env.DISPLAY;
  const argv = [
    ...captureArgvFromEnv(env),
    '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
    ...(o.inspectMain !== false ? ['--inspect=127.0.0.1:0'] : []),
    `--user-data-dir=${userData}`,
    '--disable-gpu', '--no-first-run', '--disable-dev-shm-usage',
    ...(noSandboxFromEnv(o.noSandbox, env) ? ['--no-sandbox'] : []),
    ...(o.app ? [resolve(o.app)] : []),
    ...(o.args ?? []).map(String).slice(0, 100),
  ];
  const child = spawn(exe, argv, { env, stdio: ['ignore', 'pipe', 'pipe'], detached: false });
  let tail = '';
  const keep = (s: string) => { tail = (tail + s).slice(-20_000); };
  child.stdout!.on('data', (d) => keep(String(d)));
  let exited: { code: number | null; signal: string | null } | undefined;
  const exitP = new Promise<{ exitCode: number | null; signal: string | null }>((ok) => child.once('exit', (code, signal) => { exited = { code, signal }; ok({ exitCode: code, signal }); }));
  const cleanup = async () => {
    if (!exited) { child.kill('SIGTERM'); await Promise.race([exitP, sleep(3_000)]); if (!exited) { child.kill('SIGKILL'); await Promise.race([exitP, sleep(2_000)]); } }
    if (xvfb && xvfb.exitCode === null) xvfb.kill('SIGKILL');
    await rm(userData, { recursive: true, force: true }).catch(() => undefined);
  };
  try {
    const devtools = readLineMatching(child.stderr!, /DevTools listening on (ws:\/\/127\.0\.0\.1:(\d+)\/devtools\/browser\/[\w-]+)/, timeout, keep);
    const nodeInsp = o.inspectMain !== false ? readLineMatching(child.stderr!, /Debugger listening on (ws:\/\/127\.0\.0\.1:\d+\/[\w-]+)/, timeout, () => undefined).catch(() => undefined) : Promise.resolve(undefined);
    const m = await Promise.race([devtools, exitP.then((r) => { throw new InputError(`Electron exited (${r.exitCode ?? r.signal}) before remote debugging opened: ${tail.slice(-600)}`); })]);
    const endpoint = `http://127.0.0.1:${m[2]}`;
    const insp = await Promise.race([nodeInsp, sleep(3_000).then(() => undefined)]);
    // wait for the windows
    const want = Math.max(0, Math.min(o.waitForPages ?? 1, 20));
    let t = await cdpTargets(endpoint, { timeoutMs: 3_000 });
    const until = Date.now() + timeout;
    while (t.targets.filter((x) => x.type === 'page').length < want && Date.now() < until && !exited) { await sleep(200); t = await cdpTargets(endpoint, { timeoutMs: 3_000 }); }
    if (t.targets.filter((x) => x.type === 'page').length < want) throw new InputError(`Electron opened ${t.targets.filter((x) => x.type === 'page').length} windows, waited for ${want}`);
    const id = `electron-${randomBytes(5).toString('hex')}`;
    const timer = setTimeout(() => { s.close().catch(() => undefined); }, ttl);
    timer.unref?.();
    const s: ElectronSession = {
      id, pid: child.pid, endpoint, browserWsUrl: m[1], mainInspectorWsUrl: insp?.[1], display, version: t.version, targets: t.targets, argv,
      expiresAt: new Date(Date.now() + ttl).toISOString(),
      close: async () => { clearTimeout(timer); SESSIONS.delete(id); await cleanup(); return { exitCode: exited?.code ?? null, signal: exited?.signal ?? null }; },
      stderrTail: () => tail,
    };
    SESSIONS.set(id, s);
    return s;
  } catch (e) { await cleanup(); throw e; }
}

export function electronSession(id: string): ElectronSession {
  const s = SESSIONS.get(id);
  if (!s) throw new InputError(`no Electron session ${id}; running: ${[...SESSIONS.keys()].join(', ') || 'none'}`);
  return s;
}
export function electronSessions(): { id: string; pid?: number; endpoint: string; expiresAt: string }[] { return [...SESSIONS.values()].map((s) => ({ id: s.id, pid: s.pid, endpoint: s.endpoint, expiresAt: s.expiresAt })); }
export async function closeElectron(id?: string): Promise<string[]> { const ids = id ? [electronSession(id).id] : [...SESSIONS.keys()]; for (const i of ids) await SESSIONS.get(i)?.close(); return ids; }

export interface ElectronTargets {
  endpoint: string;
  version: CdpVersion;
  electron?: string;
  chrome?: string;
  windows: (CdpTarget & { scheme: string; local: boolean })[];
  webviews: CdpTarget[];
  workers: CdpTarget[];
  other: CdpTarget[];
  mainProcess?: { wsUrl: string; title?: string; url?: string };
}

/** Targets of a running Electron app: windows (file, app or http pages), webviews, workers and the main process inspector. */
export async function electronTargets(endpointOrSession: string, opts: { allowRemote?: boolean; mainInspector?: string } = {}): Promise<ElectronTargets> {
  const s = SESSIONS.get(endpointOrSession);
  const endpoint = s?.endpoint ?? endpointOrSession;
  const t = await cdpTargets(endpoint, { allowRemote: opts.allowRemote, timeoutMs: 5_000 });
  const ua = String(t.version.userAgent ?? '');
  const out: ElectronTargets = { endpoint: t.endpoint, version: t.version, electron: /Electron\/([\d.]+)/.exec(ua)?.[1], chrome: /Chrome\/([\d.]+)/.exec(ua)?.[1], windows: [], webviews: [], workers: [], other: [] };
  for (const x of t.targets) {
    if (x.type === 'page') { let scheme = ''; try { scheme = new URL(x.url).protocol.replace(':', ''); } catch { /* blank */ } out.windows.push({ ...x, scheme, local: scheme === 'file' || scheme === 'app' || scheme === 'devtools' || scheme === 'chrome' }); }
    else if (x.type === 'webview') out.webviews.push(x);
    else if (/worker/.test(x.type)) out.workers.push(x);
    else out.other.push(x);
  }
  const main = s?.mainInspectorWsUrl ?? opts.mainInspector;
  if (main) {
    const port = /^ws:\/\/127\.0\.0\.1:(\d+)\//.exec(main)?.[1];
    let title: string | undefined, url: string | undefined;
    if (port) { try { const n = await cdpTargets(`http://127.0.0.1:${port}`, { timeoutMs: 3_000 }); title = n.targets[0]?.title; url = n.targets[0]?.url; } catch { /* inspector busy */ } }
    out.mainProcess = { wsUrl: main, title, url };
  }
  return out;
}

/** Passive inspection of one Electron window over CDP (no navigation, no page script). */
export async function inspectElectronPage(endpointOrSession: string, opts: PageInspectOptions = {}): Promise<PageInspection & { electron?: string; packageJson?: Record<string, unknown> }> {
  const s = SESSIONS.get(endpointOrSession);
  const endpoint = s?.endpoint ?? endpointOrSession;
  const r = await inspectCdpPage(endpoint, { ...opts, preferFileUrls: true });
  const ua = String(r.target.userAgent ?? '');
  let packageJson: Record<string, unknown> | undefined;
  // a file:// window: read the app's package.json next to it (local files only)
  if (r.target.url.startsWith('file://')) {
    try {
      let dir = dirname(new URL(r.target.url).pathname);
      for (let i = 0; i < 6 && !packageJson; i++) { const p = join(dir, 'package.json'); if (existsSync(p)) { const txt = await readFile(p, 'utf8'); if (txt.length < 1_000_000) packageJson = JSON.parse(txt) as Record<string, unknown>; } dir = dirname(dir); }
    } catch { /* inside an asar or unreadable */ }
  }
  return { ...r, electron: /Electron\/([\d.]+)/.exec(ua)?.[1], packageJson: packageJson ? { name: packageJson.name, version: packageJson.version, main: packageJson.main } : undefined };
}

/** Run a scenario in an Electron window: launch (or reach a session or endpoint), connect Playwright over CDP, drive the window in attach mode. */
export async function electronScenario(spec: unknown, o: ElectronLaunchOptions & ScenarioOptions & { session?: string; endpoint?: string; windowUrl?: string; keepOpen?: boolean }): Promise<ScenarioCapture & { electron?: string; sessionId?: string; exit?: { exitCode: number | null; signal: string | null } }> {
  let pw: any;
  try { pw = await import('playwright' as string); } catch { throw new InputError('Electron scenarios need the optional "playwright" package'); }
  let session: ElectronSession | undefined;
  let endpoint = o.endpoint;
  if (o.session) { session = electronSession(o.session); endpoint = session.endpoint; }
  else if (!endpoint) session = await launchElectron(o);
  if (session) endpoint = session.endpoint;
  const browser = await pw.chromium.connectOverCDP(endpoint!, { timeout: 30_000 });
  let exit: { exitCode: number | null; signal: string | null } | undefined;
  try {
    const pages = browser.contexts().flatMap((c: any) => c.pages());
    const page = pages.find((p: any) => (o.windowUrl ? String(p.url()).includes(o.windowUrl) : !String(p.url()).startsWith('devtools:'))) ?? pages[0];
    if (!page) throw new InputError('the Electron app has no window to drive');
    const version = browser.version();
    const cap = await runScenario(spec, { ...o, allowFileUrls: true, attach: { browser, context: page.context(), page, kind: 'electron', version } });
    const ua = await page.evaluate(() => navigator.userAgent).catch(() => '');
    return Object.assign(cap, { electron: /Electron\/([\d.]+)/.exec(String(ua))?.[1], sessionId: o.keepOpen ? session?.id : undefined });
  } finally {
    await browser.close().catch(() => undefined);
    if (session && !o.session && !o.keepOpen) exit = await session.close();
    void exit;
  }
}
