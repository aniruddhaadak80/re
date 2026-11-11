// The wider ADB suite: install, uninstall, push, pull, activity start, app stop, components,
// screenshot, bounded screenrecord and bugreport, settings, getprop, dumpsys package, filtered
// logcat, port forwards, pm path, backup, input events, processes, directory listing, display.
// Node only.
//
// Safety rules:
// - adb is always run with execFile style argument arrays, never through a host shell.
// - `adb shell` joins its arguments into one command line for the device shell, so every value
//   that reaches the device shell is checked against a strict pattern AND single quoted.
// - Anything that changes the device (install, uninstall, push, start, stop, input, forward and
//   reverse changes) needs allowExecution: true.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { open, readFile, rm, stat } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { describeFailure, runTool } from '../exec.js';
import {
  isPackageName, launcherActivities, parseAmStart, parseBackupHeader, parseDumpsysPackage, parseForwardList, parseGetprop,
  parseInstallResult, parseLsLong, parseAdbPmPath, parsePs, parseResolveActivity, parseSettingsList, parseTransfer, parseWm, pngSize,
} from '../parsers/adb.js';
import { lines } from '../parsers/common.js';
import type { Detection, Unavailable } from '../types.js';
import { BridgeInputError, cacheRoot, ensureDir, int, need, requireFile } from './common.js';

// ---------------- input checks ----------------

const SERIAL_RE = /^[\w.:\-[\]%]{1,256}$/;
/** Device paths: absolute, no quotes, no control characters, no `..` segments. */
const REMOTE_PATH_RE = /^\/[\w./+@=,:~ -]{0,1023}$/;
const COMPONENT_RE = /^[A-Za-z][\w.]{0,254}\/[\w.$]{1,512}$/;
const ACTION_RE = /^[A-Za-z][\w.]{0,255}$/;
const DATA_URI_RE = /^[A-Za-z][\w+.-]{0,31}:[\w\-._~:/?#[\]@!$&()*+,;=%]{0,2048}$/;
const EXTRA_KEY_RE = /^[A-Za-z_][\w.]{0,127}$/;
const SETTINGS_KEY_RE = /^[\w.:\-]{1,256}$/;
const PROP_RE = /^[\w.:\-@]{1,256}$/;
const KEYCODE_RE = /^(KEYCODE_[A-Z0-9_]{1,64}|\d{1,4})$/;
const PORT_SPEC_RE = /^(tcp:\d{1,5}|localabstract:[\w.\-]{1,100}|localreserved:[\w.\-]{1,100}|localfilesystem:\/[\w./\-]{1,200}|jdwp:\d{1,7}|vsock:\d{1,10}:\d{1,5})$/;
const LOG_SPEC_RE = /^([\w.$-]{1,128}|\*):[VDIWEFS]$/;
const LOG_BUFFERS = new Set(['main', 'system', 'crash', 'events', 'radio', 'kernel', 'all', 'default']);
const SETTINGS_NS = new Set(['system', 'secure', 'global']);
/** Remote folders a push may write to unless allowAnyRemotePath is set. */
const PUSH_ROOTS = ['/data/local/tmp/', '/sdcard/', '/storage/emulated/'];

/** Quote one value for the device's POSIX shell. */
export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function serialArgs(serial: unknown): string[] {
  if (serial === undefined || serial === null || serial === '') return [];
  if (typeof serial !== 'string' || !SERIAL_RE.test(serial)) throw new BridgeInputError('serial has characters that are not allowed');
  return ['-s', serial];
}

/** Check a device path. Throws BridgeInputError for anything outside REMOTE_PATH_RE or with `..`. */
export function checkRemotePath(p: unknown, label = 'remotePath'): string {
  if (typeof p !== 'string' || !REMOTE_PATH_RE.test(p)) throw new BridgeInputError(`${label} must be an absolute device path made of letters, digits, spaces and . / + @ = , : ~ _ -`);
  if (p.split('/').some((seg) => seg === '..')) throw new BridgeInputError(`${label} may not contain .. segments`);
  return p;
}

function checkPackage(p: unknown): string {
  if (typeof p !== 'string' || !isPackageName(p)) throw new BridgeInputError('package must be an Android package name like com.example.app');
  return p;
}

function checkPortSpec(s: unknown, label: string): string {
  if (typeof s !== 'string' || !PORT_SPEC_RE.test(s)) throw new BridgeInputError(`${label} must look like tcp:8080, localabstract:name, jdwp:1234`);
  const port = /^tcp:(\d+)$/.exec(s);
  if (port && (Number(port[1]) < 1 || Number(port[1]) > 65535)) throw new BridgeInputError(`${label} port out of range`);
  return s;
}

function head(det: Detection) {
  return { available: true as const, tool: 'adb', toolVersion: det.version ?? null };
}

/** Device changing actions refuse to run unless allowExecution is true. */
export function requireDeviceChange(input: { allowExecution?: unknown } | undefined, what: string): string | undefined {
  if (input?.allowExecution === true) return undefined;
  return `${what} changes the connected device. Pass allowExecution: true to confirm you mean it.`;
}

function blocked(det: Detection, error: string) {
  return { ...head(det), ok: false, blocked: true, error };
}

type Ready = { det: Detection; adb: string; s: string[] };

async function ready(serial: unknown): Promise<Ready | { missing: Unavailable }> {
  const s = serialArgs(serial);
  const n = await need('adb');
  if ('missing' in n) return { missing: n.missing };
  return { det: n.det, adb: n.det.path!, s };
}

/** Run `adb [-s serial] shell <cmd...>` where each value after the program name is quoted for the device shell. */
function shell(r: Ready, prog: string[], quoted: string[], timeoutMs: number, maxOutputBytes = 16 * 1024 * 1024) {
  return runTool(r.adb, [...r.s, 'shell', ...prog, ...quoted.map(shQuote)], { timeoutMs, maxOutputBytes });
}

function tmpName(ext: string): string {
  return `/data/local/tmp/revlens-${randomBytes(6).toString('hex')}.${ext}`;
}

async function sha256Local(p: string): Promise<string> {
  return createHash('sha256').update(await readFile(p)).digest('hex');
}

function localOut(outDir: unknown, sub: string): Promise<string> {
  const d = typeof outDir === 'string' && outDir.trim() ? resolve(outDir) : join(cacheRoot(), 'adb', sub);
  return ensureDir(d);
}

function safeLocalName(remote: string, fallback: string): string {
  const b = basename(remote).replace(/[^\w.+-]/g, '_').replace(/^\.+/, '');
  return (b || fallback).slice(0, 200);
}

// ---------------- install and uninstall ----------------

/** Install one APK, or a base plus split APKs with install-multiple. Changes the device. */
export async function adbInstall(input: { path?: string; paths?: string[]; serial?: string; replace?: boolean; downgrade?: boolean; allowTest?: boolean; grantPermissions?: boolean; timeoutMs?: number; allowExecution?: boolean }) {
  const list = input.paths !== undefined ? input.paths : input.path !== undefined ? [input.path] : [];
  if (!Array.isArray(list) || list.length === 0 || list.length > 64) throw new BridgeInputError('give path, or paths with 1 to 64 APK files');
  const files = list.map((p, i) => requireFile(p, `paths[${i}]`).path);
  for (const f of files) {
    const fh = await open(f, 'r');
    const b = Buffer.alloc(4);
    try { await fh.read(b, 0, 4, 0); } finally { await fh.close(); }
    if (b.readUInt32BE(0) !== 0x504b0304) throw new BridgeInputError(`${f} is not an APK (zip) file`);
  }
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const gate = requireDeviceChange(input, 'Installing an app');
  if (gate) return blocked(r.det, gate);
  const flags = [...(input.replace ? ['-r'] : []), ...(input.downgrade ? ['-d'] : []), ...(input.allowTest ? ['-t'] : []), ...(input.grantPermissions ? ['-g'] : [])];
  const verb = files.length > 1 ? 'install-multiple' : 'install';
  const res = await runTool(r.adb, [...r.s, verb, ...flags, ...files], { timeoutMs: int(input.timeoutMs, 300_000, 5000, 3_600_000), maxOutputBytes: 1024 * 1024 });
  const parsed = parseInstallResult(`${res.stdout}\n${res.stderr}`);
  return { ...head(r.det), ...parsed, ok: parsed.ok && res.code === 0, files, ...(parsed.ok ? {} : { error: parsed.message ?? parsed.code ?? describeFailure(res) }) };
}

/** Uninstall a package (keepData keeps its data and cache). Changes the device. */
export async function adbUninstall(input: { package: string; serial?: string; keepData?: boolean; timeoutMs?: number; allowExecution?: boolean }) {
  const pkg = checkPackage(input.package);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const gate = requireDeviceChange(input, 'Uninstalling an app');
  if (gate) return blocked(r.det, gate);
  const res = await runTool(r.adb, [...r.s, 'uninstall', ...(input.keepData ? ['-k'] : []), pkg], { timeoutMs: int(input.timeoutMs, 120_000, 5000, 600_000), maxOutputBytes: 1024 * 1024 });
  const parsed = parseInstallResult(`${res.stdout}\n${res.stderr}`);
  return { ...head(r.det), ...parsed, ok: parsed.ok, package: pkg, ...(parsed.ok ? {} : { error: parsed.message ?? parsed.code ?? describeFailure(res) }) };
}

// ---------------- push and pull ----------------

/** Copy a local file to the device. Only below /data/local/tmp, /sdcard or /storage/emulated unless allowAnyRemotePath. Changes the device. */
export async function adbPush(input: { path: string; remotePath: string; serial?: string; allowAnyRemotePath?: boolean; timeoutMs?: number; allowExecution?: boolean }) {
  const { path, size } = requireFile(input.path);
  const remote = checkRemotePath(input.remotePath);
  if (!input.allowAnyRemotePath && !PUSH_ROOTS.some((p) => remote.startsWith(p))) {
    throw new BridgeInputError(`remotePath must be below ${PUSH_ROOTS.join(', ')} (or pass allowAnyRemotePath: true)`);
  }
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const gate = requireDeviceChange(input, 'Pushing a file');
  if (gate) return blocked(r.det, gate);
  const res = await runTool(r.adb, [...r.s, 'push', path, remote], { timeoutMs: int(input.timeoutMs, 600_000, 5000, 7_200_000), maxOutputBytes: 1024 * 1024 });
  const transfer = parseTransfer(`${res.stdout}\n${res.stderr}`);
  const ok = res.code === 0 && !!transfer && transfer.files > 0;
  return { ...head(r.det), ok, local: path, remote, localSize: size, ...(transfer ? { transfer } : {}), ...(ok ? {} : { error: describeFailure(res) }) };
}

/** Copy one file from the device to a local folder. Refuses to overwrite unless overwrite is true. Read only on the device. */
export async function adbPull(input: { remotePath: string; outDir?: string; serial?: string; overwrite?: boolean; maxBytes?: number; timeoutMs?: number }) {
  const remote = checkRemotePath(input.remotePath);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const maxBytes = int(input.maxBytes, 2 * 1024 * 1024 * 1024, 1, 64 * 1024 * 1024 * 1024);
  const st = await shell(r, ['stat', '-c', '%s'], [remote], 30_000, 64 * 1024);
  const remoteSize = Number(st.stdout.trim());
  if (st.code !== 0 || !Number.isFinite(remoteSize)) return { ...head(r.det), ok: false, remote, error: `cannot stat ${remote}: ${describeFailure(st)}` };
  if (remoteSize > maxBytes) return { ...head(r.det), ok: false, remote, remoteSize, error: `remote file is ${remoteSize} bytes, above maxBytes ${maxBytes}` };
  const dir = await localOut(input.outDir, 'pull');
  const local = join(dir, safeLocalName(remote, 'pulled.bin'));
  if (existsSync(local) && !input.overwrite) return { ...head(r.det), ok: false, remote, local, error: 'local file exists; pass overwrite: true to replace it' };
  const res = await runTool(r.adb, [...r.s, 'pull', remote, local], { timeoutMs: int(input.timeoutMs, 600_000, 5000, 7_200_000), maxOutputBytes: 1024 * 1024 });
  const transfer = parseTransfer(`${res.stdout}\n${res.stderr}`);
  if (res.code !== 0 || !existsSync(local)) return { ...head(r.det), ok: false, remote, error: describeFailure(res) };
  const size = statSync(local).size;
  return { ...head(r.det), ok: true, remote, local, size, remoteSize, sha256: await sha256Local(local), ...(transfer ? { transfer } : {}) };
}

// ---------------- activities and apps ----------------

export interface StartActivityInput {
  serial?: string;
  /** component like com.example/.MainActivity */
  component?: string;
  /** start the launcher activity of this package (resolved with cmd package resolve-activity) */
  package?: string;
  action?: string;
  data?: string;
  categories?: string[];
  /** string extras, key to value */
  extras?: Record<string, string>;
  /** stop the app before starting (am start -S) */
  forceStop?: boolean;
  timeoutMs?: number;
  allowExecution?: boolean;
}

/** Build the `am start` argument list. Exported for tests. Every value is checked and later quoted. */
export function amStartArgs(i: StartActivityInput & { component: string }): string[] {
  if (!COMPONENT_RE.test(i.component)) throw new BridgeInputError('component must look like com.example/.MainActivity');
  const out = ['-W', ...(i.forceStop ? ['-S'] : []), '-n', i.component];
  if (i.action !== undefined) {
    if (typeof i.action !== 'string' || !ACTION_RE.test(i.action)) throw new BridgeInputError('action must look like android.intent.action.VIEW');
    out.push('-a', i.action);
  }
  if (i.data !== undefined) {
    if (typeof i.data !== 'string' || !DATA_URI_RE.test(i.data)) throw new BridgeInputError('data must be a URI like https://example.com/x');
    out.push('-d', i.data);
  }
  for (const c of (i.categories ?? []).slice(0, 16)) {
    if (typeof c !== 'string' || !ACTION_RE.test(c)) throw new BridgeInputError('categories must look like android.intent.category.DEFAULT');
    out.push('-c', c);
  }
  const ex = i.extras ?? {};
  if (typeof ex !== 'object' || Array.isArray(ex)) throw new BridgeInputError('extras must be an object of string values');
  const entries = Object.entries(ex);
  if (entries.length > 32) throw new BridgeInputError('at most 32 extras');
  for (const [k, v] of entries) {
    if (!EXTRA_KEY_RE.test(k) || typeof v !== 'string' || v.length > 1024 || /[\0\r\n]/.test(v)) throw new BridgeInputError(`bad extra ${JSON.stringify(k)}`);
    out.push('--es', k, v);
  }
  return out;
}

/** Start an activity with `am start -W` (no host shell; each value quoted for the device shell). Changes the device. */
export async function adbStartActivity(input: StartActivityInput) {
  if ((input.component === undefined) === (input.package === undefined)) throw new BridgeInputError('give exactly one of component or package');
  if (input.package !== undefined) checkPackage(input.package);
  if (input.component !== undefined) amStartArgs({ ...input, component: input.component });
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const gate = requireDeviceChange(input, 'Starting an activity');
  if (gate) return blocked(r.det, gate);
  let component = input.component;
  if (!component) {
    const res = await shell(r, ['cmd', 'package', 'resolve-activity', '--brief', '-a', 'android.intent.action.MAIN', '-c', 'android.intent.category.LAUNCHER'], [input.package!], 30_000, 256 * 1024);
    component = parseResolveActivity(res.stdout);
    if (!component) return { ...head(r.det), ok: false, error: `no launcher activity found for ${input.package}` };
  }
  const args = amStartArgs({ ...input, component });
  const res = await shell(r, ['am', 'start'], args, int(input.timeoutMs, 60_000, 2000, 600_000), 1024 * 1024);
  const parsed = parseAmStart(`${res.stdout}\n${res.stderr}`);
  return { ...head(r.det), ...parsed, ok: parsed.ok && res.code === 0, requested: component, ...(parsed.ok ? {} : { error: parsed.error ?? describeFailure(res) }) };
}

/** Force stop an app (am force-stop). Changes the device. */
export async function adbStopApp(input: { package: string; serial?: string; timeoutMs?: number; allowExecution?: boolean }) {
  const pkg = checkPackage(input.package);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const gate = requireDeviceChange(input, 'Stopping an app');
  if (gate) return blocked(r.det, gate);
  const res = await shell(r, ['am', 'force-stop'], [pkg], int(input.timeoutMs, 30_000, 2000, 300_000), 256 * 1024);
  return { ...head(r.det), ok: res.code === 0, package: pkg, ...(res.code === 0 ? {} : { error: describeFailure(res) }) };
}

/** Full `dumpsys package <pkg>` as structured JSON. Read only. */
export async function adbDumpsysPackage(input: { package: string; serial?: string; timeoutMs?: number; includeRaw?: boolean }) {
  const pkg = checkPackage(input.package);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const res = await shell(r, ['dumpsys', 'package'], [pkg], int(input.timeoutMs, 60_000, 2000, 600_000), 32 * 1024 * 1024);
  if (res.code !== 0 && !res.stdout.trim()) return { ...head(r.det), ok: false, package: pkg, error: describeFailure(res) };
  const info = parseDumpsysPackage(res.stdout, pkg);
  if (!info.package) return { ...head(r.det), ok: false, package: pkg, error: `package ${pkg} not found on the device` };
  return { ...head(r.det), ok: true, info, launcher: launcherActivities(info), ...(input.includeRaw ? { raw: res.stdout.slice(0, 2_000_000) } : {}) };
}

/** Activities, services, receivers and providers that dumpsys lists for a package. Read only. */
export async function adbListComponents(input: { package: string; serial?: string; kind?: 'activities' | 'services' | 'receivers' | 'providers' | 'all'; timeoutMs?: number }) {
  const d = await adbDumpsysPackage({ package: input.package, serial: input.serial, timeoutMs: input.timeoutMs });
  if (!('ok' in d) || !d.ok || !('info' in d)) return d;
  const kind = input.kind ?? 'all';
  const pick = <K extends 'activities' | 'services' | 'receivers' | 'providers'>(k: K) => (kind === 'all' || kind === k ? d.info[k] : undefined);
  return {
    available: true, tool: 'adb', toolVersion: d.toolVersion, ok: true, package: d.info.package, launcher: d.launcher,
    activities: pick('activities'), services: pick('services'), receivers: pick('receivers'), providers: pick('providers'),
    note: 'dumpsys lists components that declare intent filters (and providers with authorities). Use the APK manifest for components without filters.',
  };
}

/** Resolve which activity an intent opens (cmd package resolve-activity --brief). Read only. */
export async function adbResolveActivity(input: { package?: string; action?: string; category?: string; serial?: string; timeoutMs?: number }) {
  const action = input.action ?? 'android.intent.action.MAIN';
  if (!ACTION_RE.test(action)) throw new BridgeInputError('action must look like android.intent.action.MAIN');
  const category = input.category ?? (input.package ? 'android.intent.category.LAUNCHER' : 'android.intent.category.HOME');
  if (!ACTION_RE.test(category)) throw new BridgeInputError('category must look like android.intent.category.LAUNCHER');
  const pkg = input.package !== undefined ? [checkPackage(input.package)] : [];
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const res = await shell(r, ['cmd', 'package', 'resolve-activity', '--brief'], ['-a', action, '-c', category, ...pkg], int(input.timeoutMs, 30_000, 2000, 300_000), 256 * 1024);
  const component = parseResolveActivity(res.stdout);
  return { ...head(r.det), ok: !!component, action, category, ...(component ? { component } : { error: res.stdout.trim().slice(0, 500) || describeFailure(res) }) };
}

/** APK paths of an installed package (pm path). Read only. */
export async function adbPmPath(input: { package: string; serial?: string; timeoutMs?: number }) {
  const pkg = checkPackage(input.package);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const res = await shell(r, ['pm', 'path'], [pkg], int(input.timeoutMs, 30_000, 2000, 300_000), 256 * 1024);
  const paths = parseAdbPmPath(res.stdout);
  return { ...head(r.det), ok: paths.length > 0, package: pkg, paths, ...(paths.length ? {} : { error: `package ${pkg} not found (${describeFailure(res)})` }) };
}

// ---------------- screen ----------------

/** Take a PNG screenshot into a local folder (screencap to a device temp file, pull, delete). Read only. */
export async function adbScreenshot(input: { serial?: string; outDir?: string; timeoutMs?: number }) {
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const remote = tmpName('png');
  const timeoutMs = int(input.timeoutMs, 60_000, 5000, 300_000);
  try {
    const cap = await shell(r, ['screencap', '-p'], [remote], timeoutMs, 256 * 1024);
    if (cap.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(cap) };
    const dir = await localOut(input.outDir, 'screens');
    const local = join(dir, `screenshot-${Date.now()}.png`);
    const res = await runTool(r.adb, [...r.s, 'pull', remote, local], { timeoutMs, maxOutputBytes: 256 * 1024 });
    if (res.code !== 0 || !existsSync(local)) return { ...head(r.det), ok: false, error: describeFailure(res) };
    const b = await readFile(local);
    const size = pngSize(b);
    if (!size) { await rm(local, { force: true }); return { ...head(r.det), ok: false, error: 'device did not return a PNG image' }; }
    return { ...head(r.det), ok: true, local, bytes: b.length, ...size, sha256: createHash('sha256').update(b).digest('hex') };
  } finally {
    await shell(r, ['rm', '-f'], [remote], 15_000, 64 * 1024).catch(() => undefined);
  }
}

/** Record the screen for at most 180 seconds into a local MP4 (screenrecord --time-limit, pull, delete). Read only. */
export async function adbScreenrecord(input: { serial?: string; seconds?: number; size?: string; bitRate?: number; outDir?: string }) {
  const seconds = int(input.seconds, 10, 1, 180);
  const extra: string[] = ['--time-limit', String(seconds)];
  if (input.size !== undefined) {
    if (typeof input.size !== 'string' || !/^\d{2,5}x\d{2,5}$/.test(input.size)) throw new BridgeInputError('size must look like 1280x720');
    extra.push('--size', input.size);
  }
  if (input.bitRate !== undefined) extra.push('--bit-rate', String(int(input.bitRate, 4_000_000, 100_000, 100_000_000)));
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const remote = tmpName('mp4');
  try {
    const rec = await shell(r, ['screenrecord'], [...extra, remote], (seconds + 30) * 1000, 1024 * 1024);
    if (rec.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(rec) };
    const dir = await localOut(input.outDir, 'screens');
    const local = join(dir, `screenrecord-${Date.now()}.mp4`);
    const res = await runTool(r.adb, [...r.s, 'pull', remote, local], { timeoutMs: 300_000, maxOutputBytes: 256 * 1024 });
    if (res.code !== 0 || !existsSync(local)) return { ...head(r.det), ok: false, error: describeFailure(res) };
    const st = await stat(local);
    return { ...head(r.det), ok: true, local, bytes: st.size, seconds, sha256: await sha256Local(local) };
  } finally {
    await shell(r, ['rm', '-f'], [remote], 15_000, 64 * 1024).catch(() => undefined);
  }
}

/** Display size and density (wm size, wm density). Read only. */
export async function adbDisplay(input: { serial?: string; timeoutMs?: number } = {}) {
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const t = int(input.timeoutMs, 30_000, 2000, 300_000);
  const a = await shell(r, ['wm', 'size'], [], t, 64 * 1024);
  const b = await shell(r, ['wm', 'density'], [], t, 64 * 1024);
  const parsed = parseWm(`${a.stdout}\n${b.stdout}`);
  const ok = parsed.physicalSize !== undefined || parsed.physicalDensity !== undefined;
  return { ...head(r.det), ok, ...parsed, ...(ok ? {} : { error: describeFailure(a.code !== 0 ? a : b) }) };
}

/** Send an input event: tap, swipe, text or keyevent. Changes the device. */
export async function adbInput(input: { serial?: string; kind: 'tap' | 'swipe' | 'text' | 'keyevent'; x?: number; y?: number; x2?: number; y2?: number; durationMs?: number; text?: string; keycode?: string; allowExecution?: boolean }) {
  const coord = (v: unknown, name: string) => {
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 100_000) throw new BridgeInputError(`${name} must be an integer pixel coordinate`);
    return String(v);
  };
  let args: string[];
  switch (input.kind) {
    case 'tap': args = ['tap', coord(input.x, 'x'), coord(input.y, 'y')]; break;
    case 'swipe': args = ['swipe', coord(input.x, 'x'), coord(input.y, 'y'), coord(input.x2, 'x2'), coord(input.y2, 'y2'), String(int(input.durationMs, 300, 1, 60_000))]; break;
    case 'text': {
      if (typeof input.text !== 'string' || input.text.length === 0 || input.text.length > 1000 || !/^[\x20-\x7e]+$/.test(input.text)) throw new BridgeInputError('text must be 1 to 1000 printable ASCII characters');
      // `input text` reads %s as a space; a literal space would split the argument.
      args = ['text', input.text.replace(/ /g, '%s')];
      break;
    }
    case 'keyevent':
      if (typeof input.keycode !== 'string' || !KEYCODE_RE.test(input.keycode)) throw new BridgeInputError('keycode must be KEYCODE_NAME or a number');
      args = ['keyevent', input.keycode];
      break;
    default: throw new BridgeInputError('kind must be tap, swipe, text or keyevent');
  }
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const gate = requireDeviceChange(input, 'Sending input events');
  if (gate) return blocked(r.det, gate);
  const res = await shell(r, ['input'], args, 30_000, 64 * 1024);
  return { ...head(r.det), ok: res.code === 0 && !/Error|Exception/.test(res.stderr), kind: input.kind, ...(res.code === 0 ? {} : { error: describeFailure(res) }) };
}

// ---------------- system state ----------------

/** Read device properties: one key, or all of them filtered by a prefix. Read only. */
export async function adbGetprop(input: { serial?: string; key?: string; prefix?: string; limit?: number; timeoutMs?: number } = {}) {
  if (input.key !== undefined && (typeof input.key !== 'string' || !PROP_RE.test(input.key))) throw new BridgeInputError('key must be a property name like ro.build.version.sdk');
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const t = int(input.timeoutMs, 30_000, 2000, 300_000);
  if (input.key) {
    const res = await shell(r, ['getprop'], [input.key], t, 64 * 1024);
    if (res.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(res) };
    return { ...head(r.det), ok: true, key: input.key, value: res.stdout.replace(/\r?\n$/, '') };
  }
  const res = await shell(r, ['getprop'], [], t, 8 * 1024 * 1024);
  if (res.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(res) };
  const all = parseGetprop(res.stdout);
  const prefix = typeof input.prefix === 'string' ? input.prefix.slice(0, 256) : '';
  const keys = Object.keys(all).filter((k) => k.startsWith(prefix)).sort();
  const limit = int(input.limit, 2000, 1, 20_000);
  const props: Record<string, string> = {};
  for (const k of keys.slice(0, limit)) props[k] = all[k]!;
  return { ...head(r.det), ok: true, total: keys.length, more: keys.length > limit, props, summary: deviceSummary(all) };
}

/** The handful of properties an analyst usually wants first. */
export function deviceSummary(p: Record<string, string>) {
  const pick = (k: string) => p[k] ?? null;
  return {
    model: pick('ro.product.model'), manufacturer: pick('ro.product.manufacturer'), brand: pick('ro.product.brand'),
    release: pick('ro.build.version.release'), sdk: p['ro.build.version.sdk'] ? Number(p['ro.build.version.sdk']) : null,
    abi: pick('ro.product.cpu.abi'), abiList: pick('ro.product.cpu.abilist'), fingerprint: pick('ro.build.fingerprint'),
    buildType: pick('ro.build.type'), debuggable: p['ro.debuggable'] === '1', secure: p['ro.secure'] === '1',
    securityPatch: pick('ro.build.version.security_patch'),
  };
}

/** Read one setting, or list a namespace (system, secure, global). Read only. */
export async function adbSettings(input: { namespace: string; key?: string; serial?: string; limit?: number; timeoutMs?: number }) {
  if (!SETTINGS_NS.has(input.namespace)) throw new BridgeInputError('namespace must be system, secure or global');
  if (input.key !== undefined && (typeof input.key !== 'string' || !SETTINGS_KEY_RE.test(input.key))) throw new BridgeInputError('key must be a settings name like adb_enabled');
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const t = int(input.timeoutMs, 30_000, 2000, 300_000);
  if (input.key) {
    const res = await shell(r, ['settings', 'get'], [input.namespace, input.key], t, 256 * 1024);
    if (res.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(res) };
    const v = res.stdout.replace(/\r?\n$/, '');
    return { ...head(r.det), ok: true, namespace: input.namespace, key: input.key, value: v === 'null' ? null : v };
  }
  const res = await shell(r, ['settings', 'list'], [input.namespace], t, 8 * 1024 * 1024);
  if (res.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(res) };
  const all = parseSettingsList(res.stdout);
  const keys = Object.keys(all).sort();
  const limit = int(input.limit, 2000, 1, 20_000);
  const settings: Record<string, string> = {};
  for (const k of keys.slice(0, limit)) settings[k] = all[k]!;
  return { ...head(r.det), ok: true, namespace: input.namespace, total: keys.length, more: keys.length > limit, settings };
}

/** Running processes (ps -A, falling back to ps on old devices). Read only. */
export async function adbPs(input: { serial?: string; filter?: string; limit?: number; timeoutMs?: number } = {}) {
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const t = int(input.timeoutMs, 30_000, 2000, 300_000);
  let res = await shell(r, ['ps', '-A'], [], t, 16 * 1024 * 1024);
  let procs = parsePs(res.stdout);
  if (procs.length <= 1) {
    res = await shell(r, ['ps'], [], t, 16 * 1024 * 1024);
    procs = parsePs(res.stdout);
  }
  if (procs.length === 0) return { ...head(r.det), ok: false, error: describeFailure(res) };
  const f = typeof input.filter === 'string' ? input.filter.toLowerCase().slice(0, 256) : '';
  if (f) procs = procs.filter((p) => p.name.toLowerCase().includes(f));
  const limit = int(input.limit, 2000, 1, 100_000);
  return { ...head(r.det), ok: true, total: procs.length, more: procs.length > limit, processes: procs.slice(0, limit) };
}

/** List a device folder (ls -la). Read only. */
export async function adbLs(input: { remotePath: string; serial?: string; limit?: number; timeoutMs?: number }) {
  const remote = checkRemotePath(input.remotePath);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const res = await shell(r, ['ls', '-la'], [remote], int(input.timeoutMs, 30_000, 2000, 300_000), 16 * 1024 * 1024);
  const entries = parseLsLong(res.stdout);
  if (res.code !== 0 && entries.length === 0) return { ...head(r.det), ok: false, remote, error: (res.stderr || res.stdout).trim().slice(0, 500) || describeFailure(res) };
  const limit = int(input.limit, 2000, 1, 100_000);
  return { ...head(r.det), ok: true, remote, total: entries.length, more: entries.length > limit, entries: entries.slice(0, limit) };
}

/** Recent logcat lines with filter specs (Tag:P), a pid, a buffer, a since time and a host side substring filter. Read only. */
export async function adbLogcatFiltered(input: { serial?: string; lines?: number; specs?: string[]; pid?: number; buffer?: string; since?: string; contains?: string; timeoutMs?: number } = {}) {
  const count = int(input.lines, 500, 1, 50_000);
  const args = ['logcat', '-d', '-v', 'threadtime'];
  if (input.buffer !== undefined) {
    if (!LOG_BUFFERS.has(input.buffer)) throw new BridgeInputError(`buffer must be one of ${[...LOG_BUFFERS].join(', ')}`);
    args.push('-b', input.buffer);
  }
  if (input.since !== undefined) {
    if (typeof input.since !== 'string' || !/^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}|\d{1,10}\.\d{1,3})$/.test(input.since)) throw new BridgeInputError("since must be 'MM-DD hh:mm:ss.mmm' or epoch seconds like 1700000000.000");
    args.push('-T', input.since);
  } else args.push('-t', String(count));
  if (input.pid !== undefined) {
    if (!Number.isSafeInteger(input.pid) || input.pid <= 0) throw new BridgeInputError('pid must be a positive integer');
    args.push(`--pid=${input.pid}`);
  }
  const specs = input.specs ?? [];
  if (!Array.isArray(specs) || specs.length > 32) throw new BridgeInputError('specs must be up to 32 Tag:Priority strings');
  for (const s of specs) if (typeof s !== 'string' || !LOG_SPEC_RE.test(s)) throw new BridgeInputError(`bad filter spec ${JSON.stringify(s)}: use Tag:P with P one of V D I W E F S`);
  if (specs.length) args.push(...specs, ...(specs.some((s) => s.startsWith('*:')) ? [] : ['*:S']));
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  // logcat runs host side through adb directly (no device shell), so the args are passed as is.
  const res = await runTool(r.adb, [...r.s, ...args], { timeoutMs: int(input.timeoutMs, 60_000, 2000, 600_000), maxOutputBytes: 32 * 1024 * 1024 });
  if (res.code !== 0) return { ...head(r.det), ok: false, error: describeFailure(res) };
  let ls = lines(res.stdout).filter((l) => l.trim() && !l.startsWith('--------- beginning of'));
  const needle = typeof input.contains === 'string' ? input.contains.slice(0, 512) : '';
  if (needle) ls = ls.filter((l) => l.includes(needle));
  ls = ls.slice(-count).map((l) => l.slice(0, 4000));
  return { ...head(r.det), ok: true, count: ls.length, lines: ls };
}

// ---------------- bugreport and backup ----------------

/** Collect a bugreport zip with a hard time limit (default 10 minutes, max 30). Read only. */
export async function adbBugreport(input: { serial?: string; outDir?: string; timeoutMs?: number; maxBytes?: number } = {}) {
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const dir = await localOut(input.outDir, 'bugreports');
  const local = join(dir, `bugreport-${Date.now()}.zip`);
  const res = await runTool(r.adb, [...r.s, 'bugreport', local], { timeoutMs: int(input.timeoutMs, 600_000, 30_000, 1_800_000), maxOutputBytes: 4 * 1024 * 1024 });
  if (!existsSync(local)) return { ...head(r.det), ok: false, timedOut: res.timedOut, error: describeFailure(res) };
  const size = statSync(local).size;
  const maxBytes = int(input.maxBytes, 1024 * 1024 * 1024, 1024, 16 * 1024 * 1024 * 1024);
  if (size > maxBytes) { await rm(local, { force: true }); return { ...head(r.det), ok: false, error: `bugreport is ${size} bytes, above maxBytes ${maxBytes}; deleted` }; }
  const fh = await open(local, 'r');
  const sig = Buffer.alloc(4);
  try { await fh.read(sig, 0, 4, 0); } finally { await fh.close(); }
  return { ...head(r.det), ok: sig.readUInt32BE(0) === 0x504b0304, local, bytes: size, sha256: await sha256Local(local) };
}

/** Make an adb backup (.ab) of one package. The device asks the user to confirm. Read only. */
export async function adbBackup(input: { package: string; serial?: string; includeApk?: boolean; outDir?: string; timeoutMs?: number }) {
  const pkg = checkPackage(input.package);
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  const dir = await localOut(input.outDir, 'backups');
  const local = join(dir, `${pkg}-${Date.now()}.ab`);
  const res = await runTool(r.adb, [...r.s, 'backup', '-f', local, ...(input.includeApk ? ['-apk'] : ['-noapk']), pkg], { timeoutMs: int(input.timeoutMs, 180_000, 10_000, 1_800_000), maxOutputBytes: 1024 * 1024 });
  if (!existsSync(local)) return { ...head(r.det), ok: false, package: pkg, error: describeFailure(res) };
  const b = await readFile(local);
  const header = parseBackupHeader(b);
  const ok = !!header && b.length > 24;
  return {
    ...head(r.det), ok, package: pkg, local, bytes: b.length, ...(header ? { header } : {}),
    ...(ok ? {} : { error: b.length <= 24 ? 'backup is empty: the device user did not confirm, or the app sets allowBackup=false' : 'not an Android backup file' }),
  };
}

// ---------------- port forwards ----------------

/** List, add or remove adb port forwards (host to device) or reverses (device to host). Adding and removing need allowExecution. */
export async function adbPortMap(input: { direction: 'forward' | 'reverse'; action?: 'list' | 'add' | 'remove' | 'remove-all'; local?: string; remote?: string; serial?: string; allowExecution?: boolean }) {
  const dir = input.direction;
  if (dir !== 'forward' && dir !== 'reverse') throw new BridgeInputError('direction must be forward or reverse');
  const action = input.action ?? 'list';
  let args: string[];
  if (action === 'list') args = [dir, '--list'];
  else if (action === 'add') args = [dir, '--no-rebind', checkPortSpec(input.local, 'local'), checkPortSpec(input.remote, 'remote')];
  else if (action === 'remove') args = [dir, '--remove', checkPortSpec(input.local, 'local')];
  else if (action === 'remove-all') args = [dir, '--remove-all'];
  else throw new BridgeInputError('action must be list, add, remove or remove-all');
  const r = await ready(input.serial);
  if ('missing' in r) return r.missing;
  if (action !== 'list') {
    const gate = requireDeviceChange(input, `Changing adb ${dir} rules`);
    if (gate) return blocked(r.det, gate);
  }
  const res = await runTool(r.adb, [...r.s, ...args], { timeoutMs: 30_000, maxOutputBytes: 256 * 1024 });
  if (res.code !== 0) return { ...head(r.det), ok: false, direction: dir, action, error: describeFailure(res) };
  if (action === 'list') return { ...head(r.det), ok: true, direction: dir, action, rules: parseForwardList(res.stdout) };
  return { ...head(r.det), ok: true, direction: dir, action, ...(input.local ? { local: input.local } : {}), ...(input.remote ? { remote: input.remote } : {}), output: res.stdout.trim().slice(0, 200) };
}
