// Parsers for adb output: `adb devices -l`, `pm list packages -f`, `pm path`.
import { lines, PARSE_LIMITS } from './common.js';

export interface AdbDevice {
  serial: string;
  state: string;
  product?: string;
  model?: string;
  device?: string;
  transportId?: string;
  usb?: string;
}

export interface AdbPackage {
  name: string;
  apkPath?: string;
}

/** Parse `adb devices -l` (also accepts plain `adb devices`). */
export function parseAdbDevices(text: string): AdbDevice[] {
  const out: AdbDevice[] = [];
  for (const raw of lines(text, 10_000)) {
    const l = raw.trim();
    if (!l || l.startsWith('List of devices') || l.startsWith('*') || l.startsWith('adb server')) continue;
    const parts = l.split(/\s+/);
    if (parts.length < 2) continue;
    const [serial, state, ...rest] = parts as [string, string, ...string[]];
    if (!/^[\w.:\-[\]%/]{1,256}$/.test(serial)) continue;
    if (!/^(device|offline|unauthorized|recovery|sideload|bootloader|authorizing|no|host|rescue|connecting)$/.test(state)) continue;
    const d: AdbDevice = { serial, state: state === 'no' ? 'no permissions' : state };
    for (const kv of rest) {
      const i = kv.indexOf(':');
      if (i <= 0) continue;
      const k = kv.slice(0, i);
      const v = kv.slice(i + 1).slice(0, 256);
      if (k === 'product') d.product = v;
      else if (k === 'model') d.model = v;
      else if (k === 'device') d.device = v;
      else if (k === 'transport_id') d.transportId = v;
      else if (k === 'usb') d.usb = v;
    }
    out.push(d);
  }
  return out;
}

/** Parse `pm list packages` with or without -f. With -f the APK path is everything up to the last `=`. */
export function parseAdbPackages(text: string): AdbPackage[] {
  const out: AdbPackage[] = [];
  for (const raw of lines(text)) {
    if (out.length >= PARSE_LIMITS.maxItems) break;
    const l = raw.trim();
    if (!l.startsWith('package:')) continue;
    const body = l.slice('package:'.length);
    const eq = body.lastIndexOf('=');
    if (eq > 0 && body.startsWith('/')) {
      const name = body.slice(eq + 1);
      if (isListedPackage(name)) out.push({ name, apkPath: body.slice(0, eq) });
    } else if (isListedPackage(body)) {
      out.push({ name: body });
    }
  }
  return out;
}

/** Parse `pm path <package>`: one `package:/path/x.apk` per split APK. */
export function parseAdbPmPath(text: string): string[] {
  const out: string[] = [];
  for (const raw of lines(text, 10_000)) {
    const l = raw.trim();
    if (l.startsWith('package:/') && l.endsWith('.apk') && !l.includes('..')) out.push(l.slice('package:'.length));
  }
  return out.slice(0, 256);
}

/** Names pm prints, including the framework package `android` that has no dot. */
function isListedPackage(s: string): boolean {
  return s.length > 0 && s.length <= 255 && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/.test(s);
}

/** Android package names: letters, digits, underscores and dots. */
export function isPackageName(s: string): boolean {
  return s.length > 0 && s.length <= 255 && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(s);
}

// ---------------------------------------------------------------------------------------------
// Parsers for the wider ADB suite. Every parser is pure, line capped and never throws.
// Checked against real device captures recorded in samples/bridges/recorded/adb (see SOURCES.md).

/** Parse `getprop` with no arguments: `[key]: [value]` lines. Values may span lines. */
export function parseGetprop(text: string): Record<string, string> {
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  let count = 0;
  let pendingKey: string | undefined;
  let pendingVal = '';
  for (const raw of lines(text, 200_000)) {
    if (pendingKey !== undefined) {
      if (raw.endsWith(']')) { out[pendingKey] = (pendingVal + '\n' + raw.slice(0, -1)).slice(0, 8192); pendingKey = undefined; }
      else if (pendingVal.length < 8192) pendingVal += '\n' + raw;
      continue;
    }
    const m = /^\[([^\]\s]{1,256})\]: \[(.*)$/.exec(raw);
    if (!m) continue;
    if (count >= 20_000) break;
    const key = m[1]!;
    const rest = m[2]!;
    count++;
    if (rest.endsWith(']')) out[key] = rest.slice(0, -1).slice(0, 8192);
    else { pendingKey = key; pendingVal = rest; }
  }
  return out;
}

/** Parse `settings list <namespace>`: `key=value` lines. */
export function parseSettingsList(text: string): Record<string, string> {
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  let n = 0;
  for (const raw of lines(text, 100_000)) {
    const i = raw.indexOf('=');
    if (i <= 0) continue;
    const k = raw.slice(0, i);
    if (!/^[\w.:\-]{1,256}$/.test(k)) continue;
    if (n++ >= 20_000) break;
    out[k] = raw.slice(i + 1).slice(0, 8192);
  }
  return out;
}

export interface AdbComponent {
  /** full component as printed, for example com.example/.MainActivity */
  component: string;
  /** expanded class name, for example com.example.MainActivity */
  className: string;
  /** intent actions seen in the resolver table for this component */
  actions: string[];
  categories: string[];
  schemes: string[];
  /** permission required to bind or start, when dumpsys prints one */
  permission?: string;
}

export interface AdbPermission { name: string; granted?: boolean; flags?: string[] }

export interface AdbPackageInfo {
  package?: string;
  appId?: number;
  versionCode?: number;
  minSdk?: number;
  targetSdk?: number;
  versionName?: string;
  codePath?: string;
  dataDir?: string;
  primaryCpuAbi?: string | null;
  apkSigningVersion?: number;
  flags: string[];
  privateFlags: string[];
  debuggable: boolean;
  allowBackup: boolean;
  firstInstallTime?: string;
  lastUpdateTime?: string;
  installerPackageName?: string | null;
  installed?: boolean;
  stopped?: boolean;
  declaredPermissions: string[];
  requestedPermissions: string[];
  installPermissions: AdbPermission[];
  runtimePermissions: AdbPermission[];
  activities: AdbComponent[];
  services: AdbComponent[];
  receivers: AdbComponent[];
  providers: { component: string; className: string; authority: string }[];
}

const TABLES: Record<string, 'activities' | 'services' | 'receivers'> = {
  'Activity Resolver Table:': 'activities',
  'Service Resolver Table:': 'services',
  'Receiver Resolver Table:': 'receivers',
};

const COMPONENT_RE = /^([A-Za-z][\w.]{0,254})\/([\w.$]{1,512})$/;

/** Expand `pkg/.Cls` to `pkg.Cls`; `pkg/full.Cls` stays `full.Cls`. */
export function expandComponent(component: string): string | undefined {
  const m = COMPONENT_RE.exec(component);
  if (!m) return undefined;
  return m[2]!.startsWith('.') ? m[1]! + m[2]! : m[2]!;
}

function perm(line: string): AdbPermission | undefined {
  const m = /^([\w.$-]{1,256}): granted=(true|false)(?:, flags=\[ ?([^\]]*)\])?/.exec(line.trim());
  if (!m) return undefined;
  const flags = m[3]?.split(/[|\s]+/).filter(Boolean).slice(0, 32);
  return { name: m[1]!, granted: m[2] === 'true', ...(flags && flags.length ? { flags } : {}) };
}

/**
 * Parse `dumpsys package <pkg>`: the resolver tables (activities, services, receivers with their
 * intent filters), content provider authorities, and the `Packages:` block (versions, SDK levels,
 * flags, permissions, install times). Components that declare no intent filter do not appear in
 * the resolver tables; that is a limit of dumpsys, not of this parser.
 */
export function parseDumpsysPackage(text: string, pkgFilter?: string): AdbPackageInfo {
  const info: AdbPackageInfo = {
    flags: [], privateFlags: [], debuggable: false, allowBackup: false, declaredPermissions: [], requestedPermissions: [],
    installPermissions: [], runtimePermissions: [], activities: [], services: [], receivers: [], providers: [],
  };
  const maps: Record<'activities' | 'services' | 'receivers', Map<string, AdbComponent>> = { activities: new Map(), services: new Map(), receivers: new Map() };
  let section: string | undefined;
  let table: 'activities' | 'services' | 'receivers' | undefined;
  let current: AdbComponent | undefined;
  let inPackages = false;
  let pkgCount = 0;
  let permList: 'declared' | 'requested' | 'install' | 'runtime' | undefined;
  let permIndent = -1;
  let providerAuthority: string | undefined;
  const cap = 5000;
  for (const raw of lines(text, 500_000)) {
    const line = raw.replace(/\s+$/, '');
    if (!line) { current = undefined; continue; }
    const indent = line.length - line.trimStart().length;
    const t = line.trim();
    if (indent === 0) {
      section = t; table = TABLES[t]; current = undefined; permList = undefined; providerAuthority = undefined;
      inPackages = t === 'Packages:';
      continue;
    }
    if (table) {
      const cm = /^[0-9a-f]{1,16} ([^\s]+)(?: filter [0-9a-f]+)?(?: permission ([\w.$-]+))?/.exec(t);
      if (cm && cm[1]!.includes('/')) {
        const comp = cm[1]!;
        const cls = expandComponent(comp);
        if (!cls || (pkgFilter && !comp.startsWith(pkgFilter + '/'))) { current = undefined; continue; }
        const map = maps[table];
        current = map.get(comp);
        if (!current) {
          if (map.size >= cap) { current = undefined; continue; }
          current = { component: comp, className: cls, actions: [], categories: [], schemes: [] };
          map.set(comp, current);
        }
        if (cm[2] && !current.permission) current.permission = cm[2];
        continue;
      }
      if (current) {
        const am = /^(Action|Category|Scheme): "([^"]{0,512})"/.exec(t);
        if (am) {
          const list = am[1] === 'Action' ? current.actions : am[1] === 'Category' ? current.categories : current.schemes;
          if (!list.includes(am[2]!) && list.length < 64) list.push(am[2]!);
        }
      }
      continue;
    }
    if (section === 'ContentProvider Authorities:') {
      const am = /^\[([^\]]{1,512})\]:$/.exec(t);
      if (am) { providerAuthority = am[1]; continue; }
      const pm = /^Provider\{[0-9a-f]+ ([^\s}]+)\}$/.exec(t);
      if (pm && providerAuthority) {
        const cls = expandComponent(pm[1]!);
        if (cls && (!pkgFilter || pm[1]!.startsWith(pkgFilter + '/')) && info.providers.length < cap) {
          info.providers.push({ component: pm[1]!, className: cls, authority: providerAuthority });
        }
        providerAuthority = undefined;
      }
      continue;
    }
    if (!inPackages) continue;
    const pk = /^Package \[([^\]]{1,255})\]/.exec(t);
    if (pk) {
      pkgCount++;
      if (pkgCount > 1) { inPackages = false; continue; } // only the first package block is reported
      info.package = pk[1];
      continue;
    }
    if (permList && indent > permIndent) {
      if (permList === 'declared') { const n = /^([\w.$-]{1,256}):/.exec(t)?.[1]; if (n && info.declaredPermissions.length < cap) info.declaredPermissions.push(n); }
      else if (permList === 'requested') { const n = /^([\w.$-]{1,256})/.exec(t)?.[1]; if (n && info.requestedPermissions.length < cap) info.requestedPermissions.push(n); }
      else { const p = perm(t); const list = permList === 'install' ? info.installPermissions : info.runtimePermissions; if (p && list.length < cap) list.push(p); }
      continue;
    }
    permList = undefined;
    const pl = /^(declared|requested|install|runtime) permissions:$/.exec(t);
    if (pl) { permList = pl[1] as typeof permList; permIndent = indent; continue; }
    const vc = /^versionCode=(\d+)(?: minSdk=(\d+))?(?: targetSdk=(\d+))?/.exec(t);
    if (vc) {
      info.versionCode = Number(vc[1]);
      if (vc[2]) info.minSdk = Number(vc[2]);
      if (vc[3]) info.targetSdk = Number(vc[3]);
      continue;
    }
    const kv = /^([A-Za-z]+)=(.*)$/.exec(t);
    if (kv) {
      const [, k, v] = kv as unknown as [string, string, string];
      const val = v.slice(0, 2048);
      switch (k) {
        case 'versionName': info.versionName = val; break;
        case 'appId': case 'userId': if (info.appId === undefined && /^\d+$/.test(val)) info.appId = Number(val); break;
        case 'codePath': info.codePath = val; break;
        case 'dataDir': info.dataDir = val; break;
        case 'primaryCpuAbi': info.primaryCpuAbi = val === 'null' ? null : val; break;
        case 'apkSigningVersion': if (/^\d+$/.test(val)) info.apkSigningVersion = Number(val); break;
        case 'flags': info.flags = val.replace(/^\[|\]$/g, '').trim().split(/\s+/).filter(Boolean).slice(0, 64); break;
        case 'privateFlags': info.privateFlags = val.replace(/^\[|\]$/g, '').trim().split(/\s+/).filter(Boolean).slice(0, 64); break;
        case 'firstInstallTime': info.firstInstallTime = val; break;
        case 'lastUpdateTime': info.lastUpdateTime = val; break;
        case 'installerPackageName': info.installerPackageName = val === 'null' ? null : val; break;
        default: break;
      }
      continue;
    }
    const user = /^User 0: .*\binstalled=(true|false)\b.*\bstopped=(true|false)\b/.exec(t);
    if (user) { info.installed = user[1] === 'true'; info.stopped = user[2] === 'true'; }
  }
  info.activities = [...maps.activities.values()];
  info.services = [...maps.services.values()];
  info.receivers = [...maps.receivers.values()];
  info.debuggable = info.flags.includes('DEBUGGABLE');
  info.allowBackup = info.flags.includes('ALLOW_BACKUP');
  return info;
}

/** Components that can start from the launcher: MAIN action with LAUNCHER or LEANBACK_LAUNCHER category. */
export function launcherActivities(info: AdbPackageInfo): string[] {
  return info.activities.filter((a) => a.actions.includes('android.intent.action.MAIN') &&
    (a.categories.includes('android.intent.category.LAUNCHER') || a.categories.includes('android.intent.category.LEANBACK_LAUNCHER'))).map((a) => a.component);
}

/** Parse `am start -W` output. */
export function parseAmStart(text: string): { ok: boolean; component?: string; status?: string; launchState?: string; totalTimeMs?: number; waitTimeMs?: number; error?: string } {
  const out: ReturnType<typeof parseAmStart> = { ok: false };
  for (const raw of lines(text, 2000)) {
    const t = raw.trim();
    let m: RegExpExecArray | null;
    if ((m = /^Status: (\w+)/.exec(t))) out.status = m[1];
    else if ((m = /^Activity: (\S+)/.exec(t))) out.component = m[1];
    else if ((m = /^LaunchState: (\w+)/.exec(t))) out.launchState = m[1];
    else if ((m = /^TotalTime: (\d+)/.exec(t))) out.totalTimeMs = Number(m[1]);
    else if ((m = /^WaitTime: (\d+)/.exec(t))) out.waitTimeMs = Number(m[1]);
    else if ((m = /^Starting: Intent \{.*\bcmp=([^\s}]+)/.exec(t)) && !out.component) out.component = m[1];
    else if (/^(Error|Exception|java\.lang\.\w+|Warning: Activity not started)/.test(t) && !out.error) out.error = t.slice(0, 1000);
  }
  out.ok = !out.error && (out.status === 'ok' || (out.status === undefined && out.component !== undefined));
  return out;
}

/** Parse the result line of `adb install`, `adb install-multiple` or `adb uninstall`. */
export function parseInstallResult(text: string): { ok: boolean; code?: string; message?: string } {
  const ls = lines(text, 5000).map((l) => l.trim()).filter(Boolean);
  if (ls.some((l) => l === 'Success')) return { ok: true };
  for (const l of ls) {
    const m = /Failure \[([A-Z0-9_]{1,128})(?:[:\s]([^\]]{0,500}))?\]/.exec(l);
    if (m) return { ok: false, code: m[1], ...(m[2] ? { message: m[2].trim() } : {}) };
  }
  const err = ls.find((l) => /^(adb: |error: |Failure)/.test(l));
  return { ok: false, ...(err ? { message: err.slice(0, 1000) } : {}) };
}

/** Parse the summary line printed by `adb push` and `adb pull`. */
export function parseTransfer(text: string): { files: number; skipped: number; bytes?: number; seconds?: number; rate?: string } | undefined {
  for (const raw of lines(text, 5000)) {
    const m = /: (\d+) files? (?:pushed|pulled), (\d+) skipped\.(?: ([\d.]+ [KMG]?B\/s))?(?: \((\d+) bytes in ([\d.]+)s\))?/.exec(raw);
    if (m) return { files: Number(m[1]), skipped: Number(m[2]), ...(m[3] ? { rate: m[3] } : {}), ...(m[4] ? { bytes: Number(m[4]) } : {}), ...(m[5] ? { seconds: Number(m[5]) } : {}) };
  }
  return undefined;
}

export interface AdbProcess { user: string; pid: number; ppid: number; vsz?: number; rss?: number; state?: string; name: string }

/** Parse `ps -A` (toybox) or old toolbox `ps`. Header columns are read from the first line. */
export function parsePs(text: string): AdbProcess[] {
  const out: AdbProcess[] = [];
  let cols: string[] | undefined;
  for (const raw of lines(text, 200_000)) {
    const t = raw.trim();
    if (!t) continue;
    if (!cols) {
      if (/^USER\s+PID\s+PPID\b/.test(t)) cols = t.split(/\s+/);
      continue;
    }
    const parts = t.split(/\s+/);
    if (parts.length < cols.length) continue;
    // NAME is last and may contain spaces; everything before maps one to one.
    const fixed = cols.length - 1;
    const rec: Record<string, string> = {};
    for (let i = 0; i < fixed; i++) rec[cols[i]!] = parts[i]!;
    const name = parts.slice(fixed).join(' ');
    const pid = Number(rec.PID);
    const ppid = Number(rec.PPID);
    if (!Number.isSafeInteger(pid) || !Number.isSafeInteger(ppid)) continue;
    const p: AdbProcess = { user: rec.USER ?? '', pid, ppid, name: name.slice(0, 512) };
    const vsz = Number(rec.VSZ ?? rec.VSIZE);
    const rss = Number(rec.RSS);
    if (Number.isFinite(vsz)) p.vsz = vsz;
    if (Number.isFinite(rss)) p.rss = rss;
    if (rec.S) p.state = rec.S;
    out.push(p);
    if (out.length >= 100_000) break;
  }
  return out;
}

/** Parse `wm size` and `wm density`. */
export function parseWm(text: string): { physicalSize?: { width: number; height: number }; overrideSize?: { width: number; height: number }; physicalDensity?: number; overrideDensity?: number } {
  const out: ReturnType<typeof parseWm> = {};
  for (const raw of lines(text, 1000)) {
    const t = raw.trim();
    let m: RegExpExecArray | null;
    if ((m = /^(Physical|Override) size: (\d{1,6})x(\d{1,6})$/.exec(t))) {
      const v = { width: Number(m[2]), height: Number(m[3]) };
      if (m[1] === 'Physical') out.physicalSize = v; else out.overrideSize = v;
    } else if ((m = /^(Physical|Override) density: (\d{1,5})$/.exec(t))) {
      if (m[1] === 'Physical') out.physicalDensity = Number(m[2]); else out.overrideDensity = Number(m[2]);
    }
  }
  return out;
}

/** Parse `cmd package resolve-activity --brief`: the last line is the component, or "No activity found". */
export function parseResolveActivity(text: string): string | undefined {
  const ls = lines(text, 1000).map((l) => l.trim()).filter(Boolean);
  for (let i = ls.length - 1; i >= 0; i--) {
    if (COMPONENT_RE.test(ls[i]!)) return ls[i];
  }
  return undefined;
}

/** Parse `adb forward --list` and `adb reverse --list`: `<serial> <local> <remote>` or `<transport> <local> <remote>`. */
export function parseForwardList(text: string): { serial: string; local: string; remote: string }[] {
  const out: { serial: string; local: string; remote: string }[] = [];
  for (const raw of lines(text, 10_000)) {
    const p = raw.trim().split(/\s+/);
    if (p.length !== 3) continue;
    if (!/^[a-z]+:/.test(p[1]!) || !/^[a-z]+:/.test(p[2]!)) continue;
    out.push({ serial: p[0]!, local: p[1]!, remote: p[2]! });
    if (out.length >= 1000) break;
  }
  return out;
}

export interface AdbDirEntry { mode: string; type: 'file' | 'dir' | 'link' | 'other'; links?: number; owner?: string; group?: string; size?: number; date?: string; name: string; target?: string }

/** Parse `ls -la` in the toybox layout: mode links owner group size YYYY-MM-DD HH:MM name [-> target]. */
export function parseLsLong(text: string): AdbDirEntry[] {
  const out: AdbDirEntry[] = [];
  for (const raw of lines(text, 200_000)) {
    const m = /^([bcdlps-][rwxsStT-]{9}[.+@]?)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+(?:,\s*\d+)?)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s(.+)$/.exec(raw);
    if (!m) continue;
    const mode = m[1]!;
    let name = m[7]!;
    let target: string | undefined;
    const type = mode[0] === 'd' ? 'dir' : mode[0] === '-' ? 'file' : mode[0] === 'l' ? 'link' : 'other';
    if (type === 'link') {
      const i = name.indexOf(' -> ');
      if (i > 0) { target = name.slice(i + 4); name = name.slice(0, i); }
    }
    if (name === '.' || name === '..') continue;
    const size = Number(m[5]);
    out.push({ mode, type, links: Number(m[2]), owner: m[3], group: m[4], ...(Number.isFinite(size) ? { size } : {}), date: m[6], name: name.slice(0, 1024), ...(target ? { target: target.slice(0, 1024) } : {}) });
    if (out.length >= 100_000) break;
  }
  return out;
}

/** Read width and height from a PNG IHDR chunk. */
export function pngSize(b: Uint8Array): { width: number; height: number } | undefined {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (b.length < 24 || !sig.every((v, i) => b[i] === v)) return undefined;
  if (String.fromCharCode(b[12]!, b[13]!, b[14]!, b[15]!) !== 'IHDR') return undefined;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return { width: dv.getUint32(16), height: dv.getUint32(20) };
}

/** Read the plain text header of an Android backup (.ab) file. */
export function parseBackupHeader(b: Uint8Array): { version: number; compressed: boolean; encryption: string } | undefined {
  const head = new TextDecoder('latin1').decode(b.subarray(0, Math.min(b.length, 256)));
  const m = /^ANDROID BACKUP\n(\d{1,3})\n([01])\n([A-Za-z0-9-]{1,32})\n/.exec(head);
  if (!m) return undefined;
  return { version: Number(m[1]), compressed: m[2] === '1', encryption: m[3]! };
}
