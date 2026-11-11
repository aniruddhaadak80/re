// Installed application records from Linux .desktop entries, macOS Info.plist and Windows uninstall
// registry keys (reg query output). No Node imports.
import type { PlistValue } from './plist.js';

export interface AppRecord {
  platform: 'linux' | 'macos' | 'windows';
  source: string;
  name: string;
  id?: string;
  version?: string;
  publisher?: string;
  exec?: string;
  /** first token of Exec / CFBundleExecutable / DisplayIcon, without arguments */
  executable?: string;
  installLocation?: string;
  icon?: string;
  categories?: string[];
  mimeTypes?: string[];
  packaging?: 'flatpak' | 'snap' | 'appimage' | 'msi' | 'app-bundle' | 'deb-or-rpm' | 'other';
  hidden?: boolean;
  terminal?: boolean;
  extra?: Record<string, string>;
}

export interface DesktopEntry { groups: Record<string, Record<string, string>>; errors: string[] }

/** Parse a freedesktop .desktop file into groups of key=value (localized keys kept as Key[xx]). */
export function parseDesktopFile(text: string): DesktopEntry {
  const groups: Record<string, Record<string, string>> = Object.create(null);
  const errors: string[] = [];
  let cur: Record<string, string> | undefined;
  let n = 0;
  for (const raw of text.split('\n', 50_000)) {
    n++;
    const l = raw.replace(/\r$/, '');
    if (!l.trim() || l.trimStart().startsWith('#')) continue;
    const g = /^\[([^\[\]]{1,200})\]\s*$/.exec(l);
    if (g) { cur = groups[g[1]!] ??= Object.create(null); continue; }
    const eq = l.indexOf('=');
    if (eq <= 0 || !cur) { if (errors.length < 50) errors.push(`line ${n}: not a key=value inside a group`); continue; }
    const k = l.slice(0, eq).trim();
    if (Object.keys(cur).length < 2000) cur[k] = unescapeDesktop(l.slice(eq + 1).trim()).slice(0, 8000);
  }
  return { groups, errors };
}

function unescapeDesktop(v: string): string {
  return v.replace(/\\([sntr\\;])/g, (_m, c: string) => ({ s: ' ', n: '\n', t: '\t', r: '\r', '\\': '\\', ';': '\\;' } as Record<string, string>)[c]!);
}
const list = (v?: string) => (v ? v.split(/(?<!\\);/).map((x) => x.replace(/\\;/g, ';').trim()).filter(Boolean).slice(0, 200) : undefined);

/** Split an Exec value into arguments per the Desktop Entry spec quoting rules, dropping %f %u style field codes. */
export function splitExec(exec: string): string[] {
  const out: string[] = [];
  let cur = '', q = false, any = false;
  for (let i = 0; i < exec.length && out.length < 500; i++) {
    const c = exec[i]!;
    if (q) {
      if (c === '\\' && i + 1 < exec.length && '"`$\\'.includes(exec[i + 1]!)) { cur += exec[++i]; continue; }
      if (c === '"') { q = false; continue; }
      cur += c;
    } else if (c === '"') { q = true; any = true; }
    else if (c === ' ' || c === '\t') { if (cur || any) out.push(cur); cur = ''; any = false; }
    else cur += c;
  }
  if (cur || any) out.push(cur);
  return out.filter((a) => !/^%[fFuUdDnNickvm]$/.test(a)).map((a) => a.replace(/%%/g, '%'));
}

/** Turn a parsed .desktop file into an AppRecord (or undefined if it is not an application). */
export function desktopEntryToApp(e: DesktopEntry, source: string): AppRecord | undefined {
  const d = e.groups['Desktop Entry'];
  if (!d || (d.Type && d.Type !== 'Application')) return undefined;
  const exec = d.Exec;
  const args = exec ? splitExec(exec) : [];
  let executable = args[0];
  let packaging: AppRecord['packaging'] = 'deb-or-rpm';
  if (d['X-Flatpak'] || /\/flatpak\//.test(source) || executable === 'flatpak' || /\/flatpak$/.test(executable ?? '')) packaging = 'flatpak';
  else if (d['X-SnapInstanceName'] || /\/snapd?\//.test(source) || /^\/snap\//.test(executable ?? '')) packaging = 'snap';
  else if (/\.AppImage$/i.test(executable ?? '') || d['X-AppImage-Version']) packaging = 'appimage';
  if (executable === 'env') executable = args.find((a, i) => i > 0 && !a.includes('='));
  const extra: Record<string, string> = {};
  for (const k of ['StartupWMClass', 'X-Flatpak', 'X-SnapInstanceName', 'TryExec', 'Path', 'DBusActivatable', 'X-GNOME-UsesNotifications']) if (d[k] !== undefined) extra[k] = d[k]!;
  return {
    platform: 'linux', source, name: d.Name ?? source.split('/').pop()!.replace(/\.desktop$/, ''), id: source.split('/').pop()!.replace(/\.desktop$/, ''),
    version: d['X-AppImage-Version'], exec, executable, icon: d.Icon, categories: list(d.Categories), mimeTypes: list(d.MimeType),
    packaging, hidden: d.NoDisplay === 'true' || d.Hidden === 'true', terminal: d.Terminal === 'true', extra: Object.keys(extra).length ? extra : undefined,
  };
}

/** Turn an app bundle's Info.plist into an AppRecord. bundlePath is the .app folder. */
export function infoPlistToApp(p: PlistValue, bundlePath: string): AppRecord {
  const o = (p && typeof p === 'object' && !Array.isArray(p) ? p : {}) as Record<string, PlistValue>;
  const s = (k: string) => (typeof o[k] === 'string' ? (o[k] as string).slice(0, 2000) : undefined);
  const exeName = s('CFBundleExecutable');
  const extra: Record<string, string> = {};
  for (const k of ['CFBundleVersion', 'LSMinimumSystemVersion', 'NSHumanReadableCopyright', 'CFBundlePackageType', 'LSApplicationCategoryType', 'DTSDKName', 'ElectronAsarIntegrity']) {
    const v = o[k];
    if (typeof v === 'string' || typeof v === 'number') extra[k] = String(v).slice(0, 500);
    else if (v && typeof v === 'object') extra[k] = '[present]';
  }
  const urlTypes = Array.isArray(o.CFBundleURLTypes) ? (o.CFBundleURLTypes as Record<string, PlistValue>[]).flatMap((u) => (Array.isArray(u?.CFBundleURLSchemes) ? (u.CFBundleURLSchemes as string[]) : [])).slice(0, 50) : [];
  if (urlTypes.length) extra.urlSchemes = urlTypes.join(',');
  return {
    platform: 'macos', source: `${bundlePath}/Contents/Info.plist`, name: s('CFBundleDisplayName') ?? s('CFBundleName') ?? bundlePath.split('/').pop()!.replace(/\.app$/, ''),
    id: s('CFBundleIdentifier'), version: s('CFBundleShortVersionString') ?? s('CFBundleVersion'), executable: exeName ? `${bundlePath}/Contents/MacOS/${exeName}` : undefined,
    installLocation: bundlePath, icon: s('CFBundleIconFile') ?? s('CFBundleIconName'), packaging: 'app-bundle', extra,
  };
}

/** Parse `reg query <key> /s` output into one record per subkey with its values. */
export function parseRegQuery(text: string): { key: string; values: Record<string, { type: string; data: string }> }[] {
  const out: { key: string; values: Record<string, { type: string; data: string }> }[] = [];
  let cur: (typeof out)[number] | undefined;
  for (const raw of text.split(/\r?\n/, 2_000_000)) {
    if (!raw.trim()) continue;
    if (/^HKEY_[A-Z_]+/.test(raw)) { cur = { key: raw.trim().slice(0, 1000), values: Object.create(null) }; if (out.length < 200_000) out.push(cur); continue; }
    const m = /^\s{2,}(.*?)\s{2,}(REG_[A-Z_0-9]+)(?:\s{2,}(.*))?$/.exec(raw);
    if (m && cur && Object.keys(cur.values).length < 500) cur.values[m[1] === '(Default)' ? '' : m[1]!] = { type: m[2]!, data: (m[3] ?? '').slice(0, 8000) };
  }
  return out;
}

/** Turn uninstall registry keys into AppRecords (keys without DisplayName or marked SystemComponent are dropped). */
export function uninstallKeysToApps(keys: ReturnType<typeof parseRegQuery>): AppRecord[] {
  const apps: AppRecord[] = [];
  for (const k of keys) {
    const v = (n: string) => k.values[n]?.data || undefined;
    const name = v('DisplayName');
    if (!name || v('SystemComponent') === '0x1' || v('ParentKeyName')) continue;
    const icon = v('DisplayIcon');
    const exe = icon?.replace(/^"|"?(?:,\s*-?\d+)?$/g, '').replace(/"$/, '');
    const size = v('EstimatedSize');
    const extra: Record<string, string> = {};
    for (const n of ['UninstallString', 'QuietUninstallString', 'InstallDate', 'URLInfoAbout', 'InstallSource']) if (v(n)) extra[n] = v(n)!;
    if (size) extra.EstimatedSizeKb = String(parseInt(size, 16) || Number(size) || 0);
    apps.push({
      platform: 'windows', source: k.key, name, id: k.key.split('\\').pop(), version: v('DisplayVersion'), publisher: v('Publisher'),
      installLocation: v('InstallLocation'), executable: exe && /\.exe$/i.test(exe) ? exe : undefined, icon,
      packaging: v('WindowsInstaller') === '0x1' || /MsiExec/i.test(v('UninstallString') ?? '') ? 'msi' : 'other', extra,
    });
  }
  return apps;
}
