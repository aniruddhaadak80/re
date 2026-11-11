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
      if (isPackageName(name)) out.push({ name, apkPath: body.slice(0, eq) });
    } else if (isPackageName(body)) {
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

/** Android package names: letters, digits, underscores and dots. */
export function isPackageName(s: string): boolean {
  return s.length > 0 && s.length <= 255 && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(s);
}
