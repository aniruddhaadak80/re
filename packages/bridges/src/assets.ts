// Scripts this package ships for other programs (the Cutter plugin, the JEB script) are normally
// files next to dist/. Inside a Node single executable application there is no such folder, so the
// build embeds them as SEA assets under the keys in BUNDLED_SCRIPTS. On first use the asset is
// written to a private folder (mode 0700, owned by this user, checked before every reuse) under the
// system temp folder, and that path is returned. The folder name carries a hash of the content, so
// a new binary never reuses an old copy, and a copy changed on disk is written again.
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { basename, join } from 'node:path';

/** SEA asset key to the path of the file inside this package. */
export const BUNDLED_SCRIPTS = {
  'bridges/cutter/revlens_cutter_bridge.py': 'scripts/cutter/revlens_cutter_bridge.py',
  'bridges/jeb/RevLensJeb.py': 'scripts/jeb/RevLensJeb.py',
} as const;
export type BundledScriptKey = keyof typeof BUNDLED_SCRIPTS;

interface SeaApi { isSea(): boolean; getAsset(key: string): ArrayBuffer }

function seaApi(): SeaApi | undefined {
  try {
    const get = (process as unknown as { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule;
    const sea = get?.('node:sea') as SeaApi | undefined;
    return sea && typeof sea.isSea === 'function' && sea.isSea() ? sea : undefined;
  } catch { return undefined; }
}

/** True when this code runs inside a single executable application. */
export function runningAsSea(): boolean { return seaApi() !== undefined; }

function safeUser(): string {
  let u = 'user';
  try { u = String(process.getuid?.() ?? userInfo().username); } catch { /* keep default */ }
  return u.replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 40) || 'user';
}

/** Make or check a private folder: a real directory (not a link), owned by us, not group or world writable. */
export function privateDir(path: string): string {
  if (!existsSync(path)) mkdirSync(path, { recursive: true, mode: 0o700 });
  const st = lstatSync(path);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error(`${path} is not a plain folder`);
  if (process.platform !== 'win32') {
    const uid = process.getuid?.();
    if (uid !== undefined && st.uid !== uid) throw new Error(`${path} belongs to another user`);
    if ((st.mode & 0o077) !== 0) chmodSync(path, 0o700);
  }
  return path;
}

/**
 * Write bytes to `<base>/<name>` unless an identical regular file is already there. The write goes
 * to a temporary name first and is renamed into place, so a reader never sees half a file.
 */
export function materialize(base: string, name: string, bytes: Uint8Array): string {
  const dir = privateDir(base);
  const target = join(dir, name);
  if (existsSync(target)) {
    const st = lstatSync(target);
    if (st.isFile() && !st.isSymbolicLink() && st.size === bytes.length && Buffer.compare(readFileSync(target), Buffer.from(bytes)) === 0) return target;
  }
  const tmp = join(dir, `.${name}.${process.pid}.${Date.now()}.tmp`);
  writeFileSync(tmp, bytes, { mode: 0o600, flag: 'wx' });
  renameSync(tmp, target);
  return target;
}

/** Folder used for extracted assets: <tmp>/<prefix>-assets-<user>-<hash of content>. */
export function assetDir(bytes: Uint8Array, prefix = 'revlens', base = tmpdir()): string {
  const h = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
  return join(base, `${prefix.replace(/[^A-Za-z0-9_.-]/g, '_')}-assets-${safeUser()}-${h}`);
}

/**
 * Path of a shipped script. `candidates` are the on-disk places (next to dist/ or src/); the first
 * that exists wins. Inside a SEA the embedded copy is written out and its path returned. When neither
 * is there, the first candidate is returned so error messages still name the expected place.
 */
export function bundledScriptPath(key: BundledScriptKey, candidates: string[], opts: { sea?: SeaApi; base?: string } = {}): string {
  const onDisk = candidates.find((p) => existsSync(p));
  if (onDisk) return onDisk;
  const sea = opts.sea ?? seaApi();
  if (sea) {
    let bytes: Uint8Array | undefined;
    try { bytes = new Uint8Array(sea.getAsset(key)); } catch { bytes = undefined; }
    if (bytes) {
      const name = key.split('/').pop()!;
      // the folder prefix is the binary's own name, so a renamed build needs no change here
      const prefix = basename(process.execPath).replace(/\.exe$/i, '') || 'sea';
      return materialize(assetDir(bytes, prefix, opts.base), name, bytes);
    }
  }
  return candidates[0]!;
}
