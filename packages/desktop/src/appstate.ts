// Desktop application state: where an installed app keeps its settings and data on Linux, macOS
// and Windows (config folders, preference plists, registry keys, dconf, Electron userData with
// Local Storage), a typed listing of it, a redacted zip export with a manifest, and task checks
// evaluated against a home folder.
import { readdir, lstat, readFile, writeFile, open, realpath } from 'node:fs/promises';
import { join, relative, basename, sep, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { deflateRawSync, inflateRawSync, gunzipSync } from 'node:zlib';
import { InputError } from './proc.js';
import { run } from './exec.js';
import { parseRegQuery } from './apps.js';
import { writeZip } from './zip.js';
import { readLevelDb, decodeLocalStorage } from './leveldb.js';
import { dconfDump, isGvdb } from './gvdb.js';
import { viewOf, detectFormat, isSecretFile, redactValue, redactLines, runTask, validateTask, type ViewHelpers, type DesktopTask, type FileSource } from './views.js';
import { parsePlist } from './plist.js';
import type { UiNode } from './gvariant.js';

export interface AppIdentity { name?: string; id?: string; bundleId?: string; publisher?: string; executable?: string; electron?: boolean; productName?: string }
export interface StateRoot { path: string; role: string; exists: boolean; kind: 'dir' | 'file' | 'registry' | 'dconf' }

const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const uniq = <T,>(xs: T[]) => [...new Set(xs)];

/** Node helpers for typed views: SQLite through node:sqlite (read-only, bounded), raw inflate and gunzip with output caps. */
export async function nodeViewHelpers(): Promise<ViewHelpers> {
  let sqliteMod: { DatabaseSync: new (path: string, o?: Record<string, unknown>) => { prepare(q: string): { all(...a: unknown[]): unknown[] }; close(): void } } | undefined;
  try { sqliteMod = await import('node:sqlite' as string); } catch { sqliteMod = undefined; }
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  return {
    inflateRaw: (b, max) => new Uint8Array(inflateRawSync(b, { maxOutputLength: max })),
    gunzip: (b, max) => new Uint8Array(gunzipSync(b, { maxOutputLength: max })),
    sqlite: sqliteMod ? (bytes) => {
      const dir = mkdtempSync(join(tmpdir(), 'rl-sqlite-'));
      const f = join(dir, 'db.sqlite');
      writeFileSync(f, bytes);
      const db = new sqliteMod!.DatabaseSync(f, { readOnly: true });
      try {
        const tables: Record<string, { columns: string[]; rows: unknown[][] }> = {};
        let truncated = false;
        const names = (db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[]).slice(0, 200);
        for (const { name } of names) {
          const q = `"${name.replace(/"/g, '""')}"`;
          const cols = (db.prepare(`PRAGMA table_info(${q})`).all() as { name: string }[]).map((c) => c.name);
          const rows = (db.prepare(`SELECT * FROM ${q} LIMIT 5001`).all() as Record<string, unknown>[]);
          if (rows.length > 5000) { truncated = true; rows.length = 5000; }
          tables[name] = { columns: cols, rows: rows.map((r) => cols.map((c) => { const v = r[c]; return v instanceof Uint8Array ? `[blob ${v.length} bytes]` : typeof v === 'bigint' ? Number(v) : v; })) };
        }
        return { tables, truncated };
      } finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
    } : undefined,
  };
}

/** Candidate state locations for an app on a platform (whether or not they exist). */
export function stateCandidates(app: AppIdentity, platform: string = process.platform, home: string = homedir(), env: NodeJS.ProcessEnv = process.env): StateRoot[] {
  const names = uniq([app.productName, app.name, app.id, app.bundleId, app.executable && basename(app.executable).replace(/\.(exe|app)$/i, '')].filter((x): x is string => !!x && x.length < 200 && !/[\\/]/.test(x) && x !== '.' && x !== '..'));
  const variants = uniq(names.flatMap((n) => [n, n.toLowerCase(), n.replace(/\s+/g, ''), n.replace(/\s+/g, '-').toLowerCase()]));
  const shortId = app.id?.split('.').pop();
  if (shortId && shortId !== app.id) variants.push(shortId, shortId.toLowerCase());
  const out: StateRoot[] = [];
  const add = (path: string, role: string, kind: StateRoot['kind'] = 'dir') => { if (!out.some((o) => o.path === path)) out.push({ path, role, exists: false, kind }); };
  if (platform === 'linux') {
    const cfg = env.XDG_CONFIG_HOME || join(home, '.config'), data = env.XDG_DATA_HOME || join(home, '.local/share'), cache = env.XDG_CACHE_HOME || join(home, '.cache'), state = env.XDG_STATE_HOME || join(home, '.local/state');
    for (const v of uniq(variants)) {
      add(join(cfg, v), app.electron ? 'electron userData' : 'config'); add(join(data, v), 'data'); add(join(state, v), 'state'); add(join(cache, v), 'cache'); add(join(home, `.${v}`), 'dotfolder');
      add(join(cfg, `${v}rc`), 'config file', 'file'); add(join(home, `.${v}rc`), 'config file', 'file');
    }
    if (app.id) { add(join(home, '.var/app', app.id), 'flatpak sandbox'); add(join(home, 'snap', app.id), 'snap'); }
    for (const v of names) add(join(home, 'snap', v.toLowerCase()), 'snap');
    if (app.id && app.id.includes('.')) add(`/${app.id.split('.').join('/')}/`, 'dconf path', 'dconf');
    for (const v of uniq(names.map((n) => n.toLowerCase().replace(/\s+/g, '-')))) add(`/org/${v}/`, 'dconf path', 'dconf');
  } else if (platform === 'darwin') {
    const L = join(home, 'Library');
    if (app.bundleId) {
      add(join(L, 'Preferences', `${app.bundleId}.plist`), 'preferences plist', 'file');
      add(join(L, 'Containers', app.bundleId), 'sandbox container');
      add(join(L, 'Caches', app.bundleId), 'cache'); add(join(L, 'HTTPStorages', app.bundleId), 'http storage'); add(join(L, 'WebKit', app.bundleId), 'webkit data');
      add(join(L, 'Saved Application State', `${app.bundleId}.savedState`), 'saved window state');
      add(join(L, 'Cookies', `${app.bundleId}.binarycookies`), 'cookies', 'file');
      add(join(L, 'Application Support', app.bundleId), 'application support');
      add(join(L, 'Application Scripts', app.bundleId), 'application scripts');
    }
    for (const v of names) { add(join(L, 'Application Support', v), app.electron ? 'electron userData' : 'application support'); add(join(L, 'Caches', v), 'cache'); add(join(L, 'Logs', v), 'logs'); }
  } else if (platform === 'win32') {
    const appdata = env.APPDATA || join(home, 'AppData', 'Roaming'), local = env.LOCALAPPDATA || join(home, 'AppData', 'Local');
    for (const v of names) {
      add(join(appdata, v), app.electron ? 'electron userData' : 'roaming app data'); add(join(local, v), 'local app data');
      if (app.publisher && !/[\\/]/.test(app.publisher)) { add(join(appdata, app.publisher, v), 'roaming app data'); add(join(local, app.publisher, v), 'local app data'); }
      add(`HKCU\\Software\\${v}`, 'registry', 'registry');
      if (app.publisher && !/[\\/]/.test(app.publisher)) add(`HKCU\\Software\\${app.publisher}\\${v}`, 'registry', 'registry');
    }
    if (app.id) add(join(local, 'Packages', app.id), 'packaged app data');
  }
  return out;
}

export interface StateFile { root: string; path: string; rel: string; size: number; mtime: string; format: string; sha256?: string; secret: boolean; summary?: unknown }
export interface AppStateResult {
  app: AppIdentity; platform: string; roots: StateRoot[]; files: StateFile[]; totalBytes: number; truncated: boolean;
  electron?: { userData: string; localStorage?: { origin?: string; key: string; value?: string }[]; markers: string[] }[];
  registry?: { key: string; values: Record<string, string> }[];
  /** source: the dconf program (user plus system databases) or the user's binary database read directly */
  dconf?: { path: string; dump: string; source: 'dconf' | 'gvdb'; file?: string }[];
  warnings: string[];
}

export interface AppStateOptions {
  /** .desktop file, .app bundle or Info.plist of the app (identity is read from it) */
  path?: string; name?: string; id?: string; bundleId?: string; publisher?: string; electron?: boolean;
  /** more files or folders to include */
  paths?: string[];
  home?: string; maxFiles?: number; maxDepth?: number; hash?: boolean; summaries?: boolean; localStorage?: boolean;
}

async function walk(root: string, maxFiles: number, maxDepth: number, cb: (abs: string, st: Awaited<ReturnType<typeof lstat>>) => Promise<void>): Promise<boolean> {
  let count = 0, truncated = false;
  const rec = async (dir: string, depth: number) => {
    if (depth > maxDepth) { truncated = true; return; }
    let ents: string[];
    try { ents = (await readdir(dir)).sort(); } catch { return; }
    for (const n of ents.slice(0, 50_000)) {
      if (count >= maxFiles) { truncated = true; return; }
      const p = join(dir, n);
      let st; try { st = await lstat(p); } catch { continue; }
      if (st.isSymbolicLink()) continue; // never follow links out of the app's folders
      if (st.isDirectory()) await rec(p, depth + 1);
      else if (st.isFile()) { count++; await cb(p, st); }
    }
  };
  const st = await lstat(root).catch(() => undefined);
  if (st?.isFile()) await cb(root, st); else if (st?.isDirectory()) await rec(root, 0);
  return truncated;
}

async function readCapped(p: string, max: number): Promise<Uint8Array> {
  const fh = await open(p, 'r');
  try { const st = await fh.stat(); const n = Math.min(st.size, max); const b = Buffer.alloc(n); await fh.read(b, 0, n, 0); return new Uint8Array(b); } finally { await fh.close(); }
}

function summarize(format: string, view: unknown): unknown {
  if (view === null || view === undefined) return undefined;
  if (format === 'json' || format === 'plist') return view && typeof view === 'object' && !Array.isArray(view) ? { keys: Object.keys(view as object).slice(0, 50) } : Array.isArray(view) ? { length: (view as unknown[]).length } : { value: String(view).slice(0, 100) };
  if (format === 'keyfile') return { groups: Object.fromEntries(Object.entries((view as { groups: Record<string, Record<string, string>> }).groups).slice(0, 30).map(([g, kv]) => [g, Object.keys(kv).slice(0, 30)])) };
  if (format === 'sqlite') return { tables: Object.fromEntries(Object.entries((view as { tables: Record<string, { rows: unknown[] }> }).tables).map(([t, v]) => [t, v.rows.length])) };
  if (format === 'text' || format.endsWith('+text')) return { lines: (view as { lines: string[] }).lines.length };
  if (format === 'xml') return { root: (view as { root: { name: string } }).root.name };
  if (format === 'zip') return { entries: (view as { entries: unknown[] }).entries.length };
  return undefined;
}

/** Resolve the app identity from options (and its .desktop / .app / Info.plist when path is given). */
async function identity(o: AppStateOptions): Promise<AppIdentity> {
  const app: AppIdentity = { name: o.name, id: o.id, bundleId: o.bundleId, publisher: o.publisher, electron: o.electron };
  if (o.path) {
    const { inspectApp } = await import('./node.js');
    const a = await inspectApp(o.path);
    app.name ??= a.name; app.id ??= a.id; app.publisher ??= a.publisher; app.executable = a.resolvedExecutable ?? a.executable; app.electron ??= a.electron;
    if (a.platform === 'macos') app.bundleId ??= a.id;
    const ex = a.extra as Record<string, string> | undefined;
    if (ex?.StartupWMClass) app.productName = ex.StartupWMClass;
  }
  if (!app.name && !app.id && !app.bundleId && !app.executable) throw new InputError('give path, name, id or bundleId for the app');
  return app;
}

/** List an app's state: folders and files with format, size, hash and a short summary, Electron Local Storage keys, registry values and dconf settings. */
export async function appState(o: AppStateOptions): Promise<AppStateResult> {
  const app = await identity(o);
  const home = o.home ?? homedir();
  const maxFiles = Math.max(1, Math.min(o.maxFiles ?? 5000, 100_000)), maxDepth = Math.max(0, Math.min(o.maxDepth ?? 12, 40));
  const roots = stateCandidates(app, process.platform, home);
  for (const p of o.paths ?? []) { if (typeof p !== 'string' || !isAbsolute(p)) throw new InputError('paths must be absolute'); roots.push({ path: p, role: 'extra', exists: false, kind: 'dir' }); }
  const h = await nodeViewHelpers();
  const res: AppStateResult = { app, platform: process.platform, roots, files: [], totalBytes: 0, truncated: false, warnings: [] };
  const seenReal = new Set<string>();
  const dconfUser = join(o.home === undefined ? (process.env.XDG_CONFIG_HOME || join(home, '.config')) : join(home, '.config'), 'dconf', 'user');
  let userDb: Uint8Array | null | undefined;
  for (const r of roots) {
    if (r.kind === 'registry') {
      if (process.platform !== 'win32') continue;
      const q = await run('reg', ['query', r.path, '/s'], { timeoutMs: 30_000 }).catch(() => undefined);
      if (q && q.code === 0) { r.exists = true; (res.registry ??= []).push(...parseRegQuery(q.stdout).slice(0, 2000).map((k) => ({ key: k.key, values: Object.fromEntries(Object.entries(k.values).map(([n, v]) => [n, v.data])) }))); }
      continue;
    }
    if (r.kind === 'dconf') {
      if (process.platform !== 'linux') continue;
      // with an explicit home, read that home's database; otherwise ask dconf first (it merges the
      // system databases), then fall back to reading the user database file without dconf
      if (o.home === undefined) {
        const cmd = process.env.REVLENS_DCONF_COMMAND || 'dconf';
        const d = await run(cmd, ['dump', r.path], { timeoutMs: 10_000 }).catch(() => undefined);
        if (d && d.code === 0 && d.stdout.trim()) { r.exists = true; (res.dconf ??= []).push({ path: r.path, dump: d.stdout.slice(0, 200_000), source: 'dconf' }); continue; }
      }
      userDb ??= await readCapped(dconfUser, 64 * 1024 * 1024).catch(() => null);
      if (userDb && isGvdb(userDb)) {
        try { const dump = dconfDump(userDb, r.path); if (dump.trim()) { r.exists = true; (res.dconf ??= []).push({ path: r.path, dump: dump.slice(0, 200_000), source: 'gvdb', file: dconfUser }); } }
        catch (e) { res.warnings.push(`${dconfUser}: ${(e as Error).message}`); }
      }
      continue;
    }
    const st = await lstat(r.path).catch(() => undefined);
    if (!st || st.isSymbolicLink()) continue;
    const real = await realpath(r.path).catch(() => r.path);
    if (seenReal.has(real)) continue;
    seenReal.add(real);
    r.exists = true;
    const truncated = await walk(r.path, maxFiles - res.files.length, maxDepth, async (abs, fst) => {
      const rel = relative(r.kind === 'file' ? join(r.path, '..') : r.path, abs).split(sep).join('/');
      const f: StateFile = { root: r.path, path: abs, rel, size: Number(fst.size), mtime: new Date(Number(fst.mtimeMs)).toISOString(), format: 'unknown', secret: isSecretFile(abs) };
      res.totalBytes += f.size;
      if (f.size <= 16 * 1024 * 1024) {
        try {
          const b = await readCapped(abs, 16 * 1024 * 1024);
          if (o.hash !== false) f.sha256 = sha(b);
          f.format = detectFormat(abs, b);
          if (o.summaries !== false && !f.secret && f.size <= 4 * 1024 * 1024 && f.format !== 'binary') { const v = viewOf(abs, b, h); f.format = v.format; f.summary = summarize(v.format, v.view); }
        } catch (e) { f.format = 'unreadable'; res.warnings.length < 200 && res.warnings.push(`${abs}: ${(e as Error).message.slice(0, 120)}`); }
      } else f.format = 'large';
      res.files.push(f);
    });
    if (truncated) res.truncated = true;
    if (r.kind === 'dir') {
      const markers = ['Local Storage', 'Session Storage', 'IndexedDB', 'Preferences', 'Cookies', 'Network', 'GPUCache', 'Code Cache', 'blob_storage'].filter((m) => res.files.some((f) => f.root === r.path && (f.rel === m || f.rel.startsWith(`${m}/`) || f.rel.startsWith(`Default/${m}`))));
      if (markers.length >= 2) {
        const e: NonNullable<AppStateResult['electron']>[number] = { userData: r.path, markers };
        if (o.localStorage !== false) {
          // logs and Snappy tables of each Local Storage folder, merged by sequence number
          const dbFiles = res.files.filter((x) => x.root === r.path && /^(Default\/)?Local Storage\/leveldb\/[^/]+\.(log|ldb|sst)$/.test(x.rel));
          for (const dir of uniq(dbFiles.map((f) => f.rel.slice(0, f.rel.lastIndexOf('/'))))) {
            try {
              const files: { name: string; bytes: Uint8Array }[] = [];
              for (const f of dbFiles.filter((x) => x.rel.startsWith(dir + '/'))) files.push({ name: basename(f.path), bytes: await readCapped(f.path, 64 * 1024 * 1024) });
              const db = readLevelDb(files);
              for (const fr of db.files) if (fr.error) res.warnings.push(`${dir}/${fr.name}: ${fr.error}`);
              for (const ent of db.entries) {
                const d = decodeLocalStorage(ent.key, ent.value);
                if (d.meta) continue;
                (e.localStorage ??= []).push({ origin: d.origin, key: d.key, value: d.value === undefined ? undefined : /token|secret|pass|auth|cookie|session/i.test(d.key) ? '[redacted]' : d.value.slice(0, 500) });
              }
            } catch (err) { res.warnings.push(`${dir}: ${(err as Error).message}`); }
          }
        }
        (res.electron ??= []).push(e);
      }
    }
    if (res.files.length >= maxFiles) { res.truncated = true; break; }
  }
  return res;
}

/** Zip an app's state with a manifest. Files named like secrets are withheld; secret-looking keys in JSON, plist and key=value files are masked. */
export async function appExport(o: AppStateOptions & { out: string; redact?: boolean; maxBytes?: number }): Promise<{ out: string; bytes: number; sha256: string; files: number; withheld: number; redactedFiles: number; manifest: unknown }> {
  if (typeof o.out !== 'string' || !o.out) throw new InputError('out must be the zip path to write');
  const st = await appState({ ...o, summaries: false });
  const redact = o.redact !== false;
  const maxBytes = Math.max(1, Math.min(o.maxBytes ?? 512 * 1024 * 1024, 2 * 1024 * 1024 * 1024));
  const entries: { name: string; data: Uint8Array; mtime?: Date }[] = [];
  const manifestFiles: Record<string, unknown>[] = [];
  let total = 0, withheld = 0, redactedFiles = 0;
  const rootLabel = new Map<string, string>();
  st.roots.filter((r) => r.exists && r.kind !== 'registry' && r.kind !== 'dconf').forEach((r, i) => rootLabel.set(r.path, `${String(i + 1).padStart(2, '0')}-${r.role.replace(/\W+/g, '-')}-${basename(r.path).replace(/[^\w.-]+/g, '_')}`));
  // Local Storage logs keep values in the clear: withhold them when any key there looks secret
  const lsSecret = new Set<string>();
  for (const e of st.electron ?? []) if (e.localStorage?.some((x) => x.value === '[redacted]')) lsSecret.add(e.userData);
  for (const f of st.files) {
    const zipName = `state/${rootLabel.get(f.root)}/${f.rel}`;
    const rec: Record<string, unknown> = { path: zipName, source: f.path, size: f.size, sha256: f.sha256, format: f.format, mtime: f.mtime };
    if (redact && f.secret) { rec.redacted = 'withheld'; withheld++; manifestFiles.push(rec); continue; }
    if (redact && lsSecret.has(f.root) && /^(Default\/)?(Local|Session) Storage\/leveldb\/[^/]+\.(log|ldb)$/.test(f.rel)) { rec.redacted = 'withheld: Local Storage holds secret-looking keys (non-secret keys are in the manifest)'; withheld++; manifestFiles.push(rec); continue; }
    if (f.size > 64 * 1024 * 1024 || total + f.size > maxBytes) { rec.redacted = 'skipped-size'; manifestFiles.push(rec); continue; }
    let data: Uint8Array;
    try { data = new Uint8Array(await readFile(f.path)); } catch { rec.redacted = 'unreadable'; manifestFiles.push(rec); continue; }
    if (redact && ['json', 'plist', 'keyfile', 'text'].includes(f.format)) {
      const masked: string[] = [];
      let out: Uint8Array | undefined;
      const text = new TextDecoder().decode(data);
      if (f.format === 'json') { try { const v = redactValue(JSON.parse(text), '', masked); if (masked.length) out = new TextEncoder().encode(JSON.stringify(v, null, 2)); } catch { /* leave */ } }
      else if (f.format === 'plist') { try { const v = redactValue(JSON.parse(JSON.stringify(parsePlist(data))), '', masked); if (masked.length) { out = new TextEncoder().encode(JSON.stringify(v, null, 2)); rec.path = zipName + '.redacted.json'; rec.note = 'plist with masked values, written as JSON'; } } catch { /* leave */ } }
      else { const t = redactLines(text, masked); if (masked.length) out = new TextEncoder().encode(t); }
      if (out) { data = out; rec.redacted = 'values'; rec.masked = masked.slice(0, 100); rec.exportedSha256 = sha(data); redactedFiles++; }
    }
    total += data.length;
    entries.push({ name: String(rec.path), data, mtime: new Date(f.mtime) });
    manifestFiles.push(rec);
  }
  const manifest = { kind: 'revlens-app-export', version: 1, createdAt: new Date().toISOString(), platform: st.platform, app: st.app, roots: st.roots.filter((r) => r.exists), files: manifestFiles, electron: st.electron?.map((e) => ({ userData: e.userData, markers: e.markers, localStorageKeys: e.localStorage?.map((x) => `${x.origin ?? ''} ${x.key}`) })), registry: st.registry, dconf: st.dconf, redaction: redact ? { withheldFiles: 'names like Cookies, Login Data, Local State, *.key, *.pem, *token*, *secret*, *password*, *credential*', maskedKeys: 'password, secret, token, api key, auth, cookie, session id, credential, private key, bearer, refresh' } : 'off', truncated: st.truncated, warnings: st.warnings };
  if (st.registry) entries.push({ name: 'registry.json', data: new TextEncoder().encode(JSON.stringify(redact ? redactValue(st.registry) : st.registry, null, 1)) });
  if (st.dconf) entries.push({ name: 'dconf.txt', data: new TextEncoder().encode(st.dconf.map((d) => `# ${d.path}\n${redact ? redactLines(d.dump) : d.dump}`).join('\n')) });
  entries.push({ name: 'manifest.json', data: new TextEncoder().encode(JSON.stringify(manifest, null, 1)) });
  const zip = writeZip(entries, (b) => new Uint8Array(deflateRawSync(b, { level: 6 })));
  await writeFile(o.out, zip);
  return { out: o.out, bytes: zip.length, sha256: sha(zip), files: entries.length - 1, withheld, redactedFiles, manifest };
}

/** A file reader rooted at a home folder that refuses paths leaving it. */
export function homeSource(home: string, max = 64 * 1024 * 1024): FileSource {
  return {
    async read(rel: string) {
      if (isAbsolute(rel) || rel.split(/[\\/]/).some((s) => s === '..')) throw new InputError(`file ${rel} must stay under the home`);
      const p = join(home, rel);
      try {
        const st = await lstat(p);
        if (!st.isFile()) return undefined;
        const real = await realpath(p); const rh = await realpath(home);
        if (!real.startsWith(rh + sep) && real !== rh) throw new InputError(`file ${rel} resolves outside the home`);
        if (st.size > max) return undefined;
        return new Uint8Array(await readFile(p));
      } catch (e) { if (e instanceof InputError) throw e; return undefined; }
    },
  };
}

/** Load and check a task file (JSON), then evaluate it against a home folder and an optional saved UI tree. */
export async function checkTaskFile(o: { task: string | DesktopTask; home?: string; uiTree?: string }): Promise<Awaited<ReturnType<typeof runTask>> & { problems: string[] }> {
  let t: DesktopTask;
  if (typeof o.task === 'string') { const b = await readCapped(o.task, 4 * 1024 * 1024); try { t = JSON.parse(new TextDecoder().decode(b)); } catch { throw new InputError('task file is not JSON'); } } else t = o.task;
  const problems = validateTask(t);
  if (problems.length) return { task: String((t as DesktopTask)?.name ?? ''), pass: false, passed: 0, failed: 0, undecided: 0, results: [], answers: {}, problems };
  let nodes: UiNode[] | undefined;
  if (o.uiTree) { try { nodes = JSON.parse(new TextDecoder().decode(await readCapped(o.uiTree, 256 * 1024 * 1024))).nodes; } catch { throw new InputError('uiTree must be a UI tree JSON file (desktop_ui_tree or a checkpoint ui-tree.json)'); } }
  const r = await runTask(t, homeSource(o.home ?? homedir()), await nodeViewHelpers(), nodes);
  return { ...r, problems };
}
