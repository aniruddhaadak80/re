// Node side of replay environments: build from a file into a folder, serve a folder or zip on
// localhost for a limited time, and export a folder as a zip with manifest, bodies, scenario and tasks.
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { mkdir, readFile, writeFile, readdir, stat, open } from 'node:fs/promises';
import { join, resolve, dirname, sep, basename } from 'node:path';
import { buildEnvironment, EnvMatcher, type EnvManifest } from './env.js';
import { listZip, readZipEntry } from './trace.js';
import { InputError, safeRelPath } from './util.js';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);

async function readCapped(path: string, max: number): Promise<Buffer> {
  const fh = await open(path, 'r');
  try { const st = await fh.stat(); if (!st.isFile()) throw new InputError(`${path} is not a file`); if (st.size > max) throw new InputError(`${path} is ${st.size} bytes, over ${max}`); return await fh.readFile(); } finally { await fh.close(); }
}

/** Build an environment folder from a HAR or capture JSON file. The folder must be absent or empty. */
export async function buildEnvironmentFromFile(capturePath: string, outDir: string, opts: { name?: string; scenarioPath?: string; tasks?: boolean } = {}): Promise<{ outDir: string; manifest: EnvManifest; files: { path: string; bytes: number }[] }> {
  const text = (await readCapped(capturePath, 1024 * 1024 * 1024)).toString('utf8');
  let cap: unknown;
  try { cap = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new InputError(`${capturePath} is not JSON`); }
  let scenario: unknown;
  if (opts.scenarioPath) { try { scenario = JSON.parse((await readCapped(opts.scenarioPath, 4 * 1024 * 1024)).toString('utf8')); } catch { throw new InputError('scenario file is not JSON'); } }
  const built = buildEnvironment(cap, { name: opts.name ?? basename(capturePath).replace(/\.(?:har|json)$/i, '').replace(/\.capture$/, ''), sourceText: text, scenario, tasks: opts.tasks });
  const dir = resolve(outDir);
  await mkdir(dir, { recursive: true });
  const existing = await readdir(dir);
  if (existing.length) throw new InputError(`${dir} is not empty; the build never replaces a folder`);
  const written: { path: string; bytes: number }[] = [];
  for (const f of built.files) {
    const rel = safeRelPath(f.path);
    const target = resolve(dir, rel);
    if (!target.startsWith(dir + sep)) throw new InputError(`unsafe path ${f.path}`);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, f.bytes, { mode: 0o600 });
    written.push({ path: rel, bytes: f.bytes.length });
  }
  if (built.manifest.scenario) { await writeFile(join(dir, 'scenario.json'), JSON.stringify(built.manifest.scenario, null, 1), { mode: 0o600 }); written.push({ path: 'scenario.json', bytes: (await stat(join(dir, 'scenario.json'))).size }); }
  const readme = envReadme(built.manifest);
  await writeFile(join(dir, 'README.md'), readme, { mode: 0o600 });
  written.push({ path: 'README.md', bytes: Buffer.byteLength(readme) });
  return { outDir: dir, manifest: built.manifest, files: written };
}

function envReadme(m: EnvManifest): string {
  return [`# ${m.name} replay environment`, '', `Built by RevLens webrt from a recorded ${m.source.kind} (sha256 ${m.source.sha256}, ${m.source.entries} entries).`,
    `It answers ${m.routes.length} recorded responses for ${m.origin} and ${m.origins.length - 1} other origins with fixed matching rules: ${m.rules.order.join(', then ')}. Repeated identical requests get the recorded answers in order, then the last one again.`,
    '', 'Serve it on localhost with `revlens env-serve <this folder>` or the `web_env_serve` tool, then point a browser or the scenario at the printed URL. Other origins are reached under `/__host/<host>/`.',
    '', `\`tasks/tasks.json\` holds ${m.tasks.length} eval tasks with ground truth from the recording, in the shape the RevLens extras \`x_eval_score\` tool scores.`,
    '', 'Replay is not emulation: nothing is computed, only recorded answers are returned. The recorded content belongs to the application that served it; do not publish it without the right to.', ''].join('\n');
}

/** Load a manifest and a body reader from an environment folder or zip. */
export async function loadEnvironment(path: string): Promise<{ manifest: EnvManifest; body: (file: string) => Promise<Uint8Array | undefined> }> {
  const st = await stat(path);
  if (st.isDirectory()) {
    const root = resolve(path);
    let manifest: EnvManifest;
    try { manifest = JSON.parse((await readCapped(join(root, 'manifest.json'), 512 * 1024 * 1024)).toString('utf8')); } catch (e) { throw e instanceof InputError ? e : new InputError('manifest.json is missing or not JSON'); }
    return { manifest, body: async (file) => { const rel = safeRelPath(file); if (!rel.startsWith('bodies/')) return undefined; try { return new Uint8Array(await readCapped(join(root, rel), 512 * 1024 * 1024)); } catch { return undefined; } } };
  }
  const zip = new Uint8Array(await readCapped(path, 2 * 1024 * 1024 * 1024));
  const entries = listZip(zip);
  const find = (n: string) => entries.find((e) => e.name === n || e.name.endsWith('/' + n));
  const me = find('manifest.json');
  if (!me) throw new InputError('zip has no manifest.json');
  const manifest = JSON.parse(new TextDecoder().decode(readZipEntry(zip, me, 512 * 1024 * 1024))) as EnvManifest;
  return { manifest, body: async (file) => { const e = find(file); return e ? readZipEntry(zip, e, 512 * 1024 * 1024) : undefined; } };
}

export interface ServedEnvironment { id: string; url: string; port: number; expiresAt: string; close: () => Promise<void>; log: ServedRequest[]; manifest: EnvManifest }
export interface ServedRequest { method: string; path: string; status: number; rule: string; route?: number; sequence?: number }
const RUNNING = new Map<string, ServedEnvironment>();

/**
 * Serve an environment on a loopback address for a limited time. Requests are answered only from the
 * recording. GET /__revlens/log lists what was served, POST /__revlens/reset rewinds the sequences.
 */
export async function serveEnvironment(path: string, opts: { port?: number; host?: string; ttlMs?: number; maxRequests?: number; maxBodyBytes?: number } = {}): Promise<ServedEnvironment> {
  const host = opts.host ?? '127.0.0.1';
  if (!LOOPBACK.has(host)) throw new InputError('environments are served on loopback only (127.0.0.1, ::1 or localhost)');
  const ttl = Math.max(1_000, Math.min(opts.ttlMs ?? 10 * 60_000, 2 * 60 * 60_000));
  const maxReq = Math.max(1, Math.min(opts.maxRequests ?? 100_000, 10_000_000));
  const maxBody = Math.max(0, Math.min(opts.maxBodyBytes ?? 16 * 1024 * 1024, 256 * 1024 * 1024));
  const { manifest, body } = await loadEnvironment(path);
  const matcher = new EnvMatcher(manifest);
  const log: ServedRequest[] = [];
  let served = 0;
  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const method = String(req.method ?? 'GET').toUpperCase();
    const url = String(req.url ?? '/');
    // read and hash the request body (capped) so POSTs with different bodies keep apart
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) { size += (c as Buffer).length; if (size > maxBody) { res.writeHead(413).end(); return; } chunks.push(c as Buffer); }
    if (url === '/__revlens/log' && method === 'GET') { res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ served, log: log.slice(-5000) })); return; }
    if (url === '/__revlens/reset' && method === 'POST') { matcher.reset(); log.length = 0; served = 0; res.writeHead(204).end(); return; }
    if (++served > maxReq) { res.writeHead(503, { 'content-type': 'text/plain' }).end('request budget used up'); return; }
    const bodyBuf = Buffer.concat(chunks);
    const sha = bodyBuf.length ? createHash('sha256').update(bodyBuf).digest('hex') : undefined;
    const m = matcher.match(method, url, { bodySha256: sha });
    if (!m.route) {
      log.push({ method, path: url.slice(0, 2000), status: 404, rule: 'none' });
      res.writeHead(404, { 'content-type': 'application/json', 'x-revlens-replay': 'none' }).end(JSON.stringify({ error: 'no recorded response', method, path: url.slice(0, 2000) }));
      return;
    }
    const r = m.route;
    const headers: Record<string, string> = {};
    for (const [n, v] of r.headers) {
      if (n === 'location') { try { const lu = new URL(v, manifest.origin); headers[n] = lu.origin === manifest.origin ? lu.pathname + lu.search : `/__host/${lu.host}${lu.pathname}${lu.search}`; } catch { headers[n] = v; } continue; }
      headers[n] = v;
    }
    headers['x-revlens-replay'] = `${r.id};${m.rule};${m.sequence}`;
    headers['cache-control'] = 'no-store';
    const data = r.body ? await body(r.body.file) : undefined;
    log.push({ method, path: url.slice(0, 2000), status: r.status, rule: m.rule, route: r.id, sequence: m.sequence });
    res.writeHead(r.status, headers);
    res.end(method === 'HEAD' ? undefined : data ? Buffer.from(data) : undefined);
  };
  const server: Server = createServer((req, res) => { handler(req, res).catch(() => { try { res.writeHead(500).end(); } catch { /* closed */ } }); });
  await new Promise<void>((ok, bad) => { server.once('error', bad); server.listen(opts.port ?? 0, host, () => ok()); });
  const port = (server.address() as { port: number }).port;
  const id = `env-${port}-${Date.now().toString(36)}`;
  let closed = false;
  const close = async () => { if (closed) return; closed = true; clearTimeout(timer); RUNNING.delete(id); server.closeAllConnections?.(); await new Promise<void>((ok) => server.close(() => ok())); };
  const timer = setTimeout(() => { close().catch(() => undefined); }, ttl);
  timer.unref?.();
  const env: ServedEnvironment = { id, url: `http://${host.includes(':') ? `[${host}]` : host}:${port}/`, port, expiresAt: new Date(Date.now() + ttl).toISOString(), close, log, manifest };
  RUNNING.set(id, env);
  return env;
}

/** Stop a served environment by id (or all of them). */
export async function stopEnvironment(id?: string): Promise<string[]> {
  const ids = id ? [id] : [...RUNNING.keys()];
  for (const x of ids) await RUNNING.get(x)?.close();
  return ids.filter((x) => !RUNNING.has(x));
}
export function runningEnvironments(): { id: string; url: string; expiresAt: string; served: number }[] {
  return [...RUNNING.values()].map((e) => ({ id: e.id, url: e.url, expiresAt: e.expiresAt, served: e.log.length }));
}

// ---- zip writer (deflate, CRC-32) ----
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
export function crc32(b: Uint8Array): number { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]!) & 0xff]! ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

/** Write a zip archive (deflated entries, fixed timestamps so the same input gives the same bytes). */
export function writeZip(files: { path: string; bytes: Uint8Array }[]): Uint8Array {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  const DOS_TIME = 0, DOS_DATE = (2026 - 1980) << 9 | 1 << 5 | 1;
  for (const f of files) {
    const name = Buffer.from(f.path, 'utf8');
    const data = Buffer.from(f.bytes);
    const comp = deflateRawSync(data, { level: 6 });
    const useStore = comp.length >= data.length;
    const body = useStore ? data : comp;
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(useStore ? 0 : 8, 8);
    lh.writeUInt16LE(DOS_TIME, 10); lh.writeUInt16LE(DOS_DATE, 12); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26); lh.writeUInt16LE(0, 28);
    parts.push(lh, name, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(useStore ? 0 : 8, 10);
    ch.writeUInt16LE(DOS_TIME, 12); ch.writeUInt16LE(DOS_DATE, 14); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...parts, cd, end]));
}

/** Export an environment folder (or rebuild from a capture file first) as one zip with manifest, bodies, scenario, tasks and README. */
export async function exportEnvironment(path: string, outZip: string, opts: { name?: string } = {}): Promise<{ zip: string; files: number; bytes: number; sha256: string; tasks: number; routes: number }> {
  let dir = resolve(path);
  const st = await stat(dir);
  if (st.isFile()) {
    const tmp = resolve(dirname(resolve(outZip)), `.revlens-env-${Date.now().toString(36)}`);
    await buildEnvironmentFromFile(dir, tmp, opts);
    dir = tmp;
  }
  const files: { path: string; bytes: Uint8Array }[] = [];
  const walkDir = async (d: string, rel: string, depth: number) => {
    if (depth > 4) return;
    for (const ent of (await readdir(d, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = join(d, ent.name), r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) await walkDir(p, r, depth + 1);
      else if (ent.isFile()) files.push({ path: r, bytes: new Uint8Array(await readCapped(p, 512 * 1024 * 1024)) });
      if (files.length > 200_000) throw new InputError('too many files');
    }
  };
  await walkDir(dir, '', 0);
  const man = files.find((f) => f.path === 'manifest.json');
  if (!man) throw new InputError(`${dir} has no manifest.json`);
  const manifest = JSON.parse(new TextDecoder().decode(man.bytes)) as EnvManifest;
  // the manifest first, then the rest in name order
  files.sort((a, b) => (a.path === 'manifest.json' ? -1 : b.path === 'manifest.json' ? 1 : a.path.localeCompare(b.path)));
  const zip = writeZip(files);
  await mkdir(dirname(resolve(outZip)), { recursive: true });
  await writeFile(outZip, zip, { mode: 0o600 });
  return { zip: resolve(outZip), files: files.length, bytes: zip.length, sha256: createHash('sha256').update(zip).digest('hex'), tasks: manifest.tasks.length, routes: manifest.routes.length };
}
void inflateRawSync;
