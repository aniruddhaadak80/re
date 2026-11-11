// JVM, Android and .NET decompiler bridges: jadx, apktool and ilspycmd. Node only.
import { existsSync } from 'node:fs';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { installFor } from '../catalog.js';
import { join } from 'node:path';
import { describeFailure, runTool } from '../exec.js';
import { lines } from '../parsers/common.js';
import type { Detection } from '../types.js';
import { BridgeInputError, cacheRoot, ensureDir, inside, int, listFiles, need, requireFile, sha256File, withLock } from './common.js';

function javaEnv(det: Detection, java?: Detection): NodeJS.ProcessEnv {
  const env = { ...process.env };
  const jh = java?.details?.javaHome;
  if (!env.JAVA_HOME && typeof jh === 'string' && jh) env.JAVA_HOME = jh;
  void det;
  return env;
}

async function javaDet(): Promise<Detection | undefined> {
  const j = await need('java');
  return 'det' in j ? j.det : undefined;
}

/** Java class or package name, dots or slashes. */
const CLASS_RE = /^[A-Za-z_$][\w$]{0,255}([./][A-Za-z_$][\w$]{0,255}){0,64}$/;
/** .NET type name, allowing nested types (+) and generic arity (`1). */
const DOTNET_TYPE_RE = /^[A-Za-z_][\w]{0,255}([.+][A-Za-z_][\w]{0,255}){0,64}(`[0-9]{1,2})?$/;

// ---------------- jadx ----------------

export interface JadxInput {
  path: string;
  cacheDir?: string;
  timeoutMs?: number;
  /** skip resources (default true, much faster) */
  noResources?: boolean;
}

/** Decompile once per input SHA-256 into the cache and return the output folder. */
async function jadxRun(input: JadxInput) {
  const { path } = requireFile(input.path);
  const n = await need('jadx');
  if ('missing' in n) return { missing: n.missing };
  const sha = await sha256File(path);
  const outDir = join(cacheRoot(input.cacheDir), 'jadx', sha.slice(0, 32) + (input.noResources === false ? '-res' : ''));
  const done = join(outDir, '.revlens-done');
  return withLock(outDir, async () => {
    if (existsSync(done)) return { ok: true as const, outDir, cached: true, det: n.det, durationMs: 0 };
    await rm(outDir, { recursive: true, force: true });
    await ensureDir(outDir);
    const args = ['-q', '-d', outDir, '--show-bad-code', '-j', '2'];
    if (input.noResources !== false) args.push('--no-res');
    args.push(path);
    const java = await javaDet();
    const r = await runTool(n.det.path!, args, { timeoutMs: int(input.timeoutMs, 10 * 60_000, 5000, 2 * 3600_000), maxOutputBytes: 4 * 1024 * 1024, env: javaEnv(n.det, java) });
    const src = join(outDir, 'sources');
    if (!existsSync(src)) return { ok: false as const, error: `jadx produced no sources (${describeFailure(r)})`, det: n.det };
    await writeFile(done, new Date().toISOString(), 'utf8');
    return { ok: true as const, outDir, cached: false, det: n.det, durationMs: r.durationMs };
  });
}

function head(tool: string, det: Detection, file: string) {
  return { available: true as const, tool, toolVersion: det.version ?? null, file };
}

/**
 * Decompile an APK, DEX, JAR, AAR or class file with jadx. Without `className` it lists the
 * decompiled classes (paged). With `className` it returns that class's Java source.
 */
export async function jadxDecompile(input: JadxInput & { className?: string; limit?: number; offset?: number; maxChars?: number }) {
  if (input.className !== undefined && (typeof input.className !== 'string' || !CLASS_RE.test(input.className))) {
    throw new BridgeInputError('className must be a Java class name like com.example.Foo');
  }
  const r = await jadxRun(input);
  if ('missing' in r) return r.missing;
  const file = requireFile(input.path).path;
  if (!r.ok) return { available: true, tool: 'jadx', file, ok: false, error: r.error };
  const src = join(r.outDir, 'sources');
  const { files, truncated } = await listFiles(src, { filter: (p) => p.endsWith('.java'), maxFiles: 200_000 });
  const toClass = (p: string) => p.replace(/\.java$/, '').split('/').join('.');
  if (input.className !== undefined) {
    const want = input.className.replace(/\//g, '.').replace(/\$.*$/, '');
    const hit = files.find((f) => toClass(f.path) === want);
    if (!hit) {
      const near = files.filter((f) => toClass(f.path).toLowerCase().includes(want.split('.').pop()!.toLowerCase())).slice(0, 10).map((f) => toClass(f.path));
      return { ...head('jadx', r.det, file), ok: false, error: `class ${want} not found`, closeMatches: near };
    }
    const full = join(src, hit.path);
    if (!inside(src, hit.path)) throw new BridgeInputError('path escape');
    const text = await readFile(full, 'utf8');
    const max = int(input.maxChars, 200_000, 1000, 4_000_000);
    return { ...head('jadx', r.det, file), ok: true, cached: r.cached, className: want, sourcePath: full, truncated: text.length > max, source: text.slice(0, max) };
  }
  const offset = int(input.offset, 0, 0, 1e9);
  const limit = int(input.limit, 500, 0, 10_000);
  const all = files.map((f) => ({ className: toClass(f.path), size: f.size }));
  return { ...head('jadx', r.det, file), ok: true, cached: r.cached, outDir: r.outDir, total: all.length, listTruncated: truncated,
    offset, limit, more: offset + limit < all.length, classes: all.slice(offset, offset + limit) };
}

/**
 * Search jadx output for a literal string (case insensitive by default). Returns class, line number
 * and the line text so an agent can cite it. No regular expressions, so no ReDoS.
 */
export async function jadxSearch(input: JadxInput & { query: string; caseSensitive?: boolean; limit?: number }) {
  if (typeof input.query !== 'string' || input.query.length === 0 || input.query.length > 1024) throw new BridgeInputError('query must be 1 to 1024 characters');
  const r = await jadxRun(input);
  if ('missing' in r) return r.missing;
  const file = requireFile(input.path).path;
  if (!r.ok) return { available: true, tool: 'jadx', file, ok: false, error: r.error };
  const src = join(r.outDir, 'sources');
  const { files } = await listFiles(src, { filter: (p) => p.endsWith('.java'), maxFiles: 200_000 });
  const limit = int(input.limit, 200, 1, 5000);
  const cs = input.caseSensitive === true;
  const q = cs ? input.query : input.query.toLowerCase();
  const hits: { className: string; line: number; text: string }[] = [];
  let scanned = 0;
  let more = false;
  for (const f of files) {
    if (hits.length >= limit) { more = true; break; }
    if (f.size > 32 * 1024 * 1024) continue;
    scanned++;
    const text = await readFile(join(src, f.path), 'utf8');
    const ls = lines(text, 1_000_000);
    for (let i = 0; i < ls.length; i++) {
      const l = ls[i]!;
      if ((cs ? l : l.toLowerCase()).includes(q)) {
        if (hits.length >= limit) { more = true; break; }
        hits.push({ className: f.path.replace(/\.java$/, '').split('/').join('.'), line: i + 1, text: l.trim().slice(0, 500) });
      }
    }
  }
  return { ...head('jadx', r.det, file), ok: true, cached: r.cached, query: input.query, filesScanned: scanned, count: hits.length, more, hits };
}

// ---------------- apktool ----------------

/** Decode an APK with apktool: AndroidManifest.xml as text, apktool.yml, and the decoded file list. */
export async function apktoolDecode(input: { path: string; cacheDir?: string; timeoutMs?: number; limit?: number; noSources?: boolean }) {
  const { path } = requireFile(input.path);
  const n = await need('apktool');
  if ('missing' in n) return n.missing;
  const sha = await sha256File(path);
  const outDir = join(cacheRoot(input.cacheDir), 'apktool', sha.slice(0, 32));
  const java = await javaDet();
  const isJar = n.det.path!.endsWith('.jar');
  if (isJar && !java) return { available: false, tool: 'java', reason: 'apktool is a jar and Java was not found', install: installFor('java') };
  return withLock(outDir, async () => {
    const done = join(outDir, '.revlens-done');
    let cached = existsSync(done);
    let durationMs = 0;
    if (!cached) {
      await rm(outDir, { recursive: true, force: true });
      const args = ['d', '-f', '-o', outDir, ...(input.noSources ? ['-s'] : []), path];
      const r = isJar
        ? await runTool(java!.path!, ['-jar', n.det.path!, ...args], { timeoutMs: int(input.timeoutMs, 10 * 60_000, 5000, 7_200_000), env: javaEnv(n.det, java) })
        : await runTool(n.det.path!, args, { timeoutMs: int(input.timeoutMs, 10 * 60_000, 5000, 7_200_000), env: javaEnv(n.det, java) });
      durationMs = r.durationMs;
      if (!existsSync(join(outDir, 'AndroidManifest.xml'))) return { ...head('apktool', n.det, path), ok: false, error: `apktool failed (${describeFailure(r)})` };
      await writeFile(done, new Date().toISOString(), 'utf8');
    }
    const manifest = (await readFile(join(outDir, 'AndroidManifest.xml'), 'utf8')).slice(0, 2_000_000);
    const yml = existsSync(join(outDir, 'apktool.yml')) ? (await readFile(join(outDir, 'apktool.yml'), 'utf8')).slice(0, 200_000) : null;
    const { files, truncated } = await listFiles(outDir, { maxFiles: 100_000 });
    const limit = int(input.limit, 500, 0, 10_000);
    const pkg = /<manifest[^>]{0,4000}?\spackage="([\w.]{1,255})"/.exec(manifest)?.[1] ?? null;
    return { ...head('apktool', n.det, path), ok: true, cached, durationMs, outDir, package: pkg, manifest, apktoolYml: yml,
      fileCount: files.length, listTruncated: truncated || files.length > limit, files: files.slice(0, limit) };
  });
}

// ---------------- ILSpy ----------------

/**
 * Decompile a .NET assembly with ilspycmd. Without `typeName` it lists the types (classes,
 * interfaces, structs, enums, delegates). With `typeName` it returns that type as C#.
 */
export async function ilspyDecompile(input: { path: string; typeName?: string; timeoutMs?: number; maxChars?: number; limit?: number; offset?: number }) {
  const { path } = requireFile(input.path);
  const n = await need('ilspy');
  if ('missing' in n) return n.missing;
  const env = { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1' };
  const timeoutMs = int(input.timeoutMs, 5 * 60_000, 5000, 3_600_000);
  const max = int(input.maxChars, 200_000, 1000, 4_000_000);
  if (input.typeName !== undefined) {
    if (typeof input.typeName !== 'string' || !DOTNET_TYPE_RE.test(input.typeName)) throw new BridgeInputError('typeName must be a full .NET type name like Namespace.Type');
    const r = await runTool(n.det.path!, ['--disable-updatecheck', '-t', input.typeName, path], { timeoutMs, maxOutputBytes: 32 * 1024 * 1024, env });
    const code = r.stdout;
    if (r.code !== 0 || !code.trim()) return { ...head('ilspy', n.det, path), ok: false, error: describeFailure(r) };
    return { ...head('ilspy', n.det, path), ok: true, typeName: input.typeName, truncated: code.length > max, code: code.slice(0, max) };
  }
  const r = await runTool(n.det.path!, ['--disable-updatecheck', '-l', 'cisde', path], { timeoutMs, maxOutputBytes: 16 * 1024 * 1024, env });
  if (r.code !== 0) return { ...head('ilspy', n.det, path), ok: false, error: describeFailure(r) };
  const types = parseIlspyTypes(r.stdout);
  const offset = int(input.offset, 0, 0, 1e9);
  const limit = int(input.limit, 500, 0, 10_000);
  return { ...head('ilspy', n.det, path), ok: true, total: types.length, offset, limit, more: offset + limit < types.length, types: types.slice(offset, offset + limit) };
}

/** Parse `ilspycmd -l` lines such as "Class RevLens.Samples.Greeter". */
export function parseIlspyTypes(text: string): { kind: string; name: string }[] {
  const out: { kind: string; name: string }[] = [];
  for (const l of lines(text, 500_000)) {
    const m = /^(Class|Interface|Struct|Enum|Delegate)\s+(\S{1,2048})$/.exec(l.trim());
    if (m && m[2] !== '<Module>') out.push({ kind: m[1]!.toLowerCase(), name: m[2]! });
  }
  return out;
}
