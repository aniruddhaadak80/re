// Node-only entry: file path inputs, writing recovered trees, full ASAR extraction, Electron app folders,
// browser capture, and CLI commands. Import as '@revlens/webrt/node'.
import { readFile, writeFile, mkdir, stat, lstat, readdir, realpath, copyFile, open } from 'node:fs/promises';
import { join, resolve, dirname, sep } from 'node:path';
import { makeTools, type ToolDef, type ToolIO } from './tools.js';
import { readAsar, readAsarFile, isAsar } from './asar.js';
import { auditAsar, auditElectron, detectElectronVersionInBinary, type ElectronAudit } from './electron.js';
import { browserCapture, type CaptureOptions } from './capture.js';
import { InputError, safeRelPath, LIMITS } from './util.js';

export { browserCapture } from './capture.js';
export type { CaptureOptions, CaptureResult } from './capture.js';

/** Read a file with a size cap. */
export async function readFileCapped(path: string, maxBytes = LIMITS.maxInputBytes): Promise<Uint8Array> {
  const st = await stat(path);
  if (!st.isFile()) throw new InputError(`${path} is not a regular file`);
  if (st.size > maxBytes) throw new InputError(`${path} is ${st.size} bytes, over the ${maxBytes} byte limit`);
  return new Uint8Array(await readFile(path));
}

/** Resolve rel under root and refuse anything that would land outside it (including through symlinks). */
async function safeTarget(root: string, rel: string): Promise<string> {
  const clean = safeRelPath(rel);
  if (!clean) throw new InputError(`unsafe path ${rel}`);
  const absRoot = resolve(root);
  const target = resolve(absRoot, clean);
  if (target !== absRoot && !target.startsWith(absRoot + sep)) throw new InputError(`path escapes output folder: ${rel}`);
  await mkdir(dirname(target), { recursive: true });
  const realRoot = await realpath(absRoot);
  const realParent = await realpath(dirname(target));
  if (realParent !== realRoot && !realParent.startsWith(realRoot + sep)) throw new InputError(`path escapes output folder through a link: ${rel}`);
  try { if ((await lstat(target)).isSymbolicLink()) throw new InputError(`refusing to overwrite symlink ${rel}`); } catch (e) { if (e instanceof InputError) throw e; }
  return target;
}

/** Write files under outDir with traversal protection. Returns what was written. */
export async function writeTree(outDir: string, files: { path: string; content: string | Uint8Array }[], opts: { maxFiles?: number; maxTotalBytes?: number } = {}): Promise<{ outDir: string; written: number; bytes: number; skipped: string[] }> {
  await mkdir(outDir, { recursive: true });
  let written = 0, bytes = 0;
  const skipped: string[] = [];
  const maxFiles = opts.maxFiles ?? 50_000, maxTotal = opts.maxTotalBytes ?? 2 * 1024 * 1024 * 1024;
  for (const f of files) {
    if (written >= maxFiles) { skipped.push(f.path); continue; }
    const size = typeof f.content === 'string' ? Buffer.byteLength(f.content) : f.content.length;
    if (bytes + size > maxTotal) { skipped.push(f.path); continue; }
    try { const t = await safeTarget(outDir, f.path); await writeFile(t, f.content); written++; bytes += size; }
    catch { skipped.push(f.path); }
  }
  return { outDir: resolve(outDir), written, bytes, skipped: skipped.slice(0, 500) };
}

/** Extract an ASAR archive to a folder. Unpacked files are copied from <archive>.unpacked. Links are recorded, not followed. */
export async function extractAsar(asarPath: string, outDir: string, opts: { maxTotalBytes?: number } = {}): Promise<{ outDir: string; files: number; unpackedCopied: number; links: { path: string; target: string }[]; skipped: string[] }> {
  const bytes = await readFileCapped(asarPath);
  const arc = readAsar(bytes);
  const files: { path: string; content: Uint8Array }[] = [];
  const links: { path: string; target: string }[] = [];
  let unpackedCopied = 0;
  const skipped: string[] = [];
  for (const e of arc.entries) {
    if (e.type === 'link') { links.push({ path: e.path, target: e.link ?? '' }); continue; }
    if (e.type !== 'file') continue;
    if (e.unpacked) {
      const src = join(`${asarPath}.unpacked`, ...e.path.split('/').map((p) => safeRelPath(p)).filter(Boolean));
      try {
        const st = await lstat(src);
        if (!st.isFile()) { skipped.push(e.path); continue; }
        await copyFile(src, await safeTarget(outDir, e.path)); unpackedCopied++;
      } catch { skipped.push(e.path); }
      continue;
    }
    const data = readAsarFile(bytes, arc, e.path);
    if (data) files.push({ path: e.path, content: data });
  }
  const w = await writeTree(outDir, files, { maxTotalBytes: opts.maxTotalBytes });
  return { outDir: w.outDir, files: w.written, unpackedCopied, links, skipped: [...skipped, ...w.skipped] };
}

async function headBytes(path: string, n: number): Promise<Uint8Array> {
  const fh = await open(path, 'r');
  try { const b = Buffer.alloc(n); const { bytesRead } = await fh.read(b, 0, n, 0); return new Uint8Array(b.subarray(0, bytesRead)); } finally { await fh.close(); }
}

async function collectJs(dir: string, root: string, out: { path: string; code: string }[], depth = 0): Promise<void> {
  if (depth > 12 || out.length >= 2000) return;
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
    const p = join(dir, ent.name);
    if (ent.isDirectory()) await collectJs(p, root, out, depth + 1);
    else if (ent.isFile() && /\.(?:c|m)?js$/.test(ent.name)) {
      const st = await stat(p);
      if (st.size <= 4 * 1024 * 1024) out.push({ path: p.slice(root.length + 1).split(sep).join('/'), code: await readFile(p, 'utf8') });
    }
  }
}

/** Audit an Electron app given an .asar, a resources folder, an app install folder, or an unpacked app source folder. */
export async function auditElectronPath(path: string, opts: { binaryPath?: string } = {}): Promise<ElectronAudit & { input: string; asarPath?: string; binaryPath?: string }> {
  const st = await stat(path);
  let binary: Uint8Array | undefined;
  let binaryPath = opts.binaryPath;
  if (binaryPath) binary = await readFileCapped(binaryPath, 1024 * 1024 * 1024);
  let versionFile: string | undefined;
  if (st.isFile()) {
    const head = await headBytes(path, 64);
    if (isAsar(head)) return { ...auditAsar(await readFileCapped(path), { binary }), input: path, asarPath: path, binaryPath };
    // an Electron executable on its own
    const bin = await readFileCapped(path, 1024 * 1024 * 1024);
    const v = detectElectronVersionInBinary(bin);
    const a = auditElectron({ files: [], binary: bin });
    if (!v.electron && !a.fuses) throw new InputError('file is neither an ASAR archive nor an Electron executable');
    return { ...a, input: path, binaryPath: path };
  }
  const candidates = [join(path, 'resources', 'app.asar'), join(path, 'Contents', 'Resources', 'app.asar'), join(path, 'app.asar')];
  for (const c of candidates) {
    try {
      await stat(c);
      for (const vf of [join(path, 'version'), join(dirname(dirname(c)), 'version'), join(dirname(c), '..', 'version')]) {
        try { versionFile = (await readFile(vf, 'utf8')).trim().slice(0, 40); break; } catch { /* none */ }
      }
      if (!binary) {
        // look for the Electron executable next to resources/ (largest file at the install root)
        const root = dirname(dirname(c));
        try {
          const ents = await readdir(root, { withFileTypes: true });
          let best: { p: string; size: number } | undefined;
          for (const e of ents) if (e.isFile()) { const s = await stat(join(root, e.name)); if (s.size > 20 * 1024 * 1024 && (!best || s.size > best.size)) best = { p: join(root, e.name), size: s.size }; }
          if (best) { binaryPath = best.p; binary = await readFileCapped(best.p, 1024 * 1024 * 1024); }
        } catch { /* optional */ }
      }
      const a = auditAsar(await readFileCapped(c), { binary });
      if (!a.electronVersion && versionFile) { a.electronVersion = versionFile.replace(/^v/, ''); a.versionSource = 'version file'; }
      return { ...a, input: path, asarPath: c, binaryPath };
    } catch (e) { if (e instanceof InputError) throw e; }
  }
  // unpacked app source folder
  const files: { path: string; code: string }[] = [];
  await collectJs(resolve(path), resolve(path), files);
  let pkg: Record<string, unknown> | undefined;
  try { pkg = JSON.parse(await readFile(join(path, 'package.json'), 'utf8')) as Record<string, unknown>; } catch { /* optional */ }
  return { ...auditElectron({ files, packageJson: pkg, binary }), input: path, binaryPath };
}

const nodeExtra: ToolDef[] = [
  { name: '__write_tree', description: 'internal', inputSchema: {}, run: async (i: { outDir: string; files: { path: string; content: string }[] }) => writeTree(i.outDir, i.files) },
  { name: '__asar_extract_all', description: 'internal', inputSchema: {}, run: async (i: { path?: string; outDir: string }) => { if (!i.path) throw new InputError('path is required for outDir extraction'); return extractAsar(i.path, i.outDir); } },
  { name: '__electron_audit_path', description: 'internal', inputSchema: {}, run: async (i: { path: string; binaryPath?: string }) => auditElectronPath(i.path, { binaryPath: i.binaryPath }) },
  {
    name: 'web_browser_capture',
    description: 'Open a URL in a headless browser (Playwright, optional dependency, Node only) and record network requests as HAR entries, loaded and inline scripts with source, console messages, cookie names and flags, storage keys, WebSocket frames and service workers, then run endpoint and bundle analysis on the scripts. Strict timeouts; downloads are refused and temp files removed.',
    inputSchema: {
      url: { type: 'string', description: 'http or https URL to open.' },
      timeoutMs: { type: 'number', description: 'Total budget in ms (default 45000, max 300000).', optional: true },
      settleMs: { type: 'number', description: 'Wait after load for late requests (default 2000).', optional: true },
      browser: { type: 'string', description: 'chromium (default), firefox or webkit.', optional: true },
      includeSources: { type: 'boolean', description: 'Return script sources (capped at 200 KB each). Default false.', optional: true },
      limit: { type: 'number', description: 'Max HAR entries returned (default 200).', optional: true },
    },
    run: async (input: CaptureOptions & { url: string; includeSources?: boolean; limit?: number }) => {
      const r = await browserCapture(String(input.url), input);
      const lim = Math.max(1, Math.min(Number(input.limit ?? 200), 5000));
      return { ...r, har: { log: { ...r.har.log, entries: r.har.log.entries.slice(0, lim) } }, harEntryCount: r.har.log.entries.length, scripts: r.scripts.map((s) => ({ ...s, source: input.includeSources ? s.source?.slice(0, 200_000) : undefined })) };
    },
  },
];

const io: ToolIO = { readFile: (p, max) => readFileCapped(p, max), extra: nodeExtra };

/** Tools with file path support and browser capture. */
export const TOOLS: ToolDef[] = makeTools(io);

// ---------------- CLI ----------------
export interface CliCommand { name: string; usage: string; summary: string; run(argv: string[]): Promise<number> }

function parseArgs(argv: string[]): { pos: string[]; flags: Record<string, string | boolean> } {
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined];
      if (v !== undefined) flags[k] = v;
      else if (i + 1 < argv.length && !(argv[i + 1] as string).startsWith('--') && !['json', 'include-code', 'include-content', 'no-analyze', 'decode-escapes'].includes(k)) flags[k] = argv[++i] as string;
      else flags[k] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}
const num = (v: unknown) => (v === undefined || v === true ? undefined : Number(v));

type Human = (out: any) => string;
const tool = (n: string) => TOOLS.find((t) => t.name === n) as ToolDef;

function cmd(name: string, toolName: string, usage: string, build: (pos: string[], f: Record<string, string | boolean>) => Record<string, unknown>, human: Human): CliCommand {
  const t = tool(toolName);
  return {
    name, usage, summary: t.description.split('. ')[0] + '.',
    async run(argv) {
      const { pos, flags } = parseArgs(argv);
      if (flags.help || flags.h) { process.stdout.write(`${usage}\n\n${t.description}\n`); return 0; }
      try {
        const out = await t.run(build(pos, flags));
        process.stdout.write(flags.json ? JSON.stringify(out, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n' : human(out) + '\n');
        return 0;
      } catch (e) {
        process.stderr.write(`${name}: ${(e as Error).message}\n`);
        return e instanceof InputError ? 2 : 1;
      }
    },
  };
}
const needPath = (pos: string[]) => { if (!pos[0]) throw new InputError('missing file argument'); return pos[0]; };
const lines = (xs: (string | undefined | false)[]) => xs.filter((x): x is string => typeof x === 'string').join('\n');

export const CLI_COMMANDS: CliCommand[] = [
  cmd('js-beautify', 'web_js_beautify', 'revlens js-beautify <file.js> [--max-chars N] [--json]', (p, f) => ({ path: needPath(p), maxChars: num(f['max-chars']) ?? 2_000_000 }), (o) => o.code),
  cmd('js-deobfuscate', 'web_js_deobfuscate', 'revlens js-deobfuscate <file.js> [--json]', (p, f) => ({ path: needPath(p), maxChars: num(f['max-chars']) ?? 2_000_000 }), (o) => lines([`// RevLens deobfuscate: ${o.stats.stringsDecoded} strings decoded${o.stringArray ? ` from ${o.stringArray.arrayName} (${o.stringArray.encoding}, rotated ${o.stringArray.rotated})` : ''}, ${o.stats.proxiesInlined} proxies inlined, ${o.stats.helpersRemoved} helpers removed`, ...o.notes.map((n: string) => `// note: ${n}`), o.code])),
  cmd('js-bundle', 'web_bundle_modules', 'revlens js-bundle <bundle.js> [--map file.map] [--include-code] [--limit N] [--json]', (p, f) => ({ path: needPath(p), sourceMapPath: typeof f.map === 'string' ? f.map : undefined, includeCode: !!f['include-code'], limit: num(f.limit), offset: num(f.offset) }), (o) => lines([`bundler: ${o.bundler} (confidence ${o.confidence}), ${o.moduleCount} modules${o.chunkIds.length ? `, chunk ${o.chunkIds.join(',')}` : ''}`, ...o.modules.items.map((m: any) => `  ${String(m.id).padEnd(12)} ${m.path ?? '?'}  line ${m.line}, ${m.size} B${m.deps.length ? `, deps ${m.deps.join(',')}` : ''}${m.exports.length ? `, exports ${m.exports.join(',')}` : ''}`), o.imports.length ? `imports: ${o.imports.map((i: any) => i.source).join(', ')}` : undefined])),
  cmd('js-endpoints', 'web_js_endpoints', 'revlens js-endpoints <file.js> [--json]', (p, f) => ({ path: needPath(p), limit: num(f.limit) }), (o) => lines([...o.calls.items.map((c: any) => `${String(c.line).padStart(6)}  ${c.api}${c.method ? ' ' + c.method : ''} ${c.url ?? '(dynamic)'}`), `hosts: ${o.hosts.join(', ') || '-'}`, `env: ${o.envNames.join(', ') || '-'}`, `flags: ${o.featureFlags.map((x: any) => x.name).join(', ') || '-'}`, `dynamic code: ${o.dynamicCode.map((d: any) => `${d.api}@${d.line}`).join(', ') || '-'}`])),
  cmd('sourcemap-recover', 'web_sourcemap_recover', 'revlens sourcemap-recover <file.map|file.js> [--out dir] [--json]', (p, f) => ({ path: needPath(p), outDir: typeof f.out === 'string' ? f.out : undefined, limit: num(f.limit) }), (o) => lines([`${o.withContent}/${o.sources} sources with content (${o.coverage}%), ${o.mappings} mapping segments`, ...Object.entries(o.tree).map(([k, v]) => `  ${k}: ${v}`), o.written ? `wrote ${o.written.written} files to ${o.written.outDir}` : undefined])),
  cmd('asar-list', 'web_asar_list', 'revlens asar-list <app.asar> [--filter text] [--limit N] [--json]', (p, f) => ({ path: needPath(p), filter: typeof f.filter === 'string' ? f.filter : undefined, limit: num(f.limit) ?? 10_000 }), (o) => lines([`${o.files} files, ${o.dirs} dirs, ${o.unpackedFiles} unpacked, header ${o.headerSize} B`, ...o.entries.items.map((e: any) => `  ${e.type === 'dir' ? 'd' : e.type === 'link' ? 'l' : e.unpacked ? 'u' : '-'} ${String(e.size).padStart(10)} ${e.offset !== undefined ? ('0x' + e.offset.toString(16)).padStart(10) : '          '} ${e.path}${e.link ? ' -> ' + e.link : ''}`)])),
  cmd('asar-extract', 'web_asar_extract', 'revlens asar-extract <app.asar> (--out dir | --file path) [--json]', (p, f) => ({ path: needPath(p), outDir: typeof f.out === 'string' ? f.out : undefined, file: typeof f.file === 'string' ? f.file : undefined }), (o) => (o.outDir ? `extracted ${o.files} files (+${o.unpackedCopied} unpacked) to ${o.outDir}${o.skipped.length ? `, skipped ${o.skipped.length}` : ''}` : o.text ?? `[binary ${o.size} bytes, use --json for base64]`)),
  cmd('electron-audit', 'web_electron_audit', 'revlens electron-audit <app.asar|app folder> [--binary electron-exe] [--json]', (p, f) => ({ path: needPath(p), binaryPath: typeof f.binary === 'string' ? f.binary : undefined }), (o) => lines([`Electron ${o.electronVersion ?? 'unknown'}${o.versionSource ? ` (${o.versionSource})` : ''}, ${o.filesScanned} files scanned, ${o.windows.length} windows, ${o.ipc.main.length} IPC handlers`, o.fuses ? `fuses: ${Object.entries(o.fuses.fuses).map(([k, v]) => `${k}=${v}`).join(' ')}` : undefined, ...o.findings.map((x: any) => `  [${x.severity}] ${x.title}${x.evidence[0]?.path ? ` (${x.evidence[0].path}${x.evidence[0].snippet ? ' ' + String(x.evidence[0].snippet).slice(0, 60) : ''})` : ''}`)])),
  cmd('browser-capture', 'web_browser_capture', 'revlens browser-capture <url> [--timeout ms] [--browser chromium] [--json]', (p, f) => ({ url: needPath(p), timeoutMs: num(f.timeout), browser: typeof f.browser === 'string' ? f.browser : undefined }), (o) => lines([`${o.finalUrl ?? o.url} "${o.title ?? ''}" in ${o.durationMs} ms with ${o.browser} ${o.browserVersion ?? ''}`, `${o.harEntryCount} requests, ${o.scripts.length} scripts, ${o.console.length} console messages, ${o.cookies.length} cookies, ${o.webSockets.length} websockets`, ...o.scripts.slice(0, 50).map((s: any) => `  ${s.inline ? 'inline' : 'script'} ${s.size} B ${s.url}${s.endpoints ? `  calls=${s.endpoints.counts.calls} hosts=${s.endpoints.hosts.join(',')}` : ''}`), ...o.warnings.map((w: string) => `  warning: ${w}`)])),
  cmd('pcap-summary', 'web_pcap_summary', 'revlens pcap-summary <capture.pcap|.pcapng> [--json]', (p, f) => ({ path: needPath(p), limit: num(f.limit) }), (o) => lines([`${o.format}, ${o.packetCount} packets, ${o.totalBytes} bytes, ${o.durationSeconds}s, ${o.flowCount} flows`, `protocols: ${Object.entries(o.protocols).map(([k, v]) => `${k}=${v}`).join(' ')}`, ...o.dns.items.filter((d: any) => !d.response).map((d: any) => `  dns #${d.packet} ${d.questions.map((q: any) => `${q.type}? ${q.name}`).join(', ')}`), ...o.dns.items.filter((d: any) => d.response).map((d: any) => `  dns #${d.packet} answer ${d.answers.map((a: any) => `${a.type} ${a.data}`).join(', ')}`), ...o.http.items.map((h: any) => `  http #${h.packet} ${h.kind === 'request' ? `${h.method} ${h.host ?? ''}${h.target}` : `${h.status}`}`), ...o.tls.items.map((t: any) => `  tls #${t.packet} sni=${t.sni ?? '-'} ja3=${t.ja3Hash}`)])),
  cmd('pcap-flows', 'web_pcap_flows', 'revlens pcap-flows <capture> [--proto tcp|udp] [--host ip] [--limit N] [--json]', (p, f) => ({ path: needPath(p), proto: typeof f.proto === 'string' ? f.proto : undefined, host: typeof f.host === 'string' ? f.host : undefined, limit: num(f.limit) }), (o) => lines(o.flows.items.map((x: any) => `${x.proto} ${x.client}:${x.clientPort} -> ${x.server}:${x.serverPort} ${x.service ?? ''} pkts ${x.packetsToServer}/${x.packetsToClient} bytes ${x.bytesToServer}/${x.bytesToClient}`))),
  cmd('sqlite-tables', 'web_sqlite_tables', 'revlens sqlite-tables <db.sqlite> [--samples N] [--json]', (p, f) => ({ path: needPath(p), samples: num(f.samples) }), (o) => lines([`page size ${o.header.pageSize}, ${o.header.pageCount} pages, ${o.header.encoding}`, ...o.tables.map((t: any) => `  ${t.name} (${t.rowCount ?? '?'} rows${t.withoutRowid ? ', without rowid' : ''}): ${t.columns.map((c: any) => `${c.name}${c.type ? ' ' + c.type : ''}${c.pk ? ' pk' : ''}`).join(', ')}`), ...o.views.map((v: any) => `  view ${v.name}`)])),
  cmd('sqlite-query', 'web_sqlite_query', 'revlens sqlite-query <db.sqlite> "<SELECT ...>" [--max-rows N] [--json]', (p, f) => ({ path: needPath(p), sql: p[1], maxRows: num(f['max-rows']) }), (o) => lines([o.columns.join('\t'), ...o.rows.map((r: unknown[]) => r.map((v) => (v && typeof v === 'object' ? JSON.stringify(v) : String(v))).join('\t')), `(${o.rowCount} rows${o.truncated ? ', truncated' : ''})`])),
  cmd('har-summary', 'web_har_summary', 'revlens har-summary <file.har> [--json]', (p, f) => ({ path: needPath(p), limit: num(f.limit) }), (o) => lines([`${o.entries} entries${o.creator ? ` from ${o.creator}` : ''}, ${o.totalResponseBytes} response bytes`, `statuses: ${Object.entries(o.statuses).map(([k, v]) => `${k}=${v}`).join(' ')}`, ...o.hosts.map((h: any) => `  ${h.thirdParty ? '3p ' : '   '}${h.host} ${h.requests} req`), ...o.endpoints.map((e: any) => `  api ${e.method} ${e.host}${e.pattern} x${e.count}`), ...o.redirects.map((r: any) => `  redirect ${r.status} ${r.from} -> ${r.to}`), ...o.missingSecurityHeaders.map((m: any) => `  missing headers on ${m.url}: ${m.missing.join(', ')}`)])),
];

export * from './index.js';
