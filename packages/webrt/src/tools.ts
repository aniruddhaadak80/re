// Agent tool definitions. makeTools() builds the list around an IO adapter so the same tools work in a
// browser worker (bytes or text inputs) and in Node (file paths, output folders, browser capture).
import { beautify } from './js/print.js';
import { deobfuscate } from './js/deobfuscate.js';
import { unpackBundle } from './js/bundle.js';
import { findEndpoints } from './js/endpoints.js';
import { recoverSources, inlineSourceMap, parseSourceMap, sourceMapUrl, type RawSourceMap } from './sourcemap.js';
import { readAsar, readAsarFile } from './asar.js';
import { auditAsar } from './electron.js';
import { analyzePcap } from './pcap.js';
import { SqliteFile, runSelect, sampleRows, jsonValue } from './sqlite.js';
import { analyzeHar } from './har.js';
import { scanWebMcpScript, scanHtmlForMcp, classifyWellKnown } from './webmcp.js';
import { compareCaptures } from './compare.js';
import { makeR3Tools, type TreeIO } from './tools-r3.js';
import { InputError, base64ToBytes, bytesToBase64, decodeUtf8, encodeUtf8, page, clampLimit, LIMITS } from './util.js';

export type SchemaType = 'string' | 'number' | 'boolean' | 'array' | 'object';
export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, { type: SchemaType; description: string; optional?: boolean }>;
  run: (input: any) => Promise<unknown>;
}

export interface ToolIO {
  /** read a file path, or undefined when paths are not supported (browser) */
  readFile?: (path: string, maxBytes: number) => Promise<Uint8Array>;
  /** list of extra tools only available on this platform */
  extra?: ToolDef[];
  /** folder reading for the graph, source compare and export shape tools (Node) */
  readTree?: TreeIO['readTree'];
  isDir?: TreeIO['isDir'];
}

const SRC = {
  path: { type: 'string' as const, description: 'File path to read (Node only).', optional: true },
  base64: { type: 'string' as const, description: 'File bytes as base64, when no path is given.', optional: true },
  text: { type: 'string' as const, description: 'File content as text, when no path is given.', optional: true },
};
const PAGING = {
  offset: { type: 'number' as const, description: 'Skip this many items (paging).', optional: true },
  limit: { type: 'number' as const, description: `Return at most this many items (default ${LIMITS.defaultLimit}).`, optional: true },
};

export async function loadBytes(input: { path?: string; base64?: string; text?: string; bytes?: Uint8Array }, io: ToolIO, maxBytes = LIMITS.maxInputBytes): Promise<Uint8Array> {
  if (input.bytes instanceof Uint8Array) return input.bytes;
  if (typeof input.base64 === 'string') { const b = base64ToBytes(input.base64); if (b.length > maxBytes) throw new InputError('input too large'); return b; }
  if (typeof input.text === 'string') { if (input.text.length > maxBytes) throw new InputError('input too large'); return encodeUtf8(input.text); }
  if (typeof input.path === 'string') {
    if (!io.readFile) throw new InputError('file paths are only supported in Node; pass base64 or text');
    return io.readFile(input.path, maxBytes);
  }
  throw new InputError('give one of path, base64 or text');
}

async function loadText(input: { path?: string; base64?: string; text?: string }, io: ToolIO, max = LIMITS.maxJsBytes): Promise<string> {
  if (typeof input.text === 'string') return input.text;
  return decodeUtf8(await loadBytes(input, io, max));
}

function window(code: string, input: { charOffset?: number; maxChars?: number }): { code: string; totalChars: number; charOffset: number; truncated: boolean } {
  const off = Math.max(0, Math.floor(input.charOffset ?? 0));
  const max = Math.max(1, Math.min(Math.floor(input.maxChars ?? 200_000), 2_000_000));
  return { code: code.slice(off, off + max), totalChars: code.length, charOffset: off, truncated: off + max < code.length };
}

const CODE_WINDOW = {
  charOffset: { type: 'number' as const, description: 'Start of the returned code window in characters.', optional: true },
  maxChars: { type: 'number' as const, description: 'Size of the returned code window (default 200000).', optional: true },
};

async function loadMap(input: { sourceMapPath?: string; sourceMap?: string; path?: string }, io: ToolIO, js?: string): Promise<RawSourceMap | undefined> {
  if (typeof input.sourceMap === 'string') return parseSourceMap(input.sourceMap);
  if (typeof input.sourceMapPath === 'string') return parseSourceMap(decodeUtf8(await loadBytes({ path: input.sourceMapPath }, io, 256 * 1024 * 1024)));
  if (js) {
    const inline = inlineSourceMap(js);
    if (inline) return inline;
    // Node: follow a relative sourceMappingURL next to the script
    const ref = sourceMapUrl(js);
    const base = (input as { path?: string }).path;
    if (ref && base && io.readFile && !/^[a-z][a-z0-9+.-]*:/i.test(ref) && !ref.split(/[\\/]/).includes('..')) {
      const dir = base.replace(/[^/\\]*$/, '');
      try { return parseSourceMap(decodeUtf8(await io.readFile(dir + ref.split('?')[0], 256 * 1024 * 1024))); } catch { /* map not shipped */ }
    }
  }
  return undefined;
}

export function makeTools(io: ToolIO = {}): ToolDef[] {
  const tools: ToolDef[] = [
    {
      name: 'web_js_beautify',
      description: 'Reformat minified JavaScript into readable code and decode hex and unicode escapes in literals. Behavior is unchanged. Returns a paged code window.',
      inputSchema: { ...SRC, decodeEscapes: { type: 'boolean', description: 'Rewrite \\x and \\u escapes as plain characters (default true).', optional: true }, ...CODE_WINDOW },
      run: async (input) => {
        const r = beautify(await loadText(input, io), { decodeEscapes: input.decodeEscapes });
        return { ...window(r.code, input), lines: r.lines, literalsNormalized: r.literalsNormalized, parserErrors: r.parserErrors };
      },
    },
    {
      name: 'web_js_deobfuscate',
      description: 'Statically deobfuscate JavaScript: decode javascript-obfuscator string arrays (plain, base64, rc4) with rotation and wrapper functions, inline proxy objects, unflatten switch dispatchers, fold constants and drop dead branches. Never executes the input.',
      inputSchema: { ...SRC, ...CODE_WINDOW, maxStrings: { type: 'number', description: 'How many decoded strings to list (default 200).', optional: true } },
      run: async (input) => {
        const r = deobfuscate(await loadText(input, io));
        return { ...window(r.code, input), changed: r.changed, stringArray: r.stringArray, stats: r.stats, decodedStrings: r.decodedStrings.slice(0, clampLimit(input.maxStrings)), decodedStringCount: r.decodedStrings.length, notes: r.notes, parserErrors: r.parserErrors };
      },
    },
    {
      name: 'web_bundle_modules',
      description: 'Split a webpack 4/5 bundle or jsonp chunk, browserify bundle or esbuild bundle into modules with ids, recovered source paths, dependencies and exports. Uses a source map (inline, sourceMap text or sourceMapPath) to name numeric webpack ids. Lists chunk-level imports for rollup and vite output.',
      inputSchema: { ...SRC, sourceMapPath: { type: 'string', description: 'Path to the .map file (Node only).', optional: true }, sourceMap: { type: 'string', description: 'Source map JSON text.', optional: true }, includeCode: { type: 'boolean', description: 'Include each module body as readable code (capped).', optional: true }, ...PAGING },
      run: async (input) => {
        const code = await loadText(input, io);
        const map = await loadMap(input, io, code);
        const r = unpackBundle(code, { includeCode: !!input.includeCode, sourceMap: map, maxModuleCode: 50_000 });
        const { modules, ...rest } = r;
        return { ...rest, moduleCount: modules.length, modules: page(modules, input.offset, input.limit) };
      },
    },
    {
      name: 'web_js_endpoints',
      description: 'Find API endpoints and network calls in JavaScript (fetch, XHR, axios, jQuery, WebSocket, EventSource, sendBeacon, socket.io, workers), plus eval/Function use, process.env and import.meta.env names, feature flag checks, storage keys and postMessage listeners. Each hit has line, column and offset.',
      inputSchema: { ...SRC, ...PAGING },
      run: async (input) => {
        const r = findEndpoints(await loadText(input, io));
        return { ...r, calls: page(r.calls, input.offset, input.limit), urls: page(r.urls, input.offset, input.limit) };
      },
    },
    {
      name: 'web_sourcemap_recover',
      description: 'Recover original source files from a source map (or a script with an inline map): safe relative paths, sizes, a folder tree summary and optionally file contents. In Node, outDir writes the tree to disk.',
      inputSchema: { ...SRC, includeContent: { type: 'boolean', description: 'Return file contents (capped per file).', optional: true }, outDir: { type: 'string', description: 'Write recovered files under this folder (Node only).', optional: true }, ...PAGING },
      run: async (input) => {
        const text = await loadText(input, io, 256 * 1024 * 1024);
        let map: RawSourceMap | undefined;
        const trimmed = text.trimStart();
        if (trimmed.startsWith('{') || trimmed.startsWith(")]}'")) map = parseSourceMap(text);
        else map = inlineSourceMap(text);
        if (!map) { const ref = sourceMapUrl(text); throw new InputError(ref ? `script references an external source map at ${ref}; pass that file` : 'no source map found'); }
        const r = recoverSources(map, { includeContent: !!input.includeContent || !!input.outDir });
        let written: unknown;
        if (input.outDir) {
          const w = io.extra?.find((t) => t.name === '__write_tree');
          if (!w) throw new InputError('outDir is only supported in Node');
          written = await w.run({ outDir: input.outDir, files: r.files.map((f) => ({ path: f.path, content: f.content ?? '' })) });
        }
        const files = r.files.map((f) => ({ ...f, content: input.includeContent && f.content !== undefined ? f.content.slice(0, 100_000) : undefined }));
        return { ...r, files: page(files, input.offset, input.limit), written };
      },
    },
    {
      name: 'web_asar_list',
      description: 'List the files in an Electron ASAR archive with sizes, absolute data offsets, unpacked and executable flags, links and integrity hashes.',
      inputSchema: { path: SRC.path, base64: SRC.base64, filter: { type: 'string', description: 'Only entries whose path contains this text.', optional: true }, ...PAGING },
      run: async (input) => {
        const a = readAsar(await loadBytes(input, io));
        const entries = input.filter ? a.entries.filter((e) => e.path.includes(String(input.filter))) : a.entries;
        return { ...a, entries: page(entries, input.offset, input.limit) };
      },
    },
    {
      name: 'web_asar_extract',
      description: 'Extract files from an ASAR archive. With file, returns that file (text or base64). In Node, outDir extracts everything (unpacked files copied from the .asar.unpacked folder) with path traversal blocked.',
      inputSchema: { path: SRC.path, base64: SRC.base64, file: { type: 'string', description: 'One archive path to return.', optional: true }, outDir: { type: 'string', description: 'Extract the whole archive under this folder (Node only).', optional: true }, maxBytes: { type: 'number', description: 'Cap for a returned file (default 1 MiB).', optional: true } },
      run: async (input) => {
        if (input.outDir) {
          const w = io.extra?.find((t) => t.name === '__asar_extract_all');
          if (!w) throw new InputError('outDir is only supported in Node');
          return w.run(input);
        }
        if (!input.file) throw new InputError('give file, or outDir in Node');
        const bytes = await loadBytes(input, io);
        const a = readAsar(bytes);
        const data = readAsarFile(bytes, a, String(input.file));
        if (!data) return { file: input.file, unpacked: true, note: 'file is stored in the .asar.unpacked folder next to the archive' };
        const max = Math.min(Number(input.maxBytes ?? 1 << 20), 16 << 20);
        const slice = data.subarray(0, max);
        const text = decodeUtf8(slice);
        const isText = !/[\u0000-\u0008\u000e-\u001f]/.test(text.slice(0, 4096));
        return { file: input.file, size: data.length, offset: a.entries.find((e) => e.path === input.file)?.offset, truncated: data.length > max, ...(isText ? { text } : { base64: bytesToBase64(slice) }) };
      },
    },
    {
      name: 'web_electron_audit',
      description: 'Security review of an Electron app (ASAR archive, or in Node an app folder or resources folder): Electron version, fuses, BrowserWindow webPreferences (nodeIntegration, contextIsolation, sandbox, webSecurity, remote module), contextBridge exposure, IPC channels, shell.openExternal, custom protocols, auto-update URLs and risky switches.',
      inputSchema: { path: SRC.path, base64: SRC.base64, binaryPath: { type: 'string', description: 'Electron executable for version and fuses (Node only).', optional: true } },
      run: async (input) => {
        const w = io.extra?.find((t) => t.name === '__electron_audit_path');
        if (w && input.path) return w.run(input);
        const bytes = await loadBytes(input, io);
        return auditAsar(bytes);
      },
    },
    {
      name: 'web_pcap_summary',
      description: 'Summarize a PCAP or PCAPNG capture: packet and byte counts, time range, protocol mix, top talkers and ports, DNS queries and answers, HTTP/1.x requests and responses, TLS ClientHello SNI, ALPN and JA3 hash, ServerHello JA3S.',
      inputSchema: { path: SRC.path, base64: SRC.base64, ...PAGING },
      run: async (input) => {
        const r = analyzePcap(await loadBytes(input, io));
        const { flows, dns, http, tls, tlsServer, ...rest } = r;
        return { ...rest, flowCount: flows.length, dns: page(dns, input.offset, input.limit), http: page(http, input.offset, input.limit), tls: page(tls, input.offset, input.limit), tlsServer: page(tlsServer, input.offset, input.limit), dnsNames: [...new Set(dns.flatMap((d) => d.questions.map((q) => q.name)))].slice(0, 500), sniNames: [...new Set(tls.map((x) => x.sni).filter(Boolean))].slice(0, 500) };
      },
    },
    {
      name: 'web_pcap_flows',
      description: 'List TCP and UDP conversations in a capture with client and server endpoints, service guess, packet and byte counts per direction, first packet index and TCP flags seen.',
      inputSchema: { path: SRC.path, base64: SRC.base64, proto: { type: 'string', description: 'tcp or udp.', optional: true }, host: { type: 'string', description: 'Only flows with this IP on either side.', optional: true }, ...PAGING },
      run: async (input) => {
        const r = analyzePcap(await loadBytes(input, io));
        let flows = r.flows;
        if (input.proto) flows = flows.filter((f) => f.proto === input.proto);
        if (input.host) flows = flows.filter((f) => f.client === input.host || f.server === input.host);
        return { format: r.format, packetCount: r.packetCount, flows: page(flows.sort((a, b) => b.bytes - a.bytes), input.offset, input.limit) };
      },
    },
    {
      name: 'web_sqlite_tables',
      description: 'Read a SQLite 3 database file with a pure TypeScript page parser: header, tables with columns, primary keys, row counts, indexes, views and triggers, and sample rows.',
      inputSchema: { path: SRC.path, base64: SRC.base64, samples: { type: 'number', description: 'Sample rows per table (default 3, max 50).', optional: true } },
      run: async (input) => {
        const db = new SqliteFile(await loadBytes(input, io));
        const n = Math.max(0, Math.min(Number(input.samples ?? 3), 50));
        const tables = db.tables().map((t) => { let sample: unknown; try { sample = sampleRows(db, t.name, n); } catch (e) { sample = { error: (e as Error).message }; } return { ...t, sample }; });
        const schema = db.schema();
        return { header: db.header, tables, indexes: schema.filter((o) => o.type === 'index').map((o) => ({ name: o.name, table: o.tblName, sql: o.sql })), views: schema.filter((o) => o.type === 'view').map((o) => ({ name: o.name, sql: o.sql })), triggers: schema.filter((o) => o.type === 'trigger').map((o) => ({ name: o.name, table: o.tblName, sql: o.sql })) };
      },
    },
    {
      name: 'web_sqlite_query',
      description: 'Run one read-only SELECT on a SQLite file: SELECT cols|*|COUNT(*) FROM table [WHERE ...] [ORDER BY col [DESC]] [LIMIT n [OFFSET m]]. WHERE supports comparisons, AND/OR/NOT, LIKE, GLOB, IN, BETWEEN and IS NULL. Anything that could write is rejected by the parser; SQLite itself is never run.',
      inputSchema: { path: SRC.path, base64: SRC.base64, sql: { type: 'string', description: 'The SELECT statement.' }, maxRows: { type: 'number', description: 'Row cap (default 200, max 10000).', optional: true } },
      run: async (input) => {
        if (typeof input.sql !== 'string') throw new InputError('sql is required');
        const db = new SqliteFile(await loadBytes(input, io));
        const r = runSelect(db, input.sql, { maxRows: input.maxRows });
        return { ...r, rows: r.rows.map((row) => row.map(jsonValue)) };
      },
    },
    {
      name: 'web_har_summary',
      description: 'Summarize a HAR file: hosts (third-party marked), API endpoint patterns, methods, statuses, MIME types, redirects, slowest requests, auth header schemes and cookie names (values never returned), missing security headers, mixed content, WebSockets, and endpoints found inside captured scripts.',
      inputSchema: { ...SRC, analyzeScripts: { type: 'boolean', description: 'Run endpoint analysis on script bodies in the HAR (default true).', optional: true }, limit: PAGING.limit },
      run: async (input) => analyzeHar(await loadText(input, io, 512 * 1024 * 1024), { analyzeScripts: input.analyzeScripts, limit: clampLimit(input.limit) }),
    },
    {
      name: 'web_webmcp_scan',
      description: 'Static WebMCP scan of one HTML page or script: navigator.modelContext provideContext and registerTool calls with tool names, descriptions and input schema fields, declarative tool forms (toolname and tooldescription), MCP link and meta tags, and MCP-B polyfill imports. Nothing is run.',
      inputSchema: { ...SRC, kind: { type: 'string', description: 'html or js (default: guessed from the content).', optional: true }, limit: PAGING.limit },
      run: async (input) => {
        const text = await loadText(input, io, 16 * 1024 * 1024);
        const isHtml = input.kind ? input.kind === 'html' : /^\s*(?:<!doctype|<html|<head|<body|<)/i.test(text.slice(0, 2000));
        const lim = clampLimit(input.limit);
        if (!isHtml) { const r = scanWebMcpScript(text, { source: input.path }); return { kind: 'js', ...r, tools: r.tools.slice(0, lim) }; }
        const h = scanHtmlForMcp(text);
        const tools = h.inlineScripts.flatMap((code, i) => { try { return scanWebMcpScript(code, { source: `inline-${i}` }).tools; } catch { return []; } });
        return { kind: 'html', links: h.links, meta: h.meta, forms: h.forms, scriptSrcs: h.scriptSrcs.slice(0, lim), inlineScripts: h.inlineScripts.length, tools: tools.slice(0, lim) };
      },
    },
    {
      name: 'web_wellknown_classify',
      description: 'Classify a fetched well-known discovery document (MCP server card, MCP endpoint list, AI plugin manifest, A2A agent card, OAuth protected resource metadata, llms.txt) and pull out its name, endpoints and tool names.',
      inputSchema: { path: { type: 'string', description: 'The well-known path, for example /.well-known/mcp.json.' }, text: { type: 'string', description: 'Document body.' }, status: { type: 'number', description: 'HTTP status (default 200).', optional: true }, contentType: { type: 'string', description: 'Content-Type header.', optional: true } },
      run: async (input) => classifyWellKnown(String(input.path), Number(input.status ?? 200), input.contentType, String(input.text ?? '').slice(0, 2 * 1024 * 1024)),
    },
    {
      name: 'web_capture_compare',
      description: 'Compare two captures (RevLens scenario capture.json, web_browser_capture output, or HAR): endpoints added and removed with id-normalized paths, status changes, request and response header changes, scripts added, removed or changed by sha256, console differences and per-step screenshot pixel diffs, with a 0 to 1 similarity score.',
      inputSchema: { aPath: { type: 'string', description: 'First capture JSON file (Node only).', optional: true }, bPath: { type: 'string', description: 'Second capture JSON file (Node only).', optional: true }, aText: { type: 'string', description: 'First capture as JSON text.', optional: true }, bText: { type: 'string', description: 'Second capture as JSON text.', optional: true }, threshold: { type: 'number', description: 'Largest channel difference (0 to 255) still counted as the same pixel (default 0).', optional: true }, limit: PAGING.limit },
      run: async (input) => {
        const special = io.extra?.find((t) => t.name === '__capture_compare_paths');
        if ((input.aPath || input.bPath) && special) return special.run(input);
        if (typeof input.aText !== 'string' || typeof input.bText !== 'string') throw new InputError('give aText and bText (or aPath and bPath in Node)');
        let a: unknown, b: unknown;
        try { a = JSON.parse(input.aText); b = JSON.parse(input.bText); } catch { throw new InputError('captures must be JSON'); }
        return compareCaptures(a as never, b as never, { threshold: input.threshold, limit: input.limit });
      },
    },
  ];
  tools.push(...makeR3Tools(io));
  for (const e of io.extra ?? []) if (!e.name.startsWith('__')) tools.push(e);
  return tools;
}
