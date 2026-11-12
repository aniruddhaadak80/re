// Agent tools for the round 3 features that run anywhere (browser worker or Node): import graphs,
// source map tracing, source to bundle comparison, export shapes, the static and observed endpoint
// join and building a replay environment. File and folder paths work when the IO adapter has them.
import type { ToolDef, ToolIO } from './tools.js';
import { buildImportGraph, bundleImportGraph, sourceMapImportGraph, importGraphMermaid } from './js/imports.js';
import { traceSourceLocation, compareSourceToBundle } from './js/sourcecompare.js';
import { moduleExportShapes, packageExportShapes, bundleExportShapes, compareExportShapes, type ExportShape } from './js/exportshape.js';
import { compareStaticAndObservedEndpoints } from './endpointjoin.js';
import { buildEnvironment } from './env.js';
import { inlineSourceMap, sourceMapUrl } from './sourcemap.js';
import { InputError, decodeUtf8, base64ToBytes, bytesToBase64, page, clampLimit } from './util.js';

export interface TreeIO {
  /** read every text file under a folder (relative paths, capped), Node only */
  readTree?: (path: string, opts?: { maxFiles?: number; exts?: RegExp; includeNodeModules?: boolean }) => Promise<{ path: string; code: string }[]>;
  isDir?: (path: string) => Promise<boolean>;
}

type IO = ToolIO & TreeIO;

async function textOf(i: { path?: string; text?: string; base64?: string }, io: IO, max = 64 * 1024 * 1024): Promise<string> {
  if (typeof i.text === 'string') return i.text;
  if (typeof i.base64 === 'string') return decodeUtf8(base64ToBytes(i.base64));
  if (typeof i.path === 'string') { if (!io.readFile) throw new InputError('paths need Node; pass text or base64'); return decodeUtf8(await io.readFile(i.path, max)); }
  throw new InputError('give path, text or base64');
}

async function filesOf(i: { files?: { path: string; code?: string; content?: string }[]; path?: string; folder?: string }, io: IO, opts: { includeNodeModules?: boolean } = {}): Promise<{ path: string; code: string }[] | undefined> {
  if (Array.isArray(i.files)) return i.files.slice(0, 20_000).map((f) => ({ path: String(f.path), code: String(f.code ?? f.content ?? '') }));
  const dir = i.folder ?? i.path;
  if (typeof dir === 'string' && io.isDir && io.readTree && await io.isDir(dir)) return io.readTree(dir, { includeNodeModules: opts.includeNodeModules });
  return undefined;
}

async function mapOf(i: { sourceMap?: string; sourceMapPath?: string; bundlePath?: string; bundle?: string }, io: IO, bundleText?: string): Promise<string | undefined> {
  if (typeof i.sourceMap === 'string') return i.sourceMap;
  if (typeof i.sourceMapPath === 'string') return textOf({ path: i.sourceMapPath }, io, 256 * 1024 * 1024);
  if (bundleText) {
    const inline = inlineSourceMap(bundleText);
    if (inline) return JSON.stringify(inline);
    const ref = sourceMapUrl(bundleText);
    if (ref && i.bundlePath && io.readFile && !/^[a-z][a-z0-9+.-]*:/i.test(ref) && !ref.split(/[\\/]/).includes('..')) {
      try { return await textOf({ path: i.bundlePath.replace(/[^/\\]*$/, '') + ref.split('?')[0] }, io, 256 * 1024 * 1024); } catch { /* not shipped */ }
    }
  }
  return undefined;
}

const LIM = { limit: { type: 'number' as const, description: 'Cap for each list (default 500).', optional: true } };

export function makeR3Tools(io: IO = {}): ToolDef[] {
  return [
    {
      name: 'web_trace_module_imports',
      description: 'ES module and CommonJS import graph (rea trace_web_module_imports) for a source folder or file list, one bundle (webpack 4/5, browserify, esbuild registries; rollup, vite and esbuild ESM chunks), a folder of chunks, or the original sources inside a source map. Edges carry kind (import, import-type, export-from, dynamic-import, require, worker, preload, bundle-dep) and line; reports entry points (package.json main, module, exports, bin, bundle entry), cycles (strongly connected components with one concrete loop), unresolved and external imports, unreachable modules and Mermaid.',
      inputSchema: {
        path: { type: 'string', description: 'Folder of sources or chunks, a bundle, or a .map file (Node).', optional: true },
        files: { type: 'array', description: 'Instead of path: [{ path, code }] source files.', optional: true },
        text: { type: 'string', description: 'Bundle or source map text.', optional: true },
        mode: { type: 'string', description: 'auto (default), files, chunks, bundle or sourcemap.', optional: true },
        sourceMap: { type: 'string', description: 'Source map text for naming bundle modules.', optional: true },
        sourceMapPath: { type: 'string', description: 'Source map file (Node).', optional: true },
        entries: { type: 'array', description: 'Entry module paths, overriding package.json.', optional: true },
        includeExternals: { type: 'boolean', description: 'Show packages and builtins in the Mermaid chart (default true).', optional: true },
        maxNodes: { type: 'number', description: 'Mermaid node cap (default 300).', optional: true },
        ...LIM,
      },
      run: async (i) => {
        const mode = String(i.mode ?? 'auto');
        const files = mode === 'bundle' || mode === 'sourcemap' ? undefined : await filesOf(i, io);
        let g;
        if (files) g = buildImportGraph(files, { entries: Array.isArray(i.entries) ? i.entries.map(String) : undefined, mode: mode === 'chunks' ? 'chunks' : 'files' });
        else {
          const text = await textOf(i, io, 64 * 1024 * 1024);
          const isMap = mode === 'sourcemap' || (mode === 'auto' && /^\s*(?:\)\]\}'\s*)?\{[\s\S]{0,200}"(?:version|mappings|sources)"/.test(text.slice(0, 2000)));
          g = isMap ? sourceMapImportGraph(text) : bundleImportGraph(text, { sourceMap: await mapOf({ ...i, bundlePath: i.path }, io, text) });
        }
        if (i.includeExternals === false || i.maxNodes) g.mermaid = importGraphMermaid(g, { includeExternals: i.includeExternals !== false, maxNodes: i.maxNodes });
        const lim = clampLimit(i.limit, 500);
        return { ...g, nodes: page(g.nodes, 0, lim), edges: page(g.edges, 0, Math.max(lim, 2000)) };
      },
    },
    {
      name: 'web_trace_source_location',
      description: 'Map bundle positions or a whole stack trace (V8, Firefox or Safari frames) to original sources through a source map (rea trace_web_source_location): original file, line, column and name, the original line text, the enclosing original function, and with the bundle the bundle module the position falls in. Also maps an original file and line back to every generated position.',
      inputSchema: {
        sourceMap: { type: 'string', description: 'Source map text.', optional: true },
        sourceMapPath: { type: 'string', description: 'Source map file (Node).', optional: true },
        bundlePath: { type: 'string', description: 'Bundle file; its map is found inline or next to it (Node).', optional: true },
        bundle: { type: 'string', description: 'Bundle text.', optional: true },
        positions: { type: 'array', description: '[{ line (1-based), column (0-based) }] in the bundle.', optional: true },
        stack: { type: 'string', description: 'A stack trace to map frame by frame (columns as printed, 1-based).', optional: true },
        original: { type: 'object', description: '{ source, line, column? }: list the generated positions of an original location.', optional: true },
      },
      run: async (i) => {
        const bundle = typeof i.bundle === 'string' ? i.bundle : typeof i.bundlePath === 'string' ? await textOf({ path: i.bundlePath }, io) : undefined;
        const map = await mapOf(i, io, bundle);
        if (!map) throw new InputError('no source map: give sourceMap, sourceMapPath, or a bundle with an inline or neighbouring map');
        const out: Record<string, unknown> = {};
        if (i.positions || i.stack) Object.assign(out, traceSourceLocation({ sourceMap: map, positions: i.positions, stack: i.stack, bundleCode: bundle }));
        if (i.original && typeof i.original === 'object') {
          const { SourceMapIndex } = await import('./sourcemap.js');
          out.generated = new SourceMapIndex(map).generatedPositionsFor(String(i.original.source), Number(i.original.line), i.original.column === undefined ? undefined : Number(i.original.column));
        }
        if (!Object.keys(out).length) throw new InputError('give positions, stack or original');
        return out;
      },
    },
    {
      name: 'web_compare_source_to_bundle',
      description: 'Compare a bundle source map with a source folder (rea compare_source_to_bundle): which original files the bundle carries and are unchanged (SHA-256 of sourcesContent against the file), which changed (lines added and removed, first different line), which bundle sources the folder lacks, and which folder files are missing from the bundle. Maps without sourcesContent are checked by fitting their mappings and names onto the folder files.',
      inputSchema: {
        sourceMap: { type: 'string', description: 'Source map text.', optional: true },
        sourceMapPath: { type: 'string', description: 'Source map file (Node).', optional: true },
        bundlePath: { type: 'string', description: 'Bundle whose inline or neighbouring map is used (Node).', optional: true },
        folder: { type: 'string', description: 'Source folder (Node).', optional: true },
        files: { type: 'array', description: 'Instead of folder: [{ path, content }].', optional: true },
        includeNodeModules: { type: 'boolean', description: 'Also compare node_modules sources (default false).', optional: true },
        ...LIM,
      },
      run: async (i) => {
        const bundle = typeof i.bundlePath === 'string' ? await textOf({ path: i.bundlePath }, io) : undefined;
        const map = await mapOf(i, io, bundle);
        if (!map) throw new InputError('no source map found');
        const files = await filesOf({ files: i.files, folder: i.folder }, io, { includeNodeModules: i.includeNodeModules });
        if (!files) throw new InputError('give folder (Node) or files');
        return compareSourceToBundle(map, files.map((f) => ({ path: f.path, content: f.code })), { includeNodeModules: i.includeNodeModules, limit: i.limit });
      },
    },
    {
      name: 'web_export_shapes',
      description: 'Exported names of a JavaScript module, package folder or bundle with what each is: function or class with arity (Function.length rules), async and generator flags, class prototype and static members with arities, object keys and value types. AST based, nothing is run; CommonJS, ES modules, tsc and babel re-export getters, webpack export getters and esbuild __commonJS and __export are followed.',
      inputSchema: { path: { type: 'string', description: 'File or package folder (Node).', optional: true }, text: { type: 'string', description: 'Module or bundle text.', optional: true }, files: { type: 'array', description: '[{ path, code }] of a package, with package.json.', optional: true }, kind: { type: 'string', description: 'auto (default), module, package or bundle.', optional: true } },
      run: async (i) => shapesOf(i, io),
    },
    {
      name: 'web_compare_export_shapes',
      description: 'Compare the export shapes of two JavaScript bundles, modules or package folders (rea compare_javascript_export_shapes), AST based with no execution: exports added and removed, kind changes, arity changes, async and generator flips, base class changes, class members added, removed and changed, object keys added and removed, a breaking change count and a 0 to 1 similarity. Bundle modules are compared by path too.',
      inputSchema: { a: { type: 'object', description: 'First side: { path } (Node), { text }, or { files } with a package.json.' }, b: { type: 'object', description: 'Second side, same forms.' }, kind: { type: 'string', description: 'auto (default), module, package or bundle.', optional: true }, ...LIM },
      run: async (i) => {
        if (!i.a || !i.b) throw new InputError('give a and b');
        const [sa, sb] = [await shapesOf({ ...i.a, kind: i.kind }, io), await shapesOf({ ...i.b, kind: i.kind }, io)];
        const top = compareExportShapes(sa.exports, sb.exports);
        const modules: { path: string; comparison: ReturnType<typeof compareExportShapes> }[] = [];
        const ma = new Map((sa.modules ?? []).filter((m) => m.path).map((m) => [m.path!, m.exports]));
        for (const m of sb.modules ?? []) if (m.path && ma.has(m.path)) { const c = compareExportShapes(ma.get(m.path)!, m.exports); if (c.added.length || c.removed.length || c.changed.length) modules.push({ path: m.path, comparison: c }); }
        const lim = clampLimit(i.limit, 500);
        return { a: { kind: sa.kind, exports: Object.keys(sa.exports).length }, b: { kind: sb.kind, exports: Object.keys(sb.exports).length }, ...top, changed: top.changed.slice(0, lim), modules: modules.slice(0, lim) };
      },
    },
    {
      name: 'web_endpoint_join',
      description: 'Join endpoints found statically in JavaScript with requests seen in a HAR, RevLens scenario capture or browser capture (rea compare_static_and_observed_endpoints): matched endpoints with the values seen for each template parameter and the query names used, static-only endpoints (dead, gated or hidden code), and observed-only requests with inferred path templates (built at run time or from code that was not given). Without scripts, the JavaScript bodies in the capture are used.',
      inputSchema: {
        capturePath: { type: 'string', description: 'HAR or capture JSON (Node).', optional: true },
        captureText: { type: 'string', description: 'HAR or capture JSON text.', optional: true },
        scripts: { type: 'array', description: '[{ url?, code }] scripts to scan instead of those in the capture.', optional: true },
        scriptPaths: { type: 'array', description: 'Script files to scan (Node).', optional: true },
        origin: { type: 'string', description: 'Page origin for relative endpoints (default: the document in the capture).', optional: true },
        includeAssets: { type: 'boolean', description: 'Also list documents, scripts, styles and images as observed-only.', optional: true },
        ...LIM,
      },
      run: async (i) => {
        const text = typeof i.captureText === 'string' ? i.captureText : typeof i.capturePath === 'string' ? await textOf({ path: i.capturePath }, io, 1024 * 1024 * 1024) : undefined;
        if (text === undefined) throw new InputError('give capturePath or captureText');
        let capture: unknown;
        try { capture = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new InputError('capture is not JSON'); }
        const scripts: { url?: string; code: string }[] = Array.isArray(i.scripts) ? i.scripts.map((s: { url?: string; code: string }) => ({ url: s.url, code: String(s.code) })) : [];
        for (const p of Array.isArray(i.scriptPaths) ? i.scriptPaths.slice(0, 200) : []) scripts.push({ url: String(p), code: await textOf({ path: String(p) }, io, 16 * 1024 * 1024) });
        return compareStaticAndObservedEndpoints({ capture, scripts, origin: i.origin, includeAssets: i.includeAssets, limit: i.limit });
      },
    },
    {
      name: 'web_env_build',
      description: 'Turn a HAR or scenario capture into a replay environment (rea environment-build): routes with recorded responses and deduplicated bodies, deterministic matching rules (method, host, path, query and request body with in-order sequences, then query names, path, id template), the scenario to re-run, the original run results, and eval tasks with ground truth in the extras x_eval_score shape. In Node, outDir writes the folder; otherwise the manifest and files come back inline (base64).',
      inputSchema: { capturePath: { type: 'string', description: 'HAR or capture JSON (Node).', optional: true }, captureText: { type: 'string', description: 'HAR or capture JSON text.', optional: true }, outDir: { type: 'string', description: 'Folder to write (Node, must be absent or empty).', optional: true }, name: { type: 'string', description: 'Environment name (kebab-case).', optional: true }, tasks: { type: 'boolean', description: 'Generate eval tasks (default true).', optional: true } },
      run: async (i) => {
        const special = io.extra?.find((t) => t.name === '__env_build_dir');
        if (i.outDir && special) return special.run(i);
        if (i.outDir) throw new InputError('outDir needs Node');
        const text = typeof i.captureText === 'string' ? i.captureText : typeof i.capturePath === 'string' ? await textOf({ path: i.capturePath }, io, 1024 * 1024 * 1024) : undefined;
        if (text === undefined) throw new InputError('give capturePath or captureText');
        let capture: unknown;
        try { capture = JSON.parse(text); } catch { throw new InputError('capture is not JSON'); }
        const b = buildEnvironment(capture, { name: i.name, sourceText: text, tasks: i.tasks });
        return { manifest: b.manifest, files: b.files.filter((f) => f.path.startsWith('bodies/')).slice(0, 5000).map((f) => ({ path: f.path, base64: bytesToBase64(f.bytes) })) };
      },
    },
  ];
}

interface Shapes { kind: string; exports: Record<string, ExportShape>; modules?: { path?: string; exports: Record<string, ExportShape> }[] }

async function shapesOf(i: { path?: string; text?: string; files?: { path: string; code: string }[]; kind?: string }, io: IO): Promise<Shapes> {
  const kind = String(i.kind ?? 'auto');
  const files = await filesOf({ files: i.files, folder: i.path }, io);
  if (files && kind !== 'bundle' && kind !== 'module') {
    const p = packageExportShapes(files);
    return { kind: 'package', exports: p.exports };
  }
  const text = await textOf(i, io, 64 * 1024 * 1024);
  if (kind === 'module') return { kind: 'module', exports: moduleExportShapes(text, { path: i.path ? i.path.split(/[\\/]/).pop() : undefined }).exports };
  const b = bundleExportShapes(text);
  if (kind === 'bundle' || b.modules.length) return { kind: `bundle:${b.bundler}`, exports: b.top.exports, modules: b.modules.map((m) => ({ path: m.path, exports: m.shapes.exports })) };
  return { kind: 'module', exports: b.top.exports };
}
