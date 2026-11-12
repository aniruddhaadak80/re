// Module import graphs for JavaScript and TypeScript: a folder of sources, a bundle (webpack, browserify,
// esbuild registries), a set of rollup, vite or esbuild ESM chunks, or the original sources inside a
// source map. Edges carry the import kind and line, cycles come from Tarjan's strongly connected
// components, entry points from package.json, bundle runtimes and in-degree, and the graph renders as
// Mermaid. Browser safe: callers hand in file contents, nothing is read or run here.
import { parseJs, walk, staticString, templateShape, memberName, t } from './ast.js';
import { unpackBundle, type BundleResult } from './bundle.js';
import { parseSourceMap, type RawSourceMap } from '../sourcemap.js';
import { InputError } from '../util.js';

export type ImportKind = 'import' | 'import-type' | 'export-from' | 'dynamic-import' | 'require' | 'require-resolve' | 'import-scripts' | 'worker' | 'bundle-dep' | 'preload';

export interface ModuleImport { specifier: string; kind: ImportKind; line: number; column: number; names?: string[]; dynamicTemplate?: boolean }
export interface ModuleScan { format: 'esm' | 'cjs' | 'mixed' | 'none'; imports: ModuleImport[]; exportsCount: number; parserErrors: string[] }

export interface GraphNode {
  id: string;
  kind: 'module' | 'external' | 'chunk' | 'builtin' | 'missing';
  path?: string;
  format?: ModuleScan['format'];
  size?: number;
  /** bundle module id, when the graph comes from a bundle */
  bundleId?: string;
  inDegree: number;
  outDegree: number;
}
export interface GraphEdge { from: string; to: string; specifier: string; kind: ImportKind; line?: number; names?: string[] }
export interface EntryPoint { id: string; reason: 'package-main' | 'package-module' | 'package-exports' | 'package-bin' | 'bundle-entry' | 'html-script' | 'no-importers' | 'given' }
export interface ImportGraph {
  mode: 'files' | 'bundle' | 'chunks' | 'sourcemap';
  bundler?: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  entryPoints: EntryPoint[];
  /** strongly connected components with more than one module (or a self import), each with one concrete loop */
  cycles: { members: string[]; loop: string[] }[];
  unresolved: { from: string; specifier: string; kind: ImportKind; line?: number }[];
  externals: { name: string; importers: number }[];
  /** modules that no entry point reaches */
  unreachable: string[];
  stats: { modules: number; externals: number; edges: number; cycles: number; dynamicEdges: number; maxDepth: number };
  mermaid: string;
  warnings: string[];
}

const NODE_BUILTINS = new Set(['assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib', 'test', 'sqlite', 'sea']);
const RESOLVE_EXT = ['', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.json', '.vue', '.svelte'];
const INDEX_FILES = ['index.js', 'index.mjs', 'index.cjs', 'index.jsx', 'index.ts', 'index.tsx', 'index.json'];
const TS_FILE = /\.(?:ts|tsx|mts|cts)$/;
const MAX_FILES = 20_000;

/** POSIX path normalisation that works without node:path (".." past the root is dropped). */
export function normPath(p: string): string {
  const out: string[] = [];
  for (const seg of p.replace(/\\/g, '/').split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out.join('/');
}
const dirOf = (p: string) => { const i = p.lastIndexOf('/'); return i < 0 ? '' : p.slice(0, i); };

/** Imports, requires and re-exports of one module. TypeScript is parsed when the path says so. */
export function scanModuleImports(code: string, path = 'input.js'): ModuleScan {
  const ts = TS_FILE.test(path);
  const { ast, errors } = parseJs(code, { typescript: ts });
  const imports: ModuleImport[] = [];
  let esm = false, cjs = false, exportsCount = 0;
  const at = (n: t.Node) => ({ line: n.loc?.start.line ?? 0, column: n.loc?.start.column ?? 0 });
  const add = (spec: string | undefined, kind: ImportKind, n: t.Node, names?: string[], dynamicTemplate?: boolean) => {
    if (spec === undefined || spec.length > 2000 || imports.length >= 20_000) return;
    imports.push({ specifier: spec, kind, ...at(n), names: names?.length ? names.slice(0, 200) : undefined, dynamicTemplate: dynamicTemplate || undefined });
  };
  walk(ast, ({ node }) => {
    switch (node.type) {
      case 'ImportDeclaration': {
        esm = true;
        const typeOnly = node.importKind === 'type' || (node.specifiers.length > 0 && node.specifiers.every((s) => s.type === 'ImportSpecifier' && s.importKind === 'type'));
        const names = node.specifiers.map((s) => (s.type === 'ImportDefaultSpecifier' ? 'default' : s.type === 'ImportNamespaceSpecifier' ? '*' : s.imported.type === 'Identifier' ? s.imported.name : s.imported.value));
        add(node.source.value, typeOnly ? 'import-type' : 'import', node, names);
        return 'skip';
      }
      case 'ExportNamedDeclaration':
      case 'ExportAllDeclaration':
        esm = true; exportsCount++;
        if (node.source) {
          const typeOnly = node.exportKind === 'type';
          const names = node.type === 'ExportAllDeclaration' ? ['*'] : node.specifiers.map((s) => (s.type === 'ExportSpecifier' ? (s.local.type === 'Identifier' ? s.local.name : String(s.local)) : '*'));
          add(node.source.value, typeOnly ? 'import-type' : 'export-from', node, names);
        }
        return undefined;
      case 'ExportDefaultDeclaration': esm = true; exportsCount++; return undefined;
      case 'TSImportEqualsDeclaration':
        if (node.moduleReference.type === 'TSExternalModuleReference') { cjs = true; add(node.moduleReference.expression.value, 'require', node); }
        return undefined;
      case 'ImportExpression': {
        const s = staticString(node.source);
        if (s !== undefined) add(s, 'dynamic-import', node);
        else { const tpl = templateShape(node.source); if (tpl) add(tpl, 'dynamic-import', node, undefined, true); }
        return undefined;
      }
      case 'CallExpression':
      case 'NewExpression': {
        const callee = node.callee as t.Node;
        const a0 = node.arguments[0] as t.Node | undefined;
        if (callee.type === 'Import' && a0) {
          const s = staticString(a0);
          if (s !== undefined) add(s, 'dynamic-import', node); else { const tpl = templateShape(a0); if (tpl) add(tpl, 'dynamic-import', node, undefined, true); }
          return undefined;
        }
        const name = callee.type === 'Identifier' ? callee.name : memberName(callee);
        if (!name || !a0) return undefined;
        if (node.type === 'CallExpression' && (name === 'require' || name === 'module.require')) { cjs = true; const s = staticString(a0); if (s !== undefined) add(s, 'require', node); else { const tpl = templateShape(a0); if (tpl) add(tpl, 'require', node, undefined, true); } }
        else if (node.type === 'CallExpression' && name === 'require.resolve') { const s = staticString(a0); if (s !== undefined) add(s, 'require-resolve', node); }
        else if (node.type === 'CallExpression' && (name === 'importScripts' || name === 'self.importScripts')) { for (const a of node.arguments) { const s = staticString(a as t.Node); if (s !== undefined) add(s, 'import-scripts', node); } }
        else if (node.type === 'NewExpression' && /^(?:(?:window|self|globalThis)\.)?(?:Worker|SharedWorker)$/.test(name)) {
          // new Worker(new URL('./w.js', import.meta.url)) or new Worker('./w.js')
          let s = staticString(a0);
          if (s === undefined && a0.type === 'NewExpression' && a0.callee.type === 'Identifier' && a0.callee.name === 'URL') s = staticString(a0.arguments[0] as t.Node);
          if (s !== undefined) add(s, 'worker', node);
        } else if (node.type === 'CallExpression' && name === '__vitePreload') {
          // __vitePreload(() => import('./x.js'), __VITE_IS_MODERN__ ? [deps] : void 0): list the preloaded css and js too
          const deps = node.arguments[1] as t.Node | undefined;
          const arr = deps?.type === 'ArrayExpression' ? deps : deps?.type === 'ConditionalExpression' && deps.consequent.type === 'ArrayExpression' ? deps.consequent : undefined;
          for (const el of arr?.elements ?? []) { const s = staticString(el as t.Node); if (s !== undefined) add(s, 'preload', node); }
        }
        return undefined;
      }
      case 'MemberExpression':
        if (!cjs) { const n = memberName(node); if (n === 'module.exports' || (n?.startsWith('exports.') ?? false)) cjs = true; }
        return undefined;
      default: return undefined;
    }
  });
  return { format: esm && cjs ? 'mixed' : esm ? 'esm' : cjs ? 'cjs' : 'none', imports, exportsCount, parserErrors: errors };
}

function packageName(spec: string): string {
  const s = spec.replace(/^node:/, '');
  if (s.startsWith('@')) return s.split('/').slice(0, 2).join('/');
  return s.split('/')[0] ?? s;
}

interface PackageJsonLike { name?: string; main?: string; module?: string; browser?: unknown; bin?: unknown; exports?: unknown; imports?: unknown }

/** Collect every relative target named in a package.json exports value (conditions and subpaths, any depth). */
function exportTargets(v: unknown, out: string[], depth = 0): void {
  if (depth > 8 || out.length > 500) return;
  if (typeof v === 'string') { if (v.startsWith('./') && !v.includes('*')) out.push(v); return; }
  if (Array.isArray(v)) { for (const x of v) exportTargets(x, out, depth + 1); return; }
  if (v && typeof v === 'object') for (const x of Object.values(v as Record<string, unknown>)) exportTargets(x, out, depth + 1);
}

/** Tarjan's strongly connected components, iterative so a long import chain cannot overflow the stack. */
export function stronglyConnected(ids: string[], next: Map<string, string[]>): string[][] {
  const index = new Map<string, number>(), low = new Map<string, number>(), onStack = new Set<string>();
  const stack: string[] = [];
  const out: string[][] = [];
  let counter = 0;
  for (const root of ids) {
    if (index.has(root)) continue;
    const work: { v: string; i: number }[] = [{ v: root, i: 0 }];
    index.set(root, counter); low.set(root, counter); counter++; stack.push(root); onStack.add(root);
    while (work.length) {
      const top = work[work.length - 1]!;
      const succ = next.get(top.v) ?? [];
      if (top.i < succ.length) {
        const w = succ[top.i++]!;
        if (!index.has(w)) { index.set(w, counter); low.set(w, counter); counter++; stack.push(w); onStack.add(w); work.push({ v: w, i: 0 }); }
        else if (onStack.has(w)) low.set(top.v, Math.min(low.get(top.v)!, index.get(w)!));
        continue;
      }
      work.pop();
      if (work.length) { const p = work[work.length - 1]!.v; low.set(p, Math.min(low.get(p)!, low.get(top.v)!)); }
      if (low.get(top.v) === index.get(top.v)) {
        const comp: string[] = [];
        let w: string;
        do { w = stack.pop()!; onStack.delete(w); comp.push(w); } while (w !== top.v);
        out.push(comp);
      }
    }
  }
  return out;
}

/** One concrete loop inside a strongly connected component: BFS from its first member back to itself. */
function loopIn(members: string[], next: Map<string, string[]>): string[] {
  const set = new Set(members);
  const start = [...members].sort()[0]!;
  const prev = new Map<string, string>();
  const q = [start];
  for (let qi = 0; qi < q.length; qi++) {
    const v = q[qi]!;
    for (const w of next.get(v) ?? []) {
      if (!set.has(w)) continue;
      if (w === start) {
        const path = [start];
        for (let x: string | undefined = v; x && x !== start; x = prev.get(x)) path.splice(1, 0, x);
        if (v === start && path.length === 1) return [start, start];
        return [...path, start];
      }
      if (!prev.has(w)) { prev.set(w, v); q.push(w); }
    }
  }
  return [start];
}

const mermaidId = (i: number) => `n${i}`;
const mermaidLabel = (s: string) => s.replace(/["<>]/g, (c) => (c === '"' ? '#quot;' : c === '<' ? '#lt;' : '#gt;')).replace(/[\r\n]+/g, ' ').slice(0, 120);

/** Render a graph as a Mermaid flowchart. Dynamic imports are dotted, cycle edges are red, externals are rounded. */
export function importGraphMermaid(g: Pick<ImportGraph, 'nodes' | 'edges' | 'cycles' | 'entryPoints'>, opts: { maxNodes?: number; includeExternals?: boolean; direction?: 'LR' | 'TD' } = {}): string {
  const max = Math.max(1, Math.min(opts.maxNodes ?? 300, 2000));
  const keep = g.nodes.filter((n) => opts.includeExternals !== false || n.kind === 'module' || n.kind === 'chunk')
    .sort((a, b) => (b.inDegree + b.outDegree) - (a.inDegree + a.outDegree)).slice(0, max);
  const idx = new Map(keep.map((n, i) => [n.id, i]));
  const inCycle = new Set<string>();
  for (const c of g.cycles) for (let i = 0; i + 1 < c.loop.length; i++) inCycle.add(`${c.loop[i]}\u0000${c.loop[i + 1]}`);
  const entries = new Set(g.entryPoints.map((e) => e.id));
  const lines = [`graph ${opts.direction ?? 'LR'}`];
  for (const n of keep) {
    const i = idx.get(n.id)!;
    const label = mermaidLabel(n.path ?? n.id);
    lines.push(n.kind === 'external' || n.kind === 'builtin' ? `  ${mermaidId(i)}(["${label}"])` : n.kind === 'missing' ? `  ${mermaidId(i)}{{"${label}"}}` : entries.has(n.id) ? `  ${mermaidId(i)}[["${label}"]]` : `  ${mermaidId(i)}["${label}"]`);
  }
  const seen = new Set<string>();
  const red: number[] = [];
  let edgeNo = 0;
  for (const e of g.edges) {
    const a = idx.get(e.from), b = idx.get(e.to);
    if (a === undefined || b === undefined) continue;
    const k = `${a}>${b}>${e.kind === 'dynamic-import'}`;
    if (seen.has(k)) continue;
    seen.add(k);
    lines.push(e.kind === 'dynamic-import' || e.kind === 'worker' || e.kind === 'preload' ? `  ${mermaidId(a)} -.-> ${mermaidId(b)}` : `  ${mermaidId(a)} --> ${mermaidId(b)}`);
    if (inCycle.has(`${e.from}\u0000${e.to}`)) red.push(edgeNo);
    edgeNo++;
  }
  if (red.length) lines.push(`  linkStyle ${red.slice(0, 500).join(',')} stroke:#d33,stroke-width:2px`);
  if (g.nodes.length > keep.length) lines.push(`  %% ${g.nodes.length - keep.length} more nodes left out (maxNodes ${max})`);
  return lines.join('\n');
}

function finish(mode: ImportGraph['mode'], nodes: Map<string, GraphNode>, edges: GraphEdge[], entries: EntryPoint[], unresolved: ImportGraph['unresolved'], warnings: string[], bundler?: string): ImportGraph {
  for (const e of edges) { const a = nodes.get(e.from), b = nodes.get(e.to); if (a) a.outDegree++; if (b) b.inDegree++; }
  const ids = [...nodes.keys()];
  const next = new Map<string, string[]>();
  for (const e of edges) { if (e.kind === 'import-type') continue; const l = next.get(e.from) ?? next.set(e.from, []).get(e.from)!; if (!l.includes(e.to)) l.push(e.to); }
  const cycles: ImportGraph['cycles'] = [];
  for (const comp of stronglyConnected(ids, next)) {
    const self = comp.length === 1 && (next.get(comp[0]!) ?? []).includes(comp[0]!);
    if (comp.length > 1 || self) cycles.push({ members: comp.sort(), loop: loopIn(comp, next) });
  }
  cycles.sort((a, b) => b.members.length - a.members.length || a.members[0]!.localeCompare(b.members[0]!));
  // entries: given ones first, then modules nobody imports
  const entrySet = new Set(entries.map((e) => e.id));
  if (!entries.length) for (const n of nodes.values()) if ((n.kind === 'module' || n.kind === 'chunk') && n.inDegree === 0 && !entrySet.has(n.id)) { entries.push({ id: n.id, reason: 'no-importers' }); entrySet.add(n.id); }
  // reachability and depth from the entries
  const depth = new Map<string, number>();
  const q: string[] = [];
  for (const e of entries) if (nodes.has(e.id) && !depth.has(e.id)) { depth.set(e.id, 0); q.push(e.id); }
  for (let qi = 0; qi < q.length; qi++) { const v = q[qi]!; for (const w of next.get(v) ?? []) if (!depth.has(w)) { depth.set(w, depth.get(v)! + 1); q.push(w); } }
  const unreachable = [...nodes.values()].filter((n) => (n.kind === 'module' || n.kind === 'chunk') && !depth.has(n.id)).map((n) => n.id).sort();
  const externals = [...nodes.values()].filter((n) => n.kind === 'external' || n.kind === 'builtin').map((n) => ({ name: n.id, importers: n.inDegree })).sort((a, b) => b.importers - a.importers || a.name.localeCompare(b.name));
  const g: ImportGraph = {
    mode, bundler, nodes: [...nodes.values()], edges, entryPoints: entries, cycles, unresolved: unresolved.slice(0, 2000), externals, unreachable,
    stats: { modules: [...nodes.values()].filter((n) => n.kind === 'module' || n.kind === 'chunk').length, externals: externals.length, edges: edges.length, cycles: cycles.length, dynamicEdges: edges.filter((e) => e.kind === 'dynamic-import').length, maxDepth: Math.max(0, ...depth.values()) },
    mermaid: '', warnings,
  };
  g.mermaid = importGraphMermaid(g);
  return g;
}

export interface FileGraphOptions {
  /** entry module paths relative to the root (default: package.json fields, then modules nobody imports) */
  entries?: string[];
  packageJson?: PackageJsonLike | string;
  /** tsconfig-style aliases: { "@/*": ["src/*"] } */
  paths?: Record<string, string[]>;
  /** include `import type` edges (default true; they are never part of cycles) */
  typeImports?: boolean;
  mode?: 'files' | 'chunks' | 'sourcemap';
}

/** Build the import graph of a set of source files keyed by their relative path. */
export function buildImportGraph(files: { path: string; code: string }[], opts: FileGraphOptions = {}): ImportGraph {
  if (files.length > MAX_FILES) throw new InputError(`${files.length} files, over the ${MAX_FILES} limit`);
  const byPath = new Map<string, { path: string; code: string }>();
  for (const f of files) byPath.set(normPath(f.path), f);
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const unresolved: ImportGraph['unresolved'] = [];
  const warnings: string[] = [];
  const isCode = (p: string) => /\.(?:m?jsx?|cjs|tsx?|mts|cts|vue|svelte)$/.test(p);
  for (const p of byPath.keys()) if (isCode(p) || p.endsWith('.json')) nodes.set(p, { id: p, kind: 'module', path: p, size: byPath.get(p)!.code.length, inDegree: 0, outDegree: 0 });
  const resolveRel = (from: string, spec: string): string | undefined => {
    const clean = spec.split(/[?#]/)[0]!;
    const base = clean.startsWith('/') ? normPath(clean) : normPath(`${dirOf(from)}/${clean}`);
    const tries: string[] = [];
    for (const ext of RESOLVE_EXT) tries.push(base + ext);
    // TypeScript ESM style: import './a.js' that names a.ts
    const m = /\.(m|c)?js$/.exec(base);
    if (m) for (const e of ['.ts', '.tsx', '.mts', '.cts']) tries.push(base.slice(0, -m[0].length) + e);
    for (const ix of INDEX_FILES) tries.push(base ? `${base}/${ix}` : ix);
    return tries.find((x) => nodes.has(x));
  };
  const resolveAlias = (spec: string): string | undefined => {
    for (const [pat, targets] of Object.entries(opts.paths ?? {})) {
      const star = pat.indexOf('*');
      const pre = star < 0 ? pat : pat.slice(0, star), post = star < 0 ? '' : pat.slice(star + 1);
      if (star < 0 ? spec !== pat : !(spec.startsWith(pre) && spec.endsWith(post) && spec.length >= pre.length + post.length)) continue;
      const mid = star < 0 ? '' : spec.slice(pre.length, spec.length - post.length);
      for (const tg of targets.slice(0, 10)) { const r = resolveRel('', tg.replace('*', mid)); if (r) return r; }
    }
    return undefined;
  };
  let pkg: PackageJsonLike | undefined;
  try { pkg = typeof opts.packageJson === 'string' ? JSON.parse(opts.packageJson) : opts.packageJson; } catch { warnings.push('package.json is not JSON'); }
  if (!pkg && byPath.has('package.json')) { try { pkg = JSON.parse(byPath.get('package.json')!.code); } catch { warnings.push('package.json is not JSON'); } }
  if (pkg) nodes.delete('package.json');
  for (const [p, f] of byPath) {
    if (!isCode(p)) continue;
    let scan: ModuleScan;
    try { scan = scanModuleImports(f.code, p); }
    catch (e) { warnings.push(`${p}: ${(e as Error).message.slice(0, 200)}`); continue; }
    const node = nodes.get(p)!;
    node.format = scan.format;
    for (const im of scan.imports) {
      if (im.kind === 'import-type' && opts.typeImports === false) continue;
      const spec = im.specifier;
      if (im.dynamicTemplate) { unresolved.push({ from: p, specifier: spec, kind: im.kind, line: im.line }); continue; }
      let target: string | undefined;
      if (spec.startsWith('.') || spec.startsWith('/')) target = resolveRel(p, spec);
      else target = resolveAlias(spec);
      if (!target && (spec.startsWith('.') || spec.startsWith('/'))) {
        if (/\.(?:css|scss|sass|less|svg|png|jpe?g|gif|webp|woff2?|html)$/.test(spec.split(/[?#]/)[0]!)) continue; // assets
        const missingId = `missing:${normPath(`${dirOf(p)}/${spec}`)}`;
        if (!nodes.has(missingId)) nodes.set(missingId, { id: missingId, kind: 'missing', inDegree: 0, outDegree: 0 });
        unresolved.push({ from: p, specifier: spec, kind: im.kind, line: im.line });
        target = missingId;
      }
      if (!target) {
        if (/^(?:https?:)?\/\//.test(spec) || spec.startsWith('data:')) target = spec.slice(0, 300);
        else {
          const bare = spec.replace(/^node:/, '');
          const builtin = spec.startsWith('node:') || NODE_BUILTINS.has(bare.split('/')[0]!);
          target = builtin ? `node:${bare}` : packageName(spec);
          if (!nodes.has(target)) nodes.set(target, { id: target, kind: builtin ? 'builtin' : 'external', inDegree: 0, outDegree: 0 });
        }
        if (!nodes.has(target)) nodes.set(target, { id: target, kind: 'external', inDegree: 0, outDegree: 0 });
      }
      if (edges.length < 200_000) edges.push({ from: p, to: target, specifier: spec, kind: im.kind, line: im.line, names: im.names });
    }
  }
  const entries: EntryPoint[] = [];
  const addEntry = (rel: string | undefined, reason: EntryPoint['reason']) => {
    if (!rel) return;
    const r = resolveRel('', rel.replace(/^\.\//, ''));
    if (r && !entries.some((e) => e.id === r)) entries.push({ id: r, reason });
  };
  for (const e of opts.entries ?? []) addEntry(e, 'given');
  if (!opts.entries?.length && pkg) {
    if (typeof pkg.main === 'string') addEntry(pkg.main, 'package-main');
    if (typeof pkg.module === 'string') addEntry(pkg.module, 'package-module');
    const ex: string[] = [];
    exportTargets(pkg.exports, ex);
    for (const x of ex) addEntry(x, 'package-exports');
    if (typeof pkg.bin === 'string') addEntry(pkg.bin, 'package-bin');
    else if (pkg.bin && typeof pkg.bin === 'object') for (const v of Object.values(pkg.bin as Record<string, unknown>)) if (typeof v === 'string') addEntry(v, 'package-bin');
    if (!entries.length) addEntry('index.js', 'package-main');
  }
  return finish(opts.mode ?? 'files', nodes, edges, entries, unresolved, warnings);
}

/** Module graph inside one bundle (webpack 4/5, jsonp chunks, browserify, esbuild registries). */
export function bundleImportGraph(code: string, opts: { sourceMap?: string | RawSourceMap; bundle?: BundleResult } = {}): ImportGraph {
  const b = opts.bundle ?? unpackBundle(code, { sourceMap: opts.sourceMap });
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const unresolved: ImportGraph['unresolved'] = [];
  const warnings = [...b.notes];
  const idOf = (bid: string) => { const m = b.modules.find((x) => x.id === bid); return m?.path ?? `#${bid}`; };
  const byBundleId = new Map<string, string>();
  for (const m of b.modules) {
    const id = m.path ?? `#${m.id}`;
    byBundleId.set(m.id, id);
    nodes.set(id, { id, kind: 'module', path: m.path, size: m.size, bundleId: m.id, inDegree: 0, outDegree: 0 });
  }
  // browserify deps hold names ("./dep") mapped to ids; esbuild requires use the original names
  const byPath = new Map<string, string>();
  for (const m of b.modules) if (m.path) byPath.set(normPath(m.path), m.path);
  for (const m of b.modules) {
    const from = byBundleId.get(m.id)!;
    for (const d of m.deps) {
      let to = byBundleId.get(d);
      if (!to && m.path && (d.startsWith('.') || d.startsWith('/'))) {
        const base = normPath(`${dirOf(m.path)}/${d}`);
        for (const ext of RESOLVE_EXT) { const hit = byPath.get(base + ext); if (hit) { to = hit; break; } }
      }
      if (!to) {
        if (/^\d+$/.test(d) || d.startsWith('.')) { unresolved.push({ from, specifier: d, kind: 'bundle-dep' }); to = `missing:${d}`; if (!nodes.has(to)) nodes.set(to, { id: to, kind: 'missing', inDegree: 0, outDegree: 0 }); }
        else { to = packageName(d); if (!nodes.has(to)) nodes.set(to, { id: to, kind: NODE_BUILTINS.has(to.replace(/^node:/, '')) ? 'builtin' : 'external', inDegree: 0, outDegree: 0 }); }
      }
      edges.push({ from, to, specifier: d, kind: 'bundle-dep' });
    }
  }
  // webpack: chunk loads inside module bodies (__webpack_require__.e(id).then(require.bind(r, 123)))
  if (b.bundler.startsWith('webpack')) {
    try {
      const { ast } = parseJs(code);
      walk(ast, ({ node }) => {
        if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression' || node.callee.property.type !== 'Identifier' || node.callee.property.name !== 'then') return undefined;
        const obj = node.callee.object;
        const isChunkLoad = (n: t.Node): boolean => (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && n.callee.property.type === 'Identifier' && n.callee.property.name === 'e') || (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && memberName(n.callee)?.endsWith('Promise.all') === true && n.arguments[0]?.type === 'ArrayExpression' && n.arguments[0].elements.some((x) => !!x && isChunkLoad(x as t.Node)));
        if (!isChunkLoad(obj)) return undefined;
        const arg = node.arguments[0];
        let target: string | undefined;
        if (arg?.type === 'CallExpression' && arg.callee.type === 'MemberExpression' && arg.callee.property.type === 'Identifier' && arg.callee.property.name === 'bind') {
          const a1 = arg.arguments[1];
          if (a1?.type === 'NumericLiteral') target = String(a1.value); else if (a1?.type === 'StringLiteral') target = a1.value;
        }
        if (target === undefined) return undefined;
        const owner = b.modules.find((m) => (node.start ?? 0) >= m.start && (node.end ?? 0) <= m.end);
        if (!owner) return undefined;
        const from = byBundleId.get(owner.id)!;
        let to = byBundleId.get(target);
        if (!to) { to = `chunk-module:${target}`; if (!nodes.has(to)) nodes.set(to, { id: to, kind: 'chunk', bundleId: target, inDegree: 0, outDegree: 0 }); }
        edges.push({ from, to, specifier: target, kind: 'dynamic-import', line: node.loc?.start.line });
        return undefined;
      });
    } catch (e) { warnings.push(`chunk loads: ${(e as Error).message.slice(0, 160)}`); }
  }
  // chunk level imports of ESM output (rollup, vite, esbuild ESM) when there is no registry
  if (!b.modules.length) {
    nodes.set('<bundle>', { id: '<bundle>', kind: 'chunk', size: code.length, inDegree: 0, outDegree: 0 });
    for (const im of b.imports) {
      const to = im.source.startsWith('.') || im.source.startsWith('/') ? normPath(im.source) : packageName(im.source);
      if (!nodes.has(to)) nodes.set(to, { id: to, kind: im.source.startsWith('.') ? 'chunk' : 'external', inDegree: 0, outDegree: 0 });
      edges.push({ from: '<bundle>', to, specifier: im.source, kind: im.kind === 'dynamic-import' ? 'dynamic-import' : im.kind === 'require' ? 'require' : im.kind === 'export-from' ? 'export-from' : 'import', line: im.line });
    }
  }
  const entries: EntryPoint[] = b.entryIds.map((e) => byBundleId.get(e)).filter((x): x is string => !!x).map((id) => ({ id, reason: 'bundle-entry' as const }));
  void idOf;
  return finish('bundle', nodes, edges, entries, unresolved, warnings, b.bundler);
}

/** Import graph of the original sources a source map carries (sourcesContent), with webpack:// and similar prefixes removed. */
export function sourceMapImportGraph(map: string | RawSourceMap, opts: { includeNodeModules?: boolean } = {}): ImportGraph {
  const raw = parseSourceMap(map);
  const parts: RawSourceMap[] = raw.sections ? raw.sections.map((s) => s.map).filter((m): m is RawSourceMap => !!m) : [raw];
  const files: { path: string; code: string }[] = [];
  const seen = new Set<string>();
  let missing = 0;
  for (const m of parts) {
    (m.sources ?? []).forEach((s, i) => {
      const content = m.sourcesContent?.[i];
      if (typeof content !== 'string') { missing++; return; }
      const p = sourceKey(String(s ?? ''), m.sourceRoot);
      if (!p || seen.has(p) || /^webpack\/(?:runtime|bootstrap)/.test(p)) return;
      if (!opts.includeNodeModules && p.split('/').includes('node_modules')) return;
      seen.add(p); files.push({ path: p, code: content });
    });
  }
  const g = buildImportGraph(files, { mode: 'sourcemap' });
  if (missing) g.warnings.push(`${missing} sources in the map have no sourcesContent`);
  return g;
}

/** A source map "sources" entry as a plain relative path: webpack://app/./src/a.js becomes src/a.js. */
export function sourceKey(source: string, sourceRoot?: string): string {
  let s = source;
  if (sourceRoot && !/^[a-z][\w+.-]*:/i.test(s)) s = `${sourceRoot.replace(/\/+$/, '')}/${s}`;
  s = s.replace(/^webpack:\/\/[^/]*\//, '').replace(/^(?:webpack|vite|rollup|turbopack|file):\/*/i, '').replace(/^[a-z][\w+.-]*:\/\/\/?/i, '').replace(/\?[^/]*$/, '');
  return normPath(s);
}
