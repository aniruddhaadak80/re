// Bundle unpacking: webpack 4/5 (runtime and jsonp chunks), browserify, esbuild (__commonJS / __esm and
// path comments), and rollup/vite chunk-level imports. Purely static: the bundle is parsed, never run.
import { parseJs, walk, staticString, propKey, memberName, t } from './ast.js';
import { printAst } from './print.js';
import { lineIndex, safeRelPath, truncate } from '../util.js';
import { SourceMapIndex, sourceMappingComments, type RawSourceMap } from '../sourcemap.js';

export type BundlerKind = 'webpack5' | 'webpack4' | 'webpack-chunk' | 'browserify' | 'esbuild' | 'rollup' | 'vite' | 'parcel' | 'unknown';

export interface BundleModule {
  id: string;
  /** path from the bundle itself (webpack dev keys, esbuild, browserify dependency maps) or from a source map */
  path?: string;
  pathSource?: 'bundle-key' | 'comment' | 'dependency-map' | 'sourcemap';
  start: number;
  end: number;
  line: number;
  size: number;
  /** ids of modules this module requires */
  deps: string[];
  /** export names declared through the bundler runtime (webpack __webpack_require__.d) */
  exports: string[];
  code?: string;
}

export interface BundleImport { source: string; kind: 'import' | 'dynamic-import' | 'require' | 'export-from' | 'import-scripts'; line: number; specifiers?: string[] }

export interface BundleResult {
  bundler: BundlerKind;
  confidence: number;
  chunkIds: string[];
  modules: BundleModule[];
  entryIds: string[];
  imports: BundleImport[];
  exports: string[];
  /** chunk file name pattern or public path seen in the webpack runtime */
  runtime: { publicPath?: string; chunkGlobal?: string; chunkUrlTemplate?: string };
  sourceMappingURL?: string;
  parserErrors: string[];
  notes: string[];
}

type Fn = t.FunctionExpression | t.ArrowFunctionExpression | t.ObjectMethod;

function asFn(n: t.Node | null | undefined): Fn | undefined {
  if (!n) return undefined;
  if (n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression' || n.type === 'ObjectMethod') return n;
  return undefined;
}

function moduleEntries(obj: t.ObjectExpression | t.ArrayExpression): { id: string; fn: Fn; node: t.Node; extra?: t.Node }[] | undefined {
  const out: { id: string; fn: Fn; node: t.Node; extra?: t.Node }[] = [];
  if (obj.type === 'ArrayExpression') {
    obj.elements.forEach((el, i) => {
      const fn = asFn(el);
      if (fn) out.push({ id: String(i), fn, node: el as t.Node });
    });
    return out.length && out.length >= obj.elements.filter(Boolean).length * 0.8 ? out : undefined;
  }
  for (const p of obj.properties) {
    if (p.type === 'SpreadElement') return undefined;
    const k = propKey(p);
    if (k === undefined) return undefined;
    if (p.type === 'ObjectMethod') { out.push({ id: k, fn: p, node: p }); continue; }
    const fn = asFn(p.value);
    if (fn) { out.push({ id: k, fn, node: p }); continue; }
    // browserify: id: [function(require,module,exports){}, {"./dep": 2}]
    if (p.value.type === 'ArrayExpression') {
      const f = asFn(p.value.elements[0]);
      if (f && p.value.elements[1]?.type === 'ObjectExpression') { out.push({ id: k, fn: f, node: p, extra: p.value.elements[1] }); continue; }
    }
    return undefined;
  }
  return out.length ? out : undefined;
}

function fnParams(fn: Fn): string[] {
  return fn.params.map((p) => (p.type === 'Identifier' ? p.name : ''));
}

const PATH_RE = /^(?:\.{0,2}\/)?(?:[\w@.$+-]+\/)*[\w@.$+-]+\.(?:m?jsx?|cjs|tsx?|vue|svelte|json|css|scss|less|wasm|html|mjs|node)$/;

/** Analyze a JavaScript bundle and split it into modules with ids, recovered paths, dependencies and exports. */
export function unpackBundle(code: string, opts: { includeCode?: boolean; maxModuleCode?: number; sourceMap?: string | RawSourceMap } = {}): BundleResult {
  const { ast, errors } = parseJs(code);
  const pos = lineIndex(code);
  const res: BundleResult = { bundler: 'unknown', confidence: 0, chunkIds: [], modules: [], entryIds: [], imports: [], exports: [], runtime: {}, parserErrors: errors, notes: [] };
  const tail = code.slice(-4096);
  for (const [start, end] of sourceMappingComments(tail, false, true)) {
    const v = tail.slice(start, end);
    if (v && !/\s/.test(v)) { res.sourceMappingURL = v; break; }
  }
  const maxCode = opts.maxModuleCode ?? 200_000;

  // ESM / CJS level imports and exports of the file itself
  walk(ast, ({ node }) => {
    const line = node.loc?.start.line ?? 0;
    if (node.type === 'ImportDeclaration') res.imports.push({ source: node.source.value, kind: 'import', line, specifiers: node.specifiers.map((s) => s.local.name) });
    else if ((node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') && node.source) res.imports.push({ source: node.source.value, kind: 'export-from', line });
    else if (node.type === 'ImportExpression' || (node.type === 'CallExpression' && node.callee.type === 'Import')) {
      const src = node.type === 'ImportExpression' ? node.source : node.arguments[0];
      const s = staticString(src as t.Node);
      if (s !== undefined) res.imports.push({ source: s, kind: 'dynamic-import', line });
    } else if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (node.callee.name === 'require' || node.callee.name === 'importScripts')) {
      const s = staticString(node.arguments[0] as t.Node);
      if (s !== undefined) res.imports.push({ source: s, kind: node.callee.name === 'require' ? 'require' : 'import-scripts', line });
    }
    if (node.type === 'ExportNamedDeclaration') {
      if (node.declaration) {
        const d = node.declaration;
        if ((d.type === 'FunctionDeclaration' || d.type === 'ClassDeclaration') && d.id) res.exports.push(d.id.name);
        if (d.type === 'VariableDeclaration') for (const v of d.declarations) if (v.id.type === 'Identifier') res.exports.push(v.id.name);
      }
      for (const s of node.specifiers) res.exports.push(s.exported.type === 'Identifier' ? s.exported.name : s.exported.value);
    }
    if (node.type === 'ExportDefaultDeclaration') res.exports.push('default');
    if (res.imports.length > 5000) return 'stop';
    return undefined;
  });

  type Found = { kind: BundlerKind; entries: { id: string; fn: Fn; node: t.Node; extra?: t.Node }[]; requireName?: string; chunkIds?: string[]; confidence: number };
  const found: Found[] = [];

  walk(ast, ({ node }) => {
    // webpack 5 runtime: var e = {...}; function r(n){ ... e[n](m, m.exports, r) ... }  or  var __webpack_modules__ = {...}
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init && (node.init.type === 'ObjectExpression' || node.init.type === 'ArrayExpression')) {
      const entries = moduleEntries(node.init);
      if (entries && entries.length) {
        const name = node.id.name;
        if (name === '__webpack_modules__') { found.push({ kind: 'webpack5', entries, confidence: 0.98 }); return 'skip'; }
        // look for a call name[x](a, a.exports, req) anywhere
        let req: string | undefined;
        walk(ast, ({ node: m }) => {
          if (req) return 'stop';
          if (m.type === 'CallExpression') {
            let callee: t.Node = m.callee;
            if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier' && callee.property.name === 'call') callee = callee.object;
            if (callee.type === 'MemberExpression' && callee.computed && callee.object.type === 'Identifier' && callee.object.name === name) {
              const hasExports = m.arguments.some((a) => a.type === 'MemberExpression' && !a.computed && a.property.type === 'Identifier' && a.property.name === 'exports');
              if (hasExports) { const last = m.arguments[m.arguments.length - 1]; req = last?.type === 'Identifier' ? last.name : '?'; }
            }
          }
          return undefined;
        });
        if (req) { found.push({ kind: 'webpack5', entries, requireName: req, confidence: 0.9 }); return 'skip'; }
      }
    }
    if (node.type === 'CallExpression') {
      // jsonp chunk: (self.webpackChunkX = self.webpackChunkX || []).push([[ids], {modules}, runtime?])
      if (node.callee.type === 'MemberExpression' && !node.callee.computed && node.callee.property.type === 'Identifier' && node.callee.property.name === 'push') {
        const arg = node.arguments[0];
        const target = node.callee.object;
        const tName = target.type === 'AssignmentExpression' ? memberName(target.left as t.Node) : memberName(target);
        if (arg?.type === 'ArrayExpression' && arg.elements[0]?.type === 'ArrayExpression' && arg.elements[1] && (arg.elements[1].type === 'ObjectExpression' || arg.elements[1].type === 'ArrayExpression')) {
          const entries = moduleEntries(arg.elements[1]);
          if (entries) {
            const ids = (arg.elements[0].elements).map((e) => (e?.type === 'NumericLiteral' ? String(e.value) : staticString(e as t.Node) ?? '?'));
            found.push({ kind: 'webpack-chunk', entries, chunkIds: ids, confidence: tName && /webpack|Jsonp/i.test(tName) ? 0.97 : 0.7 });
            if (tName) res.runtime.chunkGlobal = tName;
            return 'skip';
          }
        }
      }
      // webpack 4 / browserify: (function(modules){...})([fn, fn]) or ({1:[fn,{}]}, {}, [1])
      const callee = node.callee.type === 'CallExpression' ? node.callee : node.callee;
      const isFnCallee = asFn(callee as t.Node) !== undefined || callee.type === 'CallExpression';
      const a0 = node.arguments[0];
      if (isFnCallee && a0 && (a0.type === 'ObjectExpression' || a0.type === 'ArrayExpression')) {
        const entries = moduleEntries(a0);
        if (entries && entries.length) {
          const browserify = entries.some((e) => e.extra) && node.arguments.length >= 3;
          if (browserify) {
            const entryArr = node.arguments[2];
            if (entryArr?.type === 'ArrayExpression') res.entryIds = entryArr.elements.map((e) => (e?.type === 'NumericLiteral' ? String(e.value) : staticString(e as t.Node) ?? '?'));
            found.push({ kind: 'browserify', entries, confidence: 0.9 });
            return 'skip';
          }
          const body = asFn(callee as t.Node);
          const runtimeText = body ? code.slice(body.start ?? 0, Math.min(body.end ?? 0, (body.start ?? 0) + 20000)) : '';
          if (/\.exports/.test(runtimeText) && /\.call\(/.test(runtimeText)) {
            found.push({ kind: 'webpack4', entries, confidence: 0.85 });
            const m = /\.s\s*=\s*(\d+)|__webpack_require__\.s\s*=\s*["']?([^"')]+)/.exec(runtimeText);
            if (m) res.entryIds.push(m[1] ?? m[2] ?? '');
            return 'skip';
          }
        }
      }
      // esbuild: __commonJS({ "path"(exports, module) {...} }) / __esm({...})
      if (node.callee.type === 'Identifier' && /^__(commonJS|esm)$/.test(node.callee.name) && node.arguments[0]?.type === 'ObjectExpression') {
        const entries = moduleEntries(node.arguments[0]);
        if (entries) found.push({ kind: 'esbuild', entries, confidence: 0.95 });
        return 'skip';
      }
    }
    return undefined;
  });

  const program = ast.program;
  if (!found.length) {
    // esbuild ESM output marks inlined files with "// path/to/file.ts" comments at top level
    const marks: { path: string; stmtIndex: number; start: number }[] = [];
    program.body.forEach((st, i) => {
      for (const c of st.leadingComments ?? []) {
        const v = c.value.trim();
        if (c.type === 'CommentLine' && PATH_RE.test(v) && !v.includes(' ')) marks.push({ path: v, stmtIndex: i, start: st.start ?? 0 });
      }
    });
    if (marks.length >= 2) {
      marks.forEach((m, i) => {
        const endStmt = i + 1 < marks.length ? (marks[i + 1] as typeof m).stmtIndex : program.body.length;
        const last = program.body[endStmt - 1];
        const end = last?.end ?? m.start;
        res.modules.push({ id: String(i), path: m.path, pathSource: 'comment', start: m.start, end, line: pos(m.start).line, size: end - m.start, deps: [], exports: [], code: opts.includeCode ? truncate(code.slice(m.start, end), maxCode) : undefined });
      });
      res.bundler = 'esbuild'; res.confidence = 0.8;
    }
  }

  const vite = /__vitePreload|import\.meta\.env|\/assets\/[\w.-]+-[\w-]{8}\.js/.test(code);
  if (!found.length && !res.modules.length) {
    if (vite) { res.bundler = 'vite'; res.confidence = 0.7; }
    else if (/parcelRequire|\$parcel\$/.test(code)) { res.bundler = 'parcel'; res.confidence = 0.7; }
    else if (res.imports.length || res.exports.length) { res.bundler = 'rollup'; res.confidence = 0.4; res.notes.push('ES module chunk without a module registry: rollup, vite and esbuild ESM output inline modules, so only chunk-level imports and exports are listed'); }
  }

  // pick the best registry (largest module count, then confidence)
  found.sort((a, b) => b.entries.length - a.entries.length || b.confidence - a.confidence);
  const best = found[0];
  if (best) {
    res.bundler = best.kind; res.confidence = best.confidence;
    if (best.chunkIds) res.chunkIds = best.chunkIds;
    const seen = new Set<t.Node>();
    for (const f of found) {
      if (f !== best && f.kind !== best.kind) continue;
      for (const e of f.entries) {
        if (seen.has(e.node)) continue;
        seen.add(e.node);
        const start = e.node.start ?? 0, end = e.node.end ?? start;
        const params = fnParams(e.fn);
        const reqName = best.kind === 'esbuild' ? 'require' : best.kind === 'browserify' ? params[0] : params[2];
        const deps: string[] = [];
        const exports: string[] = [];
        const body = e.fn.body;
        walk(body, ({ node }) => {
          if (node.type !== 'CallExpression') return;
          if (reqName && node.callee.type === 'Identifier' && node.callee.name === reqName) {
            const a = node.arguments[0];
            if (a?.type === 'NumericLiteral') deps.push(String(a.value));
            else { const s = staticString(a as t.Node); if (s !== undefined) deps.push(s); }
          }
          // __webpack_require__.d(exports, { name: () => x })  or  n.d(t, ["name", 0, value])
          if (reqName && node.callee.type === 'MemberExpression' && node.callee.object.type === 'Identifier' && node.callee.object.name === reqName && !node.callee.computed && node.callee.property.type === 'Identifier' && node.callee.property.name === 'd') {
            const spec = node.arguments[1];
            if (spec?.type === 'ObjectExpression') for (const p of spec.properties) { if (p.type !== 'SpreadElement') { const k = propKey(p); if (k) exports.push(k); } }
            if (spec?.type === 'ArrayExpression') {
              for (let i = 0; i < spec.elements.length;) {
                const k = staticString(spec.elements[i] as t.Node);
                const kind = spec.elements[i + 1];
                if (k !== undefined) exports.push(k);
                i += kind?.type === 'NumericLiteral' && kind.value === 0 ? 3 : 2;
              }
            }
            if (spec?.type === 'StringLiteral') exports.push(spec.value);
          }
          // esbuild __export(target, { name: () => x })
          if (node.callee.type === 'Identifier' && node.callee.name === '__export' && node.arguments[1]?.type === 'ObjectExpression') {
            for (const p of node.arguments[1].properties) if (p.type !== 'SpreadElement') { const k = propKey(p); if (k) exports.push(k); }
          }
          return undefined;
        });
        let path: string | undefined, pathSource: BundleModule['pathSource'];
        if (PATH_RE.test(e.id) || /[/\\]/.test(e.id)) { path = e.id; pathSource = 'bundle-key'; }
        const mod: BundleModule = { id: e.id, path, pathSource, start, end, line: pos(start).line, size: end - start, deps: [...new Set(deps)], exports: [...new Set(exports)] };
        if (e.extra?.type === 'ObjectExpression') {
          // browserify dependency map gives names for other modules: {"./dep": 2}
          mod.deps = [];
          for (const p of e.extra.properties) {
            if (p.type !== 'ObjectProperty') continue;
            const k = propKey(p);
            const v = p.value.type === 'NumericLiteral' ? String(p.value.value) : staticString(p.value);
            if (k && v) mod.deps.push(v);
          }
        }
        if (opts.includeCode) {
          try { mod.code = truncate(printAst(e.fn.body), maxCode); } catch { mod.code = truncate(code.slice(start, end), maxCode); }
        }
        res.modules.push(mod);
      }
    }
    // browserify: name modules from the dependency maps of others
    if (best.kind === 'browserify') {
      const names = new Map<string, string>();
      for (const f of found) for (const e of f.entries) {
        if (e.extra?.type !== 'ObjectExpression') continue;
        for (const p of e.extra.properties) {
          if (p.type !== 'ObjectProperty') continue;
          const k = propKey(p);
          const v = p.value.type === 'NumericLiteral' ? String(p.value.value) : staticString(p.value);
          if (k && v && !names.has(v)) names.set(v, k);
        }
      }
      for (const m of res.modules) if (!m.path && names.has(m.id)) { m.path = names.get(m.id); m.pathSource = 'dependency-map'; }
    }
    // webpack dev builds carry /*!*** ./path ***!*/ banners
    for (const m of res.modules) {
      if (m.path) continue;
      const before = code.slice(Math.max(0, m.start - 400), m.start);
      const banner = /!\*{3}\s+(.+?)\s+\*{3}!/.exec(before);
      if (banner && banner[1]) { m.path = banner[1]; m.pathSource = 'comment'; }
    }
    // webpack runtime details
    const pp = /\.p\s*=\s*"([^"]{0,300})"/.exec(code);
    if (pp) res.runtime.publicPath = pp[1];
    const u = /\.u\s*=\s*(?:\(?\w+\)?\s*=>|function\s*\(\w+\)\s*\{\s*return)\s*([^;},]{1,300})/.exec(code);
    if (u && u[1]) res.runtime.chunkUrlTemplate = u[1].trim();
    if (best.kind === 'webpack5' && best.requireName) {
      // entry: top level calls of the require function with a literal id outside module bodies
      const inModules = (n: t.Node) => res.modules.some((m) => (n.start ?? 0) >= m.start && (n.end ?? 0) <= m.end);
      walk(ast, ({ node }) => {
        if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === best.requireName && (node.arguments[0]?.type === 'NumericLiteral' || node.arguments[0]?.type === 'StringLiteral') && !inModules(node)) {
          const a = node.arguments[0];
          res.entryIds.push(a.type === 'NumericLiteral' ? String(a.value) : (a as t.StringLiteral).value);
        }
      });
      res.entryIds = [...new Set(res.entryIds)];
    }
  }

  // numeric webpack ids: map each module body back through the source map to its original file
  if (opts.sourceMap && res.modules.some((m) => !m.path)) {
    try {
      const idx = new SourceMapIndex(opts.sourceMap);
      for (const m of res.modules) {
        if (m.path) continue;
        const a = pos(m.start), b = pos(m.end);
        const src = idx.sourceInRange(a.line, a.column, b.line, b.column);
        if (src) { m.path = src.replace(/^webpack:\/\/[^/]*\//, ''); m.pathSource = 'sourcemap'; }
      }
    } catch (e) { res.notes.push(`source map not usable: ${(e as Error).message}`); }
  }
  for (const m of res.modules) if (m.path) m.path = safeRelPath(m.path) || m.path;
  return res;
}
