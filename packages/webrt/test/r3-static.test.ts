// Round 3 static features checked against independent references recorded by
// packages/webrt/scripts/make-r3-fixtures.mjs: esbuild's metafile (import graph), webpack stats
// (bundle graph), source-map-js (positions) and Node's own require/import reflection (export shapes).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import fc from 'fast-check';
import {
  buildImportGraph, bundleImportGraph, sourceMapImportGraph, scanModuleImports, traceSourceLocation, compareSourceToBundle, parseStackTrace,
  packageExportShapes, moduleExportShapes, bundleExportShapes, compareExportShapes, SourceMapIndex, sha256Hex, InputError, type ExportShape,
} from '../src/index.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const read = (p: string) => readFileSync(join(S, p), 'utf8');
const json = (p: string) => JSON.parse(read(p));
function walkDir(d: string, out: { path: string; code: string }[] = [], root = d): { path: string; code: string }[] {
  for (const n of readdirSync(d).sort()) { const p = join(d, n); if (statSync(p).isDirectory()) walkDir(p, out, root); else out.push({ path: relative(root, p).split('\\').join('/'), code: readFileSync(p, 'utf8') }); }
  return out;
}
const KIND: Record<string, string> = { 'import-statement': 'import', 'require-call': 'require', 'dynamic-import': 'dynamic-import' };

test('sha256Hex matches node:crypto', () => {
  for (const s of ['', 'abc', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'héllo wörld'.repeat(40)]) assert.equal(sha256Hex(s), createHash('sha256').update(s).digest('hex'));
});

test('import graph of a source folder equals esbuild 0.28 metafile imports', () => {
  const ref = json('graph-dist/esbuild-inputs.json').inputs as Record<string, { path: string; kind: string; external: boolean }[]>;
  const g = buildImportGraph(walkDir(join(S, 'graph-app')));
  for (const [file, imps] of Object.entries(ref)) {
    const mine = g.edges.filter((e) => e.from === file && e.kind !== 'import-type').map((e) => `${KIND_BACK(e.kind)} ${e.to.replace(/^node:/, '')}`).sort();
    const want = imps.map((i) => `${i.kind} ${i.path}`).sort();
    assert.deepEqual(mine, want, file);
  }
  // esbuild drops type-only imports; RevLens keeps them as import-type edges outside cycle detection
  assert.ok(g.edges.some((e) => e.from === 'src/util/strings.ts' && e.to === 'src/util/types.ts' && e.kind === 'import-type'));
  assert.deepEqual(g.cycles.map((c) => c.members), [['src/a.js', 'src/b.js', 'src/c.js']]);
  assert.deepEqual(g.cycles[0]!.loop, ['src/a.js', 'src/b.js', 'src/c.js', 'src/a.js']);
  assert.deepEqual(g.entryPoints, [{ id: 'src/index.js', reason: 'package-main' }, { id: 'src/cli.cjs', reason: 'package-bin' }]);
  assert.deepEqual(g.unreachable, ['src/unused.js', 'src/util/types.ts']);
  assert.deepEqual(g.externals.map((e) => e.name), ['lodash-es', 'node:path']);
  assert.equal(g.nodes.find((n) => n.id === 'src/legacy.cjs')?.format, 'cjs');
  assert.equal(g.nodes.find((n) => n.id === 'src/index.js')?.format, 'esm');
  assert.equal(g.stats.dynamicEdges, 1);
  assert.match(g.mermaid, /^graph LR/);
  assert.match(g.mermaid, /\[\["src\/index\.js"\]\]/);
  assert.match(g.mermaid, /-\.->/);
  assert.match(g.mermaid, /linkStyle [\d,]+ stroke:#d33/);
});
function KIND_BACK(k: string): string { return Object.entries(KIND).find(([, v]) => v === k)?.[0] ?? k; }

test('chunk graph of esbuild ESM split output equals the metafile output imports', () => {
  const ref = json('graph-dist/esbuild-inputs.json').outputs as Record<string, { imports: { path: string; kind: string; external?: boolean }[] }>;
  const g = buildImportGraph(walkDir(join(S, 'graph-dist/esm')), { mode: 'chunks' });
  assert.equal(g.mode, 'chunks');
  for (const [out, info] of Object.entries(ref)) {
    const name = out.replace('../graph-dist/esm/', '');
    const mine = g.edges.filter((e) => e.from === name).map((e) => `${KIND_BACK(e.kind)} ${e.to.replace(/^node:/, '')}`).sort();
    const want = info.imports.map((i) => `${i.kind} ${i.path.replace('../graph-dist/esm/', '')}`).sort();
    assert.deepEqual(mine, want, name);
  }
  assert.deepEqual(g.entryPoints.map((e) => e.id).sort(), ['cli.js', 'index.js']);
});

test('bundle graph: esbuild CommonJS bundle recovers the source edges and the cycle from __esm and __commonJS factories', () => {
  const g = bundleImportGraph(read('graph-dist/bundle.cjs.js'));
  assert.equal(g.bundler, 'esbuild');
  const edges = new Set(g.edges.map((e) => `${e.from} ${e.kind} ${e.to}`));
  for (const e of ['src/a.js bundle-dep src/b.js', 'src/b.js bundle-dep src/c.js', 'src/c.js bundle-dep src/a.js', 'src/lazy.js bundle-dep src/c.js', 'src/legacy.cjs bundle-dep src/helpers.cjs', 'src/legacy.cjs bundle-dep path', '<entry> bundle-dep src/a.js', '<entry> bundle-dep src/legacy.cjs', '<entry> dynamic-import src/lazy.js']) assert.ok(edges.has(e), e);
  assert.deepEqual(g.cycles.map((c) => c.members), [['src/a.js', 'src/b.js', 'src/c.js']]);
});

test('bundle graph: webpack 5 production and development bundles match webpack stats', () => {
  const stats = json('webpack-dist/stats.prod.json') as { chunk: number; modules: { id: number | string; name: string }[] }[];
  const lazy = stats.find((c) => c.modules.some((m) => m.name === './dashboard.js'))!.modules.find((m) => m.name === './dashboard.js')!;
  const prod = bundleImportGraph(read('webpack-dist/bundle.prod.js'), { sourceMap: read('webpack-dist/bundle.prod.js.map') });
  assert.deepEqual(prod.entryPoints, [{ id: 'index.js', reason: 'bundle-entry' }]);
  const pe = prod.edges.map((e) => `${e.from} ${e.kind} ${e.to}`).sort();
  assert.deepEqual(pe, ['index.js bundle-dep api.js', 'index.js bundle-dep util/format.js', `index.js dynamic-import chunk-module:${lazy.id}`]);
  const dev = bundleImportGraph(read('webpack-dist/bundle.dev.js'));
  assert.deepEqual(dev.entryPoints, [{ id: 'index.js', reason: 'bundle-entry' }]);
  assert.deepEqual(dev.edges.map((e) => `${e.from} ${e.kind} ${e.to}`).sort(), ['index.js bundle-dep api.js', 'index.js bundle-dep util/format.js', 'index.js dynamic-import chunk-module:dashboard.js']);
});

test('source map graph: original sources inside the map give the same graph as the folder', () => {
  const g = sourceMapImportGraph(read('graph-dist/bundle.cjs.js.map'));
  const folder = buildImportGraph(walkDir(join(S, 'graph-app')));
  const strip = (s: string) => s.replace(/^graph-app\//, '');
  const a = g.edges.filter((e) => e.kind !== 'import-type').map((e) => `${strip(e.from)} ${e.kind} ${strip(e.to)}`).sort();
  const b = folder.edges.filter((e) => e.kind !== 'import-type' && e.from !== 'src/cli.cjs').map((e) => `${e.from} ${e.kind} ${e.to}`).sort();
  assert.deepEqual(a, b);
  assert.equal(g.cycles.length, 1);
});

test('scanModuleImports: workers, require.resolve, template imports, vite preload and TypeScript import =', () => {
  const s = scanModuleImports(`
    const w = new Worker(new URL('./w.js', import.meta.url));
    const p = require.resolve('./p.json');
    const m = import(\`./locale/\${lang}.js\`);
    __vitePreload(() => import('./page.js'), __VITE_IS_MODERN__ ? ["assets/page.css", "assets/dep.js"] : void 0);
  `, 'app.js');
  assert.deepEqual(s.imports.map((i) => `${i.kind} ${i.specifier}${i.dynamicTemplate ? ' T' : ''}`).sort(), ['dynamic-import ./locale/${}.js T', 'dynamic-import ./page.js', 'preload assets/dep.js', 'preload assets/page.css', 'require-resolve ./p.json', 'worker ./w.js']);
  const ts = scanModuleImports(`import fs = require('fs'); import type { X } from './x'; export type { Y } from './y';`, 'a.ts');
  assert.deepEqual(ts.imports.map((i) => `${i.kind} ${i.specifier}`), ['require fs', 'import-type ./x', 'import-type ./y']);
});

interface SmRef { file: string; original: { gen: [number, number]; orig: { source: string | null; line: number | null; column: number | null; name: string | null } }[]; generated: { source: string; line: number; positions: { line: number; column: number }[] }[] }
// source-map-js normalises "webpack:///./a.js" to "webpack:///a.js"; RevLens keeps the map's own spelling
const normSource = (s?: string) => s?.replace(/\/\.\//g, '/');
const SMREF = () => json('graph-dist/source-map-js-reference.json').maps as Record<string, SmRef>;

test('trace_web_source_location: originalPositionFor equals source-map-js on four real maps', () => {
  let checked = 0;
  for (const [name, r] of Object.entries(SMREF())) {
    const res = traceSourceLocation({ sourceMap: read(r.file + '.map'), positions: r.original.map((o) => ({ line: o.gen[0], column: o.gen[1] })), bundleCode: read(r.file) });
    r.original.forEach((o, i) => {
      const got = res.locations[i]!.original;
      const at = `${name} ${o.gen.join(':')}`;
      if (o.orig.source === null) { assert.equal(got, undefined, at); return; }
      assert.equal(normSource(got?.source), o.orig.source, at);
      assert.equal(got?.line, o.orig.line, at);
      assert.equal(got?.column, o.orig.column, at);
      assert.equal(got?.name ?? null, o.orig.name, at);
      checked++;
    });
  }
  assert.ok(checked > 1500, `checked ${checked}`);
});

test('generatedPositionsFor equals source-map-js allGeneratedPositionsFor', () => {
  let checked = 0;
  for (const [name, r] of Object.entries(SMREF())) {
    const raw = JSON.parse(read(r.file + '.map')).sources as string[];
    const idx = new SourceMapIndex(read(r.file + '.map'));
    for (const g of r.generated) {
      const mine = idx.generatedPositionsFor(raw.find((x) => normSource(x) === g.source) ?? g.source, g.line).map((p) => `${p.line}:${p.column}`);
      assert.deepEqual(mine, g.positions.map((p) => `${p.line}:${p.column}`), `${name} ${g.source}:${g.line}`);
      checked++;
    }
  }
  assert.ok(checked >= 100, `checked ${checked}`);
});

test('trace a stack trace through the marked source map: original file, line text, enclosing function and bundle module', () => {
  const map = read('shapes/marked-16.4.2/marked.esm.js.map');
  const r = SMREF().marked!;
  const hit = r.original.find((o) => o.orig.source === '../src/Lexer.ts' && o.orig.name)!;
  const stack = `Error: boom\n    at Lexer.lex (https://cdn.example/marked.esm.js:${hit.gen[0]}:${hit.gen[1] + 1})\n    at async x@https://cdn.example/marked.esm.js:${hit.gen[0]}:${hit.gen[1] + 1}`;
  const frames = parseStackTrace(stack);
  assert.equal(frames.length, 2);
  assert.equal(frames[0]!.functionName, 'Lexer.lex');
  const t = traceSourceLocation({ sourceMap: map, stack });
  assert.equal(t.locations[0]!.original?.source, '../src/Lexer.ts');
  assert.equal(t.locations[0]!.original?.line, hit.orig.line);
  assert.equal(t.locations[0]!.original?.path, 'src/Lexer.ts');
  const lexer = JSON.parse(map).sourcesContent[JSON.parse(map).sources.indexOf('../src/Lexer.ts')] as string;
  assert.equal(t.locations[0]!.original?.lineText, lexer.split('\n')[hit.orig.line! - 1]!.slice(0, 400));
  assert.ok(t.locations[0]!.original?.enclosingFunction, 'found an enclosing function in the TypeScript source');
  // webpack: positions inside module bodies report the bundle module
  const wp = traceSourceLocation({ sourceMap: read('webpack-dist/bundle.prod.js.map'), bundleCode: read('webpack-dist/bundle.prod.js'), positions: SMREF()['webpack-prod']!.original.filter((o) => o.orig.source === 'webpack:///api.js').slice(0, 3).map((o) => ({ line: o.gen[0], column: o.gen[1] })) });
  for (const l of wp.locations) assert.equal(l.bundleModule?.id, '504'); // webpack stats: ./api.js is module 504
});

test('compare_source_to_bundle: same folder, edited, deleted and new files, and a map without sourcesContent', () => {
  const folder = walkDir(join(S, 'graph-app')).map((f) => ({ path: f.path, content: f.code }));
  const same = compareSourceToBundle(read('graph-dist/bundle.cjs.js.map'), folder);
  assert.equal(same.summary.changed, 0);
  assert.equal(same.summary.missingInFolder, 0);
  assert.equal(same.summary.same, 8);
  assert.deepEqual(same.missingFromBundle, ['src/cli.cjs', 'src/unused.js', 'src/util/types.ts']);
  for (const f of same.files) assert.equal(f.bundleSha256, sha256Hex(folder.find((x) => x.path === f.folderPath)!.content));
  const edited = folder.filter((f) => f.path !== 'src/helpers.cjs').map((f) => f.path === 'src/b.js' ? { ...f, content: f.content.replace('return c();', 'const v = c();\n  return v * 2;') } : f);
  edited.push({ path: 'src/new-feature.js', content: 'export const x = 1;\n' });
  const diff = compareSourceToBundle(read('graph-dist/bundle.cjs.js.map'), edited);
  const b = diff.files.find((f) => f.path.endsWith('src/b.js'))!;
  assert.equal(b.status, 'changed');
  assert.equal(b.linesAdded, 2); assert.equal(b.linesRemoved, 1); assert.equal(b.firstDifferentLine, 2);
  assert.equal(diff.files.find((f) => f.path.endsWith('src/helpers.cjs'))!.status, 'missing-in-folder');
  assert.ok(diff.missingFromBundle.includes('src/new-feature.js'));
  // minified map without sourcesContent: mappings are checked against the folder file
  const nc = compareSourceToBundle(read('graph-dist/nocontent/bundle.cjs.js.map'), folder);
  assert.equal(nc.summary.changed, 0);
  assert.equal(nc.summary.noContent, 8);
  const shifted = folder.map((f) => f.path === 'src/a.js' ? { ...f, content: f.content.replace('export function startA', '\n\n\nexport function begin') } : f.path === 'src/lazy.js' ? { ...f, content: 'export const x = 1;\n' } : f);
  const nc2 = compareSourceToBundle(read('graph-dist/nocontent/bundle.cjs.js.map'), shifted);
  assert.equal(nc2.files.find((f) => f.path.endsWith('src/a.js'))!.status, 'changed');
  assert.ok((nc2.files.find((f) => f.path.endsWith('src/lazy.js'))!.mappingsOutOfRange ?? 0) > 0);
});

// ---- export shapes against Node reflection ----
type Ref = Record<string, { kind: string; arity?: number; members?: Record<string, string>; statics?: string[]; keys?: string[]; valueType?: string }>;
const REFL = () => json('shapes/node-reflection.json').packages as Record<string, Ref>;
// values Node only knows after running code: semver fills `tokens` in a loop, marked builds parseInline with a call
const DYNAMIC = new Set(['tokens', 'parseInline']);
function checkAgainst(name: string, got: Record<string, ExportShape>): number {
  const ref = REFL()[name]!;
  const names = Object.keys(got).filter((k) => k !== 'module.exports' && k !== 'default').sort();
  assert.deepEqual(names, Object.keys(ref).sort(), `${name}: export names`);
  let n = 0;
  for (const [k, e] of Object.entries(ref)) {
    if (DYNAMIC.has(k)) continue;
    const g = got[k]!;
    assert.equal(g.kind, e.kind, `${name}.${k} kind`);
    if (e.kind === 'function' || e.kind === 'class') assert.equal(g.arity, e.arity, `${name}.${k} arity`);
    if (e.kind === 'class') {
      const pm = Object.fromEntries((g.members ?? []).filter((m) => !m.static && m.kind !== 'field').map((m) => [m.name, m.kind === 'method' ? `method/${m.arity}` : 'accessor']));
      assert.deepEqual(pm, e.members, `${name}.${k} prototype members`);
    }
    if (e.kind === 'object') assert.deepEqual(g.keys, e.keys, `${name}.${k} keys`);
    n++;
  }
  return n;
}

test('export shapes of real semver 6.3.1 and 7.7.1 packages equal Node require() reflection', () => {
  for (const v of ['6.3.1', '7.7.1']) {
    const p = packageExportShapes(walkDir(join(S, `shapes/semver-${v}`)));
    assert.equal(p.version, v);
    assert.ok(checkAgainst(`semver-${v}`, p.exports) >= 40);
  }
  // semver 6 exports the SemVer class itself with every helper as a static property
  const six = packageExportShapes(walkDir(join(S, 'shapes/semver-6.3.1')));
  assert.equal(six.exports['module.exports']!.kind, 'class');
  assert.equal(six.exports['module.exports']!.keys?.length, 43);
});

test('export shapes of esbuild CommonJS bundles of semver and the marked ESM build equal Node reflection', () => {
  for (const v of ['6.3.1', '7.7.1']) assert.ok(checkAgainst(`semver-${v}.bundle.cjs`, bundleExportShapes(read(`shapes/semver-${v}.bundle.cjs`)).top.exports) >= 40);
  const m = moduleExportShapes(read('shapes/marked-16.4.2/marked.esm.js'));
  assert.equal(m.format, 'esm');
  assert.ok(checkAgainst('marked-16.4.2', m.exports) >= 17);
});

test('compare_javascript_export_shapes: semver 6.3.1 to 7.7.1 equals the difference of the reflections', () => {
  const a = packageExportShapes(walkDir(join(S, 'shapes/semver-6.3.1'))).exports;
  const b = packageExportShapes(walkDir(join(S, 'shapes/semver-7.7.1'))).exports;
  delete a['module.exports']; delete b['module.exports'];
  const c = compareExportShapes(a, b);
  const ra = REFL()['semver-6.3.1']!, rb = REFL()['semver-7.7.1']!;
  assert.deepEqual(c.added, Object.keys(rb).filter((k) => !(k in ra)).sort());
  assert.deepEqual(c.removed, Object.keys(ra).filter((k) => !(k in rb)).sort());
  // functions whose arity changed per reflection
  const arity = Object.keys(ra).filter((k) => k in rb && ra[k]!.arity !== undefined && rb[k]!.arity !== undefined && ra[k]!.arity !== rb[k]!.arity && !DYNAMIC.has(k)).sort();
  assert.deepEqual(c.changed.filter((x) => x.change === 'arity').map((x) => x.name).sort(), arity);
  // prototype member changes per reflection
  for (const k of ['SemVer', 'Range', 'Comparator']) {
    const before = ra[k]!.members!, after = rb[k]!.members!;
    const added = Object.keys(after).filter((n) => !(n in before)).sort();
    const changedSig = Object.keys(before).filter((n) => n in after && before[n] !== after[n]).sort();
    const ch = c.changed.find((x) => x.name === k && x.change === 'members');
    assert.deepEqual((ch?.membersAdded ?? []).filter((n) => !n.startsWith('static ')).sort(), added, `${k} added members`);
    assert.deepEqual((ch?.membersChanged ?? []).map((m) => m.name).filter((n) => !n.startsWith('static ')).sort(), changedSig, `${k} changed members`);
  }
  assert.ok(c.breaking >= 1);
  assert.ok(c.score > 0.5 && c.score < 1);
});

// ---- hostile inputs ----
function safe(fn: () => unknown): void {
  try { fn(); } catch (e) { if (!(e instanceof InputError) && !(e instanceof SyntaxError)) throw e; }
}

test('hostile: random text never crashes the graph, shape and source map tools', () => {
  const t0 = Date.now();
  fc.assert(fc.property(fc.string({ maxLength: 2000 }), (s) => {
    safe(() => scanModuleImports(s));
    safe(() => buildImportGraph([{ path: 'a.js', code: s }, { path: 'b.ts', code: `import './a.js';${s}` }]));
    safe(() => moduleExportShapes(s));
    safe(() => bundleExportShapes(s));
    safe(() => traceSourceLocation({ sourceMap: s, positions: [{ line: 1, column: 0 }] }));
    safe(() => compareSourceToBundle(s, [{ path: 'a.js', content: s }]));
    safe(() => parseStackTrace(s));
  }), { numRuns: 300 });
  assert.ok(Date.now() - t0 < 60_000);
});

test('hostile: truncated and bit-flipped real bundles and maps', () => {
  const bundle = read('graph-dist/bundle.cjs.js'), map = read('graph-dist/bundle.cjs.js.map');
  const t0 = Date.now();
  fc.assert(fc.property(fc.integer({ min: 0, max: bundle.length }), fc.integer({ min: 0, max: map.length - 1 }), fc.integer({ min: 32, max: 126 }), (cut, pos, ch) => {
    const b = bundle.slice(0, cut);
    const m = map.slice(0, pos) + String.fromCharCode(ch) + map.slice(pos + 1);
    safe(() => bundleImportGraph(b));
    safe(() => bundleExportShapes(b));
    safe(() => sourceMapImportGraph(m));
    safe(() => traceSourceLocation({ sourceMap: m, bundleCode: b, positions: [{ line: 3, column: 4 }, { line: -1, column: 2 }] }));
    safe(() => compareSourceToBundle(m, [{ path: 'src/a.js', content: b }]));
  }), { numRuns: 120 });
  assert.ok(Date.now() - t0 < 60_000);
});

test('hostile: deep cycles, huge fan-out and self imports stay bounded', () => {
  const files = Array.from({ length: 3000 }, (_, i) => ({ path: `m${i}.js`, code: `import './m${(i + 1) % 3000}.js'; import './m${i}.js';` }));
  const t0 = Date.now();
  const g = buildImportGraph(files);
  assert.equal(g.cycles.length, 1);
  assert.equal(g.cycles[0]!.members.length, 3000);
  assert.ok(Date.now() - t0 < 20_000);
  assert.ok(g.mermaid.split('\n').length < 2000);
  assert.throws(() => buildImportGraph(Array.from({ length: 20_001 }, (_, i) => ({ path: `${i}.js`, code: '' }))), InputError);
});
