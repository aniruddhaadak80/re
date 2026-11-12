// Round 3 fixtures and reference values for the import graph, source map and export shape tests.
// Reference tools: esbuild (MIT, its metafile records every resolved import with its kind) and Node
// itself (require/import of the real packages, then reflection on the loaded exports).
// Run from the repo root: node packages/webrt/scripts/make-r3-fixtures.mjs
import { readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const S = join(root, 'samples/webrt');
const require = createRequire(import.meta.url);
const esbuild = await import('esbuild');

// ---- import graph fixture built with esbuild ----
const app = join(S, 'graph-app');
const dist = join(S, 'graph-dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
const esm = await esbuild.build({ absWorkingDir: app, entryPoints: ['src/index.js', 'src/cli.cjs'], bundle: true, format: 'esm', splitting: true, outdir: join(dist, 'esm'), external: ['lodash-es'], platform: 'node', metafile: true, logLevel: 'silent', chunkNames: 'chunk-[hash]' });
const ref = {};
for (const [file, info] of Object.entries(esm.metafile.inputs)) ref[file] = info.imports.map((i) => ({ path: i.path, kind: i.kind, external: !!i.external, original: i.original }));
writeFileSync(join(dist, 'esbuild-inputs.json'), JSON.stringify({ tool: `esbuild ${esbuild.version} metafile`, inputs: ref, outputs: Object.fromEntries(Object.entries(esm.metafile.outputs).map(([k, v]) => [k, { imports: v.imports, entryPoint: v.entryPoint }])) }, null, 1) + '\n');
await esbuild.build({ absWorkingDir: app, entryPoints: ['src/index.js'], bundle: true, format: 'cjs', outfile: join(dist, 'bundle.cjs.js'), external: ['lodash-es'], platform: 'node', sourcemap: true, sourcesContent: true, logLevel: 'silent' });
await esbuild.build({ absWorkingDir: app, entryPoints: ['src/index.js'], bundle: true, format: 'cjs', outfile: join(dist, 'nocontent', 'bundle.cjs.js'), external: ['lodash-es'], platform: 'node', sourcemap: true, sourcesContent: false, minify: true, logLevel: 'silent' });

// ---- export shapes: real semver releases and esbuild bundles of them ----
const shapes = join(S, 'shapes');
function reflect(mod) {
  const out = {};
  const describe = (v) => {
    if (typeof v === 'function') {
      const isClass = /^class[\s{]/.test(Function.prototype.toString.call(v));
      const proto = v.prototype ? Object.getOwnPropertyNames(v.prototype).filter((n) => n !== 'constructor').sort() : [];
      const statics = Object.getOwnPropertyNames(v).filter((n) => !['length', 'name', 'prototype', 'arguments', 'caller'].includes(n)).sort();
      const members = {};
      if (v.prototype) for (const n of proto) { const d = Object.getOwnPropertyDescriptor(v.prototype, n); members[n] = d.get || d.set ? 'accessor' : typeof d.value === 'function' ? `method/${d.value.length}` : 'field'; }
      return { kind: isClass || proto.length ? 'class' : 'function', arity: v.length, members, statics };
    }
    if (v && typeof v === 'object') return { kind: Array.isArray(v) ? 'value' : 'object', keys: Array.isArray(v) ? undefined : Object.keys(v).sort() };
    return { kind: 'value', valueType: v === null ? 'null' : typeof v };
  };
  for (const k of Object.keys(mod).sort()) out[k] = describe(mod[k]);
  return out;
}
const refShapes = { tool: `node ${process.version} require() and Object.getOwnPropertyNames reflection`, packages: {} };
for (const v of ['6.3.1', '7.7.1']) {
  const dir = join(shapes, `semver-${v}`);
  const mod = require(dir);
  refShapes.packages[`semver-${v}`] = reflect(mod);
  await esbuild.build({ entryPoints: [join(dir, 'index.js').replace('semver-6.3.1/index.js', 'semver-6.3.1/semver.js')], bundle: true, format: 'cjs', platform: 'node', outfile: join(shapes, `semver-${v}.bundle.cjs`), logLevel: 'silent' });
  refShapes.packages[`semver-${v}.bundle.cjs`] = reflect(require(join(shapes, `semver-${v}.bundle.cjs`)));
}
// an ES module build with classes: marked 16.4.2 (MIT), copied from its npm package lib/marked.esm.js
refShapes.packages['marked-16.4.2'] = reflect(await import(pathToFileURL(join(shapes, 'marked-16.4.2', 'marked.esm.js')).href));
writeFileSync(join(shapes, 'node-reflection.json'), JSON.stringify(refShapes, null, 1) + '\n');

// ---- source map positions from source-map-js (BSD-3-Clause, the maintained fork of Mozilla's source-map) ----
const { SourceMapConsumer } = require('source-map-js');
const smRef = { tool: `source-map-js ${require('source-map-js/package.json').version}`, maps: {} };
for (const [name, jsPath] of [['marked', join(shapes, 'marked-16.4.2', 'marked.esm.js')], ['graph-cjs', join(dist, 'bundle.cjs.js')], ['graph-min', join(dist, 'nocontent', 'bundle.cjs.js')], ['webpack-prod', join(S, 'webpack-dist', 'bundle.prod.js')]]) {
  const js = readFileSync(jsPath, 'utf8');
  const map = JSON.parse(readFileSync(jsPath + '.map', 'utf8'));
  const c = new SourceMapConsumer(map);
  const lines = js.split('\n');
  const original = [];
  lines.forEach((l, i) => { for (let col = 0; col < l.length; col += Math.max(7, Math.floor(l.length / 60))) original.push({ gen: [i + 1, col], orig: c.originalPositionFor({ line: i + 1, column: col }) }); });
  const generated = [];
  for (const src of c.sources.slice(0, 20)) for (let line = 1; line <= 40; line += 3) {
    const all = c.allGeneratedPositionsFor({ source: src, line });
    if (all.length && all.every((g) => g.line !== null && c.originalPositionFor({ line: g.line, column: g.column }).line === line && c.originalPositionFor({ line: g.line, column: g.column }).source === src)) generated.push({ source: src, line, positions: all.map((g) => ({ line: g.line, column: g.column })) });
  }
  smRef.maps[name] = { file: jsPath.slice(S.length + 1), original, generated };
}
writeFileSync(join(S, 'graph-dist', 'source-map-js-reference.json'), JSON.stringify(smRef) + '\n');
console.log('wrote graph-dist and shapes');
void readFileSync;
