// Regenerates the real test fixtures in samples/webrt with real toolchains:
//   javascript-obfuscator (BSD-2-Clause), webpack (MIT), @electron/asar (MIT), python3 sqlite3.
// Run from the repo root: node packages/webrt/scripts/make-fixtures.mjs
import { readFileSync, writeFileSync, rmSync, mkdirSync, existsSync, copyFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const S = join(root, 'samples/webrt');

async function obfuscated() {
  const { default: JO } = await import('javascript-obfuscator');
  const variants = {
    'obfuscated.js': ['obf-input.js', { stringArrayEncoding: ['rc4'], controlFlowFlattening: true, controlFlowFlatteningThreshold: 1 }],
    'obfuscated-base64.js': ['obf-input.js', { stringArrayEncoding: ['base64'] }],
    'obfuscated-cff.js': ['obf-cff-input.js', { stringArrayEncoding: ['none'], controlFlowFlattening: true, controlFlowFlatteningThreshold: 1 }],
  };
  for (const [name, [input, extra]] of Object.entries(variants)) {
    const src = readFileSync(join(S, input), 'utf8');
    const r = JO.obfuscate(src, { seed: 1337, compact: true, stringArray: true, stringArrayThreshold: 1, rotateStringArray: true, shuffleStringArray: true, stringArrayWrappersCount: 2, stringArrayWrappersType: 'function', stringArrayIndexShift: true, ...extra });
    writeFileSync(join(S, name), r.getObfuscatedCode() + '\n');
  }
}

async function bundles() {
  const { default: webpack } = await import('webpack');
  const out = join(S, 'webpack-dist');
  rmSync(out, { recursive: true, force: true });
  const run = (cfg) => new Promise((res, rej) => webpack(cfg, (err, stats) => (err || stats.hasErrors() ? rej(err ?? new Error(stats.toString())) : res(stats))));
  const base = { context: join(S, 'webpack-src'), entry: './index.js', target: 'web', output: { path: out, publicPath: '/' }, optimization: { moduleIds: 'deterministic', chunkIds: 'deterministic', concatenateModules: false } };
  const modulesOf = (stats) => stats.toJson({ chunks: true, chunkModules: true, ids: true, modules: false, assets: false, source: false, reasons: false }).chunks.map((c) => ({ chunk: c.id, files: c.files, modules: c.modules.map((m) => ({ id: m.id, name: m.name })) }));
  const prod = await run({ ...base, mode: 'production', devtool: 'source-map', output: { ...base.output, filename: 'bundle.prod.js', chunkFilename: 'chunk.[id].prod.js' } });
  // webpack's own record of chunk and module ids, used by the tests as the reference
  writeFileSync(join(out, 'stats.prod.json'), JSON.stringify(modulesOf(prod), null, 1) + '\n');
  const dev = await run({ ...base, mode: 'development', devtool: false, output: { ...base.output, filename: 'bundle.dev.js', chunkFilename: 'chunk.[name].dev.js' }, optimization: { concatenateModules: false } });
  writeFileSync(join(out, 'stats.dev.json'), JSON.stringify(modulesOf(dev), null, 1) + '\n');
}

async function asar() {
  const asarMod = await import('@electron/asar');
  const createPackageWithOptions = asarMod.createPackageWithOptions ?? asarMod.default?.createPackageWithOptions;
  const dest = join(S, 'electron/app.asar');
  rmSync(join(S, 'electron'), { recursive: true, force: true });
  mkdirSync(join(S, 'electron'), { recursive: true });
  await createPackageWithOptions(join(S, 'electron-app'), dest, { unpack: '*.node' });
}

function sqlite() {
  const db = join(S, 'fixture.sqlite');
  rmSync(db, { force: true });
  execFileSync('python3', [join(here, 'make-sqlite.py'), db], { stdio: 'inherit', timeout: 60_000 });
}

await obfuscated();
await bundles();
await asar();
sqlite();
console.log('fixtures written to', S);
