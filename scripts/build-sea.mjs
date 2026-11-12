#!/usr/bin/env node
// Build the CLI as a Node single executable application (SEA) for the platform this runs on.
// Steps: bundle packages/cli/dist with esbuild into one CommonJS file, make a SEA blob with the
// disassembler WebAssembly files as assets, copy this Node binary, inject the blob with postject,
// re-sign on macOS, then run `<binary> --version` as a smoke test and write a .sha256 file.
//
//   npm run build && node scripts/build-sea.mjs [--out dist-sea] [--name <bin>] [--node <path to node>]
//
// The binary name comes from the first "bin" entry of packages/cli/package.json, so a rename of the
// CLI needs no change here. Needs Node 22.12 or newer; esbuild and postject are taken from node_modules
// when present and fetched with npx otherwise.
import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, createReadStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(join(root, 'package.json'));
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };

const cliPkg = JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8'));
const binName = opt('name', Object.keys(cliPkg.bin ?? {})[0] ?? cliPkg.name);
const version = cliPkg.version;
const out = resolve(opt('out', join(root, 'dist-sea')));
const nodeBin = resolve(opt('node', process.execPath));
const plat = { linux: 'linux', darwin: 'macos', win32: 'windows' }[process.platform] ?? process.platform;
const arch = process.arch;
const exe = process.platform === 'win32' ? '.exe' : '';
const asset = `${binName}-${plat}-${arch}${exe}`;
const target = join(out, asset);
const log = (m) => process.stderr.write(`[sea] ${m}\n`);

if (!existsSync(join(root, 'packages/cli/dist/index.js'))) throw new Error('packages/cli/dist is missing. Run npm run build first.');
mkdirSync(out, { recursive: true });

// 1. bundle
const bundle = join(out, `${binName}.bundle.cjs`);
let esbuild;
try { esbuild = require('esbuild'); } catch { esbuild = undefined; }
const OPTIONAL = ['playwright', 'playwright-core', 'ws', 'bufferutil', 'utf-8-validate', 'fsevents', 'electron', 'chromium-bidi'];
const esopts = {
  entryPoints: [join(root, 'scripts/sea/entry.mjs')], bundle: true, platform: 'node', format: 'cjs', target: 'node22',
  outfile: bundle, external: OPTIONAL, mainFields: ['module', 'main'], conditions: ['node', 'import', 'default'],
  // dynamic import() is turned into require(), which a SEA can use for Node built in modules
  supported: { 'dynamic-import': false },
  define: { 'import.meta.url': '__rl_import_meta_url' },
  banner: { js: 'var __rl_import_meta_url = require("url").pathToFileURL(__filename).href;' },
  legalComments: 'none', logLevel: 'warning', minifySyntax: true, keepNames: true,
};
if (esbuild) await esbuild.build(esopts);
else {
  log('esbuild not in node_modules, using npx');
  execFileSync('npx', ['--yes', 'esbuild@0.28', esopts.entryPoints[0], '--bundle', '--platform=node', '--format=cjs', '--target=node22', `--outfile=${bundle}`,
    ...OPTIONAL.map((x) => `--external:${x}`), '--supported:dynamic-import=false', '--define:import.meta.url=__rl_import_meta_url',
    `--banner:js=var __rl_import_meta_url = require("url").pathToFileURL(__filename).href;`, '--log-level=warning'], { stdio: 'inherit', shell: process.platform === 'win32' });
}
// The bundle must not hold the SEA fuse string itself, or postject finds it twice. RevLens code that
// detects SEA binaries names it as a literal; split such literals so the value only exists at run time.
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
{
  let text = readFileSync(bundle, 'utf8');
  text = text.split(`"${FUSE}"`).join(`("NODE_SEA_FUSE" + "${FUSE.slice('NODE_SEA_FUSE'.length)}")`).split(`'${FUSE}'`).join(`('NODE_SEA_FUSE' + '${FUSE.slice('NODE_SEA_FUSE'.length)}')`);
  if (text.includes(FUSE)) throw new Error('the bundle still contains the SEA fuse string in a form this script cannot split');
  writeFileSync(bundle, text);
}
log(`bundled ${basename(bundle)} (${(statSync(bundle).size / 1048576).toFixed(1)} MiB)`);

// 2. blob with assets
const wasm = (spec, file) => join(dirname(require.resolve(spec)), file);
const assets = {
  'iced_x86_bg.wasm': wasm('iced-x86/package.json', 'iced_x86_bg.wasm'),
  'capstone.wasm': wasm('@alexaltea/capstone-js/dist/capstone.js', 'capstone.wasm'),
};
// Scripts the bridges hand to other programs (Cutter plugin, JEB script). The key list lives in the
// bridges package, so the binary and the code that reads the assets cannot drift apart.
const { BUNDLED_SCRIPTS } = await import(pathToFileURL(join(root, 'packages/bridges/dist/assets.js')).href);
for (const [key, rel] of Object.entries(BUNDLED_SCRIPTS)) assets[key] = join(root, 'packages/bridges', rel);
for (const [k, v] of Object.entries(assets)) if (!existsSync(v)) throw new Error(`asset ${k} not found at ${v}`);
const blob = join(out, `${binName}.blob`);
const config = join(out, 'sea-config.json');
writeFileSync(config, JSON.stringify({ main: bundle, output: blob, disableExperimentalSEAWarning: true, useSnapshot: false, useCodeCache: true, assets }, null, 2));
execFileSync(nodeBin, ['--experimental-sea-config', config], { stdio: 'inherit' });

// 3. copy node and inject
rmSync(target, { force: true });
copyFileSync(nodeBin, target);
chmodSync(target, 0o755);
if (process.platform === 'darwin') execFileSync('codesign', ['--remove-signature', target], { stdio: 'inherit' });
const postjectArgs = [target, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2', ...(process.platform === 'darwin' ? ['--macho-segment-name', 'NODE_SEA'] : [])];
let postject;
try { postject = require.resolve('postject/dist/cli.js'); } catch { postject = undefined; }
if (postject) execFileSync(process.execPath, [postject, ...postjectArgs], { stdio: 'inherit' });
else execFileSync('npx', ['--yes', 'postject@1.0.0-alpha.6', ...postjectArgs], { stdio: 'inherit', shell: process.platform === 'win32' });
if (process.platform === 'darwin') execFileSync('codesign', ['--sign', '-', target], { stdio: 'inherit' });

// 4. smoke test and checksum
const v = execFileSync(target, ['--version'], { encoding: 'utf8' }).trim();
if (v !== version) throw new Error(`${asset} --version printed "${v}", expected "${version}"`);
// the embedded Cutter plugin must come out byte for byte, in a private folder
{
  const r = JSON.parse(execFileSync(target, ['bridge', 'cutter_sessions', '--json'], { encoding: 'utf8', maxBuffer: 16 << 20 }));
  const script = r.plugin?.script;
  const want = readFileSync(join(root, 'packages/bridges', BUNDLED_SCRIPTS['bridges/cutter/revlens_cutter_bridge.py']));
  if (!script || !existsSync(script) || Buffer.compare(readFileSync(script), want) !== 0) throw new Error(`the embedded Cutter plugin was not written out correctly (got ${script})`);
  if (process.platform !== 'win32' && (statSync(dirname(script)).mode & 0o077) !== 0) throw new Error(`${dirname(script)} is not private`);
  log(`embedded Cutter plugin ok at ${script}`);
}
const sha = await new Promise((ok, bad) => { const h = createHash('sha256'); createReadStream(target).on('data', (d) => h.update(d)).on('end', () => ok(h.digest('hex'))).on('error', bad); });
writeFileSync(`${target}.sha256`, `${sha}  ${asset}\n`);
for (const f of [bundle, blob, config]) rmSync(f, { force: true });
log(`${asset}  ${(statSync(target).size / 1048576).toFixed(1)} MiB  sha256 ${sha}`);
process.stdout.write(JSON.stringify({ asset, path: target, version: v, sha256: sha, bytes: statSync(target).size }) + '\n');
