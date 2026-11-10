// Downloads larger real world samples into samples/.cache for the test suite.
// Every file comes from its official public source. Run: node samples/fetch-samples.mjs
import { mkdirSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const cache = join(here, '.cache');
mkdirSync(cache, { recursive: true });

async function get(url, out) {
  if (existsSync(join(cache, out))) return;
  const r = await fetch(url, { redirect: 'follow' });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  writeFileSync(join(cache, out), new Uint8Array(await r.arrayBuffer()));
  console.log('fetched', out);
}

async function npmFile(pkg, version, member, out) {
  if (existsSync(join(cache, out))) return;
  const tgz = join(cache, `${out}.tgz`);
  const meta = await (await fetch(`https://registry.npmjs.org/${pkg.replace('/', '%2f')}/${version}`)).json();
  await get(meta.dist.tarball, `${out}.tgz`);
  execFileSync('tar', ['-xzf', tgz, '-C', cache, member]);
  renameSync(join(cache, member), join(cache, out));
}

await npmFile('@esbuild/win32-x64', '0.24.0', 'package/esbuild.exe', 'esbuild.exe');
await npmFile('@esbuild/darwin-arm64', '0.24.0', 'package/bin/esbuild', 'esbuild-macho');
await npmFile('esbuild-wasm', '0.24.0', 'package/esbuild.wasm', 'esbuild.wasm');
await get('https://addons.mozilla.org/firefox/downloads/file/4458450/ublock_origin-1.63.2.xpi', 'ublock.xpi').catch(() =>
  get('https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi', 'ublock.xpi'));
await get('https://open-vsx.org/api/redhat/vscode-yaml/1.15.0/file/redhat.vscode-yaml-1.15.0.vsix', 'yaml.vsix');
console.log('samples ready in', cache);
