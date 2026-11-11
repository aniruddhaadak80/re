// Downloads large real Go binaries (esbuild 0.24.0 and 0.23.1, MIT) from the npm registry into
// samples/.cache/disasm for the performance tests. Run: node packages/disasm/scripts/fetch-fixtures.mjs
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const cache = join(here, '..', '..', '..', 'samples', '.cache', 'disasm');
mkdirSync(cache, { recursive: true });

/** Minimal tar reader: returns the named member. */
function untar(buf, member) {
  let off = 0;
  while (off + 512 <= buf.length) {
    const name = buf.subarray(off, off + 100).toString('latin1').replace(/\0.*$/s, '');
    if (!name) break;
    const size = parseInt(buf.subarray(off + 124, off + 136).toString('latin1').replace(/\0.*$/s, '').trim() || '0', 8);
    if (name === member) return buf.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`member ${member} not found`);
}

// 0.24.0 is the main fixture; 0.23.1 is the older version for cross version function matching.
const targets = [
  ['@esbuild/linux-x64', 'package/bin/esbuild', 'esbuild-linux-x64', '0.24.0'],
  ['@esbuild/win32-x64', 'package/esbuild.exe', 'esbuild-win32-x64.exe', '0.24.0'],
  ['@esbuild/darwin-arm64', 'package/bin/esbuild', 'esbuild-darwin-arm64', '0.24.0'],
  ['@esbuild/linux-x64', 'package/bin/esbuild', 'esbuild-linux-x64-0.23.1', '0.23.1'],
  ['@esbuild/darwin-arm64', 'package/bin/esbuild', 'esbuild-darwin-arm64-0.23.1', '0.23.1'],
];
for (const [pkg, member, out, version] of targets) {
  const dest = join(cache, out);
  if (existsSync(dest)) continue;
  const meta = await (await fetch(`https://registry.npmjs.org/${pkg.replace('/', '%2f')}/${version}`)).json();
  const r = await fetch(meta.dist.tarball);
  if (!r.ok) throw new Error(`${pkg}: HTTP ${r.status}`);
  const tgz = Buffer.from(await r.arrayBuffer());
  writeFileSync(dest, untar(gunzipSync(tgz), member));
  console.log('fetched', out);
}
void readFileSync;
console.log('fixtures ready in', cache);
