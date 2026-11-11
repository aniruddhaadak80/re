// Downloads fixtures that cannot be committed into samples/.cache/extras.
// Run: node packages/extras/scripts/fetch-fixtures.mjs   (tests that need them skip when absent)
import { mkdirSync, writeFileSync, existsSync, renameSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const cache = join(here, '..', '..', '..', 'samples', '.cache', 'extras');
mkdirSync(cache, { recursive: true });

async function get(url) {
  const r = await fetch(url, { redirect: 'follow' });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

/** Extract one stored or deflated member from a zip (enough for these archives). */
function unzipMember(zip, name) {
  const dv = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('no zip directory');
  let p = dv.getUint32(eocd + 16, true);
  const n = dv.getUint16(eocd + 10, true);
  for (let k = 0; k < n; k++) {
    const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
    const nl = dv.getUint16(p + 28, true), el = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true);
    const lho = dv.getUint32(p + 42, true);
    const fname = new TextDecoder().decode(zip.subarray(p + 46, p + 46 + nl));
    if (fname === name) {
      const data = lho + 30 + dv.getUint16(lho + 26, true) + dv.getUint16(lho + 28, true);
      const raw = zip.subarray(data, data + csize);
      return method === 0 ? raw : new Uint8Array(inflateRawSync(raw));
    }
    p += 46 + nl + el + cl;
  }
  throw new Error(`${name} not in zip`);
}

const jobs = [
  // Microsoft signed PE (Sysinternals license forbids redistribution, so it is fetched)
  ['strings64.exe', async () => unzipMember(await get('https://download.sysinternals.com/files/Strings.zip'), 'strings64.exe')],
  // real macOS 12 crash report with a trailing System Profile section, posted publicly as a gist
  ['WindowServer.ips', async () => get('https://gist.githubusercontent.com/luckman212/5b645096c44936ba8530071fa6a23efd/raw/WindowServer-2021-10-27-175344.ips')],
  // Maccy 2.8.0 (MIT, https://github.com/p0deje/Maccy): a real Xcode-built Assets.car and a Swift Mach-O
  ['maccy-Assets.car', async () => unzipMember(await maccy(), 'Maccy.app/Contents/Resources/Assets.car')],
  ['maccy-Maccy.macho', async () => unzipMember(await maccy(), 'Maccy.app/Contents/MacOS/Maccy')],
  // CardExample-Unity (MIT, https://github.com/rygo6/CardExample-Unity): a 1.2 MB Unity 5.5 asset bundle with 52 textures
  ['unity-cards.unity3d', async () => get('https://raw.githubusercontent.com/rygo6/CardExample-Unity/master/ExternalAssets/cards')],
];
let maccyZip;

/** Write to a fresh temp file next to dest (created exclusively), then rename it into place. */
function writeAtomic(dest, data) {
  const tmp = `${dest}.${process.pid}.tmp`;
  rmSync(tmp, { force: true });
  writeFileSync(tmp, data, { flag: 'wx' });
  renameSync(tmp, dest);
}
async function maccy() { return (maccyZip ??= await get('https://github.com/p0deje/Maccy/releases/download/2.8.0/Maccy.app.zip')); }
for (const [out, f] of jobs) {
  const dest = join(cache, out);
  if (existsSync(dest)) continue;
  try { writeAtomic(dest, await f()); console.log('fetched', out); } catch (e) { console.error('skip', out, e.message); }
}
console.log('extras fixtures in', cache);
