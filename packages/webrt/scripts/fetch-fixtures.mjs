// Downloads a real Electron release (MIT) and extracts the executable into samples/.cache/webrt/
// so tests can check version detection and fuse reading against @electron/fuses.
// Run from the repo root: node packages/webrt/scripts/fetch-fixtures.mjs
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = '33.2.1';
const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, '../../../samples/.cache/webrt');
const exe = join(out, `electron-v${VERSION}-linux-x64`, 'electron');
if (existsSync(exe)) { console.log('already present:', exe); process.exit(0); }
mkdirSync(dirname(exe), { recursive: true });
const url = `https://github.com/electron/electron/releases/download/v${VERSION}/electron-v${VERSION}-linux-x64.zip`;
console.log('downloading', url);
const zipPath = join(out, `electron-v${VERSION}-linux-x64.zip`);
let zip;
if (existsSync(zipPath)) zip = readFileSync(zipPath);
else {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  zip = Buffer.from(await res.arrayBuffer());
}
// find the central directory and the "electron" entry
const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
if (eocd < 0) throw new Error('not a zip');
const count = zip.readUInt16LE(eocd + 10);
let p = zip.readUInt32LE(eocd + 16);
for (let i = 0; i < count; i++) {
  const method = zip.readUInt16LE(p + 10), csize = zip.readUInt32LE(p + 20), nlen = zip.readUInt16LE(p + 28), xlen = zip.readUInt16LE(p + 30), clen = zip.readUInt16LE(p + 32), lho = zip.readUInt32LE(p + 42);
  const name = zip.subarray(p + 46, p + 46 + nlen).toString('utf8');
  if (name === 'electron' || name === 'version') {
    const lnlen = zip.readUInt16LE(lho + 26), lxlen = zip.readUInt16LE(lho + 28);
    const data = zip.subarray(lho + 30 + lnlen + lxlen, lho + 30 + lnlen + lxlen + csize);
    writeFileSync(join(dirname(exe), name), method === 8 ? inflateRawSync(data) : data);
    console.log('wrote', join(dirname(exe), name));
  }
  p += 46 + nlen + xlen + clen;
}
