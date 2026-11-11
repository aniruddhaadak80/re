// Downloads a real Electron release (MIT) and extracts the executable into samples/.cache/webrt/
// so tests can check version detection and fuse reading against @electron/fuses.
// Run from the repo root: node packages/webrt/scripts/fetch-fixtures.mjs
import { mkdirSync, writeFileSync, existsSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = '33.2.1';
// SHA-256 of the extracted files from the official v33.2.1 linux-x64 release; anything else is refused.
const SHA256 = {
  electron: '20828dd41e2247931844e04fc4af25b1ca0bca8469c4536e2cd2a8f9e115ac35',
  version: '30317a6c28602246343ef9b6f07f1ef0f046817b942f57b2d9851e393e8ebf00',
};
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
    const bytes = method === 8 ? inflateRawSync(data) : data;
    const got = createHash('sha256').update(bytes).digest('hex');
    if (got !== SHA256[name]) throw new Error(`${name}: SHA-256 ${got} does not match the pinned ${SHA256[name]}`);
    // verified bytes go to a fresh temp file (created exclusively) and are renamed into place
    const dest = join(dirname(exe), name);
    const tmp = `${dest}.${process.pid}.tmp`;
    rmSync(tmp, { force: true });
    writeFileSync(tmp, bytes, { flag: 'wx' });
    renameSync(tmp, dest);
    console.log('wrote', join(dirname(exe), name));
  }
  p += 46 + nlen + xlen + clen;
}
