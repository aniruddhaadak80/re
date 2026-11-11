#!/usr/bin/env node
// Pull the native companions of System.IO.Compression.Brotli.dll out of the official .NET 8.0.11
// runtime packs on nuget.org with HTTP range requests (only the needed ZIP members are read).
// Writes samples/managed/native/<rid>/<file>.gz. MIT (.NET runtime).
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync, gzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', '..', '..', 'samples', 'managed', 'native');
const V = '8.0.11';
const TARGETS = [
  ['linux-x64', 'libSystem.IO.Compression.Native.so'],
  ['win-x64', 'System.IO.Compression.Native.dll'],
  ['osx-arm64', 'libSystem.IO.Compression.Native.dylib'],
];

async function range(url, start, end) {
  const r = await fetch(url, { headers: { Range: `bytes=${start}-${end}` } });
  if (r.status !== 206 && r.status !== 200) throw new Error(`HTTP ${r.status} for ${url}`);
  return new Uint8Array(await r.arrayBuffer());
}
async function member(url, name) {
  const head = await fetch(url, { method: 'HEAD' });
  const size = Number(head.headers.get('content-length'));
  const tail = await range(url, Math.max(0, size - 65536), size - 1);
  const dv = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('no end of central directory');
  const cdSize = dv.getUint32(eocd + 12, true), cdOff = dv.getUint32(eocd + 16, true);
  const cd = await range(url, cdOff, cdOff + cdSize - 1);
  const c = new DataView(cd.buffer, cd.byteOffset, cd.byteLength);
  for (let p = 0; p + 46 <= cd.length;) {
    const n = c.getUint16(p + 28, true), x = c.getUint16(p + 30, true), k = c.getUint16(p + 32, true);
    const fname = new TextDecoder().decode(cd.subarray(p + 46, p + 46 + n));
    if (fname === name) {
      const method = c.getUint16(p + 10, true), csize = c.getUint32(p + 20, true), lho = c.getUint32(p + 42, true);
      const lh = await range(url, lho, lho + 29);
      const l = new DataView(lh.buffer, lh.byteOffset, lh.byteLength);
      const dataOff = lho + 30 + l.getUint16(26, true) + l.getUint16(28, true);
      const data = await range(url, dataOff, dataOff + csize - 1);
      return method === 8 ? new Uint8Array(inflateRawSync(data)) : data;
    }
    p += 46 + n + x + k;
  }
  throw new Error(`${name} not in ${url}`);
}

for (const [rid, file] of TARGETS) {
  const url = `https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.runtime.${rid}/${V}/microsoft.netcore.app.runtime.${rid}.${V}.nupkg`;
  const data = await member(url, `runtimes/${rid}/native/${file}`);
  await mkdir(join(out, rid), { recursive: true });
  await writeFile(join(out, rid, file + '.gz'), gzipSync(data, { level: 9 }));
  console.log('wrote', rid, file, data.length);
}
