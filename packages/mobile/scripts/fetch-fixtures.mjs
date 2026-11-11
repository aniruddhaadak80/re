#!/usr/bin/env node
// Fetch large real-world mobile fixtures into samples/.cache/mobile/ for the optional tests.
// Uses HTTP range requests to pull only the ZIP members we need out of big APKs, so the
// download stays small (a few MB) even though the APKs are 60 to 70 MB.
//
// Sources (license-clean):
//   Daggerfall Unity Android port, MIT, https://github.com/Vwing/daggerfall-unity-android
//     release v1.1.1.2: daggerfall-unity-il2cpp-64bit.apk (Unity IL2CPP), daggerfall-unity-mono-32bit.apk (Unity Mono)
//   LocalSend, Apache-2.0, https://github.com/localsend/localsend, F-Droid build org.localsend.localsend_app_643.apk (Flutter)

import { createHash } from 'node:crypto';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const cacheDir = join(here, '..', '..', '..', 'samples', '.cache', 'mobile');

const TARGETS = [
  {
    id: 'daggerfall-il2cpp-64',
    url: 'https://github.com/Vwing/daggerfall-unity-android/releases/download/v1.1.1.2/daggerfall-unity-il2cpp-64bit.apk',
    license: 'MIT',
    members: ['AndroidManifest.xml', 'assets/bin/Data/Managed/Metadata/global-metadata.dat'],
    sha256: {
      'AndroidManifest.xml': 'a567e6a11b6a4f4f80c4a737d5bb67121d40a7cab48704aadf4d8b33a8533cbb',
      'assets/bin/Data/Managed/Metadata/global-metadata.dat': 'baaff1bb4e826659e85db6eceb85cfd48671e4cec14e19d1acdea78a78c58dd8',
    },
  },
  {
    id: 'daggerfall-mono-32',
    url: 'https://github.com/Vwing/daggerfall-unity-android/releases/download/v1.1.1.2/daggerfall-unity-mono-32bit.apk',
    license: 'MIT',
    members: ['AndroidManifest.xml'],
    sha256: { 'AndroidManifest.xml': 'a567e6a11b6a4f4f80c4a737d5bb67121d40a7cab48704aadf4d8b33a8533cbb' },
  },
  {
    id: 'localsend-flutter',
    url: 'https://f-droid.org/repo/org.localsend.localsend_app_643.apk',
    license: 'Apache-2.0',
    members: ['AndroidManifest.xml', 'resources.arsc'],
    sha256: {
      'AndroidManifest.xml': '12cc84245ecbd9d47c70ead8f5dc8d229ac3cda96cd6024d8ddb458139b97109',
      'resources.arsc': 'ea2275e556f26ef9d277d99d1c6604ef476f615cc8a16f269ae0d04134fb154a',
      'lib/arm64-v8a/libapp.so': '5b995c8b67d6da4f91e34377afe773641b6a03bfa7f4c10645a6b295b25b703e',
    },
    // only the head of the AOT library, which holds the Dart VM snapshot header
    partial: { 'lib/arm64-v8a/libapp.so': 1024 * 1024 },
  },
];

async function range(url, start, end) {
  const res = await fetch(url, { headers: { Range: `bytes=${start}-${end}` }, redirect: 'follow' });
  if (res.status !== 206) throw new Error(`range request failed with HTTP ${res.status} for ${url}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function size(url) {
  const res = await fetch(url, { method: 'HEAD', redirect: 'follow' });
  const n = Number(res.headers.get('content-length'));
  if (!n) throw new Error(`no content-length for ${url}`);
  return n;
}

function u16(b, o) { return b[o] | (b[o + 1] << 8); }
function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

async function fetchTarget(t) {
  const total = await size(t.url);
  const tail = await range(t.url, Math.max(0, total - 65_557), total - 1);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (u32(tail, i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('no end of central directory');
  const cdSize = u32(tail, eocd + 12), cdOff = u32(tail, eocd + 16), count = u16(tail, eocd + 10);
  const cd = await range(t.url, cdOff, cdOff + cdSize - 1);
  const listing = [];
  const wanted = new Map();
  let p = 0;
  for (let i = 0; i < count && p + 46 <= cd.length; i++) {
    const method = u16(cd, p + 10), csize = u32(cd, p + 20), usize = u32(cd, p + 24);
    const nlen = u16(cd, p + 28), xlen = u16(cd, p + 30), clen = u16(cd, p + 32), local = u32(cd, p + 42);
    const name = new TextDecoder().decode(cd.subarray(p + 46, p + 46 + nlen));
    listing.push({ name, size: usize, compressedSize: csize });
    if (t.members.includes(name) || (t.partial && name in t.partial)) wanted.set(name, { method, csize, usize, local, cap: t.partial?.[name] });
    p += 46 + nlen + xlen + clen;
  }
  const outDir = join(cacheDir, t.id);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'listing.json'), JSON.stringify({ source: t.url, license: t.license, apkSize: total, entries: listing }, null, 1));
  for (const [name, e] of wanted) {
    const head = await range(t.url, e.local, e.local + 29);
    const dataStart = e.local + 30 + u16(head, 26) + u16(head, 28);
    if (e.cap && e.method !== 0) { console.log(`  ${t.id}: ${name} is compressed, partial fetch skipped`); continue; }
    const n = e.cap ? Math.min(e.cap, e.csize) : e.csize;
    const raw = await range(t.url, dataStart, dataStart + n - 1);
    const data = e.method === 0 ? raw : inflateRawSync(raw);
    // Only bytes that match the pinned SHA-256 are kept (the APKs are fixed release builds).
    const got = createHash('sha256').update(data).digest('hex');
    if (got !== t.sha256[name]) throw new Error(`${t.id}: ${name} SHA-256 ${got} does not match the pinned ${t.sha256[name]}`);
    const file = join(outDir, name.replace(/\//g, '__'));
    const tmp = `${file}.${process.pid}.tmp`;
    await rm(tmp, { force: true });
    await writeFile(tmp, data, { flag: 'wx' });
    await rename(tmp, file);
    console.log(`  ${t.id}: ${name} (${data.length} bytes)`);
  }
}

for (const t of TARGETS) {
  try {
    console.log(`fetching ${t.id}`);
    await fetchTarget(t);
  } catch (err) {
    console.error(`  skipped ${t.id}: ${err.message}`);
  }
}
