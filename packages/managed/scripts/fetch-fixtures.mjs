#!/usr/bin/env node
// Fetch or build the larger real fixtures for @revlens/managed into samples/.cache/managed/.
//  1. Newtonsoft.Json 13.0.3 (MIT) from nuget.org: lib/netstandard2.0/Newtonsoft.Json.dll
//  2. A PyInstaller onefile app built from samples/managed/pyinstaller/hello_revlens.py, when
//     `python3 -m PyInstaller` is available (pip install pyinstaller). Its TOC reference is
//     written with PyInstaller's own archive reader.
// Tests that need these files skip when they are missing.
import { mkdirSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { unzipSync } from 'fflate';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..', '..');
const cache = join(root, 'samples', '.cache', 'managed');
mkdirSync(cache, { recursive: true });

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 300_000, maxBuffer: 64 * 1024 * 1024, ...opts }, (err, stdout, stderr) => resolve({ err, stdout, stderr }));
  });
}

async function newtonsoft() {
  const out = join(cache, 'Newtonsoft.Json.dll');
  if (existsSync(out)) { console.log('have', out); return; }
  const url = 'https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg';
  console.log('fetch', url);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const zip = unzipSync(new Uint8Array(await res.arrayBuffer()), { filter: (f) => f.name === 'lib/netstandard2.0/Newtonsoft.Json.dll' });
  const dll = zip['lib/netstandard2.0/Newtonsoft.Json.dll'];
  if (!dll) throw new Error('Newtonsoft.Json.dll not found in nupkg');
  writeFileSync(out, dll);
  console.log('wrote', out, dll.length);
}

async function pyinstaller() {
  const out = join(cache, 'hello_revlens');
  if (existsSync(out) && existsSync(out + '.ref.json')) { console.log('have', out); return; }
  const python = process.env.PYTHON ?? 'python3';
  const probe = await run(python, ['-m', 'PyInstaller', '--version']);
  if (probe.err) { console.log('skip PyInstaller fixture: python3 -m PyInstaller not available'); return; }
  const work = join(cache, 'pyi-build');
  mkdirSync(work, { recursive: true });
  for (const f of ['hello_revlens.py', 'helper_mod.py']) copyFileSync(join(root, 'samples', 'managed', 'pyinstaller', f), join(work, f));
  const b = await run(python, ['-m', 'PyInstaller', '--onefile', '--noconfirm', '--log-level', 'WARN', '--distpath', join(work, 'dist'), '--workpath', join(work, 'build'), '--specpath', work, join(work, 'hello_revlens.py')], { cwd: work });
  if (b.err) { console.log('PyInstaller build failed:', b.stderr.slice(-2000)); return; }
  const exe = join(work, 'dist', process.platform === 'win32' ? 'hello_revlens.exe' : 'hello_revlens');
  copyFileSync(exe, out);
  const refScript = [
    'import sys, json',
    'from PyInstaller.archive.readers import CArchiveReader',
    'r = CArchiveReader(sys.argv[1])',
    'z = r.open_embedded_archive("PYZ.pyz")',
    'json.dump({"toc": {k: list(v) for k, v in r.toc.items()}, "options": r.options, "pyz": {k: list(v) for k, v in z.toc.items()}}, open(sys.argv[2], "w"))',
  ].join('\n');
  const rr = await run(python, ['-c', refScript, out, out + '.ref.json']);
  if (rr.err) { console.log('reference dump failed:', rr.stderr.slice(-2000)); return; }
  console.log('wrote', out);
}

await newtonsoft();
await pyinstaller();
