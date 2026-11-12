#!/usr/bin/env node
// Fetch a few real recordings from merbanan/rtl_433_tests into samples/.cache/extras/rtl_433_tests.
// That repository has no license file, so the recordings are fetched for local tests only and are
// never committed. Reference values (from rtl_433 25.02) live in samples/extras/signals/rtl_433_tests.reference.json.
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const out = join(root, 'samples', '.cache', 'extras', 'rtl_433_tests');
const ref = JSON.parse(await readFile(join(root, 'samples', 'extras', 'signals', 'rtl_433_tests.reference.json'), 'utf8'));
const base = `https://raw.githubusercontent.com/merbanan/rtl_433_tests/${ref.commit}/tests/`;
await mkdir(out, { recursive: true });
for (const r of ref.recordings) {
  const dest = join(out, r.path.replaceAll('/', '__'));
  try {
    const have = await readFile(dest);
    if (createHash('sha256').update(have).digest('hex') === r.sha256) { console.log('ok', r.path); continue; }
  } catch { /* fetch */ }
  const res = await fetch(base + r.path);
  if (!res.ok) { console.error('failed', r.path, res.status); process.exitCode = 1; continue; }
  const buf = Buffer.from(await res.arrayBuffer());
  const sha = createHash('sha256').update(buf).digest('hex');
  if (sha !== r.sha256) { console.error('sha256 mismatch', r.path, sha); process.exitCode = 1; continue; }
  await mkdir(dirname(dest), { recursive: true });
  await writeFile(dest, buf);
  console.log('fetched', r.path, buf.length);
}
