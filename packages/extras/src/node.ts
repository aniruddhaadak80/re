// Node entry: installs a file loader for `path` inputs and file persistence for ledgerPath.
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { setFileLoader } from './util.js';
import { setLedgerStore } from './tools.js';

const MAX_FILE = 2 * 1024 * 1024 * 1024;
setFileLoader(async (p) => {
  const b = await readFile(p);
  if (b.length > MAX_FILE) throw new Error('file larger than 2 GiB');
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
});
setLedgerStore({
  async load(p) { try { return await readFile(p, 'utf8'); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw e; } },
  async save(p, text) { await mkdir(dirname(p), { recursive: true }); const tmp = `${p}.tmp-${process.pid}`; await writeFile(tmp, text); await rename(tmp, p); },
});

export * from './index.js';
