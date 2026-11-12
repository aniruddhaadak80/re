// Node entry: installs a file loader for `path` inputs and file persistence for ledgerPath.
import { readFile, writeFile, rename, mkdir, open } from 'node:fs/promises';
import { dirname } from 'node:path';
import { setFileLoader } from './util.js';
import { setLedgerStore } from './tools.js';
import { setExtractionWriter } from './tools3.js';
import { writeExtraction } from './firmware/write-node.js';

const MAX_FILE = 2 * 1024 * 1024 * 1024;
setFileLoader(async (p) => {
  // One descriptor for the check and the read, so the file cannot be swapped in between.
  const fh = await open(p, 'r');
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new Error(`${p} is not a regular file`);
    if (st.size > MAX_FILE) throw new Error('file larger than 2 GiB');
    const b = await fh.readFile();
    if (b.length > MAX_FILE) throw new Error('file larger than 2 GiB');
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  } finally { await fh.close(); }
});
setLedgerStore({
  async load(p) { try { return await readFile(p, 'utf8'); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw e; } },
  async save(p, text) { await mkdir(dirname(p), { recursive: true }); const tmp = `${p}.tmp-${process.pid}`; await writeFile(tmp, text); await rename(tmp, p); },
});

setExtractionWriter((r, outDir, o) => writeExtraction(r, outDir, o));

export { writeExtraction, type WriteOptions, type WriteReport } from './firmware/write-node.js';
export * from './index.js';
