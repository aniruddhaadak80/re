// Node entry: same API, with path inputs read through node:fs.
import { readFile } from 'node:fs/promises';
import { setFileReader } from './api.js';

setFileReader(async (p) => new Uint8Array(await readFile(p)));

export * from './index.js';
