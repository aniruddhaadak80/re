import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const SAMPLES = join(ROOT, 'samples', 'managed');
export const CACHE = join(ROOT, 'samples', '.cache', 'managed');
export const sample = (...p: string[]) => join(SAMPLES, ...p);
export const cached = (...p: string[]) => join(CACHE, ...p);
export const bytes = (p: string) => { const b = readFileSync(p); return new Uint8Array(b.buffer, b.byteOffset, b.byteLength); };
export const json = (p: string) => JSON.parse(readFileSync(p, 'utf8'));
export const has = (p: string) => existsSync(p);
