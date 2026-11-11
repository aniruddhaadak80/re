import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const S = join(ROOT, 'samples', 'extras');
export const CACHE = join(ROOT, 'samples', '.cache', 'extras');
export const fx = (f: string): Uint8Array => new Uint8Array(readFileSync(join(S, f)));
export const cached = (f: string): Uint8Array | null => (existsSync(join(CACHE, f)) ? new Uint8Array(readFileSync(join(CACHE, f))) : null);
export const REF = JSON.parse(readFileSync(join(S, 'reference.json'), 'utf8'));
