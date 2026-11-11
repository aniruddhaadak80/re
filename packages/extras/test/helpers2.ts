import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { S, CACHE } from './helpers.js';
export const RG = JSON.parse(readFileSync(join(S, 'reference-gaps.json'), 'utf8'));
export const wx = (f: string): Uint8Array => new Uint8Array(readFileSync(join(S, 'windows', f)));
export const sx = (dir: string, f: string): Uint8Array => new Uint8Array(readFileSync(join(S, dir, f)));
export const cachedAt = (dir: string, f: string): Uint8Array | null => (existsSync(join(CACHE, dir, f)) ? new Uint8Array(readFileSync(join(CACHE, dir, f))) : null);
