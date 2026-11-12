import type { Options } from './types.js';
export function slug(s: string, o?: Options): string { return s.toLowerCase().replace(/\s+/g, o?.sep ?? '-'); }
