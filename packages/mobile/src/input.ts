// Input loading for tools and CLI commands. Browser-safe: reading a path needs a file reader,
// which src/node.ts registers, or falls back to node:fs when running under Node.

import { ParseError } from './bytes.js';

export type FileReader = (path: string) => Promise<{ bytes: Uint8Array; key: string }>;

let reader: FileReader | undefined;

/** Register how `path` inputs are read (src/node.ts does this for Node). */
export function setFileReader(r: FileReader | undefined): void { reader = r; }

export const INPUT_LIMITS = { maxFileBytes: 2 * 1024 * 1024 * 1024 - 1, maxBase64Chars: 200 * 1024 * 1024 };

function fromBase64(s: string): Uint8Array {
  if (s.length > INPUT_LIMITS.maxBase64Chars) throw new ParseError('base64 input is too large');
  const g = globalThis as { atob?: (s: string) => string };
  if (!g.atob) throw new Error('atob is not available');
  const bin = g.atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export interface LoadedInput { bytes: Uint8Array; key: string; name: string }

/** Accepts { path } or { base64 } or { bytes }. */
export async function loadInput(input: { path?: unknown; base64?: unknown; bytes?: unknown }): Promise<LoadedInput> {
  if (input.bytes instanceof Uint8Array) return { bytes: input.bytes, key: `bytes:${input.bytes.length}:${input.bytes[0]}:${input.bytes[input.bytes.length - 1]}`, name: 'input' };
  if (typeof input.base64 === 'string') {
    const b = fromBase64(input.base64);
    return { bytes: b, key: `b64:${input.base64.length}:${input.base64.slice(0, 64)}:${input.base64.slice(-64)}`, name: 'input' };
  }
  if (typeof input.path === 'string' && input.path) {
    const path = input.path;
    const name = path.split(/[\\/]/).pop() ?? path;
    if (reader) { const r = await reader(path); return { ...r, name }; }
    const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
    if (proc?.versions?.node) {
      const modName = 'node:fs/promises';
      const fs = (await import(/* @vite-ignore */ modName)) as typeof import('node:fs/promises');
      const st = await fs.stat(path);
      if (!st.isFile()) throw new Error(`${path} is not a file`);
      if (st.size > INPUT_LIMITS.maxFileBytes) throw new Error(`${path} is larger than 2 GB`);
      const bytes = new Uint8Array(await fs.readFile(path));
      return { bytes, key: `path:${path}:${st.size}:${st.mtimeMs}`, name };
    }
    throw new Error('reading a path needs @revlens/mobile/node, or pass base64 bytes');
  }
  throw new Error('pass a file path as "path" or file bytes as "base64"');
}

/** Tiny LRU for parsed objects keyed by input identity. */
export class Lru<V> {
  private map = new Map<string, V>();
  constructor(private max = 4) {}
  get(k: string): V | undefined {
    const v = this.map.get(k);
    if (v !== undefined) { this.map.delete(k); this.map.set(k, v); }
    return v;
  }
  set(k: string, v: V): void {
    this.map.delete(k);
    this.map.set(k, v);
    while (this.map.size > this.max) { const first = this.map.keys().next().value as string; this.map.delete(first); }
  }
}
