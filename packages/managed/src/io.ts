// Input loading shared by tools and CLI commands. Paths need Node; bytes work everywhere.
import { ParseError, hexToBytes } from './util.js';

export interface InputSpec { path?: string; bytesBase64?: string; hex?: string }

export const MAX_INPUT_BYTES = 1024 * 1024 * 1024;

function b64(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, '');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Read the file at `path` with Node, without making the module Node only at import time. */
export async function readPath(path: string): Promise<Uint8Array> {
  const modName = 'node:fs/promises';
  let fs: { readFile(p: string): Promise<Uint8Array>; stat(p: string): Promise<{ size: number; isFile(): boolean }> };
  try { fs = await import(/* @vite-ignore */ modName); } catch { throw new ParseError('reading a path needs Node; pass bytesBase64 instead'); }
  const st = await fs.stat(path);
  if (!st.isFile()) throw new ParseError(`${path} is not a regular file`);
  if (st.size > MAX_INPUT_BYTES) throw new ParseError(`${path} is larger than ${MAX_INPUT_BYTES} bytes`);
  const b = await fs.readFile(path);
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

export async function loadInput(input: InputSpec): Promise<{ bytes: Uint8Array; name: string }> {
  if (input.path) return { bytes: await readPath(input.path), name: input.path };
  if (input.bytesBase64) return { bytes: b64(input.bytesBase64), name: 'input' };
  if (input.hex) return { bytes: hexToBytes(input.hex), name: 'input.hex' };
  throw new ParseError('give path, bytesBase64 or hex');
}

export function toBase64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Make an archive member name safe to join under an output directory. */
export function safeRelPath(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/').filter((x) => x && x !== '.' && x !== '..');
  const s = parts.map((x) => x.replace(/[\0:*?"<>|]/g, '_')).join('/');
  return s || '_unnamed';
}

/** Write extracted files under outDir (Node only). Member names are sanitised so nothing escapes outDir. */
export async function writeFiles(outDir: string, files: { path: string; data: Uint8Array }[]): Promise<string[]> {
  const fsName = 'node:fs/promises', pathName = 'node:path';
  let fs: { mkdir(p: string, o: { recursive: boolean }): Promise<unknown>; writeFile(p: string, d: Uint8Array): Promise<void> };
  let path: { resolve(...p: string[]): string; dirname(p: string): string; sep: string };
  try { fs = await import(/* @vite-ignore */ fsName); path = await import(/* @vite-ignore */ pathName); } catch { throw new ParseError('writing files needs Node'); }
  const root = path.resolve(outDir);
  const written: string[] = [];
  for (const f of files) {
    const dest = path.resolve(root, safeRelPath(f.path));
    if (dest !== root && !dest.startsWith(root + path.sep)) throw new ParseError(`refusing to write outside ${root}: ${f.path}`);
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.writeFile(dest, f.data);
    written.push(dest);
  }
  return written;
}
