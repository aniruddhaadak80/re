// Node side of engine detection: walk an app folder (bounded, symlinks not followed) and give
// detectEngines a range reader over the real files.
import { readdir, lstat, open } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { InputError } from './proc.js';
import { detectEngines, type EngineFileInfo, type EngineFinding } from './engines.js';

export interface EngineScanOptions { maxFiles?: number; maxDepth?: number; maxScanBytes?: number; maxProbes?: number }

/** Detect Unity, Unreal, Godot, GameMaker, Ren'Py, RPG Maker and .NET in an app folder (or in the folder holding a file). */
export async function detectAppFolder(path: string, o: EngineScanOptions = {}): Promise<{ root: string; files: number; truncated: boolean; engines: EngineFinding[]; probed: number; warnings: string[] }> {
  if (typeof path !== 'string' || !path) throw new InputError('path must be an app folder');
  let root = path;
  const st = await lstat(root).catch(() => undefined);
  if (!st) throw new InputError(`${path} does not exist`);
  if (st.isFile()) root = join(root, '..');
  const maxFiles = Math.max(1, Math.min(o.maxFiles ?? 50_000, 500_000)), maxDepth = Math.max(0, Math.min(o.maxDepth ?? 10, 40));
  const files: EngineFileInfo[] = [];
  let truncated = false;
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > maxDepth) { truncated = true; return; }
    let names: string[];
    try { names = (await readdir(dir)).sort(); } catch { return; }
    for (const n of names.slice(0, 100_000)) {
      if (files.length >= maxFiles) { truncated = true; return; }
      const p = join(dir, n);
      const s = await lstat(p).catch(() => undefined);
      if (!s || s.isSymbolicLink()) continue;
      if (s.isDirectory()) await walk(p, depth + 1);
      else if (s.isFile()) files.push({ path: relative(root, p).split(sep).join('/'), size: Number(s.size) });
    }
  };
  await walk(root, 0);
  const read = async (rel: string, offset: number, length: number): Promise<Uint8Array> => {
    if (rel.split('/').includes('..')) throw new InputError('path leaves the folder');
    const fh = await open(join(root, ...rel.split('/')), 'r');
    try { const b = Buffer.alloc(Math.max(0, Math.min(length, 8 * 1024 * 1024))); const { bytesRead } = await fh.read(b, 0, b.length, Math.max(0, offset)); return new Uint8Array(b.buffer, b.byteOffset, bytesRead); } finally { await fh.close(); }
  };
  const r = await detectEngines(files, read, o);
  return { root, files: files.length, truncated, ...r };
}
