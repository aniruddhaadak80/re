// Node only: write an in-memory firmware extraction to disk without letting any member escape
// the output directory. Every path is sanitized again, resolved and checked against the root;
// parent directories are checked with lstat so a symlink planted on disk is never followed;
// files are created with O_EXCL | O_NOFOLLOW; symlinks from the image are listed in
// manifest.json and only created on request when their target stays inside the root.

import { open, mkdir, lstat, readdir, symlink, writeFile, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, sep, dirname, join, relative, isAbsolute, posix } from 'node:path';
import { sanitizeMemberPath, extractionSummary, type ExtractResult } from './extract.js';

export interface WriteOptions { symlinks?: 'skip' | 'inside'; overwrite?: boolean; maxFiles?: number; maxBytes?: number; maxDepth?: number }
export interface WriteReport { outDir: string; written: number; bytes: number; skipped: { path: string; reason: string }[]; manifest: string }

const NOFOLLOW = (constants as Record<string, number>).O_NOFOLLOW ?? 0;

async function ensureDir(root: string, rel: string[]): Promise<string> {
  let cur = root;
  for (const seg of rel) {
    cur = join(cur, seg);
    try {
      const st = await lstat(cur);
      if (st.isSymbolicLink()) throw new Error(`refusing to follow symlink at ${cur}`);
      if (!st.isDirectory()) throw new Error(`${cur} exists and is not a directory`);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
      await mkdir(cur);
    }
  }
  return cur;
}

/** Write the files of an extraction under outDir. outDir must not exist or be empty unless overwrite is set. */
export async function writeExtraction(r: ExtractResult, outDir: string, opts: WriteOptions = {}): Promise<WriteReport> {
  const maxFiles = opts.maxFiles ?? 100000, maxBytes = opts.maxBytes ?? 4 * 1024 ** 3, maxDepth = Math.min(opts.maxDepth ?? 64, 128);
  await mkdir(outDir, { recursive: true });
  const root = await realpath(resolve(outDir));
  if (!opts.overwrite && (await readdir(root)).length) throw new Error(`${root} is not empty`);
  const skipped: WriteReport['skipped'] = [];
  const links: { path: string; target: string; created: boolean }[] = [];
  let written = 0, bytes = 0;
  const inside = (p: string) => p === root || p.startsWith(root + sep);
  for (const f of r.files) {
    const rel = sanitizeMemberPath(f.path);
    const segs = rel.split('/');
    if (segs.length > maxDepth) { skipped.push({ path: f.path, reason: 'too deep' }); continue; }
    const target = resolve(root, ...segs);
    if (!inside(target) || target === root) { skipped.push({ path: f.path, reason: 'outside the output directory' }); continue; }
    if (written >= maxFiles) { skipped.push({ path: f.path, reason: 'file limit' }); continue; }
    try {
      if (f.kind === 'dir') { await ensureDir(root, segs); continue; }
      const parent = await ensureDir(root, segs.slice(0, -1));
      if (!inside(parent)) throw new Error('parent outside the output directory');
      if (f.kind === 'symlink') {
        const t = f.target ?? '';
        const resolvedT = isAbsolute(t) || t.startsWith('/') ? resolve(root, '.' + posix.normalize('/' + t)) : resolve(dirname(target), t);
        const ok = opts.symlinks === 'inside' && t !== '' && !t.startsWith('/') && inside(resolvedT);
        if (ok) await symlink(relative(dirname(target), resolvedT) || '.', target);
        links.push({ path: rel, target: t, created: ok });
        continue;
      }
      if (f.kind === 'device') { skipped.push({ path: f.path, reason: 'device node not created' }); continue; }
      if (!f.data) { skipped.push({ path: f.path, reason: 'no data kept' }); continue; }
      if (bytes + f.data.length > maxBytes) { skipped.push({ path: f.path, reason: 'byte limit' }); continue; }
      const fh = await open(target, constants.O_WRONLY | constants.O_CREAT | (opts.overwrite ? constants.O_TRUNC : constants.O_EXCL) | NOFOLLOW, 0o644);
      try { await fh.writeFile(f.data); } finally { await fh.close(); }
      written++; bytes += f.data.length;
    } catch (e) {
      skipped.push({ path: f.path, reason: (e as Error).message });
    }
  }
  const manifest = join(root, 'revlens-extract.json');
  await writeFile(manifest, JSON.stringify({ tool: 'revlens x_firmware_extract', ...extractionSummary(r), symlinks: links, skipped }, null, 1), { flag: 'wx' }).catch(async (e) => {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST' && opts.overwrite) await writeFile(manifest, JSON.stringify({ ...extractionSummary(r), symlinks: links, skipped }, null, 1));
    else throw e;
  });
  return { outDir: root, written, bytes, skipped: skipped.slice(0, 500), manifest };
}
