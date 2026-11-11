// Node only helpers: read files by path and write extracted archives to disk.
import { readFile } from 'node:fs/promises';
import { writeFiles, readPath } from './io.js';
import { extractPyInstaller } from './python/pyinstaller.js';
import { runManagedAnalyzers } from './analyzers.js';
import type { Report } from '@revlens/core';

export { writeFiles, readPath };

/** Extract a PyInstaller executable at `path` into `outDir`. Returns written file paths and warnings. */
export async function extractPyInstallerToDir(path: string, outDir: string): Promise<{ written: string[]; errors: string[]; pythonVersion: string }> {
  const b = await readFile(path);
  const res = extractPyInstaller(new Uint8Array(b.buffer, b.byteOffset, b.byteLength), { includeBinaries: true });
  const written = await writeFiles(outDir, res.files.map((f) => ({ path: f.path, data: f.data })));
  return { written, errors: res.errors, pythonVersion: res.archive.pythonVersion };
}

/** Run the managed analyzers for a file on disk against an existing report. */
export async function analyzeManagedFile(path: string, report: Report): Promise<Report> {
  return runManagedAnalyzers(await readPath(path), report, path);
}
