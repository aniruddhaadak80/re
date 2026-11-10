import { loadSample, type Sample } from './samples';
import { openBytes, openFile } from './store';

export async function openSample(s: Sample): Promise<string> {
  const bytes = await loadSample(s);
  return openBytes(s.file, bytes);
}
export async function openFiles(files: File[]): Promise<void> {
  for (const f of files) await openFile(f);
}
