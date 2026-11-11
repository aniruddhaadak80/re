// Node entry: registers a node:fs file reader so `path` inputs work, and re-exports everything.

import { readFile, stat } from 'node:fs/promises';
import { setFileReader } from './input.js';

setFileReader(async (path) => {
  const st = await stat(path);
  if (!st.isFile()) throw new Error(`${path} is not a file`);
  if (st.size > 2 * 1024 * 1024 * 1024 - 1) throw new Error(`${path} is larger than 2 GB`);
  return { bytes: new Uint8Array(await readFile(path)), key: `path:${path}:${st.size}:${st.mtimeMs}` };
});

export * from './index.js';

/** Run one CLI command by name, for hosts that dispatch argv. Returns the exit code. */
export async function runCli(argv: string[]): Promise<number> {
  const { CLI_COMMANDS } = await import('./cli.js');
  const [name, ...rest] = argv;
  const c = CLI_COMMANDS.find((x) => x.name === name);
  if (!c) {
    console.error(`unknown command ${name ?? ''}. Commands: ${CLI_COMMANDS.map((x) => x.name).join(', ')}`);
    return 2;
  }
  return c.run(rest);
}
