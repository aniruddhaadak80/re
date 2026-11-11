// Node entry: registers a node:fs file reader so `path` inputs work, and re-exports everything.

import { open } from 'node:fs/promises';
import { setFileReader } from './input.js';

setFileReader(async (path) => {
  // One descriptor for the check and the read, so the file cannot be swapped in between.
  const fh = await open(path, 'r');
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new Error(`${path} is not a file`);
    if (st.size > 2 * 1024 * 1024 * 1024 - 1) throw new Error(`${path} is larger than 2 GB`);
    return { bytes: new Uint8Array(await fh.readFile()), key: `path:${path}:${st.size}:${st.mtimeMs}` };
  } finally { await fh.close(); }
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
