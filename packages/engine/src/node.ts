// Node entry for @revlens/engine: every package's agent tools and CLI commands with file path inputs.
import { openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import * as managed from '@revlens/managed';
import * as webrt from '@revlens/webrt/node';
import * as mobile from '@revlens/mobile/node';
import * as disasm from '@revlens/disasm/node';
import { analyzeAll, type EngineOptions } from './index.js';
import type { Report } from '@revlens/core';

export * from './index.js';

export type ParamType = 'string' | 'number' | 'boolean' | 'array' | 'object';
export interface ToolParam { type: ParamType; description: string; optional?: boolean }

/** A package agent tool, as every RevLens package exports it. */
export interface PackageTool {
  name: string;
  description: string;
  inputSchema: Record<string, ToolParam>;
  run: (input: any) => Promise<unknown>;
}

/** A package CLI command. */
export interface PackageCommand {
  name: string;
  usage: string;
  summary: string;
  run(argv: string[]): Promise<number>;
}

export interface ToolGroup {
  /** CLI namespace and short id */
  id: string;
  npm: string;
  title: string;
  tools: PackageTool[];
  commands: PackageCommand[];
}

export const TOOL_GROUPS: ToolGroup[] = [
  { id: 'mobile', npm: '@revlens/mobile', title: 'Android, Java and iOS', tools: mobile.TOOLS as unknown as PackageTool[], commands: mobile.CLI_COMMANDS as PackageCommand[] },
  { id: 'managed', npm: '@revlens/managed', title: 'Managed and bytecode runtimes', tools: managed.TOOLS as unknown as PackageTool[], commands: managed.CLI_COMMANDS as PackageCommand[] },
  { id: 'web', npm: '@revlens/webrt', title: 'Web runtime', tools: webrt.TOOLS as unknown as PackageTool[], commands: webrt.CLI_COMMANDS as PackageCommand[] },
  { id: 'disasm', npm: '@revlens/disasm', title: 'Native code', tools: disasm.TOOLS as unknown as PackageTool[], commands: disasm.CLI_COMMANDS as PackageCommand[] },
];

/** All package tools, flat. Names are unique across packages (each is prefixed with its area). */
export const PACKAGE_TOOLS: (PackageTool & { group: string })[] = TOOL_GROUPS.flatMap((g) => g.tools.map((t) => ({ ...t, group: g.id })));

/**
 * Tools that write files, start processes or reach the network. Everything else only reads its input.
 * Hosts use this for MCP annotations and confirmations.
 */
export const TOOL_EFFECTS: Record<string, { writes?: boolean; network?: boolean; executes?: boolean }> = {
  managed_pyinstaller_extract: { writes: true },
  web_asar_extract: { writes: true },
  web_sourcemap_recover: { writes: true },
  web_browser_capture: { network: true, executes: true },
};

const MAX_FILE = Number(process.env.REVLENS_MAX_FILE_MB ?? 256) * 1024 * 1024;

/** Read a regular file through one descriptor, with a size cap. */
export function readInput(path: string, maxBytes = MAX_FILE): { bytes: Uint8Array; abs: string; mtime: number } {
  const abs = resolve(path);
  const fd = openSync(abs, 'r');
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${abs} is not a regular file`);
    if (st.size > maxBytes) throw new Error(`${abs} is larger than ${maxBytes} bytes. Raise REVLENS_MAX_FILE_MB to allow it.`);
    return { bytes: new Uint8Array(readFileSync(fd)), abs, mtime: st.mtimeMs };
  } finally { closeSync(fd); }
}

/** Analyze a file on disk with core plus every package. */
export async function analyzeFile(path: string, opts: EngineOptions = {}): Promise<Report> {
  const { bytes, abs } = readInput(path);
  return analyzeAll(bytes, { name: basename(abs), ...opts });
}
