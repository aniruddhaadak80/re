// Node entry for @revlens/engine: every package's agent tools and CLI commands with file path inputs.
import { openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import * as managed from '@revlens/managed';
import * as webrt from '@revlens/webrt/node';
import * as mobile from '@revlens/mobile/node';
import * as disasm from '@revlens/disasm/node';
import * as bridges from '@revlens/bridges/node';
import * as extras from '@revlens/extras/node';
import { analyzeAll, ALL_ANALYZERS, type EngineOptions } from './index.js';
import type { Analyzer, Report } from '@revlens/core';

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
  { id: 'extras', npm: '@revlens/extras', title: 'Extras: demangling, deep PE, ELF, Mach-O, firmware and more', tools: extras.TOOLS as unknown as PackageTool[], commands: extras.CLI_COMMANDS as PackageCommand[] },
  { id: 'disasm', npm: '@revlens/disasm', title: 'Native code', tools: disasm.TOOLS as unknown as PackageTool[], commands: disasm.CLI_COMMANDS as PackageCommand[] },
  // bridges' own commands (doctor, setup, bridge) are top level CLI commands, see TOP_LEVEL_COMMANDS
  { id: 'bridges', npm: '@revlens/bridges', title: 'External tool bridges', tools: bridges.TOOLS as unknown as PackageTool[], commands: [] },
];

/** CLI commands that live at the top level: revlens doctor, revlens setup <client>, revlens bridge <tool>. */
export const TOP_LEVEL_COMMANDS: PackageCommand[] = bridges.CLI_COMMANDS as PackageCommand[];

/**
 * Node-only analyzers. The bridges analyzers (bridges-inventory, bridges-r2, bridges-jadx) only run when
 * named in options.analyzers or when REVLENS_BRIDGES=1, because they start external programs.
 */
export const NODE_ANALYZERS: Analyzer[] = bridges.ANALYZERS as Analyzer[];

/** analyzeAll plus the Node-only analyzers. */
export async function analyzeAllNode(bytes: Uint8Array, opts: EngineOptions = {}): Promise<Report> {
  return analyzeAll(bytes, { ...opts, extraAnalyzers: [...(opts.extraAnalyzers ?? []), ...NODE_ANALYZERS] });
}

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
  bridge_frida_run: { executes: true },
  bridge_gdb_run: { executes: true },
  bridge_adb_pull_apk: { writes: true },
  bridge_adb_logcat: { network: true },
  bridge_setup_mcp: { writes: true },
  bridge_adb_install: { executes: true },
  bridge_adb_uninstall: { executes: true, writes: true },
  bridge_adb_push: { executes: true },
  bridge_adb_pull: { writes: true },
  bridge_adb_start_activity: { executes: true },
  bridge_adb_stop_app: { executes: true },
  bridge_adb_screenshot: { writes: true },
  bridge_adb_screenrecord: { writes: true },
  bridge_adb_input: { executes: true },
  bridge_adb_logcat_filtered: { network: true },
  bridge_adb_bugreport: { writes: true },
  bridge_adb_backup: { writes: true },
  bridge_adb_forward: { executes: true, network: true },
  bridge_adb_reverse: { executes: true, network: true },
  bridge_session_close: { executes: true },
  bridge_r2_session_open: { executes: true },
  bridge_r2_session_cmd: { executes: true },
  bridge_gdb_session_open: { executes: true },
  bridge_gdb_session_cmd: { executes: true },
  bridge_lldb_session_open: { executes: true },
  bridge_lldb_session_cmd: { executes: true },
  bridge_frida_session_attach: { executes: true },
  bridge_frida_session_load: { executes: true },
  bridge_frida_session_post: { executes: true },
  bridge_frida_session_collect: { executes: true },
  bridge_frida_session_unload: { executes: true },
  bridge_frida_session_resume: { executes: true },
  bridge_ghidra_apply_names: { writes: true, executes: true },
  bridge_ghidra_export_names: { writes: true, executes: true },
  bridge_ida_apply_names: { writes: true, executes: true },
  bridge_ida_export_names: { writes: true, executes: true },
  bridge_r2_apply_names: { writes: true, executes: true },
  bridge_r2_export_names: { writes: true, executes: true },
  x_ledger_record: { writes: true },
  x_ledger_unknown: { writes: true },
  x_ledger_verify: { writes: true },
  x_ledger_import: { writes: true },
};

/** Close every open bridge session (radare2, gdb, lldb, Frida). Hosts call this when they shut down. */
export async function closeAllSessions(): Promise<number> {
  return bridges.SESSIONS.closeAll();
}

/** Kill every bridge session process right away, for a synchronous exit path. */
export function killAllSessions(): void {
  bridges.SESSIONS.killAll();
}

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
  return analyzeAllNode(bytes, { name: basename(abs), ...opts });
}

/** Every analyzer, including the opt in Node-only ones. */
export const ALL_ANALYZERS_NODE = [
  ...ALL_ANALYZERS,
  ...NODE_ANALYZERS.map((a) => ({ id: a.id, title: a.title, description: `${a.description} (opt in)`, package: 'bridges' })),
];
