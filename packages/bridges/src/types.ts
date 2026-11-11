// Shared types for @revlens/bridges. No runtime code here.

/** Every external tool RevLens knows how to find. */
export type ToolId =
  | 'radare2' | 'rizin' | 'cutter' | 'ghidra' | 'java' | 'jadx' | 'apktool' | 'ilspy' | 'dotnet'
  | 'frida' | 'gdb' | 'lldb' | 'objdump' | 'llvm-objdump' | 'binwalk' | 'adb'
  | 'ida' | 'binja' | 'hopper';

export type Platform = 'linux' | 'darwin' | 'win32';

/** How to install a tool on one operating system. Each field is a full command line or a URL. */
export interface InstallMethods {
  brew?: string;
  apt?: string;
  winget?: string;
  choco?: string;
  scoop?: string;
  pip?: string;
  dotnet?: string;
  cargo?: string;
  script?: string;
  url?: string;
  note?: string;
}

export interface InstallInfo {
  homepage: string;
  license: string;
  linux: InstallMethods;
  darwin: InstallMethods;
  win32: InstallMethods;
}

/** Result of looking for one tool on this machine. */
export interface Detection {
  id: ToolId;
  name: string;
  available: boolean;
  /** absolute path of the main executable (or install root for Ghidra, IDA, Binary Ninja) */
  path?: string;
  version?: string;
  /** where it was found */
  via?: 'env' | 'path' | 'dir' | 'override';
  /** extra facts, for example Ghidra's analyzeHeadless path, required Java version, or r2ghidra presence */
  details?: Record<string, string | number | boolean | null>;
  /** problems that make the tool partly or fully unusable */
  problems?: string[];
}

/** One row of the capability inventory printed by `revlens doctor`. */
export interface InventoryEntry extends Detection {
  description: string;
  capabilities: string[];
  /** tools RevLens bridges to that this one needs, for example ghidra needs java */
  requires: ToolId[];
  /** install commands for the current OS, present when the tool is missing or broken */
  install?: InstallMethods & { homepage: string };
}

export interface Inventory {
  schema: 'revlens/bridges-inventory@1';
  platform: Platform;
  arch: string;
  generatedAt: string;
  tools: InventoryEntry[];
  /** capability name to the tool ids that provide it right now */
  capabilities: Record<string, ToolId[]>;
  summary: { available: number; missing: number; total: number };
}

/** Uniform shape returned by every bridge operation when the needed tool is not installed. */
export interface Unavailable {
  available: false;
  tool: ToolId;
  reason: string;
  install: InstallMethods & { homepage: string };
}

/** Result of one child process run. */
export interface RunResult {
  command: string;
  args: string[];
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** true when stdout or stderr went past maxOutputBytes and was cut */
  truncated: boolean;
  durationMs: number;
  /** spawn error, for example ENOENT */
  error?: string;
}

export interface ToolInputField {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description: string;
  optional?: boolean;
}

export interface BridgeTool {
  name: string;
  description: string;
  inputSchema: Record<string, ToolInputField>;
  run: (input: any) => Promise<unknown>;
}

export interface CliCommand {
  name: string;
  usage: string;
  summary: string;
  run(argv: string[]): Promise<number>;
}
