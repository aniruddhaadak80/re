// Agent tools. Every tool returns JSON. When the needed program is missing the result is
// { available: false, tool, reason, install } instead of an error. Tools that run code need
// allowExecution: true. Node only.
import { inventory } from './doctor.js';
import { HOOK_TEMPLATES } from './hooks.js';
import { BridgeInputError } from './providers/common.js';
import { fridaDevices, fridaPs, fridaRun, gdbRun, lldbRun } from './providers/dynamic.js';
import { ghidraDecompile, ghidraFunctions } from './providers/ghidra.js';
import { apktoolDecode, ilspyDecompile, jadxDecompile, jadxSearch } from './providers/jvm.js';
import { r2Decompile, r2Disasm, r2Functions, r2Info, r2Strings, r2Xrefs } from './providers/radare2.js';
import { adbDevices, adbLogcat, adbPackages, adbPullApk, binjaFunctions, binwalkScan, idaRun, objdump } from './providers/static.js';
import { MCP_CLIENTS, setupClient, SetupError } from './setup.js';
import { UnsafeArgumentError } from './exec.js';
import { HookParamError } from './hooks.js';
import type { BridgeTool, ToolInputField } from './types.js';

const f = (type: ToolInputField['type'], description: string, optional = true): ToolInputField => ({ type, description, ...(optional ? { optional: true } : {}) });
const PATH = f('string', 'path to the file to analyze', false);
const ENGINE = f('string', 'radare2, rizin or auto (default)');
const ANALYSIS = f('string', 'analysis depth before the query: none, aa (default) or aaa');
const FN = f('string', 'function name (main, sym.main, check_password) or 0x address');
const LIMIT = f('number', 'max items to return');
const OFFSET = f('number', 'items to skip, for paging');
const TIMEOUT = f('number', 'time limit in milliseconds');
const ALLOW = f('boolean', 'must be true: this runs or instruments code, only use on trusted targets or inside a sandbox', false);

/** Wrap a run function so bad input comes back as { ok: false, error } instead of throwing. */
function safe(run: (input: any) => Promise<unknown>): (input: any) => Promise<unknown> {
  return async (input: any) => {
    try {
      return await run(input ?? {});
    } catch (e) {
      if (e instanceof BridgeInputError || e instanceof UnsafeArgumentError || e instanceof SetupError || e instanceof HookParamError) {
        return { ok: false, inputError: true, error: e.message };
      }
      throw e;
    }
  };
}

const RAW: BridgeTool[] = [
  {
    name: 'bridge_doctor',
    description: 'Inventory of external reverse engineering tools on this machine (radare2, rizin, Ghidra, jadx, apktool, ILSpy, Frida, gdb, lldb, objdump, binwalk, adb, IDA, Binary Ninja): versions, paths, what each unlocks, and install commands for missing ones.',
    inputSchema: { refresh: f('boolean', 'probe again instead of using the cached result') },
    run: (i) => inventory({ refresh: i.refresh === true }),
  },
  {
    name: 'bridge_r2_functions',
    description: 'List functions recovered by radare2 or rizin with address, size, basic blocks and call counts. Paged.',
    inputSchema: { path: PATH, engine: ENGINE, analysis: ANALYSIS, filter: f('string', 'substring filter on the name'), limit: LIMIT, offset: OFFSET, timeoutMs: TIMEOUT },
    run: (i) => r2Functions(i),
  },
  {
    name: 'bridge_r2_disasm',
    description: 'Disassemble one function (or N instructions at an address) with radare2 or rizin. Returns address, bytes and text per instruction.',
    inputSchema: { path: PATH, function: FN, engine: ENGINE, analysis: ANALYSIS, maxInstructions: f('number', 'cap, default 2000'), timeoutMs: TIMEOUT },
    run: (i) => r2Disasm(i),
  },
  {
    name: 'bridge_r2_decompile',
    description: 'Decompile one function to C with r2ghidra or rz-ghidra, falling back to radare2 pseudo code (pdc) when the plugin is missing.',
    inputSchema: { path: PATH, function: FN, engine: ENGINE, analysis: ANALYSIS, maxChars: f('number', 'cap on returned characters'), timeoutMs: TIMEOUT },
    run: (i) => r2Decompile(i),
  },
  {
    name: 'bridge_r2_xrefs',
    description: 'Cross references to a function or address (who calls or reads it) with radare2 or rizin.',
    inputSchema: { path: PATH, function: FN, engine: ENGINE, analysis: ANALYSIS, timeoutMs: TIMEOUT },
    run: (i) => r2Xrefs(i),
  },
  {
    name: 'bridge_r2_strings',
    description: 'Strings in data sections with virtual and file addresses, from radare2 or rizin. Paged.',
    inputSchema: { path: PATH, engine: ENGINE, minLength: f('number', 'minimum length, default 4'), limit: LIMIT, offset: OFFSET, timeoutMs: TIMEOUT },
    run: (i) => r2Strings(i),
  },
  {
    name: 'bridge_r2_info',
    description: 'Binary info (arch, bits, format, hardening flags, base address) and imports from radare2 or rizin.',
    inputSchema: { path: PATH, engine: ENGINE, timeoutMs: TIMEOUT },
    run: (i) => r2Info(i),
  },
  {
    name: 'bridge_ghidra_functions',
    description: 'List functions with Ghidra headless (address including image base, size, signature, calling convention). The analyzed project is cached per file hash. Paged.',
    inputSchema: { path: PATH, limit: LIMIT, offset: OFFSET, timeoutMs: TIMEOUT, cacheDir: f('string', 'folder for cached Ghidra projects') },
    run: (i) => ghidraFunctions(i),
  },
  {
    name: 'bridge_ghidra_decompile',
    description: 'Decompile functions to C with Ghidra headless. Give names or 0x addresses (Ghidra addresses include the image base, for example 0x100828 for a PIE at 0x828).',
    inputSchema: { path: PATH, functions: f('array', 'function names or 0x addresses', false), maxCharsPerFunction: f('number', 'cap per function'), perFunctionTimeoutSec: f('number', 'decompiler time per function, default 60'), timeoutMs: TIMEOUT, cacheDir: f('string', 'folder for cached Ghidra projects') },
    run: (i) => ghidraDecompile(i),
  },
  {
    name: 'bridge_jadx_decompile',
    description: 'Decompile an APK, DEX, JAR, AAR or class file to Java with jadx. Without className lists classes (paged); with className returns that class source.',
    inputSchema: { path: PATH, className: f('string', 'fully qualified class, for example com.example.MainActivity'), limit: LIMIT, offset: OFFSET, maxChars: f('number', 'cap on returned characters'), timeoutMs: TIMEOUT },
    run: (i) => jadxDecompile(i),
  },
  {
    name: 'bridge_jadx_search',
    description: 'Search jadx decompiled Java for a literal string (URLs, keys, class names). Returns class, line number and line text.',
    inputSchema: { path: PATH, query: f('string', 'literal text to find', false), caseSensitive: f('boolean', 'default false'), limit: LIMIT, timeoutMs: TIMEOUT },
    run: (i) => jadxSearch(i),
  },
  {
    name: 'bridge_apktool_decode',
    description: 'Decode an APK with apktool: AndroidManifest.xml as text, apktool.yml, and the decoded resource and smali file list.',
    inputSchema: { path: PATH, noSources: f('boolean', 'skip smali for speed'), limit: LIMIT, timeoutMs: TIMEOUT },
    run: (i) => apktoolDecode(i),
  },
  {
    name: 'bridge_ilspy_decompile',
    description: 'Decompile a .NET assembly with ilspycmd. Without typeName lists types (paged); with typeName returns that type as C#.',
    inputSchema: { path: PATH, typeName: f('string', 'full type name, for example MyApp.Program'), limit: LIMIT, offset: OFFSET, maxChars: f('number', 'cap on returned characters'), timeoutMs: TIMEOUT },
    run: (i) => ilspyDecompile(i),
  },
  {
    name: 'bridge_frida_ps',
    description: 'List processes (or installed apps) on a Frida device. Read only.',
    inputSchema: { device: f('string', 'local (default), usb, remote or a device id'), applications: f('boolean', 'list installed apps instead of processes'), filter: f('string', 'substring filter'), limit: LIMIT },
    run: (i) => fridaPs(i),
  },
  {
    name: 'bridge_frida_devices',
    description: 'List Frida devices (local, USB, remote). Read only.',
    inputSchema: {},
    run: (i) => fridaDevices(i),
  },
  {
    name: 'bridge_frida_run',
    description: `Attach to a process (pid or name) or spawn a program and run a RevLens hook template, collecting JSON events. Templates: ${HOOK_TEMPLATES.map((t) => t.id).join(', ')}. Needs allowExecution: true.`,
    inputSchema: {
      template: f('string', 'hook template id', false), params: f('object', 'template parameters, see bridge_frida_templates'),
      pid: f('number', 'attach to this pid'), name: f('string', 'attach to a process by name'), spawn: f('string', 'spawn this program or Android package'),
      args: f('array', 'arguments for a spawned local program'), device: f('string', 'local (default), usb, remote or a device id'),
      durationMs: f('number', 'how long to collect events, default 5000'), maxEvents: f('number', 'cap, default 2000'), allowExecution: ALLOW,
    },
    run: (i) => fridaRun(i),
  },
  {
    name: 'bridge_frida_templates',
    description: 'List the built-in Frida hook templates and their parameters.',
    inputSchema: {},
    run: async () => ({ templates: HOOK_TEMPLATES }),
  },
  {
    name: 'bridge_gdb_run',
    description: 'Run a program under gdb (or lldb with debugger: lldb) in batch mode. At each breakpoint returns registers, backtrace and an optional memory dump. Needs allowExecution: true.',
    inputSchema: {
      path: PATH, args: f('array', 'program arguments'), breakpoints: f('array', 'symbols or 0x addresses', false),
      registers: f('array', 'register names, default all'), backtrace: f('number', 'frames per stop, default 16'),
      memory: f('object', '{ base: "$sp" or 0x address, count: bytes }'), maxStops: f('number', 'stops to inspect, default 8'),
      debugger: f('string', 'gdb (default) or lldb'), timeoutMs: TIMEOUT, allowExecution: ALLOW,
    },
    run: (i) => (i.debugger === 'lldb' ? lldbRun(i) : gdbRun(i)),
  },
  {
    name: 'bridge_objdump',
    description: 'Disassemble (optionally one symbol or an address range), list sections or list symbols with GNU objdump or llvm-objdump. Good second opinion next to radare2.',
    inputSchema: { path: PATH, mode: f('string', 'disasm (default), sections or symbols'), function: f('string', 'symbol to disassemble'), startAddress: f('string', '0x start'), stopAddress: f('string', '0x stop'), engine: f('string', 'objdump, llvm-objdump or auto'), limit: LIMIT, timeoutMs: TIMEOUT },
    run: (i) => objdump(i),
  },
  {
    name: 'bridge_binwalk',
    description: 'Firmware signature scan with binwalk: embedded archives, images, file systems and compressed blobs with their offsets. Never extracts.',
    inputSchema: { path: PATH, limit: LIMIT, timeoutMs: TIMEOUT },
    run: (i) => binwalkScan(i),
  },
  {
    name: 'bridge_adb_devices',
    description: 'List Android devices and emulators visible to adb.',
    inputSchema: {},
    run: (i) => adbDevices(i),
  },
  {
    name: 'bridge_adb_packages',
    description: 'List installed Android packages with their APK paths.',
    inputSchema: { serial: f('string', 'device serial when several are connected'), filter: f('string', 'substring filter'), thirdPartyOnly: f('boolean', 'only user installed apps'), limit: LIMIT },
    run: (i) => adbPackages(i),
  },
  {
    name: 'bridge_adb_pull_apk',
    description: 'Pull the base and split APKs of an installed package to a local folder, ready for bridge_jadx_decompile.',
    inputSchema: { package: f('string', 'package name, for example com.example.app', false), serial: f('string', 'device serial'), outDir: f('string', 'local folder') },
    run: (i) => adbPullApk(i),
  },
  {
    name: 'bridge_adb_logcat',
    description: 'Dump recent logcat lines from a device, optionally for one tag.',
    inputSchema: { serial: f('string', 'device serial'), lines: f('number', 'how many lines, default 500'), tag: f('string', 'only this tag') },
    run: (i) => adbLogcat(i),
  },
  {
    name: 'bridge_ida_run',
    description: 'Run IDA (idat) in batch mode to list functions or decompile selected ones with Hex-Rays when licensed.',
    inputSchema: { path: PATH, mode: f('string', 'functions (default) or decompile'), functions: f('array', 'names or 0x addresses for decompile'), limit: LIMIT, offset: OFFSET, timeoutMs: TIMEOUT },
    run: (i) => idaRun(i),
  },
  {
    name: 'bridge_binja_functions',
    description: 'List functions with the Binary Ninja headless API (needs a license that allows headless use).',
    inputSchema: { path: PATH, python: f('string', 'python interpreter to use'), limit: LIMIT, offset: OFFSET, timeoutMs: TIMEOUT },
    run: (i) => binjaFunctions(i),
  },
  {
    name: 'bridge_setup_mcp',
    description: `Add the RevLens MCP server to an agent client config (${MCP_CLIENTS.join(', ')}). Dry run by default and returns the new file text; write: true saves it with a backup.`,
    inputSchema: { client: f('string', MCP_CLIENTS.join(', '), false), scope: f('string', 'user (default) or project'), write: f('boolean', 'actually write the file') },
    run: (i) => setupClient({ client: i.client, scope: i.scope, write: i.write === true }),
  },
];

/** Every bridge tool, with input errors returned as JSON instead of thrown. */
export const TOOLS: BridgeTool[] = RAW.map((t) => ({ ...t, run: safe(t.run) }));
