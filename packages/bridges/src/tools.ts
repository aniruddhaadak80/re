// Agent tools. Every tool returns JSON. When the needed program is missing the result is
// { available: false, tool, reason, install } instead of an error. Tools that run code need
// allowExecution: true. Node only.
import { inventory } from './doctor.js';
import { HOOK_TEMPLATES } from './hooks.js';
import { BridgeInputError, need } from './providers/common.js';
import { fridaDevices, fridaPs, fridaRun, gdbRun, lldbRun } from './providers/dynamic.js';
import { ghidraDecompile, ghidraFunctions } from './providers/ghidra.js';
import { apktoolDecode, ilspyDecompile, jadxDecompile, jadxSearch } from './providers/jvm.js';
import { r2Decompile, r2Disasm, r2Functions, r2Info, r2Strings, r2Xrefs } from './providers/radare2.js';
import { adbDevices, adbLogcat, adbPackages, adbPullApk, binjaFunctions, binwalkScan, idaRun, objdump } from './providers/static.js';
import {
  adbBackup, adbBugreport, adbDisplay, adbDumpsysPackage, adbGetprop, adbInput, adbInstall, adbListComponents, adbLogcatFiltered, adbLs,
  adbPmPath, adbPortMap, adbPs, adbPull, adbPush, adbResolveActivity, adbScreenrecord, adbScreenshot, adbSettings, adbStartActivity, adbStopApp, adbUninstall,
} from './providers/adb.js';
import { MCP_CLIENTS, setupClient, SetupError } from './setup.js';
import { gdbSessionCmd, gdbSessionOpen, lldbSessionCmd, lldbSessionOpen, r2SessionCmd, r2SessionOpen, sessionClose, sessionList } from './sessions/debuggers.js';
import { fridaSessionAttach, fridaSessionCollect, fridaSessionLoad, fridaSessionPost, fridaSessionResume, fridaSessionUnload } from './sessions/frida.js';
import { SessionError } from './sessions/manager.js';
import { ghidraApplyNames, ghidraExportNames, idaApplyNames, idaExportNames, r2ApplyNames, r2ExportNames } from './writeback/providers.js';
import { NamesError } from './names.js';
import { detect } from './detect.js';
import { installFor } from './catalog.js';
import { UnsafeArgumentError } from './exec.js';
import { listCutterSessions, cutterCommand } from './cutter.js';
import { detectJeb, jebDecompile, jebInfo, jebUnits, JEB_INSTALL, jebScriptPath } from './jeb.js';
import { HookParamError } from './hooks.js';
import type { BridgeTool, ToolId, ToolInputField } from './types.js';

const f = (type: ToolInputField['type'], description: string, optional = true): ToolInputField => ({ type, description, ...(optional ? { optional: true } : {}) });
const PATH = f('string', 'path to the file to analyze', false);
const ENGINE = f('string', 'radare2, rizin or auto (default)');
const ANALYSIS = f('string', 'analysis depth before the query: none, aa (default) or aaa');
const FN = f('string', 'function name (main, sym.main, check_password) or 0x address');
const LIMIT = f('number', 'max items to return');
const OFFSET = f('number', 'items to skip, for paging');
const TIMEOUT = f('number', 'time limit in milliseconds');
const NAMES = f('object', 'RevLens names JSON object { schema: "revlens/names@1", functions, comments, labels, types }');
const NAMES_PATH = f('string', 'path to a RevLens names JSON file instead of names');
const SID = f('string', 'session id from the open call', false);
const IDLE = f('number', 'close the session after this many ms without use (default 15 minutes)');
const SERIAL = f('string', 'device serial when several are connected');
const PKG = f('string', 'package name, for example com.example.app', false);
const DEVICE = f('boolean', 'must be true: this changes the connected device', false);
const ALLOW = f('boolean', 'must be true: this runs or instruments code, only use on trusted targets or inside a sandbox', false);

/**
 * Tools that need exactly one program. For these the program is looked up before the input is
 * checked, so a missing program always answers { available: false, install } whatever the input.
 */
function requiredTool(name: string): ToolId | ToolId[] | undefined {
  if (name.startsWith('bridge_adb_')) return 'adb';
  if (name.startsWith('bridge_gdb_session_')) return 'gdb';
  if (name.startsWith('bridge_lldb_session_')) return 'lldb';
  if (name.startsWith('bridge_frida_session_')) return 'frida';
  if (name.startsWith('bridge_r2_session_') || name === 'bridge_r2_apply_names' || name === 'bridge_r2_export_names') return ['radare2', 'rizin'];
  return REQUIRES[name];
}
const REQUIRES: Record<string, ToolId> = {
  bridge_ghidra_apply_names: 'ghidra', bridge_ghidra_export_names: 'ghidra', bridge_ida_apply_names: 'ida', bridge_ida_export_names: 'ida',
};

/** Wrap a run function so bad input comes back as { ok: false, error } instead of throwing. */
function safe(run: (input: any) => Promise<unknown>, requires?: ToolId | ToolId[]): (input: any) => Promise<unknown> {
  return async (input: any) => {
    if (requires) {
      // any one of the listed programs is enough
      let missing: unknown;
      for (const id of Array.isArray(requires) ? requires : [requires]) {
        const n = await need(id);
        if (!('missing' in n)) { missing = undefined; break; }
        missing ??= n.missing;
      }
      if (missing) return missing;
    }
    try {
      return await run(input ?? {});
    } catch (e) {
      if (e instanceof BridgeInputError || e instanceof UnsafeArgumentError || e instanceof SetupError || e instanceof HookParamError) {
        return { ok: false, inputError: true, error: e.message };
      }
      if (e instanceof SessionError) return { ok: false, sessionError: true, error: e.message };
      if (e instanceof NamesError) return { ok: false, inputError: true, error: e.message, problems: e.problems.slice(0, 100) };
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
  // ---- wider ADB suite ----
  {
    name: 'bridge_adb_install',
    description: 'Install an APK (or base plus split APKs with install-multiple) on a device. Changes the device: needs allowExecution: true.',
    inputSchema: { path: f('string', 'APK file'), paths: f('array', 'base and split APK files for install-multiple'), serial: SERIAL, replace: f('boolean', 'reinstall keeping data (-r)'), downgrade: f('boolean', 'allow version downgrade (-d)'), allowTest: f('boolean', 'allow test-only APKs (-t)'), grantPermissions: f('boolean', 'grant runtime permissions (-g)'), timeoutMs: TIMEOUT, allowExecution: DEVICE },
    run: (i) => adbInstall(i),
  },
  {
    name: 'bridge_adb_uninstall',
    description: 'Uninstall a package from a device. Changes the device: needs allowExecution: true.',
    inputSchema: { package: PKG, serial: SERIAL, keepData: f('boolean', 'keep data and cache (-k)'), allowExecution: DEVICE },
    run: (i) => adbUninstall(i),
  },
  {
    name: 'bridge_adb_push',
    description: 'Copy a local file to the device, below /data/local/tmp, /sdcard or /storage/emulated unless allowAnyRemotePath. Changes the device: needs allowExecution: true.',
    inputSchema: { path: f('string', 'local file', false), remotePath: f('string', 'device destination path', false), serial: SERIAL, allowAnyRemotePath: f('boolean', 'allow other device folders'), timeoutMs: TIMEOUT, allowExecution: DEVICE },
    run: (i) => adbPush(i),
  },
  {
    name: 'bridge_adb_pull',
    description: 'Copy one file from the device to a local folder with its SHA-256. Checks the remote size first (maxBytes) and never overwrites unless asked.',
    inputSchema: { remotePath: f('string', 'device file path', false), outDir: f('string', 'local folder'), serial: SERIAL, overwrite: f('boolean', 'replace an existing local file'), maxBytes: f('number', 'refuse bigger files, default 2 GiB'), timeoutMs: TIMEOUT },
    run: (i) => adbPull(i),
  },
  {
    name: 'bridge_adb_start_activity',
    description: 'Start an activity with am start -W by component, or the launcher activity of a package. Every value is validated and quoted for the device shell. Changes the device: needs allowExecution: true.',
    inputSchema: { component: f('string', 'component like com.example/.MainActivity'), package: f('string', 'start this package launcher activity instead'), action: f('string', 'intent action'), data: f('string', 'intent data URI'), categories: f('array', 'intent categories'), extras: f('object', 'string extras { key: value }'), forceStop: f('boolean', 'stop the app first (-S)'), serial: SERIAL, timeoutMs: TIMEOUT, allowExecution: DEVICE },
    run: (i) => adbStartActivity(i),
  },
  {
    name: 'bridge_adb_stop_app',
    description: 'Force stop an app (am force-stop). Changes the device: needs allowExecution: true.',
    inputSchema: { package: PKG, serial: SERIAL, allowExecution: DEVICE },
    run: (i) => adbStopApp(i),
  },
  {
    name: 'bridge_adb_dumpsys_package',
    description: 'dumpsys package as JSON: version, SDK levels, flags (debuggable, allowBackup), install times, declared, requested, install and runtime permissions, and components with intent filters.',
    inputSchema: { package: PKG, serial: SERIAL, includeRaw: f('boolean', 'also return the raw text (capped)'), timeoutMs: TIMEOUT },
    run: (i) => adbDumpsysPackage(i),
  },
  {
    name: 'bridge_adb_components',
    description: 'List activities, services, receivers and providers of an installed package with their intent actions, categories, schemes and permissions, plus launcher activities.',
    inputSchema: { package: PKG, kind: f('string', 'activities, services, receivers, providers or all (default)'), serial: SERIAL, timeoutMs: TIMEOUT },
    run: (i) => adbListComponents(i),
  },
  {
    name: 'bridge_adb_resolve_activity',
    description: 'Which activity an intent opens (cmd package resolve-activity). Default: the launcher activity of package, or the HOME screen without one.',
    inputSchema: { package: f('string', 'package to resolve within'), action: f('string', 'intent action, default MAIN'), category: f('string', 'intent category, default LAUNCHER (HOME without package)'), serial: SERIAL },
    run: (i) => adbResolveActivity(i),
  },
  {
    name: 'bridge_adb_pm_path',
    description: 'APK paths (base and splits) of an installed package (pm path).',
    inputSchema: { package: PKG, serial: SERIAL },
    run: (i) => adbPmPath(i),
  },
  {
    name: 'bridge_adb_screenshot',
    description: 'Take a PNG screenshot into a local folder; returns the path, size in pixels and SHA-256.',
    inputSchema: { serial: SERIAL, outDir: f('string', 'local folder'), timeoutMs: TIMEOUT },
    run: (i) => adbScreenshot(i),
  },
  {
    name: 'bridge_adb_screenrecord',
    description: 'Record the screen to a local MP4 for a bounded time (1 to 180 seconds, default 10).',
    inputSchema: { serial: SERIAL, seconds: f('number', 'length, max 180'), size: f('string', 'video size like 1280x720'), bitRate: f('number', 'bits per second'), outDir: f('string', 'local folder') },
    run: (i) => adbScreenrecord(i),
  },
  {
    name: 'bridge_adb_display',
    description: 'Display size and density, physical and override (wm size, wm density).',
    inputSchema: { serial: SERIAL },
    run: (i) => adbDisplay(i),
  },
  {
    name: 'bridge_adb_input',
    description: 'Send one input event: tap (x, y), swipe (x, y, x2, y2, durationMs), text (printable ASCII) or keyevent (KEYCODE_HOME or a number). Changes the device: needs allowExecution: true.',
    inputSchema: { kind: f('string', 'tap, swipe, text or keyevent', false), x: f('number', 'x'), y: f('number', 'y'), x2: f('number', 'swipe end x'), y2: f('number', 'swipe end y'), durationMs: f('number', 'swipe time'), text: f('string', 'text to type'), keycode: f('string', 'KEYCODE_NAME or number'), serial: SERIAL, allowExecution: DEVICE },
    run: (i) => adbInput(i),
  },
  {
    name: 'bridge_adb_getprop',
    description: 'Device properties: one key, or all (optionally by prefix) plus a summary (model, release, SDK, ABI, fingerprint, debuggable, secure, patch level).',
    inputSchema: { key: f('string', 'one property, for example ro.build.version.sdk'), prefix: f('string', 'only keys with this prefix'), serial: SERIAL, limit: LIMIT },
    run: (i) => adbGetprop(i),
  },
  {
    name: 'bridge_adb_settings',
    description: 'Read one setting or list a settings namespace (system, secure, global). Read only.',
    inputSchema: { namespace: f('string', 'system, secure or global', false), key: f('string', 'one key; omit to list all'), serial: SERIAL, limit: LIMIT },
    run: (i) => adbSettings(i),
  },
  {
    name: 'bridge_adb_ps',
    description: 'Running processes on the device (user, pid, ppid, memory, state, name), optionally filtered by name.',
    inputSchema: { filter: f('string', 'substring filter on the name'), serial: SERIAL, limit: LIMIT },
    run: (i) => adbPs(i),
  },
  {
    name: 'bridge_adb_ls',
    description: 'List a device folder (ls -la): type, mode, owner, group, size, date, name and link target.',
    inputSchema: { remotePath: f('string', 'device folder', false), serial: SERIAL, limit: LIMIT },
    run: (i) => adbLs(i),
  },
  {
    name: 'bridge_adb_logcat_filtered',
    description: 'Logcat with filter specs (Tag:P), one pid, a buffer (main, system, crash, events, all), a since time and a substring filter.',
    inputSchema: { specs: f('array', 'filter specs like ActivityManager:I or MyTag:D'), pid: f('number', 'only this process'), buffer: f('string', 'main, system, crash, events, radio, kernel, all'), since: f('string', "'MM-DD hh:mm:ss.mmm' or epoch seconds"), contains: f('string', 'keep lines containing this text'), lines: f('number', 'how many lines, default 500'), serial: SERIAL },
    run: (i) => adbLogcatFiltered(i),
  },
  {
    name: 'bridge_adb_bugreport',
    description: 'Collect a bugreport zip with a hard time limit (default 10 minutes, max 30) and a size cap.',
    inputSchema: { serial: SERIAL, outDir: f('string', 'local folder'), timeoutMs: TIMEOUT, maxBytes: f('number', 'size cap, default 1 GiB') },
    run: (i) => adbBugreport(i),
  },
  {
    name: 'bridge_adb_backup',
    description: 'adb backup of one package to a local .ab file and its header. The device asks its user to confirm; apps with allowBackup=false give an empty file.',
    inputSchema: { package: PKG, includeApk: f('boolean', 'include the APK'), outDir: f('string', 'local folder'), serial: SERIAL, timeoutMs: TIMEOUT },
    run: (i) => adbBackup(i),
  },
  {
    name: 'bridge_adb_forward',
    description: 'List, add or remove host to device port forwards (tcp:N, localabstract:name, jdwp:pid). Adding and removing need allowExecution: true.',
    inputSchema: { action: f('string', 'list (default), add, remove or remove-all'), local: f('string', 'host side, for example tcp:27042'), remote: f('string', 'device side, for example tcp:27042'), serial: SERIAL, allowExecution: f('boolean', 'must be true for add and remove') },
    run: (i) => adbPortMap({ ...i, direction: 'forward' }),
  },
  {
    name: 'bridge_adb_reverse',
    description: 'List, add or remove device to host reverse port rules. Adding and removing change the device: need allowExecution: true.',
    inputSchema: { action: f('string', 'list (default), add, remove or remove-all'), local: f('string', 'device side, for example tcp:8081'), remote: f('string', 'host side, for example tcp:8081'), serial: SERIAL, allowExecution: f('boolean', 'must be true for add and remove') },
    run: (i) => adbPortMap({ ...i, direction: 'reverse' }),
  },
  // ---- persistent sessions ----
  {
    name: 'bridge_session_list',
    description: 'List open radare2/rizin, gdb, lldb and Frida sessions with ids, targets, idle timeouts and command counts.',
    inputSchema: {},
    run: () => sessionList(),
  },
  {
    name: 'bridge_session_close',
    description: 'Close one session by id (or every session with all: true). Sessions also close after their idle timeout and when the server exits.',
    inputSchema: { sessionId: f('string', 'session id'), all: f('boolean', 'close every session') },
    run: (i) => sessionClose(i),
  },
  {
    name: 'bridge_r2_session_open',
    description: 'Open a radare2 (or rizin) session on a file and keep it alive across calls, so analysis runs once and names you set stay. Static only, sandboxed (cfg.sandbox), no shell.',
    inputSchema: { path: PATH, engine: ENGINE, analysis: f('string', 'none (default), aa or aaa, run once at open'), idleTimeoutMs: IDLE, timeoutMs: TIMEOUT },
    run: (i) => r2SessionOpen(i),
  },
  {
    name: 'bridge_r2_session_cmd',
    description: 'Run one radare2 or rizin command in an open session (afl, pdf @ main, afn name @ addr, axt, izj). JSON commands come back parsed. Shell, pipes, file writes, opening other files and scripts are refused.',
    inputSchema: { sessionId: SID, command: f('string', 'one r2 command line', false), timeoutMs: TIMEOUT, maxChars: f('number', 'cap on returned characters') },
    run: (i) => r2SessionCmd(i),
  },
  {
    name: 'bridge_gdb_session_open',
    description: 'Start gdb (MI) on a program with arguments, or attached to a pid, and keep it alive across calls. Program output goes to its own stream. Needs allowExecution: true.',
    inputSchema: { path: f('string', 'program to debug'), args: f('array', 'program arguments (passed without a shell)'), pid: f('number', 'attach to this pid instead'), idleTimeoutMs: IDLE, allowExecution: ALLOW },
    run: (i) => gdbSessionOpen(i),
  },
  {
    name: 'bridge_gdb_session_cmd',
    description: 'Run one gdb console command in a session (break, run, continue, stepi, info registers, bt, x/16gx $sp). Resuming commands wait for the next stop, then interrupt on timeout. shell, python, source, dump, file and similar are refused.',
    inputSchema: { sessionId: SID, command: f('string', 'one gdb command', false), timeoutMs: TIMEOUT, maxChars: f('number', 'cap on returned characters') },
    run: (i) => gdbSessionCmd(i),
  },
  {
    name: 'bridge_lldb_session_open',
    description: 'Start lldb on a program with arguments, or attached to a pid, and keep it alive across calls. Needs allowExecution: true.',
    inputSchema: { path: f('string', 'program to debug'), args: f('array', 'program arguments'), pid: f('number', 'attach to this pid instead'), idleTimeoutMs: IDLE, allowExecution: ALLOW },
    run: (i) => lldbSessionOpen(i),
  },
  {
    name: 'bridge_lldb_session_cmd',
    description: 'Run one lldb command in a session (b, run, continue, si, register read, bt, memory read). Waits until the program stops. platform shell, script, command script and similar are refused.',
    inputSchema: { sessionId: SID, command: f('string', 'one lldb command', false), timeoutMs: TIMEOUT, maxChars: f('number', 'cap on returned characters') },
    run: (i) => lldbSessionCmd(i),
  },
  {
    name: 'bridge_frida_session_attach',
    description: 'Attach Frida to a process (pid or name) or spawn a program and keep the session open for scripts and messages. Needs allowExecution: true.',
    inputSchema: { pid: f('number', 'attach to this pid'), name: f('string', 'attach by process name'), spawn: f('string', 'spawn this program (stays suspended until a script loads or resume)'), args: f('array', 'arguments for a spawned program'), device: f('string', 'local (default), usb, remote or a device id'), maxEvents: f('number', 'event buffer size, default 10000'), idleTimeoutMs: IDLE, allowExecution: ALLOW },
    run: (i) => fridaSessionAttach(i),
  },
  {
    name: 'bridge_frida_session_load',
    description: 'Load a script into a Frida session: a RevLens hook template (see bridge_frida_templates) or your own JavaScript source. Returns a script id. A spawned program is resumed after the first load unless resume: false.',
    inputSchema: { sessionId: SID, template: f('string', 'hook template id'), params: f('object', 'template parameters'), source: f('string', 'JavaScript source instead of a template'), resume: f('boolean', 'resume a spawned program (default true)') },
    run: (i) => fridaSessionLoad(i),
  },
  {
    name: 'bridge_frida_session_post',
    description: 'Post a JSON message to a loaded script (the script reads it with recv()).',
    inputSchema: { sessionId: SID, script: f('number', 'script id from load', false), message: f('object', 'JSON message, usually { type: "...", ... }', false) },
    run: (i) => fridaSessionPost(i),
  },
  {
    name: 'bridge_frida_session_collect',
    description: 'Take buffered events from a Frida session: send() payloads, console logs, parsed RevLens template events, script errors and detach notices. Can wait up to waitMs for minEvents.',
    inputSchema: { sessionId: SID, script: f('number', 'only this script'), limit: LIMIT, waitMs: f('number', 'wait this long for events'), minEvents: f('number', 'how many events to wait for, default 1') },
    run: (i) => fridaSessionCollect(i),
  },
  {
    name: 'bridge_frida_session_unload',
    description: 'Unload one script from a Frida session; the session stays attached.',
    inputSchema: { sessionId: SID, script: f('number', 'script id', false) },
    run: (i) => fridaSessionUnload(i),
  },
  {
    name: 'bridge_frida_session_resume',
    description: 'Resume a spawned program that is still suspended.',
    inputSchema: { sessionId: SID },
    run: (i) => fridaSessionResume(i),
  },
  // ---- write-back ----
  {
    name: 'bridge_ghidra_apply_names',
    description: 'Write function names, signatures, comments, labels and C types from a RevLens names JSON into a Ghidra project (the cached RevLens project for the file by default, so later Ghidra decompiles show the names, or your own project).',
    inputSchema: { path: PATH, names: NAMES, namesPath: NAMES_PATH, projectDir: f('string', 'your Ghidra project folder'), projectName: f('string', 'project name (the .gpr file name without extension)'), programName: f('string', 'program inside the project'), cacheDir: f('string', 'folder for cached Ghidra projects'), timeoutMs: TIMEOUT },
    run: (i) => ghidraApplyNames(i),
  },
  {
    name: 'bridge_ghidra_export_names',
    description: 'Export user defined function names and signatures, comments in functions, user labels and /RevLens types from a Ghidra project as a RevLens names JSON.',
    inputSchema: { path: PATH, all: f('boolean', 'every non default name and comment'), outPath: f('string', 'also save the JSON here'), projectDir: f('string', 'your Ghidra project folder'), projectName: f('string', 'project name'), programName: f('string', 'program inside the project'), cacheDir: f('string', 'folder for cached Ghidra projects'), timeoutMs: TIMEOUT },
    run: (i) => ghidraExportNames(i),
  },
  {
    name: 'bridge_ida_apply_names',
    description: 'Write a RevLens names JSON into an IDA database with idat: give a .i64/.idb to update it, or a binary plus outDatabase to create one. Names, prototypes, comments, labels and C types.',
    inputSchema: { path: f('string', 'IDA database (.i64/.idb) or binary', false), names: NAMES, namesPath: NAMES_PATH, outDatabase: f('string', 'new .i64 path when path is a binary'), binaryForBase: f('string', 'original binary, to read its image base when path is a database'), timeoutMs: TIMEOUT },
    run: (i) => idaApplyNames(i),
  },
  {
    name: 'bridge_ida_export_names',
    description: 'Export user names, prototypes, comments, labels and local types from an IDA database (or a binary) as a RevLens names JSON.',
    inputSchema: { path: f('string', 'IDA database (.i64/.idb) or binary', false), all: f('boolean', 'every non dummy name'), outPath: f('string', 'also save the JSON here'), timeoutMs: TIMEOUT },
    run: (i) => idaExportNames(i),
  },
  {
    name: 'bridge_r2_apply_names',
    description: 'Write a RevLens names JSON into a radare2 project (or rizin .rzdb), creating it from the binary when needed; returns the r2 script too. Names that r2 cannot hold are mapped to safe ones and listed.',
    inputSchema: { path: PATH, names: NAMES, namesPath: NAMES_PATH, engine: ENGINE, project: f('string', 'project name, default revlens_<sha256 prefix>'), projectsDir: f('string', 'projects folder'), analysis: f('string', 'analysis when creating the project: none, aa (default) or aaa'), timeoutMs: TIMEOUT },
    run: (i) => r2ApplyNames(i),
  },
  {
    name: 'bridge_r2_export_names',
    description: 'Export what was added to a radare2 or rizin project (names and comments that differ from a fresh analysis, plus RevLens labels) as a RevLens names JSON.',
    inputSchema: { path: PATH, engine: ENGINE, project: f('string', 'project name'), projectsDir: f('string', 'projects folder'), all: f('boolean', 'every function name'), outPath: f('string', 'also save the JSON here'), timeoutMs: TIMEOUT },
    run: (i) => r2ExportNames(i),
  },
  {
    name: 'bridge_cutter_info',
    description: 'Find Cutter (the rizin GUI) without starting it: AppImage, macOS app, Windows release or Scoop, Flatpak, distro package. Reports version, install kind, a rizin bundled with it, and how to open a file in it.',
    inputSchema: { path: f('string', 'file you want to open in Cutter (only used to build the command line)') },
    run: async (i) => {
      const d = await detect('cutter');
      if (!d.available) return { available: false, tool: 'cutter', reason: 'Cutter was not found on this machine.', install: installFor('cutter') };
      const rz = await detect('rizin');
      const bundled = typeof d.details?.bundledRizin === 'string' ? d.details.bundledRizin : null;
      const launch = d.details?.kind === 'flatpak' ? ['flatpak', 'run', 're.rizin.cutter'] : [d.path!];
      const file = typeof i.path === 'string' && i.path ? [i.path] : [];
      return {
        available: true, tool: 'cutter', version: d.version ?? null, path: d.path, via: d.via, kind: d.details?.kind ?? null, bundledRizin: bundled,
        rizin: rz.available ? { path: rz.path, version: rz.version ?? null } : bundled ? { path: bundled, version: null, note: 'set REVLENS_RIZIN_PATH to this file to use it for bridge_r2_* with engine: rizin' } : null,
        openCommand: [...launch, ...file],
        note: 'RevLens does not drive the Cutter GUI. Use rizin directly (bridge_r2_* with engine: rizin, or bridge_r2_session_open) and write names into a rizin project with bridge_r2_apply_names, then open that project in Cutter.',
      };
    },
  },
  {
    name: 'bridge_cutter_sessions',
    description: 'Running Cutter windows with their pid, the binaries and rizin project they have open (command line plus open file handles), and whether the RevLens Cutter plugin is live in them for in-window commands. Also called list_cutter_sessions.',
    inputSchema: {},
    run: () => listCutterSessions(),
  },
  {
    name: 'bridge_cutter_command',
    description: 'Run one rizin command for a Cutter window: inside Cutter through the RevLens plugin when it is loaded (sees your renames), else in a separate rizin (Cutter\'s bundled rizin first) on the same file and project. Shell, write, open and script commands are refused. Needs allowExecution: true. Also called cutter_command.',
    inputSchema: {
      session: f('string', 'Cutter pid from bridge_cutter_sessions'), file: f('string', 'file to use when there is no session, or which of the session files'),
      project: f('string', 'rizin project (.rzdb) to load'), command: f('string', 'rizin command, for example afl, pdf @ main, axt @ sym.imp.strcpy', false),
      mode: f('string', 'auto (default), live (plugin only) or rizin (separate process)'), analysis: f('string', 'none, aa (default without a project) or aaa'),
      maxChars: f('number', 'cap on returned characters'), allowExecution: ALLOW, timeoutMs: TIMEOUT,
    },
    run: (i) => cutterCommand(i),
  },
  {
    name: 'bridge_jeb_info',
    description: 'Find JEB and, given a path, open the file in JEB headless with the RevLens script: project name, artifacts and unit count. Without a path it only reports the install and the script path.',
    inputSchema: { path: f('string', 'file to open in JEB'), timeoutMs: TIMEOUT },
    run: async (i) => {
      if (!i.path) { const d = await detectJeb(); return d.available ? { ...d, script: jebScriptPath() } : { ...d, install: JEB_INSTALL }; }
      return jebInfo(i);
    },
  },
  {
    name: 'bridge_jeb_units',
    description: 'List the units JEB builds for a file (APK, DEX, resources, native code, certificates) with type, format and child count, using JEB headless.',
    inputSchema: { path: PATH, timeoutMs: TIMEOUT },
    run: (i) => jebUnits(i),
  },
  {
    name: 'bridge_jeb_decompile',
    description: 'Decompile one item with JEB headless: a class (Lcom/a/B;), a method (Lcom/a/B;->m()V) or a native address. Returns the source text from the unit decompiler that handles it.',
    inputSchema: { path: PATH, item: f('string', 'class or method signature, or an address', false), maxChars: f('number', 'cap on returned characters'), timeoutMs: TIMEOUT },
    run: (i) => jebDecompile(i),
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
export const TOOLS: BridgeTool[] = RAW.map((t) => ({ ...t, run: safe(t.run, requiredTool(t.name)) }));
