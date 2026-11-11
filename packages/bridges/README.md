# @revlens/bridges

RevLens core is pure TypeScript and needs nothing installed. This package is the other half: it drives the
reverse engineering tools you already have, so RevLens (and any agent using it) can go deeper when they are
present and say exactly what to install when they are not.

Bridged tools: radare2, rizin, Ghidra headless, jadx, apktool, ILSpy (ilspycmd), Frida, gdb, lldb,
GNU objdump, llvm-objdump, binwalk, adb, IDA (idat batch mode) and Binary Ninja headless. Cutter is
detected without being started (and the rizin it bundles is used); Hopper is detected only.

On top of one shot runs it keeps long lived sessions (radare2 or rizin, gdb over MI, lldb, Frida) open
across tool calls, drives the full adb suite with a gate on device changing actions, and writes names,
signatures, comments, labels and C types into Ghidra, IDA and radare2 projects from one portable names
file, and exports them back out.

Node only. Node 20.10 or newer.

## What it does

- Finds each tool on PATH, in the usual install folders for Linux, macOS and Windows, and through env vars
  (`GHIDRA_INSTALL_DIR`, `JADX_HOME`, `IDADIR`, `BN_INSTALL_DIR`, `JAVA_HOME`, `ANDROID_HOME`, or
  `REVLENS_<TOOL>_PATH` to point at a binary directly). Reads versions. Notices partial installs, for example
  Ghidra with a too old JDK, Ghidra without a native decompiler for the CPU, or radare2 without r2ghidra.
- `revlens doctor` prints the inventory with install commands for the current OS (brew, apt, winget, scoop,
  choco, pipx, dotnet tool, cargo or a download link).
- Runs the tools with argument arrays (never a shell), hard timeouts that kill the whole process group, and
  output caps, then parses their output into JSON with addresses and offsets an agent can cite.
- `revlens setup <client>` adds the RevLens MCP server to Claude Code, Codex, Cursor, VS Code or Windsurf.

When a tool is missing every operation returns, instead of throwing:

```json
{ "available": false, "tool": "jadx", "reason": "jadx was not found on this machine.",
  "install": { "homepage": "https://github.com/skylot/jadx", "brew": "brew install jadx" } }
```

## Entry points

- `@revlens/bridges` (and `@revlens/bridges/pure`): browser safe parts. Tool catalog with install commands
  (`TOOL_META`, `installFor`), all output parsers (`parseR2Functions`, `parseObjdumpDisasm`, `parseGdbBatch`,
  `parseLldbBatch`, `parseBinwalkTable`, `parseFridaPs`, `parseAdbPackages`, `parseGhidraExport` and more),
  Frida hook templates (`HOOK_TEMPLATES`, `buildHookScript`), and the Ghidra and IDA export scripts.
- `@revlens/bridges/node`: everything above plus detection, providers, `TOOLS`, `CLI_COMMANDS`, setup and
  the opt in analyzers.

## API (from `@revlens/bridges/node`)

```ts
import { inventory, r2Functions, ghidraDecompile, jadxSearch, gdbRun, TOOLS, CLI_COMMANDS } from '@revlens/bridges/node';

await inventory();                                                  // capability inventory
await r2Functions({ path: 'app.elf', filter: 'check' });           // radare2 or rizin
await ghidraDecompile({ path: 'app.elf', functions: ['check_password'] });
await jadxSearch({ path: 'app.apk', query: 'https://' });
await gdbRun({ path: 'app.elf', breakpoints: ['main'], allowExecution: true });
```

Static: `r2Functions`, `r2Disasm`, `r2Decompile`, `r2Xrefs`, `r2Strings`, `r2Info`, `ghidraFunctions`,
`ghidraDecompile`, `jadxDecompile`, `jadxSearch`, `apktoolDecode`, `ilspyDecompile`, `objdump`, `binwalkScan`,
`idaRun`, `binjaFunctions`.

Devices and processes: `adbDevices`, `adbPackages`, `adbPullApk`, `adbLogcat`, `fridaPs`, `fridaDevices`.

Dynamic, these need `allowExecution: true`: `fridaRun` (attach by pid or name, or spawn), `gdbRun`,
`lldbRun`, `debugRun`. Without it they return `{ ok: false, blocked: true }` and run nothing. With it they
print a warning to stderr first.

Analyzers (`ANALYZERS`): `bridges-inventory`, `bridges-r2` (functions and binary info for ELF, PE, Mach-O)
and `bridges-jadx` (class list for DEX, APK, JAR). They spawn processes, so they only run when listed in
`options.analyzers` or when `REVLENS_BRIDGES=1` is set. Output goes to `report.meta.bridges`.

## Agent tools (`TOOLS`)

| Tool | What it does |
| --- | --- |
| `bridge_doctor` | Inventory of installed tools, versions, capabilities, install commands |
| `bridge_r2_functions` | Functions from radare2 or rizin, paged, with a name filter |
| `bridge_r2_disasm` | Disassembly of one function or N instructions at an address |
| `bridge_r2_decompile` | C from r2ghidra or rz-ghidra, or radare2 pseudo code without the plugin |
| `bridge_r2_xrefs` | Cross references to a function or address |
| `bridge_r2_strings` | Strings with virtual and file addresses |
| `bridge_r2_info` | Arch, format, hardening flags, imports |
| `bridge_ghidra_functions` | Functions from Ghidra headless (project cached per file hash) |
| `bridge_ghidra_decompile` | C from the Ghidra decompiler for names or addresses |
| `bridge_jadx_decompile` | Class list, or one class as Java, from APK, DEX, JAR, AAR or class |
| `bridge_jadx_search` | Literal text search in decompiled Java with class and line |
| `bridge_apktool_decode` | AndroidManifest.xml, apktool.yml and the decoded file list |
| `bridge_ilspy_decompile` | Type list, or one type as C#, from a .NET assembly |
| `bridge_frida_ps` | Processes or apps on a Frida device |
| `bridge_frida_devices` | Frida devices |
| `bridge_frida_run` | Inject a hook template, collect JSON events (allowExecution) |
| `bridge_frida_templates` | The hook templates and their parameters |
| `bridge_gdb_run` | gdb or lldb batch run with registers, backtrace and memory per stop (allowExecution) |
| `bridge_objdump` | Disassembly, sections or symbols from GNU objdump or llvm-objdump |
| `bridge_binwalk` | Firmware signature scan with offsets, no extraction |
| `bridge_adb_devices` | Android devices and emulators |
| `bridge_adb_packages` | Installed packages with APK paths |
| `bridge_adb_pull_apk` | Pull base and split APKs of a package |
| `bridge_adb_logcat` | Recent logcat lines |
| `bridge_adb_install` / `bridge_adb_uninstall` | Install an APK or split set, or uninstall (allowExecution) |
| `bridge_adb_push` / `bridge_adb_pull` | Copy files to the device (below /data/local/tmp, /sdcard or /storage/emulated, allowExecution) or from it (size checked, SHA-256, no overwrite unless asked) |
| `bridge_adb_start_activity` / `bridge_adb_stop_app` | `am start -W` by component or launcher, with action, data, categories and string extras; `am force-stop` (allowExecution) |
| `bridge_adb_dumpsys_package` | Version, SDK levels, flags, install times, declared, requested, install and runtime permissions |
| `bridge_adb_components` | Activities, services, receivers and providers with actions, categories, schemes and permissions, plus launcher activities |
| `bridge_adb_resolve_activity` / `bridge_adb_pm_path` | Which activity an intent opens; APK paths of a package |
| `bridge_adb_screenshot` / `bridge_adb_screenrecord` | PNG with pixel size and SHA-256; MP4 for 1 to 180 seconds |
| `bridge_adb_display` | Physical and override size and density |
| `bridge_adb_input` | tap, swipe, text, keyevent (allowExecution) |
| `bridge_adb_getprop` / `bridge_adb_settings` | Properties (one, all, by prefix, with a device summary); settings get or list for system, secure, global |
| `bridge_adb_ps` / `bridge_adb_ls` | Processes; a device folder listing |
| `bridge_adb_logcat_filtered` | Logcat with Tag:P specs, pid, buffer, since time and a substring filter |
| `bridge_adb_bugreport` / `bridge_adb_backup` | Bugreport zip with a time limit and size cap; adb backup of one package with its header |
| `bridge_adb_forward` / `bridge_adb_reverse` | List, add, remove port rules (changes need allowExecution) |
| `bridge_session_list` / `bridge_session_close` | Open sessions; close one or all |
| `bridge_r2_session_open` / `bridge_r2_session_cmd` | radare2 or rizin kept alive: analysis once, then any command (sandboxed, guarded) |
| `bridge_gdb_session_open` / `bridge_gdb_session_cmd` | gdb over MI on a program or a pid; resuming commands wait for the stop, then interrupt on timeout (allowExecution) |
| `bridge_lldb_session_open` / `bridge_lldb_session_cmd` | lldb on a program or a pid; run and continue wait for the stop (allowExecution) |
| `bridge_frida_session_attach` | Frida attached to a pid or name, or a spawned program, kept open (allowExecution) |
| `bridge_frida_session_load` / `_post` / `_collect` / `_unload` / `_resume` | Load a template or your own script, post messages, take buffered events, unload, resume |
| `bridge_ghidra_apply_names` / `bridge_ghidra_export_names` | Names JSON into or out of a Ghidra project (the cached RevLens project by default, so decompiles show the names) |
| `bridge_ida_apply_names` / `bridge_ida_export_names` | Names JSON into a .i64/.idb (or a new database from a binary) and out of one |
| `bridge_r2_apply_names` / `bridge_r2_export_names` | Names JSON into a radare2 project or rizin .rzdb (plus the r2 script) and out of one |
| `bridge_cutter_info` | Cutter version, install kind, bundled rizin and the command to open a file |
| `bridge_ida_run` | IDA batch mode: functions, or Hex-Rays decompile when licensed |
| `bridge_binja_functions` | Functions through the Binary Ninja headless API |
| `bridge_setup_mcp` | Add RevLens to an agent client config, dry run unless `write: true` |

Bad input (a function name with `;`, a breakpoint with a newline, a path that does not exist) comes back as
`{ ok: false, inputError: true, error }`.

Frida hook templates: `module-list`, `trace-native-export`, `java-method-log`, `ssl-pinning-bypass` (for
apps you own or are authorized to test) and `electron-net-observe` (DNS lookups and TCP connects). Parameters
are embedded as JSON, never pasted as code.

## Sessions

A session is a tool process kept alive in the process that opened it (normally the MCP server), so an
agent can analyze once and then ask many small questions, rename things and see the result, or step a
debugger one command at a time.

- Every session has an id like `gdb-3f9a1c0d2b7e`, an idle timeout (default 15 minutes, `idleTimeoutMs`
  or `REVLENS_SESSION_IDLE_MS`), and counts against a cap (default 8, `REVLENS_MAX_SESSIONS`, at most 64).
- Calls on one session are queued, never interleaved. A reply that does not arrive in time ends the
  radare2 and lldb sessions (they cannot resync); gdb interrupts the program instead (first with MI, then
  with SIGINT to the program, which works under gVisor ptrace too).
- `bridge_session_close` closes politely (quit, then kill the process group). On exit every session process
  group is killed, and each tool also quits when its stdin closes, so nothing outlives a crashed server.
- radare2 sessions are static only and switch on `cfg.sandbox` after loading. gdb gets a regular file as the
  program's terminal and lldb gets the null device as stdin, so the program can never read the debugger's
  command channel; its output comes back as `programOutput`.
- Command guards refuse host escapes for each tool: r2 `!`, backticks, pipes, `>`, scripts, `o`, `P`, `w`
  and sandbox changes; gdb `shell`, `pipe`, `python`, `guile`, `source`, `compile`, `dump`, `save`,
  `set logging`, `file`, `attach`, `target`, `eval`, `alias`, `define`, `apply` and `$_shell`; lldb
  `platform shell`, `script`, `command`, `target`, breakpoint and stop hook command lists, Python
  callbacks and output files. Abbreviations are caught too.
- Sessions do not survive a restart, and separate `revlens` CLI runs do not share them.

Frida sessions run a small Python helper over the frida bindings that frida-tools installs. The helper's
interpreter is found from `REVLENS_FRIDA_PYTHON`, the frida launcher's own interpreter, or python3.
`console.log` lines from RevLens templates come back as parsed events, `send()` payloads as payloads.

## Names write-back

One JSON shape moves names between tools:

```json
{ "schema": "revlens/names@1", "imageBase": "0x0", "addressing": "va",
  "functions": [{ "address": "0x848", "name": "verify_secret", "signature": "int verify_secret(char *input)", "comment": "..." }],
  "comments": [{ "address": "0x868", "text": "length check", "kind": "eol" }],
  "labels": [{ "address": "0xa08", "name": "g_secret" }],
  "types": [{ "name": "rl_pair", "c": "struct rl_pair { int a; char *b; };" }] }
```

Each tool maps addresses with `address - imageBase + toolImageBase`. Without `imageBase`, addresses are
read against the file's own declared base (lowest ELF PT_LOAD, PE ImageBase, Mach-O __TEXT). Exports carry
the tool's base, so a Ghidra export (PIE moved to 0x100000) applies cleanly to radare2 (base 0) and back.
`validateNames` checks every value (names, one line C signatures, comments, types without quotes or
preprocessor lines, caps) before anything runs.

- Ghidra: a headless script applies names (USER_DEFINED), signatures parsed by Ghidra's C parser,
  comments of every kind, labels, and types into the `/RevLens` category, then saves the project. Export
  lists user names and signatures, comments inside function bodies, user labels and `/RevLens` types.
- IDA: idat scripts use `set_name`, `SetType`, `set_cmt`, extra comment lines, `set_func_cmt`,
  `parse_decls`, then save the database. A binary is copied to a temp folder; the database is written to
  `outDatabase`.
- radare2 and rizin: names go through `afn`, comments through base64 (`CCu base64:`), types and signatures
  through r2's quoted command form, labels into the `revlens` flag space, saved with `Ps`. Names r2 cannot
  hold (`<>~` and similar) are mapped to safe ones and listed. Export diffs the project against a fresh
  analysis, so only what was added comes back.

## CLI (`CLI_COMMANDS`)

```
revlens doctor [--json] [--verbose] [--refresh]
revlens setup <claude-code|codex|cursor|vscode|windsurf> [--scope user|project] [--write] [--json]
revlens bridge list
revlens bridge <tool> [file] [--key value ...] [--json]
```

Examples:

```
revlens bridge r2_functions app.elf --filter check
revlens bridge ghidra_decompile app.elf --functions check_password,0x100828
revlens bridge jadx_search app.apk --query api.example
revlens bridge gdb_run app.elf a --breakpoints add_numbers --registers x0,x1 --allow-execution
revlens bridge adb_dumpsys_package --package com.example.app
revlens bridge adb_start_activity --component com.example.app/.MainActivity --allow-execution
revlens bridge ghidra_apply_names app.elf --names-path names.json
revlens bridge r2_export_names app.elf --out-path names.json
revlens setup codex            # shows the new config.toml, writes nothing
revlens setup codex --write    # writes it, after copying the old file to config.toml.revlens-backup-<time>
```

Setup writes `npx -y @revlens/mcp` (`cmd /c npx -y @revlens/mcp` on Windows) into:
Claude Code `~/.claude.json` or `./.mcp.json`; Codex `~/.codex/config.toml` (`$CODEX_HOME`); Cursor
`~/.cursor/mcp.json` or `./.cursor/mcp.json`; VS Code user `Code/User/mcp.json` or `./.vscode/mcp.json`;
Windsurf `~/.codeium/windsurf/mcp_config.json`. It keeps other servers and settings, accepts JSON with
comments, refuses to touch a file it cannot parse, and replaces only `[mcp_servers.revlens]` in TOML.

## Safety

- `child_process.spawn` with `shell: false` and argument arrays only. On Windows, `.bat` launchers (jadx,
  analyzeHeadless) go through `cmd.exe /d /s /c` with every argument quoted, and arguments with cmd
  metacharacters are refused.
- Default timeout 60 s (Ghidra 15 min), process group killed on timeout, 8 MiB default output cap per stream.
- radare2 runs with `cfg.sandbox=true` and `-N`. Function names, breakpoints, registers, class and type
  names are checked against strict patterns before they reach a tool's command language.
- Dynamic operations need `allowExecution: true`. Run them on trusted targets or inside a VM or container.
- adb actions that change the device (install, uninstall, push, start, stop, input, forward and reverse
  changes) also need `allowExecution: true`. `adb shell` joins its arguments into one device shell line, so
  every value is checked against a strict pattern and single quoted; tests run the quoting through a real
  POSIX shell with random strings.
- For tools that need one program, the program is looked up before the input is checked, so a missing
  program always answers `{ available: false, install }`.
- Parsers use bounded, linear regexes and caps on lines, items and depth. Tests feed them 200k character
  pathological lines and random input.
- `REVLENS_BRIDGES_DISABLE=all` (or a list of tool ids) hides tools, for locked down hosts.

Ghidra projects and jadx and apktool output are cached under `$REVLENS_CACHE_DIR` (default
`<tmp>/revlens-cache`), keyed by the input's SHA-256.

## Verified against

Integration tests run the real tools on fixtures in `samples/bridges` (see SOURCES.md) and skip with a
reason when a tool is missing. Verified on Linux arm64:

- radare2 6.2.6 with r2ghidra: `add_numbers` at 0x828, size 32; `check_password` called from `main` at 0x98c;
  r2ghidra C for `check_password` calls `strlen` and `strcmp`.
- GNU objdump 2.44 and llvm-objdump 19.1.7 agree with radare2 on every address and instruction word of
  `add_numbers`.
- Ghidra 12.2 headless (JDK 25, native arm64 decompiler built from source): image base 0x100000, so
  `add_numbers` is 0x100828 and `check_password` 0x100848; decompiles both (`return param_1 + param_2;`,
  `strcmp(param_1,SECRET)`).
- jadx 1.5.6: `dev.revlens.fixture.Hello` from the DEX and the JAR; search finds the API host string.
- ilspycmd 9.1: `RevLens.Samples.Greeter` with `AddNumbers` and the secret constant.
- binwalk 2.4.3: gzip at 0x100, zip at 0x400, PNG at 0x800 in the firmware sample.
- gdb 16.3 and lldb 19.1.7 on the static build: at `add_numbers`, x0 = 2 and x1 = 41, backtrace into `main`,
  exit code 1.
- frida-tools 17.26.2: `frida-ps` lists a child process; attach with `module-list`; tracing `getpid`
  returns the attached pid.
- adb parsers on real device captures (see SOURCES.md): `dumpsys package` from an API 35 emulator
  (versionCode 338, targetSdk 35, 25 requested, 16 install and 5 runtime permissions, launcher
  `.ui.MainActivity`) and an older device; `getprop` from an Android TV emulator (252 properties, sdk 28)
  and a Mi TV; `settings list global`; `pm list packages -f`; `pm path`; `resolve-activity --brief`;
  `ps -A` from a Galaxy A30s (438 processes, system_server pid 4358 under zygote64 3901); `wm size`;
  `am start -W` (COLD, 1542 ms); install, push and pull summaries. The real adb 1.0.41 is exercised with no
  device attached (clean errors, `forward --list`).
- Sessions: radare2 6.2.6 keeps a rename across calls and its addresses match the one shot run (0x828,
  0x848, 0x8c8); gdb 16.3 over MI stops at `check_password`, prints `total=43`, exits with code 1 and is
  interrupted on timeout after attaching to a pid; lldb 19.1.7 waits for the breakpoint stop and sees
  `access granted` with the right password; Frida 17.26.2 round trips a post and send (21 becomes 42),
  streams `module-list` events, and the target survives detach. A session left open by a process that exits
  is gone after the exit.
- Write-back: radare2 projects checked with independent r2 queries (afn, afs, CC, ts, flags) and exported
  back; Ghidra 12.2 applies 2 names, 1 signature, 3 comments, 1 label and 1 type, `main` then decompiles to
  `sum_two(param_1,0x29)` and `verify_secret(...)`, and the Ghidra export (0x100848) maps back onto radare2
  0x848. The IDA scripts run under python3 against stub IDA modules that record each API call.
- Cutter: detection against the install layouts of the official v2.5.0 release (AppImage name, the real
  Windows zip top level listing including the bundled rizin.exe, app bundle Info.plist, Flatpak AppStream).

## Limits

- Frida spawn needs ptrace and a working injector. It fails in gVisor style sandboxes; attach still works.
  The tool returns a hint in that case.
- Dynamically linked binaries can trap in the dynamic loader under gVisor ptrace; the tests use static builds.
- apktool, rizin, IDA, Binary Ninja, Cutter and Hopper are not installed in the test sandbox, so their bridges
  are covered by unit and missing-tool tests only. The IDA write-back and export scripts are checked against
  stub modules, not a real IDA. rizin projects use `Ps <file>.rzdb` and `Po`, untested here.
- No Android device or emulator was available, so device side ADB tools are verified through their parsers on
  real captures and through the no-device path of the real adb; screenshot, screenrecord, bugreport and
  backup flows are not exercised end to end.
- radare2 debug sessions are not offered (r2 `-d` breakpoints did not fire under gVisor); use gdb or lldb
  sessions. rea's rizin debug sessions map to those.
- gdb on Windows does not get the separate program output file (no `inferior-tty`), so the program shares
  gdb's console there.
- Cutter's GUI is not driven (no Cutter plugin bridge, no Cutter session list); RevLens drives rizin and writes
  rizin projects Cutter can open.
- Ghidra's first run on a file does the full auto analysis and takes about a minute and a half for a small
  ELF; later runs reuse the cached project.
- binwalk scanning only. Extraction is not exposed because it writes many files from hostile input.
