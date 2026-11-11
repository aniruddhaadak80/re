# @revlens/bridges

RevLens core is pure TypeScript and needs nothing installed. This package is the other half: it drives the
reverse engineering tools you already have, so RevLens (and any agent using it) can go deeper when they are
present and say exactly what to install when they are not.

Bridged tools: radare2, rizin, Ghidra headless, jadx, apktool, ILSpy (ilspycmd), Frida, gdb, lldb,
GNU objdump, llvm-objdump, binwalk, adb, IDA (idat batch mode) and Binary Ninja headless. Cutter and Hopper
are detected only.

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
| `bridge_ida_run` | IDA batch mode: functions, or Hex-Rays decompile when licensed |
| `bridge_binja_functions` | Functions through the Binary Ninja headless API |
| `bridge_setup_mcp` | Add RevLens to an agent client config, dry run unless `write: true` |

Bad input (a function name with `;`, a breakpoint with a newline, a path that does not exist) comes back as
`{ ok: false, inputError: true, error }`.

Frida hook templates: `module-list`, `trace-native-export`, `java-method-log`, `ssl-pinning-bypass` (for
apps you own or are authorized to test) and `electron-net-observe` (DNS lookups and TCP connects). Parameters
are embedded as JSON, never pasted as code.

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

## Limits

- Frida spawn needs ptrace and a working injector. It fails in gVisor style sandboxes; attach still works.
  The tool returns a hint in that case.
- Dynamically linked binaries can trap in the dynamic loader under gVisor ptrace; the tests use static builds.
- apktool, rizin, IDA, Binary Ninja, Cutter and Hopper are not installed in the test sandbox, so their bridges
  are covered by unit and missing-tool tests only.
- Ghidra's first run on a file does the full auto analysis and takes about a minute and a half for a small
  ELF; later runs reuse the cached project.
- binwalk scanning only. Extraction is not exposed because it writes many files from hostile input.
