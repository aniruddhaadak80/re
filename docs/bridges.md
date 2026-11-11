---
title: Bridges, doctor and setup
description: Use Ghidra, radare2, rizin, jadx, apktool, ILSpy, Frida, gdb, lldb, objdump, binwalk, adb, IDA and Binary Ninja from RevLens when they are installed, see what is missing with doctor, and register the MCP server with setup.
order: 25
---

# Bridges, doctor and setup

RevLens works with nothing installed. `@revlens/bridges` is the other half: when you already have the classic tools, RevLens drives them and turns their output into JSON with addresses an agent can cite. When a tool is missing, you get install commands instead of an error.

## doctor

```
npx revlens doctor
npx revlens doctor --json --verbose
```

Doctor finds each tool on PATH, in the usual install folders for Linux, macOS and Windows, and through environment variables (`GHIDRA_INSTALL_DIR`, `JADX_HOME`, `IDADIR`, `BN_INSTALL_DIR`, `JAVA_HOME`, `ANDROID_HOME`, or `REVLENS_<TOOL>_PATH`). It reads versions and notices partial installs, for example Ghidra with a JDK that is too old or radare2 without r2ghidra. For each missing tool it prints the install command for your system (brew, apt, winget, scoop, choco, pipx, dotnet tool or a download link).

## setup

```
npx revlens setup claude-code          # shows the change, writes nothing
npx revlens setup claude-code --write  # writes it, after a backup
npx revlens setup codex --write
npx revlens setup cursor --scope project --write
```

Clients: `claude-code`, `codex`, `cursor`, `vscode`, `windsurf`. Setup keeps your other servers and settings, accepts JSON with comments, refuses to touch a file it cannot parse, and backs up the old file before writing. The same thing is available to agents as the `bridge_setup_mcp` tool, which is a dry run unless `write: true`.

## Bridged tools

| Area | Tools | MCP tools |
| --- | --- | --- |
| Native code | radare2 or rizin, Ghidra headless, objdump, llvm-objdump, IDA (batch), Binary Ninja (headless) | `bridge_r2_*`, `bridge_ghidra_functions`, `bridge_ghidra_decompile`, `bridge_objdump`, `bridge_ida_run`, `bridge_binja_functions` |
| Android | jadx, apktool, adb | `bridge_jadx_decompile`, `bridge_jadx_search`, `bridge_apktool_decode`, `bridge_adb_*` |
| .NET | ILSpy (ilspycmd) | `bridge_ilspy_decompile` |
| Dynamic | Frida, gdb, lldb | `bridge_frida_ps`, `bridge_frida_devices`, `bridge_frida_run`, `bridge_frida_templates`, `bridge_gdb_run` |
| Firmware | binwalk (scan only) | `bridge_binwalk` |

From the CLI, run one bridge with `revlens bridge <tool> [file] [--key value ...]`, for example:

```
revlens bridge r2_functions app.elf --filter check
revlens bridge ghidra_decompile app.elf --functions check_password
revlens bridge jadx_search app.apk --query api.example
```

## Safety

- Programs start with argument arrays and never through a shell. Timeouts kill the whole process group. Output is capped.
- radare2 runs in its sandbox mode. Names, breakpoints and registers are checked against strict patterns before they reach a tool.
- Anything that runs the target (Frida, gdb, lldb) needs `allowExecution: true` and prints a warning first. Without it, nothing runs. Use these only on files you trust or inside a VM.
- `REVLENS_BRIDGES_DISABLE=all` hides every bridge on locked down hosts.

Ghidra projects and jadx output are cached by file hash under `$REVLENS_CACHE_DIR`.

## How it was checked

The [bridges integration workflow](https://github.com/aniruddhaadak80/re/actions/workflows/bridges-integration.yml) installs radare2, Ghidra, jadx, ILSpy, gdb, lldb, llvm and binwalk on Ubuntu and runs the integration tests against real fixtures. Each test checks exact addresses (for example `add_numbers` at 0x828 and Ghidra's image base 0x100000). Tests skip with a reason when a tool is missing.

## Sessions and write-back

radare2, rizin, gdb, lldb and Frida can also stay open between calls, and names, signatures, comments, labels and types can be written back into Ghidra, IDA and radare2 projects. See [sessions and write-back](sessions-and-write-back.md).
