# ELF playbook

ELF is the native format on Linux, Android native libraries, most embedded Linux systems and the BSDs.
It starts with the bytes `7f 45 4c 46`.

## Recognise
- `analyze_file` reports `format: elf` with the machine (x86-64, AArch64, ARM, MIPS, RISC-V) and the bit width.
- A `.so` with `JNI_OnLoad` or `Java_` exports is an Android native library. Continue with the APK playbook for the Java side.
- A file with a `.go.buildinfo` section or `runtime.main` is Go. Call `x_go_symbols`.
- A file with `rust_begin_unwind` or `.rustc` is Rust. Call `x_rust_info` and `x_demangle`.

## First pass
1. `analyze_file` for hashes, hardening, imports, components and the top findings.
2. `x_checksec` for RELRO, stack canary, NX, PIE, FORTIFY and RUNPATH in one place.
3. `x_elf_inspect` for program headers, dynamic entries, notes, build id and interpreter.
4. `get_imports` with `contains` to look for network (`socket`, `connect`), process (`execve`, `fork`), crypto (`EVP_`, `AES_`) and anti debug (`ptrace`) symbols.
5. `get_strings` with `tag: url`, `tag: path` and `tag: command`.

## Code
1. `disasm_info` then `disasm_list_functions`. Stripped files still get functions from the entry point, call targets and `.eh_frame`.
2. `disasm_pseudocode` on `main` or the entry point. Follow `disasm_xrefs` from interesting strings and imports.
3. `disasm_call_paths` to show how execution gets from `main` to a sensitive call such as `execve`.
4. `disasm_trace_values` to recover the constant arguments passed to a call.
5. `x_elf_unwind` when you need exact function ranges from the unwind tables.

## Bridges that help
- radare2 or rizin: `bridge_r2_functions`, `bridge_r2_decompile` (r2ghidra), and long sessions with `bridge_r2_session_open`.
- Ghidra headless: `bridge_ghidra_decompile` for the best C output.
- Cutter: `list_cutter_sessions` finds an open Cutter window, `cutter_command` runs rizin commands on the same file.
- gdb: `bridge_gdb_session_open` for dynamic work, only with `allowExecution: true` and inside a sandbox.

## Verify
- Cite the virtual address and the file offset for every claim. `hexdump` shows the bytes.
- Use `verify_claim` with `imports-symbol`, `contains-string` or `bytes-at` before you report a behavior.
