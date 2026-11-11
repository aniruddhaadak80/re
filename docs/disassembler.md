---
title: Disassembler and pseudo code
description: Native code analysis for ELF, PE and Mach-O on x86, x86-64, AArch64, ARM and Thumb, with functions, control flow graphs, cross references and readable pseudo code, all without native installs.
order: 20
---

# Disassembler and pseudo code

`@revlens/disasm` reads native programs and libraries and shows you their code. It runs in Node, in the browser and in Web Workers. Nothing is installed and nothing is executed.

Try it in the browser on the [disassembler page](https://aniruddhaadak80.github.io/re/labs/disassembler): pick a sample, read `main` as pseudo code, switch to the graph or the listing.

## What it reads

| Container | Architectures | Symbols and imports |
| --- | --- | --- |
| ELF | x86, x86-64, AArch64, ARM, Thumb | `.symtab`, `.dynsym`, PLT and GOT through relocations |
| PE | x86, x86-64, ARM (Thumb-2) | exports, COFF symbols, IAT and delay load thunks, `.pdata` |
| Mach-O, fat Mach-O | x86-64, arm64 | `LC_SYMTAB`, `__stubs`, `__got`, `LC_FUNCTION_STARTS` |
| Go binaries in any of these | as above | function names from `pclntab`, even when stripped |

Decoders: iced-x86 (MIT) for x86 in Node and Capstone 5 compiled to WebAssembly (BSD-3-Clause) for ARM, AArch64 and for x86 in browsers.

## What you get

- **Functions** found from the entry point, symbols, exports, unwind tables, call targets and a prologue scan. For stripped Linux programs `main` is recovered from the `__libc_start_main` call.
- **Control flow graphs** per function with conditional, unconditional and fallthrough edges, tail calls and calls that never return.
- **Cross references**: who calls a function, who reads a string, which instructions use an import.
- **Call graph and call paths** from the entry point to any function.
- **Search** by byte pattern with wildcards (`48 8b ?? ??`), by instruction (`call *strcmp*`) or by text.
- **Pseudo code**: C like code with `if`, `else` and loops recovered, strings and call arguments inlined. It is for reading, not for compiling.
- **Findings** with call site evidence for process execution, process injection, dynamic loading and memory protection changes.

Program wide work (xrefs, call graph) runs within a time budget (`budgetMs`, default 8000). When the budget runs out you get what is ready and `complete: false`. The next call continues where it stopped.

## CLI

```
revlens disasm-info app.elf
revlens disasm-functions app.elf --filter check --sort size
revlens decompile app.elf main
revlens disasm app.elf check_password
revlens xrefs app.elf 0x1a2f0
revlens refs app.exe --import CreateProcessW
revlens disasm-search app.elf --insn "call *strcmp*"
revlens call-paths app.elf check_password
```

Every command takes `--json`.

## MCP tools

`disasm_info`, `disasm_list_functions`, `disasm_function`, `disasm_pseudocode`, `disasm_xrefs`, `disasm_callgraph`, `disasm_search`, `disasm_find_references`, `disasm_call_paths`, `disasm_at`. See the [MCP tools reference](mcp-tools.md) for parameters.

A good agent sequence is `disasm_list_functions`, then `disasm_pseudocode` on `main`, then `disasm_find_references` from an interesting string, then `verify_claim` on what you plan to say.

## When you need more

The built in pseudo code does not track types or the stack and does not resolve jump tables. When you need real decompiled C, install Ghidra or radare2 and use the [bridges](bridges.md): `bridge_ghidra_decompile` and `bridge_r2_decompile` work on the same addresses.

## Limits

- 20000 instructions per function, files up to 512 MB.
- No `switch` recovery, no types, SIMD shows as inline `__asm`.
- Big endian targets load but are not decoded.

## How it was checked

Ten small binaries built from one C file for every supported target, compared with capstone, pyelftools, pefile and macholib: entry points, every function address, the first instructions of `main`, every direct call, string references, PLT and IAT slots. Three real 10 MB Go binaries for pclntab names. Details are in the [package README](https://github.com/aniruddhaadak80/re/tree/main/packages/disasm).
