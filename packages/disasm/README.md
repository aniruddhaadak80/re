# @revlens/disasm

Native code analysis for RevLens. It loads ELF, PE and Mach-O files (thin and fat), disassembles
x86, x86-64, AArch64, ARM and Thumb code, finds functions, builds basic blocks and control flow
graphs, cross references, a call graph, string and import references, and writes light,
readable pseudo code. Everything is TypeScript plus two WebAssembly decoders, so it runs in Node,
browsers and Web Workers with no native install.

## What it does

- Loading: maps sections and segments to virtual addresses. Reads ELF `.symtab` and `.dynsym`,
  PE exports and the COFF symbol table, Mach-O `LC_SYMTAB`, and the Go `pclntab` (Go 1.16 and
  later), which names every function in Go binaries even when they are stripped.
- Imports: ELF PLT entries and GOT slots from `JUMP_SLOT` and `GLOB_DAT` relocations, PE IAT
  slots (normal and delay load) and `jmp [IAT]` thunks, Mach-O `__stubs`, `__got` and
  `__la_symbol_ptr` through the indirect symbol table. Calls through any of these show the import
  name.
- Function discovery: entry point, symbols, exports, `.pdata`, `.eh_frame`, `.ARM.exidx`,
  `LC_FUNCTION_STARTS`, call targets, and a prologue scan in uncovered code. For stripped Linux
  binaries, `main` is recovered from the `__libc_start_main` call in `_start`.
- Per function, lazily: recursive descent CFG with conditional, unconditional and fallthrough
  edges, tail calls, no return calls (`exit`, `abort`, `__stack_chk_fail`, Go panics and more),
  data references (RIP relative, absolute, AArch64 `adrp` pairs, ARM literal pools and
  `movw/movt`, x86-32 PIC base registers), string references (C strings, Go style strings,
  UTF-16).
- Program wide, within a time budget and incrementally across calls: xref index, call graph,
  call paths, instruction search.
- Lifter: per function C like pseudo code. Recovers `if`, `if/else`, `do/while` and
  `while (true)` from the CFG, falls back to labels and `goto`, inlines string literals, symbol
  names and call arguments (SysV, Win64, AAPCS, cdecl stack arguments). Registers stand in for
  variables. It is meant for reading, not for recompiling.
- Summary per function: calls with counts, imports used, strings, constants, size, block and
  edge counts, cyclomatic complexity, loop count, leaf flag.

## Decoders

| Architecture | Engine | Package | License |
| --- | --- | --- | --- |
| x86, x86-64 | iced-x86 1.22 (Rust to WASM) | `iced-x86` | MIT |
| AArch64, ARM, Thumb-2 | Capstone 5 (C to WASM) | `@alexaltea/capstone-js` | BSD-3-Clause |
| x86, x86-64 in browsers | Capstone 5 | same | BSD-3-Clause |

The iced-x86 npm build reads its `.wasm` with `fs`, so in a browser or worker x86 falls back to
Capstone automatically. Capstone needs its `capstone.wasm`: pass the bytes as `capstoneWasm`
(or a `capstoneLocateFile` hook) when the bundler does not serve it next to `capstone.js`. When
bundling for the browser, mark `fs` and `node:fs` as empty or external (Vite does this by
default).

## API

```ts
import { disasmListFunctions, disasmPseudocode, Program } from '@revlens/disasm';
import '@revlens/disasm/node'; // only needed for `path` inputs outside Node's default reader

const fns = await disasmListFunctions({ path: 'a.out', filter: 'main' });
const pc = await disasmPseudocode({ path: 'a.out', function: 'main' });

const p = await Program.open(bytes, { arch: 'arm64' }); // low level
const af = p.analyze(p.img.entry!);
```

Exports:

- `disasmAnalyzer` (and `ANALYZERS`): an `Analyzer` for `@revlens/core`. Applies to `elf`, `pe`,
  `macho` and `macho-fat`. Writes `report.meta.disasm` (arch, decoder, function counts,
  summaries of entry and main, largest functions) and adds findings with call site evidence for
  process execution (T1059), process injection (T1055), dynamic loading (T1129) and memory
  protection changes.
- Tool functions (all take `path` or `bytes`, optional `arch` for fat files, return JSON with hex
  addresses and file offsets): `disasmInfo`, `disasmListFunctions`, `disasmFunction`,
  `disasmPseudocode`, `disasmXrefs`, `disasmCallgraph`, `disasmSearch`, `disasmFindReferences`,
  `disasmCallPaths`, `disasmAt`.
- `TOOLS`, `CLI_COMMANDS`, `Program`, `loadImage`, `loadDecoders`, `liftFunction`,
  `summarizeFunction`, `openProgram`, `clearSessions`, `setFileReader`, and the types.
- `@revlens/disasm/node`: the same exports, with `path` inputs read through `node:fs`.

Sessions are cached per file (8 most recent), so a sequence of tool calls on one binary reuses
the loaded image, the analyzed functions and the partially built xref index.

## Tools

| Name | What it returns |
| --- | --- |
| `disasm_info` | format, arch, entry, sections, symbol, import and function counts, decoder |
| `disasm_list_functions` | functions with address, size, source; `filter`, `sort`, `offset`, `limit` |
| `disasm_function` | disassembly with blocks, edges, exits, calls, annotations; instruction paging |
| `disasm_pseudocode` | pseudo code plus the function summary |
| `disasm_xrefs` | references to an address, function, symbol or import, or from a function |
| `disasm_callgraph` | callees, callers or both around a function, or functions ranked by callers |
| `disasm_search` | byte pattern with `??`, instruction glob such as `call *strcmp*`, or literal text |
| `disasm_find_references` | functions and instruction addresses that use a string or an import |
| `disasm_call_paths` | call paths from the entry point (or `from`) to a target, plus its callers |
| `disasm_at` | N instructions at any address, annotated |
| `disasm_trace_values` | value flow: what reaches each argument of a call (backward), or where a string, constant or parameter goes (forward) |
| `disasm_indirect_targets` | indirect calls and jumps with resolved targets: jump tables, code pointer tables, constants, vtable slots |
| `disasm_match_functions` | map functions between two binaries (versions, stripped vs unstripped) with confidence and method |
| `disasm_compare_functions` | side by side diff of two functions with addresses normalized |

Program wide tools take `budgetMs` (default 8000). When the budget runs out they answer with what
they have and `complete: false`; the next call continues the index where it stopped.

## Value flow, indirect targets and function matching

- Jump tables and code pointer tables: the resolver walks back from an indirect jump through its
  single predecessor chain, finds the bounds check and the table load, and reads the table from
  read only memory. It handles x86-64 relative (PIE) and absolute tables, AArch64
  `adr`/`ldrb`/`ldrh`/`add` tables, Thumb `tbb`/`tbh`, Go jump tables and ELF `RELATIVE`
  relocations. Tables are capped at 1024 entries and the walk at 64 instructions.
- Value tracker: a per function constant and value propagation over the CFG with stack slots,
  incoming parameters, call return values and loads. It feeds `disasm_trace_values`, resolves
  indirect calls through constants and the initial values of writable function pointers, and
  finds Itanium C++ vtable slots, even in stripped files where vtables are found by their shape.
- Pseudo code now shows `switch` with case labels, `for` and `break`, stack variables and
  parameters.
- Matching: each function gets a fingerprint (normalized instructions, CFG shape, strings,
  imports, constants, callees). `disasm_match_functions` matches equal names (optional), then
  identical code, then strings, imports and constants, then call graph and address order
  neighbors, then similarity, and never maps one function twice. `disasm_compare_functions`
  diffs two functions with addresses and branch targets normalized, so relocation alone is not a
  change.

```sh
revlens disasm trace-values ./a.out main --call printf
revlens disasm trace-values ./a.out --value "password:" --depth 2
revlens disasm indirect ./a.out --unresolved
revlens disasm match-functions ./v1.elf ./v2.elf --min-confidence 0.8
revlens disasm compare-functions ./v1.elf parse_header ./v2.elf
```

## CLI commands

`disasm-info`, `disasm-functions`, `disasm`, `disasm-at`, `decompile`, `xrefs`, `callgraph`,
`disasm-search`, `refs`, `call-paths`, `trace-values`, `indirect`, `match-functions`,
`compare-functions`. Each prints text by default and JSON with `--json`, for example
`revlens disasm decompile ./a.out main` or `revlens disasm refs app.exe --import CreateProcessW`.

## Limits

- Per function: 20000 instructions (`maxFunctionInsns`). Analyzed functions kept in memory are
  capped by instruction count (`cacheInsns`, default 250000), oldest first out.
- Discovery: 4 s budget for following calls and the prologue scan (`discoveryMs`). Go binaries
  skip call following because the pclntab already lists every function.
- Files up to 512 MB. Section, symbol, relocation, import and load command counts are capped.
- Jump tables are resolved only when the bounds check and table load are on a single
  predecessor chain; other indirect jumps end their block and are listed as unresolved.
- The value tracker works inside one function at a time and follows callers or callees only up to
  depth 3. It does not model memory beyond stack slots and read only data.
- Matching is tuned for builds of the same source; heavily inlined or differently optimized
  builds match fewer functions. The default budget is 60 s per call.
- The lifter does not recover types and shows SIMD as inline `__asm`.
- ARM PE files are assumed to be Thumb-2. Big endian targets load but are not decoded.
- ELF files without section headers load, but their imports are not resolved.

## Verified against

Tests run with `node --test --import tsx packages/disasm/test/*.test.ts`.

- Ten small binaries in `samples/disasm` built from one C file with zig cc for x86-64, x86,
  AArch64, ARM and Thumb Linux, x86-64 Windows, x86-64 and arm64 macOS, and a fat Mach-O. Expected
  values come from capstone 5, pyelftools, pefile and macholib (`samples/disasm/reference.json`):
  entry points, every function address, the first 16 instructions of `main` (exact text for ARM
  targets, mnemonic and size for x86), every direct call in `main`, string addresses referenced by
  `check_password`, ELF PLT relocation slots, PE IAT slots and DLL names, the PE `.pdata` table,
  the instruction that references a string in the stripped PE (from a capstone sweep), and Mach-O
  stub ranges.
- The browser path (Capstone for x86) produces the same blocks, calls and strings as iced-x86.
- Three 10 MB Go binaries (esbuild 0.24.0 for linux-x64, win32-x64, darwin-arm64), fetched by
  `scripts/fetch-fixtures.mjs`: the pclntab name at the header entry point is the Go runtime
  entry stub (`_rt0_amd64_linux` and so on), `main.main` starts with Go's stack bound check, and
  listing, pseudo code and budgeted reference search stay within time limits.
- Hostile input: truncation at many offsets, fast-check random tails behind real headers, random
  header byte flips, maxed section, symbol and load command counts, and random raw code for each
  architecture.
- Jump tables and indirect calls: `samples/disasm/switch*.elf`, `virt*.elf` and the Lua 5.4.7
  builds, checked against pyelftools (`samples/disasm/gaps-reference.json`): the
  `luaV_execute.disptab` computed goto table with its 83 entries, `char_class` with bias 0x61 on
  x86-64, vtables found by shape in the stripped `virt` build, and Go `runtime.reflectcall`
  dispatching to `runtime.call16` up to `runtime.call1073741824`.
- Matching: the stripped and file order reversed Lua build against the unstripped one, with at
  least 95 percent of functions matched and at least 95 percent of matches correct against the
  symbols; esbuild 0.23.1 against 0.24.0.
- Hostile input for the new passes: fast-check writes random bytes over jump tables, code and
  headers, then checks that the resolver, the value tracker and the matcher stay within their caps
  and give well formed answers (`test/hostile-gaps.test.ts`).
