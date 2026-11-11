# @revlens/extras

Format readers and agent tools that round out RevLens, in pure TypeScript. Everything runs in Node and in a browser Web Worker; only file paths and ledger files need the Node entry.

What it covers:

- Demangling: Itanium C++, Rust legacy and v0, MSVC, and Swift (old Swift 1 to 3 `_T` mangling and the new `_T0`, `$S`, `$s` and `@__swiftmacro_` mangling, ported from swift-demangle 6.0.3). One `demangle()` picks the scheme.
- Executables: one container model for ELF, PE and Mach-O (fat slices too), raw byte reads, wildcard byte search, address to offset mapping, checksec style hardening checks.
- PE in depth: headers and checksum, rich header, resources, version info, manifest, string tables, debug and PDB path, TLS callbacks, load config, exports, delay imports, overlay, installer and packer detection, Authenticode (digest recomputed and compared, signer signature verified with WebCrypto).
- ELF: notes (build-id, ABI tag, GNU properties), dynamic section, init and fini arrays resolved through relocations, unwind ranges from `.eh_frame_hdr` and `.eh_frame`, kernel modules and IKCONFIG.
- Mach-O: load commands, dylibs with `@rpath` expansion, code signature with cdhash, page hash checks, entitlements and CMS signer.
- Go: function names, files and packages from pclntab, also on stripped binaries.
- Rust: rustc version and commit, crates and versions, symbol schemes.
- Firmware: binwalk style scan with header validation, uImage, device tree and FIT, Intel HEX and SREC, UF2, DfuSe, ESP32 images, Android boot images, squashfs listing, cpio, UEFI firmware volumes, TRX.
- JavaScript engines: V8 code cache and bytenode `.jsc`, V8 startup snapshots, Hermes bytecode headers.
- GPU: CUDA fatbin and cubin, PTX, AMD HSA code objects, SPIR-V, clang offload bundles.
- Model files: GGUF, safetensors, NumPy `.npy`.
- Windows shortcuts (`.lnk`) and Apple `.ips` crash reports.
- An evidence and claims ledger: claims bound to byte ranges by SHA-256, open unknowns, re-verification, a hash chained export.
- An agent eval harness: 31 tasks on the fixtures in `samples/extras` with ground truth from independent tools, and a scorer.

## API

```ts
import { analyze } from '@revlens/core';
import { ANALYZERS, TOOLS, CLI_COMMANDS, demangle, peAuthenticode, scanFirmware, Ledger } from '@revlens/extras';
import '@revlens/extras/node'; // Node only: lets tools read `path` inputs and persist `ledgerPath`
```

- `ANALYZERS`: `extrasNativeAnalyzer` (ELF, PE, Mach-O) and `extrasArtifactAnalyzer` (everything else). Output goes to `report.meta.extras`, with findings such as an Authenticode digest mismatch, a bad signer signature, get-task-allow or disabled library validation entitlements, a tampered rich header, a high entropy overlay, a shortcut that launches a script host, and embedded firmware images.
- Plain functions for every format, for example `parseGguf(bytes)`, `parseLnk(bytes)`, `elfUnwind(bytes)`, `goSymbols(bytes)`, `machoCodeSignature(bytes)`, `inspectGpu(bytes)`. They take a `Uint8Array`, check every read against bounds, and throw `ParseError` on malformed input.
- `Ledger`: `claim()`, `unknown()`, `update()`, `verify(resolver)`, `items()`, `summary()`, `export()`, `Ledger.import()`, `toMarkdown()`.
- `EVAL_TASKS`, `publicTasks()`, `scoreAnswers()`.
- Swift: `demangleSwift(sym, { simplified })` returns the text swift-demangle prints, or null; `swiftDemangleCompat(sym)` returns the input unchanged on failure like swift-demangle does; `demangleSwiftTree(sym)` returns the node tree. Mach-O names with an extra leading underscore (`_$s...`, `__T...`) are accepted by `demangle()` and the tools.

## Agent tools (`TOOLS`)

Every tool takes `path` (or base64 `bytes`), returns JSON with file offsets and addresses, and pages long lists with `offset` and `limit`.

| tool | what it does |
|---|---|
| x_demangle | Demangle C++, Rust, MSVC and Swift names, or a binary symbol table with a filter |
| x_swift_demangle | Swift names like swift-demangle, with `simplified` and an optional node `tree`; with a path, the Swift symbols of a symbol table with addresses |
| x_container | Sections and segments of ELF, PE or Mach-O, fat slices |
| x_read_bytes | Up to 64 KiB at a file offset or a virtual address |
| x_search_bytes | Hex pattern with `??` wildcards or text (ASCII and UTF-16LE), hits with address and section |
| x_address_map | Virtual address to file offset and back |
| x_checksec | Hardening checks with evidence and a score |
| x_go_symbols | Go functions, files and packages from pclntab |
| x_rust_info | Rust compiler and crates |
| x_pe_inspect | Deep PE view |
| x_pe_resources | Resources, version info, manifest, string tables, rich header, installers |
| x_pe_authenticode | Authenticode digest and signature verification |
| x_elf_inspect | Notes, dynamic section, initializers |
| x_elf_unwind | FDE code ranges |
| x_kernel_module | Kernel module facts or IKCONFIG |
| x_macho_inspect | Load commands, dylibs, code signature |
| x_firmware_scan | Embedded image scan |
| x_firmware_parse | One firmware structure by kind and offset |
| x_v8_inspect | V8 code cache, snapshot, Hermes header |
| x_gpu_inspect | CUDA, PTX, AMDGPU, SPIR-V |
| x_model_inspect | GGUF, safetensors, npy |
| x_lnk_inspect | Windows shortcut |
| x_apple_ips | Apple crash report |
| x_ledger_record | Record a claim with byte ranges and an optional structured check |
| x_ledger_unknown | Record an unknown, or resolve, reject or reopen an entry |
| x_ledger_verify | Re-read files and verify every claim |
| x_ledger_list | Claims and unknowns with status and history |
| x_ledger_export | Hash chained JSON or Markdown |
| x_ledger_import | Load an export after checking its chain |
| x_eval_tasks | Eval tasks without answers |
| x_eval_score | Score answers against ground truth |

Ledger tools use an in-memory session ledger unless `ledgerPath` is given.

## CLI commands (`CLI_COMMANDS`)

`x-demangle`, `x-swift-demangle`, `x-container`, `x-read-bytes`, `x-search-bytes`, `x-address-map`, `x-checksec`, `x-go`, `x-rust`, `x-pe`, `x-pe-resources`, `x-authenticode`, `x-elf`, `x-unwind`, `x-kmod`, `x-macho`, `x-firmware`, `x-firmware-parse`, `x-v8`, `x-gpu`, `x-model`, `x-lnk`, `x-ips`, `x-claim`, `x-unknown`, `x-verify`, `x-ledger`, `x-ledger-export`, `x-eval-tasks`, `x-eval-score`.

The first bare argument is the file, `--name value` sets a tool input, `--json` prints JSON, and object inputs can come from a file with `@`:

```sh
revlens x-authenticode setup.exe
revlens x-swift-demangle '$sSaySiGSgD' --simplified      # [Int]?
revlens x-claim sample.bin --statement "C2 host in .rdata" --ranges '[{"offset":4096,"length":24}]' --ledgerPath case.json
revlens x-verify --ledgerPath case.json
revlens x-eval-score --answers @answers.json --json
```

## How it was verified

Fixtures live in `samples/extras` (see `SOURCES.md`), built with Zig 0.17.1, LLVM 19 tools, Go 1.23.4 and Node 22, or taken from PyPI and MIT licensed repositories. `scripts/gen_reference.py` ran independent tools on them and stored their answers in `samples/extras/reference.json`; the tests compare against those values.

| area | reference |
|---|---|
| Itanium demangling | GNU c++filt 2.44: all sampled symbols of a libc++ static binary identical; llvm-cxxfilt 19: identical apart from documented spelling differences |
| MSVC demangling | llvm-undname 19 on every symbol of a COFF object |
| Swift demangling | swift-demangle from the Swift 6.0.3 toolchain, each name passed as an argument: 470 of 470 names from swift's own test/Demangle/Inputs/manglings.txt (247 old mangling, 223 new) and 1947 of 1947 Swift symbols of the Maccy 2.8.0 Mach-O, identical for both `-compact` and `-compact -simplified` output. The test fails if any count drops. |
| Rust demangling | rust-demangler (legacy, 400+ symbols from jiter), llvm-cxxfilt on the rustc-demangle v0 test vectors |
| ELF | pyelftools (entry, DT_NEEDED, BIND_NOW, init_array, every FDE), readelf 2.44 (notes, FDE count on a stripped aarch64 binary) |
| PE | pefile (version info, resources with offsets, checksum, exports, imports), lief (authentihash, Microsoft signed strings64.exe signature, signer serial) |
| Mach-O | lief plus SHA-256 of the CodeDirectory blob (cdhash), dylibs, code signature location |
| Go | `go tool nm` on the unstripped build: main.main and 40 sampled functions at the same addresses in the stripped build |
| Rust | readelf `.comment` and registry paths in two PyPI wheels |
| Firmware | binwalk 2.4.3 offsets, the uboot package (uImage CRCs), fdt (device tree), intelhex, unsquashfs 4.6.1 (squashfs listing), GNU cpio 2.15 (cpio listing) |
| V8 | the cache was made by Node 22 `vm.Script` and accepted back by V8 |
| GPU | llvm-readobj (AMDGPU target, code object version, xnack, sramecc, kernels), PTX text from LLVM, SPIR-V from glslang with the GLSL sources |
| Models | gguf-py GGUFReader, safetensors safe_open, numpy |
| LNK | pylnk3 |
| Apple .ips | Python `json` on a real macOS 12 report |
| Eval | an oracle agent that only calls `TOOLS` scores 1.0 on all 31 tasks |

Hostile input tests feed random bytes, truncations, byte flipped real files, huge declared counts and deeply nested symbols to every parser with fast-check.

Run the tests:

```sh
npx tsc -p packages/core
node packages/extras/scripts/fetch-fixtures.mjs   # optional: signed PE and a real .ips, tests skip without them
node --test --import tsx packages/extras/test/*.test.ts
```

## Limits

- CUDA fatbin and cubin readers follow the documented layout but were not checked against nvcc output (no CUDA toolchain was available). Compressed fatbin entries are listed, not decompressed.
- Hermes support is the file header only and was not checked against a real hermesc file. No Hermes or V8 bytecode disassembly.
- Swift demangling follows Swift 6.0.3. Newer manglings (for example the embedded `$e` prefix from Swift 6.1) are not recognized. Only the default and simplified print options are tested. Symbols over 16 KiB, demangler nesting over 1024 levels, or printed output over 1 MiB return null; the printer stops at 768 levels like swift-demangle.
- Squashfs file listing needs gzip compression (the runtime DecompressionStream); xz, lzo, lz4 and zstd images report superblock facts only.
- Authenticode checks do not build a chain to a trusted root and do not check revocation.
- Byte reads are capped at 64 KiB, searches at 1000 hits per call, ledger evidence ranges at 16 MiB.

## License

MIT, except the Swift demangler in `src/demangle/swift/`, which is ported from the Swift project (swift-6.0.3-RELEASE, Copyright (c) 2014 - 2024 Apple Inc. and the Swift project authors) and stays under the Apache License v2.0 with Runtime Library Exception. See `NOTICE` and `LICENSE-SWIFT.txt`.

See `GAP-MATRIX.md` for how this package and the rest of RevLens compare with rea.
