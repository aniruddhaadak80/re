# @revlens/extras

Format readers and agent tools that round out RevLens, in pure TypeScript (one runtime dependency: `yaml`, ISC, for OpenAPI YAML documents). Everything runs in Node and in a browser Web Worker; only file paths and ledger files need the Node entry.

What it covers:

- Demangling: Itanium C++, Rust legacy and v0, MSVC. One `demangle()` picks the scheme.
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
- Windows offline artifacts: registry hives (regf), Prefetch files including Windows 10+ compressed ones (LZXPRESS Huffman), Jump Lists (automatic and custom) and OLE compound files.
- Apple archives: NSKeyedArchiver plists (binary and XML), compiled nibs (NIBArchive and keyed), Assets.car asset catalogs.
- App containers: WeChat mini program packages (wxapkg, with PC client decryption), Unity asset bundles (UnityFS with LZ4 blocks), JavaScript single-file executables (Node SEA, Bun, Deno).
- API contracts inside binaries and bundles: protobuf descriptors rebuilt as `.proto`, OpenAPI and Swagger documents, GraphQL schemas, introspection results and operations.
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

## Agent tools (`TOOLS`)

Every tool takes `path` (or base64 `bytes`), returns JSON with file offsets and addresses, and pages long lists with `offset` and `limit`.

| tool | what it does |
|---|---|
| x_demangle | Demangle names, or a binary symbol table with a filter |
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
| x_registry_hive | Registry hive header, a key with subkeys and decoded values, or a paged recursive key list |
| x_prefetch | Prefetch executable, hash, run count, last run times, loaded files and volumes, XP to 11 |
| x_jump_list | Jump List DestList entries with embedded shell links, or custom destination links |
| x_ole_compound | OLE compound file directory, or the hex of one stream |
| x_keyed_archive | NSKeyedArchiver archive resolved to plain JSON with class names |
| x_nib | Compiled nib: classes, strings, outlets and actions, custom classes, raw objects |
| x_asset_catalog | Assets.car header, facets, appearances and renditions |
| x_wxapkg | wxapkg member table, app config, pages; decrypts PC packages with the AppID; reads one member |
| x_unity_bundle | UnityFS header, blocks, nodes and serialized file objects by class |
| x_standalone_js | Node SEA, Bun and Deno single-file executables: entry, modules, assets; reads one embedded file |
| x_api_contracts | Protobuf descriptors (with rebuilt `.proto`), OpenAPI / Swagger documents with operations, GraphQL SDL, introspection and operations, each with its offset |

Ledger tools use an in-memory session ledger unless `ledgerPath` is given.

## CLI commands (`CLI_COMMANDS`)

`x-demangle`, `x-container`, `x-read-bytes`, `x-search-bytes`, `x-address-map`, `x-checksec`, `x-go`, `x-rust`, `x-pe`, `x-pe-resources`, `x-authenticode`, `x-elf`, `x-unwind`, `x-kmod`, `x-macho`, `x-firmware`, `x-firmware-parse`, `x-v8`, `x-gpu`, `x-model`, `x-lnk`, `x-ips`, `x-claim`, `x-unknown`, `x-verify`, `x-ledger`, `x-ledger-export`, `x-eval-tasks`, `x-eval-score`, `x-registry`, `x-prefetch`, `x-jumplist`, `x-ole`, `x-keyed-archive`, `x-nib`, `x-assets-car`, `x-wxapkg`, `x-unity`, `x-standalone-js`, `x-api-contracts`.

The first bare argument is the file, `--name value` sets a tool input, `--json` prints JSON, and object inputs can come from a file with `@`:

```sh
revlens x-authenticode setup.exe
revlens x-claim sample.bin --statement "C2 host in .rdata" --ranges '[{"offset":4096,"length":24}]' --ledgerPath case.json
revlens x-verify --ledgerPath case.json
revlens x-eval-score --answers @answers.json --json
revlens x-api-contracts service-binary --kind protobuf --proto
revlens x-registry NTUSER.DAT --key 'Software\Microsoft\Windows\CurrentVersion\Run'
```

## How it was verified

Fixtures live in `samples/extras` (see `SOURCES.md`), built with Zig 0.17.1, LLVM 19 tools, Go 1.23.4 and Node 22, or taken from PyPI and MIT licensed repositories. `scripts/gen_reference.py` ran independent tools on them and stored their answers in `samples/extras/reference.json`; the tests compare against those values.

| area | reference |
|---|---|
| Itanium demangling | GNU c++filt 2.44: all sampled symbols of a libc++ static binary identical; llvm-cxxfilt 19: identical apart from documented spelling differences |
| MSVC demangling | llvm-undname 19 on every symbol of a COFF object |
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
| Registry, Prefetch, Jump Lists | regipy 6.5.0 (key and value totals, decoded values), windowsprefetch 4.0.3 (XP, Vista, 7, 8, 10 files), dissect.util (LZXPRESS Huffman output byte identical), olefile 0.47 and LnkParse3 1.6.0 (DestList and embedded links) |
| NSKeyedArchiver, nibs, Assets.car | swift-corelibs-foundation archives decoded by NSKeyedUnArchiver 1.5.2 and plistlib, Sparkle nibs from ibtool read by nibarchive 1.1.0, Maccy Assets.car against its asset catalog source and the CARHEADER rendition count |
| wxapkg, UnityFS, single-file JS | KillWxapkg v2.4.1 (pack, extract, PC decryption), UnityPy 1.10.18 (Unity 5.5 bundle and an LZ4 repack), node 22 SEA blob, bun build 1.4.4 and deno compile 2.9.8 output against their sources |
| Protobuf | a Go 1.23 binary with protoc-gen-go v1.36.5 code holds exactly the bytes of `protoc --descriptor_set_out`; Python `_pb2.py` and `.pyc` decode to the same descriptor; the rebuilt `.proto` recompiles with protoc 29.3 to an identical descriptor set |
| OpenAPI | the YAML embedded in the Go binary equals PyYAML's load of the source; the petstore JSON esbuild inlined as a JS literal equals the original JSON |
| GraphQL | SDL from the Go binary and introspection from the bundle give the same types, fields and arguments as graphql-js 16 `buildSchema`; every extracted operation parses with graphql-js |

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
- Swift demangling is not implemented; Swift names are detected only.
- API contracts: AsyncAPI is not recognised; protobuf descriptors are found in raw, gzip, Python literal and protobuf-es base64 form (protobufjs JSON descriptors and Java lite descriptors are not); YAML documents must start at an `openapi:` or `swagger:` key or be preceded only by top level YAML lines; offsets are character offsets when a bundle is decoded as UTF-8 and byte offsets otherwise.
- LZMA blocks in UnityFS bundles are listed but not decoded.
- Squashfs file listing needs gzip compression (the runtime DecompressionStream); xz, lzo, lz4 and zstd images report superblock facts only.
- Authenticode checks do not build a chain to a trusted root and do not check revocation.
- Byte reads are capped at 64 KiB, searches at 1000 hits per call, ledger evidence ranges at 16 MiB.

See `GAP-MATRIX.md` for how this package and the rest of RevLens compare with rea.
