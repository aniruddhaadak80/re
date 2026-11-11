---
title: Extras
description: C++, Rust, MSVC and Swift demangling, raw byte tools, checksec, Go and Rust facts, deep PE with Authenticode, ELF notes and unwind ranges, kernel modules, Mach-O code signatures, firmware containers, GPU code, V8 and Hermes headers, model files, Windows and Apple artifacts, app containers, API contracts, an evidence ledger and an eval harness.
order: 24.5
---

# Extras

`@revlens/extras` collects the many smaller readers that make a reverse engineering session go faster. All pure TypeScript, all usable in the browser.

| Area | Tools | What you get |
| --- | --- | --- |
| Names | `x_demangle`, `x_swift_demangle` | C++ (Itanium), MSVC, Rust (legacy and v0) and Swift demangling; see [Swift demangling](swift-demangling.md) |
| Raw bytes | `x_container`, `x_read_bytes`, `x_search_bytes`, `x_address_map` | container facts, bytes at an offset or virtual address, hex search with `??` wildcards, address to file offset |
| Hardening | `x_checksec` | checksec style hardening checks (RELRO, NX, PIE and more) for ELF, PE and Mach-O, each with evidence |
| Toolchains | `x_go_symbols`, `x_rust_info` | Go pclntab functions and files, Rust compiler and crate facts |
| PE | `x_pe_inspect`, `x_pe_resources`, `x_pe_authenticode` | rich header, resources, version info, manifest, TLS callbacks, overlay, installer and packer detection, Authenticode with the digest recomputed and the signer signature verified |
| ELF | `x_elf_inspect`, `x_elf_unwind`, `x_kernel_module` | notes (build id, ABI tag, GNU properties), init and fini arrays, `.eh_frame` unwind ranges, kernel modules and IKCONFIG |
| Mach-O | `x_macho_inspect` | load commands, `@rpath` expansion, code signature with cdhash and page hash checks, entitlements, CMS signer |
| Firmware | `x_firmware_scan`, `x_firmware_parse` | binwalk style scan with header checks, uImage, device trees and FIT, Intel HEX, SREC, UF2, DfuSe, ESP32, Android boot images, SquashFS, cpio, UEFI volumes, TRX |
| Runtimes and models | `x_v8_inspect`, `x_gpu_inspect`, `x_model_inspect` | V8 code cache, bytenode and snapshots, Hermes headers, CUDA fatbin and cubin, PTX, AMD code objects, SPIR-V, GGUF, safetensors and `.npy` |
| Windows and Apple | `x_lnk_inspect`, `x_apple_ips`, `x_registry_hive`, `x_prefetch`, `x_jump_list`, `x_ole_compound`, `x_keyed_archive`, `x_nib`, `x_asset_catalog` | shortcut targets, Apple crash reports mapped to images, registry hives, Prefetch, Jump Lists, OLE files, NSKeyedArchiver archives, nibs and Assets.car; see [Windows and Apple artifacts](windows-and-apple-artifacts.md) |
| App containers | `x_wxapkg`, `x_unity_bundle`, `x_standalone_js` | WeChat mini programs with PC decryption, UnityFS bundles, Node SEA, Bun and Deno single file executables |
| API contracts | `x_api_contracts` | protobuf descriptors rebuilt as `.proto`, OpenAPI and Swagger documents, GraphQL schemas and operations found inside binaries and bundles |
| Evidence | `x_ledger_*` | a claims and unknowns ledger with a digest chain, export and import that re-check every claim |
| Evaluation | `x_eval_tasks`, `x_eval_score` | 31 tasks with known answers on the repository fixtures, and scoring for agent runs |

CLI commands use the same names with dashes, for example `revlens x-checksec app.elf`, `revlens x-demangle _ZN3foo3barEv` and `revlens x-authenticode setup.exe`. See `revlens help extras` and the [package README](https://github.com/aniruddhaadak80/re/tree/main/packages/extras), which also lists what each reader was verified against and the full gap matrix against rea.
