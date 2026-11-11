# RevLens tool map

Generated from the server by scripts/gen-tool-docs.mjs. 117 tools.

## Core triage and evidence

- `analyze_file` (reads only): Triage any local file (ELF, PE, Mach-O, WASM, JS bundle, source map, npm tgz, ZIP/JAR/APK, CRX/XPI/VSIX, ASAR). Returns format, hashes, hardening, components, capabilities and top findings with offsets.
- `list_findings` (reads only): All findings for a file, optionally filtered by minimum severity or analyzer id.
- `get_strings` (reads only): Interesting strings with offsets. Filter by tag (url, ip, email, path, registry, command, guid, version) or a substring.
- `get_sections` (reads only): Sections or segments with file offsets, virtual addresses, sizes and entropy.
- `get_imports` (reads only): Imported libraries and symbols, plus exports. Optional substring filter.
- `sbom` (reads only): Software bill of materials. format "list" is compact, "cyclonedx" is a CycloneDX 1.5 document.
- `check_vulns` (reads only, network): Look up known vulnerabilities (CVE, GHSA) for detected components on OSV.dev. This makes a network request.
- `scan_rules` (reads only): Run yara-lite rules (a YARA subset) against a file. The starter pack runs unless includeStarter is false.
- `diff_files` (reads only): Compare two versions of a file or package: dependencies, endpoints, imports, exports, capabilities, sections and findings.
- `verify_claim` (reads only): Check claims about a file against its bytes before you rely on them. Returns VERIFIED, REFUTED or UNKNOWN with evidence for each claim.
- `hexdump` (reads only): Hex and ASCII view of a byte range, to inspect evidence offsets.
- `report_markdown` (reads only): The full report as Markdown, good for writing up results.
- `list_analyzers` (reads only): What RevLens can analyze, one line per analyzer, across core and every package.

## Native code (disassembler)

- `disasm_info` (reads only): Overview of a native binary for disassembly: format, architecture, entry point, sections, symbol/import/function counts and decoder in use.
- `disasm_list_functions` (reads only): List functions found from symbols, exports, Go pclntab, .pdata/.eh_frame/LC_FUNCTION_STARTS, import stubs, call targets and prologue scan. Filter by name, sort by addr/name/size, paged.
- `disasm_function` (reads only): Disassemble one function with its control flow graph: basic blocks, edges (true/false/jump/fallthrough), exits, calls with resolved import names, string and data references, plus a summary.
- `disasm_pseudocode` (reads only): Readable C like pseudo code for one function (if/else and loop recovery, goto fallback) with call arguments and string literals inlined, plus a summary (calls, strings, constants, size, cyclomatic complexity).
- `disasm_xrefs` (reads only): Cross references. direction "to": every call, jump, string or data reference to an address, function, symbol or import. direction "from": everything a function calls or references.
- `disasm_callgraph` (reads only): Call graph around a function (callees, callers or both, to a depth), or without a function the program wide list of functions ranked by number of callers.
- `disasm_search` (reads only): Search code: bytes_pattern hex with ?? wildcards (e.g. "48 8d 3d ?? ?? ?? ??"), insn glob over instruction text or its resolved reference (e.g. "call *strcmp*", "xor e*, e*"), or text for literal bytes anywhere.
- `disasm_find_references` (reads only): Find the functions that reference a string (substring match by default) or call/load an import (by name, e.g. "strcmp", "CreateProcessW"), with the exact instruction addresses.
- `disasm_call_paths` (reads only): Call paths from the entry point (or a given function) to a target function, shortest first, plus the direct callers of the target. Answers "how does execution reach X".
- `disasm_at` (reads only): Disassemble N instructions linearly at any address (or function name), annotated with symbols, imports and strings. Works without function analysis.

## Android, Java and iOS

- `mobile_manifest` (reads only): Decode AndroidManifest.xml (binary AXML) from an APK: package, versions, SDK levels, permissions with risk notes, activities, services, receivers and providers with exported state and intent filters, deep links, debuggab
- `mobile_signing` (reads only): APK signing: v1 JAR signature files and certificates (subject, issuer, serial, SHA-256), APK Signing Block ids, v2/v3/v3.1 signers with certificate digests, min/max SDK and algorithms. Reports presence, does not verify.
- `mobile_dex_classes` (reads only): List DEX files (all versions 035 to 041, multidex) and their classes with access flags, superclass, interfaces, method and field counts, detected libraries and obfuscation hints. Works on APK, AAB, JAR or raw .dex.
- `mobile_dex_method` (reads only): Disassemble a DEX method to smali (baksmali compatible). Give class (com.a.B or Lcom/a/B;) and method name, optionally with signature like add(II)I. Omit method to get the whole class.
- `mobile_dex_search` (reads only): Search DEX class, method and field names and string constants (case-insensitive substring). String hits include the methods that use them.
- `mobile_dex_xrefs` (reads only): DEX cross references. direction "to": who calls a method (target like Ljava/lang/Class;->forName or just forName with kind=method), touches a field, uses a string or type. direction "from": what a method (class + target 
- `mobile_java_class` (reads only): Parse a Java .class file or a class inside a JAR and disassemble it like javap -c -p. Without class on a JAR, lists members and Main-Class.
- `mobile_ipa_info` (reads only): iOS IPA: Info.plist (binary or XML) essentials, URL schemes, ATS settings, privacy usage strings, embedded frameworks and app extensions, provisioning profile, main executable path, encryption state, code signing identif
- `mobile_app_framework` (reads only): Detect the app framework of an APK or IPA: Flutter (with Dart snapshot hash), React Native (Hermes or JS bundle), Xamarin/.NET MAUI, Unity IL2CPP or Mono, Cordova, Capacitor, Godot, Qt, Cocos2d-x, Unreal, libGDX, NativeA
- `mobile_il2cpp_types` (reads only): Unity IL2CPP global-metadata.dat (bare file or inside an APK/IPA): metadata version, images, and paged type names, method names (with declaring type) or string literals. what = summary, images, types, methods or literals
- `mobile_native_libs` (reads only): Native libraries in an APK per ABI (lib/<abi>/*.so) with soname, needed libraries, JNI_OnLoad and Java_* exports, plus DEX native methods and how many lack a static JNI export. Also accepts a single .so.
- `mobile_apk_report` (reads only): One-shot APK triage: manifest, signing, DEX stats, libraries, frameworks, native libs, sensitive API calls with callers, hardcoded URLs and keys, and security findings.

## Managed runtimes

- `managed_dotnet_info` (reads only): Summarise a .NET assembly: name, version, target framework, assembly and module references, P/Invoke imports, resources, table row counts, entry point, ReadyToRun, single-file bundle and obfuscator markers.
- `managed_dotnet_types` (reads only): List TypeDefs of a .NET assembly with tokens, base type, interfaces and optionally methods (token, signature, RVA, file offset) and fields.
- `managed_dotnet_method_il` (reads only): ildasm style CIL disassembly of one method with resolved tokens, locals, exception clauses and file offsets. Pick the method by token (0x06000001) or Type::Method.
- `managed_dotnet_search` (reads only): Search a .NET assembly by substring across types, type refs, methods, fields, member refs, user strings and P/Invoke, or set kind=xref to find every IL instruction that references a member (calls, field loads, ldstr).
- `managed_pyc_disasm` (reads only): Disassemble a CPython .pyc (3.7 to 3.13) like the dis module: header, code object tree, names, consts and instructions with offsets and resolved arguments.
- `managed_pyinstaller_list` (reads only): List a PyInstaller executable: cookie offset, Python version, entry scripts, CArchive TOC (offsets, sizes, types) and the PYZ module list.
- `managed_pyinstaller_extract` (writes files): Extract a PyInstaller executable like pyinstxtractor: scripts, modules and PYZ members become .pyc files with valid headers. Writes to outDir (Node), or returns one entry as base64.
- `managed_lua_info` (reads only): Parse Lua 5.1, 5.2, 5.3, 5.4 or LuaJIT bytecode: header, function tree, constants, locals and a luac -l style listing.
- `managed_beam_info` (reads only): Parse an Erlang or Elixir .beam file: chunk table with offsets, atoms, exports, imports, locals, attributes, compile info and literal count.
- `managed_evm_disasm` (reads only): Disassemble EVM bytecode (raw bytes or hex text) into instructions with program counters; Solidity CBOR metadata is split off.
- `managed_evm_selectors` (reads only): Extract function selectors from an EVM dispatcher with known names (ERC-20, ERC-721, Ownable, proxies), plus EIP-1967 and EIP-1167 proxy patterns, event topics, risky opcodes and solc version.

## JavaScript, Electron, network and data

- `web_js_beautify` (reads only): Reformat minified JavaScript into readable code and decode hex and unicode escapes in literals. Behavior is unchanged. Returns a paged code window.
- `web_js_deobfuscate` (reads only): Statically deobfuscate JavaScript: decode javascript-obfuscator string arrays (plain, base64, rc4) with rotation and wrapper functions, inline proxy objects, unflatten switch dispatchers, fold constants and drop dead bra
- `web_bundle_modules` (reads only): Split a webpack 4/5 bundle or jsonp chunk, browserify bundle or esbuild bundle into modules with ids, recovered source paths, dependencies and exports. Uses a source map (inline, sourceMap text or sourceMapPath) to name 
- `web_js_endpoints` (reads only): Find API endpoints and network calls in JavaScript (fetch, XHR, axios, jQuery, WebSocket, EventSource, sendBeacon, socket.io, workers), plus eval/Function use, process.env and import.meta.env names, feature flag checks, 
- `web_sourcemap_recover` (writes files): Recover original source files from a source map (or a script with an inline map): safe relative paths, sizes, a folder tree summary and optionally file contents. In Node, outDir writes the tree to disk.
- `web_asar_list` (reads only): List the files in an Electron ASAR archive with sizes, absolute data offsets, unpacked and executable flags, links and integrity hashes.
- `web_asar_extract` (writes files): Extract files from an ASAR archive. With file, returns that file (text or base64). In Node, outDir extracts everything (unpacked files copied from the .asar.unpacked folder) with path traversal blocked.
- `web_electron_audit` (reads only): Security review of an Electron app (ASAR archive, or in Node an app folder or resources folder): Electron version, fuses, BrowserWindow webPreferences (nodeIntegration, contextIsolation, sandbox, webSecurity, remote modu
- `web_pcap_summary` (reads only): Summarize a PCAP or PCAPNG capture: packet and byte counts, time range, protocol mix, top talkers and ports, DNS queries and answers, HTTP/1.x requests and responses, TLS ClientHello SNI, ALPN and JA3 hash, ServerHello J
- `web_pcap_flows` (reads only): List TCP and UDP conversations in a capture with client and server endpoints, service guess, packet and byte counts per direction, first packet index and TCP flags seen.
- `web_sqlite_tables` (reads only): Read a SQLite 3 database file with a pure TypeScript page parser: header, tables with columns, primary keys, row counts, indexes, views and triggers, and sample rows.
- `web_sqlite_query` (reads only): Run one read-only SELECT on a SQLite file: SELECT cols\|*\|COUNT(*) FROM table [WHERE ...] [ORDER BY col [DESC]] [LIMIT n [OFFSET m]]. WHERE supports comparisons, AND/OR/NOT, LIKE, GLOB, IN, BETWEEN and IS NULL. Anything
- `web_har_summary` (reads only): Summarize a HAR file: hosts (third-party marked), API endpoint patterns, methods, statuses, MIME types, redirects, slowest requests, auth header schemes and cookie names (values never returned), missing security headers,
- `web_browser_capture` (network): Open a URL in a headless browser (Playwright, optional dependency, Node only) and record network requests as HAR entries, loaded and inline scripts with source, console messages, cookie names and flags, storage keys, Web

## Extras

- `x_demangle` (reads only): Demangle C++ (Itanium), Rust (legacy and v0) and MSVC symbols. Pass symbols, or a binary path to demangle its symbol table.
- `x_container` (reads only): Unified container view of ELF, PE or Mach-O (fat slices too): machine, entry, sections and segments with file offsets and addresses.
- `x_read_bytes` (reads only): Read up to 64 KiB of raw bytes at a file offset or at a virtual address, as hex and printable text.
- `x_search_bytes` (reads only): Search a file for a hex pattern with ?? wildcards (for example "48 8b ?? 24") or a text string (ASCII and UTF-16LE). Hits include offset, address and section.
- `x_address_map` (reads only): Convert a virtual address to a file offset, or a file offset to a virtual address, with the section and segment it falls in.
- `x_checksec` (reads only): Hardening checks for ELF, PE and Mach-O: RELRO, NX, PIE, canary, FORTIFY, CET, BTI and PAC, ASLR, CFG, SafeSEH, code signing, with byte evidence and a score.
- `x_go_symbols` (reads only): Recover Go function names, source files and packages from pclntab, also on stripped binaries (Go 1.2 to 1.24).
- `x_rust_info` (reads only): Rust toolchain and crate evidence: rustc version and commit, crates with versions from registry paths, symbol schemes, panic strings.
- `x_pe_inspect` (reads only): Deep PE view: headers and checksum, rich header, resources, version info, manifest, debug and PDB path, TLS callbacks, load config, exports, delay imports, overlay, installer detection (NSIS, Inno, MSI, WiX, InstallShiel
- `x_pe_resources` (reads only): PE resources with type, name, language, file offset, size and sniffed content type, plus version info, manifest and string tables.
- `x_pe_authenticode` (reads only): Authenticode signatures of a PE: recomputes the image digest, compares it with the signed digest, verifies the signer signature, lists certificates, signing time and countersignature.
- `x_elf_inspect` (reads only): ELF notes (build-id, ABI tag, GNU properties, Go and package notes), dynamic section (NEEDED, SONAME, RPATH, RUNPATH, flags) and init/fini array targets.
- `x_elf_unwind` (reads only): Function ranges from .eh_frame_hdr and .eh_frame FDEs (start, end, size, FDE and CIE offsets). Useful function boundaries for stripped binaries.
- `x_kernel_module` (reads only): Linux kernel module (.ko) facts: modinfo, vermagic, dependencies, signature trailer, plus IKCONFIG kernel build config recovery from a kernel image.
- `x_macho_inspect` (reads only): Mach-O load commands, UUID, build version, dylibs with @rpath resolution, rpaths, encryption info and code signature (code directories, cdhash, entitlements, CMS signer, hardened runtime).
- `x_firmware_scan` (reads only): Find embedded images at any offset (binwalk style, headers validated): uImage, FIT/DTB, squashfs, cpio, UEFI volumes, TRX, UF2, Android boot and sparse, UBI, JFFS2, CramFS, ext, ELF, PEM, gzip, xz, zstd, lz4, lzma, bzip2
- `x_firmware_parse` (reads only): Parse one firmware structure at an offset: uimage, fdt (device tree or FIT), ihex, srec, uf2, dfu, esp, android-boot, squashfs (with file listing), cpio, uefi (firmware volume and files), trx.
- `x_v8_inspect` (reads only): JavaScript engine artifacts: V8 code cache and bytenode .jsc (magic, version hash, flag hash, source length, payload length), V8 startup snapshot blobs (version string), Hermes bytecode headers.
- `x_gpu_inspect` (reads only): GPU code objects: CUDA fatbin entries (PTX or cubin, sm_ target, compression), cubin kernels, PTX entries, AMD HSA code objects (gfx target, kernels), SPIR-V (version, capabilities, entry points), clang offload bundles i
- `x_model_inspect` (reads only): Model files: GGUF metadata and tensor table, safetensors header, NumPy .npy header. Checks tensor sizes against dtypes and file bounds.
- `x_lnk_inspect` (reads only): Windows shortcut (.lnk): target path, arguments, working dir, icon, timestamps, volume serial and label, tracker machine id, extra data blocks.
- `x_apple_ips` (reads only): Apple .ips crash and diagnostic reports: process, OS, exception, termination reason, crashed thread frames joined to their images with absolute addresses.
- `x_ledger_record` (writes files): Record a claim about a file in the evidence ledger, bound to byte ranges by SHA-256. Optional check is a RevLens claim (contains-string, bytes-at, format-is, sha256-is) run on verify.
- `x_ledger_unknown` (writes files): Record an open question (unknown) in the ledger, or resolve, reject or reopen a claim or unknown by id.
- `x_ledger_verify` (writes files): Re-read the files behind ledger claims and check every evidence hash and structured check. Claims become verified, refuted (bytes changed) or stale (file missing).
- `x_ledger_list` (reads only): Current claims and unknowns with status, evidence and history, plus a summary (verified share, open unknowns, chain head).
- `x_ledger_export` (reads only): Export the ledger as hash-chained JSON (revlens/ledger@1) or as a Markdown table for a report.
- `x_ledger_import` (writes files): Import an exported ledger after checking its schema and hash chain. Replaces the session ledger, or writes ledgerPath.
- `x_eval_tasks` (reads only): Reverse engineering eval tasks with hidden ground truth on the RevLens sample fixtures. Answer them with any tools, then score with x_eval_score.
- `x_eval_score` (reads only): Score answers to x_eval_tasks against ground truth verified with reference tools. Pass answers as {taskId: answer}.

## External tool bridges

- `bridge_doctor` (reads only): Inventory of external reverse engineering tools on this machine (radare2, rizin, Ghidra, jadx, apktool, ILSpy, Frida, gdb, lldb, objdump, binwalk, adb, IDA, Binary Ninja): versions, paths, what each unlocks, and install 
- `bridge_r2_functions` (reads only): List functions recovered by radare2 or rizin with address, size, basic blocks and call counts. Paged.
- `bridge_r2_disasm` (reads only): Disassemble one function (or N instructions at an address) with radare2 or rizin. Returns address, bytes and text per instruction.
- `bridge_r2_decompile` (reads only): Decompile one function to C with r2ghidra or rz-ghidra, falling back to radare2 pseudo code (pdc) when the plugin is missing.
- `bridge_r2_xrefs` (reads only): Cross references to a function or address (who calls or reads it) with radare2 or rizin.
- `bridge_r2_strings` (reads only): Strings in data sections with virtual and file addresses, from radare2 or rizin. Paged.
- `bridge_r2_info` (reads only): Binary info (arch, bits, format, hardening flags, base address) and imports from radare2 or rizin.
- `bridge_ghidra_functions` (reads only): List functions with Ghidra headless (address including image base, size, signature, calling convention). The analyzed project is cached per file hash. Paged.
- `bridge_ghidra_decompile` (reads only): Decompile functions to C with Ghidra headless. Give names or 0x addresses (Ghidra addresses include the image base, for example 0x100828 for a PIE at 0x828).
- `bridge_jadx_decompile` (reads only): Decompile an APK, DEX, JAR, AAR or class file to Java with jadx. Without className lists classes (paged); with className returns that class source.
- `bridge_jadx_search` (reads only): Search jadx decompiled Java for a literal string (URLs, keys, class names). Returns class, line number and line text.
- `bridge_apktool_decode` (reads only): Decode an APK with apktool: AndroidManifest.xml as text, apktool.yml, and the decoded resource and smali file list.
- `bridge_ilspy_decompile` (reads only): Decompile a .NET assembly with ilspycmd. Without typeName lists types (paged); with typeName returns that type as C#.
- `bridge_frida_ps` (reads only): List processes (or installed apps) on a Frida device. Read only.
- `bridge_frida_devices` (reads only): List Frida devices (local, USB, remote). Read only.
- `bridge_frida_run` (runs programs): Attach to a process (pid or name) or spawn a program and run a RevLens hook template, collecting JSON events. Templates: module-list, trace-native-export, java-method-log, ssl-pinning-bypass, electron-net-observe. Needs 
- `bridge_frida_templates` (reads only): List the built-in Frida hook templates and their parameters.
- `bridge_gdb_run` (runs programs): Run a program under gdb (or lldb with debugger: lldb) in batch mode. At each breakpoint returns registers, backtrace and an optional memory dump. Needs allowExecution: true.
- `bridge_objdump` (reads only): Disassemble (optionally one symbol or an address range), list sections or list symbols with GNU objdump or llvm-objdump. Good second opinion next to radare2.
- `bridge_binwalk` (reads only): Firmware signature scan with binwalk: embedded archives, images, file systems and compressed blobs with their offsets. Never extracts.
- `bridge_adb_devices` (reads only): List Android devices and emulators visible to adb.
- `bridge_adb_packages` (reads only): List installed Android packages with their APK paths.
- `bridge_adb_pull_apk` (writes files): Pull the base and split APKs of an installed package to a local folder, ready for bridge_jadx_decompile.
- `bridge_adb_logcat` (reads only, network): Dump recent logcat lines from a device, optionally for one tag.
- `bridge_ida_run` (reads only): Run IDA (idat) in batch mode to list functions or decompile selected ones with Hex-Rays when licensed.
- `bridge_binja_functions` (reads only): List functions with the Binary Ninja headless API (needs a license that allows headless use).
- `bridge_setup_mcp` (writes files): Add the RevLens MCP server to an agent client config (claude-code, codex, cursor, vscode, windsurf). Dry run by default and returns the new file text; write: true saves it with a backup.
