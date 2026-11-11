# RevLens tool map

Generated from the server by scripts/gen-tool-docs.mjs. 203 tools.

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
- `disasm_trace_values` (reads only): Native value flow. Backward: with function + call (address or callee name, optional occurrence and arg index from 0), shows the value reaching each argument (constant, string, stack address, incoming argument, return val
- `disasm_indirect_targets` (reads only): Indirect calls and jumps of a function (or the whole program within a budget) with resolved targets: jump tables (switch), tables of code pointers, constants found by value tracking, initial values of writable function p
- `disasm_match_functions` (reads only): Map functions between two binaries (two versions, or a stripped and an unstripped build) without relying on addresses: equal names (optional), identical normalized instructions, strings, imports and constants, CFG shape,
- `disasm_compare_functions` (reads only): Side by side diff of two functions (same binary, or function in path vs function2 in path2): overall similarity, per dimension (instructions, CFG, strings, calls, constants), identical/changed basic blocks, and a unified

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
- `mobile_app_graph` (reads only): Android application graph from an APK: the app, activities, aliases, services, receivers and providers with exported state and why, intent filter actions, deep links, provider authorities, used, defined and required perm
- `mobile_ipa_graph` (reads only): iOS bundle graph from an IPA: app, main and nested executables (CPU, team id), app extensions with extension points, embedded frameworks and dylibs with link edges from load commands, system libraries, entitlements per e
- `mobile_jni_map` (reads only): Map DEX native methods to native code: Java_* exports (short and overloaded long names), JNINativeMethod tables recovered from .so data through RELATIVE, ABS and RELR relocations (what JNI_OnLoad passes to RegisterNative
- `mobile_compare_members` (reads only): Diff classes, methods and fields between two DEX sets (two APK versions, JARs or .dex files): added and removed classes and members, access flag changes, superclass and interface changes, and with bodies=true methods who
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
- `managed_pinvoke_map` (reads only): Map .NET P/Invoke declarations (ImplMap: module, entry point, charset, calling convention, SetLastError) to exports of the native libraries shipped with the app (ELF .so, PE .dll, Mach-O .dylib), using the runtime probin
- `managed_compare_members` (reads only): Diff two .NET assemblies (for example two versions of a library): added and removed types, kind, visibility, base type and interface changes, added, removed and changed methods (keyed by name, generic arity and parameter

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
- `web_webmcp_scan` (reads only): Static WebMCP scan of one HTML page or script: navigator.modelContext provideContext and registerTool calls with tool names, descriptions and input schema fields, declarative tool forms (toolname and tooldescription), MC
- `web_wellknown_classify` (reads only): Classify a fetched well-known discovery document (MCP server card, MCP endpoint list, AI plugin manifest, A2A agent card, OAuth protected resource metadata, llms.txt) and pull out its name, endpoints and tool names.
- `web_capture_compare` (reads only): Compare two captures (RevLens scenario capture.json, web_browser_capture output, or HAR): endpoints added and removed with id-normalized paths, status changes, request and response header changes, scripts added, removed 
- `web_browser_capture` (network): Open a URL in a headless browser (Playwright, optional dependency, Node only) and record network requests as HAR entries, loaded and inline scripts with source, console messages, cookie names and flags, storage keys, Web
- `web_browser_scenario` (writes files, network): Run a scripted browser scenario with Playwright (Node only): steps goto, click, type, fill, press, select, check, hover, scroll, wait, reload, back and assert, with evaluate-free assertions (selector exists, count, text,
- `web_trace_inspect` (reads only): Read a Playwright trace.zip: actions with API name, selector, timing and errors, network requests with status, console messages, pages and screencast frame count.
- `web_cdp_targets` (reads only, network): List debuggable targets on a Chrome DevTools Protocol endpoint (a browser or Electron app started with --remote-debugging-port, or a Node --inspect port): pages, iframes, workers, service workers, Node contexts, with pro
- `web_webmcp_discover` (network): Discover WebMCP tools and MCP-over-web endpoints for a URL: agent response headers, MCP link and meta tags, declarative tool forms, navigator.modelContext registrations in inline and same-origin scripts, well-known docum
- `web_node_inspect` (network): Attach to a local Node.js process through its inspector (by pid, port or ws URL) and observe it without evaluating code: loaded scripts with hashes and source maps, function call counts from precise coverage, a CPU sampl

## Extras

- `x_demangle` (reads only): Demangle C++ (Itanium), Rust (legacy and v0), MSVC and Swift (old _T and new $s/$S/_T0 mangling) symbols. Pass symbols, or a binary path to demangle its symbol table.
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
- `x_registry_hive` (reads only): Windows registry hive (regf: SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD). Without key: header (dirty flag, checksum), root and totals. With key: that key, its subkeys and decoded values. With recur
- `x_prefetch` (reads only): Windows Prefetch (.pf) file, XP to 11, including Windows 10+ MAM (LZXPRESS Huffman) compressed files: executable, hash, run count, last 8 run times, loaded files, volumes with serials and directories.
- `x_jump_list` (reads only): Windows Jump Lists: *.automaticDestinations-ms (DestList entries with path, pin state, access count, host, droid ids, and each embedded shell link) and *.customDestinations-ms (shell links by offset).
- `x_ole_compound` (reads only): OLE compound file (MSI, legacy Office, Jump Lists, thumbs.db): directory entries with paths, sizes, CLSIDs and times; optionally the hex of one stream.
- `x_keyed_archive` (reads only): Decode an NSKeyedArchiver archive (binary or XML plist, for example .nib keyed archives, NSUserDefaults blobs, iOS backups, saved state): resolves CF$UID references from $top into plain JSON, maps Foundation classes, lis
- `x_nib` (reads only): Compiled Interface Builder file (.nib from ibtool, NIBArchive format; keyed-archive nibs are decoded too): class histogram, user visible strings, outlet and action connections, custom classes, and the raw objects with ty
- `x_asset_catalog` (reads only): Compiled asset catalog (Assets.car, a BOM store): CoreUI header and authoring tool, deployment target, key format, facets (asset names), appearances, and every rendition with name, asset, size, scale, pixel format, layou
- `x_wxapkg` (reads only): WeChat mini program package (.wxapkg): member table with offsets and sizes, app config, pages, kind (main, subpackage, plugin, game). Decrypts PC client V1MMWX packages when appId is given. With member, returns that file
- `x_unity_bundle` (reads only): Unity asset bundle (UnityFS): header, Unity version, blocks (compression), node table; each serialized file summarised with target platform, types and objects by class (path id, offset, size). LZ4/LZ4HC and uncompressed 
- `x_standalone_js` (reads only): JavaScript apps packed into one executable: Node.js SEA (fuse state, NODE_SEA_BLOB with entry script, code cache, assets, exec argv), Bun --compile (embedded module graph with sources) and Deno compile (metadata JSON, en
- `x_swift_demangle` (reads only): Demangle Swift symbols (Swift 1 to 3 _T, Swift 4 _T0, Swift 4.x $S, Swift 5+ $s, macro @__swiftmacro_), matching swift-demangle 6.0.3 text. Optional simplified form and node tree. With a binary path, lists the Swift symb
- `x_api_contracts` (reads only): API contracts shipped inside binaries and JS bundles: protobuf FileDescriptorProto blobs (Go protoc-gen-go raw or gzip, C++, Java, Python _pb2 literals and .pyc, protobuf-es base64) rebuilt as .proto text; OpenAPI 3 / Sw

## Desktop apps, processes and UI trees

- `desktop_plist_parse` (reads only): Parse an XML or binary (bplist00) property list. Data values come back as base64, dates as ISO strings, UIDs as {$uid}. With bundle=true, also summarise it as an app Info.plist (id, version, executable, URL schemes).
- `desktop_entry_parse` (reads only): Parse a freedesktop .desktop file: groups and keys, plus an app record with the executable split from Exec per the spec quoting rules, packaging (Flatpak, Snap, AppImage), categories and MIME types.
- `desktop_reg_uninstall_parse` (reads only): Parse `reg query ...\Uninstall /s` output into installed app records (name, version, publisher, install location, executable, MSI flag, uninstall command).
- `desktop_proc_parse` (reads only): Parse Linux /proc text that was copied off a machine: kind=maps (modules with base and size), status, tcp, tcp6, udp, udp6, unix (sockets with decoded addresses and states), or lsof (lsof -F output).
- `desktop_gvariant_parse` (reads only): Parse GVariant text as printed by gdbus call (tuples, arrays, dicts, variants, object paths, typed numbers) into JSON.
- `desktop_snapshot_compare` (reads only): Compare two process snapshot objects (as JSON text) without touching the system: modules, files, sockets, children, memory and thread changes.
- `desktop_process_list` (runs programs): List running processes with pid, parent pid, name, executable, command line, user, threads and memory (Linux /proc, macOS ps, Windows Win32_Process). Needs allowExecution.
- `desktop_process_inspect` (writes files): Inspect one process: identity, command line, loaded modules and libraries with base addresses (Linux /proc maps, macOS lsof and vmmap, Windows Get-Process modules), open files (Linux /proc fd, macOS lsof), and TCP, UDP a
- `desktop_process_compare` (reads only): Compare two process snapshots (JSON files from desktop_process_inspect saveTo): changed process fields, modules loaded or unloaded, files opened or closed, sockets opened or closed, child processes, memory and thread del
- `desktop_apps_list` (runs programs): Discover installed applications: Linux .desktop entries in the XDG, Flatpak and Snap folders, macOS .app bundles in /Applications with Info.plist details, Windows uninstall registry keys (reg query). Gives name, id, vers
- `desktop_app_inspect` (runs programs): Read one installed app: a .desktop file, an .app bundle or an Info.plist. Resolves the executable on PATH and flags Electron apps with the app.asar path, ready for web_electron_audit.
- `desktop_ui_tree` (runs programs): Capture the native accessibility tree of a running app: AT-SPI over gdbus on Linux, System Events (osascript JXA) on macOS, UIAutomation through PowerShell on Windows. Gives role, name, description, value, automation id 

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
- `bridge_adb_install` (runs programs): Install an APK (or base plus split APKs with install-multiple) on a device. Changes the device: needs allowExecution: true.
- `bridge_adb_uninstall` (writes files): Uninstall a package from a device. Changes the device: needs allowExecution: true.
- `bridge_adb_push` (runs programs): Copy a local file to the device, below /data/local/tmp, /sdcard or /storage/emulated unless allowAnyRemotePath. Changes the device: needs allowExecution: true.
- `bridge_adb_pull` (writes files): Copy one file from the device to a local folder with its SHA-256. Checks the remote size first (maxBytes) and never overwrites unless asked.
- `bridge_adb_start_activity` (runs programs): Start an activity with am start -W by component, or the launcher activity of a package. Every value is validated and quoted for the device shell. Changes the device: needs allowExecution: true.
- `bridge_adb_stop_app` (runs programs): Force stop an app (am force-stop). Changes the device: needs allowExecution: true.
- `bridge_adb_dumpsys_package` (reads only): dumpsys package as JSON: version, SDK levels, flags (debuggable, allowBackup), install times, declared, requested, install and runtime permissions, and components with intent filters.
- `bridge_adb_components` (reads only): List activities, services, receivers and providers of an installed package with their intent actions, categories, schemes and permissions, plus launcher activities.
- `bridge_adb_resolve_activity` (reads only): Which activity an intent opens (cmd package resolve-activity). Default: the launcher activity of package, or the HOME screen without one.
- `bridge_adb_pm_path` (reads only): APK paths (base and splits) of an installed package (pm path).
- `bridge_adb_screenshot` (writes files): Take a PNG screenshot into a local folder; returns the path, size in pixels and SHA-256.
- `bridge_adb_screenrecord` (writes files): Record the screen to a local MP4 for a bounded time (1 to 180 seconds, default 10).
- `bridge_adb_display` (reads only): Display size and density, physical and override (wm size, wm density).
- `bridge_adb_input` (runs programs): Send one input event: tap (x, y), swipe (x, y, x2, y2, durationMs), text (printable ASCII) or keyevent (KEYCODE_HOME or a number). Changes the device: needs allowExecution: true.
- `bridge_adb_getprop` (reads only): Device properties: one key, or all (optionally by prefix) plus a summary (model, release, SDK, ABI, fingerprint, debuggable, secure, patch level).
- `bridge_adb_settings` (reads only): Read one setting or list a settings namespace (system, secure, global). Read only.
- `bridge_adb_ps` (reads only): Running processes on the device (user, pid, ppid, memory, state, name), optionally filtered by name.
- `bridge_adb_ls` (reads only): List a device folder (ls -la): type, mode, owner, group, size, date, name and link target.
- `bridge_adb_logcat_filtered` (reads only, network): Logcat with filter specs (Tag:P), one pid, a buffer (main, system, crash, events, all), a since time and a substring filter.
- `bridge_adb_bugreport` (writes files): Collect a bugreport zip with a hard time limit (default 10 minutes, max 30) and a size cap.
- `bridge_adb_backup` (writes files): adb backup of one package to a local .ab file and its header. The device asks its user to confirm; apps with allowBackup=false give an empty file.
- `bridge_adb_forward` (network): List, add or remove host to device port forwards (tcp:N, localabstract:name, jdwp:pid). Adding and removing need allowExecution: true.
- `bridge_adb_reverse` (network): List, add or remove device to host reverse port rules. Adding and removing change the device: need allowExecution: true.
- `bridge_session_list` (reads only): List open radare2/rizin, gdb, lldb and Frida sessions with ids, targets, idle timeouts and command counts.
- `bridge_session_close` (runs programs): Close one session by id (or every session with all: true). Sessions also close after their idle timeout and when the server exits.
- `bridge_r2_session_open` (runs programs): Open a radare2 (or rizin) session on a file and keep it alive across calls, so analysis runs once and names you set stay. Static only, sandboxed (cfg.sandbox), no shell.
- `bridge_r2_session_cmd` (runs programs): Run one radare2 or rizin command in an open session (afl, pdf @ main, afn name @ addr, axt, izj). JSON commands come back parsed. Shell, pipes, file writes, opening other files and scripts are refused.
- `bridge_gdb_session_open` (runs programs): Start gdb (MI) on a program with arguments, or attached to a pid, and keep it alive across calls. Program output goes to its own stream. Needs allowExecution: true.
- `bridge_gdb_session_cmd` (runs programs): Run one gdb console command in a session (break, run, continue, stepi, info registers, bt, x/16gx $sp). Resuming commands wait for the next stop, then interrupt on timeout. shell, python, source, dump, file and similar a
- `bridge_lldb_session_open` (runs programs): Start lldb on a program with arguments, or attached to a pid, and keep it alive across calls. Needs allowExecution: true.
- `bridge_lldb_session_cmd` (runs programs): Run one lldb command in a session (b, run, continue, si, register read, bt, memory read). Waits until the program stops. platform shell, script, command script and similar are refused.
- `bridge_frida_session_attach` (runs programs): Attach Frida to a process (pid or name) or spawn a program and keep the session open for scripts and messages. Needs allowExecution: true.
- `bridge_frida_session_load` (runs programs): Load a script into a Frida session: a RevLens hook template (see bridge_frida_templates) or your own JavaScript source. Returns a script id. A spawned program is resumed after the first load unless resume: false.
- `bridge_frida_session_post` (runs programs): Post a JSON message to a loaded script (the script reads it with recv()).
- `bridge_frida_session_collect` (runs programs): Take buffered events from a Frida session: send() payloads, console logs, parsed RevLens template events, script errors and detach notices. Can wait up to waitMs for minEvents.
- `bridge_frida_session_unload` (runs programs): Unload one script from a Frida session; the session stays attached.
- `bridge_frida_session_resume` (runs programs): Resume a spawned program that is still suspended.
- `bridge_ghidra_apply_names` (writes files): Write function names, signatures, comments, labels and C types from a RevLens names JSON into a Ghidra project (the cached RevLens project for the file by default, so later Ghidra decompiles show the names, or your own p
- `bridge_ghidra_export_names` (writes files): Export user defined function names and signatures, comments in functions, user labels and /RevLens types from a Ghidra project as a RevLens names JSON.
- `bridge_ida_apply_names` (writes files): Write a RevLens names JSON into an IDA database with idat: give a .i64/.idb to update it, or a binary plus outDatabase to create one. Names, prototypes, comments, labels and C types.
- `bridge_ida_export_names` (writes files): Export user names, prototypes, comments, labels and local types from an IDA database (or a binary) as a RevLens names JSON.
- `bridge_r2_apply_names` (writes files): Write a RevLens names JSON into a radare2 project (or rizin .rzdb), creating it from the binary when needed; returns the r2 script too. Names that r2 cannot hold are mapped to safe ones and listed.
- `bridge_r2_export_names` (writes files): Export what was added to a radare2 or rizin project (names and comments that differ from a fresh analysis, plus RevLens labels) as a RevLens names JSON.
- `bridge_cutter_info` (reads only): Find Cutter (the rizin GUI) without starting it: AppImage, macOS app, Windows release or Scoop, Flatpak, distro package. Reports version, install kind, a rizin bundled with it, and how to open a file in it.
- `bridge_ida_run` (reads only): Run IDA (idat) in batch mode to list functions or decompile selected ones with Hex-Rays when licensed.
- `bridge_binja_functions` (reads only): List functions with the Binary Ninja headless API (needs a license that allows headless use).
- `bridge_setup_mcp` (writes files): Add the RevLens MCP server to an agent client config (claude-code, codex, cursor, vscode, windsurf). Dry run by default and returns the new file text; write: true saves it with a backup.
