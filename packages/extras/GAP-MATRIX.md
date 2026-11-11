# RevLens vs rea gap matrix

Compared against morluto/rea v6.8.0 (source clone, MCP catalog in docs, 174 contract tool names, 194 CLI command names, 60+ src/ provider folders). 
Rows group related rea tools. Status: covered, partial, missing. "Before" is the state of all RevLens branches at feat/extras ce77aa5; "after" is the state at the head of feat/extras after this round of work, every after-change backed by tests against reference tools.
Regenerate with `python3 packages/extras/scripts/gap_matrix.py packages/extras/GAP-MATRIX.md`.


## MCP tools: native code

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| open_binary / close_binary | src/native, registerNativeTools | disasm | covered | covered | stateless: every tool takes a path, no session to leak |
| binary_overview | src/native | disasm + core | covered | covered | analyze_file adds findings, SBOM, secrets and ATT&CK in the same call |
| list_procedures / search_procedures | src/ghidra, src/native | disasm | covered | covered | pure TS engine, no Ghidra or JDK needed, runs in a browser worker |
| analyze_function | src/native | disasm | covered | covered | function, CFG and pseudo code in one reply, no detail paging needed for small functions |
| decompile / decompile_all / batch_decompile | src/ghidra, src/ida, src/hopper | disasm + bridges | partial | partial | built-in pseudo code works offline; full decompile through bridges (Ghidra, r2, IDA, Binja). Left: batch whole-binary export from the built-in engine |
| get_call_graph / build_call_path / trace_call_path | src/native | disasm | covered | covered | call paths computed in-process with bounded search |
| procedure_callers / procedure_callees / procedure_references / xrefs | src/native | disasm | covered | covered | xrefs include data refs from the built-in scanner |
| list_strings / search_strings / list_names | src/native | core + disasm | covered | covered | strings carry offsets, encodings and secret scoring |
| list_segments / inspect_binary_layout | src/native | core + extras | covered | covered | x_container gives one model for ELF, PE and Mach-O including fat slices |
| read_bytes / search_bytes / address_to_file_offset | src/native | extras | missing | covered | x_read_bytes, x_search_bytes (hex with ?? wildcards), x_address_map work on any container without opening a project |
| inspect_native_instruction | src/native | disasm | covered | covered | decoder runs on x86, x64, ARM64, ARM, Thumb in TS |
| resolve_containing_procedure / inspect_address_context / get_navigation_context | src/native | disasm | partial | partial | disasm_at gives the containing function; left: UI-style navigation context |
| inspect_native_load_image | src/native | extras | partial | covered | x_container plus x_address_map show segment mapping and file offsets |
| inspect_native_exports | src/native | extras + core | covered | covered | PE exports with forwarders, ELF dynsym, Mach-O symbols with demangled names |
| inspect_native_initializers | src/native | extras | covered | covered | ELF init_array resolved through RELATIVE relocs; Mach-O mod_init_func |
| inspect_elf_notes | src/native | extras | covered | covered | build-id, ABI tag, GNU property (CET, BTI, PAC), Go and FDO package notes |
| inspect_elf_unwind_ranges | src/native | extras | missing | covered | x_elf_unwind reads .eh_frame_hdr binary search table and CIE/FDE ranges |
| inspect_kernel_module / inspect_kernel_build_config | src/native | extras | covered | covered | modinfo, vermagic, signature trailer, IKCONFIG gzip recovery |
| inspect_binary_hardening | src/native | extras | covered | covered | one checksec for ELF, PE and Mach-O with a score and byte evidence |
| inspect_byte_entropy | src/native | core | covered | covered | entropy windows plus packer detection |
| inspect_pe_imports | src/windows | core + extras | covered | covered | imports, delay imports, imphash |
| inspect_pe_resources | src/windows | extras | covered | covered | resources with type sniffing, version info, manifest, string tables |
| inspect_pe_certificates | src/windows | extras | covered | covered | Authenticode digest recomputed and compared, signature verified with WebCrypto |
| inspect_pe_load_config | src/windows | extras | covered | covered | CFG, SafeSEH, cookie, CET flags |
| inspect_macho / trace_dylib_resolution | src/native | extras | covered | covered | load commands, rpath expansion, code signature and entitlements |
| inspect_go_binary | src/go | extras + core | covered | covered | pclntab across Go 1.2 to 1.22+ magics even on stripped binaries, plus buildinfo deps |
| inspect_rust_binary | src/rust | extras + core | partial | covered | x_rust_info: rustc version, crates from paths, v0 and legacy demangle |
| demangle-swift (CLI) | src/cli | extras | missing | covered | pure TS port of swift-demangle 6.0.3 (old _T and new $s/$S/_T0 mangling): 470/470 swift test vectors and 1947/1947 Maccy symbols identical, default and simplified; in x_demangle, x_swift_demangle and x-swift-demangle; rea needs a native helper |
| match_native_functions / compare_functions | src/native | core diff + disasm | partial | partial | core diff_files compares sections and symbols; left: per-function similarity matching |
| trace_native_values / resolve_native_call_targets | src/native | disasm | missing | missing | left: constant propagation for indirect calls |
| inspect_native_api / inspect_native_dispatch_metadata / inspect_native_data_type | src/native | disasm | missing | missing | left: ObjC/Swift dispatch metadata and type libraries |
| annotate_native_function | src/ghidra | bridges | missing | missing | left: write-back names to Ghidra or IDA projects |
| inspect_with_objdump / list_objdump_architectures | src/objdump | bridges | covered | covered | execFile with argument arrays and timeouts |
| execute_rizin_command / cutter_command / list_cutter_sessions | src/rizin, src/cutter | bridges | partial | partial | radare2 bridge covered; left: Cutter sessions |
| start/close/status rizin and gdb debug sessions, gdb_console | src/rizin, src/gdb | bridges | partial | partial | one-shot gdb and lldb batches; left: long-lived debug sessions |
| inspect_recorded_crash / inspect_apple_ips / trace_crash | src/native | extras | missing | covered | x_apple_ips parses .ips JSON reports and maps frames to images |

## MCP tools: evidence, investigation, guidance

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| Evidence records (evidence_id, normalized_result, limitations) | src/domain, docs/api-contracts.md | extras | partial | covered | x_ledger_* records claims with SHA-256 bound byte ranges any reader can re-check |
| get_evidence_bundle / export_evidence_bundle / evidence-import / evidence-export / inspect-evidence-bundle | src/server | extras | missing | covered | ledger export is plain JSON with a digest chain; import verifies every claim against the file |
| verify_reconstruction / verify_claim | src/server | core + extras | partial | covered | core verify_claim plus x_ledger_verify re-reads bytes and checks hashes |
| record_unknown / update_unknown / list_unknowns / audit_residual_unknowns | src/application | extras | missing | covered | unknowns are ledger entries with status open/resolved and links to claims |
| build_reconstruction_obligation_ledger / evaluate_reconstruction_coverage | src/application | extras | missing | partial | ledger summary gives coverage by claim status; left: source reconstruction obligations |
| investigate_feature / trace_feature / trace_application_feature / find_changed_behavior | src/application | core + disasm | partial | partial | string to xref to function chains; left: guided feature tracing across providers |
| inspect_analysis_view (paging) | src/server | all | covered | covered | every RevLens tool pages with offset and limit directly |
| compare_artifacts / compare_application_versions | src/artifacts | core | covered | covered | diff_files covers any two inputs with findings delta |
| inventory_artifact / inspect_artifact / extract_artifact / open_bundle_resources | src/artifacts | core + extras | covered | covered | archives in core, firmware carving and squashfs/cpio listing in extras |
| reset_investigation / session status / close lifecycle | src/server | mcp | covered | covered | stateless tools need no reset |
| guidance / search_guidance / read_guidance_section / guided_workflows / instructions | src/guidance | mcp | partial | partial | list_analyzers and tool descriptions; left: searchable guidance corpus |
| discover_tools / capabilities / providers / inspect_input_contract | src/server | mcp + bridges | partial | partial | bridge_doctor lists external tools; left: progressive tool catalog |
| inspect/update_analysis_settings | src/server | mcp | missing | missing | left: per-session analysis profiles |

## MCP tools: Android, iOS, mobile

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| inspect_android_package / decode_android_resources | src/android | mobile | covered | covered | AXML and manifest risk findings without apktool |
| inspect_android_class / inspect_android_method / search_android_classes / trace_android_references | src/android | mobile | covered | covered | DEX and smali in TS, xrefs over all classes.dex |
| inspect_android_jni_bindings | src/android | mobile | partial | partial | native libs listed with JNI_OnLoad and Java_ exports; left: RegisterNatives table recovery |
| inspect_apk_signature | src/apkSignature | mobile | covered | covered | v1, v2, v3 blocks with certificate details |
| inspect_apktool_client / apktool | src/apktool | bridges | covered | covered | optional, built-in AXML covers the common case |
| JEB tools (open_jeb_project, list_jeb_units, decompile_jeb_item) | src/jeb | bridges | missing | missing | commercial tool; jadx bridge covers the same need |
| project_android/apple/harmony/managed_application_graph | src/application | mobile + managed | missing | missing | left: component graphs |
| identify_flutter_build / inspect_dart_aot | src/flutter | mobile | partial | partial | Flutter detection and snapshot hash; left: Dart AOT object pool |
| inspect_il2cpp_metadata | src/il2cpp | mobile | covered | covered | global-metadata.dat types and methods |
| inspect_plist / inspect_keyed_archive / decode_interface_builder / inspect_asset_catalog | src/native (Apple) | mobile | partial | partial | IPA Info.plist and entitlements; left: NSKeyedArchiver, NIB and Assets.car |
| ADB: list_adb_devices, read_adb_logcat, list_adb_packages, pull_adb_package | src/adb | bridges | covered | covered | execFile argument arrays |
| ADB: install/uninstall, push/pull file, start/stop app, activity, screen, bugreport, services, settings, window, display, processes, features, directory, resolve packages | src/adb | bridges | missing | missing | left: the rest of the ADB suite (about 18 tools) |

## MCP tools: managed runtimes

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| inspect_managed_artifact / inspect_managed_members | src/dotnet | managed | covered | covered | .NET metadata tables and CIL in TS |
| ilspycmd | src/dotnet | bridges | covered | covered | bridge_ilspy_decompile |
| compare_managed_members / import_managed_reconstruction | src/dotnet | managed | missing | missing | left |
| inspect/verify_managed_native_boundaries | src/dotnet | managed | missing | missing | left: P/Invoke to native export matching |
| inspect_python_pyc / PyInstaller | src/python | managed | covered | covered | pyc 3.7 to 3.13 disassembly plus PyInstaller extraction |
| inspect_erlang_beam | src/erlang | managed | covered | covered | chunks, atoms, exports |
| inspect_evm_interface | src/evm | managed | covered | covered | selectors and disassembly |
| inspect_wasm_artifact / compare_wasm_interfaces | src/wasm | core | covered | covered | WASM sections and imports in core; diff_files for interfaces |
| inspect_v8_code_cache | src/v8 | extras | missing | covered | x_v8_inspect: code cache header, version hash, flags hash, source hash, bytenode detection and snapshot blob |
| Hermes bytecode | src/javascript | extras | missing | partial | x_v8_inspect reads the Hermes HBC header (version, counts); not yet checked against a real hermesc output, no bytecode disassembly |

## MCP tools: web, browser, Electron, network

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| analyze_web_bundle / analyze_javascript_application / recover_javascript_sources | src/javascript | webrt | covered | covered | beautify, deobfuscate, module unpack, source map recovery |
| export_web_scripts / inspect_web_page / capture_web_screenshot / list_browser_targets | src/browser | webrt | partial | partial | Playwright capture; left: CDP target listing |
| capture_browser_scenario / observe_web_session / observe_web_execution / inspect_web_event_listeners | src/browser | webrt | partial | partial | one capture call; left: scripted scenarios and listener inventory |
| trace_web_source_location / trace_web_module_imports / compare_source_to_bundle | src/javascript | webrt | partial | partial | source map lookups; left: import graph tracing |
| compare_web_captures / compare_web_screenshots / compare_javascript_export_shapes | src/browser | webrt | missing | missing | left |
| compare_static_and_observed_endpoints | src/javascript | webrt | partial | partial | endpoints from JS plus HAR; left: automatic join |
| JS runtime: list/observe/reconcile_javascript_runtime, trace_javascript_semantics | src/javascript | webrt | missing | missing | left |
| discover_webmcp_tools | src/browser | webrt | missing | missing | left |
| inspect_electron_fuses / list_electron_targets / inspect_electron_page / capture_electron_scenario | src/electron | webrt | partial | partial | ASAR plus Electron audit incl. fuses; left: live CDP pages |
| inspect_web_network_capture (HAR) | src/captures | webrt | covered | covered | HAR summary with endpoints and secrets scan |
| inspect_pcap_capture / inspect_packet_capture / inspect_packet_fields / inspect_pcap_client | src/pcap | webrt | covered | covered | pcap and pcapng with DNS, HTTP, TLS SNI and JA3 in TS, no tshark |
| inspect_playwright_trace | src/browser | webrt | missing | missing | left |
| inspect_api_contract (OpenAPI/AsyncAPI) | src/application | webrt | missing | missing | left |
| inspect_sqlite_database | src/sqlite | webrt | covered | covered | read-only SQLite pages in TS |

## MCP tools: firmware, GPU, models, Windows, signals

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| extract_firmware | src/firmware | extras + bridges | partial | partial | x_firmware_scan carves with byte offsets, squashfs and cpio listing; binwalk bridge for full extraction |
| inspect_firmware_regions | src/firmware | extras | covered | covered | uImage, FIT, TRX, UF2, DfuSe, ESP32, Android boot, UEFI volumes |
| inspect_devicetree | src/firmware | extras | covered | covered | full FDT tree with typed props |
| hex records (Intel HEX, SREC) | src/firmware | extras | covered | covered | checksum per record, regions, optional binary image |
| inspect_gpu_code_objects | src/gpu | extras | missing | partial | x_gpu_inspect: PTX, AMD HSA code objects and SPIR-V verified on real LLVM and glslang output; CUDA fatbin and cubin readers follow the documented layout but no nvcc output was available to verify them |
| inspect_model_artifact | src/model | extras | missing | covered | x_model_inspect: GGUF metadata and tensors, safetensors header, with dtype size checks |
| inspect_windows_shortcut | src/windows | extras | missing | covered | x_lnk_inspect: LNK header, target IDList, link info, string data |
| Windows registry hive, Prefetch, Jump Lists (open requests) | issues #9865 #9423 #9866 | extras | missing | missing | left |
| inspect_signal_decoders / decode_signal_recording | src/signals | none | missing | missing | left: SDR recordings, out of scope for 1.0 |
| godot pck, iNES, wxapkg, UnityFS, Node SEA, Bun/Deno standalone | docs/*.md | extras + mobile | missing | partial | x_firmware_scan names Node SEA and wxapkg; left: entry listing |

## MCP tools: dynamic, desktop, process

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| Frida: list devices/processes, instrument, load/unload script, sessions | src/frida | bridges | partial | partial | one-shot frida runs with templates; left: persistent sessions |
| capture_process_scenario / compare_process_captures / prepare_bounded_process_capture | src/process | none | missing | missing | left |
| desktop application capture/state/export/tasks | src/desktop | none | missing | missing | left: needs a desktop harness |
| build computer (start/act/close, checkpoints, capture, consent) | src/desktop | none | missing | missing | left |
| observe_native_ui / trace_native_ui_action / capture_native_ui_scenario | src/native | none | missing | missing | left |

## Platform, packaging and process

| rea feature | where in rea | RevLens owner | before | after | how RevLens is better, or what is left |
|---|---|---|---|---|---|
| CLI with about 194 commands | src/cli, src/cliCommandNames.ts | cli | covered | covered | one CLI that also loads every package CLI_COMMANDS |
| MCP server (stdio) | src/server, src/main | mcp | covered | covered | zod 4 schemas, every package TOOLS registered |
| MCP over HTTP listener | src/main/mcpHttpArguments.ts | mcp | missing | missing | left |
| doctor / setup / uninstall / update | src/doctorRuntime.ts, src/cli | bridges + cli | covered | covered | bridge_doctor checks tools; setup writes MCP config for clients |
| server.json (MCP registry) | server.json | mcp | missing | missing | left: publish to the MCP registry |
| Claude plugin (.claude-plugin) and Codex plugin (.codex-plugin) | repo root | mcp | missing | missing | left |
| Agent skills (.agents/skills, reverse-engineer-anything) | .agents/skills | docs | missing | missing | left |
| RL agent environments (environment-build/serve/export) | src/server/environment, docs/agent-environments.md | extras | missing | partial | x_eval_* harness with ground truth on repo fixtures and scoring; left: HAR-backed replay servers |
| Agent evaluation (tests/evaluation/model-evals) | tests/evaluation | extras | missing | covered | x_eval_tasks and x_eval_score, task answers checked against verified values |
| Showcases / examples | examples/ | docs | partial | partial | samples/ plus fetch-samples.mjs; left: written showcases |
| i18n READMEs (24 locales) | website/locales | docs | missing | missing | left |
| Website | website/ | web | covered | covered | RevLens web app analyses files fully in the browser, rea site is docs only |
| Release process (release-please, CHANGELOG) | release-please-config.json | repo | partial | partial | CHANGELOG present; left: automated releases |
| Test lanes, mutation testing (stryker), conformance | tests/, stryker.config.mjs | repo | partial | partial | real-file tests against reference tools in each package; left: mutation testing |
| install.sh / portable install | install.sh | cli | partial | partial | npx works; left: single binary |

## Totals

115 rows.

| state | covered | partial | missing |
|---|---|---|---|
| before | 49 | 26 | 40 |
| after | 63 | 27 | 25 |

## Where RevLens already exceeds rea

- Runs fully in the browser: the web app and every pure TS package work in a Web Worker, rea needs a local Node process plus native providers.
- No JDK, Ghidra or Python required for core native analysis: built-in x86/x64/ARM64/ARM/Thumb disassembler with CFG, xrefs and pseudo code.
- Security findings rea does not produce: secrets detection, SBOM (CycloneDX) with OSV vulnerability lookup, attack surface and ATT&CK capability mapping, yara-lite rules.
- Report outputs for humans and CI: SARIF, CycloneDX, HTML and Markdown.
- Extension and package supply chain audits: VSIX, npm tarballs, browser extensions.
- Authenticode verification that recomputes the PE digest and checks the signature, not only listing certificates.
- Demanglers for Itanium C++, Rust legacy and v0, MSVC and Swift in pure TS, Swift verified identical to swift-demangle 6.0.3 (rea ships Swift demangling through a native helper only).
- Go symbol recovery from pclntab on stripped binaries across all Go magics, in TS.
- Claims ledger where every claim is bound to a byte range hash and can be re-verified by any reader without the original session.
- pcap DNS, HTTP, SNI and JA3 in TS with no tshark dependency.

## Top open rea requests RevLens can satisfy

| rea request | RevLens answer |
|---|---|
| #2711 Radare2 | bridges (bridge_r2_*) |
| #7993 MIPS support | disasm (proposed), extras container already parses MIPS ELF headers |
| #1558 Java reverse engineering | mobile (javap-style class reader) + bridges (jadx) |
| #3289 iOS applications | mobile (IPA) + extras (Mach-O code signature, entitlements) |
| #8121 WeChat wxapkg | extras scan detection; entry listing left |
| #1269 Codex plugin | mcp (left) |
| #8543 V8 code cache (.jsc, bytenode) | extras x_v8_inspect |
| #8911 SQLite with WAL state | webrt |
| #6337 verifiable manifest for exported bundles | extras x_ledger_export (digest chain) |
| #6333 auditable suppression rules | extras ledger status rejected with reason |
| #8472 gadget search | disasm (proposed) |
| #2298 WASM function pseudocode | disasm (proposed) |
| #9866 Jump Lists, #9423 Prefetch, #9865 registry hive | extras (left) |
| #1316 portable install | web app needs no install at all |
