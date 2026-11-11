---
name: revlens-reverse-engineer
description: Reverse engineer a shipped file with the RevLens MCP tools. Use it when a question depends on what a binary, app package, bytecode file, JavaScript bundle, Electron app, packet capture, HAR or SQLite database actually contains, and the source code is not the answer. Covers triage, picking the right tool family by format, decompiling through external bridges when they are installed, and checking every claim against the bytes before you state it.
metadata:
  version: "1.0.0"
  server: revlens
---

# Reverse engineer a file with RevLens

RevLens reads files and reports what is in them with evidence: byte offsets, virtual addresses, section names, archive paths. Your job is to turn that evidence into an answer the user can check. Never state a fact about a file that you have not seen in a tool result.

## Before you start

- If the RevLens tools (`analyze_file`, `verify_claim` and the rest) are already in your tool list, go straight to the work. Do not run setup or doctor first.
- If they are missing, the server is not registered with this client. Tell the user and suggest `npx revlens setup <client> --write` (clients: claude-code, codex, cursor, vscode, windsurf), then a client restart. You can still use the CLI meanwhile: `npx revlens analyze <file>`.
- If the user gave a source repository and asks how the code works, read the code. RevLens is for built artifacts.

## The workflow

### 1. Triage

Call `analyze_file` with the absolute path. Read, in this order:

- `format` and hashes. The format decides the next step.
- `next`: the tool families that fit this format.
- top findings, each with an analyzer id, a severity and evidence.
- components (embedded libraries with versions), imports, hardening.

If the file is large or the result is cut, page with `list_findings`, `get_strings`, `get_imports` and `get_sections` instead of asking for everything again.

### 2. Go deeper with the tools for the format

| Format | Start with | Then |
| --- | --- | --- |
| ELF, PE, Mach-O (native code) | `disasm_info`, `disasm_list_functions` | `disasm_pseudocode` for main or the entry point, `disasm_xrefs` from interesting strings or imports, `disasm_callgraph`, `disasm_call_paths` |
| APK | `mobile_apk_report` | `mobile_manifest`, `mobile_signing`, `mobile_dex_search`, `mobile_dex_method` (smali), `mobile_native_libs`, `mobile_app_framework` |
| DEX, JAR, .class | `mobile_dex_classes` or `mobile_java_class` | `mobile_dex_xrefs`, `mobile_dex_method` |
| IPA | `mobile_ipa_info` | `mobile_app_framework`, `mobile_il2cpp_types` for Unity games |
| .NET assembly | `managed_dotnet_info` | `managed_dotnet_types`, `managed_dotnet_search`, `managed_dotnet_method_il` |
| Python .pyc, PyInstaller | `managed_pyc_disasm` or `managed_pyinstaller_list` | `managed_pyinstaller_extract` (writes files, ask first) |
| Lua, BEAM, EVM bytecode | `managed_lua_info`, `managed_beam_info`, `managed_evm_selectors` | `managed_evm_disasm` |
| JavaScript bundle, source map | `web_bundle_modules`, `web_js_endpoints` | `web_js_deobfuscate`, `web_js_beautify`, `web_sourcemap_recover` |
| Electron app, ASAR | `web_electron_audit`, `web_asar_list` | `web_asar_extract` (writes files, ask first) |
| PCAP, pcapng, HAR | `web_pcap_summary` or `web_har_summary` | `web_pcap_flows` |
| SQLite | `web_sqlite_tables` | `web_sqlite_query` (read only SELECT) |

Use `hexdump` to look at the raw bytes behind any offset you plan to cite.

### 3. Decompile through bridges when they are installed

RevLens has its own disassembler and pseudo code, which work everywhere. When the user needs real decompiled source, the bridge tools drive tools the user installed:

- Call `bridge_doctor` once to see what is available. Do not call it again in the same session unless the user installs something.
- Native code: `bridge_ghidra_decompile` (best output), `bridge_r2_decompile`, `bridge_r2_functions`, `bridge_objdump` as a second opinion.
- Android: `bridge_jadx_decompile`, `bridge_jadx_search`, `bridge_apktool_decode`.
- .NET: `bridge_ilspy_decompile`.
- A missing tool returns `available: false` with install commands. Pass those to the user and continue with the built in tools. Do not try to install software yourself.
- `bridge_frida_run`, `bridge_gdb_run` and `bridge_adb_*` run or touch live programs and devices. Only use them when the user asked for dynamic analysis of a file they trust, and say so before you call them.

When two engines disagree (for example RevLens pseudo code and Ghidra), say so and show both addresses rather than picking one silently.

### 4. Check before you state

Before you write a fact into your answer, call `verify_claim` with the claims you are about to make. Supported claims:

- `contains-string` (value), `imports-symbol` (symbol, optional library), `has-section` (name)
- `format-is` (format), `sha256-is` (value), `bytes-at` (offset, hex), `uses-component` (name, optional version)

Keep only claims that come back `VERIFIED`. Drop or rephrase `REFUTED` ones. For `UNKNOWN`, say the tools could not confirm it. Claims about behavior (what a function does) cannot be verified this way, so cite the function address and the pseudo code lines instead.

### 5. Report

Write a short answer:

1. What the file is (format, architecture, version, signer when known).
2. What it does or contains, answering the user's question.
3. Risks or notable findings, by severity.
4. Evidence for every point: offset, address, section, archive path or tool name. Example: "Talks to api.example.com (string at file offset 0x1a2f0, verified)".
5. What you could not establish, and what would settle it (for example installing Ghidra for a full decompile).

## Rules

- Tools that write files or reach the network say so in their annotations. Ask before you call them.
- Never run the analysed program unless the user asked for dynamic analysis and the bridge requires their consent flag.
- Prefer paging (`limit`, `offset`) over large results.
- Do not guess offsets or addresses. If you need one, get it from a tool.

See [the tool map](references/tool-map.md) for every tool name, grouped by area.
