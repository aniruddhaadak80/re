# PE playbook

PE is the Windows format for EXE, DLL, SYS and many installers. It starts with `MZ`, and the
offset at 0x3c points to `PE\0\0`.

## Recognise
- `analyze_file` reports `format: pe` (or `dotnet` when a CLR header is present; use the .NET playbook then).
- Installers (NSIS, Inno Setup, MSI wrappers) show an overlay. Check `x_pe_inspect` for overlay size and the `x_container` tool for embedded archives.

## First pass
1. `analyze_file` for hashes, imphash, sections with entropy, hardening (ASLR, DEP, CFG, SafeSEH) and findings.
2. `x_pe_inspect` for headers, rich header, load config, TLS callbacks, delay imports and overlay.
3. `x_pe_authenticode` to check the signature, signer chain and whether the hash in the signature matches the file.
4. `x_pe_resources` for version info, manifests, icons and embedded files.
5. `get_imports` with `contains` for `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `WinHttp`, `Crypt`, `RegSetValue`.

## Code
1. `disasm_list_functions`, then `disasm_pseudocode` on the entry point and on `WinMain` or `DllMain` when found.
2. TLS callbacks run before the entry point. Read them first if `x_pe_inspect` lists any.
3. `disasm_xrefs` from a suspicious import shows every caller.
4. `disasm_indirect_targets` resolves jump tables and simple register calls.

## Signs worth reporting
- High entropy sections with a small import table often mean packing. Name the packer only if a rule or section name proves it.
- A valid signature whose signer does not match the vendor claimed in the version info.
- Writable and executable sections.

## Bridges that help
- Ghidra headless (`bridge_ghidra_decompile`) and IDA (`bridge_ida_run`) for deeper decompilation.
- ILSpy (`bridge_ilspy_decompile`) when the file is really .NET.

## Verify
- Use `verify_claim` with `imports-symbol` and `has-section`, and cite file offsets from `get_sections`.
