# Mach-O playbook

Mach-O is the native format on macOS, iOS, watchOS and tvOS. Thin files start with `cf fa ed fe`
(64-bit) and universal (fat) files start with `ca fe ba be`.

## Recognise
- `analyze_file` reports `macho` or `macho-fat`. A fat file holds one slice per CPU; RevLens analyzes each slice.
- An app bundle executable lives at `Name.app/Contents/MacOS/Name` on macOS and `Name.app/Name` inside an IPA.

## First pass
1. `analyze_file` for slices, load commands, linked dylibs, hardening (PIE, stack guard, ARC) and findings.
2. `x_macho_inspect` for load commands, the code signature, entitlements, team id and minimum OS.
3. `get_imports` for frameworks such as `Security`, `Network`, `CoreLocation` and for `ptrace` or `sysctl` anti debug calls.
4. `x_swift_demangle` on Swift symbols, and `x_demangle` for C++ names.
5. `desktop_plist_parse` on `Info.plist` to read the bundle id, version and URL schemes.

## Code
1. `disasm_list_functions` then `disasm_pseudocode` on `_main`.
2. Objective-C selectors appear as strings; `get_strings` with `contains` finds them and `disasm_xrefs` finds their users.
3. `disasm_call_paths` from `_main` to network or keychain calls.

## Bridges that help
- `bridge_lldb_session_open` for dynamic work on macOS, only with `allowExecution: true`.
- Ghidra or Hopper for a second opinion on decompilation.

## Verify
- Entitlements and signatures are claims about bytes. Quote the offset of the code signature blob and use `verify_claim`.
