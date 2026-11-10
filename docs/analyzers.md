---
title: Analyzers
description: What each of the 15 RevLens analyzers reads, what it reports, and where its limits are.
order: 4
---

# Analyzers

An analysis is one pass over the bytes. RevLens first detects the format from magic bytes and computes the hashes, then runs 15 analyzers in a fixed order. Each analyzer has an `applies` check, so a PE file never runs the ELF parser and a JS bundle never runs the PE parser.

The order matters. Structure parsers run first so that later analyzers can use their sections and imports. Content analyzers run next, then containers, then supply chain, and the behavior and rule analyzers run last.

If an analyzer throws, RevLens catches it and adds an `info` finding named "`<analyzer>` could not finish". The rest of the report is still valid. A broken file never takes the whole analysis down.

You can run a subset with `analyze(bytes, { analyzers: ['pe', 'strings'] })`. Format detection and hashing always run.

## Before the analyzers: format and hashes

**Format detection** reads magic bytes first and falls back to the file name and content sniffing. It knows `elf`, `pe`, `macho`, `macho-fat`, `wasm`, `zip`, `jar`, `apk`, `crx`, `xpi`, `vsix`, `npm-tgz`, `gzip`, `tar`, `asar`, `js`, `sourcemap`, `json`, `pdf`, `pyc`, `dex`, `class`, `text` and `unknown`. ZIP files are split into JAR, APK, XPI, VSIX and CRX by extension and by the member names inside (`AndroidManifest.xml` plus `classes.dex`, `extension.vsixmanifest`, `META-INF/MANIFEST.MF`).

**Hashes** are MD5, SHA-1 and SHA-256, plus a TLSH-like locality digest and a CTPH fuzzy hash in the ssdeep style. All five are pure TypeScript and give the same result in every runtime. MD5, SHA-1 and SHA-256 match standard tools exactly. The TLSH-like and CTPH digests are RevLens' own implementations: use them to compare files with each other in RevLens, not against digests from other tools.

## elf

**Reads:** the ELF header, the section header table, `.dynamic`, `.dynstr`, `.dynsym` and `.interp`.

**Reports:** architecture (x86, x86-64, ARM, AArch64, RISC-V, MIPS, PowerPC and more), 32 or 64 bit, endianness, every section with its offset, size, address and entropy, the `DT_NEEDED` libraries, imported dynamic symbols and exported global symbols. The hardening block has the ELF type, `pie`, `stripped` (no `.symtab`), `dynamicallyLinked`, `nxLikely` and `relroLikely`.

**Real example:** `/bin/ls` for AArch64 reports `DYN (PIE or shared object)`, stripped, dynamically linked, 4 needed libraries and 130 imported symbols.

**Limits:** NX and RELRO are inferred from section presence, not from program headers, so they are named "likely". Files with no section table (some packed or hand crafted ELFs) give an almost empty report.

## pe

**Reads:** the DOS header, PE header, optional header, data directories, the section table, the import directory and the certificate directory.

**Reports:** machine type, subsystem, sections with entropy, imports per DLL (by name or `ordN`), and the import hash. The hardening block has `aslr`, `dep_nx`, `cfg`, `highEntropyVA`, `signed` and `imphash`. A present certificate table adds an `info` finding with its size and offset.

**About imphash:** RevLens follows the pefile convention: lowercase DLL name without its extension, a dot, the lowercase function name, joined with commas, then MD5. For esbuild 0.24.0 on Windows, RevLens and `pefile` both give `b196866f0bf37f1f128fa153413b744f`, and for 0.23.0 both give `07361a3a7f515bf56ca93120b2aca73b`.

**Limits:** RevLens checks that an Authenticode blob is present. It does not validate the signature chain. Rich header, resources, exports, delay imports, TLS callbacks and overlays are not parsed yet.

## macho

**Reads:** the Mach-O header and load commands, or the fat header for universal binaries.

**Reports:** CPU type, bits, endianness, segments with offsets, sizes and entropy, linked dylibs (`LC_LOAD_DYLIB` and weak dylibs), whether there is an `LC_CODE_SIGNATURE` and whether there is an `LC_MAIN` entry point. For a universal binary it lists the architecture of each slice.

**Real example:** esbuild 0.24.0 for macOS on Apple silicon is `AArch64`, has 5 segments, links 4 dylibs and carries a code signature.

**Limits:** RevLens reports that a code signature exists, not who signed it. Slices inside a fat binary are listed but not analyzed one by one.

## wasm

**Reads:** every section of a WebAssembly module.

**Reports:** a count of each section type, imports grouped by module with their kind (`func`, `table`, `memory`, `global`), exports, and the size of each custom section such as `producers`, `name` or `go:buildid`.

**Real example:** `esbuild.wasm` 0.24.0 imports 21 functions from the `gojs` module and exports `run`, `resume`, `getsp` and `mem`, the shape of a Go program compiled with `GOOS=js GOARCH=wasm`.

**Limits:** no disassembly of function bodies.

## buildinfo

**Reads:** the Go build info block (the `\xff Go buildinf:` magic) and rustc markers in ELF, PE and Mach-O files.

**Reports:** the Go toolchain version, the main package path and module, build settings such as `-trimpath` and `GOOS`, and each `dep` line as a Go component with a `pkg:golang/` purl. For Rust it notes the rustc build markers.

**Real example:** both the Windows and macOS esbuild 0.24.0 binaries report `Built with go1.23.1`, main path `github.com/evanw/esbuild/cmd/esbuild`. The macOS one also lists `golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8`.

**Limits:** cargo-auditable data is detected by its markers but the compressed dependency list is not decoded yet. Very old Go binaries (before Go 1.18) store build info differently and may only show the version.

## entropy

**Reads:** every byte, split into 64 blocks (at least 256 bytes each).

**Reports:** `meta.entropyMap` with the block size and one Shannon entropy value per block. For binaries over 4 KB it adds `Very high overall entropy` (above 7.2 bits per byte overall, medium) or `Large high entropy regions` (a quarter or more of the blocks above 7.2, low). It looks for packer and protector markers: UPX, ASPack, MPRESS, Themida or WinLicense, VMProtect, Enigma Protector, PECompact and Petite. For text it fingerprints javascript-obfuscator string arrays and hex identifiers, JSFuck, the Dean Edwards packer, JJencode and AAencode, and `eval` of decoded data.

**Limits:** compressed containers (ZIP, gzip, PDF and friends) are expected to be near 8 bits per byte, so the high entropy findings skip them. A packer marker is a string match, so a tool that mentions "UPX" in its help text can trip it. The evidence offset makes that easy to spot.

## strings

**Reads:** every byte, looking for runs of at least 5 printable ASCII characters and the same in UTF-16LE.

**Reports:** up to `maxStrings` (default 400) strings, tagged ones first, then the longest. Tags are `url`, `email`, `registry`, `guid`, `command`, `ip`, `path` and `version`. `meta.stringsTotal` and `meta.stringsTagged` give the full counts.

**Limits:** RevLens scans at most 20,000 raw strings per file. Go and Rust binaries store literals end to end without separators, so a long run may hold many joined strings.

## archive

**Applies to:** ZIP, JAR, APK, CRX (v2 and v3), XPI, VSIX, npm tarballs, gzip, tar and Electron ASAR.

**Reads:** the central directory or tar headers, and decompresses members with the platform `DecompressionStream`.

**Reports:** every member name with sizes in `meta.members`, a `Possible decompression bomb` finding when members expand more than 100 to 1 and past 50 MB, and a `Path traversal member name` finding for zip slip names such as `../../evil`. It then picks up to 60 important members (manifests, `package.json`, scripts, maps, WASM, native libraries, DEX) and analyzes each as a child report. Child components, capabilities and non info findings bubble up to the parent with the member path in their evidence.

**Real example:** uBlock Origin 1.76.0 for Firefox has 671 members. RevLens analyzes 60 of them, including four WASM modules (`lz4-block-codec.wasm`, `publicsuffixlist.wasm`, `biditrie.wasm`, `hntrie.wasm`).

**Limits:** recursion stops at depth 2. Members over 24 MB are listed but not analyzed. Encrypted ZIP members cannot be read.

## extaudit

**Applies to:** CRX, XPI, VSIX, npm tarballs and plain ZIP files.

**Reads:** the top level `manifest.json` and `package.json`.

**Reports for browser extensions:** a finding for each risky permission (`<all_urls>`, `debugger`, `nativeMessaging`, `proxy`, `management` and `file:///*` are high, `webRequest`, `webRequestBlocking`, `cookies`, `history`, `clipboardRead`, `scripting` and `privacy` are medium, `tabs`, `downloads` and `declarativeNetRequest` are low), `Extension can read and change every site` when host permissions cover everything, a weak content security policy, and Manifest V2.

**Reports for VS Code extensions:** the publisher, version and activation events, and a medium finding when the extension activates on `*` or `onStartupFinished`.

**Reports for npm packages:** a finding for each `preinstall`, `install`, `postinstall` or `prepare` script, raised to high when the script uses `curl`, `wget`, a URL, `node -e`, `eval` or `base64`. It also flags scripts that load remote JavaScript.

**Real example:** see the uBlock Origin results in [the blog post](../content/blog/inside-ublock-origin.md): two high, three medium and three low findings, all from the manifest.

**Limits:** permissions are judged on their own. RevLens cannot know whether an extension needs them for its stated purpose. That part is your call.

## sbom

**Applies to:** JavaScript and `package.json` files, including those found inside archives.

**Reads:** banner comments such as `/*! jQuery v3.7.1`, `@license` comments, runtime version constants (React, react-dom `reconcilerVersion`, jQuery, lodash `VERSION`, Vue, Angular, Moment, axios, core-js) and `node_modules/<name>/` paths left in bundles.

**Reports:** components with `ecosystem: 'npm'`, version when known, a purl such as `pkg:npm/jquery@3.7.1`, a confidence between 0 and 1 (1 for `package.json`, 0.9 for banners, 0.75 for runtime constants, 0.6 for module paths) and the evidence offset. It also records the bundler in `meta.bundler` when it can tell (webpack, vite, esbuild, systemjs, umd, amd, parcel).

**Real example:** `react-dom.production.min.js` gives `react-dom@18.3.1`, `jquery.min.js` gives `jquery@3.7.1`, and the Red Hat YAML VSIX gives 19 components including `vscode-languageclient@10.1.2` and `yaml-language-server@2.1.1-4bf9c81.0`.

**Limits:** bundles that strip all comments and version strings give little or nothing. Dependency ranges from `package.json` are recorded with their leading `^` or `~` removed and a lower confidence.

## sourcemap

**Applies to:** JavaScript and `.map` files.

**Reads:** the `sourceMappingURL` comment, inline `data:` URI maps and standalone map files.

**Reports:** for an external reference, a low finding with the map URL. For a map it can read, a finding that says how many original files it lists and what share ships full original code in `sourcesContent`, plus the first 500 source paths in `meta.sourcemap.tree`. Coverage above zero is medium, because the original project can be rebuilt.

**Real example:** a small esbuild bundle built with `--sourcemap=inline` reports `Source map recovers 100% of original sources` with all three original file paths. The jQuery 3.7.1 map lists one source, `jquery.js`, without embedded code, so it reports 0%.

**Limits:** RevLens does not fetch external maps. Point it at the `.map` file yourself.

## secrets

**Applies to:** text files, and to the extracted strings of binaries.

**Reports:** AWS access key ids and secret keys, Google API keys and OAuth client secrets, GitHub tokens, Slack tokens and webhooks, Stripe secret keys, OpenAI and Anthropic API keys, npm tokens, SendGrid keys, Twilio account SIDs, JSON Web Tokens, private key blocks, and generic `password = "..."` style assignments that pass an entropy check and are not obvious placeholders.

**Redaction:** the report never contains the full value. Evidence looks like `AKIA...XQ (20 chars)`.

**Limits:** pattern based, so a test fixture with a real looking fake key will still be reported. That is on purpose: treat every hit as leaked until you know otherwise.

## surface

**Applies to:** text files, and to strings of binaries.

**Reports:** in `meta.surface`: URLs (with common noise such as w3.org schemas and license links removed), hosts, API paths that start with `/api`, `/v1`, `/graphql`, `/auth` and similar, GraphQL operation names, Electron IPC channel names, feature flag keys and `localStorage` or `sessionStorage` keys. It adds a low finding for plain `http://` endpoints and an info finding for IPC channels.

**Limits:** in Go binaries, joined literals can make a URL look longer than it is. esbuild reports `http://.pnp.jsbaseUrlUpgradeTrailersocks5hHEADERS` for exactly this reason. Minifiers rename function calls, so feature flag helpers are often not recognizable in production bundles.

## capa

**Reads:** imported symbols, extracted strings and text.

**Reports:** capabilities, each with a namespace, an ATT&CK id where one fits, and the matched evidence. The current set: create a process (T1106), inject into another process (T1055), access the network (T1071), resolve DNS, read or write the registry (T1112), persist via run key or service (T1547), encrypt or decrypt data (T1486), capture the screen (T1113), log keystrokes (T1056.001), enumerate files, detect a debugger (T1622), detect a virtual machine (T1497), evaluate code at runtime (T1059), read environment secrets (T1552) and contact a hardcoded host (T1071). When injection and network access appear together, it adds a high `Networked process injector behavior` finding.

**Limits:** this is capa-lite. It works from names and strings, not from disassembly, so it can see that `WriteProcessMemory` is imported but not how it is used. Short API names only count when they are real imports, which keeps English prose from matching.

## yara

**Reads:** every byte of files up to 64 MB.

**Reports:** a finding per matching rule from the starter pack plus any rules you pass with `--rules` or `AnalyzeOptions.rules`. The finding takes its severity, description and ATT&CK id from the rule's `meta`. Rule names are listed in `meta.ruleMatches`.

**Starter pack:** `UPX_Packed`, `Embedded_PE_Payload`, `Process_Injection_APIs`, `Keylogger_APIs`, `Anti_Debug_Windows`, `Linux_Ptrace_AntiDebug`, `Reverse_Shell_Strings`, `Crypto_Constants`, `Ransom_Note_Language`, `Crypto_Miner`, `JS_Eval_Decoded`, `NPM_Credential_Stealer` and `Discord_Token_Grabber`.

**Real example:** `Crypto_Constants` matches all three esbuild builds (PE, Mach-O and WASM), because the Go standard library carries the SHA-256 round constants.

**Limits:** see [Rules](rules.md) for the supported language.

## Optional: osv

Not part of `analyze`. `lookupOSV(components)` sends the components that have an exact version to the OSV.dev batch API and returns findings with the advisory id, CVE alias, summary and severity. See [SBOM and vulnerabilities](sbom-and-vulns.md).
