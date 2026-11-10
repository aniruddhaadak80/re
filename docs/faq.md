---
title: FAQ
description: Short answers to the questions people ask most about RevLens.
order: 12
---

# FAQ

## Is RevLens a decompiler?

No. RevLens parses file structure, extracts strings, matches rules and builds reports. It does not turn machine code back into C. When you need that, use Ghidra, IDA, Binary Ninja or radare2, or their MCP servers. RevLens is the quick first look that tells you whether you need them and where to start.

## Is my file uploaded anywhere?

No. In the browser it is analyzed in a Web Worker on your device. The CLI and MCP server read local files. The only network call is the optional OSV.dev vulnerability lookup, and it sends package names and versions, never the file. Details are in the [security model](security-model.md).

## Why pure TypeScript?

Because it runs everywhere without an install step: a browser tab, a CI runner, a serverless function, an agent sandbox with no compiler. No `node-gyp`, no Python, no Java, no native `yara`. The cost is that we write our own parsers, which is also why they are small and easy to read.

## How fast is it?

On Node 22, real numbers from our docs runs: `jquery.min.js` (88 KB) in about 70 ms, `lodash-4.17.21.tgz` (1054 members) in about 110 ms, the Red Hat YAML VSIX in about 1.2 seconds, uBlock Origin (671 members) in about 1.4 seconds, and the 10 MB `esbuild.exe` in about 1.5 seconds. Hashing and the rule scan take most of the time on large binaries.

## Does the imphash match other tools?

Yes. RevLens follows the pefile convention. For the Windows build of esbuild 0.24.0 both give `b196866f0bf37f1f128fa153413b744f`, and for 0.23.0 both give `07361a3a7f515bf56ca93120b2aca73b`.

## Can I use my existing YARA rules?

Often, yes. Text, hex and regex strings with the common modifiers and conditions work. Modules such as `pe` and `math`, `for` loops and hex alternations do not work yet. The [rules page](rules.md) lists exactly what is supported.

## Why is there a finding for a weird URL in my Go binary?

Go stores string literals back to back without separators, so a URL prefix runs straight into the next literal. You will see things like `http://.pnp.jsbaseUrlUpgradeTrailersocks5hHEADERS` in esbuild. RevLens reports what the bytes contain and gives you the evidence. It is a known source of low severity noise, and we are working on splitting Go literals better.

## Does a high severity finding mean the file is malicious?

No. Severity says how much power something gives, not whether it is abused. uBlock Origin asks for `<all_urls>` because a content blocker has to see every request. That earns a high finding, and it is still a well respected extension. Read the detail and the evidence, then decide.

## Does a clean report mean the file is safe?

No. RevLens only finds what it knows to look for. Code that is downloaded, decrypted or resolved at run time can hide from any static tool. Use RevLens to decide what deserves a closer look, not as a final verdict.

## Which formats are supported?

ELF, PE, Mach-O (thin and universal), WebAssembly, ZIP, JAR, APK, CRX, XPI, VSIX, npm tarballs, gzip, tar, Electron ASAR, JavaScript, source maps, JSON and text. PDF, DEX, Java class and `.pyc` files are detected by format but not parsed deeply yet.

## How does RevLens relate to REA?

RevLens is inspired by [REA](https://github.com/morluto/rea) (MIT) and written from scratch. It is not affiliated with REA and is not an official REA project. REA is a broad reverse engineering platform that drives deep engines like Hopper, Ghidra and IDA. RevLens is a small, zero install triage and supply chain layer. Many people will want both: RevLens for the first pass and for CI, REA for the deep dive. See the [comparison](comparison.md).

## Can my agent use RevLens and Ghidra MCP at the same time?

Yes, and that is a good setup. Let the agent call RevLens first to triage, list imports, check for packers and verify claims, then use the Ghidra, IDA or radare2 server to decompile the functions that matter.

## Does it work offline?

Yes. Everything except the OSV lookup works without a network. After the web app loads once, you can analyze files offline in the same tab.

## How do I report a false positive?

Open an issue with the bug template, include the finding id (such as `surface.http` or `rule.Crypto_Constants`) and, if you can share it, where the file comes from. Public files from npm or a store are ideal because we can add them to our tests.

## Who maintains RevLens?

[Aniruddha Adak](https://github.com/aniruddhaadak80) started it, and contributors are very welcome. See [CONTRIBUTING.md](https://github.com/aniruddhaadak80/re/blob/main/CONTRIBUTING.md).

## What is the license?

MIT.
