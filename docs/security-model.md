---
title: Security model
description: What RevLens does with your files, what it never does, and how it parses hostile input safely.
order: 11
---

# Security model

People point RevLens at files they do not trust. That shapes every design choice, and this page writes those choices down.

## Your files stay with you

- **The web app never uploads your file.** The bytes go from the file picker into a Web Worker on your device and nowhere else. There is no backend. The site is static files on GitHub Pages.
- **The CLI and MCP server read local paths** and keep results in memory or in the output file you name.
- **No telemetry.** RevLens does not phone home, count runs or report errors anywhere.

## The one network call

`lookupOSV` sends package names, ecosystems and versions to `https://api.osv.dev` to look up known vulnerabilities. It runs only when you ask for it: `--osv` on the CLI, the `check_vulns` MCP tool, or the vulnerability lookup in the web app, which you start yourself. It never sends the file, its name or its hashes.

Everything else in `@revlens/core` is a pure function of the bytes. The core has no `fetch`, no file system access and no Node built-ins in its source.

## RevLens never runs the code it looks at

RevLens is static analysis only. It does not execute binaries, evaluate JavaScript, load WebAssembly modules, run install scripts or open documents. Parsing a malicious file is the most it ever does with it.

The JavaScript analyzers work on text with regular expressions. They never call `eval`, `new Function` or `import()` on the content.

## Safe parsing

Parsers for hostile input have to assume every length and offset is a lie. Here is how RevLens handles that:

- **Memory safe by default.** RevLens is TypeScript, so a lying offset can never read outside the buffer. Integer reads go through a `DataView`, which throws a `RangeError` instead of reading out of bounds, and that error is caught (see below). The parsers also check the important offsets before they read, so a section header that points past the end of the file is recorded with zero entropy instead of stopping the parse.
- **Hard caps on loops.** PE import parsing stops after 1024 descriptors and 4096 thunks per DLL. ELF symbol parsing stops at 20,000 symbols. Mach-O fat headers read at most 32 slices. Strings stop at 20,000 raw strings.
- **Errors are contained.** Each analyzer runs inside a `try` block. If one fails, it becomes an `info` finding and the rest of the report is still produced.
- **Decompression limits.** Archive members are inflated with the platform `DecompressionStream`, with a hard limit of 256 MB of output per member. Members larger than 24 MB are listed but not analyzed. A ratio above 100 to 1 over 50 MB raises a `Possible decompression bomb` finding.
- **Recursion limits.** Archives inside archives are analyzed at most two levels deep, and at most 60 members per archive.
- **No path writes.** RevLens never extracts archive members to disk, so zip slip names like `../../etc/passwd` cannot overwrite anything. It reports them as a finding instead.
- **Size limits for heavy scans.** The rule engine skips files over 64 MB and runs regex strings over the first 16 MB. Text analyzers read at most the first 2 to 12 MB of a text file, depending on the analyzer.

## Secrets are redacted

When the secrets analyzer finds a credential, the report keeps only the first four and last two characters and the length, such as `ghp_...9Z (40 chars)`. The full value never appears in JSON, Markdown, HTML or SARIF output, so a report is safe to paste into an issue or upload to code scanning.

The offset is still there, so you can find the value in the file yourself when you need to rotate it.

## Reports are safe to open

The HTML report escapes every value taken from the file, uses no scripts and loads no external assets. Opening a report about a hostile file does not run anything from that file.

## What RevLens does not promise

- **It is not an antivirus.** A clean report means RevLens found nothing it knows how to find. It does not mean the file is safe.
- **Signatures are detected, not validated.** "Authenticode signature present" and "Code signature present" mean the structure exists. Use `signtool`, `osslsigncode` or `codesign` to check who signed it and whether the chain is trusted.
- **Severity is a hint.** A permission that is risky in general may be exactly what an extension needs.
- **Static analysis has blind spots.** Code that is decrypted, downloaded or resolved at run time is invisible until it runs. When RevLens suspects this, for example with high entropy or a packer marker, it says so.

## Handling samples

If you work with real malware, use the same care you would with any other tool: an isolated machine or VM, no shared folders with your main system, and no double clicking. RevLens itself will not run the sample, but your operating system might if you open it by mistake.

## Reporting a vulnerability in RevLens

If you find a way to make RevLens crash, hang, use unbounded memory, or leak data from a file, we want to hear about it. Please follow [SECURITY.md](https://github.com/aniruddhaadak80/re/blob/main/SECURITY.md) and report it privately.
