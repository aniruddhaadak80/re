---
title: Verify claims
description: Why AI agents should check what they say about a file against its bytes, and how verifyClaim and the verify_claim tool do it.
order: 9
---

# Verify claims

Language models are good at reverse engineering conversations and bad at being certain. An agent that has seen a thousand write ups about process injection will happily tell you that a binary "uses CreateRemoteThread" because it looks like the kind of binary that would. Sometimes it is right. Sometimes it is a confident guess.

`verifyClaim` turns those guesses into checked facts. The agent states one specific claim, RevLens checks it against the bytes and the parsed report, and returns one of three verdicts with evidence:

- **VERIFIED**: the bytes confirm the claim. The evidence says where.
- **REFUTED**: the bytes contradict the claim. The reason says what is there instead.
- **UNKNOWN**: RevLens cannot settle it from static data, and says why.

There is no "probably". That is the point.

## Claim kinds

| Kind | Fields | Checks |
| --- | --- | --- |
| `contains-string` | `value` | The string appears as ASCII or UTF-16LE. Returns the offset. |
| `bytes-at` | `offset`, `hex` | The exact bytes at an offset. On a mismatch it returns the bytes that are really there. |
| `format-is` | `format` | The format from magic bytes, such as `pe`, `elf` or `xpi`. |
| `sha256-is` | `value` | The SHA-256 of the file. |
| `imports-symbol` | `symbol`, optional `library` | The symbol is in the parsed import table. Needs the report. |
| `has-section` | `name` | A section or segment with that name exists. Needs the report. |
| `uses-component` | `name`, optional `version` | A component with that name (and version) was detected. Needs the report. |

The three structural kinds need the analysis report. Without it they return `UNKNOWN` with "Pass the analysis report". The MCP `verify_claim` tool and the CLI `verify` command always pass it.

## Real verdicts on esbuild 0.24.0 for Windows

```text
imports-symbol kernel32.dll CreateRemoteThread  REFUTED   The symbol is not in the import table or anywhere in the file.
imports-symbol kernel32.dll VirtualAlloc        VERIFIED  kernel32.dll imports VirtualAlloc.
has-section UPX0                                REFUTED   No section is named UPX0. Sections: .text, .rdata, .data, .pdata, .xdata, .idata, .reloc, .symtab.
has-section .text                               VERIFIED  Section .text is at offset 1536, 5455872 bytes.
format-is elf                                   REFUTED   Magic bytes identify the file as pe, not elf.
contains-string github.com/evanw/esbuild        VERIFIED  Found the ASCII string at offset 5586655.
bytes-at 0 4d5a                                 VERIFIED  The bytes match exactly.
sha256-is 26c4c83a...598de4                     VERIFIED  The SHA-256 matches.
```

Notice the first line. "This binary injects with CreateRemoteThread" is a natural thing for a model to say about any Windows executable that starts threads. The bytes say no: the name is not in the import table, and it is not anywhere else in the file either.

## When the answer is UNKNOWN

`imports-symbol` has a middle case. If the name is not in the import table but does appear somewhere in the file, the verdict is `UNKNOWN` with the reason "The name appears in the file but not in the parsed import table. It may be resolved at run time." That is common in malware that calls `GetProcAddress` to hide its imports, and also in Go binaries that load system DLLs lazily. Static analysis cannot close that gap, so RevLens does not pretend to. Hand that question to a debugger or a deep engine.

`uses-component` returns `UNKNOWN` when the package is present but the claim names a version RevLens could not read.

## Using it from code

```ts
import { analyze, verifyClaim } from '@revlens/core';

const report = await analyze(bytes, { name: 'esbuild.exe' });
const result = verifyClaim(bytes, { kind: 'has-section', name: 'UPX0' }, report);
// { verdict: 'REFUTED', claim: {...}, reason: 'No section is named UPX0. Sections: ...', evidence: [] }
```

## Using it from the CLI

```bash
npx revlens verify esbuild.exe --claim '{"kind":"imports-symbol","library":"kernel32.dll","symbol":"VirtualAlloc"}'
```

## Using it from an agent

Give your agent a rule in its system prompt or project instructions, such as `CLAUDE.md` or `AGENTS.md`:

```text
When you analyze a file with RevLens, call verify_claim before you state any of these as fact:
an imported API, a section name, a string in the file, the file format, a hash, or a dependency version.
If the verdict is REFUTED, correct yourself. If it is UNKNOWN, say so plainly.
```

This costs a few small tool calls and makes every statement in the final answer traceable to an offset a human can check in seconds with `hexdump`.

## Why this matters

When an agent writes a security report, people act on it. They block a vendor, page an on call engineer, or ship a fix. A wrong claim in that report costs real time and trust. Verifying claims against bytes is cheap, deterministic and repeatable. It does not make the agent smarter. It makes the agent honest about what it actually knows, which is the property you want most from a tool that works on your behalf.

The idea of a deterministic "propose, then verify" gate is not new. The [reverify](https://github.com/2akouwu/reverify) project does this in Python for native binaries, and REA's evidence first results follow the same spirit. RevLens brings it to TypeScript, the browser and every format it parses.
