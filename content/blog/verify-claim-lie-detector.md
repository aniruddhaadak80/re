---
title: "Give your AI agent a lie detector: verify_claim"
date: 2026-11-07
summary: "AI agents describe binaries with confidence they have not earned. verify_claim checks one specific statement against the bytes and answers VERIFIED, REFUTED or UNKNOWN with evidence. Here is how it works, real verdicts on esbuild, and the one line rule we add to every agent."
tags: [ai-agents, mcp, verification, safety]
cover: /re/media/cover-verify-claim.svg
author: Aniruddha Adak
---

# Give your AI agent a lie detector

Ask a capable model to look at a Windows executable and you will get a fluent answer. It will mention the sections, the imports, maybe a packer, maybe some suspicious APIs. Much of it will be right. Some of it will be pattern matching on what binaries like this usually contain, delivered in exactly the same confident tone.

That is not a flaw you can prompt away. A language model predicts plausible text, and "this binary uses CreateRemoteThread" is very plausible text about a Windows binary. The problem is not that the model is sometimes wrong. The problem is that you cannot tell which sentences are the wrong ones.

## A claim is a test, not a vibe

`verify_claim` asks the agent to turn a sentence into something checkable. Instead of "it probably injects code", the agent sends:

```json
{ "kind": "imports-symbol", "library": "kernel32.dll", "symbol": "CreateRemoteThread" }
```

RevLens checks it against the file and the parsed report, and answers with one of three verdicts and the evidence:

```json
{
  "verdict": "REFUTED",
  "reason": "The symbol is not in the import table or anywhere in the file.",
  "evidence": []
}
```

There are seven claim kinds today: `contains-string`, `bytes-at`, `format-is`, `sha256-is`, `imports-symbol`, `has-section` and `uses-component`. Each is deterministic. Run it twice, get the same answer. Run it on another machine, same answer.

## Real verdicts on a real binary

We ran a set of claims a model might make about esbuild 0.24.0 for Windows, a 10 MB Go executable from npm:

```text
Claim                                         Verdict    Reason
imports CreateRemoteThread                    REFUTED    not in the import table or anywhere in the file
imports WriteProcessMemory                    REFUTED    not in the import table or anywhere in the file
imports VirtualAlloc                          VERIFIED   kernel32.dll imports VirtualAlloc
has a UPX0 section (packed with UPX)          REFUTED    sections are .text, .rdata, .data, .pdata, .xdata, .idata, .reloc, .symtab
has a .text section                           VERIFIED   .text is at offset 1536, 5455872 bytes
is an ELF file                                REFUTED    magic bytes identify the file as pe
contains "github.com/evanw/esbuild"           VERIFIED   ASCII string at offset 5586655
starts with 4d5a                              VERIFIED   the bytes match exactly
sha256 is 26c4c83a...598de4                   VERIFIED   the SHA-256 matches
uses golang.org/x/sys                         REFUTED    no evidence of golang.org/x/sys was found
```

Look at the last line. The macOS build of the same esbuild release does list `golang.org/x/sys` in its Go build info, and RevLens verifies it there. The Windows build does not record it. A model that "knows" esbuild depends on `x/sys` would state it for both. The bytes say it is true for one file and not the other. That is the level of precision you want in a report someone will act on.

## Why there is an UNKNOWN

The most important verdict is the third one. If a symbol is not in the import table, but its name does appear somewhere in the file, `verify_claim` says:

```text
UNKNOWN  The name appears in the file but not in the parsed import table.
         It may be resolved at run time.
```

That is real ambiguity. Malware often hides its imports by looking them up with `GetProcAddress` at run time, and Go itself loads many system functions lazily. Static analysis cannot settle that question, so the tool refuses to pretend. An agent that gets `UNKNOWN` should say "I could not confirm this statically" instead of picking a side.

We would rather give an honest "do not know" than a confident guess. That is the property we want from our agents too.

## The rule we add to every agent

This goes into `CLAUDE.md`, `AGENTS.md` or the system prompt of any agent that has RevLens:

```text
When you analyze a file with RevLens, call verify_claim before you state any of these as fact:
an imported API, a section name, a string in the file, the file format, a hash, or a dependency version.
If the verdict is REFUTED, correct yourself. If it is UNKNOWN, say so plainly.
```

In practice this changes the shape of the final answer. Statements come with offsets. Corrections happen before you see them. And when the agent does not know, it says so, because the tool gave it a way to know that it does not know.

## How it works under the hood

Most claims need nothing but the bytes:

- `contains-string` searches for the ASCII form and then the UTF-16LE form, and returns the offset of the first hit.
- `bytes-at` compares the hex you claim with the bytes at that offset, and on a mismatch tells you what is really there.
- `format-is` runs the same magic byte detection as the analyzer.
- `sha256-is` hashes the file with our pure TypeScript SHA-256.

The structural claims use the report from `analyze`:

- `imports-symbol` walks the parsed import table, optionally for one library.
- `has-section` looks up section and segment names, and lists the real ones when it refutes.
- `uses-component` looks for the package in the SBOM across the report and its archive children, with an optional version check.

All of it is about 60 lines in `packages/core/src/verify.ts`. It is small on purpose. A verifier you cannot read is just another thing to trust.

## Try it

From your agent, after adding the MCP server:

```bash
claude mcp add revlens -- npx -y @revlens/mcp
```

Then ask: "Is this binary packed with UPX? Check with verify_claim before you answer."

From the terminal:

```bash
npx revlens verify esbuild.exe --claim '{"kind":"has-section","name":"UPX0"}'
```

From code:

```ts
import { analyze, verifyClaim } from '@revlens/core';
const report = await analyze(bytes, { name: 'esbuild.exe' });
verifyClaim(bytes, { kind: 'imports-symbol', symbol: 'CreateRemoteThread' }, report);
```

The idea of a deterministic "propose, then verify" step is not ours alone. The [reverify](https://github.com/2akouwu/reverify) project does it in Python for native binaries, and REA's evidence first results follow the same spirit. We think it should be a default part of every agent that touches files, and we hope `verify_claim` makes that a little easier.
