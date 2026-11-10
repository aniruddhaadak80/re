---
title: "Introducing RevLens: look inside any file, anywhere JavaScript runs"
date: 2026-11-10
summary: "RevLens is a zero install reverse engineering lens for people and AI agents. One pure TypeScript core runs in your browser, your terminal and your agent, and answers the first ten questions about a file in about a second."
tags: [launch, reverse-engineering, mcp, supply-chain]
cover: /re/media/cover-introducing-revlens.svg
author: Aniruddha Adak
---

# Introducing RevLens

Every time we looked at an unfamiliar file, the first ten minutes went the same way. Install something. Find the right flags. Run three tools for three questions. Copy hashes into a notes file. By the time we knew what the file even was, we had lost the thread of why we were looking at it.

Agents made this worse, not better. An AI agent can write a beautiful analysis of a binary it has never parsed. It will tell you the file "likely uses process injection" or "appears to be packed", and it sounds right, and sometimes it is.

So we built RevLens. It is a small reverse engineering lens that answers the first questions about a file quickly, honestly and with evidence, in the places we already work.

## One core, three front doors

The engine is pure TypeScript with zero native dependencies. It takes bytes and returns one report. Because it never touches the file system or the network, it runs the same way in three places:

- **The browser.** Open [the web app](https://aniruddhaadak80.github.io/re/), drop a file, and it is analyzed in a Web Worker on your device. Nothing is uploaded.
- **The terminal.** `npx revlens analyze ./file` with JSON, Markdown, HTML, SARIF and CycloneDX output.
- **Your agent.** `npx @revlens/mcp` is a stdio MCP server with 12 small tools for Claude Code, Codex, Cursor, Gemini CLI and friends.

## What it actually tells you

Here is the Windows build of esbuild 0.24.0, a 10 MB Go binary, straight from npm. RevLens takes about a second and a half in Node 22:

```text
Format   pe, x86-64, 64 bit, Windows console
SHA-256  26c4c83aa3284a24d014792496aea46dc5149f767c8ce3fafdfccfa084598de4
imphash  b196866f0bf37f1f128fa153413b744f
Go       go1.23.1, github.com/evanw/esbuild/cmd/esbuild
Imports  kernel32.dll, 48 functions
Rules    Crypto_Constants (SHA-256 round constants from the Go standard library)
Hardening  ASLR yes, DEP yes, high entropy VA yes, CFG no, signed no
```

The imphash matches what pefile gives, byte for byte. We wrote [a whole post](imphash-of-a-go-binary.md) about that.

And here is uBlock Origin 1.76.0 for Firefox, 671 files inside one XPI, in about 1.4 seconds:

```text
HIGH    Extension asks for "<all_urls>"
HIGH    Extension can read and change every site
MEDIUM  Extension asks for "privacy", "webRequest", "webRequestBlocking"
LOW     Extension asks for "tabs"
LOW     Manifest V2 extension
```

That one gets [its own post](inside-ublock-origin.md) too, because the interesting part is not the findings. It is what they mean.

## Fifteen analyzers, one report

RevLens runs 15 analyzers in order. Structure parsers for ELF, PE, Mach-O and WebAssembly. Go build info. An entropy map with packer and JavaScript obfuscator fingerprints. Strings with tags. Archive listing with recursion for ZIP, JAR, APK, CRX, XPI, VSIX, npm tarballs and Electron ASAR. An audit of extension permissions, VS Code activation events and npm install scripts. A bundle SBOM that finds npm packages and versions inside minified JavaScript. Source map detection. Secrets with redaction. An attack surface map of endpoints, GraphQL operations, IPC channels and feature flags. Capabilities mapped to MITRE ATT&CK. And yara-lite, a pure TypeScript engine for a practical subset of the YARA language, with a 13 rule starter pack.

Every finding carries its evidence: a byte offset, a length, a snippet or the path of the archive member it came from.

## Built for agents that should not guess

The tool we are proudest of is the smallest one. `verify_claim` takes a specific claim, such as "this binary imports CreateRemoteThread", and checks it against the bytes. The answer is `VERIFIED`, `REFUTED` or `UNKNOWN`, with the evidence. For esbuild, that claim is refuted: the name is not in the import table and not anywhere in the file.

We think every agent that talks about files should check itself like this. There is [a post about it](verify-claim-lie-detector.md).

## What RevLens is not

It is not a decompiler and it does not want to be one. When you need to read the logic of a function, use Ghidra, IDA, Binary Ninja or radare2, or the excellent MCP servers built on them. RevLens is the first pass that tells you whether you need them, and which part of the file to point them at.

RevLens is inspired by [REA](https://github.com/morluto/rea), the MIT licensed "Reverse Engineer Anything" project by morluto, which showed how good it feels when an agent can drive real reverse engineering tools. RevLens is written from scratch and is not affiliated with REA. We see them as partners: RevLens for zero install triage, supply chain checks and CI, REA and the deep engines for the deep dive.

## Try it

```bash
npx revlens analyze ./anything
```

Or open [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) and press "Try a sample". The code is MIT licensed on [GitHub](https://github.com/aniruddhaadak80/re), and we would love your issues, rules and pull requests.
