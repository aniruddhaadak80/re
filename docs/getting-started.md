---
title: Getting started
description: Analyze your first file with RevLens in the browser, the terminal or your AI agent, in under a minute.
order: 1
---

# Getting started

RevLens looks inside binaries, bundles and packages and tells you what is there: the format, the hashes, the imports, the npm packages inside a bundle, risky permissions in an extension, secrets, endpoints, packers and more. It is written in pure TypeScript with zero native dependencies, so you can use it in three ways with the same engine and the same results.

## Option 1: the browser

Open [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) and drop a file anywhere on the page. You can also press one of the "Try a sample" buttons to load a real file such as `jquery.min.js` or a Linux `ls` binary.

The analysis runs inside a Web Worker on your own device. The file is never uploaded. You can turn off your network after the page loads and it still works, except for the optional vulnerability lookup.

## Option 2: the terminal

You need Node.js 20.10 or newer. Node 22 is what we test on.

```bash
npx revlens analyze ./esbuild.exe
```

The first run downloads the package. After that, a 10 MB Windows binary takes about a second and a half.

Want something to try? These public files are what we use in our own docs:

```bash
npm pack @esbuild/win32-x64@0.24.0 && tar xzf esbuild-win32-x64-0.24.0.tgz
npx revlens analyze package/esbuild.exe

npm pack lodash@4.17.21
npx revlens analyze lodash-4.17.21.tgz
```

Common next steps:

```bash
npx revlens analyze ./app.js --md --out report.md        # a readable report
npx revlens analyze ./app.js --json --out report.json    # the full report object
npx revlens sbom ./app.js --cyclonedx --out bom.json     # software bill of materials
npx revlens sarif ./app.exe --out revlens.sarif          # for GitHub code scanning
```

See the [CLI reference](cli.md) for every command and flag.

## Option 3: your AI agent

RevLens ships an MCP server that speaks stdio. For Claude Code:

```bash
claude mcp add revlens -- npx -y @revlens/mcp
```

Then ask your agent something like "Use RevLens to check what permissions ublock.xpi asks for" or "Is esbuild.exe packed? Verify your answer with verify_claim." Setup for Codex, Cursor, Gemini CLI and others is in [MCP setup](mcp.md).

## Option 4: as a library

```bash
npm install @revlens/core
```

```ts
import { analyze, toMarkdown } from '@revlens/core';

const bytes = new Uint8Array(await (await fetch('/app.js')).arrayBuffer());
const report = await analyze(bytes, { name: 'app.js' });
console.log(toMarkdown(report));
```

`@revlens/core` has no Node built-ins in its source, so this works in a browser, a worker, Deno, Bun or Node.

## Reading a report

Every result is one `Report` object with the schema id `revlens/report@1`. The parts you will look at most:

- `file`: name, size, detected format, architecture, hashes and overall entropy.
- `findings`: what RevLens thinks you should know, sorted from critical to info. Each finding has an `analyzer`, a `severity`, a plain language `detail`, and `evidence` with byte offsets or archive paths.
- `components`: packages found inside the file, with versions and purl ids.
- `capabilities`: behaviors such as "access the network", each with an ATT&CK id where one fits.
- `children`: for archives, a full report for each important member.

Severity is a hint, not a verdict. A content blocker that asks for every site is doing its job. A calculator that asks for every site is not. RevLens shows you the facts and the evidence, and you make the call.

## What next

- [Analyzers](analyzers.md): what each of the 15 analyzers reads and reports.
- [Rules](rules.md): write your own yara-lite rules.
- [SARIF and CI](sarif-and-ci.md): put RevLens in your pipeline.
- [Verify claims](verify-claims.md): keep your agent honest.
