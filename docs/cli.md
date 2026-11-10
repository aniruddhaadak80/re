---
title: CLI reference
description: Every revlens command and flag, with examples and exit codes.
order: 2
---

# CLI reference

The `revlens` command is a thin wrapper around `@revlens/core`. It reads files with `node:fs`, runs the same analysis the browser runs, and prints or writes the result.

```bash
npx revlens <command> <file> [more files] [flags]
```

You can also install it once with `npm install -g revlens` and drop the `npx`.

## Commands

| Command | What it does |
| --- | --- |
| `analyze <file>` | Runs every analyzer that applies and prints a summary. Add an output flag for a full report. |
| `diff <a> <b>` | Analyzes two files and reports what changed between them. |
| `verify <file> <claim...>` or `--claim <json>` | Checks one claim against the bytes and prints `VERIFIED`, `REFUTED` or `UNKNOWN` with evidence. |
| `rules <file> --rules <file.yar>` | Runs the starter rule pack plus your rules and prints the matches. |
| `sbom <file>` | Lists the components found in the file. Use `--cyclonedx` for CycloneDX 1.5 JSON and `--osv` to look up known vulnerabilities. |
| `sarif <file>` | Writes SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. |
| `serve-mcp` | Starts the MCP stdio server, the same as `npx @revlens/mcp`. |

## Output flags

| Flag | Output |
| --- | --- |
| `--json` | The full `Report` object (or `DiffReport` for `diff`). |
| `--md` | A Markdown report, good for pull requests, issues and agent context. |
| `--html` | A self contained HTML report with an entropy strip. No external assets. |
| `--sarif` | SARIF 2.1.0. |
| `--cyclonedx` | A CycloneDX 1.5 SBOM. |
| `--out <path>` | Write to a file instead of standard output. |

## Analysis flags

| Flag | Effect |
| --- | --- |
| `--rules <file>` | Add your own yara-lite rules to the built in starter pack. |
| `--osv` | Look up detected components on OSV.dev. This is the only flag that uses the network. |

## Examples

Analyze a Windows binary and keep a Markdown report:

```bash
npx revlens analyze esbuild.exe --md --out esbuild.md
```

The top of that report, from a real run on esbuild 0.24.0:

```text
# RevLens report: esbuild.exe

| Field   | Value                                                            |
| ------- | ---------------------------------------------------------------- |
| Format  | pe, x86-64, 64 bit                                               |
| Size    | 10,430,464 bytes                                                 |
| SHA-256 | 26c4c83aa3284a24d014792496aea46dc5149f767c8ce3fafdfccfa084598de4 |
| Entropy | 6.21 bits per byte                                               |
```

Audit an npm tarball before you install it:

```bash
npm pack some-package@1.2.3
npx revlens analyze some-package-1.2.3.tgz
```

If the package runs a `preinstall`, `install`, `postinstall` or `prepare` script, you get a finding with the exact command. It becomes `high` when the script downloads, evaluates or decodes something.

Compare two releases:

```bash
npx revlens diff esbuild-0.23.0.exe esbuild-0.24.0.exe
```

```text
Between esbuild-0.23.0.exe and esbuild-0.24.0.exe: 2 endpoint changes, 1 import change, 5 section changes.
```

Check a claim:

```bash
npx revlens verify esbuild.exe --claim '{"kind":"has-section","name":"UPX0"}'
```

Short claims work too: `string=TEXT`, `import=SYMBOL`, `section=NAME`, `format=elf`, `sha256=HEX`, `at=OFFSET:HEX`, `uses=NAME@VERSION`.

```bash
npx revlens verify esbuild.exe section=.text import=CreateRemoteThread --strict
```

```text
REFUTED  No section is named UPX0. Sections: .text, .rdata, .data, .pdata, .xdata, .idata, .reloc, .symtab.
```

Run your own rules:

```bash
npx revlens rules suspicious.bin --rules ./team-rules.yar --json
```

Get a CycloneDX SBOM with known vulnerabilities:

```bash
npx revlens sbom vendor/jquery.min.js --cyclonedx --osv --out bom.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The command ran. Findings do not change the exit code on their own. |
| `1` | Something went wrong: a missing file, unreadable input or a rule syntax error. |
| `2` | A gate tripped: `--fail-on <severity>` found a finding at or above that severity, or `rules --fail-on-match` matched. |
| `3` | `verify --strict` and at least one claim was REFUTED. |

Gates are opt in, so a plain run never fails a build by surprise. The [SARIF and CI](sarif-and-ci.md) page has a ready recipe.

## Limits worth knowing

- Files over 64 MB skip the rule scan. Everything else still runs.
- Archives analyze up to 60 important members recursively, two levels deep, and skip members over 24 MB.
- The report keeps the 400 most interesting strings. The JSON report says how many strings were found in total in `meta.stringsTotal`.
