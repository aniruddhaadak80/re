---
title: MCP setup
description: Connect RevLens to Claude Code, Codex, Cursor, Gemini CLI, VS Code, Windsurf and other MCP clients, and learn what each tool returns.
order: 3
---

# MCP setup

`@revlens/mcp` is a Model Context Protocol server that runs over stdio. It gives your agent a small set of focused tools instead of hundreds, so it spends its context on your problem instead of on tool descriptions.

Every client below launches the same command:

```bash
npx -y @revlens/mcp
```

You can also run it from the CLI with `npx revlens serve-mcp`.

## Claude Code

One command:

```bash
claude mcp add revlens -- npx -y @revlens/mcp
```

Or share it with your team through a `.mcp.json` file at the project root:

```json
{
  "mcpServers": {
    "revlens": {
      "command": "npx",
      "args": ["-y", "@revlens/mcp"]
    }
  }
}
```

## OpenAI Codex CLI

Codex uses TOML in `~/.codex/config.toml`:

```toml
[mcp_servers.revlens]
command = "npx"
args = ["-y", "@revlens/mcp"]
```

Newer Codex builds also accept `codex mcp add revlens -- npx -y @revlens/mcp`.

## Cursor

Global config in `~/.cursor/mcp.json`, or per project in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "revlens": {
      "command": "npx",
      "args": ["-y", "@revlens/mcp"]
    }
  }
}
```

## Gemini CLI

Add the server to `~/.gemini/settings.json` (or `.gemini/settings.json` in a project):

```json
{
  "mcpServers": {
    "revlens": {
      "command": "npx",
      "args": ["-y", "@revlens/mcp"]
    }
  }
}
```

## VS Code (GitHub Copilot agent mode)

Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "revlens": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@revlens/mcp"]
    }
  }
}
```

## Windsurf, Cline, Claude Desktop and others

Any client that takes the common `mcpServers` shape works with the same block:

```json
{
  "mcpServers": {
    "revlens": {
      "command": "npx",
      "args": ["-y", "@revlens/mcp"]
    }
  }
}
```

On Windows, if your client cannot find `npx`, use `"command": "cmd"` and `"args": ["/c", "npx", "-y", "@revlens/mcp"]`.

## The tools

| Tool | What it returns |
| --- | --- |
| `analyze_file` | A compact summary of the report: format, arch, hashes, counts and the top findings. |
| `list_findings` | Findings, filterable by severity or analyzer, each with evidence offsets or archive paths. |
| `get_strings` | Extracted strings, interesting ones first, optionally filtered by tag such as `url` or `path`. |
| `get_sections` | Sections or segments with offsets, sizes and entropy. |
| `get_imports` | Imports per library, plus exports. |
| `sbom` | Components with versions and purl ids, or a CycloneDX 1.5 document. |
| `check_vulns` | Known vulnerabilities for detected components from OSV.dev. Uses the network. |
| `scan_rules` | yara-lite matches for rule text you pass in, plus the starter pack. |
| `diff_files` | A `DiffReport` between two files with a one line summary. |
| `verify_claim` | `VERIFIED`, `REFUTED` or `UNKNOWN` for each of up to 50 claims (`claims` array), with the evidence. |
| `report_markdown` | The full report as Markdown, ready to paste into an issue or a write up. |
| `hexdump` | A hex and ASCII view of a byte range, so the agent can look at exact bytes. |
| `list_analyzers` | The analyzers and what each one does. |

Every file tool takes `path`. `list_findings` adds `minSeverity`, `analyzer` and `limit`; `get_strings` adds `tag`, `contains` and `limit`; `get_imports` adds `contains`; `sbom` adds `format` (`list` or `cyclonedx`); `scan_rules` adds `rules` and `includeStarter`; `diff_files` takes `before` and `after`; `hexdump` takes `offset` and `length` (up to 4096). Results are cached per file until it changes on disk, and files over 256 MB are refused unless you raise `REVLENS_MAX_FILE_MB`.

The server reads files from paths on your machine and keeps every result local. Only `check_vulns` talks to the network, and only to `api.osv.dev`.

## Prompts that work well

- "Analyze `./build/app.exe` with RevLens. Tell me the architecture, whether it is packed, and the five most important findings."
- "Run RevLens `sbom` on `dist/main.js`, then `check_vulns`, and list anything with a CVE."
- "Before you tell me this binary does process injection, call `verify_claim` with `imports-symbol` for `WriteProcessMemory` and `CreateRemoteThread`."
- "Diff `v1.4.0.vsix` and `v1.5.0.vsix` and tell me about new endpoints and new permissions."

## A good habit for agents

Ask your agent to call `verify_claim` before it states a fact about a file. It costs one small tool call, and it turns "the model thinks" into "the bytes show". Read [Verify claims](verify-claims.md) for why this matters.

## When to reach for a bigger tool

RevLens does not decompile functions. When your agent needs to read the logic of a native function, add a deep engine next to RevLens: [REA](https://github.com/morluto/rea), [GhidraMCP](https://github.com/LaurieWired/GhidraMCP), [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) or [r2mcp](https://github.com/radareorg/radare2-mcp). A good flow is RevLens first for triage, then the deep engine for the two or three functions that matter.
