---
title: Agent skills and plugins
description: Install RevLens in Claude Code, Codex, Cursor, VS Code, Windsurf and Claude Desktop, use the revlens-reverse-engineer skill, run the MCP server over stdio or HTTP, and find RevLens in the MCP registry.
order: 27
---

# Agent skills and plugins

RevLens gives an agent three things: the MCP server (185 MCP tools, 2 prompts, 2 resources), a skill that teaches a careful workflow, and plugin manifests that bundle both.

## The fastest way

```
npx revlens setup claude-code --write
```

Swap `claude-code` for `codex`, `cursor`, `vscode` or `windsurf`. Without `--write` setup only shows the change. With it, your old config is backed up first. Restart the client afterwards.

## Plugins

**Claude Code.** The repository is a plugin marketplace:

```
/plugin marketplace add aniruddhaadak80/re
/plugin install revlens@revlens
```

The plugin ([.claude-plugin/plugin.json](https://github.com/aniruddhaadak80/re/blob/main/.claude-plugin/plugin.json)) registers the `revlens` MCP server with `npx -y @revlens/mcp` and loads the skills from `.agents/skills`.

**Codex.** [.codex-plugin/plugin.json](https://github.com/aniruddhaadak80/re/blob/main/.codex-plugin/plugin.json) and [.codex-plugin/mcp.json](https://github.com/aniruddhaadak80/re/blob/main/.codex-plugin/mcp.json) do the same for Codex, with suggested prompts.

## Hand written configs

Copy one of the files in [examples/mcp](https://github.com/aniruddhaadak80/re/tree/main/examples/mcp): `claude-desktop.json`, `cursor.json`, `vscode.json` or `windsurf.json`. They all run `npx -y @revlens/mcp`.

## The skill

[`.agents/skills/revlens-reverse-engineer/SKILL.md`](https://github.com/aniruddhaadak80/re/blob/main/.agents/skills/revlens-reverse-engineer/SKILL.md) is a workflow in plain words:

1. **Triage** with `analyze_file`: format, hashes, the `next` hint, findings, components.
2. **Go deeper by format**: `disasm_*` for native code, `mobile_*` for APK, DEX, class and IPA, `managed_*` for .NET, Python, Lua, BEAM and EVM, `web_*` for JavaScript, Electron, captures and databases, `x_*` for demangling, deep PE, firmware and more.
3. **Decompile through bridges** when Ghidra, radare2, jadx or ILSpy are installed. `bridge_doctor` once, then `bridge_ghidra_decompile`, `bridge_jadx_decompile` and friends. Missing tools return install commands instead of failing.
4. **Check before stating**: every fact goes through `verify_claim`, and behavior claims cite function addresses.
5. **Report** with evidence for each point and a list of what could not be established.

Any client that reads Agent Skills from `.agents/skills` picks it up when you clone the repository. You can also copy the folder into your own project or your home skills folder. The tool map in `references/tool-map.md` is generated from the server, so it always lists the real tools.

## MCP over HTTP

stdio is the default. For clients that prefer HTTP, or for one server shared by several local tools:

```
REVLENS_MCP_TOKEN=$(openssl rand -hex 24) npx revlens mcp --http --port 7337
```

- Listens on `127.0.0.1` only, at `http://127.0.0.1:7337/mcp` (Streamable HTTP).
- Checks the `Host` and `Origin` headers, so a web page cannot reach it through DNS rebinding. Add `--allowed-origin <url>` for a trusted page.
- With a token, every request needs `Authorization: Bearer <token>`. Prefer the environment variable over `--token`, which other users can see in the process list.
- Binding to another interface needs `--allow-remote` and a token of at least 16 characters.
- Request bodies are capped at 4 MiB, sessions at 32, and idle sessions close after 30 minutes.

## MCP registry

[server.json](https://github.com/aniruddhaadak80/re/blob/main/server.json) describes RevLens for the official MCP registry as `io.github.aniruddhaadak80/revlens`, with the npm packages `@revlens/mcp` (stdio) and `revlens` (`revlens mcp`). Both package.json files carry the matching `mcpName`.

## Safety for agents

Every tool carries MCP annotations. Tools that only read are marked read only. Tools that write files (`managed_pyinstaller_extract`, `web_asar_extract`, `web_sourcemap_recover` with `outDir`, the ledger tools with `ledgerPath`, `bridge_setup_mcp`), reach the network (`check_vulns`, `web_browser_capture`) or run programs (`bridge_frida_run`, `bridge_gdb_run`) say so, so the client can ask you first. Tools that run the target also need `allowExecution: true`.
