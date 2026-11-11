# MCP client configs

Copy the file for your client, or let RevLens write it for you:

```
npx revlens setup claude-code --write
npx revlens setup codex --write
npx revlens setup cursor --write
npx revlens setup vscode --write
npx revlens setup windsurf --write
```

Without `--write` setup prints the change and writes nothing. With it, the old file is backed up first.

| File | Where it goes |
| --- | --- |
| `claude-desktop.json` | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| `cursor.json` | `~/.cursor/mcp.json` or `.cursor/mcp.json` in a project |
| `vscode.json` | `.vscode/mcp.json` in a project, or the user `mcp.json` |
| `windsurf.json` | `~/.codeium/windsurf/mcp_config.json` |

On Windows, if `npx` is not found by the client, use `"command": "cmd", "args": ["/c", "npx", "-y", "@revlens/mcp"]`.
