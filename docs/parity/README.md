# Parity audit: RevLens and morluto/rea

These tables compare RevLens with morluto/rea (MIT), which RevLens uses as a scope reference. RevLens is
its own project and is not REA.

| file | what it holds |
|---|---|
| [summary.md](summary.md) | totals per table, the round 4 work list by owner package, items in progress on round-3 branches, timings |
| [rea-tools.md](rea-tools.md) | one row per rea MCP tool, with the RevLens tools that do the same job |
| [rea-cli.md](rea-cli.md) | one row per rea CLI command, with its flags and the RevLens command |
| [formats.md](formats.md) | input formats (rea artifact formats and formats read by its tools) and CLI output formats |
| [config.md](config.md) | rea settings and environment variables, CLI flags, and the RevLens variables |
| data/*.json | generated inventories, totals and timings |

## How the tables are made

1. `node scripts/parity/rea-inventory.mjs --src <rea checkout>` loads rea's own registries through its tsx
   (TOOL_CONTRACTS with JSON input schemas, the CLI tree from createCli, ARTIFACT_FORMAT_IDS,
   CLI_OUTPUT_FORMATS, debugger limits) and reads its sources for folders, the environment schema and
   every REA_* name. Needs `npm ci` in the rea checkout.
2. `node scripts/parity/revlens-inventory.mjs` starts the built RevLens MCP server in memory and calls
   tools/list, then reads TOOL_GROUPS, CLI commands, analyzers, format ids and REVLENS_* names. Needs
   `npm ci && npx tsc -b`.
3. `scripts/parity/mapping.mjs` holds the reviewed decision for every row. A status is set by reading
   both implementations, not by name likeness.
4. `node scripts/parity/generate.mjs --check` fails when any rea tool, command, format or setting has no
   row, or when a row names a RevLens tool or command that does not exist. Without `--check` it writes
   the markdown files.
5. `node scripts/parity/bench.mjs` times equivalent offline operations on the same fixtures and writes
   data/bench.json, which summary.md shows.
