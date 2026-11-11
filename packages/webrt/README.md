# @revlens/webrt

Reverse engineering for web runtimes: JavaScript, bundles, source maps, Electron apps, live browser
sessions, packet captures, SQLite files and HAR logs. Everything is static: analysed code is parsed,
never run.

The main entry (`@revlens/webrt`) loads in a browser Web Worker. Features that need the file system
or a browser live in `@revlens/webrt/node`.

## What it does

- **JavaScript**: parse with `@babel/parser`, beautify with `@babel/generator`, and deobfuscate
  common patterns: javascript-obfuscator string arrays (plain, base64 and rc4 encodings, array
  rotation with checksum loops, wrapper functions and aliases), proxy objects, switch dispatchers
  from control flow flattening, hex and unicode escapes, constant folding and dead branches.
  The string array is replayed with a small bounded evaluator over literals; nothing from the
  input is executed.
- **Bundles**: split webpack 4 and 5 bundles and jsonp chunks, browserify and esbuild bundles into
  modules with ids, paths, dependencies and exports. Numeric webpack ids are named through the
  source map. For rollup and vite output, chunk level imports and exports are listed.
- **Endpoints**: fetch, XHR, axios, jQuery, WebSocket, EventSource, sendBeacon, socket.io, workers,
  eval and Function, `process.env` and `import.meta.env` names, feature flag checks, storage keys
  and postMessage listeners, each with line, column and offset.
- **Source maps**: v3 and index maps, VLQ decoding, position lookup, and recovery of the original
  file tree with safe relative paths.
- **Electron**: ASAR read and extract (unpacked folder supported, traversal blocked), version from
  package.json, the `version` file or binary strings, fuse wire reading, and a security review of
  `webPreferences`, `contextBridge` exposure, IPC channels, `shell.openExternal`, custom protocols,
  auto-update feeds, risky switches and certificate bypasses.
- **Browser capture** (Node): Playwright opens a URL and records HAR entries, scripts with source,
  inline scripts, console, cookie names and flags, storage keys, WebSocket frames and service
  workers, then runs the JavaScript analysis on the scripts.
- **PCAP and PCAPNG**: Ethernet, VLAN, Linux SLL and SLL2, null and raw IP links, IPv4, IPv6, TCP,
  UDP, flows, DNS (UDP and TCP), HTTP/1.x requests and responses, TLS ClientHello SNI, ALPN and JA3,
  ServerHello JA3S, and summary stats.
- **SQLite**: pure TypeScript page reader (b-trees, overflow pages, records, WITHOUT ROWID tables)
  and a read-only SELECT engine. SQLite itself is never run.
- **HAR**: hosts, third-party marking, API endpoint patterns, redirects, auth header schemes and
  cookie names (values are never returned), missing security headers, mixed content, WebSockets,
  and endpoints found in captured scripts.

## API

```ts
import { deobfuscate, unpackBundle, findEndpoints, recoverSources, readAsar, auditAsar,
  analyzePcap, SqliteFile, runSelect, analyzeHar, ANALYZERS, TOOLS } from '@revlens/webrt';
import { browserCapture, extractAsar, auditElectronPath, writeTree, TOOLS as NODE_TOOLS, CLI_COMMANDS } from '@revlens/webrt/node';
```

- `ANALYZERS`: `webrt-js`, `webrt-sourcemap`, `webrt-electron`, `webrt-pcap`, `webrt-sqlite`,
  `webrt-har`. They add findings and put structured output under `report.meta.webrt.<area>`.
  PCAP and SQLite are recognised by magic bytes because core has no format id for them.
- `TOOLS` from the main entry take `base64` or `text`. `TOOLS` from `/node` also take `path` and add
  `web_browser_capture`. Every list output pages with `offset` and `limit`.

## Tools

| Tool | What it does |
| --- | --- |
| `web_js_beautify` | Reformat JavaScript and decode escapes, paged code window |
| `web_js_deobfuscate` | Static deobfuscation with decoded strings and stats |
| `web_bundle_modules` | Modules, paths, deps and exports of a bundle |
| `web_js_endpoints` | Network calls, URLs, hosts, eval, env names, flags |
| `web_sourcemap_recover` | Original file tree from a map; `outDir` writes it in Node |
| `web_asar_list` | ASAR entries with offsets, flags and integrity |
| `web_asar_extract` | One file, or the whole archive to `outDir` in Node |
| `web_electron_audit` | Electron version, fuses and security findings |
| `web_browser_capture` | Node only. Playwright capture plus analysis |
| `web_pcap_summary` | Stats, DNS, HTTP, TLS SNI and JA3 |
| `web_pcap_flows` | Conversations with per-direction counts |
| `web_sqlite_tables` | Schema, row counts, sample rows |
| `web_sqlite_query` | One read-only SELECT, rows capped |
| `web_har_summary` | HAR overview with redacted auth details |

## CLI commands

Exported from `/node` as `CLI_COMMANDS`: `js-beautify`, `js-deobfuscate`, `js-bundle`,
`js-endpoints`, `sourcemap-recover`, `asar-list`, `asar-extract`, `electron-audit`,
`browser-capture`, `pcap-summary`, `pcap-flows`, `sqlite-tables`, `sqlite-query`, `har-summary`.
Each prints text by default and JSON with `--json`. Exit code 2 means the input was rejected.

## Limits

- JavaScript over 16 MB is refused. AST walks are iterative and capped by depth and node count.
- The deobfuscator targets javascript-obfuscator output (versions 2 to 5). It does not undo
  identifier renaming, self defending, debug protection or domain lock code, and does not inline
  proxy objects that are built by later assignments.
- Bundle splitting does not recover module boundaries inside rollup, vite or esbuild ESM output
  without path comments.
- TCP reassembly keeps the first 64 KB per direction and stops at the first gap. HTTP/2, QUIC and
  encrypted TLS records are not decoded. IP fragments are counted, not reassembled.
- SQLite: no WAL file merge, no freelist recovery of deleted rows, SELECT supports one table, one
  ORDER BY column and no joins, functions or aliases. Views are listed but not queried.
- Browser capture needs `playwright` and a browser (`npx playwright install chromium`). It refuses
  downloads, removes its temp folder and enforces a total time budget.

## Verified against

- javascript-obfuscator 5 output from known inputs: all hidden strings come back, helpers removed,
  statements of the flattened function return in source order.
- webpack 5 stats: module ids and paths of production and development bundles and chunks; source
  map recovery returns the original sources byte for byte.
- @electron/asar `listPackage` and header size, SHA256 integrity hashes from the archive header, and
  @electron/fuses `getCurrentFuseWire` on the real Electron 33.2.1 Linux binary.
- tcpdump expected output for DNS, pyja3 (Salesforce JA3 reference) for JA3, dpkt for SNI and pcapng
  packet count.
- python3 `sqlite3` for schema, row counts and the results of the SELECT engine.
- Real Playwright HAR files for redirect chains and request summaries.

## Fixtures

See `samples/webrt/SOURCES.md`. Rebuild with `node packages/webrt/scripts/make-fixtures.mjs`;
download the Electron binary with `node packages/webrt/scripts/fetch-fixtures.mjs`.
