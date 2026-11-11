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

## Runtime observation (Node only, `@revlens/webrt/node`)

These features watch JavaScript while it runs. They need Node, and the browser ones need the optional
`playwright` package with a browser (`npx playwright install chromium`, or any Chromium given through
`executablePath`).

### Scripted browser scenarios

`runScenario(spec, opts)` runs a JSON list of steps in a real browser:

```json
{
  "name": "login flow",
  "startUrl": "https://app.example/",
  "viewport": { "width": 1280, "height": 800 },
  "steps": [
    { "action": "fill", "selector": "#email", "text": "a@b.c" },
    { "action": "click", "selector": "button[type=submit]",
      "expect": [{ "request": "/api/login", "status": 200 }, { "url": "/home" }] },
    { "action": "wait", "selector": ".dashboard" },
    { "action": "assert", "expect": [{ "selector": ".user", "text": "a@b.c" }, { "noPageErrors": true }] }
  ]
}
```

Actions: goto, click, type, fill, press, select, check, hover, scroll, wait (ms, selector, url or network idle),
reload, back, assert, screenshot. Assertions never run page code: they use Playwright locators (exists, count,
visible, text, textEquals, value) and the recorded events (url, title, request seen with method and status,
console message, no page errors).

For every step the capture records the network requests made during that step, console messages, the
page HTML (written to a file, with element, link, form and script counts), an ARIA snapshot, a screenshot
and a Playwright trace chunk (`step-NNN.trace.zip`). On Chromium it also records:

- function call counts for every script from V8 precise coverage (which handlers ran and how often),
- the DOM event listener inventory (event type, element, script location), including `window`,
- WebMCP tools the browser itself registers, through the CDP `WebMCP` domain (passive, tools are never invoked).

Everything is written to `outDir/capture.json`.

### Compare captures

`compareCaptures(a, b)` (browser safe) and `compareCaptureFiles(aPath, bPath)` (Node) compare two scenario
captures, browser captures or HAR files. They report endpoints added and removed (paths with ids, uuids and
long tokens folded to `{id}`), status changes, request and response header changes (security headers by
value), scripts added, removed or changed by sha256, console differences, and per-step screenshot pixel
diffs (changed pixel count, bounding box, mean channel difference). A weighted 0 to 1 score sums it up.
The PNG decoder and the diff are pure TypeScript.

### WebMCP and MCP-over-web discovery

- `scanWebMcpScript(code)`: finds `navigator.modelContext` `provideContext`, `registerTool` and
  `unregisterTool` calls (also through aliases), with tool names, descriptions and input schema fields.
- `scanHtmlForMcp(html)`: declarative tool forms (`toolname`, `tooldescription`), MCP link and meta tags.
- `classifyWellKnown(path, status, type, body)`: MCP server cards, AI plugin manifests, A2A agent cards,
  OAuth protected resource metadata and `llms.txt`.
- `discoverWebMcp(url, { browser })` (Node): all of the above for a live page, its same-origin scripts and the
  well-known paths, plus, with `browser: true`, the tools Chromium reports through CDP.

### CDP, traces and the Node inspector

- `cdpTargets(endpoint)`: lists pages, workers and Node contexts on a DevTools port (loopback only unless
  `allowRemote`).
- `inspectPlaywrightTrace(zip)`: actions with selector, timing and errors, network, console and frames.
- `attachNodeInspector({ allowExecution: true, pid | port | wsUrl })`: attaches to a local Node process,
  records loaded scripts, function call counts and a CPU sampling profile, and never evaluates code. With a
  pid it switches the inspector on (SIGUSR1, or `process._debugProcess` on Windows), and the target keeps its
  inspector port open afterwards, so only use it on processes you own.

### More tools and commands

| Tool | CLI | What it does |
|---|---|---|
| web_browser_scenario | browser-scenario | run a scenario file |
| web_capture_compare | capture-compare | compare two captures with a score |
| web_trace_inspect | trace-inspect | read a Playwright trace.zip |
| web_cdp_targets | cdp-targets | list DevTools targets |
| web_webmcp_discover | webmcp-discover | WebMCP and MCP discovery for a URL |
| web_webmcp_scan | (tool only) | static WebMCP scan of HTML or JS text, browser safe |
| web_wellknown_classify | (tool only) | classify a well-known document, browser safe |
| web_node_inspect | node-inspect | attach to a Node process (needs allowExecution) |

### Verified

- PNG decoding of RGB, RGBA, 2-bit palette, grey, grey plus alpha and 16-bit grey images gives the same RGBA
  bytes (sha256) as Pillow 13. The diff of two fixtures gives Pillow's `ImageChops.difference` count (256)
  and bounding box.
- Against Chromium 156 (Debian build, run through Playwright 1.65): a scenario on a local app records the
  `/api/count/3` request in the third click step, precise coverage reports `bump` called exactly 3 times,
  the listener inventory shows `click` on `button#inc`, and the CDP WebMCP domain reports the declarative
  `search_todos` tool with the `q` field, the same tool the static HTML scan finds. Comparing the v1 and v2
  app screenshots finds exactly the 120x60 box at (20,200) that changed colour, and Pillow agrees on the
  7200 pixels.
- The click step trace chunk reads back with the `#inc` selector and the `/api/count/1` request.
- `cdpTargets` on a real `--remote-debugging-port` lists the page with its URL and title.
- `attachNodeInspector` on a real `node --inspect` process finds the script, `tick` with a call count and
  its exact source offset, CPU samples, and also works by pid through SIGUSR1.
- Chromium 156 accepts `WebMCP.enable` and reports declarative form tools; it did not expose the imperative
  `navigator.modelContext` API in this build, so imperative registrations are covered by the static scanner.
