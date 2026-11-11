# samples/webrt sources and licenses

Fixtures used by `packages/webrt/test`. Generated files can be rebuilt with
`node packages/webrt/scripts/make-fixtures.mjs` (needs the package devDependencies and python3).

## Generated here with real toolchains

| File | Made by | Notes |
| --- | --- | --- |
| `obf-input.js`, `obf-cff-input.js` | written for RevLens (MIT) | Known plain inputs. Tests assert their strings come back. |
| `obfuscated.js` | javascript-obfuscator 5.x (BSD-2-Clause), seed 1337 | rc4 string array, rotation, 2 function wrappers, control flow flattening |
| `obfuscated-base64.js` | javascript-obfuscator 5.x, seed 1337 | base64 string array |
| `obfuscated-cff.js` | javascript-obfuscator 5.x, seed 1337 | switch dispatcher from control flow flattening |
| `webpack-src/**` | written for RevLens (MIT) | Tiny app with a dynamic import |
| `webpack-dist/*.js`, `*.map` | webpack 5 (MIT) | Production (numeric ids, source maps) and development builds, plus jsonp chunks |
| `webpack-dist/stats.*.json` | webpack 5 stats API | Reference chunk and module ids for the bundle tests |
| `electron-app/**` | written for RevLens (MIT) | Deliberately insecure Electron main and preload code |
| `electron/app.asar`, `electron/app.asar.unpacked/` | @electron/asar 4.x (MIT) | `*.node` files are unpacked |
| `fixture.sqlite` | python3 `sqlite3` (scripts/make-sqlite.py) | 1 KiB pages, overflow rows, blob, WITHOUT ROWID table, index, view |

## Downloaded

| File | Source | License |
| --- | --- | --- |
| `dns_udp.pcap`, `dns_udp.tcpdump.out` | https://github.com/the-tcpdump-group/tcpdump/tree/master/tests | BSD-3-Clause (tcpdump) |
| `ipv4_tcp_http_xml.pcap`, `ipv4_tcp_http_xml.tcpdump.out` | https://github.com/the-tcpdump-group/tcpdump/tree/master/tests | BSD-3-Clause (tcpdump) |
| `chrome-34-google.pcap` | https://github.com/zeek/zeek/blob/master/testing/btest/Traces/tls/chrome-34-google.pcap | BSD-3-Clause (Zeek) |
| `get-gzip.pcap` | https://github.com/zeek/zeek/blob/master/testing/btest/Traces/http/get-gzip.pcap | BSD-3-Clause (Zeek) |
| `pcapng-multi-interface.pcapng` | https://github.com/zeek/zeek/blob/master/testing/btest/Traces/pcapng-multi-interface.pcapng | BSD-3-Clause (Zeek) |
| `har-fulfill.har`, `har-redirect.har` | https://github.com/microsoft/playwright/tree/main/tests/assets | Apache-2.0 (Playwright) |

## Reference outputs

| File | Tool |
| --- | --- |
| `chrome-34-google.ja3.json` | `ja3 -j` from pyja3 1.0.0 (Salesforce JA3 reference, BSD-3-Clause) with dpkt 1.9.8 |
| `*.tcpdump.out` | tcpdump test suite expected output |

## Fetched on demand (not committed)

`node packages/webrt/scripts/fetch-fixtures.mjs` downloads
https://github.com/electron/electron/releases/download/v33.2.1/electron-v33.2.1-linux-x64.zip (MIT)
and extracts the `electron` executable and `version` file to `samples/.cache/webrt/`. The fuse and
version test is skipped when it is missing.

## runtime/ (scenario, compare and WebMCP fixtures)

- `a-rgb.png`, `b-rgb.png`, `a-rgba.png`, `a-palette.png` (2-bit palette), `a-grey.png`, `a-greyalpha.png`, `a-grey16.png`: drawn and saved with Pillow 13.0.0 in the sandbox (generated, no license needed). `png-reference.json` holds Pillow's decoded RGBA sha256, sizes, sample pixels and the `ImageChops.difference` pixel count (256) and bbox (10,25,26,41) for a-rgb vs b-rgb.
- `webmcp-page.html`, `webmcp-app.js`, `mcp.json`, `agent-card.json`: written for these tests (MIT, part of this repo). They follow the WebMCP explainer (navigator.modelContext provideContext, registerTool, unregisterTool and the declarative `toolname` / `tooldescription` form attributes), the MCP server card idea and the A2A agent card shape.
