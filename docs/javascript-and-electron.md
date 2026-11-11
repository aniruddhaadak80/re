---
title: JavaScript and Electron
description: Beautify and deobfuscate JavaScript, split webpack, browserify and esbuild bundles, find endpoints, recover sources from maps, and audit Electron apps and ASAR archives.
order: 23
---

# JavaScript and Electron

The web runtime package (`@revlens/webrt`) parses JavaScript with Babel and never runs it. Try it on the [JavaScript page](https://aniruddhaadak80.github.io/re/labs/javascript) and the [Electron page](https://aniruddhaadak80.github.io/re/labs/electron).

## JavaScript

- **Beautify** minified code and decode hex and unicode escapes.
- **Deobfuscate** javascript-obfuscator output: string arrays (plain, base64 and rc4), array rotation, wrapper functions, proxy objects, control flow flattening, constant folding and dead branches. Strings are recovered by a small bounded evaluator over literals. Input code is never executed.
- **Bundles**: split webpack 4 and 5, jsonp chunks, browserify and esbuild bundles into modules with ids, paths, dependencies and exports. Rollup and Vite chunks get their imports and exports.
- **Endpoints**: fetch, XHR, axios, jQuery, WebSocket, EventSource, sendBeacon, socket.io, workers, `eval` and `Function`, environment variable names, feature flags, storage keys and postMessage listeners, each with line, column and offset.
- **Source maps**: v3 and index maps, position lookup and recovery of the original file tree with safe relative paths.

## Electron

- Read and extract ASAR archives (unpacked folders supported, path traversal blocked).
- Find the Electron version and read the fuse wire.
- Review security settings: `webPreferences` (`nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity`), what `contextBridge` exposes, IPC channels, `shell.openExternal`, custom protocols, auto update feeds, risky command line switches and certificate bypasses.

## CLI

```
revlens js-beautify app.min.js
revlens js-deobfuscate obfuscated.js
revlens js-bundle main.js
revlens js-endpoints main.js
revlens sourcemap-recover main.js.map --out recovered/
revlens asar-list app.asar
revlens electron-audit app.asar
```

## MCP tools

`web_js_beautify`, `web_js_deobfuscate`, `web_bundle_modules`, `web_js_endpoints`, `web_sourcemap_recover` (writes files with `outDir`), `web_asar_list`, `web_asar_extract` (writes files), `web_electron_audit`, `web_browser_capture` (opens a URL with Playwright, network).

## Limits

- Files over 16 MB are refused.
- The deobfuscator targets javascript-obfuscator 2 to 5. It does not undo identifier renaming, self defending or domain lock code.
- Module boundaries inside Rollup, Vite or esbuild ESM output are not recovered without path comments.
- Browser capture needs Playwright and a browser installed.

## How it was checked

javascript-obfuscator 5 output from known inputs, webpack 5 stats for module ids and paths, byte for byte source recovery, `@electron/asar` and `@electron/fuses` on the real Electron 33 binary. See the [package README](https://github.com/aniruddhaadak80/re/tree/main/packages/webrt).
