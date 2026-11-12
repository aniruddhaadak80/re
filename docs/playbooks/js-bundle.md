# JavaScript bundle playbook

Web and desktop apps ship JavaScript bundled by webpack, Rollup, esbuild, Vite or Parcel, often
minified and sometimes obfuscated, with or without a source map.

## Recognise
- `analyze_file` reports `js` or `sourcemap`. A `//# sourceMappingURL=` comment points to the map.

## First pass
1. `web_bundle_modules` splits the bundle into its modules and names the bundler.
2. `web_sourcemap_recover` rebuilds the original source tree when a map is present. It writes files.
3. `web_js_endpoints` lists URLs, API paths, GraphQL operations and WebSocket endpoints with offsets.
4. `x_api_contracts` groups endpoints into an API description.

## Code
1. `web_js_beautify` for readable code, `web_js_deobfuscate` for string arrays, hex escapes and constant folding.
2. Search for `eval`, `Function(`, `postMessage`, `localStorage` and secrets with `get_strings`.
3. `x_standalone_js` recognises bundled runtimes such as Node SEA, Bun and Deno standalone executables.

## Dynamic
- `web_browser_capture` and `web_browser_scenario` record what a page really requests. They start a browser and reach the network, so only use them when allowed.

## Verify
- Cite the module id and the byte offset in the bundle, or the original file name from the source map.
