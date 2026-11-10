---
title: "Your bundle ships its source: source maps in production"
date: 2026-11-08
summary: "A source map can rebuild your original code, comments, file tree and even your build machine's folder layout from a minified bundle. We show it on a tiny real esbuild build, then look at what jQuery and a popular VS Code extension actually ship."
tags: [javascript, source-maps, privacy, supply-chain]
cover: /re/media/cover-source-maps.svg
author: Aniruddha Adak
---

# Your bundle ships its source

Minification feels like protection. Variable names become `n` and `t`, whitespace disappears, and the code turns into one long line nobody wants to read. Then the build adds one more line at the end:

```js
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLC...
```

That line can undo all of it. A source map exists so that your browser's devtools can show you the original code while debugging. If the map includes `sourcesContent`, it carries every original file, in full, with comments.

RevLens checks every JavaScript file for this. Here is what that looks like on real builds.

## A tiny app, built the normal way

We wrote three small files: an API client, a feature flag helper and a `main.js` that uses both. Then we bundled them with esbuild, minified, with an inline source map, which is a common setting in many starter templates:

```bash
esbuild src/main.js --bundle --minify --sourcemap=inline --outfile=app.min.js
```

The output is 2,022 bytes. The code part looks properly minified:

```js
(()=>{var n="https://api.acme-internal.dev/v2";async function t(e){return(await fetch(n+"/billing/invoices",{headers:{authorization:"Bearer "+e}})).json()}function o(e){return(window.__FLAGS__||{})[e]===!0}o("new-checkout-2027")&&console.log("beta");...
```

## What RevLens sees

```bash
npx revlens analyze app.min.js
```

```text
MEDIUM  Source map recovers 100% of original sources
        A source map lists 3 original files, and 3 of them include full original
        code in sourcesContent. The original project tree can be rebuilt from this map.
```

And in `report.meta.sourcemap`:

```json
{
  "origin": "inline data URI",
  "sources": 3,
  "withContent": 3,
  "coverage": 100,
  "tree": [
    "../../../tmp/smdemo/src/api.js",
    "../../../tmp/smdemo/src/flags.js",
    "../../../tmp/smdemo/src/main.js"
  ]
}
```

Three things leaked, and only one of them is obvious:

1. **The original code.** All three files, with their real names like `isFeatureEnabled` and `getInvoices`, and any comments you wrote. The minifier renamed `isFeatureEnabled` to `o`. The map hands it right back.
2. **The project layout.** `src/api.js`, `src/flags.js`, `src/main.js`. In a real app this is your whole folder structure, which tells a reader where the auth code, the admin pages and the billing logic live.
3. **Your build machine.** Look at the paths again: `../../../tmp/smdemo/src/`. Source map paths are relative to the output file, so they often climb out into the folder where the build ran. On real projects these paths can carry user names, home directories and CI workspace names.

The attack surface analyzer adds the rest from the minified code alone:

```json
{
  "urls": ["https://api.acme-internal.dev/v2"],
  "hosts": ["api.acme-internal.dev"],
  "storage": ["acme.session"]
}
```

An internal API host and a session storage key, without even opening the map.

## What popular packages actually ship

That was our own toy. What do real projects do?

**jQuery 3.7.1** ships `jquery.min.map` next to `jquery.min.js` in its npm package. RevLens on the map:

```text
INFO  Source map recovers 0% of original sources
      A source map lists 1 original files, but without embedded original code.
```

The map lists one source, `jquery.js`, and has no `sourcesContent`. The minified file does not even reference the map with a `sourceMappingURL` comment. This is a careful setup: the map is there for people who want it, the source is published anyway, and nothing is embedded by surprise.

**The Red Hat YAML extension for VS Code** is more interesting. Its VSIX holds 47 files. RevLens found that eight bundled scripts in `extension/dist/` each end with a reference to a map:

```text
extension/dist/397.js                         -> 397.js.map
extension/dist/624.extension-web.js           -> 624.extension-web.js.map
extension/dist/extension-web.js               -> extension-web.js.map
extension/dist/extension.js                   -> extension.js.map
extension/dist/languageserver-web.js          -> languageserver-web.js.map
extension/dist/languageserver.js              -> languageserver.js.map
extension/dist/vendors-node_modules_node-fetch_lib_index_mjs.js -> ...js.map
extension/dist/vendors-node_modules_whatwg-fetch_fetch_js.extension-web.js -> ...js.map
```

None of those `.map` files are in the package. The references point at nothing. That is harmless, the extension is open source anyway, and it is a very common result of a webpack config that emits maps in development and strips the files but not the comments. It does show how easy it is for map references to slip into a shipped artifact. If the maps had been copied in, every bundled file would be readable.

## How to check your own build

```bash
npx revlens analyze dist/assets/index-abc123.js
```

- `Source map recovers N% of original sources` (medium): an inline or local map with `sourcesContent`. Your source is in the file.
- `References an external source map` (low): a `sourceMappingURL` that points to a separate file. Check whether that file is deployed. If it is, anyone can fetch it.
- No source map finding: nothing to recover from this file.

In CI, upload SARIF and you will see a code scanning alert the day a config change starts shipping maps:

```bash
npx revlens sarif dist/assets/index-abc123.js --out revlens.sarif
```

## What to do about it

Source maps are genuinely useful. You want them for your error tracker. You probably do not want them on your public CDN.

- **Vite:** `build.sourcemap` is `false` by default. If you need maps for error tracking, use `'hidden'`, which writes the files without the `sourceMappingURL` comment, and upload them to your error tracker instead of deploying them.
- **webpack:** prefer `hidden-source-map` for production, and avoid `eval-*` and `inline-*` devtool values outside development.
- **esbuild:** use `--sourcemap=external` and do not deploy the `.map` files, or omit `--sourcemap` in production builds.
- **Next.js:** `productionBrowserSourceMaps` is off by default. Leave it off unless you mean it.

And remember that removing maps does not hide your logic. Anything that runs in the browser can be read by a determined person. The goal is not secrecy. It is not handing out your comments, your folder layout and your build machine's paths by accident.
