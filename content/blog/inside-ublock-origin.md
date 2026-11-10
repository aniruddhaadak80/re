---
title: "What is inside uBlock Origin: auditing a browser extension in under two seconds"
date: 2026-11-10
summary: "We pointed RevLens at the uBlock Origin 1.76.0 XPI. In 1.4 seconds it listed 671 files, analyzed 60 of them, found four WebAssembly modules and eight permission findings. Here is what each one means, and why a high severity finding is not an accusation."
tags: [browser-extensions, supply-chain, audit, xpi]
cover: /re/media/cover-inside-ublock-origin.svg
author: Aniruddha Adak
---

# What is inside uBlock Origin

Browser extensions are some of the most powerful software most people run, and some of the least inspected. An extension with the right permissions can read every page you open, including your bank and your email. Store review helps, but it reviews one version at one moment. The next update can change everything.

So we picked the most respected extension we know, uBlock Origin, and asked a simple question: what can it do, according to its own files?

## The file

uBlock Origin 1.76.0 for Firefox, downloaded as `ublock.xpi`, 6,341,734 bytes.

```text
sha256  6f20ff6749193599548770539103069c20948dfcd3e61c3089a67da7bfc3be39
```

An XPI is a ZIP file with a `manifest.json`. RevLens detects it by magic bytes and name, lists every member, reads the manifest, and analyzes the important members one by one.

```bash
npx revlens analyze ublock.xpi
```

## The timing

On Node 22, the whole run took 1.36 seconds. Here is where it went, straight from `report.timings`:

```json
{
  "hashes": 364.86,
  "entropy": 59.39,
  "strings": 45.56,
  "archive": 484.21,
  "extaudit": 5.91,
  "secrets": 2.13,
  "surface": 0.08,
  "capa": 0.13,
  "yara": 394.45,
  "total": 1357.57
}
```

Most of the time is hashing 6 MB of compressed data five ways and running the rule pack over it. The archive analyzer spends its half second inflating and analyzing 60 members as child reports.

## What is in the box

The XPI holds 671 files. RevLens picks up to 60 that matter most: manifests first, then native or WebAssembly code, then scripts. Among the first ten:

```text
manifest.json                                  json
lib/lz4/lz4-block-codec.wasm                   wasm
lib/publicsuffixlist/wasm/publicsuffixlist.wasm wasm
js/wasm/biditrie.wasm                          wasm
js/wasm/hntrie.wasm                            wasm
lib/punycode.js                                js
js/redirect-engine.js                          js
js/code-viewer.js                              js
js/about.js                                    js
js/vapi-common.js                              js
```

Four WebAssembly modules. That surprises people, and it is a lovely detail. uBlock Origin uses small hand written WASM modules for its hot paths: a trie for hostname matching, another for filter matching, an LZ4 codec for compressing its cached filter lists, and a public suffix list lookup. This is how it stays fast with hundreds of thousands of filters loaded.

## The findings

```text
HIGH    Extension asks for "<all_urls>"
HIGH    Extension can read and change every site
MEDIUM  Extension asks for "privacy"
MEDIUM  Extension asks for "webRequest"
MEDIUM  Extension asks for "webRequestBlocking"
LOW     1 plain HTTP endpoints (in lib/punycode.js)
LOW     Extension asks for "tabs"
LOW     Manifest V2 extension
```

The manifest that produced them:

```json
{
  "name": "uBlock Origin",
  "version": "1.76.0",
  "manifestVersion": 2,
  "permissions": ["alarms", "dns", "menus", "privacy", "publicSuffix", "storage", "tabs",
                  "unlimitedStorage", "webNavigation", "webRequest", "webRequestBlocking", "<all_urls>"],
  "hostPermissions": ["<all_urls>"]
}
```

Let us go through them in plain words.

**`<all_urls>` and "can read and change every site".** This is the big one. With this permission an extension can see and modify every page and every request. For a content blocker, that is the job description. It cannot block a tracker on a site it cannot see.

**`webRequest` and `webRequestBlocking`.** These let the extension inspect network requests and cancel or change them before they leave your browser. Again, this is exactly how uBlock Origin blocks ads and trackers at the network level, which is more effective than hiding them after they load.

**`privacy`.** This lets the extension change browser privacy settings, such as disabling prefetching or WebRTC leaks. uBlock Origin exposes some of those as options.

**`tabs`.** Read tab URLs and titles. Needed to apply per site rules and show the per site popup.

**Manifest V2.** Firefox still supports MV2 and its blocking `webRequest` API, which is one reason uBlock Origin on Firefox is the most capable version of it. On Chrome, MV2 is retired. RevLens flags it as low because MV2 allows remote code and blocking requests that MV3 does not, so it is worth knowing which one you have.

**The plain HTTP endpoint.** This one is a comment. `lib/punycode.js` links to `http://tools.ietf.org/html/rfc3492#section-3.4` in its source. Nothing connects to it. RevLens reports it as low and points at the file, and you can dismiss it in a second.

## Capabilities

The capa-lite analyzer saw two:

```text
access the network (T1071): XMLHttpRequest
evaluate code at runtime (T1059): \beval\s*\(
```

The network one is expected: the extension downloads filter lists. The `eval` match is the more interesting story. We followed it, and the only `eval(` in the scripts is in a comment in `js/jsonpath.js`. It says that uBO's JSON path filters support only a limited set of expressions, "since unlike the official implementation, uBO can't use JS eval() to evaluate arbitrary JS expressions". So the one place that mentions `eval` is there to explain why the code does not use it.

That is exactly how capa-lite is meant to be used. It works from names and strings, not from a parse of the code, so it tells you where to look, not what to conclude. Ten seconds with the file turned a scary sounding capability into a reassuring one.

## No secrets, no rules, no remote scripts

Just as important is what did not show up. No hardcoded tokens or keys. No starter pack rule matched: no packer, no miner, no credential stealer patterns, no `eval(atob(...))`. No reference to a remote `.js` file that would be loaded at run time, which is the classic way an extension sneaks in code after review.

## So, is uBlock Origin dangerous?

No. It is open source, widely audited, and asks for exactly the permissions a content blocker needs. But notice what the report tells you: **if this extension were ever compromised, it could read every page you open.** That is true of every extension with this permission set, good or bad.

That is the real value of an audit like this. It does not tell you who to trust. It tells you how much you are trusting them, in a few seconds, before you click "Add".

## Try it on your own extensions

```bash
npx revlens analyze some-extension.xpi
npx revlens analyze some-extension.crx
npx revlens analyze some-extension.vsix
```

To watch an extension over time, keep the previous version and diff it against the new one. A new host permission or a new remote endpoint in an update is worth a careful look:

```bash
npx revlens diff extension-1.0.xpi extension-1.1.xpi
```

Or drop the file on [the web app](https://aniruddhaadak80.github.io/re/). It never leaves your browser.
