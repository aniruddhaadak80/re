---
title: Runtime scenarios and capture compare
description: Script a real browser with steps and assertions, record network, console, DOM, screenshots, traces, coverage, listeners and WebMCP tools per step, then compare two runs or two releases with a score.
order: 23.5
---

# Runtime scenarios and capture compare

Static analysis tells you what a web app could do. A scenario shows what it does when someone uses it. This is part of `@revlens/webrt` and runs in Node with the optional `playwright` package and a Chromium (`npx playwright install chromium`, or any Chromium through `--executable`).

## Write a scenario

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

Actions: `goto`, `click`, `type`, `fill`, `press`, `select`, `check`, `hover`, `scroll`, `wait`, `reload`, `back`, `assert`, `screenshot`. Assertions never run page code. They use Playwright locators (exists, count, visible, text, value) and the recorded events (url, title, a request with method and status, a console message, no page errors). A failing assertion fails its step and shows the actual value.

```sh
revlens browser-scenario login.json --out runs/v1
```

## What each step records

- The network requests made during that step, with status and headers (secrets in headers are redacted).
- Console messages and page errors.
- The page HTML in a file, with element, link, form and script counts, and an ARIA snapshot.
- A screenshot and a Playwright trace chunk you can open with `revlens trace-inspect`.

On Chromium the run also records function call counts for every script from V8 precise coverage, the DOM event listener inventory (event type, element, script location), and WebMCP tools the page declares, read passively through the browser. Everything lands in `outDir/capture.json`.

## Compare two runs

```sh
revlens capture-compare runs/v1/capture.json runs/v2/capture.json
```

`web_capture_compare` works on scenario captures, browser captures and HAR files. It reports:

- endpoints added and removed, with ids, uuids and long tokens folded to `{id}`,
- status changes, and request and response header changes, security headers by value,
- scripts added, removed or changed by sha256,
- console differences,
- per step screenshot pixel diffs: changed pixel count, bounding box and mean difference.

A weighted score from 0 to 1 sums it up, so a CI job can fail when two releases drift more than you expect. The PNG decoder and the pixel diff are pure TypeScript.

## More runtime tools

| Tool | CLI | What it does |
|---|---|---|
| `web_browser_scenario` | `browser-scenario` | run a scenario file |
| `web_capture_compare` | `capture-compare` | compare two captures with a score |
| `web_trace_inspect` | `trace-inspect` | read a Playwright `trace.zip` |
| `web_cdp_targets` | `cdp-targets` | list pages, workers and Node contexts on a DevTools port |
| `web_webmcp_discover` | `webmcp-discover` | WebMCP and MCP discovery for a URL |
| `web_node_inspect` | `node-inspect` | attach to a local Node process for scripts, call counts and a CPU profile |

`web_node_inspect` needs `allowExecution`. It never evaluates code, but a process attached by pid keeps its inspector port open afterwards, so only use it on processes you own.

## How it was checked

Against a real Chromium through Playwright: a local counter app records the `/api/count/3` request in the third click step, coverage reports the click handler called exactly three times, the listener inventory finds `click` on the button, and the v1 to v2 screenshot diff finds exactly the 120 by 60 box that changed colour, with Pillow agreeing on all 7200 pixels. PNG decoding matches Pillow byte for byte across colour types. The Node inspector attach was checked on a real `node --inspect` process, by port and by pid.

## Limits

- Coverage, listeners and WebMCP need Chromium. Firefox and WebKit runs record the rest.
- Some Chromium builds accept the WebMCP domain but report no declarative tools; the static HTML and script scan still finds them.
- A scenario has a total time budget and stops with a warning when it runs out.
