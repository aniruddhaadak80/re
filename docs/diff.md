---
title: Diff two files
description: Compare two releases of an app, bundle, extension or binary and see the changes that matter.
order: 8
---

# Diff two files

`git diff` is great for source. For a compiled release it shows nothing useful. RevLens diff analyzes both files and compares the parts that tell a story: dependencies, imports, exports, endpoints, interesting strings, sections, findings and capabilities.

```bash
npx revlens diff old.exe new.exe
npx revlens diff old.vsix new.vsix --json --out diff.json
```

```ts
import { analyze, diff } from '@revlens/core';
const d = diff(await analyze(a, { name: 'old.exe' }), await analyze(b, { name: 'new.exe' }));
console.log(d.summary);
```

## What is compared

| Part | How |
| --- | --- |
| `components` | By name. The same name with a different version counts as changed. |
| `imports` | As `library!symbol` pairs. |
| `exports` | By name. |
| `endpoints` | URLs, API paths, GraphQL operations and IPC channels (`ipc:<name>`) from the surface analyzer. |
| `strings` | Tagged strings only (urls, paths, commands and so on), not version numbers. Untagged strings change on every build and would drown the signal. |
| `sections` | By name. A section changes when its size changes or its entropy moves by more than 0.5. |
| `findings` | By finding id, ignoring the numeric suffix that secrets use. |
| `capabilities` | By name. |

Archive members are included: the diff walks each report and all of its children, so a new endpoint in one script inside a VSIX shows up.

The result is a `DiffReport` with `schema: "revlens/diff@1"`, the name, SHA-256 and format of both files, an `added` and `removed` list for each part (plus `changed` for components and sections), and a one line `summary`.

## A real example: esbuild 0.23.0 to 0.24.0

Both files are the Windows build from `@esbuild/win32-x64`.

```text
Between esbuild-0.23.0.exe and esbuild-0.24.0.exe: 2 endpoint changes, 1 import change, 5 section changes.
```

The details:

```json
{
  "imports": { "added": [], "removed": ["kernel32.dll!CreateFileA"] },
  "sections": {
    "changed": [
      { "name": ".text",  "before": 5308928, "after": 5455872 },
      { "name": ".rdata", "before": 4411904, "after": 4455936 },
      { "name": ".data",  "before": 334848,  "after": 339456 },
      { "name": ".pdata", "before": 82432,   "after": 84992 },
      { "name": ".reloc", "before": 86016,   "after": 90112 }
    ]
  }
}
```

The section sizes above are a condensed view of the `before` and `after` section objects.

What this tells you in a few seconds:

- The new release no longer imports `CreateFileA`, which is why its imphash changed from `07361a3a7f515bf56ca93120b2aca73b` to `b196866f0bf37f1f128fa153413b744f`. If you track binaries by imphash, this is exactly the kind of change that breaks a match.
- The toolchain moved from `go1.22.4` to `go1.23.1` (from the buildinfo analyzer on each side).
- Code grew by about 147 KB. Nothing was packed and no capability, component or finding was added or removed.
- The two endpoint changes are one removed and one added version of the same joined Go string, `http://.pnp.jsbaseUrlUpgradeTrailerHEADERS` before and `http://.pnp.jsbaseUrlUpgradeTrailersocks5hHEADERS` after. It is noise from how Go stores literals, but the new `socks5h` in the middle is a real new string in the binary.

## The summary line

The summary counts the changes per part and lists only the parts that changed. Two special cases:

- `The two files are byte for byte identical.` when the SHA-256 values match.
- `The files differ in bytes but not in anything RevLens tracks.` when only untracked bytes changed, for example a rebuilt timestamp.

## Good uses

- **Dependency bumps:** diff the old and new tarball before you merge the update. A new install script or a new endpoint deserves a closer look.
- **Extension updates:** diff two versions of a browser or VS Code extension to see new permissions and hosts.
- **Your own releases:** run diff in CI between the last release and the new build, and post the summary on the release pull request.
- **Competitive research:** see which endpoints and feature flags a new version of a public app added. Please respect each product's terms.
