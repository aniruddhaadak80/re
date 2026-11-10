---
title: SBOM and vulnerabilities
description: Turn the packages inside bundles, Go binaries and archives into a CycloneDX SBOM, and check them against OSV.dev.
order: 7
---

# SBOM and vulnerabilities

A lockfile tells you what you meant to ship. A software bill of materials built from the artifact tells you what you did ship. RevLens builds the second kind, straight from the bytes, and can check it against the free [OSV.dev](https://osv.dev) database.

## Where components come from

| Source | Analyzer | Confidence | Example |
| --- | --- | --- | --- |
| `package.json` inside an archive | `sbom` | 1.0 | `lodash@4.17.21` from `lodash-4.17.21.tgz` |
| Banner and `@license` comments | `sbom` | 0.9 | `/*! jQuery v3.4.1` gives `jquery@3.4.1` |
| Runtime version constants | `sbom` | 0.75 | `reconcilerVersion:"18.3.1"` gives `react-dom@18.3.1` |
| `node_modules/<name>/` paths in bundles | `sbom` | 0.6 | name only, no version |
| `dependencies` in `package.json` | `sbom` | 0.5 | the range with `^` or `~` removed |
| Go build info `dep` lines | `buildinfo` | 0.9 | `golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f8` from esbuild for macOS |

Each component has a [purl](https://github.com/package-url/purl-spec) such as `pkg:npm/jquery@3.4.1` or `pkg:golang/golang.org%2Fx%2Fsys@v0.0.0-20220715151400-c0bba94af5f8`, and the evidence that produced it: an offset in the file, or the path of the archive member.

Components found in archive members bubble up to the parent report with their member path. The Red Hat YAML VS Code extension, for example, gives 19 components from its bundled `dist/` files and `package.json`.

## CycloneDX output

```bash
npx revlens sbom jquery-3.4.1.min.js --cyclonedx --out bom.json
```

```ts
import { analyze, toCycloneDX } from '@revlens/core';
const bom = toCycloneDX(await analyze(bytes, { name: 'jquery-3.4.1.min.js' }));
```

Real output for the jQuery 3.4.1 production build:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:0925e8ad-7bd9-4139-aa8b-1e98be8e87a6",
  "metadata": {
    "tools": { "components": [{ "type": "application", "name": "RevLens", "version": "0.1.0" }] },
    "component": {
      "type": "file",
      "name": "jquery-3.4.1.min.js",
      "hashes": [{ "alg": "SHA-256", "content": "0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a" }]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "jquery",
      "version": "3.4.1",
      "purl": "pkg:npm/jquery@3.4.1",
      "properties": [
        { "name": "revlens:confidence", "value": "0.9" },
        { "name": "revlens:ecosystem", "value": "npm" }
      ]
    }
  ]
}
```

The serial number is derived from the file's SHA-256, so the same file always produces the same BOM id. The real output also has a `metadata.timestamp`, left out above.

## Vulnerability lookup with OSV.dev

```bash
npx revlens sbom jquery-3.4.1.min.js --osv
```

```ts
import { analyze, lookupOSV } from '@revlens/core';
const report = await analyze(bytes, { name: 'jquery-3.4.1.min.js' });
const vulns = await lookupOSV(report.components);
```

Real result:

```text
MEDIUM  jquery 3.4.1 is affected by CVE-2020-11022
        Potential XSS vulnerability in jQuery See https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2
MEDIUM  jquery 3.4.1 is affected by CVE-2020-11023
        Potential XSS vulnerability in jQuery See https://osv.dev/vulnerability/GHSA-jpcq-cgw6-v4j6
```

How it works:

1. Only components with an exact version that starts with a digit are sent, in the npm, Go, crates.io, PyPI and Maven ecosystems. Names without versions stay local.
2. RevLens sends one batch request to `https://api.osv.dev/v1/querybatch` with the name, ecosystem and version of up to 1000 components.
3. It then fetches details for up to 60 advisories to get the summary, CVE alias and severity.
4. Each hit becomes a finding with the id `osv.<advisory>.<package>`, the severity from the advisory (`critical`, `high`, `moderate` as medium, `low`), and a link to the OSV page.

## Privacy

`lookupOSV` is the only function in RevLens that makes a network request, and nothing calls it unless you pass `--osv`, call `check_vulns` over MCP, or press the button in the web app. It sends package names and versions only. It never sends your file, its hashes or its name.

You can pass your own `fetch` as the second argument, for example to route the call through a proxy or to cache results in tests.

## Limits

- A minified bundle without banners or version constants may not reveal its packages. AST fingerprinting for those is on the roadmap.
- Versions from `package.json` dependency ranges are lower bounds, not what was installed, so they get a confidence of 0.5.
- OSV coverage is excellent for npm, Go and PyPI and thinner elsewhere. "No known vulnerabilities" means OSV has none on record, not that there are none.
