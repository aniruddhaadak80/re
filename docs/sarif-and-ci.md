---
title: SARIF and CI
description: Run RevLens in GitHub Actions, upload SARIF to code scanning, and gate builds on high severity findings.
order: 6
---

# SARIF and CI

RevLens writes [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), the format GitHub code scanning, Azure DevOps and many IDEs read. That means findings about your build output, such as a leaked key in a bundle, a new install script or a source map in production, show up where your team already looks.

## What the SARIF contains

- One `run` with the driver name `RevLens`, its version and `informationUri` pointing at the repo.
- One `rule` per finding kind, for example `extaudit/ext.perm.<all_urls>` or `sourcemap/sourcemap.present`. Each rule carries the finding title, its detail and a `security-severity` score so GitHub can sort alerts: critical 9.5, high 8.0, medium 5.5, low 3.0, info 0.0.
- One `result` per finding. Critical and high map to `error`, medium to `warning`, low and info to `note`. The location is the file (or the archive member path) with a `byteOffset` and `byteLength` when the finding has an offset.
- One `artifact` with the file size and SHA-256.

A real result from esbuild 0.24.0:

```json
{
  "ruleId": "surface/surface.http",
  "level": "note",
  "message": { "text": "1 plain HTTP endpoints. Traffic to http://.pnp.jsbaseUrlUpgradeTrailersocks5hHEADERS is not encrypted and can be read or changed on the network." },
  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "esbuild-0.24.0.exe" } } }],
  "properties": { "analyzer": "surface", "severity": "low" }
}
```

## GitHub Actions: the basic recipe

```yaml
name: RevLens
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci && npm run build

      - name: Analyze the build output
        run: npx -y revlens sarif ./dist/app.js --out revlens.sarif

      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: revlens.sarif
          category: revlens
```

`security-events: write` is the permission the upload step needs. On public repositories code scanning is free. On private ones it needs GitHub Advanced Security.

## Several artifacts in one job

Put each SARIF file in one folder and upload the folder. Give each artifact its own category so GitHub keeps their alerts apart.

```yaml
      - name: Analyze every artifact
        run: |
          mkdir -p sarif
          for f in dist/*.js dist/*.exe *.vsix *.tgz; do
            [ -e "$f" ] || continue
            npx -y revlens sarif "$f" --out "sarif/$(basename "$f").sarif"
          done

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: sarif
```

## Upload only medium and higher

Low and info findings are useful in a local report and noisy in the Security tab. Filter the SARIF before the upload step. RevLens writes the severity of each result to `properties.severity`:

```yaml
      - name: Keep medium, high and critical results
        run: |
          jq '.runs |= map(.results |= map(select(.properties.severity as $s | ["medium", "high", "critical"] | index($s))))' \
            revlens.sarif > revlens.filtered.sarif

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: revlens.filtered.sarif
          category: revlens
```

Keep the same `category` from run to run. When a later upload in that category no longer contains a result, GitHub closes its alert.

This repository scans its own shipped bundles the same way in `.github/workflows/revlens-scan.yml`, with `scripts/self-scan.mjs`. That script also skips the known self matches listed in `.github/revlens-baseline.json`: RevLens ships its own signatures, so scanning its bundles with those signatures matches them by design.

## Fail the build on high findings

The CLI exits with `0` when it runs, whatever it finds, unless you ask for a gate. The simplest gate is one flag:

```yaml
      - run: npx -y revlens analyze ./dist/app.js --fail-on high
```

That exits with `2` when any high or critical finding exists. For custom logic, read the JSON report with `jq`:

```yaml
      - name: Analyze
        run: npx -y revlens analyze ./dist/app.js --json --out report.json

      - name: Block on high or critical findings
        run: |
          count=$(jq '[.findings[] | select(.severity == "high" or .severity == "critical")] | length' report.json)
          echo "High or critical findings: $count"
          jq -r '.findings[] | select(.severity == "high" or .severity == "critical") | "\(.severity)  \(.title)"' report.json
          test "$count" -eq 0
```

## Check vulnerabilities in CI

Add `--osv` to look up detected components on OSV.dev. This is the only flag that uses the network, so keep it in CI where network access is expected:

```yaml
      - run: npx -y revlens sbom ./dist/app.js --cyclonedx --osv --out bom.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: bom.json
```

## Audit a dependency before it lands

A pull request that bumps a dependency is a good moment to look at what actually ships:

```yaml
      - name: Pack and audit the new version
        run: |
          npm pack left-pad@1.3.0
          npx -y revlens analyze left-pad-1.3.0.tgz --md --out audit.md
          cat audit.md >> "$GITHUB_STEP_SUMMARY"
```

The Markdown report is plain GitHub flavored Markdown, so it renders nicely in the job summary.

## Other CI systems

Any system that can run Node 20.10 or newer can run RevLens. GitLab can show SARIF through its security dashboard converters, and Azure DevOps reads SARIF through the SARIF SAST Scans Tab extension. The JSON report is stable (`schema: "revlens/report@1"`) if you would rather build your own gate.
