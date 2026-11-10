# Changelog

All notable changes to RevLens are written down here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and RevLens uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, a minor version may change the report shape. We will always call that out here.

## [Unreleased]

Nothing yet.

## [0.1.1] - 2026-11-10

A security and supply chain release. No change to the report shape.

### Security

- Fixed a regular expression denial of service in the `entropy` analyzer. The javascript-obfuscator hex identifier fingerprint used `(?:_0x....*){40}` with the dotall flag, which backtracked exponentially on text with fewer than 40 matches. It now counts matches with a linear global search.
- Bounded the OpenAI key pattern in the `secrets` analyzer, which was quadratic on repeated `sk-` prefixes.
- The `strings` analyzer tags only the first 512 characters of each string, and the email tag no longer restarts at every dot, so huge or crafted strings stay linear.
- yara-lite now has hard limits on rule text size, rule count, string definition length, condition length, hex jumps, byte comparisons per string and condition evaluation steps (`YARA_LIMITS`). Comments are stripped in one linear pass, the rule header and string definition patterns can no longer backtrack quadratically, and regex strings with nested quantifiers or backreferences are refused with a clear message (`assertSafeRegex`).
- `toHTML` escapes every value from the report, including severity, offsets, hashes and the tool version, coerces numbers, and adds a strict Content-Security-Policy meta tag that blocks scripts.
- The web app sanitizes mermaid SVG with DOMPurify before it reaches the DOM, skips raw HTML in markdown, and only keeps http, https, mailto, anchor and relative links.
- Fixed issues raised by CodeQL: yara-lite `meta` keys such as `__proto__` can no longer reach an object prototype, the CLI and MCP server check and read a file through one descriptor so it cannot be swapped between the two steps (file system race), the SARIF rule id stem no longer uses a quadratic regex, the analysis worker validates every message and checks its origin, and heading slugs drop tags without a partial regex sanitizer.
- The theme bootstrap script moved out of `index.html` into `theme.js`, so the site runs under the Content-Security-Policy in `vercel.json` without inline scripts. `vite preview` now serves the same headers, so the browser tests run under that policy.

### Changed

- Upgraded to Vite 8 and `@vitejs/plugin-react` 6. Chunk groups use `build.rolldownOptions.output.codeSplitting`.
- Upgraded `react-router-dom` to 7, Playwright to 1.65, zod to 4 and `@modelcontextprotocol/sdk` to 1.32, which supports zod 4. `npm audit` reports 0 vulnerabilities.
- `playwright.config.ts` accepts `PW_CHROMIUM` with the path to a local Chromium, for hosts where Playwright has no browser build, such as Linux arm64.
- The RevLens self scan now scans the code this repository ships (`packages/cli/dist`, `packages/mcp/dist` and `apps/web/dist`) with `scripts/self-scan.mjs` and uploads only medium, high and critical findings. Known self matches, from the signatures RevLens ships, are listed with a reason in `.github/revlens-baseline.json`. The old demo upload of a sample package is gone.
- Every GitHub Action is pinned to a full commit SHA with a version comment, workflows default to read only tokens, and write permissions are granted per job.

### Added

- CodeQL code scanning with the `security-extended` and `security-and-quality` query suites, on push, pull request and weekly.
- OpenSSF Scorecard workflow with published results and SARIF upload.
- Dependabot for npm (weekly, grouped) and GitHub Actions (weekly).
- Hostile input tests for the analyzers, yara-lite and `toHTML`, and property based fuzz tests with fast-check (`packages/core/test/fuzz.test.ts`, `REVLENS_FUZZ_RUNS` sets the run count).

## [0.1.0] - 2026-11-10

The first public release.

### Added

#### Core (`@revlens/core`)

- `analyze(bytes, options)`: one pass over a `Uint8Array` that returns a `revlens/report@1` report. Pure TypeScript, no Node built-ins, works in the browser, Web Workers, Deno, Bun and Node.
- Format detection by magic bytes, name and content for ELF, PE, Mach-O, universal Mach-O, WebAssembly, ZIP, JAR, APK, CRX, XPI, VSIX, npm tarballs, gzip, tar, Electron ASAR, JavaScript, source maps, JSON, PDF, `.pyc`, DEX, Java class files and text.
- Hashes in pure TypeScript: MD5, SHA-1, SHA-256, a TLSH-like locality digest and a CTPH fuzzy hash.
- 15 analyzers:
  - `elf`: sections with entropy, `DT_NEEDED`, dynamic imports and exports, PIE, stripped, NX and RELRO hints.
  - `pe`: sections with entropy, imports per DLL, imphash compatible with pefile, ASLR, DEP, CFG, high entropy VA, Authenticode presence.
  - `macho`: segments with entropy, linked dylibs, code signature presence, entry point, universal binary slices.
  - `wasm`: section counts, imports by module, exports, custom sections.
  - `buildinfo`: Go toolchain version, main module, build settings and module dependencies, Rust markers.
  - `entropy`: a 64 block entropy map, high entropy findings, packer markers (UPX, ASPack, MPRESS, Themida or WinLicense, VMProtect, Enigma, PECompact, Petite) and JavaScript obfuscator fingerprints.
  - `strings`: ASCII and UTF-16LE strings with tags, interesting ones first.
  - `archive`: member listing, zip slip and decompression bomb checks, and recursive child reports for up to 60 members, two levels deep.
  - `extaudit`: browser extension permissions, all sites host access, weak CSP, Manifest V2, VS Code activation events, npm install scripts and remote script references.
  - `sbom`: npm components with versions and purl ids from banners, license comments, runtime constants and module paths, plus bundler detection.
  - `sourcemap`: external map references, inline maps and `sourcesContent` coverage.
  - `secrets`: 16 credential patterns with redaction in every output.
  - `surface`: URLs, hosts, API paths, GraphQL operations, Electron IPC channels, feature flags, storage keys and plain HTTP endpoints.
  - `capa`: 15 capabilities from imports and strings, mapped to MITRE ATT&CK.
  - `yara`: the yara-lite engine with a 13 rule starter pack.
- yara-lite: text strings with `nocase`, `wide`, `ascii` and `fullword`, hex strings with wildcards and jumps, regex strings, and conditions with boolean logic, string sets, counts, offsets, `at`, `in`, `filesize`, integer reads and arithmetic. Exposed as `scanRules`, `parseRules` and `STARTER_RULES`.
- `diff(a, b)`: a `revlens/diff@1` report of changed components, imports, exports, endpoints, tagged strings, sections, findings and capabilities, with a one line summary.
- `verifyClaim(bytes, claim, report)`: `VERIFIED`, `REFUTED` or `UNKNOWN` with evidence for seven claim kinds.
- Output formats: `toMarkdown`, `toHTML` (self contained, escaped, no scripts), `toSARIF` (SARIF 2.1.0 with security severity scores) and `toCycloneDX` (CycloneDX 1.5).
- `lookupOSV(components)`: opt in vulnerability lookup through the OSV.dev batch API. The only network call in RevLens.

#### CLI (`revlens`)

- Commands: `analyze`, `diff`, `verify`, `rules`, `sbom`, `sarif` and `serve-mcp`.
- Flags: `--json`, `--md`, `--html`, `--sarif`, `--cyclonedx`, `--osv`, `--rules <file>` and `--out <path>`.

#### MCP server (`@revlens/mcp`)

- A stdio MCP server with 12 tools: `analyze_file`, `list_findings`, `get_strings`, `get_sections`, `get_imports`, `sbom`, `check_vulns`, `scan_rules`, `diff_files`, `verify_claim`, `hexdump` and `list_analyzers`.
- Setup guides for Claude Code, Codex CLI, Cursor, Gemini CLI, VS Code and other clients.

#### Web app

- A Vite and React app on GitHub Pages that runs the core in a Web Worker. Files never leave the browser.
- Drop zone, "Try a sample" buttons, findings, entropy map, SBOM, rules and diff views.
- Docs and blog rendered from the Markdown in this repository.

#### Docs, blog and media

- 13 documentation pages, from getting started to the security model.
- Five launch blog posts with real results on esbuild, uBlock Origin, jQuery and the Red Hat YAML extension.
- A launch video, a vertical cut and six short feature previews.
- Contributing guide, security policy, code of conduct, issue forms and a pull request template.

### Known limits

- No decompilation or disassembly. RevLens hands deep native work to tools like REA, GhidraMCP, ida-pro-mcp and r2mcp.
- Signatures are detected, not validated.
- yara-lite has no modules, `for` loops or hex alternations yet.
- Go binaries can produce low severity URL noise because Go stores string literals end to end.

[Unreleased]: https://github.com/aniruddhaadak80/re/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/aniruddhaadak80/re/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aniruddhaadak80/re/releases/tag/v0.1.0
