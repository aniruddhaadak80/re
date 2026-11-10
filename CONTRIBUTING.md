# Contributing to RevLens

Thank you for thinking about helping. RevLens gets better every time someone adds a packer marker, fixes a false positive, writes a rule or improves a sentence in the docs. You do not need to be a reverse engineering expert to contribute, and small pull requests are very welcome.

## Ways to help

- **Report a false positive or a missed finding.** Use the bug form. A public file we can fetch (from npm, a store or a release page) is the most useful thing you can give us.
- **Ask for a format or analyzer.** Use the analyzer request form and tell us what you would like to learn from the file.
- **Add a rule** to the starter pack in `packages/core/src/rules/starter.ts`.
- **Add a secret pattern, packer marker or capability** in the matching analyzer.
- **Improve the docs or the blog.** If something confused you, it will confuse others.
- **Try RevLens with your agent** and tell us which tool answers felt too long or too short.

## Setup

You need Node.js 22 (see `.nvmrc`) and npm.

```bash
git clone https://github.com/aniruddhaadak80/re.git
cd re
npm install
npm test
npm run typecheck
```

Run the CLI from source:

```bash
npm run cli -- analyze samples/jquery.min.js
```

Run the web app:

```bash
npm run dev -w @revlens/web
```

## Project layout

| Path | What lives there |
| --- | --- |
| `packages/core` | The engine: format detection, hashes, analyzers, rules, diff, verify, outputs. |
| `packages/cli` | The `revlens` command. |
| `packages/mcp` | The MCP server. |
| `apps/web` | The web app. |
| `docs/` | Documentation pages. |
| `content/blog/` | Blog posts. |
| `samples/` | Small real files used by tests and the web app. |

## Rules for code

1. **Real files, no format mocks.** Tests run analyzers on real files from `samples/`. If you need a new sample, use a public file with a clear license and keep it under about 2 MB. Larger samples go in `samples/fetch-samples.mjs`, which downloads them on demand.
2. **No Node built-ins in `packages/core/src`.** The core must run in a browser. Use `Uint8Array`, `DataView` and web standard APIs only.
3. **No native dependencies.** Not in core, not in the CLI, not in the MCP server.
4. **Never trust the input.** Check lengths and offsets, cap loops, and let a broken file produce a smaller report instead of an exception.
5. **Every finding needs evidence.** An offset, a length, a snippet or an archive path, so a person can check it in seconds.
6. **TypeScript strict, ESM only.** `npm run typecheck` must pass.
7. **Keep `types.ts` additive.** If you need a new field, add it as optional and mention it in your pull request.

## Adding an analyzer

1. Create `packages/core/src/analyzers/<name>.ts` and export an `Analyzer` with an `id`, `title`, `description`, `applies` and `run`.
2. Register it in `packages/core/src/analyzers/index.ts`, after the analyzers whose output it reads.
3. Add `packages/core/test/<name>.test.ts` that runs it on a real sample and checks real values.
4. Document it in `docs/analyzers.md`: what it reads, what it reports, its limits, and a real example.
5. Add a line to `CHANGELOG.md` under Unreleased.

## Adding a rule to the starter pack

Each rule needs a `description`, a `severity` and, when one fits, an `attack` id in its `meta`. Test it against at least one file it should match and one it should not, and say which files in your pull request. Rules that fire on popular, clean files (jQuery, React, lodash, esbuild) will be sent back for tuning.

## Writing style

This applies to code comments, finding text, CLI output, docs and the blog.

- Use simple, human words. Write like you are explaining to a friend who codes.
- Use "we" for the project and "you" for the reader.
- No em dashes, no exclamation marks, no emojis.
- Prefer short paragraphs over long bullet lists in prose.
- Finding details should say what was found, why it matters and what to do next.
- Colors in any UI, SVG or media stay in the brand palette: gold `#F5B301` and `#FFD166`, teal `#14B8A6`, near black `#0A0A0B`, with amber, emerald and sky as accents. Never purple or pink.

## Pull requests

- Keep each pull request about one thing.
- Fill in the template, including how you tested.
- Make sure `npm test` and `npm run typecheck` pass.
- Be patient and kind in review. We will be too.

## Security issues

Please do not open a public issue for a security problem in RevLens. Follow [SECURITY.md](SECURITY.md) instead.

## Code of Conduct

Everyone who takes part in this project is expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
