## What this changes

A short description of the change and why it is needed. Link the issue it closes, for example `Closes #12`.

## Type of change

- [ ] Bug fix or false positive fix
- [ ] New analyzer, rule, secret pattern or packer marker
- [ ] New CLI command, flag or MCP tool
- [ ] Web app
- [ ] Docs, blog or media
- [ ] Build, CI or tooling

## How I tested it

Which real files did you run it on, and what did RevLens report before and after? Paste the relevant output.

```text

```

## Checklist

- [ ] `npm test` passes.
- [ ] `npm run typecheck` passes.
- [ ] New or changed behavior has a test that uses a real file, not a mocked format.
- [ ] No Node built-ins in `packages/core/src` and no new native dependencies.
- [ ] Findings I added carry evidence (offset, length, snippet or archive path).
- [ ] Docs in `docs/` and a line in `CHANGELOG.md` under Unreleased are updated when behavior changed.
- [ ] Text follows the style guide: simple words, no em dashes, no exclamation marks, no emojis.
- [ ] Colors I added stay in the brand palette, with no purple or pink.
