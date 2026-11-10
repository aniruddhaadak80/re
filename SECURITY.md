# Security policy

RevLens is built to read files people do not trust. If you find a way for a file to hurt the person analyzing it, we want to know and we want to fix it quickly.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| older | No |

## What counts as a vulnerability

Please report anything where a crafted file or input can make RevLens:

- crash the browser tab, the CLI or the MCP server in a way that a normal `try` and `catch` does not contain,
- hang or loop for a long time,
- use unbounded memory, for example through a decompression bomb that gets past our limits,
- run any code from the analyzed file,
- write outside the output file you asked for,
- leak an unredacted secret into a report,
- inject script or markup into the HTML report or the web app,
- send any data over the network other than the opt in OSV.dev lookup.

Also report weaknesses in our release process, such as a way to publish to our npm packages or GitHub Pages without permission.

## What is not a vulnerability

- A false positive or a missed finding. Please open a normal bug report for those.
- Findings about a third party file. RevLens reports them, it does not cause them.
- A crash on a file that is only possible when you edit RevLens itself.

## How to report

Please report privately through GitHub: go to the [Security tab of the repository](https://github.com/aniruddhaadak80/re/security) and choose "Report a vulnerability". This opens a private advisory that only the maintainers can see.

If that is not possible for you, contact the maintainer, [Aniruddha Adak](https://github.com/aniruddhaadak80), through the contact details on his GitHub profile and ask for a private channel. Please do not put details in a public issue, a pull request or a social post.

Helpful things to include:

- the RevLens version and where you ran it (browser and version, or Node version and OS),
- a minimal file or script that shows the problem, or clear steps to build one,
- what happened and what you expected,
- any idea you have for a fix.

## What happens next

- We aim to confirm we received your report within 3 days.
- We aim to share an assessment and a plan within 10 days.
- We will keep you updated, credit you in the advisory and the changelog if you would like, and agree on a disclosure date with you.

RevLens is maintained by a small team, so these are goals, not guarantees. We will always tell you honestly where things stand.

## Safe harbor

We will not take legal action against anyone who reports a vulnerability in good faith, follows this policy, avoids harming users or data, and gives us reasonable time to fix the issue before sharing it.
