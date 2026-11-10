# Samples

Real files used by the tests and by the "Try a sample" buttons on the site. Nothing here is synthetic.

| File | What it is | Source |
| --- | --- | --- |
| `ls-linux.elf` | GNU coreutils `ls`, AArch64 PIE | Debian coreutils |
| `react-dom.production.min.js` | React DOM 18.3.1 UMD bundle | npm `react-dom@18.3.1` |
| `jquery.min.js`, `jquery.min.map` | jQuery 3.7.1 and its source map | npm `jquery@3.7.1` |
| `left-pad-1.3.0.tgz` | The famous left-pad package tarball | npm `left-pad@1.3.0` |

Larger binaries are not committed. `node samples/fetch-samples.mjs` downloads them into `samples/.cache/` from their official sources:
esbuild 0.24.0 for Windows (PE, Go), macOS arm64 (Mach-O, Go) and WebAssembly, uBlock Origin for Firefox (XPI) and the Red Hat YAML extension for VS Code (VSIX).
