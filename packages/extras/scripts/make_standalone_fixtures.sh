#!/bin/sh
# Builds real single-file executables into samples/.cache/extras/standalone and the small
# committed excerpts in samples/extras/containers. Needs node (>= 20), npx, curl and unzip.
#   Node SEA: node --experimental-sea-config + postject 1.0.0-alpha.6 (MIT)
#   Bun:      bun 1.4.4 `bun build --compile` (https://github.com/oven-sh/bun/releases, MIT)
#   Deno:     deno 2.9.8 `deno compile --no-check` (https://github.com/denoland/deno/releases, MIT)
set -e
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SRC="$ROOT/samples/extras/src/standalone"
OUT="$ROOT/samples/.cache/extras/standalone"
mkdir -p "$OUT"; W=$(mktemp -d); cd "$W"
cp "$SRC"/hello.js "$SRC"/greeting.txt "$SRC"/sea-config.json "$SRC"/app.ts "$SRC"/lib.ts .
node --experimental-sea-config sea-config.json
cp "$(command -v node)" node-sea-hello
npx -y postject@1.0.0-alpha.6 node-sea-hello NODE_SEA_BLOB sea-prep.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
cp node-sea-hello "$OUT/"
ARCH=$(uname -m | sed 's/x86_64/x64/; s/arm64/aarch64/')
curl -sL -o bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-$ARCH.zip" && unzip -oq bun.zip
"./bun-linux-$ARCH/bun" build --compile app.ts --outfile app-bun && cp app-bun "$OUT/"
DARCH=$(uname -m | sed 's/arm64/aarch64/')
curl -sL -o deno.zip "https://github.com/denoland/deno/releases/download/v2.9.8/deno-$DARCH-unknown-linux-gnu.zip" && unzip -oq deno.zip
./deno compile --no-check -o app-deno app.ts && cp app-deno "$OUT/"
echo "built in $OUT"
