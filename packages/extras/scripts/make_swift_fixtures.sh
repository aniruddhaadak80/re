#!/bin/sh
# Builds the Swift fixtures with the official Swift 6.0.3 toolchain for Linux
# (https://download.swift.org/swift-6.0.3-release/debian12-aarch64/, Apache-2.0).
# SWIFT points at the toolchain usr/ directory, SYSROOT at a Debian sysroot with libc6-dev,
# linux-libc-dev and libgcc-14-dev unpacked (dpkg -x) and lib -> usr/lib.
set -e
SWIFT=${SWIFT:-/workspace/work/swiftdl/swift-6.0.3-RELEASE-debian12-aarch64/usr}
SYSROOT=${SYSROOT:-/tmp/sysroot}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=$(mktemp -d)
cd "$OUT"
# NSKeyedArchiver output from swift-corelibs-foundation
"$SWIFT/bin/swiftc" -O -sdk "$SYSROOT" -use-ld=lld "$ROOT/samples/extras/src/swift/keyedarchive.swift" -o ka
LD_LIBRARY_PATH="$SWIFT/lib/swift/linux" ./ka
cp dict.keyedarchive array-xml.keyedarchive "$ROOT/samples/extras/apple/"
# Swift ELF with a varied symbol table for the demangler tests
"$SWIFT/bin/swiftc" -Onone -sdk "$SYSROOT" -use-ld=lld -emit-library -module-name RevDemo "$ROOT/samples/extras/src/swift/demo.swift" -o libRevDemo.so
cp libRevDemo.so "$ROOT/samples/extras/swift/"
