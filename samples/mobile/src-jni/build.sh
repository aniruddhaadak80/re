#!/bin/sh
# Builds samples/mobile/jni/jnidemo.apk: javac (JDK 25) + D8 (r8.jar 8.x) for classes.dex,
# zig 0.15 cc for lib/arm64-v8a and lib/armeabi-v7a libjnidemo.so, zipped by python3 zipfile.
set -e
cd "$(dirname "$0")"
T=${TOOLS:-/workspace/work/tools}
rm -rf build && mkdir -p build/classes build/dex
$T/jdk25/bin/javac --release 8 -d build/classes org/revlens/jnidemo/NativeBridge.java 2>/dev/null || $T/jdk25/bin/javac --release 11 -d build/classes org/revlens/jnidemo/NativeBridge.java
$T/jdk25/bin/java -cp $T/r8.jar com.android.tools.r8.D8 --min-api 21 --output build/dex build/classes/org/revlens/jnidemo/NativeBridge.class
$T/zig/zig cc -target aarch64-linux-musl -shared -fPIC -O1 -s -o build/libjnidemo-arm64.so jnidemo.c
$T/zig/zig cc -target arm-linux-musleabihf -shared -fPIC -O1 -s -o build/libjnidemo-arm.so jnidemo.c
mkdir -p ../jni
python3 - <<'PY'
import zipfile
with zipfile.ZipFile('../jni/jnidemo.apk', 'w', zipfile.ZIP_DEFLATED) as z:
    for name, src in [('classes.dex', 'build/dex/classes.dex'), ('lib/arm64-v8a/libjnidemo.so', 'build/libjnidemo-arm64.so'), ('lib/armeabi-v7a/libjnidemo.so', 'build/libjnidemo-arm.so')]:
        info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, open(src, 'rb').read())
PY
# Member diff fixtures: classes.dex of v1 (above) and v2 (v2/), plus javap -p references
T=${TOOLS:-/workspace/work/tools}
mkdir -p build/c1 build/c2 build/d1 build/d2
$T/jdk25/bin/javac --release 8 -d build/c1 org/revlens/jnidemo/NativeBridge.java 2>/dev/null
$T/jdk25/bin/javac --release 8 -d build/c2 v2/org/revlens/jnidemo/NativeBridge.java v2/Extra.java 2>/dev/null
$T/jdk25/bin/java -cp $T/r8.jar com.android.tools.r8.D8 --min-api 21 --output build/d1 build/c1/org/revlens/jnidemo/*.class
$T/jdk25/bin/java -cp $T/r8.jar com.android.tools.r8.D8 --min-api 21 --output build/d2 build/c2/org/revlens/jnidemo/*.class
cp build/d1/classes.dex ../jni/bridge-v1.dex
cp build/d2/classes.dex ../jni/bridge-v2.dex
(cd build/c1 && $T/jdk25/bin/javap -p -s org/revlens/jnidemo/*.class) > ../jni/bridge-v1.javap.txt
(cd build/c2 && $T/jdk25/bin/javap -p -s org/revlens/jnidemo/*.class) > ../jni/bridge-v2.javap.txt
rm -rf build
