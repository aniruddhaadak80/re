#!/bin/sh
# Rebuilds the extras fixtures with Zig (python -m ziglang, zig 0.17.1) and LLVM 19 tools.
set -x
Z="python3 -m ziglang"
L=/workspace/work/tools/sysroot/usr/lib/llvm-19/bin
cd "$(dirname "$0")"
$Z c++ -O1 -target x86_64-linux-gnu demo.cpp -o ../demo-x64.elf
$Z c++ -O1 -target aarch64-linux-musl -s demo.cpp -o ../demo-arm64-stripped.elf
$L/llvm-rc -no-preprocess /FO hello.res hello.rc && $L/llvm-cvtres /machine:x64 /out:hello-res.obj hello.res
$Z cc -O1 -target x86_64-windows-gnu hello-win.c hello-res.obj -o ../hello-res.exe
$Z cc -O1 -target aarch64-macos hello.c -o ../hello-arm64.macho
$Z c++ -O1 -target x86_64-windows-msvc -c msvc.cpp -o ../demo-msvc.obj
echo done
rm -f ../hello-res.pdb ../hello-win.lib ../*.lib
L=/workspace/work/tools/sysroot/usr/lib/llvm-19/bin; $L/llvm-strip --strip-debug ../demo-x64.elf
