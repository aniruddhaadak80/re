#!/bin/sh
# Rebuilds the extras fixtures with Zig (python -m ziglang, zig 0.17.1).
set -x
Z="python3 -m ziglang"
cd "$(dirname "$0")"
$Z c++ -O1 -target x86_64-linux-gnu demo.cpp -o ../demo-x64.elf
$Z c++ -O1 -target aarch64-linux-musl -s demo.cpp -o ../demo-arm64-stripped.elf
$Z cc -O1 -target x86_64-windows-gnu hello.c hello.rc -o ../hello-res.exe
$Z cc -O1 -target aarch64-macos hello.c -o ../hello-arm64.macho
$Z c++ -O1 -target x86_64-windows-msvc -c demo.cpp -o ../demo-msvc.obj
echo done
