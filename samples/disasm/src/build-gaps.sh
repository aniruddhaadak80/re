#!/bin/sh
# Rebuilds the jump table, virtual call and matching fixtures with zig cc 0.17.1.
# Usage: ZIG=/path/to/zig LUA=/path/to/lua-5.4.7 sh build-gaps.sh  (run from samples/disasm)
set -e
ZIG=${ZIG:-zig}
SRC=src
# switch.c: PIE x86-64 (relative tables), non PIE x86-64 (absolute tables), AArch64
$ZIG cc -target x86_64-linux-gnu -O2 -g0 -fPIE -pie -o switch-x64.elf $SRC/switch.c
$ZIG cc -target x86_64-linux-gnu -O2 -g0 -fno-pie -no-pie -o switch-x64-nopie.elf $SRC/switch.c
$ZIG cc -target aarch64-linux-gnu -O2 -g0 -o switch-arm64.elf $SRC/switch.c
# switch.c at -O0 (stack variables, loops with for/break in pseudo code)
$ZIG cc -target x86_64-linux-gnu -O0 -g0 -fno-sanitize=undefined -fno-omit-frame-pointer -o switch-x64-O0.elf $SRC/switch.c
$ZIG cc -target aarch64-linux-gnu -O0 -g0 -fno-sanitize=undefined -o switch-arm64-O0.elf $SRC/switch.c
# virt.cpp without the C++ standard library
$ZIG c++ -target x86_64-linux-gnu -O1 -g0 -fno-exceptions -fno-rtti -nostdlib++ -o virt-x64.elf $SRC/virt.cpp
$ZIG c++ -target aarch64-linux-gnu -O1 -g0 -fno-exceptions -fno-rtti -nostdlib++ -o virt-arm64.elf $SRC/virt.cpp
# Lua 5.4.7 (MIT): one build with symbols, one stripped build linked in a different file order
if [ -n "$LUA" ]; then
  L=$(cd "$LUA" && ls *.c | grep -v -E '^(ltests|onelua|luac)\.c$')
  FILES=""; for f in $L; do FILES="$FILES $LUA/$f"; done
  RFILES=""; for f in $L; do RFILES="$LUA/$f $RFILES"; done
  $ZIG cc -target x86_64-linux-gnu -O2 -g0 -DLUA_USE_LINUX -o lua-x64.elf $FILES -lm
  $ZIG cc -target x86_64-linux-gnu -O2 -g0 -DLUA_USE_LINUX -o lua-x64-reordered.unstripped $RFILES -lm
  $ZIG objcopy --strip-all lua-x64-reordered.unstripped lua-x64-stripped.elf
fi
# stripped copy of the virtual call fixture (no .symtab): vtables must be found by shape
python3 $SRC/strip-debug.py virt-x64.elf virt-x64-stripped.elf --all
