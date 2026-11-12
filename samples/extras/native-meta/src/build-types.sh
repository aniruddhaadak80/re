#!/bin/bash
# Rebuilds the PDB and COM type library fixtures in samples/extras/native-meta.
# Zig 0.17.1 (python -m ziglang), LLVM 19 (llvm-rc, llvm-pdbutil), widl 9.8 from Debian
# mingw-w64-tools 12.0.0-5 (used only as a tool; its output is our own IDL compiled).
set -e
Z=${ZIG:-zig}; L=${LLVM:-/usr/bin}; W=${WIDL:-x86_64-w64-mingw32-widl}
cd "$(dirname "$0")"
$Z cc -target x86_64-windows-gnu -O1 -g -gcodeview -fno-inline-functions -nostdlib -Dmain=revlens_entry -Wl,--entry=revlens_entry types.c -o ../types-x64.exe
$Z c++ -target x86_64-windows-gnu -O1 -g -gcodeview -nostdlib -nostdlib++ -fno-rtti -fno-exceptions -Wl,--entry=revlens_entry shapes.cpp -o ../shapes-x64.exe
$W --win64 -t -o ../revdemo.tlb revdemo.idl
cp ../revdemo.tlb revdemo.tlb && $L/llvm-rc -no-preprocess /FO revdemo.res revdemo.rc && rm revdemo.tlb
$Z cc -target x86_64-windows-gnu -O1 -nostdlib -Wl,--entry=revlens_entry -shared stub.c revdemo.res -o ../revdemo-typelib.dll
rm -f revdemo.res ../revdemo-typelib.pdb ../*.lib
python3 make-pdb-reference.py ../pdb-reference.json ../types-x64.pdb ../shapes-x64.pdb
