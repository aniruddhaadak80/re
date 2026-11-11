# samples/disasm

Small native test binaries for @revlens/disasm. All of them are built from `src/hello.c`
(written for this repo, public domain / CC0) with `zig cc` 0.17.1 (clang/LLVM, MIT licensed
toolchain, installed from the `ziglang` PyPI wheel) using `-O1 -g0 -fno-inline-functions`.
The C runtime pieces linked in come from glibc stubs, musl (MIT), MinGW-w64 (public domain and
ZPL) and compiler-rt (Apache-2.0 with LLVM exception), as shipped by zig.

| File | Target | Notes |
| --- | --- | --- |
| hello-x64.elf | x86_64-linux-gnu | dynamic, PLT, symbols |
| hello-x64-stripped.elf | x86_64-linux-gnu | same with `-s` (no .symtab) |
| hello-arm64.elf | aarch64-linux-gnu | dynamic, PLT |
| hello-x86.elf | x86-linux-gnu | 32-bit PIC (`call $+5; pop ebx`) |
| hello-arm32.elf | arm-linux-gnueabihf | ARM mode, .ARM.exidx; debug sections removed with `src/strip-debug.py` |
| hello-thumb-static.elf | thumb-linux-musleabihf | static, Thumb-2; debug sections removed with `src/strip-debug.py` |
| hello-x64.exe | x86_64-windows-gnu | PE32+, IAT, .pdata |
| hello-x64.macho | x86_64-macos | __stubs, LC_MAIN, LC_FUNCTION_STARTS |
| hello-arm64.macho | aarch64-macos | same for arm64 |
| hello-fat.macho | universal | the two Mach-O files joined by `src/make-fat.py` |

`reference.json` holds expected values produced by independent tools (capstone 5.0.9,
pyelftools 0.33, pefile 2024.8.26, macholib 1.16.4) through `src/make-reference.py`. The tests
read only the JSON; Python is not needed to run them.

Large Go samples (esbuild 0.24.0, MIT, from the npm registry packages `@esbuild/linux-x64`,
`@esbuild/win32-x64`, `@esbuild/darwin-arm64`) are downloaded on demand by
`packages/disasm/scripts/fetch-fixtures.mjs` into `samples/.cache/disasm/` and are not committed.
