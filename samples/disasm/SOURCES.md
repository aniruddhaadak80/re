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

## Jump table, value flow and matching fixtures

Built by `src/build-gaps.sh` with `zig cc` / `zig c++` 0.17.1 (same toolchain and runtime licenses as above).

| File | Source | Target and flags | Used for |
| --- | --- | --- | --- |
| switch-x64.elf | `src/switch.c` (written for this repo, CC0) | x86_64-linux-gnu, `-O2 -fPIE -pie` | relative jump tables, code pointer tables, value flow |
| switch-x64-nopie.elf | `src/switch.c` | x86_64-linux-gnu, `-O2 -fno-pie -no-pie` | absolute jump tables |
| switch-arm64.elf | `src/switch.c` | aarch64-linux-gnu, `-O2` | AArch64 `adr` / `ldrb` / `add` tables |
| switch-x64-O0.elf | `src/switch.c` | x86_64-linux-gnu, `-O0 -fno-omit-frame-pointer` | stack variables, for/break in pseudo code |
| switch-arm64-O0.elf | `src/switch.c` | aarch64-linux-gnu, `-O0` | stack variables on AArch64 |
| virt-x64.elf | `src/virt.cpp` (written for this repo, CC0) | x86_64-linux-gnu, `-O1 -fno-exceptions -fno-rtti -nostdlib++` | virtual calls and vtable slots |
| virt-arm64.elf | `src/virt.cpp` | aarch64-linux-gnu, same flags | virtual calls on AArch64 |
| virt-x64-stripped.elf | virt-x64.elf | all symbols removed by `src/strip-debug.py --all` | vtables found by shape, stripped vs unstripped matching |
| lua-x64.elf | Lua 5.4.7, MIT, https://www.lua.org/ftp/lua-5.4.7.tar.gz | x86_64-linux-gnu, `-O2 -DLUA_USE_LINUX`, with symbols | `luaV_execute` dispatch table, matching ground truth |
| lua-x64-stripped.elf | Lua 5.4.7, same flags, source files linked in reverse order | stripped with `zig objcopy --strip-all` | stripped and reordered build for function matching |

`gaps-reference.json` holds the expected values for these fixtures, read by pyelftools 0.33 through
`src/make-gaps-reference.py`: the function symbols of the unstripped twin of `lua-x64-stripped.elf`
(the ground truth for matching), the address and size of `luaV_execute.disptab` and `luaV_execute`,
and the `_ZTV*` vtable symbols of the two `virt` builds.

The cross version matching test also uses esbuild 0.23.1 (MIT, npm packages `@esbuild/linux-x64`
and `@esbuild/darwin-arm64`), downloaded next to 0.24.0 by `packages/disasm/scripts/fetch-fixtures.mjs`.

## SHA-256 of the committed binaries

These files are checked in because the tests read real binaries; their provenance is listed above.

| File | SHA-256 |
| --- | --- |
| `hello-arm32.elf` | `b0fd45badbf305973095aa1f165fbea19e4d7f1b93335807b51854c8dfefc5ed` |
| `hello-arm64.elf` | `d85e579aacba2e62aabeafc490e7cd66924dd301409ed5dd616c31e0b60ed95a` |
| `hello-arm64.macho` | `e9c9e7b3e3b0a64f0b1ce493f194d776ea601aca351246acd2763c2995ff15b5` |
| `hello-fat.macho` | `19599a3e19fffdef13ceafdb9790a04e6f19787fdf9ea17c57c513ff53bd602f` |
| `hello-thumb-static.elf` | `f512693f8238feee017e1659690c7202f21087c8e0c7a4ef5f962d9108b8b9ce` |
| `hello-x64-stripped.elf` | `6c74f1602d8b4927cbcb19ddb4b3c1dd3683279d66f30b8ed3884b00ce5f6e65` |
| `hello-x64.elf` | `10007deac7b9907fbc82bedb0e63a815ab305e9c8402abf86a9816683cff1ec4` |
| `hello-x64.exe` | `7b90fd885b7fb634a0c9b704d93463732502949d9b925ea941cb1afed83a7f89` |
| `hello-x64.macho` | `1b912fe2f96ef11bd4cee5770ea83b85ad6211e9640fff986bee52d7ed32b769` |
| `hello-x86.elf` | `74e2f2753e2469863f7e1e8f157a37b53d49c06542f51e35b7fb95d468dd1015` |
