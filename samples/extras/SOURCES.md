# samples/extras fixtures

Small real files used by the @revlens/extras tests. Generators live in `src/`.

| file | how it was made | license |
|---|---|---|
| demo-x64.elf | `src/demo.cpp`, Zig 0.17.1 `zig c++ -O1 -target x86_64-linux-gnu`, then `llvm-strip --strip-debug` (see `src/build.sh`) | MIT (this repo) |
| demo-arm64-stripped.elf | `src/demo.cpp`, `zig c++ -O1 -target aarch64-linux-musl -s` (static, stripped, libc++ and musl inside: MIT and Apache-2.0 with LLVM exception) | MIT, Apache-2.0 |
| hello-res.exe | `src/hello-win.c` plus `src/hello.rc` and `src/app.manifest` compiled with llvm-rc 19 and llvm-cvtres 19, linked with `zig cc -target x86_64-windows-gnu` (mingw-w64 runtime, ZPL and public domain parts) | MIT (this repo) |
| hello-arm64.macho | `src/hello.c`, `zig cc -O1 -target aarch64-macos` (Zig signs it ad hoc) | MIT (this repo) |
| demo-msvc.obj | `src/msvc.cpp`, `zig c++ -O1 -target x86_64-windows-msvc -c` (COFF object with MSVC mangled names) | MIT (this repo) |
| kernels.ptx | `src/kernel_nv.zig`, `zig build-obj -target nvptx64-cuda -mcpu=sm_70 -femit-asm` (LLVM NVPTX backend) | MIT (this repo) |
| kernels-gfx906.o | `src/kernel_amd.zig`, `zig build-obj -target amdgcn-amdhsa -mcpu=gfx906` | MIT (this repo) |
| triangle.vert.spv, triangle.frag.spv, emboss.comp.spv | https://github.com/SaschaWillems/Vulkan `shaders/glsl/{triangle,computeshader}/`, GLSL sources copied next to them in `src/` | MIT, Copyright (c) 2016 Sascha Willems |
| add.jsc, add.jsc.json | `src/make_v8_fixture.cjs`: `vm.Script#createCachedData` on Node v22.23.3 (V8 12.4.254.21); the JSON records the facts and that V8 accepts the cache | MIT (this repo) |
| tiny.gguf, tiny.safetensors, tiny.npy, notepad.lnk, fw.hex, board.dtb | `src/make_data_fixtures.py` with gguf-py, safetensors, numpy, pylnk3, intelhex and fdt from PyPI | MIT (this repo) |
| fw-blob.bin, uimage.bin | `src/make_firmware_fixture.py`: uImage written by the `uboot` PyPI package, gzip, board.dtb and an ELF header at fixed offsets | MIT (this repo) |
| jiter-0.5.0.so | the Rust extension from `jiter-0.5.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` on PyPI (pydantic/jiter) | MIT |
| orjson-3.10.7.so | the Rust extension from `orjson-3.10.7-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` on PyPI | Apache-2.0 or MIT |
| go-hello-stripped.elf | `src/hello.go`, Go 1.23.4 `GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w"` (reference addresses come from `go tool nm` on the same build without -s -w) | BSD-3-Clause (Go runtime), MIT (this repo) |
| rootfs.squashfs, rootfs.cpio | a 9 entry tree packed with mksquashfs 4.6.1 (`-comp gzip -all-root -mkfs-time 0 -all-time 0`) and GNU cpio 2.15 (`-o -H newc --owner=0:0 --reproducible`) from the Debian arm64 packages | MIT (this repo) |
| reference.json | `packages/extras/scripts/gen_reference.py`: answers from the independent tools listed in the package README | MIT (this repo) |

Fetched at test time, not committed (`packages/extras/scripts/fetch-fixtures.mjs` writes `samples/.cache/extras/`):

| file | source | why not committed |
|---|---|---|
| strings64.exe | https://download.sysinternals.com/files/Strings.zip (Microsoft signed) | Sysinternals license does not allow redistribution |
| WindowServer.ips | https://gist.github.com/luckman212/5b645096c44936ba8530071fa6a23efd (a public macOS 12 crash report) | no license stated, so it is not redistributed |
