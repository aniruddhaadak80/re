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
| fw.uf2 | 3000 bytes of demo-arm64-stripped.elf converted with Microsoft uf2conv.py (https://github.com/microsoft/uf2, MIT): `uf2conv.py -c -b 0x10000000 -f RP2040` | MIT (this repo) |
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

## windows/ (registry hives, Prefetch, Jump Lists)

| File | Source | License |
| --- | --- | --- |
| `SAM.gz`, `BCD`, `SECURITY`, `NTUSER.DAT.gz` | regipy test data, https://github.com/mkorman90/regipy/tree/master/regipy_tests/data (xz there, recompressed with gzip or stored raw here) | MIT |
| `*-*.pf` (XP, Vista, 7, 8.x, 10 compressed) | Eric Zimmerman Prefetch test files, https://github.com/EricZimmerman/Prefetch/tree/master/Prefetch.Test/TestFiles | MIT |
| `win10-*.automaticDestinations-ms`, `win7-*.automaticDestinations-ms`, `dtformats-*.customDestinations-ms` | Eric Zimmerman JumpList test files, https://github.com/EricZimmerman/JumpList/tree/master/JumpList.Test/TestFiles | MIT |

Expected values for these and the other gap formats live in `reference-gaps.json`, written by
`packages/extras/scripts/gen_reference_gaps.py` from regipy 6.5.0, windowsprefetch 4.0.3 (with
dissect.util 3.24 LZXPRESS Huffman standing in for the Windows-only RtlDecompressBufferEx),
olefile 0.47 and LnkParse3 1.6.0.

## apple/ (NSKeyedArchiver, compiled nibs)

| File | Source | License |
| --- | --- | --- |
| `SUUpdateAlert.nib`, `SUUpdatePermissionPrompt.nib` | Sparkle 2.10.1 `Sparkle-for-Swift-Package-Manager.zip`, `Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework/Versions/B/Resources/`, https://github.com/sparkle-project/Sparkle/releases/tag/2.10.1 (compiled by Xcode ibtool) | MIT |
| `dict.keyedarchive`, `array-xml.keyedarchive` | written by `src/swift/keyedarchive.swift` built with the Swift 6.0.3 toolchain for Linux (swift-corelibs-foundation NSKeyedArchiver), see `packages/extras/scripts/make_swift_fixtures.sh` | MIT (this repo) |

Fetched by `fetch-fixtures.mjs` (not committed, 1.7 MB and 5 MB): `maccy-Assets.car` and
`maccy-Maccy.macho` from Maccy 2.8.0 `Maccy.app.zip` (MIT, https://github.com/p0deje/Maccy/releases/tag/2.8.0).
The Assets.car test checks the facet names against the asset catalog source of that release
(https://github.com/p0deje/Maccy/tree/2.8.0/Maccy/Assets.xcassets).

## containers/ (wxapkg, UnityFS, single-file JavaScript executables)

| File | Source | License |
| --- | --- | --- |
| `demo.wxapkg` | `src/wxapkg/` packed with KillWxapkg v2.4.1 `-repack` (https://github.com/Ackites/KillWxapkg, built with Go 1.23.4) | MIT (this repo) |
| `demo-pc-encrypted.wxapkg` | `demo.wxapkg` encrypted the way the WeChat PC client does (PBKDF2-SHA1 AppID key, AES-CBC first 1024 bytes, XOR rest) for AppID `wx1234567890abcdef`; KillWxapkg decrypts it back byte for byte | MIT (this repo) |
| `ExternalAssets.unity3d` | Unity 5.5.0f3 asset bundle from https://github.com/rygo6/CardExample-Unity/blob/master/ExternalAssets/ExternalAssets | MIT |
| `ExternalAssets-lz4.unity3d` | the same bundle rewritten by UnityPy 1.10.18 `BundleFile.save(packer="lz4")` (LZ4 data block, blocks info at the end) | MIT |
| `node-sea-prep.blob` | `node --experimental-sea-config src/standalone/sea-config.json` with node 22.23.3 | MIT (this repo) |
| `bun-1.4.4-graph.bin` | the module graph section (length, graph, offsets, trailer) cut from `bun build --compile src/standalone/app.ts` with Bun 1.4.4 linux-aarch64 | MIT (this repo) |
| `deno-2.9.8-payload.bin` | the d3n0l4nd payload cut from `deno compile --no-check src/standalone/app.ts` with Deno 2.9.8 linux-aarch64 | MIT (this repo) |

`packages/extras/scripts/make_standalone_fixtures.sh` rebuilds the full 100 MB executables into
`samples/.cache/extras/standalone/` (not committed); `fetch-fixtures.mjs` downloads the 1.2 MB
`unity-cards.unity3d` bundle (CardExample-Unity, MIT).

## swift/ (Swift demangler references)

| file | how it was made | license |
|---|---|---|
| `manglings-ref.json` | 470 mangled names from `test/Demangle/Inputs/manglings.txt` in the Swift project at swift-6.0.3-RELEASE (https://github.com/swiftlang/swift/blob/swift-6.0.3-RELEASE/test/Demangle/Inputs/manglings.txt). `ref` and `simplified` are the output of `swift-demangle -compact` and `swift-demangle -compact -simplified` from the Swift 6.0.3 toolchain (swift-6.0.3-RELEASE-debian12-aarch64), each name passed as one argument; `file` is the expected text from manglings.txt | Apache-2.0 with Runtime Library Exception (Swift project) |
| `maccy-symbols-ref.json` | the 1947 Swift symbol names (`_$s...`) in the Mach-O symbol table of `Maccy.app/Contents/MacOS/Maccy` from Maccy 2.8.0 (https://github.com/p0deje/Maccy/releases/download/2.8.0/Maccy.app.zip), with the same two swift-demangle 6.0.3 outputs. The binary itself is fetched by `packages/extras/scripts/fetch-fixtures.mjs` as `samples/.cache/extras/maccy-Maccy.macho` | MIT (Maccy) |

## API contracts (samples/extras/contracts)

Built by RevLens from sources in samples/extras/src/proto and samples/extras/src/contracts-js (MIT, this repo) with real toolchains.

| file | how it was made |
|---|---|
| revdemo-go.elf.gz | `src/proto/build.sh`: protoc 29.3 + protoc-gen-go v1.36.5 code for revdemo.proto, Go 1.23.4 linux/amd64 `-trimpath -ldflags "-s -w"`, embeds openapi.yaml and schema.graphql with go:embed, then gzip -9. Links google.golang.org/protobuf v1.36.5 (BSD-3-Clause). |
| revdemo_pb2.py, revdemo_pb2.pyc | `protoc --python_out` (protobuf Python 5.29.3 gencode) and CPython 3.12 py_compile |
| revdemo.desc | `protoc --descriptor_set_out`, the reference FileDescriptorSet |
| introspection.json | graphql-js 16 `introspectionFromSchema(buildSchema(schema.graphql))` |
| app.bundle.min.js | `src/contracts-js/make.mjs`: esbuild minified ESM bundle of app.js with gql templates, query strings, a precompiled GraphQL document from graphql-js `parse`, the introspection as a JSON.parse string, and petstore.json inlined as a JS object literal |
| src/contracts-js/petstore.json | https://raw.githubusercontent.com/OAI/learn.openapis.org/main/examples/v3.0/petstore.json (OpenAPI Initiative, Apache-2.0) |

## SHA-256 of the committed binaries

These files are checked in because the tests read real binaries; their provenance is listed above.

| File | SHA-256 |
| --- | --- |
| `demo-arm64-stripped.elf` | `18edfbea9a68e5b15946f9d864afe0ec40dd555dfbceaaf9f803cc9c6b5a431d` |
| `demo-x64.elf` | `1aa324d6885e99cbcf535e6d547680b85a7a3e70bd8abff4fb3bffd23e012356` |
| `go-hello-stripped.elf` | `d2b52119436583afb65577ed3f76895b334ced4d772f9698482ecdb5e5bc6afa` |
| `hello-arm64.macho` | `9e339b6ff25673eea2858d95ec201ac57e443507070940763d9111b14ee1d6a8` |
| `hello-res.exe` | `0e0c3fb5e2fce78cbf4ffe9e6926c36e83d7b2b75057c73f11a38378984b5170` |
| `jiter-0.5.0.so` | `c18af484ce5a42352e9fdf8f36005872c70a98359a7df154c21a5d63c6894e1b` |
| `kernels-gfx906.o` | `56d8ae53652d90a3982c4fb19564d918668ffacc284e50929ea7f785ff9c6710` |
| `orjson-3.10.7.so` | `508d35f1f3ee70623d846836d717e38dacc3756ab897fa0d8e58da77f1d63993` |
