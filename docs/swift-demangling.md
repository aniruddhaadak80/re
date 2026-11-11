---
title: Swift demangling
description: Turn Swift symbol names from Mach-O and ELF binaries back into readable declarations, with output that matches swift-demangle 6.0.3, in pure TypeScript with nothing to install.
order: 24.7
---

# Swift demangling

Swift binaries are full of names like `$s4main3FooV3baryySiF`. RevLens turns them back into `main.Foo.bar(Swift.Int) -> ()` with a TypeScript port of the demangler from the Swift project (release 6.0.3). It runs in Node and in the browser, so you do not need Xcode or a Swift toolchain.

## Use it

```sh
revlens x-swift-demangle '$s4main3FooV3baryySiF'                  # main.Foo.bar(Swift.Int) -> ()
revlens x-swift-demangle '$s4main3FooV3baryySiF' --simplified     # Foo.bar(_:)
revlens x-swift-demangle '$sSaySiGSgD' --simplified               # [Int]?
revlens x-swift-demangle MyApp.app/Contents/MacOS/MyApp --filter ViewModel
```

With a binary path (Mach-O, fat Mach-O or ELF), you get the Swift symbols of its symbol table with their addresses. `--tree` adds the demangler's node tree for each name, capped in depth and size, which helps when you want the module, type and function parts as data rather than text.

The MCP tool is `x_swift_demangle` with the same options. `x_demangle` and `revlens x-demangle` also pick Swift automatically alongside Itanium C++, Rust and MSVC names.

## What it covers

- Old Swift 1 to 3 mangling (`_T`).
- The new mangling: Swift 4 `_T0`, Swift 4.x `$S`, Swift 5 and later `$s`, and macro expansion names (`@__swiftmacro_`).
- The default output and the simplified output of `swift-demangle`.
- In TypeScript code: `demangleSwift(sym, { simplified })` returns the text or null, `swiftDemangleCompat(sym)` returns the input unchanged on failure like `swift-demangle` does, and `demangleSwiftTree(sym)` returns the node tree.

## How it was checked

The tests run against `swift-demangle` from the Swift 6.0.3 toolchain, one name per argument:

- 470 of 470 names from the Swift project's own `test/Demangle/Inputs/manglings.txt` (247 old mangling, 223 new) are identical.
- 1947 of 1947 Swift symbols from the Maccy 2.8.0 Mach-O are identical.
- Both hold for the default and the simplified output, and the tests fail if either count drops.
- fast-check feeds random and deeply nested names to make sure bad input returns null instead of hanging.

## Limits

- Manglings added after Swift 6.0.3, such as the embedded `$e` prefix from Swift 6.1, are not recognized.
- Only the default and simplified print options are tested.
- Names over 16 KiB, nesting over 1024 levels or output over 1 MiB return null. The printer stops at 768 levels like `swift-demangle`.

## License

The demangler files in `packages/extras/src/demangle/swift/` are a port of code from the [Swift project](https://github.com/swiftlang/swift), Copyright Apple Inc. and the Swift project authors, and stay under the Apache License 2.0 with Runtime Library Exception. The rest of RevLens is MIT. See [NOTICE](https://github.com/aniruddhaadak80/re/blob/main/NOTICE) and [LICENSE-SWIFT.txt](https://github.com/aniruddhaadak80/re/blob/main/packages/extras/LICENSE-SWIFT.txt).
