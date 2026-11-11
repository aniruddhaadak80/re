---
title: "Showcase: read .NET and Python bytecode"
description: Identify a .NET assembly, list its types and read one method as CIL, then disassemble a Python 3.12 pyc and list a PyInstaller archive.
order: 3
---

# Showcase: read .NET and Python bytecode

Two managed runtimes, no SDKs installed: `samples/managed/dotnet/System.IO.Compression.Brotli.dll` from .NET 8 and `samples/managed/python/sample_mod.3.12.pyc`, compiled by CPython 3.12.

## 1. What is this assembly

```console
$ revlens dotnet samples/managed/dotnet/System.IO.Compression.Brotli.dll
assembly: System.IO.Compression.Brotli 8.0.0.0
targetFramework: .NETCoreApp,Version=v8.0
runtime: v4.0.30319
machine: amd64 (linux r2r)
flags: IL_LIBRARY STRONGNAMESIGNED
counts: types=18 methods=123 fields=58 memberRefs=161 typeRefs=87 userStrings=30
ref System.Runtime 8.0.0.0 b03f5f7f11d50a3a
ref System.Runtime.InteropServices 8.0.0.0 b03f5f7f11d50a3a
ref System.IO.Compression 8.0.0.0 b77a5c561934e089
ref System.Threading 8.0.0.0 b03f5f7f11d50a3a
ref System.Memory 8.0.0.0 cc7b13ffcd2ddd51
pinvoke libSystem.IO.Compression.Native!BrotliDecoderDecompress -> Interop/Brotli::BrotliDecoderDecompress(nuint, byte*, nuint*, byte*)
pinvoke libSystem.IO.Compression.Native!BrotliDecoderDestroyInstance -> Interop/Brotli::BrotliDecoderDestroyInstance(nint)
pinvoke libSystem.IO.Compression.Native!BrotliEncoderDestroyInstance -> Interop/Brotli::BrotliEncoderDestroyInstance(nint)
pinvoke libSystem.IO.Compression.Native!BrotliEncoderCompress -> Interop/Brotli::BrotliEncoderCompress(int, int, int, nuint, byte*, nuint*, byte*)
pinvoke libSystem.IO.Compression.Native!BrotliDecoderCreateInstance -> Interop/Brotli::<BrotliDecoderCreateInstance>g____PInvoke|0_0(nint, nint, nint)
pinvoke libSystem.IO.Compression.Native!BrotliDecoderDecompressStream -> Interop/Brotli::<BrotliDecoderDecompressStream>g____PInvoke|1_0(nint, nuint*, byte**, nuint*, byte**, nuint*)
pinvoke libSystem.IO.Compression.Native!BrotliDecoderIsFinished -> Interop/Brotli::<BrotliDecoderIsFinished>g____PInvoke|4_0(nint)
pinvoke libSystem.IO.Compression.Native!BrotliEncoderCreateInstance -> Interop/Brotli::<BrotliEncoderCreateInstance>g____PInvoke|5_0(nint, nint, nint)
pinvoke libSystem.IO.Compression.Native!BrotliEncoderSetParameter -> Interop/Brotli::<BrotliEncoderSetParameter>g____PInvoke|6_0(nint, System.IO.Compression.BrotliEncoderParameter, uint)
pinvoke libSystem.IO.Compression.Native!BrotliEncoderCompressStream -> Interop/Brotli::<BrotliEncoderCompressStream>g____PInvoke|7_0(nint, System.IO.Compression.BrotliEncoderOperation, nuint*, byte**, nuint*, byte**, nuint*)
pinvoke libSystem.IO.Compression.Native!BrotliEncoderHasMoreOutput -> Interop/Brotli::<BrotliEncoderHasMoreOutput>g____PInvoke|8_0(nint)
resource FxResources.System.IO.Compression.Brotli.SR.resources 2553 bytes at 5784
resource ILLink.Substitutions.xml 520 bytes at 8341
ReadyToRun 9.1 Crossgen2 8.0.1124.51707
```


## 2. Its types

```console
$ revlens dotnet samples/managed/dotnet/System.IO.Compression.Brotli.dll types --filter Brotli
14 types
0x02000003 class Interop/Brotli
0x02000005 class FxResources.System.IO.Compression.Brotli.SR
0x02000006 class Microsoft.Win32.SafeHandles.SafeBrotliEncoderHandle
0x02000007 class Microsoft.Win32.SafeHandles.SafeBrotliDecoderHandle
0x02000009 class System.IO.Compression.BrotliStream
0x0200000a struct System.IO.Compression.BrotliStream/<<ReadAsync>g__Core|25_0>d
0x0200000b struct System.IO.Compression.BrotliStream/<DisposeAsync>d__39
0x0200000c struct System.IO.Compression.BrotliStream/<FlushAsyncCore>d__14
0x0200000d struct System.IO.Compression.BrotliStream/<WriteAsyncMemoryCore>d__11
0x0200000e class System.IO.Compression.BrotliUtils
0x0200000f struct System.IO.Compression.BrotliDecoder
0x02000010 struct System.IO.Compression.BrotliEncoder
0x02000011 enum System.IO.Compression.BrotliEncoderOperation
0x02000012 enum System.IO.Compression.BrotliEncoderParameter
```


## 3. One method as CIL

```console
$ revlens dotnet samples/managed/dotnet/System.IO.Compression.Brotli.dll search Compress --kind method
22 hits
method 0x06000002 Interop/Brotli::BrotliDecoderDecompressStream(Microsoft.Win32.SafeHandles.SafeBrotliDecoderHandle, ref nuint, byte**, ref nuint, byte**, ref nuint)
method 0x06000003 Interop/Brotli::BrotliDecoderDecompress(nuint, byte*, nuint*, byte*)
method 0x06000008 Interop/Brotli::BrotliEncoderCompressStream(Microsoft.Win32.SafeHandles.SafeBrotliEncoderHandle, System.IO.Compression.BrotliEncoderOperation, ref nuint, byte**, ref nuint, byte**, ref nuint)
method 0x0600000b Interop/Brotli::BrotliEncoderCompress(int, int, int, nuint, byte*, nuint*, byte*)
method 0x0600000d Interop/Brotli::<BrotliDecoderDecompressStream>g____PInvoke|1_0(nint, nuint*, byte**, nuint*, byte**, nuint*)
method 0x06000011 Interop/Brotli::<BrotliEncoderCompressStream>g____PInvoke|7_0(nint, System.IO.Compression.BrotliEncoderOperation, nuint*, byte**, nuint*, byte**, nuint*)
method 0x06000029 System.SR::get_BrotliStream_Compress_UnsupportedOperation()
method 0x0600002a System.SR::get_BrotliStream_Compress_InvalidData()
method 0x0600002b System.SR::get_BrotliStream_Decompress_UnsupportedOperation()
method 0x0600002c System.SR::get_BrotliStream_Decompress_InvalidData()
method 0x0600002d System.SR::get_BrotliStream_Decompress_InvalidStream()
method 0x0600002e System.SR::get_BrotliStream_Decompress_TruncatedData()
method 0x06000045 System.IO.Compression.BrotliStream::TryDecompress(System.Span<byte>, ref int)
method 0x06000066 System.IO.Compression.BrotliUtils::GetQualityFromCompressionLevel(System.IO.Compression.CompressionLevel)
... (8 more lines)
```


## 4. A Python module

```console
$ revlens pyc samples/managed/python/sample_mod.3.12.pyc
# Python 3.12
Disassembly of <module> (sample_mod.py, line 1):
          0 RESUME                      0
          2 LOAD_CONST                  0 ('RevLens pyc fixture: exercises closures, comprehensions, exceptions, async and big constants.')
          4 STORE_NAME                  0 (__doc__)
          6 LOAD_CONST                  1 (0)
          8 LOAD_CONST                  2 (None)
         10 IMPORT_NAME                 1 (os)
         12 STORE_NAME                  1 (os)
         14 LOAD_CONST                  1 (0)
         16 LOAD_CONST                  2 (None)
         18 IMPORT_NAME                 2 (sys)
         20 STORE_NAME                  3 (_sys)
         22 LOAD_CONST                  1 (0)
         24 LOAD_CONST                  3 (('OrderedDict',))
         26 IMPORT_NAME                 4 (collections)
         28 IMPORT_FROM                 5 (OrderedDict)
         30 STORE_NAME                  5 (OrderedDict)
         32 POP_TOP
         34 LOAD_CONST                  4 ("hello\tworld 'quoted'")
         36 STORE_NAME                  6 (GREETING)
         38 LOAD_CONST                  5 ((1, 2.5, -3, 1000000000000000000000000000000, 1j, b'\x00\xffbytes', None, True, Ellipsis))
         40 STORE_NAME                  7 (NUMBERS)
         42 PUSH_NULL
         44 LOAD_NAME                   8 (frozenset)
         46 LOAD_CONST                  6 ('a')
         48 BUILD_SET                   1
         50 CALL                        1
         58 STORE_NAME                  9 (BIG)
         60 PUSH_NULL
         62 LOAD_BUILD_CLASS
         64 LOAD_CONST                  7 (<code object Widget at 0x0, file "sample_mod.py", line 11>)
         66 MAKE_FUNCTION               0
         68 LOAD_CONST                  8 ('Widget')
         70 LOAD_NAME                   5 (OrderedDict)
         72 CALL                        3
         80 STORE_NAME                 10 (Widget)
         82 LOAD_CONST                  9 (<code object risky at 0x0, file "sample_mod.py", line 31>)
         84 MAKE_FUNCTION               0
         86 STORE_NAME                 11 (risky)
... (532 more lines)
```

The opcode names and arguments match `dis.get_instructions` from CPython 3.12 for every instruction in the test corpus.

## 5. A PyInstaller archive

```console
$ revlens pyinstaller samples/managed/pyinstaller/mini-carchive.bin list
pythonVersion: 3.12
pylib: libpython3.12.so.1.0
cookieOffset: 1090
entryPoints: fixture_main
m        113 @64 pyimod_stub
s        114 @159 pyiboot_stub
s        231 @256 fixture_main
x         16 @437 data.txt
z        405 @461 PYZ.pyz
PYZ 2 modules
  package fixture_pkg
  module  fixture_pkg.helper
```

