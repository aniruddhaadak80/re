---
title: "Finding the imphash of a Go binary without Python"
date: 2026-11-09
summary: "The import hash is one of the most used fingerprints in malware research, and almost everyone computes it with pefile. We rebuilt it in pure TypeScript, checked it against pefile on two real esbuild releases, and found out why a Go upgrade changed the hash."
tags: [pe, imphash, go, windows, internals]
cover: /re/media/cover-imphash-go-binary.svg
author: Aniruddha Adak
---

# Finding the imphash of a Go binary without Python

If you have ever looked a Windows sample up on a threat intel site, you have seen an imphash. It is a short MD5 that fingerprints the list of functions a PE file imports. Two builds of the same malware family often share one, even when every other byte is different, because the code changes more often than the set of Windows APIs it calls.

Almost everyone computes it with Python's excellent `pefile` library:

```python
import pefile
print(pefile.PE("esbuild.exe").get_imphash())
```

We wanted the same number in a browser tab, in a Node script and inside an agent, without Python. So we wrote it in TypeScript and tested it against pefile on real files.

## The recipe

The imphash is simple once you write it down:

1. Walk the PE import directory. Each descriptor names a DLL and points at a table of imported functions.
2. For each import, take the DLL name in lowercase and drop its `.dll`, `.ocx` or `.sys` extension.
3. Take the function name in lowercase. If the import is by ordinal, use `ord` followed by the number.
4. Join DLL and function with a dot, for example `kernel32.writefile`.
5. Join all of those, in table order, with commas.
6. MD5 the result.

The order matters, and so does every detail of the lowercase and extension rules. Get one wrong and you get a perfectly valid MD5 that matches nothing.

## The hard parts

The recipe is easy. Reading a real PE safely is the work.

**RVAs are not file offsets.** The import directory gives you a relative virtual address. To read it from the file you find the section whose virtual range contains that address, then translate: `offset = section.raw + (rva - section.vaddr)`. Every name and every thunk needs the same translation.

**32 and 64 bit thunks differ.** In PE32+ each thunk is 8 bytes and the "import by ordinal" flag is the top bit of a 64 bit value. In PE32 it is 4 bytes and bit 31. JavaScript numbers lose precision above 2 to the 53, so we read 64 bit thunks as `BigInt` and check the high bit carefully.

**Two thunk tables.** A descriptor has an "original first thunk" (the lookup table) and a "first thunk" (the address table that the loader overwrites). Some linkers leave the first one at zero, so we fall back to the second.

**Hostile input.** A malicious file can point any of these at nonsense. RevLens caps the walk at 1024 descriptors and 4096 thunks per DLL, stops when a translation fails, and never reads outside the buffer.

All of that is about 60 lines in `packages/core/src/analyzers/pe.ts`, plus our own pure TypeScript MD5.

## The test: two real esbuild releases

esbuild is a great test subject. It is a real, widely used Go program, and its Windows build ships on npm, so anyone can fetch the exact same bytes:

```bash
npm pack @esbuild/win32-x64@0.24.0 && tar xzf esbuild-win32-x64-0.24.0.tgz
```

RevLens:

```ts
import { analyze } from '@revlens/core';
const r = await analyze(bytes, { name: 'esbuild.exe' });
console.log(r.hardening.imphash);
```

```text
esbuild 0.24.0   b196866f0bf37f1f128fa153413b744f
esbuild 0.23.0   07361a3a7f515bf56ca93120b2aca73b
```

pefile 2024.8.26 on the same files:

```text
esbuild 0.24.0   b196866f0bf37f1f128fa153413b744f
esbuild 0.23.0   07361a3a7f515bf56ca93120b2aca73b
```

Identical. That is the whole point: a fingerprint is only useful if everyone computes it the same way.

## What a Go import table looks like

Go binaries are a little unusual. The Go runtime loads most of what it needs at run time with `LoadLibrary` and `GetProcAddress`, so the static import table is small. esbuild 0.24.0 imports from exactly one DLL, `kernel32.dll`, and 48 functions:

```text
WriteFile, WriteConsoleW, WerSetFlags, WerGetFlags, WaitForMultipleObjects,
WaitForSingleObject, VirtualQuery, VirtualFree, VirtualAlloc, TlsAlloc,
SwitchToThread, SuspendThread, SetWaitableTimer, SetThreadPriority,
SetProcessPriorityBoost, SetEvent, SetErrorMode, SetConsoleCtrlHandler,
RtlVirtualUnwind, RtlLookupFunctionEntry, ResumeThread, RaiseFailFastException,
PostQueuedCompletionStatus, LoadLibraryW, LoadLibraryExW, SetThreadContext,
GetThreadContext, GetSystemInfo, GetSystemDirectoryA, GetStdHandle,
GetQueuedCompletionStatusEx, GetProcessAffinityMask, GetProcAddress, GetErrorMode,
GetEnvironmentStringsW, GetCurrentThreadId, GetConsoleMode, FreeEnvironmentStringsW,
ExitProcess, DuplicateHandle, CreateWaitableTimerExW, CreateWaitableTimerA,
CreateThread, CreateIoCompletionPort, CreateEventA, CloseHandle,
AddVectoredExceptionHandler, AddVectoredContinueHandler
```

Notice `SuspendThread`, `GetThreadContext`, `SetThreadContext` and `ResumeThread`. Out of context, that set can look like thread hijacking. In a Go binary it is the runtime's goroutine preemption: Go suspends its own threads to interrupt long running goroutines. It is a good reminder that an import list is evidence, not a verdict.

## Why the hash changed between releases

RevLens can diff the two releases:

```bash
npx revlens diff esbuild-0.23.0.exe esbuild-0.24.0.exe
```

```text
Between esbuild-0.23.0.exe and esbuild-0.24.0.exe: 2 endpoint changes, 1 import change, 5 section changes.
imports removed: kernel32.dll!CreateFileA
```

One import disappeared, `CreateFileA`: 49 functions in 0.23.0, 48 in 0.24.0 (pefile agrees on both counts). The buildinfo analyzer shows that the toolchain moved from `go1.22.4` to `go1.23.1` at the same time. The Go runtime declares its own kernel32 imports, so the toolchain bump is the most likely reason, though from the bytes alone we cannot prove which line of code dropped it. Either way, one fewer entry in the list gives a completely different MD5.

This is the known weakness of imphash. It is an exact fingerprint of a list, so it is very good at saying "same build pipeline" and fragile across toolchain upgrades. For Go programs in particular, many unrelated binaries built with the same Go version share an imphash, because the runtime's imports dominate the list. Treat a Go imphash match as "same Go version" before you treat it as "same program".

## What else RevLens tells you about this file

The same run gives you the rest of the picture:

```json
{
  "subsystem": "Windows console",
  "aslr": true,
  "dep_nx": true,
  "cfg": false,
  "highEntropyVA": true,
  "signed": false,
  "imphash": "b196866f0bf37f1f128fa153413b744f"
}
```

And from the Go build info block:

```text
Built with go1.23.1
path   github.com/evanw/esbuild/cmd/esbuild
build  -buildmode=exe -compiler=gc -trimpath=true
```

Eight sections, the largest `.text` at 5,455,872 bytes with an entropy of 6.12, which is normal compiled code. No packer markers. One starter rule, `Crypto_Constants`, because the Go standard library carries the SHA-256 round constants.

## Try it

```bash
npx revlens analyze your-file.exe --json | jq .hardening.imphash
```

Or drop the file on [the web app](https://aniruddhaadak80.github.io/re/) and look at the hardening card. No Python required, and the file never leaves your machine.
