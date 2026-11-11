---
title: "Showcase: find the password check in a stripped ELF"
description: Recover main from a stripped x86-64 Linux program, read its pseudo code, follow a string to the function that uses it, and verify the answer against the bytes.
order: 1
---

# Showcase: find the password check in a stripped ELF

The file is `samples/disasm/hello-x64-stripped.elf`, a small C program built for x86-64 Linux and stripped of its symbol table. The question: what input does it accept, and where is that decided?

Everything below is real output from the RevLens CLI on that file. Nothing is installed besides Node.

## 1. Triage

```console
$ revlens analyze samples/disasm/hello-x64-stripped.elf
hello-x64-stripped.elf  elf x86-64 64-bit  4,912 bytes  entropy 4.01
sha256 6c74f1602d8b4927cbcb19ddb4b3c1dd3683279d66f30b8ed3884b00ce5f6e65
hardening type=EXEC  pie=false  stripped=true  dynamicallyLinked=true  nxLikely=true  relroLikely=true
sections  .interp(3.9) .note.ABI-tag(1.4) .dynsym(0.5) .gnu.version(1.0) .gnu.version_r(1.9) .gnu.hash(0.8) .hash(0.8) .dynstr(4.4) .rela.dyn(1.1) .rela.plt(1.4) .rodata(4.5) .eh_frame_hdr(2.9)
imports   5 from 2 libraries: DT_NEEDED, dynamic symbols
deep      disasm: x86_64 11 functions

No findings.
```

It is a stripped, dynamically linked ELF with 11 functions found by the disassembler. There are no findings, so nothing looks packed or hostile.

## 2. Functions

```console
$ revlens disasm-functions samples/disasm/hello-x64-stripped.elf
11 functions (showing 11 from 0)
   0x1001760       43  entry           entry
   0x1001790       19  eh-frame        sub_1001790
   0x10017b0      294  eh-frame        sub_10017b0
   0x10018e0       57  eh-frame        sub_10018e0
   0x1001920       65  eh-frame        sub_1001920
   0x1001970       17  eh-frame        sub_1001970
   0x1001990       17  eh-frame        sub_1001990
   0x10019b0       13  eh-frame        sub_10019b0
   0x10019c0      165  entry           main
   0x1001a70      102  eh-frame        sub_1001a70
   0x1001ae0        6  eh-frame        sub_1001ae0
```

The symbol table is gone, yet `main` is named: RevLens found it from the `__libc_start_main` call in `_start`. The other functions come from the `.eh_frame` unwind table.

## 3. Strings and who uses them

```console
$ revlens refs samples/disasm/hello-x64-stripped.elf --string access
string "access denied" @ 0x10004fe
    0x1001900  in sub_10018e0
string "access granted" @ 0x10004ef
    0x10018f9  in sub_10018e0
```

The strings "access granted" and "access denied" are used by one function. That is our check.

## 4. Read it

```console
$ revlens decompile samples/disasm/hello-x64-stripped.elf sub_10018e0
// sub_10018e0 at 0x10018e0, 18 instructions, 1 blocks
// light lift: registers stand in for variables; calling convention rdi,rsi,rdx,rcx,r8,r9
void sub_10018e0() {
  rsi = "revlens-secret-key";
  strcmp();
  ebx = 0;
  bl = eax == 0;
  rax = "access granted";
  rdi = "access denied";
  if (eax == 0) rdi = rax;
  puts("access denied");
  eax = ebx;
  return rax;
}
```

The function compares its argument with the constant `revlens-secret-key` through `strcmp`, then picks the message: the compiler used a conditional move, so the light lifter prints the default `puts` argument and shows the swap on the line above it. The accepted input is `revlens-secret-key`.

## 5. Verify before you say it

```console
$ revlens verify samples/disasm/hello-x64-stripped.elf string=revlens-secret-key import=strcmp string=hunter2
VERIFIED string=revlens-secret-key  Found the ASCII string at offset 1200.
VERIFIED import=strcmp  dynamic symbols imports strcmp.
REFUTED  string=hunter2  The string does not appear in the file as ASCII or UTF-16.
```

Two claims hold, with the offset or import that proves them, and the made up password is refuted. An agent using the MCP server makes the same check with `verify_claim` before it reports.

## With Ghidra installed

The same address works with the bridge: `revlens bridge ghidra_decompile samples/disasm/hello-x64-stripped.elf --functions 0x10018e0`. See [bridges](../bridges.md).
