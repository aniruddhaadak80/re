---
title: Function matching and value flow
description: Follow values to call arguments and sinks, resolve jump tables, pointer tables and C++ vtable slots, and map functions between two builds, stripped or not, with the RevLens disassembler.
order: 20.5
---

# Function matching and value flow

These are four tools in `@revlens/disasm` that answer questions plain disassembly cannot: what value reaches this call, where does this indirect jump go, and which function in the new build is this one from the old build. They run in pure TypeScript in Node and in the browser, and the matcher is also on the [disassembler page](https://aniruddhaadak80.github.io/re/labs/disassembler) in Labs.

## What reaches a call, and where a value goes

`disasm_trace_values` works in two directions.

- Backward: pick a call, for example every `printf` in `main`, and see what each argument is: a constant, a string, a stack slot, a parameter of the caller, or the return value of another call.
- Forward: pick a string, a constant or a parameter and see which calls it reaches.

```sh
revlens disasm trace-values ./a.out main --call printf
revlens disasm trace-values ./a.out --value "password:" --depth 2
```

Under the hood is a per function constant and value propagation over the control flow graph with stack slots, incoming parameters, call return values and loads. It follows callers or callees up to depth 3.

## Indirect calls and jumps

`disasm_indirect_targets` lists indirect calls and jumps with what they resolve to:

- Jump tables: x86-64 relative (PIE) and absolute tables, AArch64 `adr`, `ldrb`, `ldrh`, `add` tables, Thumb `tbb` and `tbh`, Go jump tables and ELF `RELATIVE` relocations. Tables are read from read only memory and capped at 1024 entries.
- Code pointer tables and constants, including the initial values of writable function pointers.
- Itanium C++ vtable slots, found by their shape even in stripped files.

```sh
revlens disasm indirect ./a.out --unresolved
```

The pseudo code uses the same results, so `switch` statements show their case labels.

## Matching functions between builds

`disasm_match_functions` maps functions from one binary to another, for example two releases, or a stripped build against one with symbols. Every function gets a fingerprint from its normalized instructions, CFG shape, strings, imports, constants and callees. Matching goes in rounds: equal names (optional), identical code, shared strings, imports and constants, call graph and address order neighbors, then similarity. A function is never mapped twice, and each match reports its confidence and the round that found it.

`disasm_compare_functions` then diffs one pair side by side with addresses and branch targets normalized, so a function that only moved shows no change.

```sh
revlens disasm match-functions ./v1.elf ./v2.elf --min-confidence 0.8
revlens disasm compare-functions ./v1.elf parse_header ./v2.elf
```

A useful pattern: match a stripped release against an older build that has symbols, then carry the names over with [names write-back](sessions-and-write-back.md) into Ghidra, IDA or radare2.

## Budgets

Program wide tools take `budgetMs` (8 seconds by default, 60 seconds for matching). When the budget runs out they answer with what they have and `complete: false`; the next call continues where it stopped.

## How it was checked

- Jump tables and indirect calls on purpose built switch and virtual call binaries and on Lua 5.4.7, checked against pyelftools: the 83 entry `luaV_execute` computed goto table, a biased `char_class` table on x86-64, vtables found by shape in a stripped build, and Go `runtime.reflectcall` dispatching to every `runtime.callN`.
- Matching a stripped, file order reversed Lua build against the unstripped one: at least 95 percent of functions matched and at least 95 percent of matches correct against the symbols. esbuild 0.23.1 against 0.24.0 as a larger real case.
- fast-check writes random bytes over tables, code and headers and checks that every pass stays within its caps.

## Limits

- Jump tables resolve only when the bounds check and table load are on one predecessor chain; the rest are listed as unresolved.
- The value tracker models stack slots and read only data, not the heap.
- Matching is tuned for builds of the same source. Heavy inlining or a different optimizer level lowers the match rate.
