# @revlens/managed

Reverse engineering for managed and bytecode runtimes, in pure TypeScript. It reads .NET assemblies,
Python bytecode and PyInstaller apps, Lua and LuaJIT bytecode, Erlang BEAM files and Ethereum (EVM)
contract bytecode. Nothing is ever executed, and there are no native dependencies. It runs in Node,
in browsers and in Web Workers.

## What it does

**.NET (ECMA-335)**
- PE sections, CLI header and the metadata root, with all 45 metadata tables (plus portable PDB tables), #Strings, #US, #GUID and #Blob heaps, `#~` and `#-` streams, ENC pointer tables.
- Assembly name and version, assembly and module references with public key tokens, custom attributes with decoded arguments (so `TargetFrameworkAttribute` gives the target framework), P/Invoke imports (ImplMap), manifest resources with offsets, entry point.
- TypeDef, MethodDef, Field, MemberRef, TypeRef, TypeSpec and MethodSpec names with readable signatures (generics, arrays, pointers, byrefs, nested types).
- An ildasm style CIL disassembler: tiny and fat headers, locals, exception clauses, every opcode, tokens resolved to `Type::Member(params)` and user strings.
- Cross references: every IL instruction that touches a member, a type or a string.
- ReadyToRun header (version, sections, crossgen identifier), .NET single-file bundle manifests (v1 to v6), and obfuscator markers (ConfuserEx, Dotfuscator, SmartAssembly, Babel, Eazfuscator, .NET Reactor and others, plus a non ASCII renaming heuristic).

**Python**
- `.pyc` header (magic to version for 1.5 up to 3.15, flags, hash or mtime), a marshal decoder, the code object tree, names and constants.
- A `dis` like disassembler with opcode tables generated from CPython 3.8 to 3.13 (3.7 derived from 3.8), handling EXTENDED_ARG, inline caches, per version jump rules and argument decoding (`NULL + name`, compare ops, binary ops, paired locals).
- PyInstaller: finds the MEI cookie anywhere in the file (it can sit inside an ELF section), lists the CArchive TOC, inflates entries, reads the PYZ, and extracts like pyinstxtractor, adding valid `.pyc` headers to scripts and modules.
- Markers for Nuitka, py2exe, cx_Freeze and PyOxidizer builds.

**Lua and BEAM**
- Lua 5.1, 5.2, 5.3 and 5.4 dumps: header, nested functions, constants, locals, upvalue names, and a `luac -l` style listing with decoded operands.
- LuaJIT 2.0 and 2.1 dumps: flags, prototypes, bytecode with names, string and number constants.
- BEAM: chunk table, atoms (including the OTP 28 compact form), exports, imports, locals, Code header, attributes and compile info (external term format), literal table.

**EVM**
- Disassembler up to Cancun opcodes, with solc compatible text output.
- Function selectors from the dispatcher (`PUSH4 sel EQ PUSH dest JUMPI`), named from an embedded table of about 70 common signatures (ERC-20, ERC-721, ERC-1155, Ownable, AccessControl, proxies).
- Proxy patterns: EIP-1967 and EIP-1822 storage slots, ZeppelinOS slots, EIP-1167 clones, DELEGATECALL. Known event topics. Solidity CBOR metadata (solc version, IPFS hash shown as a CID).

## API

```ts
import { loadAssembly, dotnetInfo, methodIl, findMethods, parsePyc, disText, extractPyInstaller, parseLua, parseBeam, analyzeEvm } from '@revlens/managed';

const asm = loadAssembly(bytes);              // throws ParseError when there is no CLI metadata
const info = dotnetInfo(asm);                 // identity, references, P/Invoke, resources, counts, R2R, obfuscators
const il = methodIl(asm, findMethods(asm, 'JsonConvert::SerializeObject')[0]);
console.log(il.text);

const pyc = parsePyc(pycBytes);
console.log(disText(pyc.code, pyc.version));

const { files } = extractPyInstaller(exeBytes); // [{ path, data, fixedHeader }]
```

Every parser takes a `Uint8Array` and throws only `ParseError` on bad input. Node only helpers
(`extractPyInstallerToDir`, `analyzeManagedFile`, `writeFiles`, `readPath`) live in `@revlens/managed/node`.

### Analyzers

`ANALYZERS` holds five `Analyzer` objects for `@revlens/core`: `managed-dotnet`, `managed-python`,
`managed-lua`, `managed-beam` and `managed-evm`. They put structured output under
`report.meta.managed.<area>` and add findings, imports, exports and components. `runManagedAnalyzers(bytes, report)`
runs them against a report that core already made.

### Tools

Each tool takes `path` (Node) or `bytesBase64` and returns JSON with tokens, offsets or program counters.
List outputs are paged with `offset` and `limit`.

| Tool | What it returns |
| --- | --- |
| `managed_dotnet_info` | assembly identity, target framework, references, P/Invoke, resources, row counts, R2R, bundle, obfuscators |
| `managed_dotnet_types` | TypeDefs with tokens, base type, interfaces, and optionally methods and fields |
| `managed_dotnet_method_il` | CIL of one method by token or `Type::Method`, with resolved tokens and file offsets |
| `managed_dotnet_search` | substring search over types, methods, fields, member refs, user strings, P/Invoke, or IL xrefs |
| `managed_pyc_disasm` | dis style disassembly of a `.pyc`, whole tree as text or one code object as JSON |
| `managed_pyinstaller_list` | cookie, Python version, entry scripts, CArchive TOC and PYZ modules |
| `managed_pyinstaller_extract` | pyinstxtractor style extraction to `outDir`, or one entry as base64 |
| `managed_lua_info` | Lua or LuaJIT header, function tree, constants and a listing |
| `managed_beam_info` | BEAM chunks, atoms, exports, imports, attributes, compile info |
| `managed_evm_disasm` | EVM instructions with program counters |
| `managed_evm_selectors` | selectors with names, proxy patterns, events, metadata, risky opcodes |

### CLI commands

`CLI_COMMANDS` adds these to the `revlens` CLI. All print text, or JSON with `--json`.

```
revlens dotnet <asm.dll> [info | types [--filter s] [--members] | il <Type::Method|0x06token> | search <q> [--kind k]]
revlens pyc <file.pyc> [--code <path>] [--version 3.x]
revlens pyinstaller <app> [list | extract --out <dir> [--filter s]]
revlens lua <file.luac> [--no-listing]
revlens beam <file.beam>
revlens evm <file | 0xhex> [selectors | disasm]
```

## Limits

- Hard caps on rows per table, marshal objects and depth, instructions per method, archive entries, inflated sizes and nesting. Bad input ends in `ParseError`, never a hang.
- .NET: no decompilation to C#; generic instantiation names are decoded but generic parameters show by position rather than by name. R2R native code is not disassembled. Bundles are listed, not extracted (offsets are given). Obfuscator detection looks for markers, so a protector that leaves none is missed.
- Python: 3.7 opcodes are derived, not generated from a 3.7 interpreter (none was available for aarch64). Line number tables are not decoded. 3.14 pycs are recognised but not disassembled. Encrypted PYZ archives (PyInstaller before 6 with `--key`) are reported as errors.
- Lua: operand decoding is per opcode family, not a full `luac -l` clone; LuaJIT debug info (line maps, names) is skipped.
- BEAM: the Code chunk is summarised, not disassembled.
- EVM: selectors come from the standard dispatcher shape; hand written or heavily optimised dispatchers may hide some.
- Nuitka, py2exe and cx_Freeze detection is string based and has not been checked on real builds.

## Verified against

| Area | Reference | What the tests assert |
| --- | --- | --- |
| .NET metadata | dnfile 0.18.0 | assembly name and version, references, module refs, ImplMap names, resources, TypeDef names, non zero table row counts |
| CIL | dncil 1.0.2 | opcode and offset stream (sha1), code size and max stack of all 112 bodies in System.IO.Compression.Brotli and an aggregate over all 4064 bodies of Newtonsoft.Json 13.0.3 |
| .pyc | CPython 3.8 to 3.13 `dis.get_instructions` | offset, opname, arg, jump target and argrepr of every instruction in every code object |
| PyInstaller | PyInstaller 6.22.3 `CArchiveReader` and `ZlibArchiveReader` | TOC names, offsets, sizes, flags, typecodes, options and PYZ entries, for a mini archive and a real onefile build |
| LuaJIT | LuaJIT 2.1 `jit.util.funcbc` / `funcinfo` | every prototype's parameter count and raw bytecode words |
| Lua 5.1 to 5.4 | dumps from the real runtimes | function tree, parameters, line ranges, constants, locals, known opcode shapes |
| BEAM | pybeam 0.8.1 | module, atoms, exports with labels, imports |
| EVM | solc 0.8.26 output | disassembly text equals `deployedBytecode.opcodes`; selectors equal `methodIdentifiers` |

Fixtures and their licenses are listed in `samples/managed/SOURCES.md`. Run
`node packages/managed/scripts/fetch-fixtures.mjs` to fetch Newtonsoft.Json and build the PyInstaller onefile
sample; the tests that need them skip when they are missing.

## Dependencies

- `fflate` 0.8 (MIT): zlib inflate for PyInstaller, PYZ and BEAM literal tables.
- `@revlens/core` (types only).
