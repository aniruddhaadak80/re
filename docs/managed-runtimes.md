---
title: Managed runtimes
description: Read .NET metadata and CIL, Python bytecode and PyInstaller apps, Lua and LuaJIT chunks, Erlang and Elixir BEAM files and EVM contract bytecode, without running any of them.
order: 22
---

# Managed runtimes

`@revlens/managed` covers code that runs on a virtual machine. Everything is parsed, nothing is executed. Try it on the [managed runtimes page](https://aniruddhaadak80.github.io/re/labs/managed).

| Runtime | What you get |
| --- | --- |
| .NET | assembly identity and target framework, references with public key tokens, every metadata table, types and members with readable signatures, P/Invoke imports, resources, ildasm style CIL with resolved tokens, IL cross references, ReadyToRun and single file bundle info, obfuscator markers |
| Python | `.pyc` header for 1.5 to 3.15, marshal decoding, `dis` style disassembly for 3.7 to 3.13, PyInstaller archive listing and extraction like pyinstxtractor, markers for Nuitka, py2exe, cx_Freeze and PyOxidizer |
| Lua | 5.1 to 5.4 and LuaJIT 2.0 and 2.1: function tree, constants, locals, upvalues and a `luac -l` style listing |
| BEAM | chunks, atoms, exports, imports, attributes, compile info and literals |
| EVM | disassembly up to Cancun, function selectors with names, proxy patterns (EIP-1967, EIP-1822, EIP-1167), events and Solidity metadata |

## CLI

```
revlens dotnet App.dll
revlens dotnet App.dll types --filter Crypto --members
revlens dotnet App.dll il "MyApp.Licensing::Check"
revlens pyc module.pyc
revlens pyinstaller app.exe list
revlens lua script.luac
revlens beam elixir_sup.beam
revlens evm contract.hex selectors
```

## MCP tools

`managed_dotnet_info`, `managed_dotnet_types`, `managed_dotnet_method_il`, `managed_dotnet_search`, `managed_pyc_disasm`, `managed_pyinstaller_list`, `managed_pyinstaller_extract` (writes files), `managed_lua_info`, `managed_beam_info`, `managed_evm_disasm`, `managed_evm_selectors`.

For C# source, install ILSpy (`dotnet tool install -g ilspycmd`) and use `bridge_ilspy_decompile`.

## Limits

- No C# decompilation without the ILSpy bridge. ReadyToRun native code is not disassembled.
- Python 3.14 files are recognised but not disassembled. Encrypted PyInstaller archives are reported as errors.
- The BEAM Code chunk is summarised, not disassembled.
- EVM selectors come from the usual dispatcher shape. Hand written dispatchers can hide some.

## How it was checked

dnfile and dncil for .NET (every method body of Newtonsoft.Json), CPython 3.8 to 3.13 `dis` for every instruction, PyInstaller's own readers, LuaJIT `jit.util`, pybeam, and solc output for EVM. See the [package README](https://github.com/aniruddhaadak80/re/tree/main/packages/managed).
