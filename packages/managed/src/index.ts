// @revlens/managed: reverse engineering for managed and bytecode runtimes (.NET, Python, Lua, BEAM, EVM).
// Everything here runs in Node, browsers and Web Workers. Path based helpers load node:fs lazily.
export { ParseError, LIMITS, page, hexToBytes } from './util.js';
export type { Page } from './util.js';
export { ANALYZERS, dotnetAnalyzer, pythonAnalyzer, luaAnalyzer, beamAnalyzer, evmAnalyzer, runManagedAnalyzers } from './analyzers.js';
export { TOOLS } from './tools.js';
export type { Tool, InputSchema } from './tools.js';
export { CLI_COMMANDS } from './cli.js';
export type { CliCommand } from './cli.js';
export * from './api.js';
export type { InputSpec } from './io.js';

// .NET
export { parsePe, rvaToOffset } from './dotnet/pe.js';
export { parseMetadata, hasCliHeader, getString, getUserString, listUserStrings, listStrings, TABLE_NAMES } from './dotnet/metadata.js';
export type { Metadata, Table, Row } from './dotnet/metadata.js';
export { decodeCil, readMethodBody, CIL_ONE_BYTE, CIL_TWO_BYTE } from './dotnet/cil.js';
export type { CilInstruction, MethodBody, ExceptionClause } from './dotnet/cil.js';
export {
  loadAssembly, dotnetInfo, listTypes, findMethods, methodIl, xrefs, customAttributes, pinvokes, resources, assemblyRefs, assemblyName,
  detectObfuscators, readyToRun, singleFileBundle,
} from './dotnet/assembly.js';
export type { DotnetAssembly, DotnetInfo, TypeInfo, MethodInfo, MethodIl, Xref, BundleInfo, ReadyToRunInfo } from './dotnet/assembly.js';

// Python
export { parsePyc, parsePycHeader, disassemble as disassemblePyc, disText, walkCode, summarizeCode, isPyc, versionForMagic, pycHeader, PYC_MAGIC, SUPPORTED_VERSIONS as PYC_VERSIONS } from './python/pyc.js';
export type { PycFile, PycHeader, PyInstruction } from './python/pyc.js';
export { unmarshal, pyRepr, toJsonValue } from './python/marshal.js';
export type { PyValue, PyCode } from './python/marshal.js';
export { PY_OPCODES } from './python/opcodes.js';
export { parseCArchive, readCArchiveEntry, parsePyz, readPyzEntry, extractPyInstaller, fixPyc, isPyInstaller, detectPythonPackers } from './python/pyinstaller.js';
export type { CArchive, CArchiveEntry, Pyz, PyzEntry, ExtractedFile, PackerHit } from './python/pyinstaller.js';

// Lua, BEAM, EVM
export { parseLua, luaListing, isLuaBytecode } from './lua/lua.js';
export type { LuaChunk, LuaFunction, LuaInstruction } from './lua/lua.js';
export { parseBeam, isBeam, etf } from './beam/beam.js';
export type { BeamFile } from './beam/beam.js';
export { analyzeEvm, disassembleEvm, extractSelectors, detectProxy, solidityMetadata, solcStyleOpcodes, evmBytes, EVM_OPCODES, KNOWN_SELECTORS, KNOWN_EVENTS, PROXY_SLOTS } from './evm/evm.js';
export type { EvmInstruction, SelectorHit, ProxyHit, SolcMetadata, EvmSummary } from './evm/evm.js';
export { compareAssemblies, snapshotAssembly, mapPInvokes } from './dotnet/compare.js';
export type { NetDiff, NetTypeChange, PInvokeBinding } from './dotnet/compare.js';
export { nativeExports, probingNames } from './dotnet/native.js';
export type { NativeLibrary, NativeExport } from './dotnet/native.js';
