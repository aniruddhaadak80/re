// Agent tool table. Every tool takes `path` (Node) or `bytesBase64`, returns JSON with offsets or tokens to cite.
import * as api from './api.js';

export type InputSchema = Record<string, { type: 'string' | 'number' | 'boolean' | 'array' | 'object'; description: string; optional?: boolean }>;
export interface Tool { name: string; description: string; inputSchema: InputSchema; run: (input: any) => Promise<unknown> }

const src: InputSchema = {
  path: { type: 'string', description: 'File path to read (Node only)', optional: true },
  bytesBase64: { type: 'string', description: 'File contents as base64, instead of path', optional: true },
};
const paging: InputSchema = {
  offset: { type: 'number', description: 'Index of the first item to return (default 0)', optional: true },
  limit: { type: 'number', description: 'Maximum items to return', optional: true },
};

export const TOOLS: Tool[] = [
  {
    name: 'managed_dotnet_info',
    description: 'Summarise a .NET assembly: name, version, target framework, assembly and module references, P/Invoke imports, resources, table row counts, entry point, ReadyToRun, single-file bundle and obfuscator markers.',
    inputSchema: { ...src },
    run: (i) => api.dotnetInfoTool(i),
  },
  {
    name: 'managed_dotnet_types',
    description: 'List TypeDefs of a .NET assembly with tokens, base type, interfaces and optionally methods (token, signature, RVA, file offset) and fields.',
    inputSchema: {
      ...src, ...paging,
      namespace: { type: 'string', description: 'Only types in this exact namespace', optional: true },
      filter: { type: 'string', description: 'Case insensitive substring of the full type name', optional: true },
      members: { type: 'boolean', description: 'Include methods and fields', optional: true },
    },
    run: (i) => api.dotnetTypesTool(i),
  },
  {
    name: 'managed_dotnet_method_il',
    description: 'ildasm style CIL disassembly of one method with resolved tokens, locals, exception clauses and file offsets. Pick the method by token (0x06000001) or Type::Method.',
    inputSchema: {
      ...src,
      method: { type: 'string', description: 'MethodDef token like 0x0600002a, or Namespace.Type::Method, or Type::Method' },
      index: { type: 'number', description: 'Which overload when several match (default 0)', optional: true },
      maxInstructions: { type: 'number', description: 'Instruction cap (default 5000)', optional: true },
      format: { type: 'string', description: 'json (default) or text', optional: true },
    },
    run: (i) => api.dotnetMethodIlTool(i),
  },
  {
    name: 'managed_dotnet_search',
    description: 'Search a .NET assembly by substring across types, type refs, methods, fields, member refs, user strings and P/Invoke, or set kind=xref to find every IL instruction that references a member (calls, field loads, ldstr).',
    inputSchema: {
      ...src, ...paging,
      query: { type: 'string', description: 'Substring to look for, or a full 8 hex digit token for xref' },
      kind: { type: 'string', description: 'all, type, typeref, method, field, memberref, string, pinvoke or xref (default all)', optional: true },
    },
    run: (i) => api.dotnetSearchTool(i),
  },
  {
    name: 'managed_pyc_disasm',
    description: 'Disassemble a CPython .pyc (3.7 to 3.13) like the dis module: header, code object tree, names, consts and instructions with offsets and resolved arguments.',
    inputSchema: {
      ...src, ...paging,
      codePath: { type: 'string', description: 'One code object, like <module>/Widget/scale (default: all as text)', optional: true },
      format: { type: 'string', description: 'text (default) or json', optional: true },
      version: { type: 'string', description: 'Force a Python version like 3.11 when the magic is missing or wrong', optional: true },
    },
    run: (i) => api.pycDisasmTool(i),
  },
  {
    name: 'managed_pyinstaller_list',
    description: 'List a PyInstaller executable: cookie offset, Python version, entry scripts, CArchive TOC (offsets, sizes, types) and the PYZ module list.',
    inputSchema: { ...src, ...paging, includePyz: { type: 'boolean', description: 'Also list PYZ modules (default true)', optional: true } },
    run: (i) => api.pyinstallerListTool(i),
  },
  {
    name: 'managed_pyinstaller_extract',
    description: 'Extract a PyInstaller executable like pyinstxtractor: scripts, modules and PYZ members become .pyc files with valid headers. Writes to outDir (Node), or returns one entry as base64.',
    inputSchema: {
      ...src, ...paging,
      outDir: { type: 'string', description: 'Directory to write into (Node only); member names are sanitised', optional: true },
      filter: { type: 'string', description: 'Only paths containing this substring', optional: true },
      entry: { type: 'string', description: 'Return this one extracted path as base64', optional: true },
      includeBinaries: { type: 'boolean', description: 'Include native libraries (always on with outDir)', optional: true },
    },
    run: (i) => api.pyinstallerExtractTool(i),
  },
  {
    name: 'managed_lua_info',
    description: 'Parse Lua 5.1, 5.2, 5.3, 5.4 or LuaJIT bytecode: header, function tree, constants, locals and a luac -l style listing.',
    inputSchema: { ...src, listing: { type: 'boolean', description: 'Include the instruction listing (default true)', optional: true }, maxLines: { type: 'number', description: 'Listing line cap (default 2000)', optional: true } },
    run: (i) => api.luaInfoTool(i),
  },
  {
    name: 'managed_beam_info',
    description: 'Parse an Erlang or Elixir .beam file: chunk table with offsets, atoms, exports, imports, locals, attributes, compile info and literal count.',
    inputSchema: { ...src, maxAtoms: { type: 'number', description: 'Atom list cap (default 500)', optional: true } },
    run: (i) => api.beamInfoTool(i),
  },
  {
    name: 'managed_evm_disasm',
    description: 'Disassemble EVM bytecode (raw bytes or hex text) into instructions with program counters; Solidity CBOR metadata is split off.',
    inputSchema: { ...src, ...paging, hex: { type: 'string', description: 'Bytecode as hex, instead of a file', optional: true } },
    run: (i) => api.evmDisasmTool(i),
  },
  {
    name: 'managed_evm_selectors',
    description: 'Extract function selectors from an EVM dispatcher with known names (ERC-20, ERC-721, Ownable, proxies), plus EIP-1967 and EIP-1167 proxy patterns, event topics, risky opcodes and solc version.',
    inputSchema: { ...src, hex: { type: 'string', description: 'Bytecode as hex, instead of a file', optional: true } },
    run: (i) => api.evmSelectorsTool(i),
  },
];
