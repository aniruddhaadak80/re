// Agent tool table (MCP friendly). Every tool takes `path` (or `bytes`) plus paging params.
import {
  disasmAt, disasmCallgraph, disasmCallPaths, disasmFindReferences, disasmFunction, disasmInfo,
  disasmListFunctions, disasmPseudocode, disasmSearch, disasmXrefs,
} from './api.js';
import { disasmTraceValues, disasmIndirectTargets } from './flowapi.js';
import { disasmMatchFunctions, disasmCompareFunctions } from './matchapi.js';
import { R3_TOOLS } from './tools-r3.js';

export interface ToolParam { type: 'string' | 'number' | 'boolean' | 'array' | 'object'; description: string; optional?: boolean }
export interface Tool { name: string; description: string; inputSchema: Record<string, ToolParam>; run: (input: any) => Promise<unknown> } // eslint-disable-line @typescript-eslint/no-explicit-any

const path: ToolParam = { type: 'string', description: 'Path to an ELF, PE or Mach-O file (fat Mach-O picks x86_64, then arm64, unless arch is set)' };
const arch: ToolParam = { type: 'string', description: 'Fat Mach-O slice to analyze: x86_64, arm64, x86 or arm', optional: true };
const offset: ToolParam = { type: 'number', description: 'Paging: items to skip (default 0)', optional: true };
const limit = (d: number, max: number): ToolParam => ({ type: 'number', description: `Paging: max items (default ${d}, max ${max})`, optional: true });
const fn: ToolParam = { type: 'string', description: 'Function name (exact or without leading underscore/version suffix) or address like 0x401000' };
const budget: ToolParam = { type: 'number', description: 'Time budget in ms for program wide indexing (default 8000); results say complete:false when it ran out', optional: true };

const BASE_TOOLS: Tool[] = [
  {
    name: 'disasm_info',
    description: 'Overview of a native binary for disassembly: format, architecture, entry point, sections, symbol/import/function counts and decoder in use.',
    inputSchema: { path, arch },
    run: (i) => disasmInfo(i),
  },
  {
    name: 'disasm_list_functions',
    description: 'List functions found from symbols, exports, Go pclntab, .pdata/.eh_frame/LC_FUNCTION_STARTS, import stubs, call targets and prologue scan. Filter by name, sort by addr/name/size, paged.',
    inputSchema: {
      path, arch, offset, limit: limit(100, 2000),
      filter: { type: 'string', description: 'Case insensitive substring of the function name', optional: true },
      sort: { type: 'string', description: 'addr (default), name or size', optional: true },
      includeImports: { type: 'boolean', description: 'Include PLT/stub/thunk entries for imports', optional: true },
    },
    run: (i) => disasmListFunctions(i),
  },
  {
    name: 'disasm_function',
    description: 'Disassemble one function with its control flow graph: basic blocks, edges (true/false/jump/fallthrough), exits, calls with resolved import names, string and data references, plus a summary.',
    inputSchema: { path, arch, function: fn, offset: { type: 'number', description: 'Instruction offset for paging (default 0)', optional: true }, limit: limit(400, 5000) },
    run: (i) => disasmFunction(i),
  },
  {
    name: 'disasm_pseudocode',
    description: 'Readable C like pseudo code for one function (if/else and loop recovery, goto fallback) with call arguments and string literals inlined, plus a summary (calls, strings, constants, size, cyclomatic complexity).',
    inputSchema: { path, arch, function: fn, maxLines: { type: 'number', description: 'Max output lines (default 300)', optional: true } },
    run: (i) => disasmPseudocode(i),
  },
  {
    name: 'disasm_xrefs',
    description: 'Cross references. direction "to": every call, jump, string or data reference to an address, function, symbol or import. direction "from": everything a function calls or references.',
    inputSchema: {
      path, arch, target: { type: 'string', description: 'Address, function name, symbol or import name' },
      direction: { type: 'string', description: '"to" (default) or "from"', optional: true }, offset, limit: limit(200, 5000), budgetMs: budget,
    },
    run: (i) => disasmXrefs(i),
  },
  {
    name: 'disasm_callgraph',
    description: 'Call graph around a function (callees, callers or both, to a depth), or without a function the program wide list of functions ranked by number of callers.',
    inputSchema: {
      path, arch, function: { ...fn, optional: true },
      direction: { type: 'string', description: 'callees (default), callers or both', optional: true },
      depth: { type: 'number', description: 'Depth 1-8 (default 2)', optional: true }, offset, limit: limit(300, 5000), budgetMs: budget,
    },
    run: (i) => disasmCallgraph(i),
  },
  {
    name: 'disasm_search',
    description: 'Search code: bytes_pattern hex with ?? wildcards (e.g. "48 8d 3d ?? ?? ?? ??"), insn glob over instruction text or its resolved reference (e.g. "call *strcmp*", "xor e*, e*"), or text for literal bytes anywhere.',
    inputSchema: {
      path, arch,
      bytes_pattern: { type: 'string', description: 'Hex bytes, ?? for any byte', optional: true },
      insn: { type: 'string', description: 'Glob (* and ?) over "mnemonic operands", case insensitive', optional: true },
      text: { type: 'string', description: 'Literal text to find as bytes', optional: true },
      scope: { type: 'string', description: 'code (default for bytes_pattern) or all', optional: true },
      offset, limit: limit(100, 2000), budgetMs: budget,
    },
    run: (i) => disasmSearch(i),
  },
  {
    name: 'disasm_find_references',
    description: 'Find the functions that reference a string (substring match by default) or call/load an import (by name, e.g. "strcmp", "CreateProcessW"), with the exact instruction addresses.',
    inputSchema: {
      path, arch,
      string: { type: 'string', description: 'Text inside referenced strings', optional: true },
      import: { type: 'string', description: 'Import name (leading underscores and @version ignored)', optional: true },
      exact: { type: 'boolean', description: 'Exact match instead of substring', optional: true },
      caseSensitive: { type: 'boolean', description: 'Case sensitive string match', optional: true },
      offset, limit: limit(50, 1000), budgetMs: budget,
    },
    run: (i) => disasmFindReferences(i),
  },
  {
    name: 'disasm_call_paths',
    description: 'Call paths from the entry point (or a given function) to a target function, shortest first, plus the direct callers of the target. Answers "how does execution reach X".',
    inputSchema: {
      path, arch, target: fn,
      from: { type: 'string', description: 'Start function (default: entry point)', optional: true },
      maxDepth: { type: 'number', description: 'Max path length (default 12)', optional: true },
      maxPaths: { type: 'number', description: 'Max paths returned (default 10)', optional: true }, budgetMs: budget,
    },
    run: (i) => disasmCallPaths(i),
  },
  {
    name: 'disasm_at',
    description: 'Disassemble N instructions linearly at any address (or function name), annotated with symbols, imports and strings. Works without function analysis.',
    inputSchema: {
      path, arch, address: { type: 'string', description: 'Address like 0x401000 or a function name' },
      count: { type: 'number', description: 'Instructions (default 32, max 2000)', optional: true },
      thumb: { type: 'boolean', description: 'ARM only: decode as Thumb', optional: true },
    },
    run: (i) => disasmAt(i),
  },
  {
    name: 'disasm_trace_values',
    description: 'Native value flow. Backward: with function + call (address or callee name, optional occurrence and arg index from 0), shows the value reaching each argument (constant, string, stack address, incoming argument, return value of another call, load) with the instruction that produced it, and follows incoming arguments into callers up to depth. Forward: with value (string text, or a number/0x address) or function + param, lists where it flows: call arguments, stores, returns, and into callees up to depth.',
    inputSchema: {
      path, arch,
      function: { ...fn, optional: true },
      call: { type: 'string', description: 'Backward mode: call site address or callee name inside function', optional: true },
      occurrence: { type: 'number', description: 'With a callee name: which call (1 = first)', optional: true },
      arg: { type: 'number', description: 'Argument index from 0 (default: all register parameters of the callee)', optional: true },
      value: { type: 'string', description: 'Forward mode: string text, or a number / 0x address to follow', optional: true },
      param: { type: 'number', description: 'Forward mode: follow this parameter (index from 0) of function', optional: true },
      depth: { type: 'number', description: 'Hops into callers (backward) or callees (forward), 0-3 (default 1)', optional: true },
      limit: limit(100, 1000), budgetMs: budget,
    },
    run: (i) => disasmTraceValues(i),
  },
  {
    name: 'disasm_indirect_targets',
    description: 'Indirect calls and jumps of a function (or the whole program within a budget) with resolved targets: jump tables (switch), tables of code pointers, constants found by value tracking, initial values of writable function pointers, and C++ vtable slot candidates. unresolved:true lists only what is still unknown.',
    inputSchema: {
      path, arch, function: { ...fn, optional: true },
      unresolved: { type: 'boolean', description: 'Only unresolved sites', optional: true },
      offset, limit: limit(200, 5000), budgetMs: budget,
    },
    run: (i) => disasmIndirectTargets(i),
  },
  {
    name: 'disasm_match_functions',
    description: 'Map functions between two binaries (two versions, or a stripped and an unstripped build) without relying on addresses: equal names (optional), identical normalized instructions, strings, imports and constants, CFG shape, call graph and address order propagation, then similarity. Each match has a confidence, method and similarity; lists identical vs changed functions and functions only in one side.',
    inputSchema: {
      path, path2: { type: 'string', description: 'Second binary' }, arch, arch2: { type: 'string', description: 'Fat Mach-O slice of the second binary', optional: true },
      useNames: { type: 'boolean', description: 'Match equal symbol names first (default true); false matches by code alone', optional: true },
      minConfidence: { type: 'number', description: 'Only return matches at or above this confidence (0..1)', optional: true },
      filter: { type: 'string', description: 'Substring of a function name on either side', optional: true },
      offset, limit: limit(200, 20000), budgetMs: { type: 'number', description: 'Time budget in ms (default 60000)', optional: true },
    },
    run: (i) => disasmMatchFunctions(i),
  },
  {
    name: 'disasm_compare_functions',
    description: 'Side by side diff of two functions (same binary, or function in path vs function2 in path2): overall similarity, per dimension (instructions, CFG, strings, calls, constants), identical/changed basic blocks, and a unified diff of the disassembly with addresses normalized so relocation alone is not a change.',
    inputSchema: {
      path, arch, function: fn,
      path2: { type: 'string', description: 'Second binary (default: same as path)', optional: true },
      arch2: { type: 'string', description: 'Fat Mach-O slice of the second binary', optional: true },
      function2: { type: 'string', description: 'Function in the second binary (default: same name or address as function)', optional: true },
      context: { type: 'number', description: 'Unchanged lines of context around changes (default 2)', optional: true },
      limit: limit(400, 5000),
    },
    run: (i) => disasmCompareFunctions(i),
  },
];

/** Every disasm tool: the base set plus the round 3 navigation, debug info, export and annotation tools. */
export const TOOLS: Tool[] = [...BASE_TOOLS, ...R3_TOOLS];
