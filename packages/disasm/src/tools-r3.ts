// Round 3 agent tools: debug info types, navigation context, feature tracing, behavior change,
// whole binary export, annotations (comments, bookmarks, names) and the function dossier.
import type { Tool, ToolParam } from './tools.js';
import { disasmDebugInfo } from './debugapi.js';
import {
  disasmContext, disasmAddressName, disasmSetName, disasmGetComment, disasmSetComment, disasmListComments,
  disasmSetBookmark, disasmUnsetBookmark, disasmListBookmarks, disasmAnnotations, disasmContainingFunction,
  disasmNextAddress, disasmPrevAddress, disasmListNames, disasmSearchFunctions, disasmInstruction,
  disasmFunctionInfo, disasmAnalyzeFunction, disasmApiBoundary,
} from './navapi.js';

const path: ToolParam = { type: 'string', description: 'Path to an ELF, PE or Mach-O file (fat Mach-O picks x86_64, then arm64, unless arch is set)' };
const arch: ToolParam = { type: 'string', description: 'Fat Mach-O slice to analyze: x86_64, arm64, x86 or arm', optional: true };
const offset: ToolParam = { type: 'number', description: 'Paging: items to skip (default 0)', optional: true };
const limit = (d: number, max: number): ToolParam => ({ type: 'number', description: `Paging: max items (default ${d}, max ${max})`, optional: true });
const address: ToolParam = { type: 'string', description: 'Address like 0x401000 (or a function or symbol name)', optional: true };
const fileOffset: ToolParam = { type: 'string', description: 'File offset instead of an address (mapped to its virtual address)', optional: true };
const fn: ToolParam = { type: 'string', description: 'Function name (exact or without leading underscore/version suffix) or address like 0x401000' };
const budget: ToolParam = { type: 'number', description: 'Time budget in ms for program wide indexing (default 8000)', optional: true };
const kindC: ToolParam = { type: 'string', description: 'regular (default) or inline', optional: true };

export const R3_TOOLS: Tool[] = [
  {
    name: 'disasm_debug_info',
    description: 'DWARF 2 to 5 debug info of an ELF, Mach-O or PE binary: view summary (units, producers, languages, counts), types (structs, unions, enums, typedefs, base types; filter, kind), type (one type with member offsets, sizes, bit fields, enumerators and a C declaration), functions (prototypes with address ranges), function (parameters with types and entry registers, locals with frame offsets, frame base), globals (typed global variables with addresses). Pseudo code uses these names and types automatically.',
    inputSchema: {
      path, arch,
      view: { type: 'string', description: 'summary (default), types, type, functions, function or globals', optional: true },
      name: { type: 'string', description: 'type or function name (view type or function); a type id like 0x124; a function address', optional: true },
      filter: { type: 'string', description: 'Case insensitive substring of the name', optional: true },
      kind: { type: 'string', description: 'types view: struct, union, class, enum, typedef, base, pointer, array, function', optional: true },
      includeAnonymous: { type: 'boolean', description: 'types: include unnamed types; functions: include declarations', optional: true },
      offset, limit: limit(100, 5000),
    },
    run: (i) => disasmDebugInfo(i),
  },
  {
    name: 'disasm_context',
    description: 'Navigation context for an address or file offset in one call: mapping (section, permissions, file offset), containing function and basic block with the instructions around it, nearest symbols before and after, incoming references to the address and the function callers, outgoing references from the instruction and its block (calls, data, string, flow edges), strings at and near the address, and any comment, bookmark or analyst name there.',
    inputSchema: { path, arch, address, fileOffset, radius: { type: 'number', description: 'Bytes around the address to look for referenced strings (default 256)', optional: true }, window: { type: 'number', description: 'Instructions shown before and after (default 6)', optional: true }, budgetMs: budget },
    run: (i) => disasmContext(i),
  },
  {
    name: 'disasm_address_name',
    description: 'Primary name at a code or data address: analyst name, function, symbol (data symbols included), import stub or slot, or DWARF global, with its kind and source. name is null when the address has no name.',
    inputSchema: { path, arch, address, fileOffset },
    run: (i) => disasmAddressName(i),
  },
  {
    name: 'disasm_set_name',
    description: 'Assign an analyst name to one mapped address (in process, per binary content) and read it back. Empty name clears it and restores the original function name. A name already used at another address is refused unless force is set, which moves it. Names show in every later listing, xref and pseudo code. Export them with disasm_annotations.',
    inputSchema: { path, arch, address: { ...address, optional: false }, name: { type: 'string', description: 'New name (max 1024 characters); empty clears' }, force: { type: 'boolean', description: 'Move the name from another address', optional: true } },
    run: (i) => disasmSetName(i),
  },
  {
    name: 'disasm_get_comment',
    description: 'Read the regular or inline comment at an address. Returns null when there is none.',
    inputSchema: { path, arch, address, fileOffset, kind: kindC },
    run: (i) => disasmGetComment(i),
  },
  {
    name: 'disasm_set_comment',
    description: 'Write a regular or inline comment at a mapped address (in process, per binary content) and report whether readback matched. Empty comment clears it. Use comments to record evidence and reasoning; they appear in disasm_context, disasm_analyze_function and the export.',
    inputSchema: { path, arch, address, fileOffset, comment: { type: 'string', description: 'Comment text (max 65536 characters); empty clears' }, kind: kindC },
    run: (i) => disasmSetComment(i),
  },
  {
    name: 'disasm_list_comments',
    description: 'Every comment set on a binary (regular, inline, or both) with the function it sits in, paged.',
    inputSchema: { path, arch, kind: { type: 'string', description: 'regular, inline or all (default all)', optional: true }, offset, limit: limit(200, 5000) },
    run: (i) => disasmListComments(i),
  },
  {
    name: 'disasm_set_bookmark',
    description: 'Create or update a bookmark at a mapped address. Omit name to keep an existing name (or create an unnamed bookmark); an empty name clears the name. Bookmarks are navigation aids, not binary evidence.',
    inputSchema: { path, arch, address, fileOffset, name: { type: 'string', description: 'Bookmark name', optional: true } },
    run: (i) => disasmSetBookmark(i),
  },
  {
    name: 'disasm_unset_bookmark',
    description: 'Remove the bookmark at an address and report that it is absent.',
    inputSchema: { path, arch, address, fileOffset },
    run: (i) => disasmUnsetBookmark(i),
  },
  {
    name: 'disasm_list_bookmarks',
    description: 'Every bookmark as address and name pairs (unnamed bookmarks have a null name), with the containing function.',
    inputSchema: { path, arch, offset, limit: limit(200, 5000) },
    run: (i) => disasmListBookmarks(i),
  },
  {
    name: 'disasm_annotations',
    description: 'Export (default), import or clear the analyst annotations of a binary: comments, inline comments, bookmarks and names, as JSON keyed by hex address. Import replaces comments and bookmarks unless merge is set; names are applied with readback.',
    inputSchema: { path, arch, action: { type: 'string', description: 'export, import or clear', optional: true }, data: { type: 'object', description: 'import: the object (or JSON text) an export returned', optional: true }, merge: { type: 'boolean', description: 'import: keep existing entries', optional: true } },
    run: (i) => disasmAnnotations(i),
  },
  {
    name: 'disasm_containing_function',
    description: 'Resolve any address (an interior instruction byte or a function entry) to the analyzed function that contains it, from the decoded CFG, never from nearby symbols. status is in-function, not-in-function (mapped but no analyzed body covers it) or outside-segments. Returns the containing instruction, block and the inclusive body ranges.',
    inputSchema: { path, arch, address, fileOffset },
    run: (i) => disasmContainingFunction(i),
  },
  {
    name: 'disasm_next_address',
    description: 'Next analyzed object start after an address: instruction of the containing function, function entry or data symbol (unit object, default), or only functions, symbols, bookmarks or comments. A navigation primitive, not control flow.',
    inputSchema: { path, arch, address, fileOffset, unit: { type: 'string', description: 'object (default), instruction, function, symbol, bookmark or comment', optional: true } },
    run: (i) => disasmNextAddress(i),
  },
  {
    name: 'disasm_prev_address',
    description: 'Previous analyzed object start before an address (same units as disasm_next_address). Returns null at the start of the image.',
    inputSchema: { path, arch, address, fileOffset, unit: { type: 'string', description: 'object (default), instruction, function, symbol, bookmark or comment', optional: true } },
    run: (i) => disasmPrevAddress(i),
  },
  {
    name: 'disasm_list_names',
    description: 'Every name in the binary: functions, data symbols, imports (external), exports and dynamic symbols, DWARF globals and analyst names, each with kind (function, data, import, import-stub, user), binding (primary, dynamic, local, external, analyst) and source. Filter by kind or substring, paged, with counts per kind.',
    inputSchema: { path, arch, kind: { type: 'string', description: 'function, data, import, import-stub, symbol, user, or a binding (primary, dynamic, local, external)', optional: true }, filter: { type: 'string', description: 'Case insensitive substring', optional: true }, offset, limit: limit(200, 10000) },
    run: (i) => disasmListNames(i),
  },
  {
    name: 'disasm_search_functions',
    description: 'Search function names, including secondary names at the same entry (other symbols, DWARF linkage and qualified names, names replaced by an analyst name), by substring (default) or regex. The regex engine runs in linear time (no backtracking): literals, ., classes, \\d \\w \\s, anchors, groups, alternation and * + ? {n,m}; backreferences and lookaround are refused. Each function appears once with matchedAliases.',
    inputSchema: { path, arch, pattern: { type: 'string', description: 'Substring, or a regex with regex:true' }, regex: { type: 'boolean', description: 'Treat pattern as a regex', optional: true }, caseSensitive: { type: 'boolean', description: 'Case sensitive match (default false)', optional: true }, includeImports: { type: 'boolean', description: 'Include import stubs', optional: true }, offset, limit: limit(200, 10000) },
    run: (i) => disasmSearchFunctions(i),
  },
  {
    name: 'disasm_instruction',
    description: 'Inspect one exact address: the instruction there (or the instruction containing that byte, reported as containing-instruction), bytes, mnemonic, ordered operand tokens (register, immediate, memory with base, index, scale, displacement, size and segment), flow kind, outgoing references (branch or call target, memory operand, import slot, indirect candidates) and typed incoming references. Data addresses report the string and incoming references.',
    inputSchema: { path, arch, address, fileOffset, thumb: { type: 'boolean', description: 'ARM: decode as Thumb when not inside an analyzed function', optional: true }, budgetMs: budget },
    run: (i) => disasmInstruction(i),
  },
  {
    name: 'disasm_function_info',
    description: 'Function metadata: entry, name, signature with its source (DWARF prototype, or parameters found by value flow), calling convention, parameters and locals (DWARF names and types, or stack variables with signed displacements from the entry stack pointer), size, body bytes and span, block and instruction counts, inclusive body ranges and exits.',
    inputSchema: { path, arch, function: fn },
    run: (i) => disasmFunctionInfo(i),
  },
  {
    name: 'disasm_analyze_function',
    description: 'One call function dossier: identity with inclusive body ranges, signature, parameters and locals, summary (calls, strings, constants, complexity), pseudo code (DWARF names when present), assembly (paged), calls with resolved indirect candidates, callers, data and string references, called names, comments and bookmarks inside the function, value flow availability and limitations. detail summary leaves out pseudo code and assembly.',
    inputSchema: { path, arch, function: fn, detail: { type: 'string', description: 'complete (default) or summary', optional: true }, maxLines: { type: 'number', description: 'Pseudo code lines (default 300)', optional: true }, asmOffset: { type: 'number', description: 'Assembly paging offset', optional: true }, asmLimit: { type: 'number', description: 'Assembly instructions (default 200, max 5000)', optional: true }, budgetMs: budget },
    run: (i) => disasmAnalyzeFunction(i),
  },
  {
    name: 'disasm_api_boundary',
    description: 'API boundary of one function, such as a command or message dispatcher: each jump table with case value to target mapping, the default target proven by the bounds check (null when not proven), tables of code pointers, import calls, resolved indirect calls, unsupported (unresolved) indirect branches, residual unknowns and a confidence score with instruction addresses as evidence.',
    inputSchema: { path, arch, function: fn, maxCases: { type: 'number', description: 'Max cases per table (default 512)', optional: true } },
    run: (i) => disasmApiBoundary(i),
  },
];
