// Round 3 agent tools: debug info types, navigation context, feature tracing, behavior change,
// whole binary export, annotations (comments, bookmarks, names) and the function dossier.
import type { Tool, ToolParam } from './tools.js';
import { disasmDebugInfo } from './debugapi.js';

const path: ToolParam = { type: 'string', description: 'Path to an ELF, PE or Mach-O file (fat Mach-O picks x86_64, then arm64, unless arch is set)' };
const arch: ToolParam = { type: 'string', description: 'Fat Mach-O slice to analyze: x86_64, arm64, x86 or arm', optional: true };
const offset: ToolParam = { type: 'number', description: 'Paging: items to skip (default 0)', optional: true };
const limit = (d: number, max: number): ToolParam => ({ type: 'number', description: `Paging: max items (default ${d}, max ${max})`, optional: true });

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
];
