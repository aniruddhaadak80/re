// Agent tools for round 3 native metadata: ObjC and Swift dispatch metadata, Hermes bytecode and
// Dart AOT snapshots. Registered from tools2.ts.

import { inputBytes, PATH_INPUT, type ToolDef, type InputSpec } from '../util.js';
import { nativeDispatchMetadata, dispatchMetadataView } from './index.js';
import { hermesView } from '../hermes/index.js';
import { inspectDartAot } from '../dart/aot.js';
import { page } from '../util.js';

const P = PATH_INPUT;
const LIMIT: Record<string, InputSpec> = {
  offset: { type: 'number', description: 'Index of the first item to return (paging)', optional: true },
  limit: { type: 'number', description: 'Maximum items to return, default 100', optional: true },
};
const num = (x: unknown, d: number): number => (typeof x === 'number' && Number.isFinite(x) ? x : typeof x === 'string' && x.trim() !== '' && Number.isFinite(Number(x)) ? Number(x) : d);

const dispatchTool = (name: string, alias: boolean): ToolDef => ({
  name,
  description: (alias ? 'Same as x_native_dispatch_metadata. ' : '') + 'Objective-C and Swift dispatch metadata of a Mach-O (fat files pick a slice with arch). view summary (default): counts, image info, fixup format. objc-classes: class_ro_t with instance and class methods (selector, type encoding, IMP address and symbol), ivars with offsets, properties, protocols, superclass (bound external classes by name). objc-categories, objc-protocols, objc-classrefs. swift-types: nominal types from __swift5_types with stored fields and their demangled types, enum cases, superclass, generic parameter count, class vtable entries with implementation addresses, conformances. swift-protocols (requirements, associated types) and swift-conformances. Handles relative method lists, LC_DYLD_CHAINED_FIXUPS (including arm64e authenticated pointers) and classic bind opcodes.',
  inputSchema: {
    ...P,
    arch: { type: 'string', description: 'Fat Mach-O slice: x86_64, arm64, arm64e, x86, arm (default: first slice)', optional: true },
    view: { type: 'string', description: 'summary, objc-classes, objc-categories, objc-protocols, objc-classrefs, swift-types, swift-protocols, swift-conformances', optional: true },
    filter: { type: 'string', description: 'Case insensitive substring of the class, type, protocol or conformance name', optional: true },
    budgetMs: { type: 'number', description: 'Time budget in ms (default 30000)', optional: true },
    ...LIMIT,
  },
  async run(i) {
    const md = nativeDispatchMetadata(await inputBytes(i), { arch: i.arch, budgetMs: num(i.budgetMs, 30000) });
    return dispatchMetadataView(md, i.view ?? 'summary', i.filter, num(i.offset, 0), num(i.limit, 100));
  },
});

export const NATIVE_META_TOOLS: ToolDef[] = [
  dispatchTool('x_native_dispatch_metadata', false),
  dispatchTool('x_inspect_native_dispatch_metadata', true),
  {
    name: 'x_hermes_bytecode',
    description: 'Hermes bytecode (React Native index.android.bundle or main.jsbundle compiled by hermesc), versions 84 to 96 (plus 97 to 99 best effort). view summary (default): header, section layout, instruction and opcode counts. strings: the string table (paged, filter). functions: function headers (name, offset, size, params, registers). disassemble: one function (function = index or name) with string and function operands resolved, format raw prints exactly like hbcdump -raw-disassemble. xrefs: every instruction that uses a string (string = text, substring) or references a function. closures: which function creates which closure.',
    inputSchema: {
      ...P,
      view: { type: 'string', description: 'summary, strings, functions, disassemble, xrefs or closures', optional: true },
      function: { type: 'string', description: 'Function index or name (disassemble, xrefs)', optional: true },
      string: { type: 'string', description: 'xrefs: text inside the strings to look for', optional: true },
      filter: { type: 'string', description: 'Substring filter for strings, functions and closures', optional: true },
      format: { type: 'string', description: 'disassemble: pretty (default) or raw (hbcdump text)', optional: true },
      budgetMs: { type: 'number', description: 'Time budget in ms for whole file scans (default 20000)', optional: true },
      ...LIMIT,
    },
    async run(i) {
      return hermesView(await inputBytes(i), { view: i.view, function: i.function, string: i.string, filter: i.filter, format: i.format, offset: num(i.offset, 0), limit: num(i.limit, 200), budgetMs: num(i.budgetMs, 20000) });
    },
  },
  {
    name: 'x_dart_aot',
    description: 'Dart AOT snapshot (Flutter libapp.so, iOS App.framework/App, dart compile aot-snapshot): snapshot blobs with kind, version hash and feature flags (arch, OS, compressed pointers, null safety), the string pool read from the read only object image, package and library URIs, and function names with addresses when the ELF keeps its static symbols (unstripped or the --split-debug-info symbol file). Pass companion (libflutter.so or Flutter.framework path) to read the Dart version text. view summary (default), strings, libraries or functions.',
    inputSchema: {
      ...P,
      companion: { type: 'string', description: 'Path to libflutter.so or the Flutter engine binary, for the Dart version', optional: true },
      view: { type: 'string', description: 'summary, strings, libraries or functions', optional: true },
      filter: { type: 'string', description: 'Case insensitive substring filter', optional: true },
      ...LIMIT,
    },
    async run(i) {
      const companion = typeof i.companion === 'string' ? await inputBytes({ path: i.companion }) : undefined;
      const info = inspectDartAot(await inputBytes(i), { companion });
      const f = (i.filter ?? '').toLowerCase();
      const keep = (s: string) => !f || s.toLowerCase().includes(f);
      const view = i.view ?? 'summary';
      if (view === 'strings') return page(info.strings.filter((s) => keep(s.value)).map((s) => ({ offset: s.offset, value: s.value.length > 2000 ? s.value.slice(0, 2000) + '...' : s.value, ...(s.twoByte ? { twoByte: true } : {}), blob: s.blob })), num(i.offset, 0), num(i.limit, 200));
      if (view === 'libraries') return page(info.libraries.filter(keep), num(i.offset, 0), num(i.limit, 500));
      if (view === 'functions') return { source: info.functionSource, ...page(info.functions.filter((x) => keep(x.name)).map((x) => ({ ...x, addr: '0x' + x.addr.toString(16) })), num(i.offset, 0), num(i.limit, 200)) };
      return {
        container: info.container, snapshots: info.snapshots, dartVersionHint: info.dartVersionHint ?? null, stringLayout: info.stringLayout ?? null,
        strings: info.strings.length, libraries: info.libraries.length, packages: info.packages, functions: info.functions.length, functionSource: info.functionSource,
        sampleLibraries: info.libraries.filter((l) => l.startsWith('package:')).slice(0, 30), partial: info.partial, notes: info.notes,
      };
    },
  },
];
