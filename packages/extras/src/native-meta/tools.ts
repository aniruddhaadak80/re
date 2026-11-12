// Agent tools for round 3 native metadata: ObjC and Swift dispatch metadata, Hermes bytecode and
// Dart AOT snapshots. Registered from tools2.ts.

import { inputBytes, PATH_INPUT, type ToolDef, type InputSpec } from '../util.js';
import { nativeDispatchMetadata, dispatchMetadataView } from './index.js';
import { hermesView } from '../hermes/index.js';
import { inspectDartAot } from '../dart/aot.js';
import { page } from '../util.js';
import { readPdb, pdbTypeDecl, isPdb } from './pdb.js';
import { typeLibsIn, typeInfoIdl } from './typelib.js';

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
  {
    name: 'x_pdb_types',
    description: 'Program database (PDB, MSF 7.00) reader: view summary (default): GUID and age (the symbol server key that matches the PE CodeView record), machine, TPI and IPI stream sizes, counts, modules and sections. types: structs, classes, unions and enums (forward references resolved) with size and member count, filter by name. type: one type with members (offsets, types, bit fields, access, base classes, virtual table pointer, static members, methods), enumerators and a C declaration. functions: procedures from module symbols with RVA, size, prototype with parameter names, and locals (registers or frame offsets). typedefs: S_UDT names. globals: global and static data with RVA, constants, public symbols. Pure TypeScript, no DIA or Windows needed.',
    inputSchema: {
      ...P,
      view: { type: 'string', description: 'summary, types, type, functions, typedefs or globals', optional: true },
      name: { type: 'string', description: 'type view: type name (geo::Rect, node) or type index like 0x1018; functions: exact function name', optional: true },
      filter: { type: 'string', description: 'Case insensitive substring of the name', optional: true },
      budgetMs: { type: 'number', description: 'Time budget in ms (default 20000)', optional: true },
      ...LIMIT,
    },
    async run(i) {
      const b = await inputBytes(i);
      if (!isPdb(b)) throw new Error('not a PDB file (MSF 7.00 magic missing)');
      const d = readPdb(b, { budgetMs: num(i.budgetMs, 20000) });
      const f = (i.filter ?? '').toLowerCase();
      const keep = (s: string | undefined) => !f || (s ?? '').toLowerCase().includes(f);
      const hex = (n: number | undefined) => (n === undefined ? undefined : '0x' + n.toString(16));
      const view = i.view ?? 'summary';
      const udt = d.types.filter((t) => ['struct', 'class', 'union', 'enum'].includes(t.kind) && !t.forwardRef);
      if (view === 'types') return page(udt.filter((t) => keep(t.name)).map((t) => ({ index: hex(t.index), kind: t.kind, name: t.name, size: t.size, members: t.members?.length, enumerators: t.enumerators?.length, uniqueName: t.uniqueName })), num(i.offset, 0), num(i.limit, 200));
      if (view === 'type') {
        const want = String(i.name ?? i.filter ?? '');
        const idx = /^0x[0-9a-f]+$/i.test(want) ? parseInt(want, 16) : undefined;
        let t = d.types.find((x) => (idx !== undefined ? x.index === idx : x.name === want) && !x.forwardRef) ?? d.types.find((x) => (idx !== undefined ? x.index === idx : x.name === want));
        if (t?.forwardRef && t.definition !== undefined) t = d.types.find((x) => x.index === t!.definition) ?? t;
        if (!t) return { found: false, name: want };
        return { found: true, ...t, index: hex(t.index), declarationText: pdbTypeDecl(t) };
      }
      if (view === 'functions') return page(d.procs.filter((p) => (i.name ? p.name === i.name : keep(p.name))).map((p) => ({ ...p, rva: hex(p.rva), typeIndex: hex(p.typeIndex) })), num(i.offset, 0), num(i.limit, 200));
      if (view === 'typedefs') return page(d.udts.filter((u) => keep(u.name)).map((u) => ({ ...u, typeIndex: hex(u.typeIndex) })), num(i.offset, 0), num(i.limit, 500));
      if (view === 'globals') return page(d.globals.filter((g) => keep(g.name)).map((g) => ({ ...g, rva: hex(g.rva), typeIndex: hex(g.typeIndex) })), num(i.offset, 0), num(i.limit, 500));
      return {
        guid: d.guid, age: d.age, symbolServerId: d.symbolServerId, signature: d.signature, version: d.version, machine: d.machine, blockSize: d.blockSize, streams: d.streams,
        tpi: d.tpi, ipi: d.ipi, userTypes: udt.length, typeRecords: d.types.length, functionIds: d.funcIds.length, procedures: d.procs.length, typedefs: d.udts.length, globals: d.globals.length,
        modules: d.modules.slice(0, 100).map((m) => ({ name: m.name, objFile: m.objFile })), moduleCount: d.modules.length, sections: d.sections, complete: d.complete, warnings: d.warnings.slice(0, 20),
      };
    },
  },
  {
    name: 'x_com_typelib',
    description: 'COM type library (MSFT .tlb written by midl or widl, or the TYPELIB resources inside a DLL, OCX or EXE): view summary (default): library name, LIBID, version, LCID, syskind, help string, imports and every type info with kind, GUID and counts. types: the type infos (filter by name or kind: enum, record, union, alias, interface, dispatch, coclass, module). type: one type info with functions (DISPID, vtable offset, invoke kind propget/propput, calling convention, return type, parameters with in/out/retval/optional flags, DLL entry for modules), variables and enum constants, implemented interfaces, and IDL like text. SLTG (old format) is detected only.',
    inputSchema: {
      ...P,
      view: { type: 'string', description: 'summary, types or type', optional: true },
      name: { type: 'string', description: 'type view: type info name (IPainter) or its GUID', optional: true },
      kind: { type: 'string', description: 'types view: enum, record, union, alias, interface, dispatch, coclass or module', optional: true },
      filter: { type: 'string', description: 'Case insensitive substring of the type name', optional: true },
      library: { type: 'number', description: 'Which TYPELIB resource of a PE (index from 0, default 0)', optional: true },
      ...LIMIT,
    },
    async run(i) {
      const libs = typeLibsIn(await inputBytes(i));
      if (!libs.length) return { libraries: 0, note: 'no TYPELIB resources' };
      const lib = libs[Math.max(0, Math.min(libs.length - 1, num(i.library, 0)))]!;
      const view = i.view ?? 'summary';
      const f = (i.filter ?? '').toLowerCase();
      if (view === 'types') return page(lib.typeInfos.filter((t) => (!i.kind || t.kind === i.kind) && (!f || t.name.toLowerCase().includes(f))).map((t) => ({ index: t.index, name: t.name, kind: t.kind, guid: t.guid, version: t.version, flags: t.flags, functions: t.funcs.length, variables: t.vars.length, implements: t.implements.map((x) => x.name), helpString: t.helpString })), num(i.offset, 0), num(i.limit, 200));
      if (view === 'type') {
        const want = String(i.name ?? '');
        const t = lib.typeInfos.find((x) => x.name === want || x.guid === want.toUpperCase() || x.guid === `{${want.toUpperCase()}}`);
        if (!t) return { found: false, name: want };
        return { found: true, ...t, idl: typeInfoIdl(t) };
      }
      const kinds: Record<string, number> = {};
      for (const t of lib.typeInfos) kinds[t.kind] = (kinds[t.kind] ?? 0) + 1;
      return { libraries: libs.length, format: lib.format, name: lib.name, guid: lib.guid, version: lib.version, lcid: lib.lcid, syskind: lib.syskind, flags: lib.flags, helpString: lib.helpString, helpFile: lib.helpFile, source: lib.source, kinds, imports: lib.imports, typeInfos: lib.typeInfos.slice(0, 200).map((t) => ({ name: t.name, kind: t.kind, guid: t.guid, functions: t.funcs.length, variables: t.vars.length })), warnings: lib.warnings };
    },
  },
];
