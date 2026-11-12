// Agent tool: DWARF types, prototypes, parameters, locals and globals of a native binary.
import { openProgram, type BinaryInput } from './api.js';
import { typeDecl, type DwarfType } from './debug/dwarf.js';
import { clampInt, hx, parseAddr } from './util.js';

const strip = (s: string) => s.replace(/\b(struct|union|enum|class) /g, '');

/**
 * DWARF debug info view. view summary (default): units, counts. types: named structs, unions,
 * enums and typedefs (filter, kind, paged). type: one type by name or id with members and a C
 * declaration. functions: prototypes with ranges. function: one function with parameters (and
 * their entry registers), locals and frame base. globals: global variables with addresses.
 */
export async function disasmDebugInfo(input: BinaryInput & { view?: string; name?: string; filter?: string; kind?: string; offset?: number; limit?: number; includeAnonymous?: boolean }) {
  const p = await openProgram(input);
  const d = p.dwarf();
  const view = input.view ?? 'summary';
  const off = clampInt(input.offset, 0, 0, 1e9);
  const lim = clampInt(input.limit, 100, 1, 5000);
  const q = input.filter ? String(input.filter).toLowerCase() : undefined;
  const base = { present: d.present, complete: d.complete, warnings: d.warnings.slice(0, 20) };
  const pg = <T>(rows: T[]) => ({ total: rows.length, offset: off, limit: lim, hasMore: off + lim < rows.length, items: rows.slice(off, off + lim) });
  const typeRow = (t: DwarfType) => ({ id: hx(t.id), kind: t.kind, name: t.name, display: t.display, size: t.size, ...(t.aliasOf ? { aliasOf: t.aliasOf } : {}), ...(t.members ? { members: t.members.length } : {}), ...(t.enumerators ? { enumerators: t.enumerators.length } : {}), ...(t.declaration ? { declaration: true } : {}), ...(t.line !== undefined ? { line: t.line } : {}) });
  if (view === 'summary') {
    const kinds: Record<string, number> = {};
    for (const t of d.types) kinds[t.kind] = (kinds[t.kind] ?? 0) + 1;
    return {
      ...base, format: p.img.format, arch: p.img.arch, sections: d.sections,
      units: d.units.slice(0, 200).map((u) => ({ offset: hx(u.offset), version: u.version, unitType: u.unitType, name: u.name, language: u.language, producer: u.producer, low: u.low !== undefined ? hx(u.low) : undefined, high: u.high !== undefined ? hx(u.high) : undefined, dies: u.dies })),
      unitCount: d.units.length, types: d.types.length, typeKinds: kinds, functions: d.functions.length, definedFunctions: d.functions.filter((f) => f.low).length, globals: d.globals.length,
    };
  }
  if (view === 'types') {
    const named = new Set(['struct', 'union', 'class', 'enum', 'typedef', 'base']);
    let rows = d.types.filter((t) => (input.kind ? t.kind === input.kind : named.has(t.kind)) && (input.includeAnonymous || t.name));
    if (q) rows = rows.filter((t) => t.display.toLowerCase().includes(q));
    const seen = new Set<string>();
    rows = rows.filter((t) => { const k = t.kind + ':' + t.display + ':' + t.size + ':' + (t.members?.length ?? '') + (t.declaration ? 'd' : ''); if (seen.has(k)) return false; seen.add(k); return true; });
    const r = pg(rows);
    return { ...base, ...r, items: r.items.map(typeRow) };
  }
  if (view === 'type') {
    const want = input.name ?? input.filter;
    if (!want) throw new Error('pass name (type name like "struct node", "node" or "point_t", or an id like 0x124)');
    const id = parseAddr(want);
    const matches = d.types.filter((t) => (id !== undefined && /^0x/i.test(String(want)) ? t.id === id : t.display === want || t.name === want || strip(t.display) === strip(String(want))));
    const best = matches.find((t) => !t.declaration && (t.members || t.enumerators)) ?? matches.find((t) => !t.declaration) ?? matches[0];
    if (!best) return { ...base, found: false, name: want };
    const types = p.debugTypes();
    return {
      ...base, found: true, ...typeRow(best), declarationText: typeDecl(best),
      ...(best.members ? { members: best.members.map((m) => ({ name: m.name, type: m.type, offset: m.offset, size: types.sizeOf(m.typeRef), ...(m.bitSize !== undefined ? { bitSize: m.bitSize, bitOffset: m.bitOffset } : {}) })) } : {}),
      ...(best.enumerators ? { enumerators: best.enumerators } : {}),
      ...(best.kind === 'typedef' ? { aliasOf: best.aliasOf, resolved: types.strip(best.id)?.display } : {}),
      ...(best.kind === 'function' ? { returns: best.returns, params: best.params } : {}),
      otherDefinitions: matches.length - 1,
    };
  }
  if (view === 'functions') {
    let rows = d.functions.filter((f) => !f.declaration || input.includeAnonymous);
    if (q) rows = rows.filter((f) => f.name.toLowerCase().includes(q) || f.linkageName?.toLowerCase().includes(q));
    rows = [...rows].sort((a, b) => (a.low ?? Infinity) - (b.low ?? Infinity));
    const r = pg(rows);
    return { ...base, ...r, items: r.items.map((f) => ({ name: f.name, linkageName: f.linkageName, low: f.low !== undefined ? hx(f.low) : undefined, high: f.high !== undefined ? hx(f.high) : undefined, prototype: f.prototype, line: f.line, ...(f.declaration ? { declaration: true } : {}) })) };
  }
  if (view === 'function') {
    const want = input.name ?? input.filter;
    if (want === undefined) throw new Error('pass name (function name or address)');
    const a = parseAddr(want);
    const f = (a !== undefined ? p.debugFunction(a) ?? d.functions.find((x) => x.low !== undefined && x.high !== undefined && a >= x.low && a < x.high) : undefined)
      ?? d.functions.find((x) => (x.name === want || x.linkageName === want) && x.low) ?? d.functions.find((x) => x.name === want || x.linkageName === want);
    if (!f) return { ...base, found: false, name: want };
    const loc = (l: (typeof f.params)[number]['location']) => (l ? { ...l, ...(l.addr !== undefined ? { addr: hx(l.addr) } : {}) } : undefined);
    return {
      ...base, found: true, name: f.name, linkageName: f.linkageName, prototype: f.prototype, returns: f.returns,
      low: f.low !== undefined ? hx(f.low) : undefined, high: f.high !== undefined ? hx(f.high) : undefined, line: f.line, external: f.external, noreturn: f.noreturn,
      frameBase: f.frameBase, params: f.params.map((x) => ({ name: x.name, type: x.type, location: loc(x.location), artificial: x.artificial })), locals: f.locals.slice(0, 500).map((x) => ({ name: x.name, type: x.type, location: loc(x.location) })),
    };
  }
  if (view === 'globals') {
    let rows = d.globals.filter((g) => !g.declaration);
    if (q) rows = rows.filter((g) => g.name.toLowerCase().includes(q));
    const r = pg(rows);
    return { ...base, ...r, items: r.items.map((g) => ({ name: g.name, type: g.type, addr: g.addr !== undefined ? hx(g.addr) : undefined, external: g.external })) };
  }
  throw new Error('view must be summary, types, type, functions, function or globals');
}
