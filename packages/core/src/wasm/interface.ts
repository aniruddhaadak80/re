// Typed WebAssembly interface: every import and export with its exact type, and a compare of two
// modules that reports added, removed and changed entries by (module, name) for imports and by
// name for exports, plus a compatibility verdict for swapping one module for the other.

import { readWasmModule, funcTypeOf, globalTypeOf, tableTypeOf, type FuncType, type Limits, type WasmModule, type ImportDesc } from './module.js';

export interface InterfaceEntry { key: string; kind: 'func' | 'table' | 'memory' | 'global' | 'tag'; type: string; index: number }
export interface WasmInterface { imports: InterfaceEntry[]; exports: InterfaceEntry[]; names?: { module?: string; functions: number } }
export interface InterfaceChange { key: string; kind: string; before: string; after: string }
export interface InterfaceDiff {
  schema: 'revlens/wasm-interface-diff@1';
  imports: { added: InterfaceEntry[]; removed: InterfaceEntry[]; changed: InterfaceChange[]; same: number };
  exports: { added: InterfaceEntry[]; removed: InterfaceEntry[]; changed: InterfaceChange[]; same: number };
  /** true when the right module can replace the left: no export removed or changed and no import added or changed */
  compatible: boolean;
  summary: string;
}

export function funcSig(t: FuncType | undefined): string { return t ? `(${t.params.join(', ')}) -> (${t.results.join(', ')})` : '?'; }
function limits(l: Limits): string { return `${l.min}${l.max !== undefined ? `..${l.max}` : '..'}${l.shared ? ' shared' : ''}${l.is64 ? ' i64' : ''}`; }
function descType(m: WasmModule, d: ImportDesc): string {
  switch (d.kind) {
    case 'func': return funcSig(m.types[d.type]);
    case 'table': return `${d.table.elem} ${limits(d.table.limits)}`;
    case 'memory': return `memory ${limits(d.memory)}`;
    case 'global': return `${d.global.mutable ? 'mut ' : ''}${d.global.type}`;
    case 'tag': return funcSig(m.types[d.type]);
  }
}

/** Typed imports and exports of a module. */
export function wasmInterface(bytes: Uint8Array | WasmModule): WasmInterface {
  const m = bytes instanceof Uint8Array ? readWasmModule(bytes) : bytes;
  const idx = { func: 0, table: 0, memory: 0, global: 0, tag: 0 };
  const imports: InterfaceEntry[] = m.imports.map((i) => ({ key: `${i.module}.${i.name}`, kind: i.desc.kind, type: descType(m, i.desc), index: idx[i.desc.kind]++ }));
  const exports: InterfaceEntry[] = m.exports.map((e) => {
    let type = '?';
    if (e.kind === 'func') type = funcSig(funcTypeOf(m, e.index));
    else if (e.kind === 'global') { const g = globalTypeOf(m, e.index); type = g ? `${g.mutable ? 'mut ' : ''}${g.type}` : '?'; }
    else if (e.kind === 'table') { const t = tableTypeOf(m, e.index); type = t ? `${t.elem} ${limits(t.limits)}` : '?'; }
    else if (e.kind === 'memory') { const mi = e.index - m.importCounts.memory; const imp = m.imports.filter((x) => x.desc.kind === 'memory')[e.index]; const l = mi >= 0 ? m.memories[mi] : imp && imp.desc.kind === 'memory' ? imp.desc.memory : undefined; type = l ? `memory ${limits(l)}` : '?'; }
    return { key: e.name, kind: e.kind, type, index: e.index };
  });
  return { imports, exports, ...(m.names ? { names: { module: m.names.module, functions: Object.keys(m.names.functions).length } } : {}) };
}

function diffList(a: InterfaceEntry[], b: InterfaceEntry[]): InterfaceDiff['imports'] {
  const A = new Map(a.map((e) => [`${e.kind}:${e.key}`, e])), B = new Map(b.map((e) => [`${e.kind}:${e.key}`, e]));
  const out: InterfaceDiff['imports'] = { added: [], removed: [], changed: [], same: 0 };
  for (const [k, e] of A) { const o = B.get(k); if (!o) out.removed.push(e); else if (o.type !== e.type) out.changed.push({ key: e.key, kind: e.kind, before: e.type, after: o.type }); else out.same++; }
  for (const [k, e] of B) if (!A.has(k)) out.added.push(e);
  return out;
}

/** Compare the typed interfaces of two modules. */
export function compareWasmInterfaces(left: Uint8Array | WasmModule, right: Uint8Array | WasmModule, scope: 'imports' | 'exports' | 'both' = 'both'): InterfaceDiff {
  const a = wasmInterface(left), b = wasmInterface(right);
  const empty = { added: [], removed: [], changed: [], same: 0 };
  const imports = scope === 'exports' ? empty : diffList(a.imports, b.imports);
  const exports = scope === 'imports' ? empty : diffList(a.exports, b.exports);
  const compatible = !exports.removed.length && !exports.changed.length && !imports.added.length && !imports.changed.length;
  const part = (n: string, d: InterfaceDiff['imports']): string => `${n}: ${d.added.length} added, ${d.removed.length} removed, ${d.changed.length} changed, ${d.same} same`;
  return { schema: 'revlens/wasm-interface-diff@1', imports, exports, compatible, summary: `${part('imports', imports)}; ${part('exports', exports)}; ${compatible ? 'right can replace left' : 'not a drop-in replacement'}` };
}
