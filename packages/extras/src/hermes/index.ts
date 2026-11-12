// Hermes bytecode views for agents: summary, string table, function list, disassembly,
// string and function cross references, and the closure tree (which function creates which).

import { page, ParseError } from '../util.js';
import { HbcFile, rawInsnText, prettyInsnText, functionHeading, SUPPORTED_HBC_VERSIONS, type HbcFunction, type HbcInsn } from './hbc.js';

export * from './hbc.js';
export { SOURCE_COMMITS as HERMES_OPCODE_COMMITS } from './opcodes.js';

const CREATE_CLOSURE = /^Create(Async|Generator)?Closure(Long)?$|^CreateClosure/;

/** Locate Hermes bytecode in a file: the file itself, or a bundle inside a React Native APK member already extracted. */
export function openHbc(bytes: Uint8Array): HbcFile { return new HbcFile(bytes); }

function findFunction(h: HbcFile, ref: unknown): HbcFunction {
  if (typeof ref === 'number' || (typeof ref === 'string' && /^\d+$/.test(ref))) {
    const f = h.functions[Number(ref)];
    if (!f) throw new ParseError(`no function #${ref} (there are ${h.functions.length})`);
    return f;
  }
  if (typeof ref === 'string' && ref) {
    const f = h.functions.find((x) => x.name === ref);
    if (f) return f;
    throw new ParseError(`no function named ${ref}`);
  }
  return h.functions[h.header.globalCodeIndex] ?? h.functions[0]!;
}

export interface HermesViewInput { view?: string; function?: string | number; filter?: string; string?: string; offset?: number; limit?: number; format?: string; budgetMs?: number }

/** Run one Hermes view (summary, strings, functions, disassemble, xrefs, closures). */
export function hermesView(bytes: Uint8Array, i: HermesViewInput = {}): unknown {
  const h = new HbcFile(bytes);
  const view = i.view ?? 'summary';
  const off = i.offset ?? 0, lim = i.limit ?? 200;
  const filter = (i.filter ?? '').toLowerCase();
  const deadline = Date.now() + Math.max(100, Math.min(i.budgetMs ?? 20000, 300000));
  const fnRow = (f: HbcFunction) => ({ index: f.index, name: f.name, offset: f.offset, size: f.size, params: f.paramCount, registers: f.frameSize, symbols: f.environmentSize, strict: f.strictMode, exceptionHandlers: f.hasExceptionHandler, debugInfo: f.hasDebugInfo, ...(f.prohibitInvoke === 1 ? { notConstructor: true } : f.prohibitInvoke === 0 ? { notCallable: true } : {}) });
  switch (view) {
    case 'summary': {
      let insns = 0, unknown = 0;
      const ops = new Map<string, number>();
      let scanned = 0, complete = true;
      for (const f of h.functions) {
        if (Date.now() > deadline) { complete = false; break; }
        const d = h.disassemble(f);
        if (d.error) unknown++;
        insns += d.insns.length; scanned++;
        for (const x of d.insns) ops.set(x.name, (ops.get(x.name) ?? 0) + 1);
      }
      return {
        format: 'hermes-bytecode', version: h.header.version, supportedVersions: SUPPORTED_HBC_VERSIONS, header: h.header, layout: h.layout, notes: h.notes,
        functions: h.functions.length, globalFunction: h.functions[h.header.globalCodeIndex]?.name ?? null,
        instructions: insns, functionsScanned: scanned, complete, functionsWithDecodeErrors: unknown,
        topOpcodes: [...ops.entries()].sort((a, b) => b[1] - a[1]).slice(0, 25).map(([name, count]) => ({ name, count })),
        sampleFunctions: h.functions.filter((f) => f.name).slice(0, 20).map((f) => f.name),
      };
    }
    case 'strings': {
      const rows = [];
      for (let id = 0; id < h.header.stringCount; id++) {
        const s = h.string(id);
        if (filter && !s.value.toLowerCase().includes(filter)) continue;
        rows.push({ id, kind: s.kind, identifier: s.identifier, value: s.value.length > 2000 ? s.value.slice(0, 2000) + '...' : s.value });
      }
      return { version: h.header.version, ...page(rows, off, lim) };
    }
    case 'functions': {
      const rows = h.functions.filter((f) => !filter || f.name.toLowerCase().includes(filter)).map(fnRow);
      return { version: h.header.version, ...page(rows, off, lim) };
    }
    case 'disassemble': {
      const f = findFunction(h, i.function);
      const d = h.disassemble(f);
      const raw = i.format === 'raw';
      const rows = d.insns.map((x) => raw ? rawInsnText(x) : { offset: x.offset, fileOffset: f.offset + x.offset, text: prettyInsnText(x), ...(x.target !== undefined ? { target: x.target } : {}) });
      return { function: fnRow(f), heading: functionHeading(f), complete: d.complete, ...(d.error ? { error: d.error } : {}), exceptionHandlers: h.exceptionHandlers(f), ...page(rows, off, Math.min(lim, 5000)) };
    }
    case 'xrefs': {
      // functions that use a string (by text, substring) or reference a function
      const needle = (i.string ?? i.filter ?? '').toLowerCase();
      const fnTarget = i.function !== undefined ? findFunction(h, i.function).index : undefined;
      if (!needle && fnTarget === undefined) throw new ParseError('xrefs needs string (text) or function');
      const want = new Set<number>();
      if (needle) for (let id = 0; id < h.header.stringCount; id++) if (h.stringValue(id).toLowerCase().includes(needle)) want.add(id);
      const hits: { function: number; name: string; offset: number; fileOffset: number; insn: string; string?: string }[] = [];
      let complete = true;
      for (const f of h.functions) {
        if (Date.now() > deadline || hits.length >= 20000) { complete = false; break; }
        for (const x of h.disassemble(f).insns) {
          for (const o of x.operands) {
            if ((o.kind === 'string' && want.has(o.value)) || (o.kind === 'function' && o.value === fnTarget)) {
              hits.push({ function: f.index, name: f.name, offset: x.offset, fileOffset: f.offset + x.offset, insn: prettyInsnText(x), ...(o.kind === 'string' ? { string: o.text } : {}) });
            }
          }
        }
      }
      return { matchedStrings: want.size, complete, ...page(hits, off, lim) };
    }
    case 'closures': {
      // closure tree: for each function, the functions it creates with CreateClosure and friends
      const rows: { parent: number; parentName: string; child: number; childName: string; at: number; insn: string }[] = [];
      let complete = true;
      for (const f of h.functions) {
        if (Date.now() > deadline) { complete = false; break; }
        if (filter && !f.name.toLowerCase().includes(filter)) continue;
        for (const x of h.disassemble(f).insns) {
          if (!CREATE_CLOSURE.test(x.name)) continue;
          const o = x.operands.find((p) => p.kind === 'function');
          if (o) rows.push({ parent: f.index, parentName: f.name, child: o.value, childName: o.text ?? '', at: x.offset, insn: prettyInsnText(x) });
        }
      }
      return { complete, ...page(rows, off, lim) };
    }
    default: throw new ParseError('view must be summary, strings, functions, disassemble, xrefs or closures');
  }
}

/** Every instruction of every function as hbcdump -raw-disassemble prints it (testing and export). */
export function hermesRawListing(bytes: Uint8Array): string[] {
  const h = new HbcFile(bytes);
  const out: string[] = [];
  for (const f of h.functions) {
    out.push(functionHeading(f));
    const d = h.disassemble(f);
    for (const x of d.insns) out.push(rawInsnText(x));
    const eh = h.exceptionHandlers(f);
    if (eh.length) { out.push('Exception Handlers:'); eh.forEach((e, k) => out.push(`${k}: start = ${e.start}, end = ${e.end}, target = ${e.target}`)); }
  }
  return out;
}
export type { HbcInsn };
