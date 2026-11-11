// Agent facing functions. Every function takes a file `path` (Node) or `bytes`, returns JSON with
// hex addresses and file offsets as evidence, and pages large outputs with offset/limit.
import type { AnalyzedFunction, FunctionInfo, Insn } from './types.js';
import { Program, normName, type OpenOptions } from './analysis/program.js';
import { liftFunction } from './analysis/lift.js';
import { stringAt } from './analysis/strings.js';
import { Budget, clampInt, globMatch, hx, parseAddr } from './util.js';

export interface BinaryInput extends OpenOptions {
  path?: string;
  bytes?: Uint8Array | ArrayBuffer;
}

type Reader = (path: string) => Promise<Uint8Array>;
let fileReader: Reader | undefined;

/** Register how `path` inputs are read (src/node.ts registers fs.readFile). */
export function setFileReader(r: Reader): void { fileReader = r; }

async function readPath(path: string): Promise<Uint8Array> {
  if (fileReader) return fileReader(path);
  const g = globalThis as { process?: { versions?: { node?: string } } };
  if (g.process?.versions?.node) {
    const spec = 'node:fs/promises';
    const fs = (await import(/* @vite-ignore */ spec)) as { readFile(p: string): Promise<Uint8Array> };
    return new Uint8Array(await fs.readFile(path));
  }
  throw new Error('path input needs Node; pass bytes instead');
}

const MAX_FILE = 512 * 1024 * 1024;
const cache = new Map<string, Promise<Program>>();

function quickKey(b: Uint8Array): string {
  let h = 2166136261;
  const step = Math.max(1, Math.floor(b.length / 4096));
  for (let i = 0; i < b.length; i += step) { h ^= b[i]!; h = Math.imul(h, 16777619); }
  return `${b.length}:${(h >>> 0).toString(16)}`;
}

/** Open (or reuse) the analysis session for an input. */
export async function openProgram(input: BinaryInput): Promise<Program> {
  let bytes: Uint8Array;
  if (input.bytes) bytes = input.bytes instanceof Uint8Array ? input.bytes : new Uint8Array(input.bytes);
  else if (input.path) bytes = await readPath(input.path);
  else throw new Error('pass path or bytes');
  if (bytes.length > MAX_FILE) throw new Error(`file too large (${bytes.length} bytes, limit ${MAX_FILE})`);
  const key = `${input.path ?? 'bytes'}:${quickKey(bytes)}:${input.arch ?? ''}:${input.rawArch ?? ''}:${input.rawBase ?? ''}`;
  let p = cache.get(key);
  if (!p) {
    p = Program.open(bytes, input);
    cache.set(key, p);
    p.catch(() => cache.delete(key));
    if (cache.size > 8) cache.delete(cache.keys().next().value as string);
  }
  return p;
}

/** Drop cached sessions (tests, memory pressure). */
export function clearSessions(): void { cache.clear(); }

// ---------- helpers ----------

function fnJson(p: Program, f: FunctionInfo) {
  return {
    addr: hx(f.addr), name: f.name, size: f.size ?? p.analysisSizeHint(f.addr), source: f.source,
    fileOffset: p.mem.toOffset(f.addr) >= 0 ? p.mem.toOffset(f.addr) + p.img.fileOffset : undefined,
    ...(f.thumb ? { thumb: true } : {}), ...(f.isImportStub ? { importStub: true } : {}),
  };
}

/** Resolve a function by name (exact, then normalized) or address. */
export function resolveFunction(p: Program, ref: unknown): FunctionInfo | undefined {
  p.discover();
  const a = parseAddr(ref);
  if (a !== undefined) {
    const f = p.functions.get(a) ?? p.functionContaining(a);
    if (f) return f;
    if (p.mem.isExec(a)) return p.analyze(a);
    return undefined;
  }
  if (typeof ref !== 'string' || !ref) return undefined;
  for (const f of p.functions.values()) if (f.name === ref && !f.isImportStub) return f;
  for (const f of p.functions.values()) if (f.name === ref) return f;
  const n = normName(ref);
  for (const f of p.functions.values()) if (normName(f.name) === n && !f.isImportStub) return f;
  for (const f of p.functions.values()) if (normName(f.name) === n) return f;
  return undefined;
}

function insnJson(p: Program, af: AnalyzedFunction | undefined, i: Insn) {
  const o: Record<string, unknown> = { addr: hx(i.address), bytes: i.bytes, text: (i.mnemonic + ' ' + i.operands).trim() };
  const ref = annotate(p, af, i);
  if (ref) o.ref = ref;
  return o;
}

function annotate(p: Program, af: AnalyzedFunction | undefined, i: Insn): string | undefined {
  if (i.target !== undefined && (i.flow === 'call' || i.flow === 'jump' || i.flow === 'cjump')) {
    const n = p.symbolize(i.target);
    if (n && i.flow !== 'cjump') return n;
  }
  if (i.viaMemory && i.memAddr !== undefined) {
    const imp = p.importBySlot.get(i.memAddr);
    if (imp) return imp.name + (imp.library ? ` (${imp.library})` : '');
  }
  const d = af?.dataRefs.find((r) => r.at === i.address);
  if (d) {
    if (d.kind === 'string') return JSON.stringify(d.value);
    if (d.kind === 'import-slot') return '&' + d.value;
    if (d.value) return d.value;
  }
  if (i.memAddr !== undefined && !af) {
    const r = p.classifyRef(i.address, i.memAddr, i);
    if (r?.kind === 'string') return JSON.stringify(r.value);
    if (r?.value) return r.value;
  }
  return undefined;
}

function page<T>(items: T[], offset: unknown, limit: unknown, defLimit: number, maxLimit: number) {
  const off = clampInt(offset, 0, 0, Number.MAX_SAFE_INTEGER);
  const lim = clampInt(limit, defLimit, 1, maxLimit);
  return { total: items.length, offset: off, limit: lim, items: items.slice(off, off + lim), hasMore: off + lim < items.length };
}

/** Summary used by disasm_function, disasm_pseudocode and the analyzer. */
export function summarizeFunction(p: Program, af: AnalyzedFunction) {
  const edges = af.blocks.reduce((n, b) => n + b.succ.length, 0);
  const backEdges = af.blocks.reduce((n, b) => n + b.succ.filter((e) => e.to <= b.start).length, 0);
  const callNames = new Map<string, number>();
  for (const c of af.calls) {
    const n = c.name ?? (c.target !== undefined ? 'sub_' + c.target.toString(16) : '(indirect)');
    callNames.set(n, (callNames.get(n) ?? 0) + 1);
  }
  const strings = [...new Map(af.dataRefs.filter((d) => d.kind === 'string').map((d) => [d.addr, { addr: hx(d.addr), value: d.value, at: hx(d.at) }])).values()];
  return {
    addr: hx(af.addr), name: af.name, size: af.size ?? af.codeSize,
    instructions: af.insnCount, blocks: af.blocks.length, edges,
    cyclomaticComplexity: 1 + af.blocks.filter((b) => b.succ.length > 1).length,
    loops: backEdges, leaf: af.calls.length === 0,
    calls: [...callNames].map(([name, count]) => ({ name, count })),
    imports: [...new Set(af.dataRefs.filter((d) => d.kind === 'import-slot').map((d) => d.value!).concat(af.calls.filter((c) => c.target !== undefined && p.importByStub.has(c.target)).map((c) => c.name!)))],
    strings: strings.slice(0, 50),
    constants: af.constants.slice(0, 32).map((c) => (Math.abs(c) > 9 ? hx(c) : String(c))),
    unresolvedIndirect: af.unresolvedIndirect,
    truncated: af.truncated,
  };
}

function need<T>(v: T | undefined, msg: string): T {
  if (v === undefined) throw new Error(msg);
  return v;
}

// ---------- tool functions ----------

/** Overview: format, arch, entry, sections, counts of symbols, imports and functions. */
export async function disasmInfo(input: BinaryInput) {
  const p = await openProgram(input);
  const img = p.img;
  p.discover();
  return {
    format: img.format, arch: img.arch, bits: img.bits, endian: img.endian,
    entry: img.entry !== undefined ? hx(img.entry) : undefined,
    imageBase: hx(img.imageBase), decoder: p.decoder?.name ?? null, decoderErrors: p.decoderErrors,
    slices: img.slices?.map((s) => ({ arch: s.arch, offset: s.offset, size: s.size })),
    sections: img.sections.slice(0, 200).map((s) => ({ name: s.name, vaddr: hx(s.vaddr), size: s.size, fileOffset: s.offset + img.fileOffset, exec: s.exec, write: s.write })),
    symbols: img.symbols.length, imports: img.imports.length, importStubs: p.importByStub.size,
    functions: p.functions.size, discoveryComplete: p.discoveryComplete, notes: p.discoveryNotes,
    go: img.goVersionHint, warnings: img.warnings,
  };
}

/** List discovered functions with paging, name filter and sorting. */
export async function disasmListFunctions(input: BinaryInput & { offset?: number; limit?: number; filter?: string; sort?: 'addr' | 'name' | 'size'; includeImports?: boolean }) {
  const p = await openProgram(input);
  p.discover();
  let list = [...p.functions.values()];
  if (!input.includeImports) list = list.filter((f) => !f.isImportStub);
  if (input.filter) { const q = String(input.filter).toLowerCase(); list = list.filter((f) => f.name.toLowerCase().includes(q)); }
  const sort = input.sort ?? 'addr';
  if (sort === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
  else if (sort === 'size') list.sort((a, b) => (b.size ?? 0) - (a.size ?? 0));
  else list.sort((a, b) => a.addr - b.addr);
  const pg = page(list, input.offset, input.limit, 100, 2000);
  return {
    format: p.img.format, arch: p.img.arch, entry: p.img.entry !== undefined ? hx(p.img.entry) : undefined,
    total: pg.total, offset: pg.offset, limit: pg.limit, hasMore: pg.hasMore,
    discoveryComplete: p.discoveryComplete, notes: p.discoveryNotes,
    functions: pg.items.map((f) => fnJson(p, f)),
  };
}

/** Disassembly and CFG (blocks, edges, calls, strings) of one function. */
export async function disasmFunction(input: BinaryInput & { function: string | number; offset?: number; limit?: number }) {
  const p = await openProgram(input);
  const f = need(resolveFunction(p, input.function), `function not found: ${input.function}`);
  const af = need(p.analyze(f.addr), `cannot analyze ${f.name} (no decoder or not code)`);
  const all = af.blocks.flatMap((b) => b.insns.map((i) => ({ b, i })));
  const pg = page(all, input.offset, input.limit, 400, 5000);
  const shown = new Set(pg.items.map((x) => x.i));
  return {
    function: fnJson(p, af), summary: summarizeFunction(p, af),
    paging: { totalInstructions: pg.total, offset: pg.offset, limit: pg.limit, hasMore: pg.hasMore },
    blocks: af.blocks.map((b) => ({
      start: hx(b.start), end: hx(b.end),
      succ: b.succ.map((e) => ({ to: hx(e.to), kind: e.kind })),
      pred: b.pred.map(hx),
      ...(b.exit ? { exit: b.exit } : {}),
      insns: b.insns.filter((i) => shown.has(i)).map((i) => insnJson(p, af, i)),
    })).filter((b) => b.insns.length > 0 || pg.total === 0),
    calls: af.calls.slice(0, 500).map((c) => ({ at: hx(c.at), target: c.target !== undefined ? hx(c.target) : undefined, name: c.name, indirect: c.indirect || undefined, tail: c.tail })),
  };
}

/** Readable pseudo code plus a function summary. */
export async function disasmPseudocode(input: BinaryInput & { function: string | number; maxLines?: number }) {
  const p = await openProgram(input);
  const f = need(resolveFunction(p, input.function), `function not found: ${input.function}`);
  const af = need(p.analyze(f.addr), `cannot analyze ${f.name}`);
  const lift = liftFunction(p, af, clampInt(input.maxLines, 300, 10, 5000));
  return { function: fnJson(p, af), structured: lift.structured, gotos: lift.gotos, pseudocode: lift.text, summary: summarizeFunction(p, af) };
}

/** Cross references to an address or function (direction "to") or made by a function ("from"). */
export async function disasmXrefs(input: BinaryInput & { target: string | number; direction?: 'to' | 'from'; offset?: number; limit?: number; budgetMs?: number }) {
  const p = await openProgram(input);
  const dir = input.direction ?? 'to';
  if (dir === 'from') {
    const f = need(resolveFunction(p, input.target), `function not found: ${input.target}`);
    const af = need(p.analyze(f.addr), 'cannot analyze');
    const refs = [
      ...af.calls.map((c) => ({ at: hx(c.at), kind: c.tail ? 'jump' : 'call', target: c.target !== undefined ? hx(c.target) : undefined, name: c.name ?? (c.indirect ? '(indirect)' : undefined) })),
      ...af.dataRefs.map((d) => ({ at: hx(d.at), kind: d.kind, target: hx(d.addr), name: d.value })),
    ].sort((a, b) => parseInt(a.at, 16) - parseInt(b.at, 16));
    const pg = page(refs, input.offset, input.limit, 200, 5000);
    return { function: fnJson(p, f), direction: 'from', total: pg.total, offset: pg.offset, hasMore: pg.hasMore, refs: pg.items };
  }
  let addr = parseAddr(input.target);
  let label: string | undefined;
  if (addr === undefined) {
    const f = resolveFunction(p, input.target);
    if (f) { addr = f.addr; label = f.name; }
    else {
      const imp = p.img.imports.find((i) => i.name === input.target || normName(i.name) === normName(String(input.target)));
      if (imp) { addr = imp.stub ?? imp.slot; label = imp.name; }
      const sym = p.img.symbols.find((s) => s.name === input.target);
      if (addr === undefined && sym) { addr = sym.addr; label = sym.name; }
    }
  }
  addr = need(addr, `cannot resolve ${input.target}`);
  const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  const targets = new Set<number>([addr]);
  const imp = p.importByStub.get(addr) ?? p.importBySlot.get(addr);
  if (imp) { if (imp.stub !== undefined) targets.add(imp.stub); if (imp.slot !== undefined) targets.add(imp.slot); for (const [s, i] of p.importByStub) if (i.name === imp.name) targets.add(s); }
  const refs = [...targets].flatMap((t) => (idx.to.get(t) ?? []).map((r) => ({ from: hx(r.from), function: p.functions.get(r.func)?.name ?? hx(r.func), functionAddr: hx(r.func), kind: r.kind, target: hx(t) })));
  refs.sort((a, b) => parseInt(a.from, 16) - parseInt(b.from, 16));
  const pg = page(refs, input.offset, input.limit, 200, 5000);
  return { target: hx(addr), name: label ?? p.symbolize(addr), direction: 'to', complete: idx.complete, functionsScanned: idx.analyzed, total: pg.total, offset: pg.offset, hasMore: pg.hasMore, refs: pg.items };
}

/** Call graph around a function (callees, callers or both to a depth), or the program wide top nodes. */
export async function disasmCallgraph(input: BinaryInput & { function?: string | number; direction?: 'callees' | 'callers' | 'both'; depth?: number; limit?: number; offset?: number; budgetMs?: number }) {
  const p = await openProgram(input);
  const depth = clampInt(input.depth, 2, 1, 8);
  const limit = clampInt(input.limit, 300, 1, 5000);
  const dir = input.direction ?? 'callees';
  const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  const callersOf = (a: number) => [...new Set((idx.to.get(a) ?? []).filter((r) => r.kind === 'call' || r.kind === 'jump').map((r) => r.func))];
  const calleesOf = (a: number) => {
    const af = p.analyze(a);
    if (!af) return [] as { addr?: number; name: string }[];
    const m = new Map<string, { addr?: number; name: string }>();
    for (const c of af.calls) {
      if (c.target !== undefined) m.set(hx(c.target), { addr: c.target, name: c.name ?? 'sub_' + c.target.toString(16) });
      else if (c.name) m.set('import:' + c.name, { name: c.name });
    }
    return [...m.values()];
  };
  if (input.function === undefined) {
    const rows = [...p.functions.values()].filter((f) => !f.isImportStub).map((f) => ({ f, callers: callersOf(f.addr).length, callees: p.analyze(f.addr)?.calls.length ?? 0 }));
    rows.sort((a, b) => b.callers - a.callers || a.f.addr - b.f.addr);
    const pg = page(rows, input.offset, input.limit, 100, 2000);
    return { complete: idx.complete, total: pg.total, offset: pg.offset, hasMore: pg.hasMore, nodes: pg.items.map((r) => ({ addr: hx(r.f.addr), name: r.f.name, callers: r.callers, callSites: r.callees })) };
  }
  const root = need(resolveFunction(p, input.function), `function not found: ${input.function}`);
  const nodes = new Map<string, { addr?: string; name: string; depth: number }>();
  const edges: { from: string; to: string }[] = [];
  const key = (a?: number, n?: string) => (a !== undefined ? hx(a) : 'import:' + n);
  nodes.set(key(root.addr), { addr: hx(root.addr), name: root.name, depth: 0 });
  const walk = (start: number, forward: boolean) => {
    let frontier = [start];
    for (let d = 1; d <= depth && frontier.length && edges.length < limit; d++) {
      const next: number[] = [];
      for (const a of frontier) {
        const list = forward ? calleesOf(a) : callersOf(a).map((c) => ({ addr: c as number | undefined, name: p.functions.get(c)?.name ?? hx(c) }));
        for (const n of list) {
          const k = key(n.addr, n.name);
          if (!nodes.has(k)) { nodes.set(k, { addr: n.addr !== undefined ? hx(n.addr) : undefined, name: n.name, depth: forward ? d : -d }); if (n.addr !== undefined && !p.importByStub.has(n.addr)) next.push(n.addr); }
          edges.push(forward ? { from: hx(a), to: k } : { from: k, to: hx(a) });
          if (edges.length >= limit) break;
        }
      }
      frontier = next;
    }
  };
  if (dir === 'callees' || dir === 'both') walk(root.addr, true);
  if (dir === 'callers' || dir === 'both') walk(root.addr, false);
  return { root: fnJson(p, root), direction: dir, depth, complete: idx.complete && edges.length < limit, nodes: [...nodes.values()], edges };
}

function parsePattern(hex: string): number[] {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('byte pattern must have an even number of hex digits (use ?? for a wildcard byte)');
  const toks = clean.match(/.{2}/g) ?? [];
  const out: number[] = [];
  for (const t of toks) {
    if (t === '??' || t === '?') out.push(-1);
    else if (/^[0-9a-fA-F]{2}$/.test(t)) out.push(parseInt(t, 16));
    else throw new Error(`bad byte pattern token: ${t}`);
  }
  if (!out.length || out.length > 256) throw new Error('byte pattern must have 1 to 256 bytes');
  if (out.every((v) => v === -1)) throw new Error('byte pattern needs at least one fixed byte');
  return out;
}

/** Search code: byte pattern with ?? wildcards, instruction text glob (e.g. "call *printf*"), or literal string bytes. */
export async function disasmSearch(input: BinaryInput & { bytes_pattern?: string; insn?: string; text?: string; scope?: 'code' | 'all'; offset?: number; limit?: number; budgetMs?: number }) {
  const p = await openProgram(input);
  const limit = clampInt(input.limit, 100, 1, 2000);
  const offset = clampInt(input.offset, 0, 0, 1e9);
  const budget = new Budget(clampInt(input.budgetMs, 8000, 100, 60000));
  const want = offset + limit + 1;
  const matches: Record<string, unknown>[] = [];
  let complete = true;
  if (input.bytes_pattern || input.text) {
    const pat = input.bytes_pattern ? parsePattern(input.bytes_pattern) : [...new TextEncoder().encode(String(input.text))];
    if (!pat.length) throw new Error('empty pattern');
    const scope = input.scope ?? (input.text ? 'all' : 'code');
    const regs = p.mem.regions.filter((r) => r.fsize > 0 && (scope === 'all' || r.exec));
    const first = pat.findIndex((v) => v !== -1);
    outer: for (const r of regs) {
      const b = p.mem.view(r.start, r.fsize);
      for (let i = 0; i + pat.length <= b.length; i++) {
        if (b[i + first] !== pat[first]) continue;
        let ok = true;
        for (let k = 0; k < pat.length; k++) { const v = pat[k]!; if (v !== -1 && b[i + k] !== v) { ok = false; break; } }
        if (!ok) continue;
        const a = r.start + i;
        const f = p.functionContaining(a);
        matches.push({ addr: hx(a), fileOffset: r.offset + i + p.img.fileOffset, section: r.name, function: f?.name, functionAddr: f ? hx(f.addr) : undefined });
        if (matches.length >= want) { complete = false; break outer; }
        if ((matches.length & 255) === 0 && budget.expired) { complete = false; break outer; }
      }
    }
  } else if (input.insn) {
    const pat = String(input.insn).toLowerCase().replace(/\s+/g, ' ').trim();
    p.discover();
    outer2: for (const a of p.sortedFunctionAddrs()) {
      if (budget.expired) { complete = false; break; }
      const f = p.functions.get(a)!;
      if (f.isImportStub) continue;
      const af = p.analyze(a);
      if (!af) continue;
      for (const b of af.blocks) for (const i of b.insns) {
        const text = (i.mnemonic + ' ' + i.operands).trim().toLowerCase();
        const ref = annotate(p, af, i)?.toLowerCase();
        if (globMatch(pat, text) || (ref !== undefined && globMatch(pat, i.mnemonic + ' ' + ref))) {
          matches.push({ addr: hx(i.address), text: (i.mnemonic + ' ' + i.operands).trim(), ref: annotate(p, af, i), function: af.name, functionAddr: hx(af.addr) });
          if (matches.length >= want) { complete = false; break outer2; }
        }
      }
    }
  } else throw new Error('pass bytes_pattern, insn or text');
  const items = matches.slice(offset, offset + limit);
  return { total: complete ? matches.length : undefined, offset, limit, hasMore: matches.length > offset + limit, complete, matches: items };
}

/** Functions that reference a string (substring match) or call/load an import. */
export async function disasmFindReferences(input: BinaryInput & { string?: string; import?: string; exact?: boolean; caseSensitive?: boolean; limit?: number; offset?: number; budgetMs?: number }) {
  const p = await openProgram(input);
  const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  const out: { target: string; value: string; kind: string; refs: { from: string; function: string; functionAddr: string }[] }[] = [];
  const cs = !!input.caseSensitive;
  const norm = (s: string) => (cs ? s : s.toLowerCase());
  if (input.string !== undefined) {
    const q = norm(String(input.string));
    if (!q) throw new Error('empty string');
    for (const [addr, list] of idx.to) {
      if (!list.some((r) => r.kind === 'string')) continue;
      const s = stringAt(p.mem, addr, 1);
      if (!s) continue;
      const v = norm(s.value);
      if (input.exact ? v !== q : !v.includes(q)) continue;
      out.push({ target: hx(addr), value: s.value, kind: 'string', refs: list.filter((r) => r.kind === 'string').map((r) => ({ from: hx(r.from), function: p.functions.get(r.func)?.name ?? hx(r.func), functionAddr: hx(r.func) })) });
    }
  } else if (input.import !== undefined) {
    const q = normName(String(input.import));
    const imps = p.img.imports.filter((i) => (input.exact ? normName(i.name) === q : normName(i.name).includes(q)));
    const byName = new Map<string, Set<number>>();
    for (const i of imps) {
      const s = byName.get(i.name) ?? new Set<number>();
      if (i.slot !== undefined) s.add(i.slot);
      if (i.stub !== undefined) s.add(i.stub);
      byName.set(i.name, s);
    }
    for (const [stub, i] of p.importByStub) if (byName.has(i.name)) byName.get(i.name)!.add(stub);
    for (const [name, addrs] of byName) {
      const refs = [...addrs].flatMap((a) => (idx.to.get(a) ?? []).map((r) => ({ from: hx(r.from), function: p.functions.get(r.func)?.name ?? hx(r.func), functionAddr: hx(r.func) })));
      const uniq = [...new Map(refs.map((r) => [r.from, r])).values()].sort((a, b) => parseInt(a.from, 16) - parseInt(b.from, 16));
      out.push({ target: [...addrs].map(hx).join(','), value: name, kind: 'import', refs: uniq });
    }
  } else throw new Error('pass string or import');
  out.sort((a, b) => b.refs.length - a.refs.length || a.value.localeCompare(b.value));
  const pg = page(out, input.offset, input.limit, 50, 1000);
  const functions = [...new Set(out.flatMap((o) => o.refs.map((r) => r.function)))];
  return { complete: idx.complete, functionsScanned: idx.analyzed, total: pg.total, offset: pg.offset, hasMore: pg.hasMore, functions: functions.slice(0, 500), matches: pg.items };
}

/** Call paths from an entry (default: the entry point, or main when present) to a target function. */
export async function disasmCallPaths(input: BinaryInput & { target: string | number; from?: string | number; maxDepth?: number; maxPaths?: number; budgetMs?: number }) {
  const p = await openProgram(input);
  const target = need(resolveFunction(p, input.target), `target not found: ${input.target}`);
  let from: FunctionInfo | undefined;
  if (input.from !== undefined) from = need(resolveFunction(p, input.from), `from not found: ${input.from}`);
  else from = (p.img.entry !== undefined ? p.functions.get(p.img.entry) : undefined) ?? resolveFunction(p, 'main');
  from = need(from, 'no entry point; pass from');
  const maxDepth = clampInt(input.maxDepth, 12, 1, 40);
  const maxPaths = clampInt(input.maxPaths, 10, 1, 200);
  const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  // all call sites into a node (direct calls, tail jumps, and calls to its import stubs)
  const callers = new Map<number, Set<number>>();
  for (const [to, list] of idx.to) for (const r of list) if (r.kind === 'call' || r.kind === 'jump' || r.kind === 'code-ref' || (r.kind === 'import' && to === target.addr)) {
    let s = callers.get(to);
    if (!s) { s = new Set(); callers.set(to, s); }
    s.add(r.func);
  }
  // reverse BFS distances from target
  const dist = new Map<number, number>([[target.addr, 0]]);
  let frontier = [target.addr];
  for (let d = 1; d <= maxDepth && frontier.length; d++) {
    const next: number[] = [];
    for (const a of frontier) for (const c of callers.get(a) ?? []) if (!dist.has(c)) { dist.set(c, d); next.push(c); }
    frontier = next;
  }
  const paths: string[][] = [];
  if (dist.has(from.addr)) {
    const budget = new Budget(3000);
    const calleesCache = new Map<number, number[]>();
    const callees = (a: number) => {
      let c = calleesCache.get(a);
      if (!c) {
        const af = p.analyze(a);
        c = [...new Set([...(af?.calls ?? []).filter((x) => x.target !== undefined).map((x) => x.target!), ...(af?.dataRefs ?? []).filter((d) => d.kind === 'code' && p.functions.has(d.addr)).map((d) => d.addr)])];
        calleesCache.set(a, c);
      }
      return c;
    };
    const stack: number[] = [from.addr];
    const onPath = new Set<number>([from.addr]);
    const dfs = (a: number) => {
      if (paths.length >= maxPaths || budget.expired) return;
      if (a === target.addr) { paths.push(stack.map((x) => p.functions.get(x)?.name ?? p.nameOf(x) ?? hx(x))); return; }
      if (stack.length > maxDepth) return;
      const next = callees(a).filter((c) => dist.has(c) && !onPath.has(c)).sort((x, y) => dist.get(x)! - dist.get(y)!);
      for (const n of next) {
        if (stack.length - 1 + dist.get(n)! + 1 > maxDepth + 1) continue;
        stack.push(n); onPath.add(n);
        dfs(n);
        stack.pop(); onPath.delete(n);
      }
    };
    dfs(from.addr);
  }
  return { from: fnJson(p, from), target: fnJson(p, target), note: 'edges are direct calls, tail jumps and code addresses taken (callbacks, __libc_start_main(main))', reachable: dist.has(from.addr), shortest: dist.get(from.addr), complete: idx.complete, paths, callersOfTarget: [...(callers.get(target.addr) ?? [])].slice(0, 50).map((c) => p.functions.get(c)?.name ?? hx(c)) };
}

/** Disassemble N instructions at an address (linear, no function needed). */
export async function disasmAt(input: BinaryInput & { address: string | number; count?: number; thumb?: boolean }) {
  const p = await openProgram(input);
  let addr = parseAddr(input.address);
  if (addr === undefined && typeof input.address === 'string') addr = resolveFunction(p, input.address)?.addr;
  addr = need(addr, `bad address: ${input.address}`);
  if (!p.mem.isMapped(addr)) throw new Error(`address ${hx(addr)} is not mapped`);
  const count = clampInt(input.count, 32, 1, 2000);
  const insns = p.decodeAt(addr, count, input.thumb);
  const f = p.functionContaining(addr);
  const af = f ? p.analyze(f.addr) : undefined;
  return {
    address: hx(addr), fileOffset: p.mem.toOffset(addr) >= 0 ? p.mem.toOffset(addr) + p.img.fileOffset : undefined,
    section: p.mem.sectionName(addr), function: f ? { name: f.name, addr: hx(f.addr) } : undefined,
    instructions: insns.map((i) => insnJson(p, af, i)),
  };
}
