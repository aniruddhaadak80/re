// Agent tools for cross binary function matching and side by side function comparison.
import type { AnalyzedFunction, Insn } from './types.js';
import type { Program } from './analysis/program.js';
import { fingerprint, fingerprintAll, matchFunctions, similarity, type FingerprintSet, type FunctionMatch } from './analysis/match.js';
import { openProgram, resolveFunction, type BinaryInput } from './api.js';
import { clampInt, hx, splitOperands } from './util.js';

const fpCache = new WeakMap<Program, { set: FingerprintSet; budget: number }>();

function fingerprints(p: Program, budgetMs: number): FingerprintSet {
  const c = fpCache.get(p);
  if (c && (c.set.complete || c.budget >= budgetMs)) return c.set;
  const set = fingerprintAll(p, budgetMs);
  fpCache.set(p, { set, budget: budgetMs });
  return set;
}

/**
 * Map functions of one binary (path) to another (path2): two versions of a program, or a stripped
 * and an unstripped build. Each match has a confidence and the method that found it (equal names,
 * identical normalized instructions, strings, imports and constants, CFG shape, call graph or
 * address order propagation, similarity).
 */
export async function disasmMatchFunctions(input: BinaryInput & {
  path2?: string; bytes2?: Uint8Array | ArrayBuffer; arch2?: string; useNames?: boolean; minConfidence?: number; minSimilarity?: number;
  filter?: string; offset?: number; limit?: number; budgetMs?: number;
}) {
  const a = await openProgram(input);
  const b = await openProgram({ path: input.path2, bytes: input.bytes2, arch: (input.arch2 ?? input.arch) as never });
  const budgetMs = clampInt(input.budgetMs, 60000, 1000, 600000);
  const t0 = Date.now();
  const A = fingerprints(a, budgetMs / 2);
  const B = fingerprints(b, budgetMs / 2);
  const left = Math.max(1000, budgetMs - (Date.now() - t0));
  let matches = matchFunctions(A, B, { useNames: input.useNames, minSimilarity: typeof input.minSimilarity === 'number' ? input.minSimilarity : undefined, budgetMs: left });
  const all = matches.length;
  const byMethod: Record<string, number> = {};
  for (const m of matches) byMethod[m.method] = (byMethod[m.method] ?? 0) + 1;
  const minConf = typeof input.minConfidence === 'number' ? input.minConfidence : 0;
  matches = matches.filter((m) => m.confidence >= minConf);
  const row = (m: FunctionMatch) => {
    const x = A.fps.get(m.a)!, y = B.fps.get(m.b)!;
    return { a: { addr: hx(m.a), name: x.name, insns: x.insns }, b: { addr: hx(m.b), name: y.name, insns: y.insns }, confidence: m.confidence, method: m.method, similarity: m.similarity, identical: x.exact === y.exact };
  };
  let rows = matches.map(row);
  if (input.filter) { const q = String(input.filter).toLowerCase(); rows = rows.filter((r) => r.a.name.toLowerCase().includes(q) || r.b.name.toLowerCase().includes(q)); }
  const off = clampInt(input.offset, 0, 0, 1e9);
  const lim = clampInt(input.limit, 200, 1, 20000);
  const matchedB = new Set(matches.map((m) => m.b));
  return {
    a: { path: input.path, functions: A.fps.size, complete: A.complete },
    b: { path: input.path2, functions: B.fps.size, complete: B.complete },
    useNames: input.useNames ?? true,
    matched: all, identical: matches.filter((m) => A.fps.get(m.a)!.exact === B.fps.get(m.b)!.exact).length,
    changed: matches.filter((m) => A.fps.get(m.a)!.exact !== B.fps.get(m.b)!.exact).length,
    unmatchedA: A.fps.size - all, unmatchedB: B.fps.size - matchedB.size, byMethod, ms: Date.now() - t0,
    total: rows.length, offset: off, hasMore: off + lim < rows.length, matches: rows.slice(off, off + lim),
    onlyInA: [...A.fps.values()].filter((f) => !matches.some((m) => m.a === f.addr)).slice(0, 50).map((f) => ({ addr: hx(f.addr), name: f.name, insns: f.insns })),
    onlyInB: [...B.fps.values()].filter((f) => !matchedB.has(f.addr)).slice(0, 50).map((f) => ({ addr: hx(f.addr), name: f.name, insns: f.insns })),
  };
}

function normLine(p: Program, i: Insn): string {
  if (i.target !== undefined && (i.flow === 'call' || i.flow === 'jump')) { const imp = p.importByStub.get(i.target); return `${i.mnemonic} ${imp ? imp.name : 'F'}`; }
  if (i.flow === 'cjump') return `${i.mnemonic} L`;
  return `${i.mnemonic} ${splitOperands(i.operands).map((o) => o.replace(/0x[0-9a-f]+/g, (h) => (parseInt(h.slice(2), 16) >= 0x1000 ? 'A' : h))).join(', ')}`;
}

/** LCS diff of two line lists (capped), as a list of [op, a index, b index]. */
function diffLines(x: string[], y: string[]): ['=' | '-' | '+', number, number][] {
  const n = Math.min(x.length, 1500), m = Math.min(y.length, 1500);
  const dp = new Uint16Array((n + 1) * (m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i * (m + 1) + j] = x[i] === y[j] ? dp[(i + 1) * (m + 1) + j + 1]! + 1 : Math.max(dp[(i + 1) * (m + 1) + j]!, dp[i * (m + 1) + j + 1]!);
  const out: ['=' | '-' | '+', number, number][] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) { out.push(['=', i, j]); i++; j++; }
    else if (dp[(i + 1) * (m + 1) + j]! >= dp[i * (m + 1) + j + 1]!) { out.push(['-', i, j]); i++; }
    else { out.push(['+', i, j]); j++; }
  }
  while (i < n) out.push(['-', i++, j]);
  while (j < m) out.push(['+', i, j++]);
  return out;
}

function blockHash(p: Program, af: AnalyzedFunction) {
  return [...af.blocks].sort((a, b) => a.start - b.start).map((b) => ({ start: b.start, insns: b.insns.length, succ: b.succ.length, key: b.insns.map((i) => normLine(p, i)).join(';') }));
}

/** Side by side comparison of two functions (in one binary or two): similarity by dimension,
 * matched and changed basic blocks, and a diff of the normalized disassembly. */
export async function disasmCompareFunctions(input: BinaryInput & { function: string | number; path2?: string; bytes2?: Uint8Array | ArrayBuffer; arch2?: string; function2?: string | number; context?: number; limit?: number }) {
  const pa = await openProgram(input);
  const pb = input.path2 || input.bytes2 ? await openProgram({ path: input.path2, bytes: input.bytes2, arch: (input.arch2 ?? input.arch) as never }) : pa;
  const fa = resolveFunction(pa, input.function);
  const fb = resolveFunction(pb, input.function2 ?? input.function);
  if (!fa) throw new Error(`function not found: ${input.function}`);
  if (!fb) throw new Error(`function not found in second binary: ${input.function2 ?? input.function}`);
  const aa = pa.resolveIndirect(fa.addr)!, ab = pb.resolveIndirect(fb.addr)!;
  const xa = fingerprint(pa, aa), xb = fingerprint(pb, ab);
  const la = aa.blocks.slice().sort((a, b) => a.start - b.start).flatMap((b) => b.insns);
  const lb = ab.blocks.slice().sort((a, b) => a.start - b.start).flatMap((b) => b.insns);
  const na = la.map((i) => normLine(pa, i)), nb = lb.map((i) => normLine(pb, i));
  const d = diffLines(na, nb);
  const same = d.filter((x) => x[0] === '=').length;
  const ctx = clampInt(input.context, 2, 0, 20);
  const lim = clampInt(input.limit, 400, 10, 5000);
  // keep changed lines plus context
  const keep = new Set<number>();
  d.forEach((x, k) => { if (x[0] !== '=') for (let q = Math.max(0, k - ctx); q <= Math.min(d.length - 1, k + ctx); q++) keep.add(q); });
  const lines: { op: string; a?: string; b?: string; text: string }[] = [];
  let last = -2;
  for (let k = 0; k < d.length && lines.length < lim; k++) {
    if (!keep.has(k)) continue;
    if (k !== last + 1) lines.push({ op: '@@', text: `@@ a ${hx(la[d[k]![1]]?.address)} b ${hx(lb[d[k]![2]]?.address)} @@` });
    last = k;
    const [op, i, j] = d[k]!;
    if (op === '=') lines.push({ op: ' ', a: hx(la[i]!.address), b: hx(lb[j]!.address), text: `${la[i]!.mnemonic} ${la[i]!.operands}`.trim() });
    else if (op === '-') lines.push({ op: '-', a: hx(la[i]!.address), text: `${la[i]!.mnemonic} ${la[i]!.operands}`.trim() });
    else lines.push({ op: '+', b: hx(lb[j]!.address), text: `${lb[j]!.mnemonic} ${lb[j]!.operands}`.trim() });
  }
  const ba = blockHash(pa, aa), bb = blockHash(pb, ab);
  const bkeys = new Map<string, number[]>();
  bb.forEach((x, k) => { const l = bkeys.get(x.key); if (l) l.push(k); else bkeys.set(x.key, [k]); });
  const blockPairs: { a: string; b?: string; status: 'identical' | 'changed' | 'only-a' }[] = [];
  const usedBk = new Set<number>();
  ba.forEach((x, k) => {
    const cand = (bkeys.get(x.key) ?? []).find((q) => !usedBk.has(q));
    if (cand !== undefined) { usedBk.add(cand); blockPairs.push({ a: hx(x.start), b: hx(bb[cand]!.start), status: 'identical' }); return; }
    const pos = bb[k];
    if (pos && !usedBk.has(k) && pos.succ === x.succ) { usedBk.add(k); blockPairs.push({ a: hx(x.start), b: hx(pos.start), status: 'changed' }); return; }
    blockPairs.push({ a: hx(x.start), status: 'only-a' });
  });
  const onlyB = bb.filter((_, k) => !usedBk.has(k)).map((x) => hx(x.start));
  const dim = (u: string[], v: string[]) => ({ a: u.length, b: v.length, same: u.filter((s) => v.includes(s)).length, onlyA: u.filter((s) => !v.includes(s)).slice(0, 50), onlyB: v.filter((s) => !u.includes(s)).slice(0, 50) });
  // internal callees compare by name only when both sides have names for them
  const named = (p: Program, af: AnalyzedFunction) => af.calls.every((c) => c.target === undefined || p.importByStub.has(c.target) || !/^sub_/.test(p.nameOf(c.target) ?? 'sub_'));
  const useNames = named(pa, aa) && named(pb, ab);
  const calleeNames = (p: Program, af: AnalyzedFunction) => af.calls.map((c) => {
    if (c.target === undefined) return c.name ?? '(indirect)';
    const imp = p.importByStub.get(c.target);
    if (imp) return imp.name;
    return useNames ? p.nameOf(c.target) ?? 'F' : 'F';
  });
  return {
    a: { path: input.path, name: fa.name, addr: hx(fa.addr), insns: xa.insns, blocks: xa.blocks, edges: xa.edges },
    b: { path: input.path2 ?? input.path, name: fb.name, addr: hx(fb.addr), insns: xb.insns, blocks: xb.blocks, edges: xb.edges },
    identical: xa.exact === xb.exact,
    similarity: Math.round(similarity(xa, xb) * 1000) / 1000,
    dimensions: {
      instructions: { a: na.length, b: nb.length, same, ratio: Math.round((2 * same / Math.max(1, na.length + nb.length)) * 1000) / 1000 },
      cfg: { sameShape: xa.shape === xb.shape, blocksA: xa.blocks, blocksB: xb.blocks, edgesA: xa.edges, edgesB: xb.edges, loopsA: xa.loops, loopsB: xb.loops },
      strings: dim(xa.strings, xb.strings),
      calls: dim(calleeNames(pa, aa), calleeNames(pb, ab)),
      constants: dim(xa.consts.map(hx), xb.consts.map(hx)),
    },
    blocks: { identical: blockPairs.filter((x) => x.status === 'identical').length, changed: blockPairs.filter((x) => x.status === 'changed').length, onlyA: blockPairs.filter((x) => x.status === 'only-a').map((x) => x.a), onlyB },
    note: 'instructions are compared after normalizing addresses and branch targets, so relocation alone does not count as a change',
    diff: lines,
  };
}
