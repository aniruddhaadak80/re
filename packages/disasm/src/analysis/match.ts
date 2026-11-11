// Function fingerprints and cross binary function matching (two versions of a program, or a
// stripped and an unstripped build). Fingerprints ignore addresses: instructions are normalized
// (addresses and branch targets replaced, small immediates and registers kept), and each function
// also carries its CFG shape, referenced strings, called imports, distinctive constants and its
// position in the call graph. Matching runs in phases from the most to the least certain, each
// with a confidence, and propagates through the call graph and address order from anchors.
import type { AnalyzedFunction, Insn } from '../types.js';
import type { Program } from './program.js';
import { Budget, splitOperands } from '../util.js';

export interface Fingerprint {
  addr: number;
  name: string;
  named: boolean;
  insns: number;
  blocks: number;
  edges: number;
  loops: number;
  /** normalized instructions (mnemonic + operand classes) */
  exact: string;
  /** mnemonic sequence only */
  loose: string;
  /** CFG shape: block size buckets and out degrees */
  shape: string;
  mnemonics: Map<string, number>;
  strings: string[];
  imports: string[];
  consts: number[];
  /** internal callees in call order (addresses in this binary) */
  callees: number[];
  callers: number[];
}

function fnv(s: string): string {
  let h1 = 0x811c9dc5, h2 = 0x01000193 ^ s.length;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 16777619);
    h2 = Math.imul(h2 ^ c, 2246822507) ^ (h2 >>> 13);
  }
  return (h1 >>> 0).toString(36) + (h2 >>> 0).toString(36);
}

const HEX = /0x[0-9a-f]+/g;

function normInsn(p: Program, ins: Insn): string {
  const m = ins.mnemonic;
  if (ins.flow === 'call' || ins.flow === 'jump' || ins.flow === 'cjump') {
    if (ins.target !== undefined) {
      const imp = p.importByStub.get(ins.target);
      return m + ' ' + (imp ? 'I:' + imp.name : ins.flow === 'cjump' || ins.flow === 'jump' ? 'L' : 'F');
    }
  }
  if (ins.viaMemory && ins.memAddr !== undefined) { const imp = p.importBySlot.get(ins.memAddr); if (imp) return m + ' I:' + imp.name; }
  const ops = splitOperands(ins.operands).map((o) => o.replace(HEX, (h) => (parseInt(h.slice(2), 16) >= 0x1000 ? 'A' : h)).replace(/#-?\d{5,}/g, '#A'));
  return m + ' ' + ops.join(',');
}

/** Fingerprint of one analyzed function. */
export function fingerprint(p: Program, af: AnalyzedFunction): Fingerprint {
  const exact: string[] = [];
  const loose: string[] = [];
  const mnemonics = new Map<string, number>();
  const blocks = [...af.blocks].sort((a, b) => a.start - b.start);
  for (const b of blocks) for (const i of b.insns) {
    if (i.mnemonic === 'nop' || i.mnemonic.startsWith('nop') || i.mnemonic === 'int3') continue;
    exact.push(normInsn(p, i));
    loose.push(i.mnemonic);
    mnemonics.set(i.mnemonic, (mnemonics.get(i.mnemonic) ?? 0) + 1);
  }
  const shapeParts = blocks.map((b) => `${Math.min(8, Math.ceil(Math.log2(b.insns.length + 1)))}.${b.succ.length}`).sort();
  const imports = new Set<string>();
  const callees: number[] = [];
  for (const c of af.calls) {
    if (c.target !== undefined) {
      const imp = p.importByStub.get(c.target);
      if (imp) imports.add(imp.name);
      else if (c.target !== af.addr) callees.push(c.target);
    } else if (c.name) imports.add(c.name);
  }
  for (const d of af.dataRefs) if (d.kind === 'import-slot' && d.value) imports.add(d.value);
  const strings = [...new Set(af.dataRefs.filter((d) => d.kind === 'string' && d.value).map((d) => d.value!.slice(0, 200)))].sort();
  const consts = [...new Set(af.constants.filter((c) => Math.abs(c) >= 0x100 && !p.mem.isMapped(c)))].sort((a, b) => a - b);
  const edges = af.blocks.reduce((n, b) => n + b.succ.length, 0);
  const loops = af.blocks.reduce((n, b) => n + b.succ.filter((e) => e.to <= b.start).length, 0);
  return {
    addr: af.addr, name: af.name, named: !/^sub_[0-9a-f]+$/.test(af.name) && af.source !== 'call' && af.source !== 'prologue' && af.source !== 'eh-frame',
    insns: af.insnCount, blocks: af.blocks.length, edges, loops,
    exact: fnv(exact.join(';')), loose: fnv(loose.join(';')), shape: fnv(shapeParts.join(',')),
    mnemonics, strings, imports: [...imports].sort(), consts, callees, callers: [],
  };
}

export interface FingerprintSet {
  fps: Map<number, Fingerprint>;
  complete: boolean;
  analyzed: number;
}

/** Fingerprint every discovered function (bounded by a time budget). Analyses are not kept, so memory stays flat. */
export function fingerprintAll(p: Program, budgetMs: number): FingerprintSet {
  p.discover();
  const budget = new Budget(budgetMs);
  const fps = new Map<number, Fingerprint>();
  let complete = true;
  let analyzed = 0;
  for (const a of p.sortedFunctionAddrs()) {
    const f = p.functions.get(a)!;
    if (f.isImportStub) continue;
    if (budget.expired) { complete = false; break; }
    const af = p.analyzeTransient(a);
    analyzed++;
    if (!af || af.insnCount === 0) continue;
    fps.set(a, fingerprint(p, af));
  }
  for (const fp of fps.values()) for (const c of fp.callees) { const t = fps.get(c); if (t && t.callers.length < 64 && !t.callers.includes(fp.addr)) t.callers.push(fp.addr); }
  return { fps, complete, analyzed };
}

export interface FunctionMatch {
  a: number;
  b: number;
  confidence: number;
  method: 'name' | 'exact' | 'strings' | 'imports-constants' | 'shape' | 'callgraph' | 'neighbor' | 'similarity';
  similarity: number;
}

function jaccard<T>(x: T[], y: T[]): number {
  if (!x.length && !y.length) return 1;
  const s = new Set(x);
  let inter = 0;
  for (const v of new Set(y)) if (s.has(v)) inter++;
  return inter / (s.size + new Set(y).size - inter);
}

function cosine(x: Map<string, number>, y: Map<string, number>): number {
  let dot = 0, nx = 0, ny = 0;
  for (const [k, v] of x) { nx += v * v; const w = y.get(k); if (w) dot += v * w; }
  for (const v of y.values()) ny += v * v;
  return nx && ny ? dot / Math.sqrt(nx * ny) : nx === ny ? 1 : 0;
}

/** 0..1 similarity of two fingerprints from instructions, CFG, strings, imports and constants. */
export function similarity(a: Fingerprint, b: Fingerprint): number {
  if (a.exact === b.exact) return 1;
  const size = 1 - Math.abs(a.insns - b.insns) / Math.max(a.insns, b.insns, 1);
  const cfg = 1 - (Math.abs(a.blocks - b.blocks) + Math.abs(a.edges - b.edges)) / Math.max(a.blocks + a.edges + b.blocks + b.edges, 1);
  const mn = cosine(a.mnemonics, b.mnemonics);
  const parts: [number, number][] = [[mn, 3], [size, 2], [cfg, 2], [a.shape === b.shape ? 1 : 0, 1], [a.loose === b.loose ? 1 : 0, 1]];
  if (a.strings.length || b.strings.length) parts.push([jaccard(a.strings, b.strings), 3]);
  if (a.imports.length || b.imports.length) parts.push([jaccard(a.imports, b.imports), 2]);
  if (a.consts.length || b.consts.length) parts.push([jaccard(a.consts, b.consts), 2]);
  if (a.callees.length || b.callees.length) parts.push([1 - Math.abs(a.callees.length - b.callees.length) / Math.max(a.callees.length, b.callees.length, 1), 1]);
  let num = 0, den = 0;
  for (const [v, w] of parts) { num += v * w; den += w; }
  return num / den;
}

export interface MatchOptions {
  /** match equal symbol names first (default true); set false to evaluate fingerprints alone */
  useNames?: boolean;
  /** minimum similarity for the last, fuzzy phase (default 0.75) */
  minSimilarity?: number;
  budgetMs?: number;
}

/** Match functions between two fingerprint sets. */
export function matchFunctions(A: FingerprintSet, B: FingerprintSet, opts: MatchOptions = {}): FunctionMatch[] {
  const useNames = opts.useNames ?? true;
  const minSim = opts.minSimilarity ?? 0.75;
  const budget = new Budget(opts.budgetMs ?? 20000);
  const out = new Map<number, FunctionMatch>();
  const usedB = new Set<number>();
  const fa = A.fps, fb = B.fps;
  const add = (a: number, b: number, method: FunctionMatch['method'], confidence: number) => {
    if (out.has(a) || usedB.has(b)) return false;
    const sim = similarity(fa.get(a)!, fb.get(b)!);
    out.set(a, { a, b, confidence: Math.round(confidence * 1000) / 1000, method, similarity: Math.round(sim * 1000) / 1000 });
    usedB.add(b);
    return true;
  };
  const unique = (key: (f: Fingerprint) => string | undefined, method: FunctionMatch['method'], conf: number, minInsns = 0) => {
    const ia = new Map<string, number[]>(), ib = new Map<string, number[]>();
    for (const f of fa.values()) { if (out.has(f.addr) || f.insns < minInsns) continue; const k = key(f); if (k) { const l = ia.get(k); if (l) l.push(f.addr); else ia.set(k, [f.addr]); } }
    for (const f of fb.values()) { if (usedB.has(f.addr) || f.insns < minInsns) continue; const k = key(f); if (k) { const l = ib.get(k); if (l) l.push(f.addr); else ib.set(k, [f.addr]); } }
    let n = 0;
    for (const [k, la] of ia) { const lb = ib.get(k); if (la.length === 1 && lb?.length === 1 && add(la[0]!, lb[0]!, method, conf)) n++; }
    return n;
  };
  if (useNames) unique((f) => (f.named ? 'n:' + f.name : undefined), 'name', 1);
  // exact instructions: unique pairs, and among small duplicates only when the strings/imports also agree
  unique((f) => (f.insns >= 4 ? 'e:' + f.exact : undefined), 'exact', 0.99);
  unique((f) => (f.strings.length ? 's:' + f.strings.join('\u0000') + '|' + f.imports.join(',') : undefined), 'strings', 0.95);
  unique((f) => (f.consts.length >= 2 || (f.consts.length && f.imports.length) ? 'c:' + f.consts.join(',') + '|' + f.imports.join(',') : undefined), 'imports-constants', 0.9, 8);
  unique((f) => (f.insns >= 12 ? 'l:' + f.loose + '|' + f.shape : undefined), 'shape', 0.85);
  unique((f) => (f.insns >= 4 ? 'e2:' + f.exact + '|' + f.strings.join('\u0000') + '|' + f.imports.join(',') + '|' + f.callees.length : undefined), 'exact', 0.9);

  // propagation: callees at the same call position, callers, and address order neighbors
  const sortedA = [...fa.keys()].sort((x, y) => x - y);
  const sortedB = [...fb.keys()].sort((x, y) => x - y);
  const posA = new Map(sortedA.map((a, i) => [a, i] as const));
  const posB = new Map(sortedB.map((b, i) => [b, i] as const));
  const close = (a: number, b: number, floor: number) => {
    const x = fa.get(a), y = fb.get(b);
    if (!x || !y || out.has(a) || usedB.has(b)) return 0;
    const s = similarity(x, y);
    return s >= floor ? s : 0;
  };
  for (let round = 0; round < 12 && !budget.expired; round++) {
    let changed = 0;
    for (const m of [...out.values()]) {
      const x = fa.get(m.a)!, y = fb.get(m.b)!;
      // callees in call order: pair the k-th distinct callee on each side
      const ca = [...new Set(x.callees)], cb = [...new Set(y.callees)];
      if (ca.length === cb.length) for (let k = 0; k < ca.length; k++) { const s = close(ca[k]!, cb[k]!, 0.6); if (s && add(ca[k]!, cb[k]!, 'callgraph', Math.min(0.9, 0.55 + 0.35 * s))) changed++; }
      else {
        // different call counts: best similar unmatched callee for each
        for (const a of ca) {
          let best = 0, bb = -1, second = 0;
          for (const b of cb) { const s = close(a, b, 0.7); if (s > best) { second = best; best = s; bb = b; } else if (s > second) second = s; }
          if (bb >= 0 && best - second >= 0.08 && add(a, bb, 'callgraph', Math.min(0.85, 0.5 + 0.35 * best))) changed++;
        }
      }
      if (x.callers.length === 1 && y.callers.length === 1) { const s = close(x.callers[0]!, y.callers[0]!, 0.6); if (s && add(x.callers[0]!, y.callers[0]!, 'callgraph', Math.min(0.85, 0.5 + 0.35 * s))) changed++; }
    }
    // neighbors: the function right after (and before) a matched pair, in address order
    for (const m of [...out.values()]) {
      const ia = posA.get(m.a)!, ib = posB.get(m.b)!;
      for (const d of [1, -1]) {
        const a = sortedA[ia + d], b = sortedB[ib + d];
        if (a === undefined || b === undefined) continue;
        const s = close(a, b, 0.7);
        if (s && add(a, b, 'neighbor', Math.min(0.85, 0.45 + 0.4 * s))) changed++;
      }
    }
    if (!changed) break;
  }

  // last: best similarity among unmatched functions of similar size, with a clear margin
  if (!budget.expired) {
    const restB = [...fb.values()].filter((f) => !usedB.has(f.addr)).sort((x, y) => x.insns - y.insns);
    const restA = [...fa.values()].filter((f) => !out.has(f.addr) && f.insns >= 6);
    const lowerBound = (n: number) => { let lo = 0, hi = restB.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (restB[mid]!.insns < n) lo = mid + 1; else hi = mid; } return lo; };
    for (const x of restA) {
      if (budget.expired) break;
      let best = 0, second = 0, bb: Fingerprint | undefined;
      const lo = lowerBound(Math.floor(x.insns * 0.75));
      for (let k = lo; k < restB.length && restB[k]!.insns <= Math.ceil(x.insns * 1.33) + 2; k++) {
        const y = restB[k]!;
        if (usedB.has(y.addr)) continue;
        const s = similarity(x, y);
        if (s > best) { second = best; best = s; bb = y; } else if (s > second) second = s;
      }
      if (bb && best >= minSim && best - second >= 0.05) add(x.addr, bb.addr, 'similarity', Math.min(0.8, best * 0.8));
    }
  }
  return [...out.values()].sort((x, y) => x.a - y.a);
}
