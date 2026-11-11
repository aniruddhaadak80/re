// Agent tools on top of the value tracker: value tracing (backward to call arguments, forward from
// strings, constants and parameters) and indirect call target resolution.
import type { AnalyzedFunction, FunctionInfo } from './types.js';
import type { Program } from './analysis/program.js';
import { valKey, type FlowResult, type Val } from './analysis/dataflow.js';
import { stringAt } from './analysis/strings.js';
import { openProgram, resolveFunction, type BinaryInput } from './api.js';
import { Budget, clampInt, hx, parseAddr } from './util.js';

export interface ValueDesc {
  kind: 'constant' | 'string' | 'code' | 'address' | 'stack-address' | 'argument' | 'entry-register' | 'return-value' | 'load' | 'offset' | 'one-of' | 'unknown';
  text: string;
  value?: string;
  addr?: string;
  name?: string;
  index?: number;
  reg?: string;
  offset?: number;
  of?: ValueDesc;
  values?: ValueDesc[];
  callAt?: string;
  callee?: string;
  initial?: ValueDesc;
}

/** Human and machine readable description of an abstract value. */
export function describeVal(p: Program, v: Val, fl?: FlowResult, depthLeft = 3): ValueDesc {
  switch (v.t) {
    case 'const': {
      const a = v.v;
      if (looksLikeAddress(p, a)) {
        if (p.mem.isExec(a)) { const n = p.symbolize(a); return { kind: 'code', text: n ?? hx(a), addr: hx(a), name: n }; }
        const s = stringAt(p.mem, a);
        if (s) return { kind: 'string', text: JSON.stringify(s.value.length > 120 ? s.value.slice(0, 120) + '...' : s.value), value: s.value.slice(0, 400), addr: hx(a) };
        const n = p.symbolize(a);
        return { kind: 'address', text: n ? '&' + n : hx(a), addr: hx(a), name: n };
      }
      return { kind: 'constant', text: Math.abs(a) > 9 ? hx(a) : String(a), value: String(a) };
    }
    case 'stack': {
      const sv = fl?.stackVars.find((x) => x.off === v.off);
      return { kind: 'stack-address', text: '&' + (sv?.name ?? `stack[${v.off}]`), offset: v.off, name: sv?.name };
    }
    case 'entry': {
      const i = fl?.argRegs.indexOf(v.r) ?? -1;
      if (i >= 0) return { kind: 'argument', text: `a${i + 1} (${v.r} at entry)`, index: i, reg: v.r };
      return { kind: 'entry-register', text: `${v.r} at entry`, reg: v.r };
    }
    case 'ret': {
      const t = p.functionContaining(v.at);
      const af = t ? p.analyze(t.addr) : undefined;
      const c = af?.calls.find((x) => x.at === v.at);
      const callee = c?.name ?? (c?.target !== undefined ? p.nameOf(c.target) ?? hx(c.target) : undefined);
      return { kind: 'return-value', text: `return value of ${callee ?? 'call'} at ${hx(v.at)}`, callAt: hx(v.at), callee };
    }
    case 'load': {
      const of = depthLeft > 0 ? describeVal(p, v.addr, fl, depthLeft - 1) : { kind: 'unknown' as const, text: '?' };
      const out: ValueDesc = { kind: 'load', text: `*(${of.text.replace(/^&/, '')})`, of };
      if (v.addr.t === 'const') {
        const init = p.readUint(v.addr.v, v.w);
        if (init !== undefined && depthLeft > 0) out.initial = describeVal(p, { t: 'const', v: init }, fl, 0);
      }
      return out;
    }
    case 'sum': {
      const of = depthLeft > 0 ? describeVal(p, v.base, fl, depthLeft - 1) : { kind: 'unknown' as const, text: '?' };
      return { kind: 'offset', text: `${of.text} ${v.k < 0 ? '-' : '+'} ${hx(Math.abs(v.k))}`, of, offset: v.k };
    }
    case 'phi': {
      const values = v.vals.map((x) => describeVal(p, x, fl, depthLeft - 1));
      return { kind: 'one-of', text: 'one of ' + values.map((x) => x.text).join(', '), values };
    }
    case 'top': return { kind: 'unknown', text: 'unknown' };
  }
}

/** small values in a PIE image fall inside the mapped headers; only treat them as addresses inside a data or code section */
function looksLikeAddress(p: Program, a: number): boolean {
  if (!p.mem.isMapped(a)) return false;
  if (a >= 0x10000) return true;
  const sec = p.img.sections.find((s) => a >= s.vaddr && a < s.vaddr + s.size);
  return !!sec && !/^\.(interp|note|dynsym|dynstr|gnu|hash|rela|rel\b|rel\.)/.test(sec.name);
}

function contains(v: Val, key: string): boolean {
  if (valKey(v) === key) return true;
  if (v.t === 'phi') return v.vals.some((x) => contains(x, key));
  return false;
}

function calleeOf(p: Program, af: AnalyzedFunction, at: number): { name?: string; addr?: number } {
  const c = af.calls.find((x) => x.at === at);
  if (!c) return {};
  if (c.target !== undefined) return { name: c.name ?? p.nameOf(c.target) ?? 'sub_' + c.target.toString(16), addr: c.target };
  if (c.name) return { name: c.name };
  if (c.candidates) return { name: 'one of ' + c.candidates.slice(0, 8).map((t) => p.nameOf(t) ?? hx(t)).join(', ') };
  return { name: '(indirect)' };
}

function fnRef(f: FunctionInfo) { return { name: f.name, addr: hx(f.addr) }; }

interface ArgReport { index: number; reg: string; value: ValueDesc; producedAt?: string; fromCallers?: CallerReport[] }
interface CallerReport { function: string; functionAddr: string; callAt: string; value: ValueDesc; fromCallers?: CallerReport[] }

function callersOf(p: Program, addr: number, budgetMs: number): { func: number; at: number }[] {
  const idx = p.xrefs(budgetMs);
  return (idx.to.get(addr) ?? []).filter((r) => r.kind === 'call' || r.kind === 'jump').map((r) => ({ func: r.func, at: r.from }));
}

function backFromCallers(p: Program, f: FunctionInfo, argIndex: number, depth: number, budget: Budget, budgetMs: number, seen: Set<string>): CallerReport[] | undefined {
  if (depth <= 0 || budget.expired) return undefined;
  const out: CallerReport[] = [];
  for (const c of callersOf(p, f.addr, budgetMs).slice(0, 16)) {
    const key = c.func + ':' + c.at + ':' + argIndex;
    if (seen.has(key)) continue;
    seen.add(key);
    const cf = p.functions.get(c.func);
    const fl = p.flow(c.func);
    const facts = fl?.calls.get(c.at);
    if (!cf || !fl || !facts) continue;
    const v = facts.args[argIndex] ?? { t: 'top' as const };
    const r: CallerReport = { function: cf.name, functionAddr: hx(cf.addr), callAt: hx(c.at), value: describeVal(p, v, fl) };
    if (v.t === 'entry') {
      const k = fl.argRegs.indexOf(v.r);
      if (k >= 0) r.fromCallers = backFromCallers(p, cf, k, depth - 1, budget, budgetMs, seen);
    }
    out.push(r);
  }
  return out;
}

interface Sink {
  kind: 'call-arg' | 'store' | 'stack-store' | 'return' | 'indirect-target';
  at: string;
  function: string;
  functionAddr: string;
  callee?: string;
  calleeAddr?: string;
  argIndex?: number;
  reg?: string;
  to?: ValueDesc;
  into?: { function: string; param: number; sinks: Sink[] };
}

function forwardSinks(p: Program, f: FunctionInfo, key: string, depth: number, budget: Budget, seen: Set<string>, limit: number): Sink[] {
  const out: Sink[] = [];
  const af = p.resolveIndirect(f.addr);
  const fl = p.flow(f.addr);
  if (!af || !fl) return out;
  for (const [at, c] of fl.calls) {
    if (c.target && contains(c.target, key)) out.push({ kind: 'indirect-target', at: hx(at), function: f.name, functionAddr: hx(f.addr) });
    c.args.forEach((v, i) => {
      if (!contains(v, key) || out.length >= limit) return;
      const callee = calleeOf(p, af, at);
      const s: Sink = { kind: 'call-arg', at: hx(at), function: f.name, functionAddr: hx(f.addr), callee: callee.name, calleeAddr: callee.addr !== undefined ? hx(callee.addr) : undefined, argIndex: i, reg: fl.argRegs[i] };
      if (depth > 0 && callee.addr !== undefined && !budget.expired) {
        const cf = p.functions.get(callee.addr);
        const sk = callee.addr + ':' + i;
        if (cf && !cf.isImportStub && !seen.has(sk)) {
          seen.add(sk);
          const cfl = p.flow(cf.addr);
          // only follow when the callee actually reads that register parameter
          if (cfl && i < cfl.params.length) s.into = { function: cf.name, param: i, sinks: forwardSinks(p, cf, valKey({ t: 'entry', r: cfl.argRegs[i]! }), depth - 1, budget, seen, limit) };
        }
      }
      out.push(s);
    });
    if (c.stackArgs) c.stackArgs.forEach((v, i) => {
      if (!contains(v, key) || out.length >= limit) return;
      const callee = calleeOf(p, af, at);
      out.push({ kind: 'call-arg', at: hx(at), function: f.name, functionAddr: hx(f.addr), callee: callee.name, calleeAddr: callee.addr !== undefined ? hx(callee.addr) : undefined, argIndex: i, reg: `[esp+${4 * i}]` });
    });
  }
  for (const m of fl.mem) {
    if (!m.write || !m.value || !contains(m.value, key) || out.length >= limit) continue;
    if (m.addr.t === 'stack') {
      const sv = fl.stackVars.find((x) => x.off === (m.addr as { off: number }).off);
      if (sv?.kind === 'saved-reg') continue;
      out.push({ kind: 'stack-store', at: hx(m.at), function: f.name, functionAddr: hx(f.addr), to: describeVal(p, m.addr, fl) });
    } else out.push({ kind: 'store', at: hx(m.at), function: f.name, functionAddr: hx(f.addr), to: describeVal(p, m.addr, fl) });
  }
  for (const r of fl.returns) if (contains(r.value, key) && out.length < limit) out.push({ kind: 'return', at: hx(r.at), function: f.name, functionAddr: hx(f.addr) });
  out.sort((a, b) => parseInt(a.at, 16) - parseInt(b.at, 16));
  return out;
}

/**
 * Trace values through native code. Backward: what value reaches argument `arg` of the call at
 * `call` (address or callee name) in `function`, following incoming arguments into callers up to
 * `depth`. Forward: where a string (`value` text), a constant/address (`value` number or 0x hex) or
 * the function's own parameter `param` flows: call arguments, stores, returns, into callees.
 */
export async function disasmTraceValues(input: BinaryInput & {
  function?: string | number; call?: string | number; occurrence?: number; arg?: number;
  value?: string | number; param?: number; depth?: number; limit?: number; budgetMs?: number;
}) {
  const p = await openProgram(input);
  const depth = clampInt(input.depth, 1, 0, 3);
  const limit = clampInt(input.limit, 100, 1, 1000);
  const budgetMs = clampInt(input.budgetMs, 8000, 100, 60000);
  const budget = new Budget(budgetMs);
  const abi = p.abi();
  const fn = input.function !== undefined ? resolveFunction(p, input.function) : undefined;
  if (input.function !== undefined && !fn) throw new Error(`function not found: ${input.function}`);

  // ---- backward: arguments of a call ----
  if (input.call !== undefined) {
    if (!fn) throw new Error('pass function with call');
    const af = p.resolveIndirect(fn.addr);
    const fl = p.flow(fn.addr);
    if (!af || !fl) throw new Error(`cannot analyze ${fn.name}`);
    const callAddr = parseAddr(input.call);
    let sites = af.calls.filter((c) => (callAddr !== undefined ? c.at === callAddr : false));
    if (callAddr === undefined) {
      const q = String(input.call).toLowerCase();
      sites = af.calls.filter((c) => {
        const n = (c.name ?? (c.target !== undefined ? p.nameOf(c.target) : undefined) ?? '').toLowerCase();
        return n === q || n.replace(/^_+/, '').replace(/@.*$/, '') === q.replace(/^_+/, '');
      });
      if (input.occurrence !== undefined) sites = sites.slice(clampInt(input.occurrence, 1, 1, 10000) - 1, clampInt(input.occurrence, 1, 1, 10000));
    }
    if (!sites.length) throw new Error(`no call ${input.call} in ${fn.name}`);
    const seen = new Set<string>();
    const calls = sites.slice(0, 50).map((c) => {
      const facts = fl.calls.get(c.at);
      const callee = calleeOf(p, af, c.at);
      // without an explicit arg: the callee's register parameters when it is analyzable, else up to the last known value
      let n = Math.min(6, abi.argRegs.length);
      const cf = callee.addr !== undefined ? p.functions.get(callee.addr) : undefined;
      if (cf && !cf.isImportStub) { const cfl = p.flow(cf.addr); if (cfl) n = cfl.params.length; }
      else if (facts) { while (n > 1 && (facts.args[n - 1]!.t === 'top' || (facts.args[n - 1]!.t === 'entry' && fl.params.indexOf((facts.args[n - 1] as { r: string }).r) < 0))) n--; }
      const idxs = input.arg !== undefined ? [clampInt(input.arg, 0, 0, Math.max(0, abi.argRegs.length - 1))] : abi.argRegs.map((_, i) => i).slice(0, n);
      const args: ArgReport[] = [];
      if (facts) for (const i of idxs) {
        const v = facts.args[i] ?? { t: 'top' as const };
        const d = facts.argDefs[i];
        const a: ArgReport = { index: i, reg: abi.argRegs[i] ?? '?', value: describeVal(p, v, fl), ...(d !== undefined ? { producedAt: hx(d) } : {}) };
        if (v.t === 'entry') { const k = fl.argRegs.indexOf(v.r); if (k >= 0) a.fromCallers = backFromCallers(p, fn, k, depth, budget, budgetMs, seen); }
        args.push(a);
      }
      const stack = facts?.stackArgs ? facts.stackArgs.map((v, i) => ({ index: i, slot: `[esp+${4 * i}]`, value: describeVal(p, v, fl) })).filter((x) => x.value.kind !== 'unknown') : undefined;
      return { at: hx(c.at), callee: callee.name, calleeAddr: callee.addr !== undefined ? hx(callee.addr) : undefined, ...(c.tail ? { tail: true } : {}), args, ...(stack && stack.length ? { stackArgs: stack } : {}) };
    });
    return { mode: 'backward', function: fnRef(fn), abi: abi.name, complete: fl.complete && !budget.expired, calls };
  }

  // ---- forward: where does a value go ----
  const keys: { key: string; desc: ValueDesc; origins?: { at: string; function: string }[] }[] = [];
  const fns: FunctionInfo[] = [];
  if (input.param !== undefined) {
    if (!fn) throw new Error('pass function with param');
    const r = abi.argRegs[clampInt(input.param, 0, 0, abi.argRegs.length - 1)];
    if (!r) throw new Error('no register parameters in this calling convention');
    keys.push({ key: valKey({ t: 'entry', r }), desc: { kind: 'argument', text: `a${Number(input.param) + 1} (${r})`, index: Number(input.param), reg: r } });
    fns.push(fn);
  } else if (input.value !== undefined) {
    const num = typeof input.value === 'number' ? input.value : /^(0x[0-9a-f]+|[0-9]+)$/i.test(String(input.value).trim()) ? parseAddr(String(input.value).trim()) : undefined;
    const idx = p.xrefs(budgetMs);
    if (num !== undefined) {
      keys.push({ key: valKey({ t: 'const', v: num }), desc: describeVal(p, { t: 'const', v: num }) });
      if (fn) fns.push(fn);
      else if (p.mem.isMapped(num)) for (const r of idx.to.get(num) ?? []) { const f = p.functions.get(r.func); if (f && !fns.includes(f)) fns.push(f); }
      else {
        // a plain number: functions that use it as an immediate
        for (const a of p.sortedFunctionAddrs()) {
          if (budget.expired || fns.length >= 200) break;
          const f = p.functions.get(a)!;
          if (f.isImportStub) continue;
          const af = p.analyzeTransient(a);
          if (af && af.blocks.some((b) => b.insns.some((i) => i.imms.includes(num)))) fns.push(f);
        }
      }
    } else {
      const text = String(input.value);
      const hits: number[] = [];
      for (const [addr, list] of idx.to) {
        if (!list.some((r) => r.kind === 'string')) continue;
        const s = stringAt(p.mem, addr, 1);
        if (s && s.value === text) hits.push(addr);
      }
      if (!hits.length) for (const [addr, list] of idx.to) {
        if (!list.some((r) => r.kind === 'string')) continue;
        const s = stringAt(p.mem, addr, 1);
        if (s && s.value.includes(text)) hits.push(addr);
        if (hits.length >= 8) break;
      }
      if (!hits.length) throw new Error(`no referenced string matches ${JSON.stringify(text)}`);
      for (const h of hits.slice(0, 8)) {
        const refs = (idx.to.get(h) ?? []).filter((r) => r.kind === 'string');
        keys.push({ key: valKey({ t: 'const', v: h }), desc: describeVal(p, { t: 'const', v: h }), origins: refs.slice(0, 50).map((r) => ({ at: hx(r.from), function: p.functions.get(r.func)?.name ?? hx(r.func) })) });
        for (const r of refs) { const f = p.functions.get(r.func); if (f && (!fn || f === fn) && !fns.includes(f)) fns.push(f); }
      }
    }
  } else throw new Error('pass call (backward), value or param (forward)');

  const results = keys.map((k) => {
    const seen = new Set<string>();
    const sinks: Sink[] = [];
    for (const f of fns.slice(0, 100)) {
      if (budget.expired || sinks.length >= limit) break;
      sinks.push(...forwardSinks(p, f, k.key, depth, budget, seen, limit - sinks.length));
    }
    return { value: k.desc, ...(k.origins ? { referencedAt: k.origins } : {}), sinks };
  });
  return { mode: 'forward', function: fn ? fnRef(fn) : undefined, abi: abi.name, depth, complete: !budget.expired, functionsSearched: fns.length, results };
}

/** Indirect calls and jumps of a function (or the whole program within a budget) with the targets
 * found by jump table reads, constant propagation, writable pointer initial values and vtables. */
export async function disasmIndirectTargets(input: BinaryInput & { function?: string | number; offset?: number; limit?: number; budgetMs?: number; unresolved?: boolean }) {
  const p = await openProgram(input);
  const budget = new Budget(clampInt(input.budgetMs, 8000, 100, 60000));
  p.discover();
  const list = input.function !== undefined ? [resolveFunction(p, input.function)] : p.sortedFunctionAddrs().map((a) => p.functions.get(a));
  const rows: Record<string, unknown>[] = [];
  let scanned = 0;
  let complete = true;
  for (const f of list) {
    if (!f) { if (input.function !== undefined) throw new Error(`function not found: ${input.function}`); continue; }
    if (f.isImportStub) continue;
    if (budget.expired) { complete = false; break; }
    const af = p.resolveIndirect(f.addr);
    scanned++;
    if (!af) continue;
    for (const c of af.calls) {
      if (!c.indirect) continue;
      if (c.name && c.target === undefined && !c.candidates) continue; // import through a slot: not interesting here
      const resolved = c.target !== undefined || !!c.candidates;
      if (input.unresolved && resolved) continue;
      rows.push({
        at: hx(c.at), function: f.name, functionAddr: hx(f.addr), kind: c.tail ? 'tail-jump' : 'call', resolved, resolvedBy: c.resolvedBy,
        targets: c.target !== undefined ? [{ addr: hx(c.target), name: p.nameOf(c.target) }] : (c.candidates ?? []).slice(0, 64).map((t) => ({ addr: hx(t), name: p.nameOf(t) })),
      });
    }
    for (const s of af.switches ?? []) if (s.kind === 'switch') rows.push({ at: hx(s.at), function: f.name, functionAddr: hx(f.addr), kind: 'switch', resolved: true, resolvedBy: 'table', table: hx(s.table), entries: s.count, bound: s.bound, targets: [...new Set(s.targets)].slice(0, 64).map((t) => ({ addr: hx(t) })) });
    for (const b of af.blocks) {
      if (b.exit !== 'indirect' || rows.length >= 100000) continue;
      const l = b.insns[b.insns.length - 1]!;
      rows.push({ at: hx(l.address), function: f.name, functionAddr: hx(f.addr), kind: 'jump', resolved: false, text: `${l.mnemonic} ${l.operands}` });
    }
  }
  const filtered = input.unresolved ? rows.filter((r) => !r.resolved) : rows;
  filtered.sort((a, b) => parseInt(String(a.at), 16) - parseInt(String(b.at), 16));
  const off = clampInt(input.offset, 0, 0, 1e9);
  const lim = clampInt(input.limit, 200, 1, 5000);
  const resolved = filtered.filter((r) => r.resolved).length;
  return { complete, functionsScanned: scanned, total: filtered.length, resolved, unresolved: filtered.length - resolved, offset: off, hasMore: off + lim < filtered.length, sites: filtered.slice(off, off + lim) };
}
