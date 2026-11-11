// Native value flow. A forward abstract interpreter over one function's CFG that tracks what each
// register and stack slot holds: constants and addresses, stack addresses relative to the entry
// stack pointer, incoming argument registers, the return value of a call, values loaded from a
// fixed or stack address, or small sets of constants where paths merge. It answers:
//   - which value reaches argument N of the call at X (with the instructions that produced it)
//   - where a value (a string address, a constant, an incoming argument) flows: call arguments,
//     stores, returns
//   - which stack slots the function uses (locals, stack arguments) and which argument registers
//     it reads before writing (its parameters)
// It is bounded (instructions, iterations, set sizes) and never executes code.
import type { AnalyzedFunction, Arch, BasicBlock, Insn } from '../types.js';
import { canon, callClobbered, regWidth } from './regs.js';
import { parseImm, splitOperands } from '../util.js';

export type Val =
  | { t: 'const'; v: number }
  | { t: 'stack'; off: number }
  | { t: 'entry'; r: string }
  | { t: 'ret'; at: number }
  | { t: 'load'; addr: Val; w: number }
  /** an unknown base (argument, loaded value, call result) plus a constant offset */
  | { t: 'sum'; base: Val; k: number }
  | { t: 'phi'; vals: Val[] }
  | { t: 'top' };

const TOP: Val = { t: 'top' };
const MAX_PHI = 4;

export function valKey(v: Val): string {
  switch (v.t) {
    case 'const': return 'c' + v.v;
    case 'stack': return 's' + v.off;
    case 'entry': return 'e' + v.r;
    case 'ret': return 'r' + v.at;
    case 'load': return 'l' + v.w + '(' + valKey(v.addr) + ')';
    case 'sum': return '(' + valKey(v.base) + ')+' + v.k;
    case 'phi': return 'p[' + v.vals.map(valKey).sort().join(',') + ']';
    case 'top': return 'T';
  }
}

function join(a: Val, b: Val): Val {
  if (a.t === 'top' || b.t === 'top') return TOP;
  if (valKey(a) === valKey(b)) return a;
  const vals = new Map<string, Val>();
  for (const x of [a, b]) for (const y of x.t === 'phi' ? x.vals : [x]) vals.set(valKey(y), y);
  if (vals.size > MAX_PHI) return TOP;
  return { t: 'phi', vals: [...vals.values()] };
}

function depth(v: Val): number { return v.t === 'load' ? 1 + depth(v.addr) : v.t === 'sum' ? depth(v.base) : v.t === 'phi' ? Math.max(...v.vals.map(depth)) : 0; }

/** abstract machine state at one program point */
class State {
  regs = new Map<string, Val>();
  stack = new Map<number, Val>();
  /** instruction that last wrote each register / stack slot (provenance) */
  rdef = new Map<string, number>();
  sdef = new Map<number, number>();
  clone(): State {
    const s = new State();
    s.regs = new Map(this.regs); s.stack = new Map(this.stack); s.rdef = new Map(this.rdef); s.sdef = new Map(this.sdef);
    return s;
  }
  /** merge o into this; returns true when this changed */
  merge(o: State): boolean {
    let changed = false;
    for (const [k, v] of this.regs) {
      const w = o.regs.get(k) ?? TOP;
      const j = join(v, w);
      if (valKey(j) !== valKey(v)) { this.regs.set(k, j); changed = true; }
      if (o.rdef.get(k) !== this.rdef.get(k) && this.rdef.get(k) !== -1) { this.rdef.set(k, -1); changed = true; }
    }
    for (const [k, v] of this.stack) {
      const w = o.stack.get(k) ?? TOP;
      const j = join(v, w);
      if (valKey(j) !== valKey(v)) { this.stack.set(k, j); changed = true; }
      if (o.sdef.get(k) !== this.sdef.get(k) && this.sdef.get(k) !== -1) { this.sdef.set(k, -1); changed = true; }
    }
    return changed;
  }
}

export interface MemAccess {
  at: number;
  /** resolved address of the access */
  addr: Val;
  write: boolean;
  width: number;
  /** register or value written/read */
  value?: Val;
}

export interface CallFacts {
  at: number;
  /** value of the target operand of an indirect call or jump */
  target?: Val;
  args: Val[];
  argDefs: (number | undefined)[];
  /** x86-32: values on the stack at [esp], [esp+4], ... at the call */
  stackArgs?: Val[];
}

export interface StackVar {
  /** offset from the stack pointer at function entry (negative: locals, positive: stack arguments) */
  off: number;
  name: string;
  width: number;
  reads: number;
  writes: number;
  kind: 'local' | 'stack-arg' | 'saved-reg';
  firstAt: number;
}

export interface FlowResult {
  arch: Arch;
  argRegs: string[];
  /** argument registers read before written: the function's register parameters, in order */
  params: string[];
  calls: Map<number, CallFacts>;
  mem: MemAccess[];
  returns: { at: number; value: Val; def?: number }[];
  stackVars: StackVar[];
  /** per instruction: argument registers that still hold their entry value and are read there */
  argReads: Map<number, string[]>;
  /** per instruction: resolved memory operand (stack slot or fixed address) */
  memAt: Map<number, Val>;
  iterations: number;
  complete: boolean;
}

export interface FlowOptions {
  /** argument registers of the calling convention, in order */
  argRegs: string[];
  retReg: string;
  win64?: boolean;
  /** reads a pointer sized constant from a read only location, when the address is one */
  readConst?: (addr: number, w: number) => number | undefined;
  maxIterations?: number;
}

const SP: Record<string, string> = { x86_64: 'rsp', x86: 'esp', arm64: 'sp', arm: 'sp' };
const FP: Record<string, string> = { x86_64: 'rbp', x86: 'ebp', arm64: 'x29', arm: 'r11' };

/** Run the value tracker over an analyzed function. */
export function analyzeFlow(af: AnalyzedFunction, arch: Arch, opts: FlowOptions): FlowResult {
  const ptr = arch === 'x86_64' || arch === 'arm64' ? 8 : 4;
  const sp = SP[arch] ?? 'sp';
  const clob = callClobbered(arch, opts.win64);
  const blocks = [...af.blocks].sort((a, b) => a.start - b.start);
  const byStart = new Map(blocks.map((b) => [b.start, b] as const));
  const res: FlowResult = {
    arch, argRegs: opts.argRegs, params: [], calls: new Map(), mem: [], returns: [], stackVars: [], argReads: new Map(), memAt: new Map(), iterations: 0, complete: true,
  };
  if (!blocks.length || (arch !== 'x86_64' && arch !== 'x86' && arch !== 'arm64' && arch !== 'arm')) { res.complete = false; return res; }

  const entry = new State();
  entry.regs.set(sp, { t: 'stack', off: 0 });
  const allRegs = arch === 'x86_64' ? ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    : arch === 'x86' ? ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
      : arch === 'arm64' ? Array.from({ length: 31 }, (_, i) => 'x' + i)
        : ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'lr'];
  for (const r of allRegs) { entry.regs.set(r, { t: 'entry', r }); entry.rdef.set(r, -2); }

  const inStates = new Map<number, State>();
  const entryBlock = byStart.get(af.addr) ?? blocks[0]!;
  inStates.set(entryBlock.start, entry);
  const work: number[] = [entryBlock.start];
  const queued = new Set(work);
  const maxIter = opts.maxIterations ?? Math.max(2000, blocks.length * 12);
  const tracker = new Tracker(arch, ptr, sp, clob, opts);
  while (work.length) {
    if (++res.iterations > maxIter) { res.complete = false; break; }
    const s0 = work.shift()!;
    queued.delete(s0);
    const b = byStart.get(s0)!;
    const st = inStates.get(s0)!.clone();
    tracker.runBlock(b, st, undefined);
    for (const e of b.succ) {
      const cur = inStates.get(e.to);
      if (!cur) { inStates.set(e.to, st.clone()); if (!queued.has(e.to)) { work.push(e.to); queued.add(e.to); } }
      else if (cur.merge(st) && !queued.has(e.to)) { work.push(e.to); queued.add(e.to); }
    }
  }
  // final pass: collect facts per instruction from the fixpoint states
  for (const b of blocks) {
    const s = inStates.get(b.start);
    if (!s) continue;
    tracker.runBlock(b, s.clone(), res);
  }
  // parameters: argument registers read while still holding their entry value
  const read = new Set<string>();
  for (const l of res.argReads.values()) for (const r of l) read.add(r);
  let last = -1;
  opts.argRegs.forEach((r, i) => { if (read.has(r)) last = i; });
  res.params = opts.argRegs.slice(0, last + 1);
  res.stackVars = stackVars(res, arch, ptr, af);
  return res;
}

function stackVars(res: FlowResult, arch: Arch, ptr: number, af: AnalyzedFunction): StackVar[] {
  const slots = new Map<number, StackVar>();
  const saved = new Set<number>();
  // callee saved register spills in the entry block (push rbx / stp x29, x30 / str x19)
  for (const m of res.mem) if (m.write && m.addr.t === 'stack' && m.value?.t === 'entry' && !res.argRegs.includes(m.value.r)) saved.add(m.addr.off);
  for (const m of res.mem) {
    if (m.addr.t !== 'stack') continue;
    const off = m.addr.off;
    // the return address slot on x86
    if ((arch === 'x86_64' || arch === 'x86') && off === 0) continue;
    let v = slots.get(off);
    if (!v) {
      const positive = off > 0;
      const kind: StackVar['kind'] = saved.has(off) ? 'saved-reg' : positive ? 'stack-arg' : 'local';
      // names follow Ghidra's convention: offsets from the stack pointer at function entry
      const name = kind === 'stack-arg' ? 'stack_arg_' + off.toString(16) : kind === 'saved-reg' ? 'saved_' + (-off).toString(16) : 'local_' + (-off).toString(16);
      v = { off, name, width: m.width, reads: 0, writes: 0, kind, firstAt: m.at };
      slots.set(off, v);
    }
    if (m.write) v.writes++; else v.reads++;
    v.width = Math.max(v.width, m.width);
    if (m.at < v.firstAt) v.firstAt = m.at;
  }
  void ptr; void af;
  return [...slots.values()].sort((a, b) => a.off - b.off);
}

class Tracker {
  constructor(private arch: Arch, private ptr: number, private sp: string, private clob: Set<string>, private opts: FlowOptions) {}

  private get(st: State, r: string): Val {
    if (r === 'zr') return { t: 'const', v: 0 };
    return st.regs.get(r) ?? TOP;
  }

  private set(st: State, r: string, v: Val, at: number): void {
    if (r === 'zr') return;
    st.regs.set(r, depth(v) > 3 ? TOP : v);
    st.rdef.set(r, at);
  }

  private add(v: Val, k: number): Val {
    if (v.t === 'const') return { t: 'const', v: this.ptr === 4 ? (v.v + k) >>> 0 : v.v + k };
    if (v.t === 'stack') return { t: 'stack', off: v.off + k };
    if (v.t === 'phi') { const vals = v.vals.map((x) => this.add(x, k)); return vals.some((x) => x.t === 'top') ? TOP : { t: 'phi', vals }; }
    if (v.t === 'sum') return v.k + k === 0 ? v.base : { t: 'sum', base: v.base, k: v.k + k };
    if (v.t === 'entry' || v.t === 'load' || v.t === 'ret') return k === 0 ? v : { t: 'sum', base: v, k };
    return TOP;
  }

  /** value loaded from addr: stack slots read the tracked slot, read only constants are folded */
  private load(st: State, addr: Val, w: number): Val {
    if (addr.t === 'stack') {
      const v = st.stack.get(addr.off);
      if (v) return v;
      return { t: 'load', addr, w };
    }
    if (addr.t === 'const' && this.opts.readConst) {
      const c = this.opts.readConst(addr.v, w);
      if (c !== undefined) return { t: 'const', v: c };
    }
    if (addr.t === 'top') return TOP;
    return { t: 'load', addr, w };
  }

  private store(st: State, addr: Val, v: Val, at: number): void {
    if (addr.t === 'stack') { st.stack.set(addr.off, v); st.sdef.set(addr.off, at); }
    else if (addr.t === 'top' || addr.t === 'entry' || addr.t === 'load' || addr.t === 'ret') {
      // a store through an unknown pointer may alias stack slots whose address escaped: keep it simple and trust slots
    }
  }

  /** resolves an x86 or ARM memory operand to an address value */
  private memAddr(st: State, op: string, ins: Insn): { addr: Val; base?: string; post?: number; pre?: boolean } | undefined {
    const b = op.indexOf('[');
    if (b < 0) return undefined;
    const close = op.lastIndexOf(']');
    const inner = op.slice(b + 1, close);
    const arch = this.arch;
    if (arch === 'x86_64' || arch === 'x86') {
      if (/^[a-z]s:/.test(op.slice(b - 3, b)) || op.includes('fs:') || op.includes('gs:')) return { addr: TOP };
      if (ins.memAddr !== undefined && !/[a-z]/.test(inner.replace(/0x[0-9a-f]+/g, ''))) return { addr: { t: 'const', v: ins.memAddr } };
      const terms = inner.replace(/\s+/g, '').replace(/-/g, '+-').split('+').filter(Boolean);
      let acc: Val = { t: 'const', v: 0 };
      let haveReg = false;
      for (const t of terms) {
        if (/\*/.test(t)) {
          const [r, s] = t.split('*');
          const v = this.get(st, canon(arch, r!) ?? '');
          if (v.t !== 'const') return { addr: TOP };
          acc = this.addVals(acc, { t: 'const', v: v.v * Number(s) });
          continue;
        }
        const imm = parseImm(t);
        if (imm !== undefined) { acc = this.add(acc, imm); continue; }
        if (t === 'rip') { acc = this.add(acc, ins.address + ins.size); continue; }
        const c = canon(arch, t);
        if (!c) return { addr: TOP };
        acc = haveReg ? this.addVals(acc, this.get(st, c)) : this.addVals(this.get(st, c), acc);
        haveReg = true;
      }
      return { addr: acc };
    }
    // ARM: [base], [base, #imm], [base, #imm]!, [base, reg{, ext}], then ", #post" outside the brackets
    const parts = inner.split(',').map((s) => s.trim());
    const base = canon(arch, parts[0] ?? '');
    if (!base && parts[0] !== 'pc') return { addr: TOP };
    let bv: Val = parts[0] === 'pc' ? { t: 'const', v: ((ins.address + (ins.thumb ? 4 : 8)) & ~3) >>> 0 } : this.get(st, base!);
    let disp = 0;
    if (parts[1] !== undefined) {
      const imm = parseImm(parts[1]);
      if (imm !== undefined) disp = imm;
      else {
        const ir = canon(arch, parts[1]);
        const iv = ir ? this.get(st, ir) : TOP;
        if (iv.t !== 'const') return { addr: TOP, base: base ?? undefined };
        const sh = parts[2] ? Number(/#(\d+)/.exec(parts[2])?.[1] ?? 0) : 0;
        disp = iv.v * 2 ** sh;
      }
    }
    const pre = op.slice(close + 1).trim().startsWith('!');
    const after = op.slice(close + 1).replace(/^!/, '').trim();
    const post = after.startsWith(',') ? parseImm(after.slice(1).trim()) : undefined;
    if (ins.memAddr !== undefined && bv.t !== 'stack' && bv.t !== 'const') bv = { t: 'const', v: ins.memAddr - disp };
    return { addr: post !== undefined ? bv : this.add(bv, disp), base: base ?? undefined, post, pre };
  }

  private addVals(a: Val, b: Val): Val {
    if (a.t === 'const' && b.t === 'const') return { t: 'const', v: a.v + b.v };
    if (a.t === 'stack' && b.t === 'const') return { t: 'stack', off: a.off + b.v };
    if (b.t === 'stack' && a.t === 'const') return { t: 'stack', off: b.off + a.v };
    if (b.t === 'const') return this.add(a, b.v);
    if (a.t === 'const') return this.add(b, a.v);
    return TOP;
  }

  private noteReads(ins: Insn, st: State, ops: string[], res: FlowResult | undefined, skipFirst: boolean): void {
    if (!res) return;
    const out: string[] = [];
    const text = skipFirst ? ops.slice(1).join(',') : ops.join(',');
    for (const r of this.opts.argRegs) {
      const v = st.regs.get(r);
      if (!v || v.t !== 'entry' || v.r !== r) continue;
      const names = this.arch === 'x86_64' ? aliases64(r) : this.arch === 'arm64' ? ['x' + r.slice(1), 'w' + r.slice(1)] : [r];
      if (names.some((n) => new RegExp('(^|[^a-z0-9])' + n + '($|[^a-z0-9])').test(text))) out.push(r);
    }
    if (out.length) res.argReads.set(ins.address, out);
  }

  /** the value an indirect branch goes to: a register value, or a load through a memory operand */
  private operandTarget(ins: Insn, ops: string[], st: State, rec: (a: Val) => void): Val | undefined {
    const op = ops[ops.length - 1] ?? '';
    if (op.includes('[')) {
      const a = this.memAddr(st, op, ins);
      if (!a) return undefined;
      rec(a.addr);
      if (a.addr.t === 'const' && this.opts.readConst) { const c = this.opts.readConst(a.addr.v, this.ptr); if (c !== undefined) return { t: 'const', v: c }; }
      return a.addr.t === 'top' ? TOP : { t: 'load', addr: a.addr, w: this.ptr };
    }
    const r = canon(this.arch, op);
    return r ? this.get(st, r) : undefined;
  }

  runBlock(b: BasicBlock, st: State, res: FlowResult | undefined): void {
    for (const ins of b.insns) this.step(ins, st, res);
  }

  private step(ins: Insn, st: State, res: FlowResult | undefined): void {
    const arch = this.arch;
    const m0 = ins.mnemonic.replace(/\.[wn]$/, '');
    const m = m0.split(' ').pop()!;
    const ops = splitOperands(ins.operands);
    const at = ins.address;
    const recordMem = (addr: Val, write: boolean, width: number, value?: Val) => {
      if (!res) return;
      if (addr.t === 'stack' || addr.t === 'const') res.memAt.set(at, addr);
      if (res.mem.length < 20000) res.mem.push({ at, addr, write, width, value });
    };
    // reads of argument registers (parameter detection)
    // the first operand is only written (not read) by moves, loads and address computations on x86, and by
    // every ARM data processing instruction except stores, compares and movk
    const writesFirst = arch === 'x86_64' || arch === 'x86'
      ? /^(mov|movabs|movzx|movsx|movsxd|movq|movd|movss|movsd|movaps|movups|movdqa|movdqu|lea|pop|set\w+)$/.test(m)
      : !/^(cmp|cmn|tst|push|str\w*|stp|stur\w*|stl\w*|cbn?z|tbn?z|blr?|br|ret|movk|movt|bfi|bfxil)$/.test(m);
    this.noteReads(ins, st, ops, res, writesFirst && !(m === 'xor' && ops[0] === ops[1]));
    if (m === 'xor' && ops[0] === ops[1] && res) res.argReads.delete(at);

    if (ins.flow === 'jump' && res) {
      // direct tail call: record the arguments as for a call
      res.calls.set(at, { at, args: this.opts.argRegs.map((r) => this.get(st, r)), argDefs: this.opts.argRegs.map((r) => { const d = st.rdef.get(r); return d === undefined || d < 0 ? undefined : d; }) });
    }
    if (ins.flow === 'ijump' && res) {
      const target = this.operandTarget(ins, ops, st, recordMemFn(res, at));
      if (target) res.calls.set(at, { at, target, args: this.opts.argRegs.map((r) => this.get(st, r)), argDefs: [] });
    }
    if (ins.flow === 'call' || ins.flow === 'icall') {
      if (res) {
        const args = this.opts.argRegs.map((r) => this.get(st, r));
        const argDefs = this.opts.argRegs.map((r) => { const d = st.rdef.get(r); return d === undefined || d < 0 ? undefined : d; });
        const facts: CallFacts = { at, args, argDefs };
        if (ins.flow === 'icall') facts.target = this.operandTarget(ins, ops, st, recordMemFn(res, at));
        if (arch === 'x86') {
          const spv = this.get(st, this.sp);
          if (spv.t === 'stack') facts.stackArgs = [0, 1, 2, 3, 4, 5].map((k) => st.stack.get(spv.off + 4 * k) ?? TOP);
        }
        res.calls.set(at, facts);
      }
      for (const r of this.clob) { st.regs.set(r, TOP); st.rdef.set(r, at); }
      this.set(st, this.opts.retReg, { t: 'ret', at }, at);
      if (arch === 'arm64' || arch === 'arm') st.regs.set(arch === 'arm64' ? 'x30' : 'lr', TOP);
      return;
    }
    if (ins.flow === 'ret') {
      if (res) { const d = st.rdef.get(this.opts.retReg); res.returns.push({ at, value: this.get(st, this.opts.retReg), def: d !== undefined && d >= 0 ? d : undefined }); }
      return;
    }
    if (arch === 'x86_64' || arch === 'x86') this.stepX86(ins, m, ops, st, recordMem, res);
    else this.stepArm(ins, m, ops, st, recordMem);
  }

  private stepX86(ins: Insn, m: string, ops: string[], st: State, recordMem: (a: Val, w: boolean, width: number, v?: Val) => void, res?: FlowResult): void {
    const arch = this.arch;
    const at = ins.address;
    const dst = ops[0] ?? '';
    const dreg = canon(arch, dst);
    const width = (ins.memSize ?? 0) || this.ptr;
    const srcVal = (o: string | undefined): Val => {
      if (o === undefined) return TOP;
      if (o.includes('[')) { const a = this.memAddr(st, o, ins); if (!a) return TOP; recordMem(a.addr, false, width); return this.load(st, a.addr, width); }
      const imm = parseImm(o);
      if (imm !== undefined) return { t: 'const', v: imm };
      const c = canon(arch, o);
      return c ? this.get(st, c) : TOP;
    };
    // every memory operand resolves to an address (stack variable naming in the lifter)
    if (res && m !== 'lea') for (const o of ops) if (o.includes('[')) { const a = this.memAddr(st, o, ins); if (a && (a.addr.t === 'stack' || a.addr.t === 'const')) res.memAt.set(at, a.addr); }
    const narrow = (v: Val, r: string): Val => (regWidth(arch, r) === 4 && arch === 'x86_64' && v.t === 'const' ? { t: 'const', v: v.v >>> 0 } : regWidth(arch, r) < 4 && v.t !== 'const' ? TOP : v);
    const writeDst = (v: Val) => {
      if (dst.includes('[')) { const a = this.memAddr(st, dst, ins); if (a) { recordMem(a.addr, true, width, v); this.store(st, a.addr, v, at); } return; }
      if (dreg) this.set(st, dreg, narrow(v, dst), at);
    };
    switch (m) {
      case 'push': {
        const v = srcVal(dst);
        const spv = this.add(this.get(st, this.sp), -this.ptr);
        this.set(st, this.sp, spv, at);
        recordMem(spv, true, this.ptr, v);
        this.store(st, spv, v, at);
        return;
      }
      case 'pop': {
        const spv = this.get(st, this.sp);
        recordMem(spv, false, this.ptr);
        const v = this.load(st, spv, this.ptr);
        this.set(st, this.sp, this.add(spv, this.ptr), at);
        if (dreg) this.set(st, dreg, v, at);
        return;
      }
      case 'leave': {
        const fp = this.get(st, FP[arch]!);
        recordMem(fp, false, this.ptr);
        this.set(st, FP[arch]!, this.load(st, fp, this.ptr), at);
        this.set(st, this.sp, this.add(fp, this.ptr), at);
        return;
      }
      case 'mov': case 'movabs': case 'movzx': case 'movsx': case 'movsxd': case 'movq': case 'movd': case 'movaps': case 'movups': case 'movdqa': case 'movdqu':
        writeDst(srcVal(ops[1]));
        return;
      case 'lea': {
        const a = this.memAddr(st, ops[1] ?? '', ins);
        if (dreg) this.set(st, dreg, a ? a.addr : TOP, at);
        return;
      }
      case 'xor':
        if (ops[0] === ops[1] && dreg) { this.set(st, dreg, { t: 'const', v: 0 }, at); return; }
        break;
      case 'add': case 'sub': {
        const k = parseImm(ops[1]);
        const cur = dreg ? this.get(st, dreg) : TOP;
        if (k !== undefined && dreg) {
          const kk = regWidth(arch, dst) === 4 && k >= 2 ** 31 ? k - 2 ** 32 : k;
          this.set(st, dreg, narrow(this.add(cur, m === 'add' ? kk : -kk), dst), at);
          return;
        }
        if (dreg && ops[1] && !ops[1].includes('[')) {
          const o = srcVal(ops[1]);
          if (m === 'add') { this.set(st, dreg, this.addVals(cur, o), at); return; }
          if (o.t === 'const') { this.set(st, dreg, this.add(cur, -o.v), at); return; }
        }
        break;
      }
      case 'and': case 'or': case 'shl': case 'shr': case 'sar': case 'imul': {
        const cur = dreg ? this.get(st, dreg) : TOP;
        const k = parseImm(ops[ops.length - 1]);
        if (dreg && cur.t === 'const' && k !== undefined && ops.length === 2) {
          const v = m === 'and' ? Number(BigInt(cur.v) & BigInt(k < 0 ? 2 ** 64 + k : k)) : m === 'or' ? Number(BigInt(cur.v) | BigInt(k)) : m === 'shl' ? cur.v * 2 ** k : m === 'imul' ? cur.v * k : Math.floor(cur.v / 2 ** k);
          this.set(st, dreg, narrow({ t: 'const', v }, dst), at);
          return;
        }
        break;
      }
      case 'cmp': case 'test': case 'nop': case 'endbr64': case 'endbr32': case 'jmp': case 'int3':
        // operand reads only
        if (ops.some((o) => o.includes('['))) { const o = ops.find((x) => x.includes('['))!; const a = this.memAddr(st, o, ins); if (a) recordMem(a.addr, false, width); }
        return;
      case 'xchg': {
        const a = canon(arch, ops[0] ?? ''); const b2 = canon(arch, ops[1] ?? '');
        if (a && b2) { const va = this.get(st, a); this.set(st, a, this.get(st, b2), at); this.set(st, b2, va, at); return; }
        break;
      }
      default:
        if (ins.flow === 'cjump' || ins.flow === 'jump') return;
    }
    // unknown: the destination (register or memory) becomes unknown; other implicit writes too
    for (const o of ops.slice(1)) if (o.includes('[')) { const a = this.memAddr(st, o, ins); if (a) recordMem(a.addr, false, width); }
    if (dst.includes('[')) { const a = this.memAddr(st, dst, ins); if (a) { recordMem(a.addr, true, width, TOP); this.store(st, a.addr, TOP, at); } }
    else if (dreg) this.set(st, dreg, TOP, at);
    if (/^(mul|div|idiv|cdq|cqo|cdqe|cwde|cbw|cwd)$/.test(m) || (m === 'imul' && ops.length === 1)) { this.set(st, arch === 'x86' ? 'eax' : 'rax', TOP, at); this.set(st, arch === 'x86' ? 'edx' : 'rdx', TOP, at); }
    if (/^(rep|movs|stos|lods|scas|cmps)/.test(ins.mnemonic)) for (const r of arch === 'x86' ? ['esi', 'edi', 'ecx'] : ['rsi', 'rdi', 'rcx']) this.set(st, r, TOP, at);
  }

  private stepArm(ins: Insn, m: string, ops: string[], st: State, recordMem: (a: Val, w: boolean, width: number, v?: Val) => void): void {
    const arch = this.arch;
    const at = ins.address;
    const dreg = ops[0] ? canon(arch, ops[0]) : undefined;
    const val = (o: string | undefined): Val => {
      if (o === undefined) return TOP;
      const imm = parseImm(o);
      if (imm !== undefined) return { t: 'const', v: imm };
      const c = canon(arch, o);
      return c ? this.get(st, c) : TOP;
    };
    const w32 = (o: string | undefined, v: Val): Val => (o && /^w/.test(o) && v.t === 'const' ? { t: 'const', v: v.v >>> 0 } : v);
    const memWidth = (r: string | undefined): number => (/^(ldrb|strb|ldrsb|ldurb|sturb)$/.test(m) ? 1 : /^(ldrh|strh|ldrsh|ldurh|sturh)$/.test(m) ? 2 : m === 'ldrsw' ? 4 : r && /^w|^r/.test(r) ? 4 : r && /^[sd]\d/.test(r) ? (r[0] === 's' ? 4 : 8) : r && /^q\d/.test(r) ? 16 : this.ptr);
    const writeback = (a: { base?: string; post?: number; pre?: boolean; addr: Val }, used: Val) => {
      if (!a.base) return;
      if (a.post !== undefined) this.set(st, a.base, this.add(used, a.post), at);
      else if (a.pre) this.set(st, a.base, used, at);
    };
    switch (m) {
      case 'mov': case 'movz': case 'fmov':
        if (dreg) { this.set(st, dreg, w32(ops[0], val(ops[1])), at); return; }
        break;
      case 'movk': {
        const cur = dreg ? this.get(st, dreg) : TOP;
        const imm = parseImm(ops[1]);
        const sh = ops[2] ? Number(/#(\d+)/.exec(ops[2])?.[1] ?? 0) : 0;
        if (dreg && cur.t === 'const' && imm !== undefined) {
          const mask = BigInt(0xffff) << BigInt(sh);
          const v = Number((BigInt(cur.v) & ~mask) | (BigInt(imm) << BigInt(sh)));
          this.set(st, dreg, { t: 'const', v }, at);
          return;
        }
        break;
      }
      case 'movw': if (dreg) { const imm = parseImm(ops[1]); this.set(st, dreg, imm !== undefined ? { t: 'const', v: imm } : TOP, at); return; } break;
      case 'movt': {
        const cur = dreg ? this.get(st, dreg) : TOP;
        const imm = parseImm(ops[1]);
        if (dreg && cur.t === 'const' && imm !== undefined) { this.set(st, dreg, { t: 'const', v: ((imm << 16) | (cur.v & 0xffff)) >>> 0 }, at); return; }
        break;
      }
      case 'adrp': case 'adr': {
        const imm = parseImm(ops[1]);
        if (dreg) { this.set(st, dreg, imm !== undefined ? { t: 'const', v: arch === 'arm' ? (((ins.address + (ins.thumb ? 4 : 8)) & ~3) + imm) >>> 0 : imm } : TOP, at); return; }
        break;
      }
      case 'add': case 'sub': {
        if (!dreg) break;
        const a = val(ops[1]);
        let k = parseImm(ops[2]);
        if (k !== undefined && ops[3]) { const sh = /^lsl #(\d+)$/.exec(ops[3]); if (sh) k *= 2 ** Number(sh[1]); else k = undefined; }
        if (k !== undefined) { this.set(st, dreg, w32(ops[0], this.add(a, m === 'add' ? k : -k)), at); return; }
        if (ops[2] && !ops[3]) { const b2 = val(ops[2]); if (m === 'add') { this.set(st, dreg, this.addVals(a, b2), at); return; } if (b2.t === 'const') { this.set(st, dreg, this.add(a, -b2.v), at); return; } }
        break;
      }
      case 'orr':
        if (dreg && canon(arch, ops[1] ?? '') === 'zr' && ops.length === 3) { this.set(st, dreg, w32(ops[0], val(ops[2])), at); return; }
        break;
      case 'push': {
        // ARM32 push {r4, r5, lr}
        const list = ins.operands.slice(ins.operands.indexOf('{') + 1, ins.operands.indexOf('}')).split(',').map((s) => canon(arch, s.trim())).filter((x): x is string => !!x);
        let spv = this.get(st, this.sp);
        spv = this.add(spv, -4 * list.length);
        list.forEach((r, i) => { const a = this.add(spv, 4 * i); recordMem(a, true, 4, this.get(st, r)); this.store(st, a, this.get(st, r), at); });
        this.set(st, this.sp, spv, at);
        return;
      }
      case 'pop': {
        const list = ins.operands.slice(ins.operands.indexOf('{') + 1, ins.operands.indexOf('}')).split(',').map((s) => canon(arch, s.trim())).filter((x): x is string => !!x);
        const spv = this.get(st, this.sp);
        list.forEach((r, i) => { const a = this.add(spv, 4 * i); recordMem(a, false, 4); if (r !== 'pc') this.set(st, r, this.load(st, a, 4), at); });
        this.set(st, this.sp, this.add(spv, 4 * list.length), at);
        return;
      }
      case 'cmp': case 'cmn': case 'tst': case 'nop': case 'b': case 'bti': case 'paciasp': case 'autiasp': case 'hint':
        return;
      default: break;
    }
    // loads and stores
    if (/^(ldr|ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldur\w*|ldp|ldpsw|ldar\w*|str|strb|strh|stur\w*|stp|stlr\w*)$/.test(m)) {
      const memIdx = ops.findIndex((o) => o.startsWith('['));
      if (memIdx < 0) {
        // literal load: ldr x0, #0x1234
        if (dreg && ins.memAddr !== undefined) { const a: Val = { t: 'const', v: ins.memAddr }; const w = memWidth(ops[0]); recordMem(a, false, w); this.set(st, dreg, this.load(st, a, w), at); return; }
        if (dreg) this.set(st, dreg, TOP, at);
        return;
      }
      const memOp = ops.slice(memIdx).join(', ');
      const a = this.memAddr(st, memOp, ins);
      if (!a) return;
      const used = a.post !== undefined ? a.addr : a.addr;
      const pair = m === 'ldp' || m === 'stp' || m === 'ldpsw';
      const w = memWidth(ops[0]);
      if (m.startsWith('st')) {
        recordMem(used, true, w, val(ops[0]));
        this.store(st, used, val(ops[0]), at);
        if (pair) { const a2 = this.add(used, w); recordMem(a2, true, w, val(ops[1])); this.store(st, a2, val(ops[1]), at); }
      } else {
        recordMem(used, false, w);
        if (dreg) this.set(st, dreg, this.load(st, used, w), at);
        if (pair) { const r2 = canon(arch, ops[1] ?? ''); const a2 = this.add(used, w); recordMem(a2, false, w); if (r2) this.set(st, r2, this.load(st, a2, w), at); }
      }
      writeback(a, a.post !== undefined ? a.addr : a.addr);
      return;
    }
    if (ins.flow === 'cjump' || ins.flow === 'jump' || ins.flow === 'ijump') return;
    if (dreg) this.set(st, dreg, TOP, at);
  }
}

function recordMemFn(res: FlowResult, at: number) {
  return (a: Val) => { if (a.t === 'stack' || a.t === 'const') res.memAt.set(at, a); };
}

function aliases64(r: string): string[] {
  const map: Record<string, string[]> = {
    rdi: ['rdi', 'edi', 'di', 'dil'], rsi: ['rsi', 'esi', 'si', 'sil'], rdx: ['rdx', 'edx', 'dx', 'dl'], rcx: ['rcx', 'ecx', 'cx', 'cl'],
    r8: ['r8', 'r8d', 'r8w', 'r8b'], r9: ['r9', 'r9d', 'r9w', 'r9b'], rax: ['rax', 'eax', 'ax', 'al'], rbx: ['rbx', 'ebx', 'bx', 'bl'],
    r10: ['r10', 'r10d'], r11: ['r11', 'r11d'],
  };
  return map[r] ?? [r];
}
