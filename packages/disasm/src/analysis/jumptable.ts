// Jump table resolution. Walks back from an indirect jump (or call) through its unique predecessor
// chain, builds a small symbolic expression for the target in terms of one index register, finds
// the bounds check (cmp + unsigned conditional branch) that limits the index, then evaluates the
// expression for every index by reading the table from the image.
//
// Covers the common compiler shapes:
//   x86-64 PIC  : lea rcx,[rip+T]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax
//   x86-64 abs  : jmp qword ptr [rax*8+T]  /  lea rcx,[T]; jmp [rcx+rax*8]  (Go, function tables)
//   AArch64     : adrp/adr x9,T; adr x10,L; ldrb|ldrh|ldrsw w11,[x9,x8(,lsl #k)]; add x10,x10,x11,lsl #2; br x10
//   AArch64 gcc : ldrb w0,[x1,w0,uxtw]; adr x1,L; add x0,x1,w0,sxtb #2; br x0
//   AArch64 Go  : ldr x1,[x1,x0,lsl #3]; br x1
//   Thumb-2     : tbb [pc, rN] / tbh [pc, rN, lsl #1]
import type { Arch, Insn, SwitchTable } from '../types.js';
import { canon, writes } from './regs.js';
import { parseImm, splitOperands } from '../util.js';

type Ex =
  | { k: 'c'; v: number }
  | { k: 'r'; r: string }
  | { k: 'add'; a: Ex; b: Ex }
  | { k: 'shl'; a: Ex; n: number }
  | { k: 'ld'; a: Ex; w: number; s: boolean }
  | { k: 'sx'; a: Ex; w: number }
  | { k: 'zx'; a: Ex; w: number };

export interface JumpTableContext {
  arch: Arch;
  bits: 32 | 64;
  /** the unique control flow predecessor of an instruction, when there is exactly one */
  pred(ins: Insn): Insn | undefined;
  /** reads an unsigned little/big endian integer of w bytes */
  read(addr: number, w: number): number | undefined;
  isExec(addr: number): boolean;
  /** true when addr is the entry of a known function or import stub */
  isFunction(addr: number): boolean;
  /** start of the function being analyzed */
  funcStart: number;
  /** true when the address is not writable at run time */
  isReadOnly?(addr: number): boolean;
  /** every instruction in the function (decoded so far) that writes a register, capped at 16 */
  defsOf?(reg: string): Insn[];
}

const MAX_CHAIN = 64;
const MAX_ENTRIES = 1024;
const SCAN_ENTRIES = 512;

interface Step { ins: Insn; viaTaken: boolean }

/** Try to resolve the table behind an indirect jump or call. */
export function resolveJumpTable(ctx: JumpTableContext, jmp: Insn): SwitchTable | undefined {
  const arch = ctx.arch;
  if (arch !== 'x86_64' && arch !== 'x86' && arch !== 'arm64' && arch !== 'arm') return undefined;
  // predecessor chain, newest first
  const chain: Step[] = [{ ins: jmp, viaTaken: false }];
  for (let cur = jmp; chain.length < MAX_CHAIN;) {
    const p = ctx.pred(cur);
    if (!p) break;
    const taken = (p.flow === 'cjump' || p.flow === 'jump') && p.target === cur.address && p.address + p.size !== cur.address;
    chain[chain.length - 1]!.viaTaken = taken;
    chain.push({ ins: p, viaTaken: false });
    cur = p;
  }
  const bound = findBound(arch, chain);
  if (bound && bound.count === 0) return undefined;

  const m = jmp.mnemonic.replace(/\.[wn]$/, '');
  if (arch === 'arm' && (m === 'tbb' || m === 'tbh')) return thumbTable(ctx, jmp, m === 'tbh' ? 2 : 1, bound);

  const ops = splitOperands(jmp.operands);
  const op = ops[ops.length - 1] ?? '';
  let e: Ex | undefined;
  const ptr = ctx.bits / 8;
  const ex = new ExprBuilder(arch, chain, bound?.reg, bound?.pos, ctx.defsOf);
  if (op.includes('[')) {
    const a = ex.addr(op, 1, jmp);
    if (a) e = { k: 'ld', a, w: (jmp.memSize ?? 0) || ptr, s: false };
  } else if (arch === 'arm' && m === 'ldr' && ops[0] === 'pc') {
    const a = ex.addr(ops[1] ?? '', 1, jmp);
    if (a) e = { k: 'ld', a, w: 4, s: false };
  } else {
    const r = canon(arch, op);
    if (r) e = ex.reg(r, 1, 0);
  }
  if (!e || ex.failed) return undefined;
  // exactly one free register (the index) and at least one load from a fixed table
  const leaves = new Set<string>();
  collectLeaves(e, leaves);
  if (leaves.size === 0) {
    // a constant target (lea rax,[f]; jmp rax  or  ldr x16,[slot]; br x16 with a fixed slot)
    const t = evaluate(ctx, e, 0);
    if (t === undefined || !ctx.isExec(t)) return undefined;
    const tt = arch === 'arm' ? t & ~1 : t;
    const ld0 = firstLoad(e);
    const slot = ld0 ? evaluate(ctx, ld0.a, 0) : undefined;
    const out: SwitchTable = { at: jmp.address, table: slot ?? 0, entrySize: ld0?.w ?? 0, count: 1, targets: [tt], bound: 'const', kind: ctx.isFunction(tt) || tt === ctx.funcStart ? 'call-table' : 'switch' };
    // a pointer read from writable data is only its initial value
    const slots: number[] = [];
    allLoads(e, (l) => { const a = evaluate(ctx, l.a, 0); if (a !== undefined) slots.push(a); });
    if (ctx.isReadOnly && slots.some((a) => !ctx.isReadOnly!(a))) { out.initialValue = true; out.kind = 'call-table'; }
    return out;
  }
  if (leaves.size !== 1) return undefined;
  const idxReg = [...leaves][0]!;
  if (bound && idxReg !== bound.reg) return undefined;
  const ld = firstLoad(e);
  if (!ld) return undefined;
  const table = evaluate(ctx, ld.a, 0);
  if (table === undefined || table === 0) return undefined;

  const targets: number[] = [];
  const masked = !bound && ex.maskCount !== undefined;
  const limit = bound ? Math.min(bound.count, MAX_ENTRIES) : masked ? Math.min(ex.maskCount!, MAX_ENTRIES) : SCAN_ENTRIES;
  for (let i = 0; i < limit; i++) {
    const t = evaluate(ctx, e, i);
    if (t === undefined || !ctx.isExec(t)) { if (bound) return undefined; break; }
    if (!bound) {
      // without a bounds check, stop at the first entry that does not look like a case target
      if (Math.abs(t - ctx.funcStart) > 1 << 20 && !ctx.isFunction(t)) break;
      if (i > 0 && evaluate(ctx, ld.a, i) === jmp.address) break;
    }
    targets.push(arch === 'arm' ? t & ~1 : t);
  }
  if (!targets.length || (!bound && targets.length < 2)) return undefined;
  const kind = targets.every((t) => ctx.isFunction(t) && t !== ctx.funcStart) ? 'call-table' : 'switch';
  const out: SwitchTable = { at: jmp.address, table, entrySize: ld.w, count: targets.length, targets, bound: bound ? 'cmp' : masked ? 'mask' : 'scan', kind, indexReg: idxReg };
  if (bound?.bias) out.bias = bound.bias;
  if (bound) out.boundAt = bound.at;
  return out;
}

interface Bound { reg: string; count: number; pos: number; at: number; bias?: number }

const X86_UCC: Record<string, string> = { ja: '>', jnbe: '>', jae: '>=', jnb: '>=', jnc: '>=', jb: '<', jnae: '<', jc: '<', jbe: '<=', jna: '<=' };
const ARM_UCC: Record<string, string> = { hi: '>', hs: '>=', cs: '>=', lo: '<', cc: '<', ls: '<=' };
const FLIP: Record<string, string> = { '>': '<=', '>=': '<', '<': '>=', '<=': '>' };

function findBound(arch: Arch, chain: Step[]): Bound | undefined {
  for (let j = 1; j < chain.length; j++) {
    const J = chain[j]!.ins;
    if (J.flow !== 'cjump') continue;
    const m = J.mnemonic.replace(/\.[wn]$/, '');
    let cc: string | undefined;
    if (arch === 'x86_64' || arch === 'x86') cc = X86_UCC[m];
    else if (m.startsWith('b.')) cc = ARM_UCC[m.slice(2)];
    else if (arch === 'arm' && m.length === 3 && m[0] === 'b') cc = ARM_UCC[m.slice(1)];
    if (!cc) return undefined; // the nearest conditional branch is not a range check
    const taken = chain[j - 1]!.viaTaken;
    const held = taken ? cc : FLIP[cc]!;
    // the flag setter right before the branch
    for (let k = j + 1; k < chain.length && k < j + 6; k++) {
      const C = chain[k]!.ins;
      const cm = C.mnemonic.replace(/\.[wn]$/, '');
      if (cm !== 'cmp' && cm !== 'subs') { if (setsFlags(arch, cm) || C.flow !== 'seq') return undefined; continue; }
      const ops = splitOperands(C.operands);
      const regOp = cm === 'subs' ? ops[1] : ops[0];
      const immOp = cm === 'subs' ? ops[2] : ops[1];
      const reg = regOp ? canon(arch, regOp) : undefined;
      const n = parseImm(immOp);
      if (!reg || n === undefined || n < 0 || n > 1 << 16) return undefined;
      let count: number;
      if (held === '<=') count = n + 1;
      else if (held === '<') count = n;
      else return { reg, count: 0, pos: k, at: C.address }; // we are on the out of range path
      // a bias applied right before the check (sub w8, w0, #100 / add edi, -100)
      let bias: number | undefined;
      for (let q = k + 1; q < chain.length && q < k + 4; q++) {
        const B = chain[q]!.ins;
        const bm = B.mnemonic.replace(/\.[wn]$/, '');
        const bo = splitOperands(B.operands);
        if (!writes(arch, B).includes(reg)) continue;
        const imm32 = (v: number | undefined) => (v !== undefined && (arch === 'x86' || ((bo[0] ?? '').startsWith('e') || (bo[0] ?? '').endsWith('d')) || (bo[0] ?? '').startsWith('w')) && v >= 2 ** 31 && v < 2 ** 32 ? v - 2 ** 32 : v);
        if ((bm === 'add' || bm === 'sub') && bo.length === 2 && canon(arch, bo[0]!) === reg) { const v = imm32(parseImm(bo[1])); if (v !== undefined) bias = bm === 'add' ? -v : v; }
        else if ((bm === 'sub' || bm === 'add') && bo.length === 3 && canon(arch, bo[0]!) === reg) { const v = imm32(parseImm(bo[2])); if (v !== undefined) bias = bm === 'sub' ? v : -v; }
        else if (bm === 'lea' && canon(arch, bo[0]!) === reg) { const lm = /^\[([a-z0-9]+)([+-])(0x[0-9a-f]+|\d+)\]$/.exec((bo[1] ?? '').replace(/\s+/g, '')); if (lm) { const v = parseImm(lm[3]); if (v !== undefined) bias = lm[2] === '-' ? v : -v; } }
        break;
      }
      return { reg, count, pos: k, at: C.address, bias };
    }
    return undefined;
  }
  return undefined;
}

function setsFlags(arch: Arch, m: string): boolean {
  if (arch === 'x86_64' || arch === 'x86') return /^(add|sub|and|or|xor|test|inc|dec|neg|shl|shr|sar|sal|rol|ror|adc|sbb|cmp|bt\w*|imul|mul|popcnt|lzcnt|tzcnt|bsf|bsr)$/.test(m);
  return /^(cmp|cmn|tst|teq|ccmp|ccmn|fcmp\w*)$/.test(m) || (/s$/.test(m) && /^(adds|subs|ands|bics|negs|adcs|sbcs|orrs|eors|lsls|lsrs|asrs|movs|muls|mvns|rsbs)$/.test(m));
}

class ExprBuilder {
  failed = false;
  /** index range implied by an and with a low bit mask (and eax, 0x7f), when there is no compare */
  maskCount: number | undefined;
  private budget = 200;
  private usedUnique = 0;
  constructor(private arch: Arch, private chain: Step[], private idxReg: string | undefined, private boundPos: number | undefined, private defsOf?: (reg: string) => Insn[]) {}

  /** expression for register r as seen just before chain[from - 1] executes */
  reg(r: string, from: number, depth: number): Ex {
    if (--this.budget < 0 || depth > 12) { this.failed = true; return { k: 'r', r }; }
    if (r === 'zr') return { k: 'c', v: 0 };
    for (let i = from; i < this.chain.length; i++) {
      if (i === this.boundPos && r === this.idxReg) return { k: 'r', r };
      const ins = this.chain[i]!.ins;
      if (ins.flow === 'call' || ins.flow === 'icall') { this.failed = true; return { k: 'r', r }; }
      if (!writes(this.arch, ins).includes(r)) continue;
      return this.def(ins, r, i + 1, depth + 1);
    }
    // not defined on the chain: a register set once for the whole function (a table base kept in a
    // callee saved register by an interpreter loop) is still a constant
    if (this.defsOf && this.usedUnique < 2 && r !== this.idxReg) {
      const defs = this.defsOf(r);
      if (defs.length && defs.length < 16 && defs.every((d) => d.mnemonic === 'lea' || d.mnemonic === 'adrp' || d.mnemonic === 'adr' || d.mnemonic === 'movabs' || (d.mnemonic === 'add' && this.arch === 'arm64'))) {
        this.usedUnique++;
        const saved = this.chain;
        let val: number | undefined;
        let ok = true;
        for (const d of defs) {
          // adrp + add pairs: evaluate the add on a two instruction chain ending at the adrp
          this.chain = [{ ins: d, viaTaken: false }];
          const e = this.def(d, r, 1, depth + 1);
          if (e.k !== 'c' || (val !== undefined && e.v !== val)) { ok = false; break; }
          val = e.v;
        }
        this.chain = saved;
        if (ok && val !== undefined) { this.failed = false; return { k: 'c', v: val }; }
        this.failed = true;
      }
    }
    return { k: 'r', r };
  }

  private def(ins: Insn, r: string, next: number, depth: number): Ex {
    const arch = this.arch;
    const m = ins.mnemonic.replace(/\.[wn]$/, '');
    const ops = splitOperands(ins.operands);
    const fail = (): Ex => { this.failed = true; return { k: "r", r }; };
    const src = (o: string | undefined): Ex => {
      if (o === undefined) return fail();
      const imm = parseImm(o);
      if (imm !== undefined) return { k: 'c', v: imm };
      const c = canon(arch, o);
      return c ? this.reg(c, next, depth) : fail();
    };
    if (arch === 'x86_64' || arch === 'x86') {
      if (canon(arch, ops[0] ?? '') !== r) return fail();
      const w = (ins.memSize ?? 0) || memWidthText(ops[1] ?? '') || 0;
      switch (m) {
        case 'lea': { const a = this.addr(ops[1] ?? '', next, ins); return a ?? fail(); }
        case 'mov': case 'movabs':
          if ((ops[1] ?? '').includes('[')) { const a = this.addr(ops[1]!, next, ins); return a ? { k: 'ld', a, w: w || (arch === 'x86' ? 4 : regBytes(ops[0]!)), s: false } : fail(); }
          return src(ops[1]);
        case 'movsxd': case 'movsx': case 'movzx': {
          const s = m !== 'movzx';
          if ((ops[1] ?? '').includes('[')) { const a = this.addr(ops[1]!, next, ins); return a ? { k: 'ld', a, w: w || (m === 'movsxd' ? 4 : 1), s } : fail(); }
          const inner = src(ops[1]);
          return { k: s ? 'sx' : 'zx', a: inner, w: regBytes(ops[1] ?? '') };
        }
        case 'add': return { k: 'add', a: this.reg(r, next, depth), b: src(ops[1]) };
        case 'sub': { const v = parseImm(ops[1]); return v === undefined ? fail() : { k: 'add', a: this.reg(r, next, depth), b: { k: 'c', v: -v } }; }
        case 'shl': { const v = parseImm(ops[1]); return v === undefined ? fail() : { k: 'shl', a: this.reg(r, next, depth), n: v }; }
        case 'and': return this.mask(parseImm(ops[1]), r) ?? fail();
        default: return fail();
      }
    }
    // ARM / AArch64
    const d = canon(arch, ops[0] ?? '');
    if (d !== r) return fail();
    switch (m) {
      case 'adr': case 'adrp': { const v = parseImm(ops[1]); return v === undefined ? fail() : { k: 'c', v }; }
      case 'mov': case 'movz': return src(ops[1]);
      case 'add': {
        const a = src(ops[1]);
        let b = src(ops[2]);
        const ext = ops[3];
        if (ext) {
          const mm = /^(lsl|sxtb|sxth|sxtw|uxtb|uxth|uxtw|sxtx|uxtx)(?: #(\d+))?$/.exec(ext);
          if (!mm) return fail();
          const sh = mm[2] ? Number(mm[2]) : 0;
          if (mm[1] === 'lsl') { if (parseImm(ops[2]) !== undefined) b = { k: 'c', v: parseImm(ops[2])! * 2 ** sh }; else b = { k: 'shl', a: b, n: sh }; }
          else {
            const w = mm[1]!.endsWith('b') ? 1 : mm[1]!.endsWith('h') ? 2 : mm[1]!.endsWith('w') ? 4 : 8;
            b = { k: 'shl', a: { k: mm[1]!.startsWith('s') ? 'sx' : 'zx', a: b, w }, n: sh };
          }
        }
        return { k: 'add', a, b };
      }
      case 'sub': { const v = parseImm(ops[2]); return v === undefined ? fail() : { k: 'add', a: src(ops[1]), b: { k: 'c', v: -v } }; }
      case 'ldr': case 'ldrb': case 'ldrh': case 'ldrsw': case 'ldrsb': case 'ldrsh': case 'ldur': {
        const a = this.addr(ops[1] ?? '', next, ins);
        if (!a) return fail();
        const w = m === 'ldrb' || m === 'ldrsb' ? 1 : m === 'ldrh' || m === 'ldrsh' ? 2 : m === 'ldrsw' ? 4 : arch === 'arm' ? 4 : (ops[0] ?? '').startsWith('w') ? 4 : 8;
        return { k: 'ld', a, w, s: m.startsWith('ldrs') };
      }
      case 'sxtw': case 'sxtb': case 'sxth': case 'uxtb': case 'uxth': case 'uxtw': {
        const w = m.endsWith('b') ? 1 : m.endsWith('h') ? 2 : 4;
        return { k: m.startsWith('s') ? 'sx' : 'zx', a: src(ops[1]), w };
      }
      case 'lsl': { const v = parseImm(ops[2]); return v === undefined ? fail() : { k: 'shl', a: src(ops[1]), n: v }; }
      case 'and': return (ops.length === 3 ? this.mask(parseImm(ops[2]), r) : undefined) ?? fail();
      case 'ubfx': { const lsb = parseImm(ops[2]); const w = parseImm(ops[3]); return lsb !== undefined && w !== undefined && w <= 12 ? this.mask(2 ** w - 1, r) ?? fail() : fail(); }
      default: return fail();
    }
  }

  /** an and with 2^k - 1 limits the index: the masked register becomes the index leaf */
  private mask(v: number | undefined, r: string): Ex | undefined {
    if (v === undefined || this.idxReg !== undefined || v <= 0 || v > 4095 || (v & (v + 1)) !== 0) return undefined;
    this.maskCount = v + 1;
    return { k: 'r', r };
  }

  /** address expression for a memory operand of `ins` */
  addr(op: string, next: number, ins: Insn): Ex | undefined {
    const arch = this.arch;
    const b = op.indexOf('[');
    if (b < 0) return undefined;
    const inner = op.slice(b + 1, op.lastIndexOf(']'));
    if (arch === 'x86_64' || arch === 'x86') {
      const terms = inner.replace(/\s+/g, '').replace(/-/g, '+-').split('+').filter(Boolean);
      let e: Ex | undefined;
      const addE = (x: Ex) => { e = e ? { k: 'add', a: e, b: x } : x; };
      for (const t of terms) {
        const mm = /^([a-z0-9]+)\*([1248])$/.exec(t);
        if (mm) {
          const c = canon(arch, mm[1]!);
          if (!c) return undefined;
          addE({ k: 'shl', a: this.reg(c, next, 0), n: Math.log2(Number(mm[2])) });
          continue;
        }
        if (t === 'rip') { addE({ k: 'c', v: ins.address + ins.size }); continue; }
        const v = parseImm(t) ?? (/^-?[0-9a-f]+h$/.test(t) ? parseInt(t, 16) : undefined);
        if (v !== undefined) { addE({ k: 'c', v }); continue; }
        const c = canon(arch, t);
        if (!c) return undefined;
        addE(this.reg(c, next, 0));
      }
      return e;
    }
    const parts = inner.split(',').map((s) => s.trim());
    const baseName = parts[0] ?? '';
    let base: Ex;
    if (arch === 'arm' && baseName === 'pc') base = { k: 'c', v: ((ins.address + (ins.thumb ? 4 : 8)) & ~3) >>> 0 };
    else { const c = canon(arch, baseName); if (!c) return undefined; base = this.reg(c, next, 0); }
    if (parts.length === 1) return base;
    const imm = parseImm(parts[1]);
    if (imm !== undefined && parts.length === 2) return { k: 'add', a: base, b: { k: 'c', v: imm } };
    const ic = canon(arch, parts[1] ?? '');
    if (!ic) return undefined;
    let idx: Ex = this.reg(ic, next, 0);
    const ext = parts[2];
    if (ext) {
      const mm = /^(lsl|uxtw|sxtw|sxtx|uxtx)(?: #(\d+))?$/.exec(ext);
      if (!mm) return undefined;
      if (mm[1] === 'sxtw') idx = { k: 'sx', a: idx, w: 4 };
      else if (mm[1] === 'uxtw') idx = { k: 'zx', a: idx, w: 4 };
      if (mm[2]) idx = { k: 'shl', a: idx, n: Number(mm[2]) };
    }
    return { k: 'add', a: base, b: idx };
  }
}

function memWidthText(op: string): number {
  if (op.startsWith('byte')) return 1;
  if (op.startsWith('word')) return 2;
  if (op.startsWith('dword')) return 4;
  if (op.startsWith('qword')) return 8;
  return 0;
}

function regBytes(r: string): number {
  const s = r.trim();
  if (/^(al|bl|cl|dl|sil|dil|r\d+b)$/.test(s)) return 1;
  if (/^(ax|bx|cx|dx|si|di|r\d+w)$/.test(s)) return 2;
  if (/^(e[a-z]{2}|r\d+d)$/.test(s)) return 4;
  return 8;
}

function collectLeaves(e: Ex, out: Set<string>): void {
  switch (e.k) {
    case 'r': out.add(e.r); return;
    case 'c': return;
    case 'add': collectLeaves(e.a, out); collectLeaves(e.b, out); return;
    default: collectLeaves(e.a, out);
  }
}

function firstLoad(e: Ex): Extract<Ex, { k: 'ld' }> | undefined {
  if (e.k === 'ld') return firstLoad(e.a) ?? e;
  if (e.k === 'add') return firstLoad(e.a) ?? firstLoad(e.b);
  if (e.k === 'c' || e.k === 'r') return undefined;
  return firstLoad(e.a);
}

function allLoads(e: Ex, f: (l: Extract<Ex, { k: 'ld' }>) => void): void {
  if (e.k === 'ld') { f(e); allLoads(e.a, f); return; }
  if (e.k === 'add') { allLoads(e.a, f); allLoads(e.b, f); return; }
  if (e.k === 'c' || e.k === 'r') return;
  allLoads(e.a, f);
}

function signExt(v: number, w: number): number {
  const bits = w * 8;
  if (bits >= 53) return v;
  const max = 2 ** bits;
  const u = ((v % max) + max) % max;
  return u >= max / 2 ? u - max : u;
}

function evaluate(ctx: JumpTableContext, e: Ex, idx: number, depth = 0): number | undefined {
  if (depth > 40) return undefined;
  switch (e.k) {
    case 'c': return e.v;
    case 'r': return idx;
    case 'add': { const a = evaluate(ctx, e.a, idx, depth + 1); const b = evaluate(ctx, e.b, idx, depth + 1); return a === undefined || b === undefined ? undefined : wrap(ctx, a + b); }
    case 'shl': { const a = evaluate(ctx, e.a, idx, depth + 1); return a === undefined ? undefined : wrap(ctx, a * 2 ** e.n); }
    case 'sx': { const a = evaluate(ctx, e.a, idx, depth + 1); return a === undefined ? undefined : signExt(a, e.w); }
    case 'zx': { const a = evaluate(ctx, e.a, idx, depth + 1); return a === undefined ? undefined : e.w >= 6 ? a : ((a % 2 ** (e.w * 8)) + 2 ** (e.w * 8)) % 2 ** (e.w * 8); }
    case 'ld': {
      const a = evaluate(ctx, e.a, idx, depth + 1);
      if (a === undefined) return undefined;
      const v = ctx.read(a, e.w);
      if (v === undefined) return undefined;
      return e.s ? signExt(v, e.w) : v;
    }
  }
}

function wrap(ctx: JumpTableContext, v: number): number {
  if (ctx.bits === 32) return v >>> 0;
  return v < 0 ? v + 2 ** 64 : v; // negative results are not plausible addresses anyway
}

function thumbTable(ctx: JumpTableContext, jmp: Insn, w: 1 | 2, bound: Bound | undefined): SwitchTable | undefined {
  if (!bound) return undefined;
  const ops = bracketed(jmp.operands).split(',').map((s) => s.trim());
  if (ops[0] !== 'pc') return undefined;
  const r = canon('arm', ops[1] ?? '');
  if (r !== bound.reg) return undefined;
  const table = jmp.address + 4;
  const targets: number[] = [];
  for (let i = 0; i < Math.min(bound.count, MAX_ENTRIES); i++) {
    const v = ctx.read(table + i * w, w);
    if (v === undefined) return undefined;
    const t = table + 2 * v;
    if (!ctx.isExec(t)) return undefined;
    targets.push(t);
  }
  return { at: jmp.address, table, entrySize: w, count: targets.length, targets, bound: 'cmp', kind: 'switch', indexReg: r, boundAt: bound.at, ...(bound.bias ? { bias: bound.bias } : {}) };
}

/** Text inside the first [...] of an operand string, or '' (indexOf scan instead of an unanchored regex). */
function bracketed(s: string): string {
  const i = s.indexOf('[');
  if (i < 0) return '';
  const j = s.indexOf(']', i + 1);
  return j < 0 ? '' : s.slice(i + 1, j);
}
