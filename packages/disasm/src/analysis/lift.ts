// Light lifter: per instruction C like statements, call argument recovery from the calling
// convention, and simple structuring (if, if/else, do/while, while(true)) with goto fallback.
import type { AnalyzedFunction, Arch, BasicBlock, Insn } from '../types.js';
import type { Program } from './program.js';
import { hx, parseImm, splitOperands } from '../util.js';

interface Cond { lhs: string; rhs: string; op: string; text?: string }

const NEG: Record<string, string> = { '==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>' };

const X86_CC: Record<string, string> = {
  je: '==', jz: '==', jne: '!=', jnz: '!=', jl: '<', jnge: '<', jle: '<=', jng: '<=', jg: '>', jnle: '>', jge: '>=', jnl: '>=',
  jb: '<u', jnae: '<u', jc: '<u', jbe: '<=u', jna: '<=u', ja: '>u', jnbe: '>u', jae: '>=u', jnb: '>=u', jnc: '>=u', js: '<0', jns: '>=0',
};
const ARM_CC: Record<string, string> = {
  eq: '==', ne: '!=', lt: '<', le: '<=', gt: '>', ge: '>=', lo: '<u', cc: '<u', ls: '<=u', hi: '>u', hs: '>=u', cs: '>=u', mi: '<0', pl: '>=0',
};

const ARGS: Record<string, string[]> = {
  sysv: ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
  win64: ['rcx', 'rdx', 'r8', 'r9'],
  arm64: ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
  arm: ['r0', 'r1', 'r2', 'r3'],
};

const X86_ALIAS: Record<string, string> = {};
for (const [full, names] of Object.entries({
  rax: ['eax', 'ax', 'al'], rbx: ['ebx', 'bx', 'bl'], rcx: ['ecx', 'cx', 'cl'], rdx: ['edx', 'dx', 'dl'], rsi: ['esi', 'si', 'sil'], rdi: ['edi', 'di', 'dil'],
  r8: ['r8d', 'r8w', 'r8b'], r9: ['r9d', 'r9w', 'r9b'],
})) { X86_ALIAS[full] = full; for (const n of names) X86_ALIAS[n] = full; }

function canonReg(arch: Arch, r: string): string {
  if (arch === 'x86_64' || arch === 'x86') return X86_ALIAS[r] ?? r;
  if (arch === 'arm64' && /^w\d+$/.test(r)) return 'x' + r.slice(1);
  return r;
}

export interface LiftResult {
  name: string;
  addr: number;
  text: string;
  structured: boolean;
  gotos: number;
}

class Lifter {
  private readonly p: Program;
  private readonly af: AnalyzedFunction;
  private readonly arch: Arch;
  private readonly conv: string[];
  private readonly retReg: string;
  private readonly blocks: BasicBlock[];
  private readonly idx = new Map<number, number>();
  private readonly gotoTargets = new Set<number>();
  private lastCond: Cond | undefined;
  private argVals = new Map<string, string>();
  private stackArgs = new Map<number, string>();
  private pushes: string[] = [];
  private emittedLines = 0;
  private readonly maxLines: number;

  constructor(p: Program, af: AnalyzedFunction, maxLines: number) {
    this.p = p;
    this.af = af;
    this.arch = p.arch;
    this.maxLines = maxLines;
    this.conv = this.arch === 'x86_64' ? (p.img.format === 'pe' ? ARGS.win64! : ARGS.sysv!) : this.arch === 'arm64' ? ARGS.arm64! : this.arch === 'arm' ? ARGS.arm! : [];
    this.retReg = this.arch === 'x86_64' ? 'rax' : this.arch === 'x86' ? 'eax' : this.arch === 'arm64' ? 'x0' : 'r0';
    this.blocks = [...af.blocks].sort((a, b) => a.start - b.start);
    this.blocks.forEach((b, i) => this.idx.set(b.start, i));
  }

  private label(a: number): string { return 'L_' + a.toString(16); }

  // ----- operand rendering -----
  private refText(ins: Insn, addr: number, asAddress: boolean): string {
    const ref = this.af.dataRefs.find((d) => d.at === ins.address && (d.addr === addr || d.kind === 'string'));
    if (ref?.kind === 'string' && ref.value !== undefined) return JSON.stringify(ref.value.length > 80 ? ref.value.slice(0, 80) + '...' : ref.value);
    const sym = this.p.symbolize(addr);
    if (sym) return asAddress ? '&' + sym : sym;
    return asAddress ? hx(addr) : `*(${hx(addr)})`;
  }

  private mem(ins: Insn, op: string, asAddress = false): string {
    // x86 "dword ptr [rbp-0x14]" / arm "[x29, #-0x14]"
    const b = op.indexOf('[');
    if (b < 0) return op;
    if (ins.memAddr !== undefined && !ins.viaMemory) return this.refText(ins, ins.memAddr, asAddress);
    const inner = op.slice(b + 1, op.lastIndexOf(']')).replace(/#/g, '').split(',').map((s) => s.trim()).filter(Boolean);
    let expr = inner.join(' + ').replace(/\+ -/g, '- ');
    return asAddress ? `(${expr})` : `*(${expr})`;
  }

  private val(ins: Insn, op: string | undefined): string {
    if (op === undefined) return '?';
    if (op.includes('[')) return this.mem(ins, op);
    const imm = parseImm(op);
    if (imm !== undefined) {
      const d = this.af.dataRefs.find((r) => r.at === ins.address && r.kind === 'string' && (r.addr === imm));
      if (d?.value) return JSON.stringify(d.value);
      if (imm > 0xffff) { const s = this.p.symbolize(imm); if (s && this.p.mem.isMapped(imm)) return '&' + s; }
      return Math.abs(imm) > 9 ? hx(imm) : String(imm);
    }
    return op.replace(/^#/, '');
  }

  // ----- statements -----
  private callText(ins: Insn): string {
    let name: string | undefined;
    if (ins.target !== undefined) name = this.p.nameOf(ins.target) ?? 'sub_' + ins.target.toString(16);
    else if (ins.viaMemory && ins.memAddr !== undefined) name = this.p.importBySlot.get(ins.memAddr)?.name;
    if (!name) {
      const ops = splitOperands(ins.operands);
      name = `(*${ops[ops.length - 1] ? this.val(ins, ops[ops.length - 1]) : '?'})`;
    }
    const args: string[] = [];
    if (this.arch === 'x86') {
      const offs = [...this.stackArgs.keys()].sort((a, b) => a - b);
      for (let k = 0; k < offs.length && offs[k] === k * 4; k++) args.push(this.stackArgs.get(offs[k]!)!);
      if (!args.length && this.pushes.length) args.push(...[...this.pushes].reverse());
    } else {
      for (const r of this.conv) { const v = this.argVals.get(r); if (v === undefined) break; args.push(v); }
    }
    this.argVals.clear();
    this.stackArgs.clear();
    this.pushes = [];
    return `${name}(${args.join(', ')})`;
  }

  private setReg(dst: string, value: string): void {
    const c = canonReg(this.arch, dst);
    if (this.conv.includes(c)) this.argVals.set(c, value);
  }

  private stmt(ins: Insn): string | undefined {
    const m = ins.mnemonic.replace(/\.[wn]$/, '');
    const ops = splitOperands(ins.operands);
    const [a, b, c] = ops;
    if (ins.flow === 'call' || ins.flow === 'icall') return this.callText(ins) + ';';
    if (this.arch === 'x86' || this.arch === 'x86_64') return this.stmtX86(ins, m, ops, a, b);
    return this.stmtArm(ins, m, ops, a, b, c);
  }

  private stmtX86(ins: Insn, m: string, ops: string[], a?: string, b?: string): string | undefined {
    if (m === 'nop' || m === 'endbr64' || m === 'endbr32' || m === 'int3' || m === 'leave') return undefined;
    if ((m === 'push' || m === 'pop') && a && /^[re]?(bp|bx|si|di|r1[2-5])$/.test(a) && !this.inBody) return undefined;
    if (m === 'push') { this.pushes.push(this.val(ins, a)); return undefined; }
    if (m === 'cmp' || m === 'test') { this.lastCond = { lhs: this.val(ins, a), rhs: this.val(ins, b), op: m }; return undefined; }
    if ((m === 'sub' || m === 'add') && (a === 'rsp' || a === 'esp')) return undefined;
    if (m === 'mov' && (a === 'rbp' || a === 'ebp') && (b === 'rsp' || b === 'esp')) return undefined;
    if (!a) return `__asm("${m}");`;
    if (a.includes('[esp') && this.arch === 'x86' && (m === 'mov')) {
      const mm = /\[esp(?:\+(0x[0-9a-f]+|\d+))?\]/.exec(a);
      if (mm) { this.stackArgs.set(mm[1] ? parseImm(mm[1])! : 0, this.val(ins, b)); return undefined; }
    }
    const dst = a.includes('[') ? this.mem(ins, a) : a;
    if (['add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'neg', 'shl', 'shr', 'sar'].includes(m)) this.lastCond = { lhs: dst, rhs: '0', op: 'zero' };
    let rhs: string | undefined;
    switch (m) {
      case 'mov': case 'movabs': case 'movzx': case 'movsx': case 'movsxd': case 'movaps': case 'movups': case 'movq': case 'movd': case 'movss': case 'movsd':
        rhs = this.val(ins, b); break;
      case 'lea': rhs = b ? this.mem(ins, b, true) : '?'; break;
      case 'xor':
        if (a === b) { rhs = '0'; break; }
        return `${dst} ^= ${this.val(ins, b)};`;
      case 'add': return `${dst} += ${this.val(ins, b)};`;
      case 'sub': return `${dst} -= ${this.val(ins, b)};`;
      case 'and': return `${dst} &= ${this.val(ins, b)};`;
      case 'or': return `${dst} |= ${this.val(ins, b)};`;
      case 'shl': case 'sal': return `${dst} <<= ${this.val(ins, b ?? '1')};`;
      case 'shr': case 'sar': return `${dst} >>= ${this.val(ins, b ?? '1')};`;
      case 'imul': if (ops.length === 3) { rhs = `${this.val(ins, b)} * ${this.val(ins, ops[2])}`; break; } if (b) return `${dst} *= ${this.val(ins, b)};`; break;
      case 'inc': return `${dst}++;`;
      case 'dec': return `${dst}--;`;
      case 'neg': rhs = `-${dst}`; break;
      case 'not': rhs = `~${dst}`; break;
      case 'pop': rhs = 'pop()'; break;
      default:
        if (m.startsWith('set') && X86_CC['j' + m.slice(3)] && this.lastCond) { rhs = this.condText(this.lastCond, X86_CC['j' + m.slice(3)]!); break; }
        if (m.startsWith('cmov') && X86_CC['j' + m.slice(4)] && this.lastCond) return `if (${this.condText(this.lastCond, X86_CC['j' + m.slice(4)]!)}) ${dst} = ${this.val(ins, b)};`;
        return `__asm("${m} ${ins.operands}");`;
    }
    if (rhs === undefined) return `__asm("${m} ${ins.operands}");`;
    if (!a.includes('[')) this.setReg(a, rhs);
    return `${dst} = ${rhs};`;
  }

  private inBody = false;

  private stmtArm(ins: Insn, m: string, ops: string[], a?: string, b?: string, c?: string): string | undefined {
    if (m === 'nop' || m === 'paciasp' || m === 'autiasp' || m === 'bti' || m === 'hint' || m.startsWith('it')) return m.startsWith('it') && m !== 'it' && !/^it[te]*$/.test(m) ? `__asm("${m} ${ins.operands}");` : undefined;
    if ((m === 'stp' || m === 'ldp') && a === 'x29' && b === 'x30') return undefined;
    if ((m === 'stp' || m === 'ldp') && ops[2]?.startsWith('[sp') && /^x(19|2[0-9]|30)$/.test(a ?? '') && /^x(19|2[0-9]|30)$/.test(b ?? '')) return undefined;
    if ((m === 'push' || m === 'pop') && !ins.operands.includes('pc')) return undefined;
    if (m === 'mov' && a === 'x29' && b === 'sp') return undefined;
    if ((m === 'add' || m === 'sub') && (a === 'sp' || (a === 'r7' && b === 'sp') || (a === 'x29' && b === 'sp'))) return undefined;
    if (m === 'cmp' || m === 'cmn' || m === 'tst') { this.lastCond = { lhs: this.val(ins, a), rhs: this.val(ins, b), op: m === 'tst' ? 'test' : 'cmp' }; return undefined; }
    if (!a) return `__asm("${m}");`;
    if (['adds', 'subs', 'ands', 'orrs', 'eors', 'lsls', 'lsrs', 'asrs', 'muls', 'negs', 'rsbs'].includes(m)) this.lastCond = { lhs: a.replace(/^w/, 'x'), rhs: '0', op: 'zero' };
    let rhs: string | undefined;
    if (ins.memAddr !== undefined && (m === 'adrp' || m === 'adr' || m === 'add' || m === 'movt' || (m === 'ldr' && ops.length === 2 && !b?.startsWith('[')))) {
      rhs = this.refText(ins, ins.memAddr, true);
      if (m === 'ldr' && ins.memAddr !== undefined && !this.af.dataRefs.some((d) => d.at === ins.address && d.kind === 'string')) rhs = `*(${rhs.replace(/^&/, '')})`;
    } else if (m === 'movw' && ins.memAddr === undefined && this.blocksHasMovt(ins)) {
      return undefined;
    } else switch (m) {
      case 'adrp': case 'adr': case 'mov': case 'movz': case 'movw': case 'fmov': case 'sxtw': case 'uxtw': case 'sxth': case 'sxtb': case 'uxth': case 'uxtb':
        rhs = this.val(ins, b); break;
      case 'mvn': rhs = `~${this.val(ins, b)}`; break;
      case 'neg': rhs = `-${this.val(ins, b)}`; break;
      case 'add': case 'adds': rhs = `${this.val(ins, c === undefined ? a : b)} + ${this.val(ins, c ?? b)}`; break;
      case 'sub': case 'subs': rhs = `${this.val(ins, c === undefined ? a : b)} - ${this.val(ins, c ?? b)}`; break;
      case 'rsb': case 'rsbs': rhs = `${this.val(ins, c ?? b)} - ${this.val(ins, c === undefined ? a : b)}`; break;
      case 'mul': case 'muls': rhs = `${this.val(ins, c === undefined ? a : b)} * ${this.val(ins, c ?? b)}`; break;
      case 'sdiv': case 'udiv': rhs = `${this.val(ins, b)} / ${this.val(ins, c)}`; break;
      case 'and': case 'ands': rhs = `${this.val(ins, c === undefined ? a : b)} & ${this.val(ins, c ?? b)}`; break;
      case 'orr': case 'orrs': rhs = `${this.val(ins, c === undefined ? a : b)} | ${this.val(ins, c ?? b)}`; break;
      case 'eor': case 'eors': rhs = `${this.val(ins, c === undefined ? a : b)} ^ ${this.val(ins, c ?? b)}`; break;
      case 'lsl': case 'lsls': rhs = `${this.val(ins, b)} << ${this.val(ins, c)}`; break;
      case 'lsr': case 'lsrs': case 'asr': case 'asrs': rhs = `${this.val(ins, b)} >> ${this.val(ins, c)}`; break;
      case 'ldr': case 'ldrb': case 'ldrh': case 'ldrsw': case 'ldrsb': case 'ldrsh': case 'ldur':
        rhs = b ? this.mem(ins, b) : '?'; break;
      case 'str': case 'strb': case 'strh': case 'stur':
        return `${b ? this.mem(ins, b) : '?'} = ${this.val(ins, a)};`;
      case 'cset': case 'csetm':
        if (this.lastCond && b && ARM_CC[b]) { rhs = this.condText(this.lastCond, ARM_CC[b]!); break; }
        return `__asm("${m} ${ins.operands}");`;
      case 'csel': case 'csinc':
        if (this.lastCond && ops[3] && ARM_CC[ops[3]]) { rhs = `${this.condText(this.lastCond, ARM_CC[ops[3]]!)} ? ${this.val(ins, b)} : ${this.val(ins, c)}${m === 'csinc' ? ' + 1' : ''}`; break; }
        return `__asm("${m} ${ins.operands}");`;
      default: {
        const base = m.slice(0, -2);
        const cc = m.slice(-2);
        if (ARM_CC[cc] && this.lastCond && ['mov', 'add', 'sub', 'ldr', 'str', 'mvn'].includes(base)) return `if (${this.condText(this.lastCond, ARM_CC[cc]!)}) __asm("${base} ${ins.operands}");`;
        return `__asm("${m} ${ins.operands}");`;
      }
    }
    this.setReg(a, rhs);
    return `${a.replace(/^w/, 'x')} = ${rhs};`;
  }

  private blocksHasMovt(ins: Insn): boolean {
    for (const b of this.blocks) {
      const k = b.insns.indexOf(ins);
      if (k >= 0) {
        const reg = splitOperands(ins.operands)[0];
        return b.insns.slice(k + 1, k + 4).some((n) => n.mnemonic.replace(/\.w$/, '') === 'movt' && splitOperands(n.operands)[0] === reg);
      }
    }
    return false;
  }

  private condText(c: Cond, op: string): string {
    const unsigned = op.endsWith('u');
    const o = unsigned ? op.slice(0, -1) : op;
    if (o === '<0' || o === '>=0') {
      const e = c.op === 'test' && c.lhs === c.rhs ? c.lhs : c.op === 'test' ? `(${c.lhs} & ${c.rhs})` : `(${c.lhs} - ${c.rhs})`;
      return `${e} ${o === '<0' ? '<' : '>='} 0`;
    }
    if (c.op === 'test') {
      const e = c.lhs === c.rhs ? c.lhs : `(${c.lhs} & ${c.rhs})`;
      return `${unsigned ? '(unsigned)' : ''}${e} ${o} 0`;
    }
    if (c.op === 'zero') return `${c.lhs} ${o} 0`;
    if (c.op === 'bit') return `${o === '==' ? '!' : ''}(${c.lhs} & ${c.rhs})`;
    return `${unsigned ? '(unsigned)' : ''}${c.lhs} ${o} ${c.rhs}`;
  }

  /** condition under which the conditional branch at the end of block b is taken */
  private branchCond(b: BasicBlock): string {
    const last = b.insns[b.insns.length - 1]!;
    const m = last.mnemonic.replace(/\.[wn]$/, '');
    const ops = splitOperands(last.operands);
    if (this.arch === 'x86' || this.arch === 'x86_64') {
      const op = X86_CC[m];
      if (op && this.lastCond) return this.condText(this.lastCond, op);
      return `/* ${m} */ cond`;
    }
    if (m === 'cbz' || m === 'cbnz') return `${ops[0]} ${m === 'cbz' ? '==' : '!='} 0`;
    if (m === 'tbz' || m === 'tbnz') return this.condText({ lhs: ops[0] ?? '?', rhs: hx(2 ** (parseImm(ops[1]) ?? 0)), op: 'bit' }, m === 'tbz' ? '==' : '!=');
    const cc = m.startsWith('b.') ? m.slice(2) : m.startsWith('bc.') ? m.slice(3) : m.slice(1);
    const op = ARM_CC[cc];
    if (op && this.lastCond) return this.condText(this.lastCond, op);
    return `/* ${m} */ cond`;
  }

  private negate(cond: string): string {
    const mm = /^(\(unsigned\))?([^<>=!]+) (==|!=|<|>=|>|<=) ([^<>=!]+)$/.exec(cond);
    if (mm && NEG[mm[3]!]) return `${mm[1] ?? ''}${mm[2]} ${NEG[mm[3]!]} ${mm[4]}`;
    if (cond.startsWith('!(') && cond.endsWith(')')) return cond.slice(1);
    return `!(${cond})`;
  }

  // ----- structuring -----
  private out: string[] = [];
  private push(indent: number, line: string): void {
    if (this.emittedLines++ > this.maxLines) return;
    this.out.push('  '.repeat(indent) + line);
  }

  private preds(i: number): number[] { return this.blocks[i]!.pred.map((p) => this.idx.get(p) ?? -1); }

  private singleEntry(from: number, lo: number, hi: number): boolean {
    for (let k = lo; k < hi; k++) for (const p of this.preds(k)) if (p < from || p >= hi) return false;
    return true;
  }

  private emitBlockBody(b: BasicBlock, indent: number, skipLast: boolean): void {
    this.inBody = b.start !== this.af.addr;
    this.lastCond = undefined;
    const n = b.insns.length;
    for (let k = 0; k < n; k++) {
      const ins = b.insns[k]!;
      const isLast = k === n - 1;
      if (isLast && skipLast && (ins.flow === 'cjump' || (ins.flow === 'jump' && b.exit !== 'tail'))) continue;
      if (ins.flow === 'ret') { this.push(indent, `return ${this.retReg};`); continue; }
      if (ins.flow === 'jump' || ins.flow === 'ijump') {
        if (b.exit === 'tail') {
          if (ins.target !== undefined || ins.viaMemory) { this.push(indent, `return ${this.callText(ins)};`); continue; }
        }
        if (ins.flow === 'ijump') { this.push(indent, `goto *${this.val(ins, splitOperands(ins.operands)[0])}; // indirect jump`); continue; }
        continue;
      }
      if (ins.flow === 'cjump') continue;
      if (ins.flow === 'trap') { this.push(indent, `__trap(); // ${ins.mnemonic}`); continue; }
      if (ins.flow === 'invalid') { this.push(indent, `__invalid(); // undecodable bytes at ${hx(ins.address)}`); continue; }
      const s = this.stmt(ins);
      if (s) this.push(indent, s);
    }
    if (b.exit === 'noreturn') this.push(indent, '// does not return');
  }

  private emitRange(lo: number, hi: number, indent: number, loopHead?: number, depth = 0, follow?: number): void {
    let i = lo;
    while (i < hi) {
      if (depth > 40) { this.gotoFallback(i, hi, indent); return; }
      const b = this.blocks[i]!;
      // loop with header b?
      let latch = -1;
      for (let k = hi - 1; k >= i; k--) if (this.blocks[k]!.succ.some((e) => e.to === b.start)) { latch = k; break; }
      if (latch >= 0 && b.start !== loopHead && this.singleEntryLoop(i, latch)) {
        const lb = this.blocks[latch]!;
        const lastL = lb.insns[lb.insns.length - 1]!;
        const condLoop = lastL.flow === 'cjump' && lb.succ.some((e) => e.to === b.start && e.kind === 'true');
        this.push(indent, `${this.label(b.start)}:`);
        this.push(indent, condLoop ? 'do {' : 'while (true) {');
        this.emitRange(i, latch, indent + 1, b.start, depth + 1, lb.start);
        // latch body
        this.emitBlockBody(lb, indent + 1, true);
        if (!condLoop && lastL.flow === 'cjump') {
          const t = lastL.target;
          const c = this.branchCond(lb);
          if (t !== undefined && t !== b.start) { this.gotoTargets.add(t); this.push(indent + 1, `if (${c}) goto ${this.label(t)};`); }
        }
        if (condLoop) this.push(indent, `} while (${this.branchCond(lb)});`);
        else this.push(indent, '}');
        i = latch + 1;
        continue;
      }
      this.push(indent, `${this.label(b.start)}:`);
      const last = b.insns[b.insns.length - 1]!;
      this.emitBlockBody(b, indent, true);
      const next = this.blocks[i + 1];
      if (last.flow === 'cjump' && last.target !== undefined && this.idx.has(last.target)) {
        const ti = this.idx.get(last.target)!;
        const cond = this.branchCond(b);
        if (last.target === loopHead) { this.push(indent, `if (${cond}) continue;`); i++; continue; }
        if (ti > i + 1 && ti <= hi && this.singleEntry(i, i + 1, ti)) {
          // if (!cond) { then } possibly with else
          const thenLast = this.blocks[ti - 1]!;
          const tl = thenLast.insns[thenLast.insns.length - 1]!;
          const t2i = tl.flow === 'jump' && tl.target !== undefined && thenLast.exit !== 'tail' ? this.idx.get(tl.target) : undefined;
          if (t2i !== undefined && t2i > ti && t2i <= hi && this.singleEntry(i, ti, t2i)) {
            this.push(indent, `if (${this.negate(cond)}) {`);
            const join = this.blocks[t2i]?.start ?? follow;
            this.emitRange(i + 1, ti, indent + 1, loopHead, depth + 1, join);
            this.push(indent, '} else {');
            this.emitRange(ti, t2i, indent + 1, loopHead, depth + 1, join);
            this.push(indent, '}');
            i = t2i;
            continue;
          }
          this.push(indent, `if (${this.negate(cond)}) {`);
          this.emitRange(i + 1, ti, indent + 1, loopHead, depth + 1, this.blocks[ti]?.start ?? follow);
          this.push(indent, '}');
          i = ti;
          continue;
        }
        this.gotoTargets.add(last.target);
        this.push(indent, `if (${cond}) goto ${this.label(last.target)};`);
      } else if (last.flow === 'jump' && last.target !== undefined && b.exit !== 'tail') {
        const natural = i + 1 >= hi ? follow : next?.start;
        if (last.target === loopHead) this.push(indent, 'continue;');
        else if (natural !== last.target) { this.gotoTargets.add(last.target); this.push(indent, `goto ${this.label(last.target)};`); }
      } else if (!b.exit && b.succ.length === 1 && b.succ[0]!.kind === 'fallthrough' && b.succ[0]!.to !== (i + 1 >= hi ? follow : next?.start)) {
        const t = b.succ[0]!.to;
        if (t === loopHead) this.push(indent, 'continue;');
        else { this.gotoTargets.add(t); this.push(indent, `goto ${this.label(t)};`); }
      }
      i++;
    }
  }

  private singleEntryLoop(head: number, latch: number): boolean {
    // all blocks inside (head, latch] must only be entered from inside [head, latch]
    for (let k = head + 1; k <= latch; k++) for (const p of this.preds(k)) if (p < head || p > latch) return false;
    return true;
  }

  private gotoFallback(lo: number, hi: number, indent: number): void {
    for (let i = lo; i < hi; i++) {
      const b = this.blocks[i]!;
      this.push(indent, `${this.label(b.start)}:`);
      this.emitBlockBody(b, indent, true);
      const last = b.insns[b.insns.length - 1]!;
      if (last.flow === 'cjump' && last.target !== undefined) { this.gotoTargets.add(last.target); this.push(indent, `if (${this.branchCond(b)}) goto ${this.label(last.target)};`); }
      else if (last.flow === 'jump' && last.target !== undefined && b.exit !== 'tail') { this.gotoTargets.add(last.target); this.push(indent, `goto ${this.label(last.target)};`); }
    }
  }

  run(): LiftResult {
    const af = this.af;
    const sig = `${af.name}(${this.conv.slice(0, 0).join(', ')})`;
    this.emitRange(0, this.blocks.length, 1);
    // drop labels nobody jumps to
    const lines = this.out.filter((l) => {
      const m = /^\s*L_([0-9a-f]+):$/.exec(l);
      return !m || this.gotoTargets.has(parseInt(m[1]!, 16));
    });
    if (this.emittedLines > this.maxLines) lines.push(`  // ... truncated after ${this.maxLines} lines`);
    const header = [
      `// ${af.name} at ${hx(af.addr)}, ${af.insnCount} instructions, ${af.blocks.length} blocks${af.truncated ? ' (analysis truncated)' : ''}`,
      `// light lift: registers stand in for variables; calling convention ${this.arch === 'x86' ? 'cdecl stack' : this.conv.join(',')}`,
      `void ${sig} {`,
    ];
    return { name: af.name, addr: af.addr, text: [...header, ...lines, '}'].join('\n'), structured: this.gotoTargets.size === 0, gotos: this.gotoTargets.size };
  }
}

/** Lift one analyzed function to readable pseudo code. */
export function liftFunction(p: Program, af: AnalyzedFunction, maxLines = 400): LiftResult {
  return new Lifter(p, af, maxLines).run();
}
