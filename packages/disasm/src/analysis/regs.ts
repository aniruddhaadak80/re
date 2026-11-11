// Register naming helpers shared by the jump table resolver, the value tracker and the lifter.
import type { Arch, Insn } from '../types.js';
import { splitOperands } from '../util.js';

const X86_CANON: Record<string, string> = {};
for (const [full, names] of Object.entries({
  rax: ['eax', 'ax', 'al', 'ah'], rbx: ['ebx', 'bx', 'bl', 'bh'], rcx: ['ecx', 'cx', 'cl', 'ch'], rdx: ['edx', 'dx', 'dl', 'dh'],
  rsi: ['esi', 'si', 'sil'], rdi: ['edi', 'di', 'dil'], rbp: ['ebp', 'bp', 'bpl'], rsp: ['esp', 'sp', 'spl'],
})) { X86_CANON[full] = full; for (const n of names) X86_CANON[n] = full; }
for (let i = 8; i <= 15; i++) { const r = 'r' + i; X86_CANON[r] = r; for (const s of ['d', 'w', 'b']) X86_CANON[r + s] = r; }

const X86_32: Record<string, string> = { rax: 'eax', rbx: 'ebx', rcx: 'ecx', rdx: 'edx', rsi: 'esi', rdi: 'edi', rbp: 'ebp', rsp: 'esp' };

/** Canonical full width register name (eax -> rax on x86-64, w3 -> x3), or undefined when not a GPR. */
export function canon(arch: Arch, r: string): string | undefined {
  const s = r.trim().toLowerCase();
  if (arch === 'x86_64') return X86_CANON[s];
  if (arch === 'x86') { const c = X86_CANON[s]; return c && !/^r\d/.test(c) ? X86_32[c] : undefined; }
  if (arch === 'arm64') {
    if (s === 'sp' || s === 'wsp') return 'sp';
    if (s === 'xzr' || s === 'wzr') return 'zr';
    if (s === 'fp') return 'x29';
    if (s === 'lr') return 'x30';
    const m = /^[xw]([0-9]|[12][0-9]|30)$/.exec(s);
    return m ? 'x' + m[1] : undefined;
  }
  if (arch === 'arm') {
    const alias: Record<string, string> = { sb: 'r9', sl: 'r10', fp: 'r11', ip: 'r12', sp: 'sp', lr: 'lr', pc: 'pc' };
    if (alias[s]) return alias[s];
    return /^r([0-9]|1[0-5])$/.test(s) ? s : undefined;
  }
  return undefined;
}

/** Width in bytes of a register as written (eax 4, al 1, w0 4, x0 8). */
export function regWidth(arch: Arch, r: string): number {
  const s = r.trim().toLowerCase();
  if (arch === 'arm64') return s.startsWith('w') ? 4 : 8;
  if (arch === 'arm') return 4;
  if (/^(al|bl|cl|dl|ah|bh|ch|dh|sil|dil|bpl|spl|r\d+b)$/.test(s)) return 1;
  if (/^(ax|bx|cx|dx|si|di|bp|sp|r\d+w)$/.test(s)) return 2;
  if (/^(e[a-z]{2}|r\d+d)$/.test(s)) return 4;
  return arch === 'x86' ? 4 : 8;
}

/** Caller saved (clobbered by a call) registers per architecture and ABI. */
export function callClobbered(arch: Arch, win64 = false): Set<string> {
  if (arch === 'x86_64') return new Set(win64 ? ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'] : ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']);
  if (arch === 'x86') return new Set(['eax', 'ecx', 'edx']);
  if (arch === 'arm64') { const s = new Set<string>(); for (let i = 0; i <= 18; i++) s.add('x' + i); s.add('x30'); return s; }
  if (arch === 'arm') return new Set(['r0', 'r1', 'r2', 'r3', 'r12', 'lr']);
  return new Set();
}

const X86_NO_DEST = /^(cmp|test|push|jmp|call|ret|nop|bt|ucomis[sd]|comis[sd]|leave|int3|ud2|hlt|endbr(32|64)|prefetch\w*|cpuid|lfence|mfence|sfence|pause)$/;
const ARM_NO_DEST = /^(cmp|cmn|tst|teq|str\w*|stp|stur\w*|stl\w*|stx\w*|b|bl|blr|br|b\.\w+|bc\.\w+|cbn?z|tbn?z|ret|nop|prfm|dmb|dsb|isb|hint|bti|paciasp|autiasp|brk|udf|svc|push|it\w*|bx|blx)$/;

/** Registers (canonical) an instruction writes. Over approximates for unknown forms. */
export function writes(arch: Arch, ins: Insn): string[] {
  const m = ins.mnemonic.replace(/\.[wn]$/, '');
  const base = m.split(' ').pop()!;
  const ops = splitOperands(ins.operands);
  if (arch === 'x86_64' || arch === 'x86') {
    if (X86_NO_DEST.test(base)) return base === 'push' ? [arch === 'x86' ? 'esp' : 'rsp'] : [];
    const out: string[] = [];
    if (base === 'pop') out.push(arch === 'x86' ? 'esp' : 'rsp');
    if (/^(mul|div|idiv|cdq|cqo|cwd|cdqe|cwde|cbw)$/.test(base) || (base === 'imul' && ops.length === 1)) out.push(...(arch === 'x86' ? ['eax', 'edx'] : ['rax', 'rdx']));
    if (base === 'xchg' || base === 'xadd' || base === 'cmpxchg') { for (const o of ops) { const c = canon(arch, o); if (c) out.push(c); } return out; }
    if (/^rep/.test(m) || (/^(movs|stos|lods|scas|cmps)[bwdq]?$/.test(base) && (ops.length === 0 || /[re]?[sd]i\]/.test(ins.operands)))) out.push(...(arch === 'x86' ? ['esi', 'edi', 'ecx', 'eax'] : ['rsi', 'rdi', 'rcx', 'rax']));
    const d = ops[0] ? canon(arch, ops[0]) : undefined;
    if (d) out.push(d);
    return out;
  }
  if (arch === 'arm64' || arch === 'arm') {
    if (ARM_NO_DEST.test(m)) {
      // pre/post index writeback updates the base
      const mem = ops.find((o) => o.startsWith('['));
      if (mem && (mem.endsWith('!') || ops[ops.length - 1] !== mem)) { const b = canon(arch, mem.slice(1).split(/[,\]]/)[0]!); if (b) return [b]; }
      if (m === 'bl' || m === 'blr' || m === 'blx') return [arch === 'arm64' ? 'x30' : 'lr'];
      return [];
    }
    const out: string[] = [];
    if (m === 'ldp' || m === 'ldpsw' || m === 'ldnp') { for (const o of ops.slice(0, 2)) { const c = canon(arch, o); if (c) out.push(c); } }
    else if (arch === 'arm' && (m === 'pop' || m.startsWith('ldm'))) {
      const list = ins.operands.slice(ins.operands.indexOf('{') + 1, ins.operands.indexOf('}'));
      for (const o of list.split(',')) { const c = canon(arch, o); if (c) out.push(c); }
    } else { const d = ops[0] ? canon(arch, ops[0]) : undefined; if (d) out.push(d); }
    const mem = ops.find((o) => o.startsWith('['));
    if (mem && (mem.endsWith('!') || (ops[ops.length - 1] !== mem && ops.indexOf(mem) >= 1 && ops.length > ops.indexOf(mem) + 1))) { const b = canon(arch, mem.slice(1).split(/[,\]]/)[0]!); if (b) out.push(b); }
    return out;
  }
  return [];
}
