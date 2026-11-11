// Small register value tracker for RISC style address building (AArch64 adrp+add/ldr, ARM add ip,pc,#imm)
// and for indirect calls through a register loaded from an import slot. Runs over one basic block.
import type { Arch, Insn } from '../types.js';
import { parseImm, splitOperands } from '../util.js';

function norm(reg: string): string {
  const r = reg.trim().toLowerCase();
  if (/^w([0-9]|[12][0-9]|30)$/.test(r)) return 'x' + r.slice(1);
  return r;
}

const STORE_LOAD = /^(ldr|ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldur|ldp|str|strb|strh|stur|stp|ldar|stlr|prfm|vldr|vstr)$/;

/** Mutates insns: sets memAddr on instructions whose address operand is derived from tracked registers,
 * and marks register indirect calls/jumps whose register was loaded from a slot in `slots`. */
export function trackBlock(arch: Arch, insns: Insn[], slots: (addr: number) => boolean, readU32?: (addr: number) => number | undefined, pcThunk?: (target: number) => string | undefined): void {
  if (arch === 'x86') return trackX86(insns, pcThunk);
  if (arch !== 'arm64' && arch !== 'arm') return;
  const regs = new Map<string, number>();
  const loaded = new Map<string, number>();
  for (const ins of insns) {
    const m = ins.mnemonic.replace(/\.[wn]$/, '');
    const ops = splitOperands(ins.operands);
    const dst = ops[0] ? norm(ops[0]) : '';
    if (m === 'adrp' || (m === 'adr' && arch === 'arm64')) {
      if (ins.memAddr !== undefined) regs.set(dst, ins.memAddr);
      if (m === 'adrp') delete ins.memAddr;
      loaded.delete(dst);
      continue;
    }
    if ((ins.flow === 'icall' || ins.flow === 'ijump') && !STORE_LOAD.test(m)) {
      const r = norm(ops[ops.length - 1] ?? '');
      const s = loaded.get(r);
      if (s !== undefined && ins.memAddr === undefined) { ins.memAddr = s; ins.viaMemory = true; }
      if (ins.flow === 'icall') { regs.clear(); loaded.clear(); }
      continue;
    }
    if (ins.flow === 'call') { regs.clear(); loaded.clear(); continue; }
    if (arch === 'arm' && m === 'add' && ops.length === 3 && (norm(ops[1]!) === 'pc' || norm(ops[2]!) === 'pc')) {
      const other = norm(ops[1]!) === 'pc' ? norm(ops[2]!) : norm(ops[1]!);
      const v = regs.get(other);
      if (v !== undefined) {
        const r = (ins.address + (ins.thumb ? 4 : 8) + v) >>> 0;
        regs.set(dst, r);
        ins.memAddr = r;
        loaded.delete(dst);
        continue;
      }
    }
    if (m === 'add' && ops.length >= 3) {
      const src = norm(ops[1]!);
      let base = regs.get(src);
      if (arch === 'arm' && src === 'pc') base = ins.address + (ins.thumb ? 4 : 8);
      let imm = parseImm(ops[2]);
      if (imm !== undefined && ops[3]) {
        const sh = ops[3].match(/^lsl #(\d+)$/);
        if (sh) imm *= 2 ** Number(sh[1]);
        else {
          // ARM rotated immediate printed as "#imm, #rot"
          const rot = parseImm(ops[3]);
          if (rot !== undefined && arch === 'arm') imm = ((imm >>> rot) | (imm << (32 - rot))) >>> 0;
        }
      }
      if (base !== undefined && imm !== undefined) {
        const v = arch === 'arm' ? (base + imm) >>> 0 : base + imm;
        regs.set(dst, v);
        if (src !== 'pc' || arch === 'arm') ins.memAddr = v;
        loaded.delete(dst);
        continue;
      }
    }
    if ((m === 'movw' || m === 'movt') && ops.length === 2) {
      const imm = parseImm(ops[1]);
      if (imm !== undefined) {
        if (m === 'movw') regs.set(dst, imm & 0xffff);
        else if (regs.has(dst)) {
          const v = (((imm & 0xffff) << 16) | (regs.get(dst)! & 0xffff)) >>> 0;
          regs.set(dst, v);
          ins.memAddr = v;
        }
        loaded.delete(dst);
        continue;
      }
    }
    if (m === 'mov' && ops.length === 2) {
      const src = norm(ops[1]!);
      if (regs.has(src)) { regs.set(dst, regs.get(src)!); loaded.delete(dst); continue; }
      if (loaded.has(src)) { loaded.set(dst, loaded.get(src)!); regs.delete(dst); continue; }
    }
    if (STORE_LOAD.test(m)) {
      const memOp = ops.find((o) => o.startsWith('['));
      if (memOp) {
        const close = memOp.indexOf(']');
        const inner = memOp.slice(1, close < 0 ? undefined : close);
        const parts = inner.split(',').map((x) => x.trim());
        const base = regs.get(norm(parts[0] ?? ''));
        const disp = parts[1] ? parseImm(parts[1]) : 0;
        if (base !== undefined && disp !== undefined && ins.memAddr === undefined) {
          ins.memAddr = arch === 'arm' ? (base + disp) >>> 0 : base + disp;
          if (memOp.endsWith('!')) regs.set(norm(parts[0]!), ins.memAddr);
        }
        if (m.startsWith('ld') || m === 'vldr') {
          const isPair = m === 'ldp';
          regs.delete(dst);
          if (arch === 'arm' && m === 'ldr' && inner.startsWith('pc') && ins.memAddr !== undefined && readU32) {
            const lit = readU32(ins.memAddr);
            if (lit !== undefined) regs.set(dst, lit);
          }
          loaded.delete(dst);
          if (isPair && ops[1]) { regs.delete(norm(ops[1])); loaded.delete(norm(ops[1])); }
          if (!isPair && ins.memAddr !== undefined && slots(ins.memAddr)) loaded.set(dst, ins.memAddr);
          // ARM: "ldr pc, [ip, #x]!" in a PLT entry
          if (dst === 'pc' && ins.memAddr !== undefined) ins.viaMemory = true;
        }
        continue;
      }
    }
    // any other write to the destination register kills what we knew
    if (dst && !m.startsWith('st') && !m.startsWith('cmp') && !m.startsWith('tst') && !m.startsWith('cmn') && m !== 'push') {
      regs.delete(dst);
      loaded.delete(dst);
    }
  }
}

/** x86-32 PIC: call $+5 / pop reg and __x86.get_pc_thunk.* establish a base register; then
 * add reg, imm and [reg+disp] operands resolve to absolute addresses. */
function trackX86(insns: Insn[], pcThunk?: (target: number) => string | undefined): void {
  const regs = new Map<string, number>();
  let pendingPop: number | undefined;
  for (const ins of insns) {
    const ops = splitOperands(ins.operands);
    const dst = (ops[0] ?? '').toLowerCase();
    const next = ins.address + ins.size;
    if (ins.mnemonic === 'call') {
      if (ins.target === next) { pendingPop = next; continue; }
      const r = ins.target !== undefined && pcThunk ? pcThunk(ins.target) : undefined;
      if (r) { regs.set(r, next); continue; }
      // calls clobber eax, ecx, edx
      regs.delete('eax'); regs.delete('ecx'); regs.delete('edx');
      continue;
    }
    if (ins.mnemonic === 'pop' && pendingPop !== undefined) { regs.set(dst, pendingPop); pendingPop = undefined; continue; }
    pendingPop = undefined;
    if (ins.mnemonic === 'add' && regs.has(dst) && ops[1]) {
      const v = parseImm(ops[1]);
      if (v !== undefined) { regs.set(dst, (regs.get(dst)! + v) >>> 0); continue; }
    }
    if (ins.memAddr === undefined) {
      for (const o of ops) {
        const b = o.indexOf('[');
        if (b < 0) continue;
        const inner = o.slice(b + 1, o.indexOf(']', b)).replace(/\s+/g, '');
        const mm = /^([a-z]{3})([+-])(0x[0-9a-f]+|[0-9]+)$/.exec(inner);
        if (mm && regs.has(mm[1]!)) {
          const d = parseImm(mm[3]) ?? 0;
          ins.memAddr = (regs.get(mm[1]!)! + (mm[2] === '-' ? -d : d)) >>> 0;
        }
      }
    }
    if (dst && !dst.startsWith('[') && ins.mnemonic !== 'cmp' && ins.mnemonic !== 'test' && ins.mnemonic !== 'push') regs.delete(dst);
  }
}
