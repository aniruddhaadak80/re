// AArch64, ARM/Thumb (and x86 as a browser fallback) decoding with Capstone 5 compiled to WASM
// (@alexaltea/capstone-js, BSD-3-Clause). Capstone's detail API is not exposed by that build, so
// control flow and pc relative operands are recovered from the operand text, which is stable.
import type { Arch, Decoder, Flow, Insn } from '../types.js';
import { hexOf, parseImm, splitOperands } from '../util.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type CsModule = any;

const ARM_CONDS = new Set(['eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le']);

export class CapstoneDecoder implements Decoder {
  readonly name = 'capstone';
  private readonly cs: CsModule;
  private readonly handles = new Map<string, CsModule>();
  constructor(cs: CsModule) { this.cs = cs; }

  supports(arch: Arch): boolean { return arch === 'arm64' || arch === 'arm' || arch === 'x86' || arch === 'x86_64'; }

  private handle(arch: Arch, thumb: boolean): CsModule {
    const key = arch + (thumb ? ':t' : '');
    let h = this.handles.get(key);
    if (!h) {
      const cs = this.cs;
      if (arch === 'arm64') h = new cs.Capstone(cs.ARCH_ARM64, cs.MODE_ARM);
      else if (arch === 'arm') h = new cs.Capstone(cs.ARCH_ARM, thumb ? cs.MODE_THUMB : cs.MODE_ARM);
      else if (arch === 'x86_64') h = new cs.Capstone(cs.ARCH_X86, cs.MODE_64);
      else h = new cs.Capstone(cs.ARCH_X86, cs.MODE_32);
      this.handles.set(key, h);
    }
    return h;
  }

  decode(arch: Arch, bytes: Uint8Array, address: number, maxInsns: number, thumb = false): Insn[] {
    const out: Insn[] = [];
    if (bytes.length === 0 || maxInsns <= 0) return out;
    const h = this.handle(arch, thumb && arch === 'arm');
    // Capstone decodes the whole buffer; feed it in slices so a cap on instructions caps work too.
    const maxBytes = Math.min(bytes.length, maxInsns * (arch === 'x86' || arch === 'x86_64' ? 15 : 4));
    let pos = 0;
    while (pos < maxBytes && out.length < maxInsns) {
      const chunk = bytes.subarray(pos, Math.min(maxBytes, pos + 4096));
      let list: CsModule[] = [];
      try { list = h.disasm(chunk, address + pos, maxInsns - out.length); } catch { list = []; }
      let used = 0;
      for (const ci of list) {
        const size: number = ci.size;
        // a decode that runs off the end of a chunk boundary is re-read in the next round
        out.push(this.normalize(arch, thumb, address + pos + used, bytes.subarray(pos + used, pos + used + size), String(ci.mnemonic), String(ci.op_str ?? '')));
        used += size;
        if (out.length >= maxInsns) break;
      }
      if (out.length >= maxInsns) break;
      pos += used;
      if (used < chunk.length) {
        // stopped early: invalid bytes (unless the chunk merely cut an instruction)
        const remain = maxBytes - pos;
        if (used > 0 && chunk.length === 4096 && remain > 0 && used >= chunk.length - 16) continue;
        const w = arch === 'arm64' || (arch === 'arm' && !thumb) ? 4 : arch === 'arm' ? 2 : 1;
        if (pos < bytes.length) out.push({ address: address + pos, size: w, bytes: hexOf(bytes.subarray(pos, pos + w)), mnemonic: '(bad)', operands: '', flow: 'invalid', imms: [] });
        break;
      }
    }
    return out;
  }

  private normalize(arch: Arch, thumb: boolean, address: number, raw: Uint8Array, mnemonic: string, operands: string): Insn {
    const insn: Insn = { address, size: raw.length, bytes: hexOf(raw), mnemonic, operands, flow: 'seq', imms: [] };
    if (thumb) insn.thumb = true;
    const ops = splitOperands(operands);
    if (arch === 'arm64') a64Flow(insn, ops);
    else if (arch === 'arm') armFlow(insn, ops, thumb);
    else x86Flow(insn, ops);
    return insn;
  }
}

function lastImm(ops: string[]): number | undefined {
  return parseImm(ops[ops.length - 1]);
}

function collectImms(insn: Insn, ops: string[]): void {
  for (const o of ops) {
    const v = parseImm(o);
    if (v !== undefined) insn.imms.push(v);
  }
}

function a64Flow(insn: Insn, ops: string[]): void {
  const m = insn.mnemonic;
  let flow: Flow = 'seq';
  if (m === 'b') { flow = 'jump'; insn.target = lastImm(ops); }
  else if (m.startsWith('b.') || m.startsWith('bc.')) { flow = 'cjump'; insn.target = lastImm(ops); }
  else if (m === 'bl') { flow = 'call'; insn.target = lastImm(ops); }
  else if (m === 'cbz' || m === 'cbnz' || m === 'tbz' || m === 'tbnz') { flow = 'cjump'; insn.target = lastImm(ops); }
  else if (m.startsWith('blr')) flow = 'icall';
  else if (m === 'br' || m.startsWith('bra')) flow = 'ijump';
  else if (m === 'ret' || m === 'retaa' || m === 'retab' || m === 'eret') flow = 'ret';
  else if (m === 'brk' || m === 'udf' || m === 'hlt') flow = 'trap';
  else if (m === 'adr' || m === 'adrp') { const v = lastImm(ops); if (v !== undefined) insn.memAddr = v; return void (insn.flow = 'seq'); }
  else if ((m === 'ldr' || m === 'ldrsw' || m === 'prfm') && ops.length === 2 && ops[1]!.startsWith('#')) { const v = lastImm(ops); if (v !== undefined) insn.memAddr = v; }
  else collectImms(insn, ops);
  if ((flow === 'jump' || flow === 'call' || flow === 'cjump') && insn.target === undefined) flow = flow === 'call' ? 'icall' : flow === 'jump' ? 'ijump' : 'cjump';
  insn.flow = flow;
}

function armFlow(insn: Insn, ops: string[], thumb: boolean): void {
  let m = insn.mnemonic;
  if (m.endsWith('.w') || m.endsWith('.n')) m = m.slice(0, -2);
  const cond = (base: string): boolean => m.length === base.length + 2 && m.startsWith(base) && ARM_CONDS.has(m.slice(base.length));
  const pcRelBase = ((insn.address + (thumb ? 4 : 8)) & ~3) >>> 0;
  let flow: Flow = 'seq';
  const regList = ops.join(',');
  if (m === 'b') { flow = 'jump'; insn.target = lastImm(ops); }
  else if (cond('b')) { flow = 'cjump'; insn.target = lastImm(ops); }
  else if (m === 'bl' || m === 'blx' || cond('bl')) {
    const t = lastImm(ops);
    if (t !== undefined) { flow = 'call'; insn.target = t; } else flow = 'icall';
  } else if (m === 'cbz' || m === 'cbnz') { flow = 'cjump'; insn.target = lastImm(ops); }
  else if (m === 'bx') flow = ops[0] === 'lr' ? 'ret' : 'ijump';
  else if ((m === 'pop' || m === 'ldm' || m === 'ldmia' || m === 'ldmfd') && /\bpc\b/.test(regList)) flow = 'ret';
  else if (m === 'ldr' && ops[0] === 'pc') flow = ops[1]?.startsWith('[sp') ? 'ret' : 'ijump';
  else if (m === 'mov' && ops[0] === 'pc') flow = ops[1] === 'lr' ? 'ret' : 'ijump';
  else if (m === 'tbb' || m === 'tbh') flow = 'ijump';
  else if (m === 'udf' || m === 'bkpt') flow = 'trap';
  if (flow === 'seq') {
    // pc relative literal loads and adr
    const mem = ops[1];
    if ((m === 'ldr' || m === 'vldr' || m === 'ldrd') && mem && mem.startsWith('[pc')) {
      const imm = mem.includes(',') ? parseImm(mem.slice(mem.indexOf(',') + 1, -1)) : 0;
      if (imm !== undefined) insn.memAddr = (pcRelBase + imm) >>> 0;
    } else if (m === 'adr' && ops[1]) {
      const imm = parseImm(ops[1]);
      if (imm !== undefined) insn.memAddr = (pcRelBase + imm) >>> 0;
    } else collectImms(insn, ops);
  }
  if ((flow === 'jump' || flow === 'cjump') && insn.target === undefined) flow = flow === 'jump' ? 'ijump' : 'seq';
  insn.flow = flow;
}

function x86Flow(insn: Insn, ops: string[]): void {
  const m = insn.mnemonic;
  let flow: Flow = 'seq';
  const op0 = ops[0] ?? '';
  const isLit = /^0x[0-9a-f]+$/.test(op0);
  if (m === 'call') flow = isLit ? 'call' : 'icall';
  else if (m === 'jmp') flow = isLit ? 'jump' : 'ijump';
  else if (m.startsWith('j') || m.startsWith('loop')) flow = 'cjump';
  else if (m.startsWith('ret') || m.startsWith('iret')) flow = 'ret';
  else if (m === 'int3' || m === 'ud2' || m === 'hlt') flow = 'trap';
  if (isLit && flow !== 'seq') insn.target = parseInt(op0.slice(2), 16);
  for (const o of ops) {
    const b = o.indexOf('[');
    if (b < 0) continue;
    const inner = o.slice(b + 1, o.indexOf(']', b) >>> 0).replace(/\s+/g, '');
    if (inner.startsWith('rip+') || inner.startsWith('rip-')) {
      const d = parseImm(inner.slice(4));
      if (d !== undefined) insn.memAddr = insn.address + insn.size + (inner[3] === '-' ? -d : d);
    } else {
      const d = parseImm(inner);
      if (d !== undefined) insn.memAddr = d;
    }
  }
  if ((flow === 'icall' || flow === 'ijump') && insn.memAddr !== undefined) insn.viaMemory = true;
  if (flow === 'seq') for (const o of ops) { if (/^-?0x[0-9a-f]+$|^-?[0-9]+$/.test(o)) { const v = parseImm(o); if (v !== undefined) insn.imms.push(v); } }
  insn.flow = flow;
}
