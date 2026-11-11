// x86 / x86-64 decoding with iced-x86 (MIT, Rust compiled to WebAssembly).
import type { Arch, Decoder, Flow, Insn } from '../types.js';
import { hexOf } from '../util.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type IcedModule = any;

const PREFIXES = new Set(['rep', 'repe', 'repne', 'lock', 'bnd', 'notrack', 'xacquire', 'xrelease', 'data16', 'addr32']);

/** Instruction record whose hex bytes are computed on first use. */
class LazyInsn implements Insn {
  address: number; size: number; mnemonic: string; operands: string; flow: Flow; imms: number[];
  target?: number; memAddr?: number; viaMemory?: boolean;
  private raw: Uint8Array | undefined;
  private hex: string | undefined;
  constructor(address: number, size: number, raw: Uint8Array, mnemonic: string, operands: string, flow: Flow, imms: number[]) {
    this.address = address; this.size = size; this.raw = raw; this.mnemonic = mnemonic; this.operands = operands; this.flow = flow; this.imms = imms;
  }
  get bytes(): string {
    if (this.hex === undefined) { this.hex = hexOf(this.raw ?? new Uint8Array(0)); this.raw = undefined; }
    return this.hex;
  }
  toJSON() { return { address: this.address, size: this.size, bytes: this.bytes, mnemonic: this.mnemonic, operands: this.operands, flow: this.flow, target: this.target, memAddr: this.memAddr, viaMemory: this.viaMemory, imms: this.imms }; }
}

export class IcedDecoder implements Decoder {
  readonly name = 'iced-x86';
  private readonly m: IcedModule;
  private readonly fmt: IcedModule;
  constructor(m: IcedModule) {
    this.m = m;
    const f = new m.Formatter(m.FormatterSyntax.Intel);
    f.hexPrefix = '0x';
    f.hexSuffix = '';
    f.uppercaseHex = false;
    f.spaceAfterOperandSeparator = true;
    f.branchLeadingZeros = false;
    f.leadingZeros = false;
    f.showBranchSize = false;
    f.ripRelativeAddresses = false;
    this.fmt = f;
  }

  supports(arch: Arch): boolean { return arch === 'x86' || arch === 'x86_64'; }

  decode(arch: Arch, bytes: Uint8Array, address: number, maxInsns: number): Insn[] {
    const m = this.m;
    const out: Insn[] = [];
    if (bytes.length === 0 || maxInsns <= 0) return out;
    const bitness = arch === 'x86_64' ? 64 : 32;
    const dec = new m.Decoder(bitness, bytes, m.DecoderOptions.None);
    const ins = new m.Instruction();
    try {
      dec.ip = BigInt(address);
      let pos = 0;
      while (dec.canDecode && out.length < maxInsns) {
        dec.decodeOut(ins);
        const len: number = ins.length;
        const ip = address + pos;
        const raw = bytes.subarray(pos, pos + len);
        pos += len;
        if (ins.isInvalid) {
          out.push({ address: ip, size: Math.max(1, len), bytes: hexOf(raw.subarray(0, Math.max(1, len))), mnemonic: '(bad)', operands: '', flow: 'invalid', imms: [] });
          break;
        }
        const full: string = this.fmt.format(ins);
        const sp = full.indexOf(' ');
        let mnemonic = sp < 0 ? full : full.slice(0, sp);
        let operands = sp < 0 ? '' : full.slice(sp + 1);
        // prefixes (rep, lock, bnd, notrack) stay with the mnemonic
        while (PREFIXES.has(mnemonic) && operands) {
          const k = operands.indexOf(' ');
          if (k < 0) { mnemonic += ' ' + operands; operands = ''; break; }
          mnemonic += ' ' + operands.slice(0, k);
          operands = operands.slice(k + 1);
        }
        const fc: number = ins.flowControl;
        const FC = m.FlowControl;
        let flow: Flow = 'seq';
        let target: number | undefined;
        if (fc === FC.UnconditionalBranch) flow = 'jump';
        else if (fc === FC.ConditionalBranch) flow = 'cjump';
        else if (fc === FC.IndirectBranch) flow = 'ijump';
        else if (fc === FC.Return) flow = 'ret';
        else if (fc === FC.Call) flow = 'call';
        else if (fc === FC.IndirectCall) flow = 'icall';
        else if (fc === FC.Exception) flow = 'trap';
        else if (fc === FC.Interrupt && mnemonic === 'int3') flow = 'trap';
        else if (mnemonic === 'hlt') flow = 'trap';
        let memAddr: number | undefined;
        let viaMemory = false;
        const imms: number[] = [];
        const n: number = ins.opCount;
        for (let i = 0; i < n; i++) {
          const k: number = ins.opKind(i);
          if (k === m.OpKind.NearBranch16 || k === m.OpKind.NearBranch32 || k === m.OpKind.NearBranch64) {
            target = Number(ins.nearBranchTarget);
          } else if (k === m.OpKind.Memory) {
            if (ins.isIpRelMemoryOperand) memAddr = Number(ins.ipRelMemoryAddress);
            else if (ins.memoryBase === m.Register.None && ins.memoryIndex === m.Register.None) memAddr = Number(BigInt.asUintN(bitness, ins.memoryDisplacementU64));
            if ((flow === 'icall' || flow === 'ijump') && memAddr !== undefined) viaMemory = true;
          } else if (k >= m.OpKind.Immediate8 && k <= m.OpKind.Immediate32to64) {
            const v = Number(BigInt.asIntN(64, ins.immediate(i)));
            imms.push(v);
          }
        }
        if ((flow === 'jump' || flow === 'call' || flow === 'cjump') && target === undefined) flow = flow === 'call' ? 'icall' : flow === 'jump' ? 'ijump' : 'cjump';
        const insn: Insn = new LazyInsn(ip, len, raw, mnemonic, operands, flow, imms);
        if (target !== undefined) insn.target = target;
        if (memAddr !== undefined) insn.memAddr = memAddr;
        if (viaMemory) insn.viaMemory = true;
        out.push(insn);
      }
    } finally {
      ins.free();
      dec.free();
    }
    return out;
  }
}
