// CIL opcode table (ECMA-335 III) and a method body decoder.
import { ByteReader, ParseError, LIMITS } from '../util.js';

/** Operand kinds. */
export type Operand = 'none' | 'i8' | 'u8' | 'i32' | 'i64' | 'r4' | 'r8' | 'br8' | 'br32' | 'tok' | 'var8' | 'var16' | 'switch';

const ONE: Record<number, [string, Operand]> = {};
const TWO: Record<number, [string, Operand]> = {};

function def(table: Record<number, [string, Operand]>, start: number, names: string, operand: Operand = 'none'): void {
  names.split(' ').forEach((n, i) => { if (n !== '-') table[start + i] = [n, operand]; });
}

def(ONE, 0x00, 'nop break ldarg.0 ldarg.1 ldarg.2 ldarg.3 ldloc.0 ldloc.1 ldloc.2 ldloc.3 stloc.0 stloc.1 stloc.2 stloc.3');
def(ONE, 0x0e, 'ldarg.s ldarga.s starg.s ldloc.s ldloca.s stloc.s', 'var8');
def(ONE, 0x14, 'ldnull ldc.i4.m1 ldc.i4.0 ldc.i4.1 ldc.i4.2 ldc.i4.3 ldc.i4.4 ldc.i4.5 ldc.i4.6 ldc.i4.7 ldc.i4.8');
def(ONE, 0x1f, 'ldc.i4.s', 'i8');
def(ONE, 0x20, 'ldc.i4', 'i32');
def(ONE, 0x21, 'ldc.i8', 'i64');
def(ONE, 0x22, 'ldc.r4', 'r4');
def(ONE, 0x23, 'ldc.r8', 'r8');
def(ONE, 0x25, 'dup pop');
def(ONE, 0x27, 'jmp call calli', 'tok');
def(ONE, 0x2a, 'ret');
def(ONE, 0x2b, 'br.s brfalse.s brtrue.s beq.s bge.s bgt.s ble.s blt.s bne.un.s bge.un.s bgt.un.s ble.un.s blt.un.s', 'br8');
def(ONE, 0x38, 'br brfalse brtrue beq bge bgt ble blt bne.un bge.un bgt.un ble.un blt.un', 'br32');
def(ONE, 0x45, 'switch', 'switch');
def(ONE, 0x46, 'ldind.i1 ldind.u1 ldind.i2 ldind.u2 ldind.i4 ldind.u4 ldind.i8 ldind.i ldind.r4 ldind.r8 ldind.ref stind.ref stind.i1 stind.i2 stind.i4 stind.i8 stind.r4 stind.r8 add sub mul div div.un rem rem.un and or xor shl shr shr.un neg not conv.i1 conv.i2 conv.i4 conv.i8 conv.r4 conv.r8 conv.u4 conv.u8');
def(ONE, 0x6f, 'callvirt cpobj ldobj ldstr newobj castclass isinst', 'tok');
def(ONE, 0x76, 'conv.r.un');
def(ONE, 0x79, 'unbox', 'tok');
def(ONE, 0x7a, 'throw');
def(ONE, 0x7b, 'ldfld ldflda stfld ldsfld ldsflda stsfld stobj', 'tok');
def(ONE, 0x82, 'conv.ovf.i1.un conv.ovf.i2.un conv.ovf.i4.un conv.ovf.i8.un conv.ovf.u1.un conv.ovf.u2.un conv.ovf.u4.un conv.ovf.u8.un conv.ovf.i.un conv.ovf.u.un');
def(ONE, 0x8c, 'box newarr', 'tok');
def(ONE, 0x8e, 'ldlen');
def(ONE, 0x8f, 'ldelema', 'tok');
def(ONE, 0x90, 'ldelem.i1 ldelem.u1 ldelem.i2 ldelem.u2 ldelem.i4 ldelem.u4 ldelem.i8 ldelem.i ldelem.r4 ldelem.r8 ldelem.ref stelem.i stelem.i1 stelem.i2 stelem.i4 stelem.i8 stelem.r4 stelem.r8 stelem.ref');
def(ONE, 0xa3, 'ldelem stelem unbox.any', 'tok');
def(ONE, 0xb3, 'conv.ovf.i1 conv.ovf.u1 conv.ovf.i2 conv.ovf.u2 conv.ovf.i4 conv.ovf.u4 conv.ovf.i8 conv.ovf.u8');
def(ONE, 0xc2, 'refanyval', 'tok');
def(ONE, 0xc3, 'ckfinite');
def(ONE, 0xc6, 'mkrefany', 'tok');
def(ONE, 0xd0, 'ldtoken', 'tok');
def(ONE, 0xd1, 'conv.u2 conv.u1 conv.i conv.ovf.i conv.ovf.u add.ovf add.ovf.un mul.ovf mul.ovf.un sub.ovf sub.ovf.un endfinally');
def(ONE, 0xdd, 'leave', 'br32');
def(ONE, 0xde, 'leave.s', 'br8');
def(ONE, 0xdf, 'stind.i conv.u');
def(TWO, 0x00, 'arglist ceq cgt cgt.un clt clt.un');
def(TWO, 0x06, 'ldftn ldvirtftn', 'tok');
def(TWO, 0x09, 'ldarg ldarga starg ldloc ldloca stloc', 'var16');
def(TWO, 0x0f, 'localloc - endfilter');
def(TWO, 0x12, 'unaligned.', 'u8');
def(TWO, 0x13, 'volatile. tail.');
def(TWO, 0x15, 'initobj constrained.', 'tok');
def(TWO, 0x17, 'cpblk initblk');
def(TWO, 0x19, 'no.', 'u8');
def(TWO, 0x1a, 'rethrow');
def(TWO, 0x1c, 'sizeof', 'tok');
def(TWO, 0x1d, 'refanytype readonly.');

export const CIL_ONE_BYTE = ONE;
export const CIL_TWO_BYTE = TWO;

export interface CilInstruction {
  /** offset inside the method body code */
  offset: number;
  opcode: string;
  /** raw opcode value, two byte opcodes as 0xfeXX */
  code: number;
  size: number;
  operandKind: Operand;
  operand?: number | string | number[];
  /** metadata token for tok operands */
  token?: number;
  /** branch target(s) */
  target?: number | number[];
  /** resolved text for tokens, filled by the caller */
  text?: string;
}

export interface ExceptionClause { kind: 'catch' | 'filter' | 'finally' | 'fault'; tryOffset: number; tryLength: number; handlerOffset: number; handlerLength: number; classTokenOrFilter: number }

export interface MethodBody {
  /** file offset of the header */
  offset: number;
  format: 'tiny' | 'fat';
  headerSize: number;
  maxStack: number;
  codeSize: number;
  localVarSigTok: number;
  initLocals: boolean;
  codeOffset: number;
  code: Uint8Array;
  clauses: ExceptionClause[];
}

/** Read a method body header, code and exception sections at a file offset. */
export function readMethodBody(bytes: Uint8Array, offset: number): MethodBody {
  const r = new ByteReader(bytes, offset);
  const b = r.u8();
  if ((b & 3) === 2) {
    const codeSize = b >> 2;
    const code = r.take(codeSize);
    return { offset, format: 'tiny', headerSize: 1, maxStack: 8, codeSize, localVarSigTok: 0, initLocals: false, codeOffset: offset + 1, code, clauses: [] };
  }
  if ((b & 3) !== 3) throw new ParseError('bad method header', offset);
  r.seek(offset);
  const flagsSize = r.u16();
  const headerSize = (flagsSize >> 12) * 4;
  if (headerSize < 12) throw new ParseError('bad fat header size', offset);
  const maxStack = r.u16();
  const codeSize = r.u32();
  const localVarSigTok = r.u32();
  r.seek(offset + headerSize);
  if (codeSize > bytes.length) throw new ParseError('code size past end', offset);
  const codeOffset = r.pos;
  const code = r.take(codeSize);
  const clauses: ExceptionClause[] = [];
  let more = (flagsSize & 0x8) !== 0;
  let guard = 0;
  while (more && guard++ < 64) {
    while (r.pos % 4) r.pos++;
    const kind = r.u8();
    const fat = (kind & 0x40) !== 0;
    more = (kind & 0x80) !== 0;
    let dataSize: number;
    if (fat) { dataSize = r.u8() | (r.u8() << 8) | (r.u8() << 16); } else { dataSize = r.u8(); r.skip(2); }
    const end = r.pos - 4 + dataSize;
    if ((kind & 0x3f) === 1) {
      const n = Math.floor((dataSize - 4) / (fat ? 24 : 12));
      for (let i = 0; i < n && clauses.length < 4096; i++) {
        const flags = fat ? r.u32() : r.u16();
        const c: ExceptionClause = {
          kind: flags === 1 ? 'filter' : flags === 2 ? 'finally' : flags === 4 ? 'fault' : 'catch',
          tryOffset: fat ? r.u32() : r.u16(), tryLength: fat ? r.u32() : r.u8(),
          handlerOffset: fat ? r.u32() : r.u16(), handlerLength: fat ? r.u32() : r.u8(),
          classTokenOrFilter: r.u32(),
        };
        clauses.push(c);
      }
    }
    if (end <= r.pos - 1 && dataSize < 4) break;
    r.seek(Math.min(bytes.length, end));
  }
  return { offset, format: 'fat', headerSize, maxStack, codeSize, localVarSigTok, initLocals: (flagsSize & 0x10) !== 0, codeOffset, code, clauses };
}

/** Decode CIL instructions. Stops at the end of code or an undefined opcode. */
export function decodeCil(code: Uint8Array, max = LIMITS.maxInstructions): { instructions: CilInstruction[]; error?: string } {
  const r = new ByteReader(code);
  const out: CilInstruction[] = [];
  try {
    while (!r.eof() && out.length < max) {
      const offset = r.pos;
      let op = r.u8();
      let entry: [string, Operand] | undefined;
      let codeVal = op;
      if (op === 0xfe) { op = r.u8(); entry = TWO[op]; codeVal = 0xfe00 | op; } else entry = ONE[op];
      if (!entry) return { instructions: out, error: `undefined opcode 0x${codeVal.toString(16)} at IL_${offset.toString(16).padStart(4, '0')}` };
      const [name, kind] = entry;
      const ins: CilInstruction = { offset, opcode: name, code: codeVal, size: 0, operandKind: kind };
      switch (kind) {
        case 'i8': ins.operand = r.i8(); break;
        case 'u8': case 'var8': ins.operand = r.u8(); break;
        case 'var16': ins.operand = r.u16(); break;
        case 'i32': ins.operand = r.i32(); break;
        case 'i64': ins.operand = r.i64().toString(); break;
        case 'r4': ins.operand = r.f32(); break;
        case 'r8': ins.operand = r.f64(); break;
        case 'br8': { const d = r.i8(); ins.operand = d; ins.target = r.pos + d; break; }
        case 'br32': { const d = r.i32(); ins.operand = d; ins.target = r.pos + d; break; }
        case 'tok': ins.token = r.u32(); ins.operand = ins.token; break;
        case 'switch': {
          const n = r.u32();
          if (n > 65536 || n * 4 > r.remaining()) throw new ParseError('switch table past end', offset);
          const deltas: number[] = [];
          for (let i = 0; i < n; i++) deltas.push(r.i32());
          ins.operand = deltas; ins.target = deltas.map((d) => r.pos + d);
          break;
        }
        default: break;
      }
      ins.size = r.pos - offset;
      out.push(ins);
    }
  } catch (e) {
    return { instructions: out, error: e instanceof Error ? e.message : String(e) };
  }
  return { instructions: out };
}

export function ilLabel(o: number): string { return 'IL_' + o.toString(16).padStart(4, '0'); }
