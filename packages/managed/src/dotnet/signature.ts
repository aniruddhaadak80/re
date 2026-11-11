// Signature blob decoding (ECMA-335 II.23.2) into readable C#-like type names.
import { ByteReader, ParseError, LIMITS } from '../util.js';
import { readCompressedU, readCompressedI } from './metadata.js';

export type TypeNamer = (table: number, rid: number) => string;

const PRIM: Record<number, string> = {
  0x01: 'void', 0x02: 'bool', 0x03: 'char', 0x04: 'sbyte', 0x05: 'byte', 0x06: 'short', 0x07: 'ushort', 0x08: 'int', 0x09: 'uint',
  0x0a: 'long', 0x0b: 'ulong', 0x0c: 'float', 0x0d: 'double', 0x0e: 'string', 0x16: 'TypedReference', 0x18: 'nint', 0x19: 'nuint', 0x1c: 'object',
};

function typeDefOrRefEncoded(r: ByteReader, namer: TypeNamer): string {
  const v = readCompressedU(r);
  const tag = v & 3; const rid = v >>> 2;
  const table = tag === 0 ? 0x02 : tag === 1 ? 0x01 : 0x1b;
  return namer(table, rid);
}

/** Decode one Type from a signature reader. */
export function readType(r: ByteReader, namer: TypeNamer, depth = 0): string {
  if (depth > LIMITS.maxDepth) throw new ParseError('signature nesting too deep');
  const et = r.u8();
  const p = PRIM[et];
  if (p) return p;
  switch (et) {
    case 0x0f: return readType(r, namer, depth + 1) + '*';
    case 0x10: return 'ref ' + readType(r, namer, depth + 1);
    case 0x11: case 0x12: return typeDefOrRefEncoded(r, namer);
    case 0x13: return '!' + readCompressedU(r);
    case 0x1e: return '!!' + readCompressedU(r);
    case 0x14: {
      const t = readType(r, namer, depth + 1);
      const rank = readCompressedU(r);
      const nsizes = readCompressedU(r); for (let i = 0; i < nsizes && i < 64; i++) readCompressedU(r);
      const nlo = readCompressedU(r); for (let i = 0; i < nlo && i < 64; i++) readCompressedI(r);
      return `${t}[${','.repeat(Math.max(0, Math.min(rank, 32) - 1))}]`;
    }
    case 0x15: {
      const gen = readType(r, namer, depth + 1);
      const n = readCompressedU(r);
      if (n > 256) throw new ParseError('too many generic arguments');
      const args: string[] = [];
      for (let i = 0; i < n; i++) args.push(readType(r, namer, depth + 1));
      return `${gen.replace(/`\d+$/, '')}<${args.join(', ')}>`;
    }
    case 0x1b: { const s = readMethodSig(r, namer, depth + 1); return `method ${s.ret} *(${s.params.join(', ')})`; }
    case 0x1d: return readType(r, namer, depth + 1) + '[]';
    case 0x1f: { const t = typeDefOrRefEncoded(r, namer); return `modreq(${t}) ` + readType(r, namer, depth + 1); }
    case 0x20: { typeDefOrRefEncoded(r, namer); return readType(r, namer, depth + 1); }
    case 0x41: return '...';
    case 0x45: return readType(r, namer, depth + 1) + ' pinned';
    default: throw new ParseError(`unknown element type 0x${et.toString(16)}`, r.pos - 1);
  }
}

export interface MethodSig { callConv: number; hasThis: boolean; generic: number; ret: string; params: string[] }

export function readMethodSig(r: ByteReader, namer: TypeNamer, depth = 0): MethodSig {
  const cc = r.u8();
  let generic = 0;
  if (cc & 0x10) generic = readCompressedU(r);
  const n = readCompressedU(r);
  if (n > 4096) throw new ParseError('too many parameters');
  const ret = readType(r, namer, depth);
  const params: string[] = [];
  for (let i = 0; i < n && !r.eof(); i++) params.push(readType(r, namer, depth));
  return { callConv: cc, hasThis: (cc & 0x20) !== 0, generic, ret, params };
}

export function decodeMethodSig(blob: Uint8Array, namer: TypeNamer): MethodSig | undefined {
  try { return readMethodSig(new ByteReader(blob), namer); } catch { return undefined; }
}

export function decodeFieldSig(blob: Uint8Array, namer: TypeNamer): string | undefined {
  try {
    const r = new ByteReader(blob);
    if (r.u8() !== 0x06) return undefined;
    return readType(r, namer);
  } catch { return undefined; }
}

export function decodeTypeSpec(blob: Uint8Array, namer: TypeNamer): string {
  try { return readType(new ByteReader(blob), namer); } catch { return '<typespec>'; }
}

export function decodeMethodSpec(blob: Uint8Array, namer: TypeNamer): string[] {
  try {
    const r = new ByteReader(blob);
    if (r.u8() !== 0x0a) return [];
    const n = readCompressedU(r);
    const out: string[] = [];
    for (let i = 0; i < n && i < 256; i++) out.push(readType(r, namer));
    return out;
  } catch { return []; }
}

export function decodeLocalsSig(blob: Uint8Array, namer: TypeNamer): string[] {
  try {
    const r = new ByteReader(blob);
    if (r.u8() !== 0x07) return [];
    const n = readCompressedU(r);
    const out: string[] = [];
    for (let i = 0; i < n && i < 65536; i++) {
      // custom modifiers and pinned / byref are handled by readType
      out.push(readType(r, namer));
    }
    return out;
  } catch { return []; }
}
