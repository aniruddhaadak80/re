// Go pclntab reader (Go 1.16 through current): recovers function names and entry points from
// Go binaries, even when the regular symbol table is stripped.
import { BR } from '../util.js';
import type { BinaryImage, Sym } from '../types.js';

const MAGICS = new Map<number, string>([[0xfffffff1, 'go1.20+'], [0xfffffff0, 'go1.18-1.19'], [0xfffffffa, 'go1.16-1.17']]);
const MAX_FUNCS = 1_000_000;

function validHeader(r: BR, o: number, bits: 32 | 64): boolean {
  if (!MAGICS.has(r.u32(o))) return false;
  if (r.u8(o + 4) !== 0 || r.u8(o + 5) !== 0) return false;
  const quantum = r.u8(o + 6);
  const ptr = r.u8(o + 7);
  return [1, 2, 4].includes(quantum) && ptr === bits / 8;
}

/** Finds the pclntab inside the image (by section name, then by scanning read only data). */
function locate(img: BinaryImage): number {
  const r = new BR(img.bytes, img.endian === 'le');
  const named = img.sections.find((s) => s.name === '.gopclntab' || s.name === '__gopclntab');
  if (named && named.fsize > 16 && validHeader(r, named.offset, img.bits)) return named.offset;
  // scan non exec sections (PE keeps it in .rdata) for a valid header
  const b = img.bytes;
  const order = img.sections.filter((s) => !s.exec && s.fsize > 64);
  for (const s of order) {
    const end = Math.min(b.length - 8, s.offset + s.fsize - 8);
    for (let o = s.offset - (s.offset % 4); o < end; o += 4) {
      if (b[o + 3] === 0xff && b[o + 2] === 0xff && b[o + 1] === 0xff && (b[o]! & 0xf0) === 0xf0 && validHeader(r, o, img.bits)) return o;
    }
  }
  return -1;
}

export function readGoPclntab(img: BinaryImage): { symbols: Sym[]; version?: string } {
  const at = locate(img);
  if (at < 0) return { symbols: [] };
  const r = new BR(img.bytes, img.endian === 'le');
  const magic = r.u32(at);
  const ps = img.bits / 8;
  const word = (i: number) => (ps === 8 ? r.u64(at + 8 + i * 8) : r.u32(at + 8 + i * 4));
  const nfunc = Math.min(word(0), MAX_FUNCS);
  const out: Sym[] = [];
  let textStart = 0;
  let funcnameOff: number, pclnOff: number;
  if (magic === 0xfffffffa) {
    funcnameOff = word(2);
    pclnOff = word(6);
  } else {
    textStart = word(2);
    funcnameOff = word(3);
    pclnOff = word(7);
  }
  const functab = at + pclnOff;
  for (let i = 0; i < nfunc; i++) {
    let entry: number, funcOff: number;
    if (magic === 0xfffffffa) {
      entry = ps === 8 ? r.u64(functab + i * 16) : r.u32(functab + i * 8);
      funcOff = ps === 8 ? r.u64(functab + i * 16 + 8) : r.u32(functab + i * 8 + 4);
    } else {
      entry = textStart + r.u32(functab + i * 8);
      funcOff = r.u32(functab + i * 8 + 4);
    }
    const fo = functab + funcOff;
    if (!r.ok(fo, 8)) break;
    const nameOff = magic === 0xfffffffa ? r.i32(fo + ps) : r.i32(fo + 4);
    const name = r.cstr(at + funcnameOff + nameOff, 512);
    // size: next entry minus this one
    let next: number;
    if (i + 1 < nfunc) next = magic === 0xfffffffa ? (ps === 8 ? r.u64(functab + (i + 1) * 16) : r.u32(functab + (i + 1) * 8)) : textStart + r.u32(functab + (i + 1) * 8);
    else next = entry;
    if (!name || !entry) continue;
    out.push({ addr: entry, name, size: next > entry && next - entry < 1 << 24 ? next - entry : undefined, kind: 'func', source: 'gopclntab' });
  }
  return { symbols: out, version: MAGICS.get(magic) };
}
