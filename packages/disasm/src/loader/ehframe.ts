// Minimal .eh_frame reader: returns the pc_begin/pc_range of every FDE (function start hints).
import { BR, uleb, sleb } from '../util.js';

const MAX_RECORDS = 500_000;

interface Cie { fdeEnc: number }

function readEncoded(r: BR, pos: number, enc: number, secAddr: number, bits: 32 | 64, applyRel: boolean): [number, number] {
  if (enc === 0xff) return [0, pos];
  const fmt = enc & 0x0f;
  let v = 0;
  let next = pos;
  switch (fmt) {
    case 0x00: v = bits === 64 ? r.u64(pos) : r.u32(pos); next = pos + bits / 8; break;
    case 0x01: [v, next] = uleb(r.b, pos); break;
    case 0x02: v = r.u16(pos); next = pos + 2; break;
    case 0x03: v = r.u32(pos); next = pos + 4; break;
    case 0x04: v = r.u64(pos); next = pos + 8; break;
    case 0x09: [v, next] = sleb(r.b, pos); break;
    case 0x0a: v = (r.u16(pos) << 16) >> 16; next = pos + 2; break;
    case 0x0b: v = r.i32(pos); next = pos + 4; break;
    case 0x0c: v = r.i64(pos); next = pos + 8; break;
    default: return [NaN, pos];
  }
  if (applyRel && (enc & 0x70) === 0x10) v += secAddr + pos;
  if (bits === 32) v = v >>> 0;
  return [v, next];
}

export function parseEhFrame(sec: Uint8Array, secAddr: number, bits: 32 | 64, le: boolean): { addr: number; size: number }[] {
  const r = new BR(sec, le);
  const out: { addr: number; size: number }[] = [];
  const cies = new Map<number, Cie>();
  let pos = 0;
  let count = 0;
  while (pos + 8 <= sec.length && count++ < MAX_RECORDS) {
    let len = r.u32(pos);
    let hdr = 4;
    if (len === 0) break;
    if (len === 0xffffffff) { len = r.u64(pos + 4); hdr = 12; }
    const start = pos + hdr;
    const end = start + len;
    if (end > sec.length || len < 4) break;
    const idPos = start;
    const id = r.u32(idPos);
    if (id === 0) {
      // CIE
      let p = idPos + 4;
      const version = r.u8(p++);
      let aug = '';
      while (p < end && r.u8(p) !== 0 && aug.length < 16) aug += String.fromCharCode(r.u8(p++));
      p++;
      if (aug.includes('eh')) p += bits / 8;
      [, p] = uleb(sec, p);
      [, p] = sleb(sec, p);
      if (version === 1) p++; else [, p] = uleb(sec, p);
      let fdeEnc = 0;
      if (aug.startsWith('z')) {
        let augLen; [augLen, p] = uleb(sec, p);
        const augEnd = p + augLen;
        for (let i = 1; i < aug.length && p < augEnd; i++) {
          const c = aug[i];
          if (c === 'R') fdeEnc = r.u8(p++);
          else if (c === 'L') p++;
          else if (c === 'P') { const e = r.u8(p++); [, p] = readEncoded(r, p, e & 0x7f, secAddr, bits, false); }
          else if (c === 'S' || c === 'B') { /* no data */ }
          else break;
        }
      }
      cies.set(pos, { fdeEnc });
    } else {
      const ciePos = idPos - id;
      const cie = cies.get(ciePos) ?? { fdeEnc: 0 };
      const [begin, p2] = readEncoded(r, idPos + 4, cie.fdeEnc, secAddr, bits, true);
      const [range] = readEncoded(r, p2, cie.fdeEnc & 0x0f, secAddr, bits, false);
      if (Number.isFinite(begin) && begin > 0 && Number.isFinite(range) && range > 0 && range < 1 << 28) out.push({ addr: begin, size: range });
    }
    pos = end;
  }
  return out;
}
