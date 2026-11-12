// Bounds checked reads and PE section mapping for the deep PE view. Same results as the helpers in
// @revlens/extras, with faster inner loops: native Uint8Array.indexOf for byte searches, chunked
// String.fromCharCode instead of character by character concatenation, and cached section tables.

export class ParseError extends Error {
  constructor(message: string, readonly offset?: number) {
    super(offset === undefined ? message : `${message} at 0x${offset.toString(16)}`);
    this.name = 'ParseError';
  }
}

function codes(arr: ArrayLike<number>, start: number, end: number): string {
  let s = '';
  const CH = 4096;
  for (let i = start; i < end; i += CH) s += String.fromCharCode.apply(null, Array.prototype.slice.call(arr, i, Math.min(end, i + CH)) as number[]);
  return s;
}

/** Bounds checked little endian view over a byte array. */
export class View {
  readonly dv: DataView;
  constructor(readonly bytes: Uint8Array, public le = true) { this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }
  get length(): number { return this.bytes.length; }
  has(off: number, n: number): boolean { return Number.isInteger(off) && off >= 0 && n >= 0 && off + n <= this.bytes.length; }
  need(off: number, n: number): void { if (!this.has(off, n)) throw new ParseError(`read of ${n} bytes out of range`, off); }
  u8(o: number): number { this.need(o, 1); return this.bytes[o] as number; }
  u16(o: number, le = this.le): number { this.need(o, 2); return this.dv.getUint16(o, le); }
  u32(o: number, le = this.le): number { this.need(o, 4); return this.dv.getUint32(o, le); }
  u64(o: number, le = this.le): bigint { this.need(o, 8); return this.dv.getBigUint64(o, le); }
  u64n(o: number, le = this.le): number {
    this.need(o, 8);
    const lo = this.dv.getUint32(o + (le ? 0 : 4), le), hi = this.dv.getUint32(o + (le ? 4 : 0), le);
    if (hi > 0x1fffff) throw new ParseError('64 bit value too large', o);
    return hi * 4294967296 + lo;
  }
  uN(o: number, size: number, le = this.le): number { return size === 8 ? this.u64n(o, le) : size === 4 ? this.u32(o, le) : size === 2 ? this.u16(o, le) : this.u8(o); }
  sub(o: number, n: number): Uint8Array { this.need(o, n); return this.bytes.subarray(o, o + n); }
  /** NUL terminated latin1 string, capped. */
  cstr(o: number, max = 4096): string {
    if (o < 0 || o >= this.bytes.length) throw new ParseError('string offset out of range', o);
    const end = Math.min(this.bytes.length, o + max);
    let z = this.bytes.indexOf(0, o);
    if (z < 0 || z > end) z = end;
    return codes(this.bytes, o, z);
  }
  utf8z(o: number, max = 4096): string {
    if (o < 0 || o >= this.bytes.length) throw new ParseError('string offset out of range', o);
    const end = Math.min(this.bytes.length, o + max);
    let z = this.bytes.indexOf(0, o);
    if (z < 0 || z > end) z = end;
    return utf8(this.bytes.subarray(o, z));
  }
  utf16(o: number, chars: number, le = true): string {
    this.need(o, chars * 2);
    const u = new Uint16Array(chars);
    for (let i = 0; i < chars; i++) u[i] = this.dv.getUint16(o + i * 2, le);
    return codes(u, 0, chars);
  }
  utf16z(o: number, max = 4096): string {
    let n = 0;
    while (n < max && this.has(o + n * 2, 2) && this.dv.getUint16(o + n * 2, true) !== 0) n++;
    return n ? this.utf16(o, n) : '';
  }
}

const dec = new TextDecoder('utf-8', { fatal: false });
export function utf8(b: Uint8Array): string { return dec.decode(b); }
export function toHex(b: Uint8Array): string { const H = '0123456789abcdef'; const o: string[] = new Array(b.length); for (let i = 0; i < b.length; i++) { const c = b[i] as number; o[i] = (H[c >> 4] as string) + (H[c & 15] as string); } return o.join(''); }
export function ascii(s: string): Uint8Array { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff; return o; }
export function startsWithBytes(b: Uint8Array, sig: ArrayLike<number>, at = 0): boolean {
  if (at < 0 || at + sig.length > b.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig[i]) return false;
  return true;
}
/** First index of needle in h[from, to), or -1. Uses the native byte search to jump between candidates. */
export function indexOfBytes(h: Uint8Array, n: Uint8Array, from = 0, to = h.length): number {
  if (n.length === 0) return -1;
  const first = n[0] as number;
  const last = Math.min(to, h.length) - n.length;
  let i = Math.max(0, from);
  while (i <= last) {
    i = h.indexOf(first, i);
    if (i < 0 || i > last) return -1;
    let j = 1;
    while (j < n.length && h[i + j] === n[j]) j++;
    if (j === n.length) return i;
    i++;
  }
  return -1;
}
export function guid(b: Uint8Array, o = 0): string {
  const v = new View(b);
  const d1 = v.u32(o).toString(16).padStart(8, '0');
  const d2 = v.u16(o + 4).toString(16).padStart(4, '0');
  const d3 = v.u16(o + 6).toString(16).padStart(4, '0');
  const r = toHex(v.sub(o + 8, 8));
  return `${d1}-${d2}-${d3}-${r.slice(0, 4)}-${r.slice(4)}`.toUpperCase();
}
export function unixTime(sec: number): string | null {
  if (!Number.isFinite(sec) || sec <= 0 || sec > 8.64e12) return null;
  return new Date(sec * 1000).toISOString();
}
/** Shannon entropy, same arithmetic order as the extras helper so results are bit identical. */
export function entropyOf(b: Uint8Array): number {
  if (!b.length) return 0;
  const f = new Uint32Array(256);
  for (let i = 0; i < b.length; i++) f[b[i] as number]!++;
  let e = 0;
  for (let k = 0; k < 256; k++) { const n = f[k] as number; if (n) { const p = n / b.length; e -= p * Math.log2(p); } }
  return e;
}

export interface BinSection { name: string; vaddr: number; vsize: number; offset: number; size: number; flags: number }
export interface BinImage { format: 'pe'; bits: 32 | 64; le: true; machine: string; imageBase: number; entry: number; sections: BinSection[]; segments: never[]; sliceOffset: 0; view: View }
const PE_MACHINE: Record<number, string> = { 0x14c: 'x86', 0x8664: 'x86-64', 0x1c0: 'arm', 0x1c4: 'armnt', 0xaa64: 'aarch64', 0x200: 'ia64', 0x5064: 'riscv64' };

export function parsePe(bytes: Uint8Array): BinImage {
  const v = new View(bytes, true);
  if (v.u16(0) !== 0x5a4d) throw new ParseError('missing MZ header');
  const pe = v.u32(0x3c);
  if (v.u32(pe) !== 0x4550) throw new ParseError('missing PE signature', pe);
  const machine = v.u16(pe + 4);
  const nsec = Math.min(v.u16(pe + 6), 96);
  const optSize = v.u16(pe + 20);
  const opt = pe + 24;
  const magic = v.u16(opt);
  const is64 = magic === 0x20b;
  const entry = v.u32(opt + 16);
  const imageBase = is64 ? v.u64n(opt + 24) : v.u32(opt + 28);
  const sections: BinSection[] = [];
  const secOff = opt + optSize;
  for (let i = 0; i < nsec; i++) {
    const b = secOff + i * 40;
    if (!v.has(b, 40)) break;
    let end = b;
    while (end < b + 8 && bytes[end] !== 0) end++;
    sections.push({ name: codes(bytes, b, end), vsize: v.u32(b + 8), vaddr: v.u32(b + 12), size: v.u32(b + 16), offset: v.u32(b + 20), flags: v.u32(b + 36) });
  }
  return { format: 'pe', bits: is64 ? 64 : 32, le: true, machine: PE_MACHINE[machine] ?? `pe-machine-0x${machine.toString(16)}`, imageBase, entry, sections, segments: [], sliceOffset: 0, view: v };
}

export function vaToOffset(img: BinImage, va: number): number {
  const rva = va >= img.imageBase && img.imageBase > 0 ? va - img.imageBase : va;
  for (const s of img.sections) {
    const span = Math.max(s.vsize, s.size);
    if (rva >= s.vaddr && rva < s.vaddr + span) {
      const d = rva - s.vaddr;
      return d < s.size ? s.offset + d : -1;
    }
  }
  if (rva < (img.sections[0]?.offset ?? 0x400)) return rva;
  return -1;
}
