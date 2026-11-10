// Small byte and math helpers used across analyzers. Pure, no Node built-ins.

export class Reader {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  pos = 0;
  little = true;

  constructor(bytes: Uint8Array, little = true) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.little = little;
  }

  get length(): number { return this.bytes.length; }
  seek(p: number): this { this.pos = p; return this; }
  skip(n: number): this { this.pos += n; return this; }
  remaining(): number { return this.bytes.length - this.pos; }

  u8(p = this.pos): number { this.pos = p + 1; return this.view.getUint8(p); }
  u16(p = this.pos): number { this.pos = p + 2; return this.view.getUint16(p, this.little); }
  u32(p = this.pos): number { this.pos = p + 4; return this.view.getUint32(p, this.little); }
  i32(p = this.pos): number { this.pos = p + 4; return this.view.getInt32(p, this.little); }
  u64(p = this.pos): bigint { this.pos = p + 8; return this.view.getBigUint64(p, this.little); }

  slice(start: number, end: number): Uint8Array { return this.bytes.subarray(start, end); }
}

export function hex(bytes: Uint8Array, start = 0, end = bytes.length): string {
  let s = '';
  for (let i = start; i < end; i++) s += (bytes[i] as number).toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(h: string): Uint8Array {
  const clean = h.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/** Shannon entropy in bits per byte, 0..8. */
export function entropy(bytes: Uint8Array, start = 0, end = bytes.length): number {
  const n = end - start;
  if (n <= 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = start; i < end; i++) counts[bytes[i] as number] = (counts[bytes[i] as number] as number) + 1;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i] as number;
    if (c === 0) continue;
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Index of first occurrence of needle in haystack, or -1. */
export function indexOf(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
  const n = needle.length;
  if (n === 0) return from;
  const first = needle[0] as number;
  const last = haystack.length - n;
  let i = haystack.indexOf(first, from);
  while (i >= 0 && i <= last) {
    let j = 1;
    while (j < n && haystack[i + j] === needle[j]) j++;
    if (j === n) return i;
    i = haystack.indexOf(first, i + 1);
  }
  return -1;
}

export function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

const decoder = new TextDecoder('utf-8', { fatal: false });
export function decodeUtf8(bytes: Uint8Array): string { return decoder.decode(bytes); }

/** Heuristic: is this buffer mostly printable text. */
export function looksTextual(bytes: Uint8Array, sample = 4096): boolean {
  const end = Math.min(bytes.length, sample);
  if (end === 0) return false;
  let printable = 0;
  for (let i = 0; i < end; i++) {
    const b = bytes[i] as number;
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable++;
    else if (b === 0) return false;
  }
  return printable / end > 0.85;
}

export function startsWith(bytes: Uint8Array, sig: number[], at = 0): boolean {
  if (at + sig.length > bytes.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[at + i] !== sig[i]) return false;
  return true;
}
