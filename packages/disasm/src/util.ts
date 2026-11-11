// Bounds checked byte reading. Every read past the end returns 0 (or an empty string)
// instead of throwing, so hostile headers degrade into empty results.

export class BR {
  readonly b: Uint8Array;
  readonly v: DataView;
  le: boolean;
  constructor(b: Uint8Array, le = true) {
    this.b = b;
    this.v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    this.le = le;
  }
  get length(): number { return this.b.length; }
  ok(off: number, n: number): boolean { return Number.isInteger(off) && off >= 0 && n >= 0 && off + n <= this.b.length; }
  u8(o: number): number { return this.ok(o, 1) ? this.b[o]! : 0; }
  u16(o: number): number { return this.ok(o, 2) ? this.v.getUint16(o, this.le) : 0; }
  u32(o: number): number { return this.ok(o, 4) ? this.v.getUint32(o, this.le) : 0; }
  i32(o: number): number { return this.ok(o, 4) ? this.v.getInt32(o, this.le) : 0; }
  /** 64 bit unsigned as a JS number (precision loss above 2^53 is acceptable for addresses) */
  u64(o: number): number { return this.ok(o, 8) ? Number(this.v.getBigUint64(o, this.le)) : 0; }
  i64(o: number): number { return this.ok(o, 8) ? Number(this.v.getBigInt64(o, this.le)) : 0; }
  ptr(o: number, bits: 32 | 64): number { return bits === 64 ? this.u64(o) : this.u32(o); }
  /** NUL terminated latin1 string, capped */
  cstr(o: number, max = 1024): string {
    if (!this.ok(o, 0)) return '';
    let s = '';
    const end = Math.min(this.b.length, o + max);
    for (let i = o; i < end; i++) {
      const c = this.b[i]!;
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }
  fixstr(o: number, n: number): string {
    let s = '';
    for (let i = 0; i < n; i++) {
      const c = this.u8(o + i);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }
  sub(o: number, n: number): Uint8Array {
    if (o < 0 || o >= this.b.length || n <= 0) return new Uint8Array(0);
    return this.b.subarray(o, Math.min(this.b.length, o + n));
  }
}

/** Reads a ULEB128 at pos; returns [value, nextPos]. Caps at 10 bytes. */
export function uleb(b: Uint8Array, pos: number): [number, number] {
  let result = 0;
  let mul = 1;
  for (let i = 0; i < 10 && pos < b.length; i++) {
    const byte = b[pos++]!;
    result += (byte & 0x7f) * mul;
    mul *= 128;
    if ((byte & 0x80) === 0) return [result, pos];
  }
  return [result, pos];
}

export function sleb(b: Uint8Array, pos: number): [number, number] {
  let result = 0;
  let mul = 1;
  let byte = 0;
  for (let i = 0; i < 10 && pos < b.length; i++) {
    byte = b[pos++]!;
    result += (byte & 0x7f) * mul;
    mul *= 128;
    if ((byte & 0x80) === 0) break;
  }
  if (byte & 0x40) result -= mul;
  return [result, pos];
}

export function hexOf(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

export function hx(n: number | undefined): string {
  if (n === undefined || !Number.isFinite(n)) return '?';
  return n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16);
}

/** Parses "0x401000", "401000h", "4198400" or a number into a number, or undefined. */
export function parseAddr(v: unknown): number | undefined {
  if (typeof v === 'number') return Number.isFinite(v) && v >= 0 ? Math.floor(v) : undefined;
  if (typeof v !== 'string') return undefined;
  const s = v.trim().toLowerCase();
  if (/^0x[0-9a-f]{1,16}$/.test(s)) return parseInt(s.slice(2), 16);
  if (/^[0-9a-f]{1,16}h$/.test(s)) return parseInt(s.slice(0, -1), 16);
  if (/^[0-9]{1,16}$/.test(s)) return parseInt(s, 10);
  return undefined;
}

export function clampInt(v: unknown, def: number, min: number, max: number): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN;
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

/** Simple deadline helper so long analyses stop cleanly. */
export class Budget {
  private readonly end: number;
  constructor(ms: number) { this.end = Date.now() + ms; }
  get expired(): boolean { return Date.now() > this.end; }
}

/** Glob match with only '*' and '?', linear time (no regex). */
export function globMatch(pattern: string, text: string): boolean {
  let p = 0, t = 0, star = -1, mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) { p++; t++; }
    else if (p < pattern.length && pattern[p] === '*') { star = p++; mark = t; }
    else if (star !== -1) { p = star + 1; t = ++mark; }
    else return false;
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

/** Split an operand string on top level commas (ignores commas inside [] {} ()). */
export function splitOperands(s: string): string[] {
  const out: string[] = [];
  let depth = 0, cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '[' || c === '{' || c === '(') depth++;
    else if (c === ']' || c === '}' || c === ')') depth = Math.max(0, depth - 1);
    if (c === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Parse a capstone style immediate: "#0x10", "#-8", "0x401000", "16". */
export function parseImm(s: string | undefined): number | undefined {
  if (!s) return undefined;
  let t = s.trim();
  if (t.startsWith('#')) t = t.slice(1);
  let neg = false;
  if (t.startsWith('-')) { neg = true; t = t.slice(1); }
  let n: number | undefined;
  if (/^0x[0-9a-f]{1,16}$/i.test(t)) n = parseInt(t.slice(2), 16);
  else if (/^[0-9]{1,16}$/.test(t)) n = parseInt(t, 10);
  if (n === undefined) return undefined;
  return neg ? -n : n;
}
