// Swift's Punycode variant (delimiter '_', digits a-z then A-J), decode side only.
// Ported from swift/lib/Demangling/Punycode.cpp (swift-6.0.3-RELEASE), Apache-2.0 with Runtime Library Exception.

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;
const MAXI = 0x7fffffff;

function digitIndex(c: string): number {
  if (c >= 'a' && c <= 'z') return c.charCodeAt(0) - 97;
  if (c >= 'A' && c <= 'J') return c.charCodeAt(0) - 65 + 26;
  return -1;
}
const isValidUnicodeScalar = (s: number): boolean => s < 0xd880 || (s >= 0xe000 && s <= 0x10ffff);

function adapt(delta: number, numpoints: number, first: boolean): number {
  delta = first ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numpoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) { delta = Math.floor(delta / (BASE - TMIN)); k += BASE; }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

/** Decode Swift Punycode to code points, or undefined when malformed. */
export function decodePunycode(input: string): number[] | undefined {
  const out: number[] = [];
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  const last = input.lastIndexOf('_');
  if (last >= 0) {
    for (const c of input.slice(0, last)) { const v = c.charCodeAt(0); if (v > 0x7f) return undefined; out.push(v); }
    input = input.slice(last + 1);
  }
  let p = 0;
  while (p < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (p >= input.length) return undefined;
      const digit = digitIndex(input[p++]!);
      if (digit < 0) return undefined;
      if (digit > Math.floor((MAXI - i) / w)) return undefined;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAXI / (BASE - t))) return undefined;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    if (Math.floor(i / (out.length + 1)) > MAXI - n) return undefined;
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n < 0x80) return undefined;
    if (out.length > 4096) return undefined;
    out.splice(i, 0, n);
    i++;
  }
  return out;
}

/** Decode Swift Punycode into a JS string (non-symbol ASCII mapped at 0xD800 is unmapped). */
export function decodePunycodeString(input: string): string | undefined {
  const cps = decodePunycode(input);
  if (!cps) return undefined;
  let s = '';
  for (let c of cps) {
    if (!isValidUnicodeScalar(c)) return undefined;
    if (c >= 0xd800 && c < 0xd880) c -= 0xd800;
    s += String.fromCodePoint(c);
  }
  return s;
}
