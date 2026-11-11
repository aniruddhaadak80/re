// String recognition at a virtual address (C strings, Go style unterminated runs, UTF-16LE).
import type { Memory } from '../loader/memory.js';

const MAX_LEN = 200;

function printable(c: number): boolean { return (c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13; }

/** Returns the string starting at addr, or undefined when the bytes do not look like text. */
export function stringAt(mem: Memory, addr: number, minLen = 4): { value: string; kind: 'ascii' | 'utf16' } | undefined {
  const b = mem.view(addr, MAX_LEN * 2 + 2);
  if (b.length < minLen) return undefined;
  // UTF-16LE
  if (b.length >= minLen * 2 && printable(b[0]!) && b[1] === 0 && printable(b[2]!) && b[3] === 0) {
    let s = '';
    for (let i = 0; i + 1 < b.length && s.length < MAX_LEN; i += 2) {
      const c = b[i]! | (b[i + 1]! << 8);
      if (c === 0) break;
      if (c > 0x7e || (c < 0x20 && c !== 9 && c !== 10 && c !== 13)) { if (s.length >= minLen) break; return undefined; }
      s += String.fromCharCode(c);
    }
    if (s.length >= minLen) return { value: s, kind: 'utf16' };
  }
  let s = '';
  let i = 0;
  for (; i < b.length && s.length < MAX_LEN; i++) {
    const c = b[i]!;
    if (c === 0) break;
    if (!printable(c)) {
      // allow UTF-8 multi byte sequences
      if (c >= 0xc2 && c <= 0xf4 && i + 1 < b.length && (b[i + 1]! & 0xc0) === 0x80) {
        let n = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : 1;
        let j = i + 1;
        let ok = true;
        while (n-- > 0) { if (j >= b.length || (b[j]! & 0xc0) !== 0x80) { ok = false; break; } j++; }
        if (ok) {
          try { s += new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(i, j)); } catch { break; }
          i = j - 1;
          continue;
        }
      }
      break;
    }
    s += String.fromCharCode(c);
  }
  if (s.length < minLen) return undefined;
  // reject runs that are mostly punctuation or one repeated char (tables, padding)
  let alnum = 0;
  for (let k = 0; k < s.length; k++) { const c = s.charCodeAt(k); if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 32) alnum++; }
  if (alnum < s.length * 0.5) return undefined;
  if (/^(.)\1+$/.test(s)) return undefined;
  return { value: s, kind: 'ascii' };
}
