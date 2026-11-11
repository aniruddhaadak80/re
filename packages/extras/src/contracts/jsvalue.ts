// Bounded parser for JSON and JavaScript object literals as minifiers emit them
// ({a:1,"b":'x',c:!0,d:[1,2,],e:void 0}). Used to lift API contracts out of bundles.
// Never evaluates code: only literal syntax is accepted, anything else is a ParseError.

import { ParseError } from '../util.js';

export interface JsValueLimits { maxChars?: number; maxDepth?: number; maxNodes?: number }

export type JsValue = null | boolean | number | string | JsValue[] | { [k: string]: JsValue };

const isIdStart = (c: number): boolean => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 36 || c === 95;
const isId = (c: number): boolean => isIdStart(c) || (c >= 48 && c <= 57);

/** Parse a literal starting at `at` (after optional whitespace). Returns the value and the end index. */
export function parseJsValue(s: string, at: number, lim: JsValueLimits = {}): { value: JsValue; end: number } {
  const end = Math.min(s.length, at + (lim.maxChars ?? 8 << 20));
  const maxDepth = lim.maxDepth ?? 200;
  let nodes = 0;
  const maxNodes = lim.maxNodes ?? 2_000_000;
  let p = at;
  const fail = (m: string): never => { throw new ParseError(`js literal: ${m}`, p); };
  const ws = (): void => {
    while (p < end) {
      const c = s.charCodeAt(p);
      if (c === 32 || c === 9 || c === 10 || c === 13) p++;
      else if (c === 47 && s.charCodeAt(p + 1) === 42) { const e = s.indexOf('*/', p + 2); if (e < 0 || e >= end) fail('unterminated comment'); p = e + 2; }
      else break;
    }
  };
  const str = (): string => {
    const q = s[p++];
    let out = '';
    let seg = p;
    while (p < end) {
      const c = s[p]!;
      if (c === q) { out += s.slice(seg, p); p++; return out; }
      if (c === '\\') {
        out += s.slice(seg, p);
        const n = s[p + 1];
        p += 2;
        switch (n) {
          case 'n': out += '\n'; break; case 't': out += '\t'; break; case 'r': out += '\r'; break;
          case 'b': out += '\b'; break; case 'f': out += '\f'; break; case 'v': out += '\v'; break; case '0': out += '\0'; break;
          case 'x': { const h = s.slice(p, p + 2); if (!/^[0-9a-fA-F]{2}$/.test(h)) fail('bad \\x escape'); out += String.fromCharCode(parseInt(h, 16)); p += 2; break; }
          case 'u': {
            if (s[p] === '{') { const e = s.indexOf('}', p); const h = s.slice(p + 1, e); if (e < 0 || !/^[0-9a-fA-F]{1,6}$/.test(h) || parseInt(h, 16) > 0x10ffff) fail('bad \\u{} escape'); out += String.fromCodePoint(parseInt(h, 16)); p = e + 1; }
            else { const h = s.slice(p, p + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail('bad \\u escape'); out += String.fromCharCode(parseInt(h, 16)); p += 4; }
            break;
          }
          case '\r': if (s[p] === '\n') p++; break;
          case '\n': break;
          case undefined: fail('unterminated string'); break;
          default: out += n;
        }
        seg = p;
        continue;
      }
      if (q === '`' && c === '$' && s[p + 1] === '{') fail('template substitution');
      if (q !== '`' && (c === '\n' || c === '\r')) fail('newline in string');
      p++;
    }
    return fail('unterminated string');
  };
  const num = (): number => {
    const m = /^-?(?:0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/.exec(s.slice(p, Math.min(end, p + 64)));
    if (!m) fail('bad number');
    p += m![0].length;
    return Number(m![0]);
  };
  const val = (depth: number): JsValue => {
    if (depth > maxDepth) fail('too deep');
    if (++nodes > maxNodes) fail('too many nodes');
    ws();
    if (p >= end) fail('unexpected end');
    const c = s.charCodeAt(p);
    if (c === 123) { // {
      p++;
      const o: { [k: string]: JsValue } = {};
      for (;;) {
        ws();
        if (s[p] === '}') { p++; return o; }
        let k: string;
        const kc = s.charCodeAt(p);
        if (kc === 34 || kc === 39) k = str();
        else if (isIdStart(kc)) { const st = p; while (p < end && isId(s.charCodeAt(p))) p++; k = s.slice(st, p); }
        else if (kc >= 48 && kc <= 57) k = String(num());
        else return fail('bad key');
        ws();
        if (s[p] !== ':') fail('expected :');
        p++;
        const v = val(depth + 1);
        if (k === '__proto__') Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        else o[k] = v;
        ws();
        if (s[p] === ',') { p++; continue; }
        if (s[p] === '}') { p++; return o; }
        fail('expected , or }');
      }
    }
    if (c === 91) { // [
      p++;
      const a: JsValue[] = [];
      for (;;) {
        ws();
        if (s[p] === ']') { p++; return a; }
        a.push(val(depth + 1));
        ws();
        if (s[p] === ',') { p++; continue; }
        if (s[p] === ']') { p++; return a; }
        fail('expected , or ]');
      }
    }
    if (c === 34 || c === 39 || c === 96) return str();
    if (c === 33) { // !0 !1
      if (s[p + 1] === '0' && !isId(s.charCodeAt(p + 2))) { p += 2; return true; }
      if (s[p + 1] === '1' && !isId(s.charCodeAt(p + 2))) { p += 2; return false; }
      fail('bad ! literal');
    }
    if (c === 45 || c === 46 || (c >= 48 && c <= 57)) return num();
    for (const [w, v] of [['true', true], ['false', false], ['null', null], ['void 0', null], ['undefined', null]] as const) {
      if (s.startsWith(w, p) && !isId(s.charCodeAt(p + w.length))) { p += w.length; return v; }
    }
    return fail('unexpected token');
  };
  const value = val(0);
  return { value, end: p };
}

/**
 * Find the `{` that opens the object holding the key at `keyAt`, scanning backwards and
 * balancing braces. Bounded by `window` characters. String contents are not tracked, so the
 * caller verifies by parsing.
 */
export function enclosingBrace(s: string, keyAt: number, window = 1 << 20): number {
  let depth = 0;
  const stop = Math.max(0, keyAt - window);
  for (let i = keyAt - 1; i >= stop; i--) {
    const c = s.charCodeAt(i);
    if (c === 125 || c === 93) depth++;
    else if (c === 123 || c === 91) { if (depth === 0) return c === 123 ? i : -1; depth--; }
  }
  return -1;
}
