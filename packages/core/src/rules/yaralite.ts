// yara-lite: a pure TypeScript subset of the YARA rule language.
// Supported: meta, text strings (nocase, wide, ascii, fullword), hex strings with ?? wildcards
// and [n-m] jumps, regex strings, and conditions with and, or, not, parentheses,
// "any of them", "all of them", "N of them", "N of ($a*, $b)", "$a", "#a > N", "@a[1] < N",
// "$a at N", "$a in (N..M)", filesize, uint8/16/32(be) at offset, KB and MB suffixes.
import type { RuleMatch } from '../types.js';

type StrDef =
  | { id: string; kind: 'text'; value: string; nocase: boolean; wide: boolean; ascii: boolean; fullword: boolean }
  | { id: string; kind: 'hex'; pattern: (number | null)[][]; jumps: [number, number][] }
  | { id: string; kind: 'regex'; re: RegExp };

export interface Rule { name: string; tags: string[]; meta: Record<string, string>; strings: StrDef[]; condition: string }

export function parseRules(src: string): Rule[] {
  const text = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"\\])\/\/[^\n]*/g, '$1');
  const rules: Rule[] = [];
  const ruleRe = /\b(?:private\s+|global\s+)*rule\s+(\w+)\s*(?::\s*([\w\s]+?))?\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = ruleRe.exec(text))) {
    // find the matching closing brace, skipping strings and regexes roughly
    let depth = 1, i = ruleRe.lastIndex, inStr = false;
    for (; i < text.length && depth > 0; i++) {
      const c = text[i];
      if (c === '"' && text[i - 1] !== '\\') inStr = !inStr;
      if (inStr) continue;
      if (c === '{') depth++; else if (c === '}') depth--;
    }
    const body = text.slice(ruleRe.lastIndex, i - 1);
    ruleRe.lastIndex = i;
    const sec = (name: string) => {
      const r = new RegExp(`\\b${name}\\s*:([\\s\\S]*?)(?=\\b(?:meta|strings|condition)\\s*:|$)`);
      return r.exec(body)?.[1]?.trim() ?? '';
    };
    const meta: Record<string, string> = {};
    for (const line of sec('meta').split('\n')) {
      const mm = /^\s*(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))/.exec(line);
      if (mm) meta[mm[1] as string] = (mm[2] ?? mm[3]) as string;
    }
    const strings: StrDef[] = [];
    const strSrc = sec('strings');
    const sre = /\$(\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"([^\n$]*)|\{([^}]*)\}|\/((?:[^\/\\\n]|\\.)+)\/([is]*))/g;
    let sm: RegExpExecArray | null;
    let anon = 0;
    while ((sm = sre.exec(strSrc))) {
      const id = '$' + (sm[1] || `anon${anon++}`);
      if (sm[2] !== undefined) {
        const mods = (sm[3] ?? '').toLowerCase();
        const value = sm[2].replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
          .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        const wide = /\bwide\b/.test(mods);
        strings.push({ id, kind: 'text', value, nocase: /\bnocase\b/.test(mods), wide, ascii: !wide || /\bascii\b/.test(mods), fullword: /\bfullword\b/.test(mods) });
      } else if (sm[4] !== undefined) {
        strings.push(parseHex(id, sm[4]));
      } else if (sm[5] !== undefined) {
        strings.push({ id, kind: 'regex', re: new RegExp(sm[5], (sm[6] ?? '').replace(/[^is]/g, '') + 'g') });
      }
    }
    rules.push({ name: m[1] as string, tags: (m[2] ?? '').trim().split(/\s+/).filter(Boolean), meta, strings, condition: sec('condition') || 'any of them' });
  }
  return rules;
}

function parseHex(id: string, src: string): StrDef {
  const tokens = src.replace(/\s+/g, ' ').trim().split(' ');
  const pattern: (number | null)[][] = [[]];
  const jumps: [number, number][] = [];
  for (const t of tokens.join('').match(/\[[^\]]*\]|\?\?|[0-9a-fA-F]{2}|\?[0-9a-fA-F]|[0-9a-fA-F]\?/g) ?? []) {
    if (t.startsWith('[')) {
      const [a, b] = t.slice(1, -1).split('-');
      const lo = parseInt(a || '0', 10); const hi = b === undefined ? lo : b === '' ? 4096 : parseInt(b, 10);
      jumps.push([lo, hi]); pattern.push([]);
    } else (pattern[pattern.length - 1] as (number | null)[]).push(t.includes('?') ? null : parseInt(t, 16));
  }
  return { id, kind: 'hex', pattern, jumps };
}

function encodeWide(s: string): Uint8Array { const o = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) o[i * 2] = s.charCodeAt(i) & 0xff; return o; }
function encode(s: string): Uint8Array { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 0xff; return o; }
const lower = (b: number) => (b >= 65 && b <= 90 ? b + 32 : b);
const isWordByte = (b: number | undefined) => b !== undefined && ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 95);

function findAll(data: Uint8Array, needle: Uint8Array, nocase: boolean, fullword: boolean, cap: number): number[] {
  const hits: number[] = [];
  const n = needle.length; if (!n) return hits;
  const f = needle[0] as number;
  const firsts = nocase && ((f >= 65 && f <= 90) || (f >= 97 && f <= 122)) ? [lower(f), lower(f) - 32] : [f];
  const check = (i: number): boolean => {
    for (let j = 1; j < n; j++) {
      const a = data[i + j] as number, b = needle[j] as number;
      if (a !== b && !(nocase && lower(a) === lower(b))) return false;
    }
    if (fullword && (isWordByte(data[i - 1]) || isWordByte(data[i + n]))) return false;
    return true;
  };
  for (const first of firsts) {
    let i = data.indexOf(first);
    while (i >= 0 && i + n <= data.length && hits.length < cap) {
      if (check(i)) hits.push(i);
      i = data.indexOf(first, i + 1);
    }
  }
  return hits.sort((a, b) => a - b);
}

function matchPart(data: Uint8Array, at: number, part: (number | null)[]): boolean {
  if (at + part.length > data.length) return false;
  for (let j = 0; j < part.length; j++) { const p = part[j]; if (p !== null && data[at + j] !== p) return false; }
  return true;
}

function findHex(data: Uint8Array, def: Extract<StrDef, { kind: 'hex' }>, cap: number): { off: number; len: number }[] {
  const hits: { off: number; len: number }[] = [];
  const parts = def.pattern;
  const first = parts[0] as (number | null)[];
  const anchor = first.findIndex((x) => x !== null);
  for (let i = anchor >= 0 ? data.indexOf(first[anchor] as number, anchor) - anchor : 0; i >= 0 && i + first.length <= data.length && hits.length < cap;
    i = anchor >= 0 ? (() => { const k = data.indexOf(first[anchor] as number, i + anchor + 1); return k < 0 ? -1 : k - anchor; })() : i + 1) {
    if (!matchPart(data, i, first)) continue;
    // resolve jumps greedily left to right
    const walk = (pi: number, pos: number): number => {
      if (pi >= parts.length) return pos;
      const [lo, hi] = def.jumps[pi - 1] as [number, number];
      const part = parts[pi] as (number | null)[];
      for (let k = lo; k <= hi && pos + k + part.length <= data.length; k++) {
        if (matchPart(data, pos + k, part)) { const end = walk(pi + 1, pos + k + part.length); if (end >= 0) return end; }
      }
      return -1;
    };
    const end = walk(1, i + first.length);
    if (end >= 0) hits.push({ off: i, len: end - i });
  }
  return hits;
}

type Hits = Map<string, { off: number; len: number }[]>;

function searchStrings(data: Uint8Array, rule: Rule, latin: string): Hits {
  const hits: Hits = new Map();
  for (const s of rule.strings) {
    let list: { off: number; len: number }[] = [];
    if (s.kind === 'text') {
      if (s.ascii) list.push(...findAll(data, encode(s.value), s.nocase, s.fullword, 1000).map((o) => ({ off: o, len: s.value.length })));
      if (s.wide) list.push(...findAll(data, encodeWide(s.value), s.nocase, s.fullword, 1000).map((o) => ({ off: o, len: s.value.length * 2 })));
    } else if (s.kind === 'hex') list = findHex(data, s, 1000);
    else {
      s.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = s.re.exec(latin)) && list.length < 1000) { list.push({ off: m.index, len: m[0].length }); if (!m[0].length) s.re.lastIndex++; }
    }
    hits.set(s.id, list.sort((a, b) => a.off - b.off));
  }
  return hits;
}

// ---- condition evaluation: tokenizer + recursive descent ----
type Tok = { t: string; v: string };
function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  const re = /\s*(?:(0x[0-9a-fA-F]+|\d+(?:KB|MB)?)|(\$\w*\*?)|(#\w*)|(@\w*)|(\.\.)|(==|!=|<=|>=|<|>|\(|\)|\[|\]|,|\+|-|\*|\\|&|\|)|([A-Za-z_]\w*))/gy;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) && m[0].length) {
    if (m[1]) out.push({ t: 'num', v: m[1] });
    else if (m[2]) out.push({ t: 'str', v: m[2] });
    else if (m[3]) out.push({ t: 'cnt', v: '$' + m[3].slice(1) });
    else if (m[4]) out.push({ t: 'off', v: '$' + m[4].slice(1) });
    else if (m[5]) out.push({ t: 'op', v: '..' });
    else if (m[6]) out.push({ t: 'op', v: m[6] });
    else if (m[7]) out.push({ t: 'id', v: m[7] });
  }
  return out;
}

function num(v: string): number {
  if (v.startsWith('0x')) return parseInt(v, 16);
  if (v.endsWith('KB')) return parseInt(v, 10) * 1024;
  if (v.endsWith('MB')) return parseInt(v, 10) * 1024 * 1024;
  return parseInt(v, 10);
}

function evaluate(cond: string, data: Uint8Array, hits: Hits, ids: string[]): boolean {
  const toks = tokenize(cond);
  let p = 0;
  const peek = () => toks[p];
  const eat = (v?: string) => { const t = toks[p++]; if (v && t?.v !== v) throw new Error(`expected ${v} in condition`); return t as Tok; };
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const setOf = (): string[] => {
    const t = eat();
    if (t.v === 'them') return ids;
    if (t.v !== '(') throw new Error('expected them or (');
    const out: string[] = [];
    while (peek() && peek()!.v !== ')') {
      const s = eat();
      if (s.t === 'str') out.push(...(s.v.endsWith('*') ? ids.filter((i) => i.startsWith(s.v.slice(0, -1))) : [s.v]));
      if (peek()?.v === ',') eat();
    }
    eat(')');
    return out;
  };
  const count = (id: string) => hits.get(id)?.length ?? 0;
  const value = (): number => {
    const t = eat();
    if (t.t === 'num') return num(t.v);
    if (t.t === 'cnt') { if (!ids.includes(t.v)) throw new Error(`condition uses #${t.v.slice(1)}, which is not defined in strings`); return count(t.v); }
    if (t.t === 'off') {
      let idx = 1;
      if (peek()?.v === '[') { eat('['); idx = value(); eat(']'); }
      return hits.get(t.v)?.[idx - 1]?.off ?? -1;
    }
    if (t.t === 'id' && t.v === 'filesize') return data.length;
    if (t.t === 'id' && /^u?int(8|16|32)(be)?$/.test(t.v)) {
      eat('('); const o = value(); eat(')');
      const bits = parseInt(/\d+/.exec(t.v)![0], 10); const be = t.v.endsWith('be');
      if (o < 0 || o + bits / 8 > data.length) return -1;
      return bits === 8 ? dv.getUint8(o) : bits === 16 ? dv.getUint16(o, !be) : dv.getUint32(o, !be);
    }
    if (t.v === '(') { const v = value(); eat(')'); return v; }
    throw new Error(`unexpected ${t.v}`);
  };
  const arith = (): number => {
    let v = value();
    while (peek() && ['+', '-', '*', '\\', '&', '|'].includes(peek()!.v) && peek()!.t === 'op') {
      const op = eat().v; const r = value();
      v = op === '+' ? v + r : op === '-' ? v - r : op === '*' ? v * r : op === '\\' ? Math.floor(v / r) : op === '&' ? v & r : v | r;
    }
    return v;
  };
  const primary = (): boolean => {
    const t = peek();
    if (!t) throw new Error('empty condition');
    if (t.v === 'not') { eat(); return !primary(); }
    if (t.v === 'true') { eat(); return true; }
    if (t.v === 'false') { eat(); return false; }
    if (t.v === '(') {
      // could be grouped boolean or arithmetic; try boolean
      const save = p;
      try { eat('('); const b = orExpr(); eat(')'); return b; } catch { p = save; }
    }
    if (t.v === 'any' || t.v === 'all' || t.t === 'num' && toks[p + 1]?.v === 'of') {
      const q = eat().v; eat('of'); const set = setOf();
      const n = set.filter((id) => count(id) > 0).length;
      return q === 'any' ? n > 0 : q === 'all' ? n === set.length && set.length > 0 : n >= num(q);
    }
    if (t.t === 'str' && !t.v.endsWith('*')) {
      eat();
      if (!ids.includes(t.v)) throw new Error(`condition uses ${t.v}, which is not defined in strings`);
      if (peek()?.v === 'at') { eat(); const o = arith(); return (hits.get(t.v) ?? []).some((h) => h.off === o); }
      if (peek()?.v === 'in') { eat(); eat('('); const a = arith(); eat('..'); const b = arith(); eat(')'); return (hits.get(t.v) ?? []).some((h) => h.off >= a && h.off <= b); }
      return count(t.v) > 0;
    }
    const left = arith();
    const op = eat().v; const right = arith();
    switch (op) { case '==': return left === right; case '!=': return left !== right; case '<': return left < right; case '>': return left > right; case '<=': return left <= right; case '>=': return left >= right; }
    throw new Error(`unknown operator ${op}`);
  };
  const andExpr = (): boolean => { let v = primary(); while (peek()?.v === 'and') { eat(); const r = primary(); v = v && r; } return v; };
  const orExpr = (): boolean => { let v = andExpr(); while (peek()?.v === 'or') { eat(); const r = andExpr(); v = v || r; } return v; };
  const result = orExpr();
  if (p < toks.length) throw new Error(`unexpected "${toks[p]!.v}" in condition`);
  return result;
}

function latin1(data: Uint8Array): string {
  let s = '';
  const CH = 0x8000;
  for (let i = 0; i < data.length; i += CH) s += String.fromCharCode.apply(null, Array.from(data.subarray(i, i + CH)));
  return s;
}

/** Scan bytes with rule text. Throws on a rule syntax error with a readable message. */
export function scanRules(data: Uint8Array, ruleText: string): RuleMatch[] {
  const rules = parseRules(ruleText);
  const needsRegex = rules.some((r) => r.strings.some((s) => s.kind === 'regex'));
  const text = needsRegex ? latin1(data.length > 16_000_000 ? data.subarray(0, 16_000_000) : data) : '';
  const out: RuleMatch[] = [];
  for (const rule of rules) {
    const hits = searchStrings(data, rule, text);
    let ok = false;
    try { ok = evaluate(rule.condition, data, hits, rule.strings.map((s) => s.id)); }
    catch (e) { throw new Error(`rule ${rule.name}: ${(e as Error).message}`); }
    if (!ok) continue;
    const strings: RuleMatch['strings'] = [];
    for (const [id, list] of hits) for (const h of list.slice(0, 5)) {
      let snip = '';
      for (let i = h.off; i < Math.min(data.length, h.off + Math.min(h.len, 48)); i++) { const b = data[i] as number; snip += b >= 32 && b < 127 ? String.fromCharCode(b) : '.'; }
      strings.push({ id, offset: h.off, length: h.len, snippet: snip });
    }
    out.push({ rule: rule.name, tags: rule.tags, meta: rule.meta, strings });
  }
  return out;
}

export { STARTER_RULES } from './starter.js';
