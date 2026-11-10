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

/**
 * Limits that keep a scan bounded when the data, or a rule, is hostile. Files are attacker
 * input and rule text can come from an agent, so every loop below has a ceiling.
 */
export const YARA_LIMITS = {
  /** Largest rule text accepted, in characters. */
  maxRuleText: 512 * 1024,
  /** Most rules in one rule text. */
  maxRules: 2000,
  /** Longest text, hex or regex string definition, in characters. */
  maxStringDef: 1024,
  /** Longest condition, in characters. */
  maxCondition: 8192,
  /** Most jumps in one hex string. */
  maxHexJumps: 16,
  /** Byte comparisons allowed per string before the search stops early. */
  workPerString: 50_000_000,
  /** Condition evaluation steps allowed per rule. */
  conditionSteps: 200_000,
  /** Largest data prefix regex strings run on, in bytes. */
  maxRegexData: 16_000_000,
};

/** Removes block and line comments in one linear pass. Unterminated block comments are kept as text. */
function stripComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end < 0) { out += src.slice(i); break; }
      i = end + 2;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      const prev = out[out.length - 1];
      if (prev !== ':' && prev !== '"' && prev !== '\\') {
        const nl = src.indexOf('\n', i);
        i = nl < 0 ? src.length : nl;
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * Rejects regex strings that can backtrack catastrophically: nested quantifiers such as
 * (a+)+ or (a|aa)*, quantified groups that contain alternation over a quantified atom, and
 * backreferences. The check is conservative; rewrite a refused pattern without nesting.
 */
export function assertSafeRegex(src: string): void {
  if (src.length > YARA_LIMITS.maxStringDef) throw new Error(`regex is longer than ${YARA_LIMITS.maxStringDef} characters`);
  if (/\\[1-9]|\\k</.test(src)) throw new Error('regex backreferences are not supported');
  // Walk the pattern, tracking for each open group whether it holds a quantifier or alternation.
  const stack: { quant: boolean; alt: boolean }[] = [];
  let quantInGroup = false;
  let altInGroup = false;
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') { i++; continue; }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; continue; }
    if (c === '(') { stack.push({ quant: quantInGroup, alt: altInGroup }); quantInGroup = false; altInGroup = false; continue; }
    if (c === '|') { altInGroup = true; continue; }
    const isQuant = c === '*' || c === '+' || c === '?' || (c === '{' && /^\{\d+(,\d*)?\}/.test(src.slice(i)));
    if (c === ')') {
      const inner: { quant: boolean; alt: boolean } = { quant: quantInGroup, alt: altInGroup };
      const outer = stack.pop() ?? { quant: false, alt: false };
      const next = src[i + 1];
      const groupQuantified = next === '*' || next === '+' || (next === '{' && /^\{\d+,\d*\}/.test(src.slice(i + 1)) && !/^\{(\d+),\1\}/.test(src.slice(i + 1)));
      if (groupQuantified && (inner.quant || inner.alt)) throw new Error(`regex /${src}/ has a repeated group that contains a quantifier or alternation, which can take exponential time`);
      quantInGroup = outer.quant || inner.quant || groupQuantified;
      altInGroup = outer.alt;
      continue;
    }
    if (isQuant && c !== '?') quantInGroup = true;
  }
}

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype', 'hasOwnProperty', 'toString', 'valueOf', 'toJSON']);

export function parseRules(src: string): Rule[] {
  if (src.length > YARA_LIMITS.maxRuleText) throw new Error(`rule text is ${src.length} characters, the limit is ${YARA_LIMITS.maxRuleText}`);
  const text = stripComments(src);
  const rules: Rule[] = [];
  const ruleRe = /\b(?:private\s+|global\s+)*rule\s+(\w+)\s*(?::\s*(\w+(?:[ \t]+\w+)*))?\s*\{/g;
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
    // Built with fromEntries so a meta key such as __proto__ becomes a plain own property
    // instead of reaching the prototype. Keys that shadow Object methods are dropped.
    const metaEntries: [string, string][] = [];
    for (const line of sec('meta').split('\n')) {
      const mm = /^\s*(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))/.exec(line);
      if (mm && !UNSAFE_KEYS.has(mm[1] as string)) metaEntries.push([mm[1] as string, (mm[2] ?? mm[3]) as string]);
    }
    const meta: Record<string, string> = Object.fromEntries(metaEntries);
    const strings: StrDef[] = [];
    const strSrc = sec('strings');
    // Each alternative is bounded and cannot cross a line (hex strings may span lines up to the
    // length cap), so an unterminated quote or brace costs at most maxStringDef per position.
    const sre = /\$(\w*)\s*=\s*(?:"((?:[^"\\\n]|\\.){0,1024})"([^\n$]*)|\{([^}]{0,4096})\}|\/((?:[^\/\\\n]|\\.){1,1024})\/([is]*))/g;
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
        try { assertSafeRegex(sm[5]); } catch (e) { throw new Error(`rule ${m[1]}: string ${id}: ${(e as Error).message}`); }
        strings.push({ id, kind: 'regex', re: new RegExp(sm[5], (sm[6] ?? '').replace(/[^is]/g, '') + 'g') });
      }
    }
    if (rules.length >= YARA_LIMITS.maxRules) throw new Error(`more than ${YARA_LIMITS.maxRules} rules`);
    const condition = sec('condition') || 'any of them';
    if (condition.length > YARA_LIMITS.maxCondition) throw new Error(`rule ${m[1]}: condition is longer than ${YARA_LIMITS.maxCondition} characters`);
    rules.push({ name: m[1] as string, tags: (m[2] ?? '').trim().split(/\s+/).filter(Boolean), meta, strings, condition });
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
      if (jumps.length >= YARA_LIMITS.maxHexJumps) throw new Error(`hex string ${id} has more than ${YARA_LIMITS.maxHexJumps} jumps`);
      if (!(lo >= 0 && hi >= lo)) throw new Error(`hex string ${id} has a bad jump ${t}`);
      jumps.push([lo, Math.min(hi, lo + 65536)]); pattern.push([]);
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
  let budget = YARA_LIMITS.workPerString;
  const check = (i: number): boolean => {
    for (let j = 1; j < n; j++) {
      budget--;
      const a = data[i + j] as number, b = needle[j] as number;
      if (a !== b && !(nocase && lower(a) === lower(b))) return false;
    }
    if (fullword && (isWordByte(data[i - 1]) || isWordByte(data[i + n]))) return false;
    return true;
  };
  for (const first of firsts) {
    let i = data.indexOf(first);
    while (i >= 0 && i + n <= data.length && hits.length < cap && budget > 0) {
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
  let budget = YARA_LIMITS.workPerString;
  const first = parts[0] as (number | null)[];
  const anchor = first.findIndex((x) => x !== null);
  for (let i = anchor >= 0 ? data.indexOf(first[anchor] as number, anchor) - anchor : 0; i >= 0 && i + first.length <= data.length && hits.length < cap;
    i = anchor >= 0 ? (() => { const k = data.indexOf(first[anchor] as number, i + anchor + 1); return k < 0 ? -1 : k - anchor; })() : i + 1) {
    if (budget <= 0) break;
    budget -= first.length;
    if (!matchPart(data, i, first)) continue;
    // Resolve jumps left to right with backtracking. The shared budget stops pathological
    // patterns such as many open jumps over repetitive data.
    const walk = (pi: number, pos: number): number => {
      if (pi >= parts.length) return pos;
      const [lo, hi] = def.jumps[pi - 1] as [number, number];
      const part = parts[pi] as (number | null)[];
      for (let k = lo; k <= hi && pos + k + part.length <= data.length; k++) {
        budget -= part.length || 1;
        if (budget <= 0) return -1;
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
  let steps = YARA_LIMITS.conditionSteps;
  const eat = (v?: string) => {
    if (--steps < 0) throw new Error('condition is too complex to evaluate');
    const t = toks[p++]; if (v && t?.v !== v) throw new Error(`expected ${v} in condition`); return t as Tok;
  };
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
      try { eat('('); const b = orExpr(); eat(')'); return b; } catch (e) { if (steps < 0) throw e; p = save; }
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
  const text = needsRegex ? latin1(data.length > YARA_LIMITS.maxRegexData ? data.subarray(0, YARA_LIMITS.maxRegexData) : data) : '';
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
