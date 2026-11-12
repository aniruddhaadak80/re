// Linear time regular expressions for untrusted patterns (function and symbol name search).
// Thompson NFA simulation: no backtracking, so run time is O(pattern x text) whatever the input.
// Supported: literals, '.', character classes [a-z0-9_] and [^...], escapes \d \w \s \D \W \S and
// escaped metacharacters, anchors ^ and $, groups (...) and (?:...), alternation |, and the
// quantifiers * + ? {n} {n,} {n,m} (m up to 64), lazy suffix ? accepted and treated as greedy.
// Backreferences and lookaround are rejected.

type Node =
  | { t: 'char'; test: (c: number) => boolean }
  | { t: 'bol' } | { t: 'eol' }
  | { t: 'cat'; a: Node[] }
  | { t: 'alt'; a: Node[] }
  | { t: 'rep'; n: Node; min: number; max: number };

const MAX_PATTERN = 512;
const MAX_STATES = 20000;

export class SafeRegexError extends Error {}

class Parser {
  private i = 0;
  constructor(private readonly s: string, private readonly ci: boolean) {}
  parse(): Node {
    const n = this.alt();
    if (this.i < this.s.length) throw new SafeRegexError(`unexpected '${this.s[this.i]}' at ${this.i}`);
    return n;
  }
  private alt(): Node {
    const parts = [this.cat()];
    while (this.s[this.i] === '|') { this.i++; parts.push(this.cat()); }
    return parts.length === 1 ? parts[0]! : { t: 'alt', a: parts };
  }
  private cat(): Node {
    const a: Node[] = [];
    while (this.i < this.s.length && this.s[this.i] !== '|' && this.s[this.i] !== ')') a.push(this.rep());
    return { t: 'cat', a };
  }
  private rep(): Node {
    let n = this.atom();
    for (;;) {
      const c = this.s[this.i];
      let min = -1, max = -1;
      if (c === '*') { min = 0; max = Infinity; this.i++; }
      else if (c === '+') { min = 1; max = Infinity; this.i++; }
      else if (c === '?') { min = 0; max = 1; this.i++; }
      else if (c === '{') {
        const m = /^\{(\d{1,3})(,(\d{0,3}))?\}/.exec(this.s.slice(this.i));
        if (!m) break;
        min = Number(m[1]); max = m[2] ? (m[3] ? Number(m[3]) : Infinity) : min;
        if (min > 64 || (max !== Infinity && (max > 64 || max < min))) throw new SafeRegexError('repeat counts are limited to 64');
        this.i += m[0].length;
      } else break;
      if (this.s[this.i] === '?') this.i++; // lazy: same matches for a yes/no search
      if (n.t === 'bol' || n.t === 'eol') throw new SafeRegexError('quantifier after an anchor');
      n = { t: 'rep', n, min, max };
    }
    return n;
  }
  private atom(): Node {
    const c = this.s[this.i++];
    if (c === undefined) throw new SafeRegexError('pattern ends early');
    if (c === '(') {
      if (this.s[this.i] === '?') {
        if (this.s[this.i + 1] !== ':') throw new SafeRegexError('lookaround and named groups are not supported');
        this.i += 2;
      }
      const n = this.alt();
      if (this.s[this.i++] !== ')') throw new SafeRegexError('missing )');
      return n;
    }
    if (c === '^') return { t: 'bol' };
    if (c === '$') return { t: 'eol' };
    if (c === '.') return { t: 'char', test: (x) => x !== 10 };
    if (c === '[') return this.cls();
    if (c === '\\') return this.esc();
    if (c === ')' || c === '*' || c === '+' || c === '?' || c === '{') throw new SafeRegexError(`unexpected '${c}'`);
    return this.lit(c.charCodeAt(0));
  }
  private lit(code: number): Node {
    if (!this.ci) return { t: 'char', test: (x) => x === code };
    const lo = String.fromCharCode(code).toLowerCase().charCodeAt(0), up = String.fromCharCode(code).toUpperCase().charCodeAt(0);
    return { t: 'char', test: (x) => x === lo || x === up };
  }
  private escClass(e: string): ((x: number) => boolean) | undefined {
    const d = (x: number) => x >= 48 && x <= 57;
    const w = (x: number) => d(x) || (x >= 65 && x <= 90) || (x >= 97 && x <= 122) || x === 95;
    const sp = (x: number) => x === 32 || (x >= 9 && x <= 13);
    switch (e) {
      case 'd': return d; case 'D': return (x) => !d(x);
      case 'w': return w; case 'W': return (x) => !w(x);
      case 's': return sp; case 'S': return (x) => !sp(x);
      default: return undefined;
    }
  }
  private esc(): Node {
    const e = this.s[this.i++];
    if (e === undefined) throw new SafeRegexError('pattern ends after \\');
    if (/[1-9k]/.test(e)) throw new SafeRegexError('backreferences are not supported');
    const f = this.escClass(e);
    if (f) return { t: 'char', test: f };
    if (e === 'n') return this.lit(10);
    if (e === 't') return this.lit(9);
    return this.lit(e.charCodeAt(0));
  }
  private cls(): Node {
    let neg = false;
    if (this.s[this.i] === '^') { neg = true; this.i++; }
    const tests: ((x: number) => boolean)[] = [];
    let first = true;
    while (this.i < this.s.length && (this.s[this.i] !== ']' || first)) {
      first = false;
      let c = this.s[this.i++]!;
      if (c === '\\') {
        const e = this.s[this.i++] ?? '';
        const f = this.escClass(e);
        if (f) { tests.push(f); continue; }
        c = e === 'n' ? '\n' : e === 't' ? '\t' : e;
      }
      let lo = c.charCodeAt(0), hi = lo;
      if (this.s[this.i] === '-' && this.s[this.i + 1] !== ']' && this.i + 1 < this.s.length) {
        this.i++;
        let h = this.s[this.i++]!;
        if (h === '\\') h = this.s[this.i++] ?? '';
        hi = h.charCodeAt(0);
        if (hi < lo) throw new SafeRegexError('bad class range');
      }
      const L = lo, H = hi;
      if (this.ci) tests.push((x) => { const l = String.fromCharCode(x).toLowerCase().charCodeAt(0), u = String.fromCharCode(x).toUpperCase().charCodeAt(0); return (l >= L && l <= H) || (u >= L && u <= H); });
      else tests.push((x) => x >= L && x <= H);
    }
    if (this.s[this.i++] !== ']') throw new SafeRegexError('missing ]');
    return { t: 'char', test: neg ? (x) => x !== 10 && !tests.some((f) => f(x)) : (x) => tests.some((f) => f(x)) };
  }
}

// NFA states
interface St { kind: 'char' | 'split' | 'bol' | 'eol' | 'match'; test?: (c: number) => boolean; out: number; out2: number }

class Builder {
  readonly st: St[] = [];
  add(s: St): number { if (this.st.length >= MAX_STATES) throw new SafeRegexError('pattern too complex'); this.st.push(s); return this.st.length - 1; }
  /** compile n so that it continues to `next`; returns the entry state */
  build(n: Node, next: number): number {
    switch (n.t) {
      case 'char': return this.add({ kind: 'char', test: n.test, out: next, out2: -1 });
      case 'bol': return this.add({ kind: 'bol', out: next, out2: -1 });
      case 'eol': return this.add({ kind: 'eol', out: next, out2: -1 });
      case 'cat': { let cur = next; for (let i = n.a.length - 1; i >= 0; i--) cur = this.build(n.a[i]!, cur); return cur; }
      case 'alt': {
        const entries = n.a.map((x) => this.build(x, next));
        let cur = entries[entries.length - 1]!;
        for (let i = entries.length - 2; i >= 0; i--) cur = this.add({ kind: 'split', out: entries[i]!, out2: cur });
        return cur;
      }
      case 'rep': {
        let cur = next;
        if (n.max === Infinity) {
          const loop = this.add({ kind: 'split', out: -1, out2: next });
          const body = this.build(n.n, loop);
          this.st[loop]!.out = body;
          cur = loop;
        } else {
          // up to (max - min) optional copies, each one leading to the next or skipping to `next`
          for (let k = n.max; k > n.min; k--) { const body = this.build(n.n, cur); cur = this.add({ kind: 'split', out: body, out2: next }); }
        }
        for (let k = 0; k < n.min; k++) cur = this.build(n.n, cur);
        return cur;
      }
    }
  }
}

/** A compiled linear time pattern. test() searches anywhere in the text unless anchored with ^ / $. */
export class SafeRegex {
  private readonly st: St[];
  private readonly start: number;
  readonly source: string;
  constructor(pattern: string, opts: { caseInsensitive?: boolean } = {}) {
    if (pattern.length > MAX_PATTERN) throw new SafeRegexError(`pattern longer than ${MAX_PATTERN} characters`);
    this.source = pattern;
    const ast = new Parser(pattern, !!opts.caseInsensitive).parse();
    const b = new Builder();
    const match = b.add({ kind: 'match', out: -1, out2: -1 });
    this.start = b.build(ast, match);
    this.st = b.st;
  }
  test(text: string, maxLen = 4096): boolean {
    const s = text.length > maxLen ? text.slice(0, maxLen) : text;
    const n = this.st.length;
    let cur: number[] = [], nxt: number[] = [];
    const mark = new Int32Array(n).fill(-1);
    const addState = (list: number[], i: number, pos: number) => {
      const stack = [i];
      while (stack.length) {
        const x = stack.pop()!;
        if (x < 0 || mark[x] === pos) continue;
        mark[x] = pos;
        const t = this.st[x]!;
        if (t.kind === 'split') { stack.push(t.out2, t.out); continue; }
        if (t.kind === 'bol') { if (pos === 0) stack.push(t.out); continue; }
        if (t.kind === 'eol') { if (pos === s.length) stack.push(t.out); continue; }
        list.push(x);
      }
    };
    for (let pos = 0; pos <= s.length; pos++) {
      addState(cur, this.start, pos); // unanchored search: a new thread at every position
      for (const x of cur) if (this.st[x]!.kind === 'match') return true;
      if (pos === s.length) break;
      const c = s.charCodeAt(pos);
      nxt = [];
      for (const x of cur) { const t = this.st[x]!; if (t.kind === 'char' && t.test!(c)) addState(nxt, t.out, pos + 1); }
      cur = nxt;
    }
    return false;
  }
}
