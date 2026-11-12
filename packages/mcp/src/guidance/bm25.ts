// Small BM25 search index over markdown sections. Pure code with no Node APIs, so the same tokenizer
// runs at build time (scripts/build-guidance.mjs writes the index) and at query time.

/** One searchable section of a guidance page. */
export interface GuidanceSection {
  /** stable id: <file>#<anchor> */
  id: string;
  /** file relative to docs/, for example playbooks/elf.md */
  file: string;
  /** heading text of this section */
  title: string;
  /** headings from the page title down to this one */
  path: string[];
  /** heading depth, 1 for the page title */
  level: number;
  /** section body without the heading line */
  text: string;
  /** short content hash, so a stale locator can be detected */
  hash: string;
}

/** Postings are flat pairs [docIndex, termFrequency, docIndex, termFrequency, ...]. */
export interface Bm25Index {
  version: 1;
  k1: number;
  b: number;
  avgdl: number;
  /** token count of each section, by index */
  lengths: number[];
  postings: Record<string, number[]>;
}

export interface GuidanceBundle {
  sections: GuidanceSection[];
  index: Bm25Index;
  /** files the bundle was built from, with their first heading */
  files: { file: string; title: string; kind: 'doc' | 'playbook' }[];
}

const STOP = new Set(('a an and are as at be by can do does for from has have how i if in into is it its of on or that the this to '
  + 'was what when where which who why will with you your use using used me my we our than then there these those they them so not no').split(' '));

const MAX_TOKEN = 40;
const MAX_TOKENS_PER_TEXT = 200_000;

/** Light English stemmer: strips a few common suffixes. Deterministic and linear. */
export function stem(w: string): string {
  if (w.length <= 3 || /\d/.test(w)) return w;
  if (w.endsWith('ies') && w.length > 5) return w.slice(0, -3) + 'y';
  if (w.endsWith('ing') && w.length > 6) return w.slice(0, -3);
  if (w.endsWith('ed') && w.length > 5) return w.slice(0, -2);
  if (w.endsWith('es') && /(sh|ch|x|ss)es$/.test(w)) return w.slice(0, -2);
  if (w.endsWith('s') && !w.endsWith('ss') && !w.endsWith('us') && !w.endsWith('is')) return w.slice(0, -1);
  return w;
}

/**
 * Split text into lowercase tokens. Letters, digits and underscore form words; snake_case names are kept
 * whole and also split into their parts, so "disasm_pseudocode" matches both "disasm_pseudocode" and "pseudocode".
 * Scans characters once, no regular expressions on the input.
 */
export function tokenize(text: string, keepStop = false): string[] {
  const out: string[] = [];
  let cur = '';
  const flush = () => {
    if (!cur) return;
    const w = cur.length > MAX_TOKEN ? cur.slice(0, MAX_TOKEN) : cur;
    cur = '';
    const parts = w.includes('_') ? w.split('_').filter(Boolean) : [];
    for (const p of [w, ...parts]) {
      const t = p.replace(/^_+|_+$/g, '');
      if (!t || (!keepStop && STOP.has(t)) || (t.length < 2 && !/\d/.test(t))) continue;
      out.push(stem(t));
    }
  };
  const n = Math.min(text.length, MAX_TOKENS_PER_TEXT * 8);
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    const word = (c >= 48 && c <= 57) || (c >= 97 && c <= 122) || c === 95;
    if (word) cur += text[i];
    else if (c >= 65 && c <= 90) cur += String.fromCharCode(c + 32);
    else { flush(); if (out.length >= MAX_TOKENS_PER_TEXT) break; }
  }
  flush();
  return out;
}

/** Turn a heading into a URL style anchor. */
export function slug(s: string): string {
  let out = '';
  let dash = false;
  for (const ch of s.toLowerCase()) {
    const c = ch.charCodeAt(0);
    if ((c >= 48 && c <= 57) || (c >= 97 && c <= 122)) { out += ch; dash = false; }
    else if (!dash && out) { out += '-'; dash = true; }
  }
  return out.replace(/-$/, '') || 'section';
}

/** FNV-1a 32 bit hash as 8 hex characters. Enough to notice that a section changed. */
export function shortHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).padStart(8, '0');
}

/**
 * Split a markdown page into sections at #, ## , ### and #### headings. Headings inside fenced code
 * blocks are ignored. Text before the first heading belongs to a section named after the file.
 */
export function splitMarkdown(file: string, md: string): GuidanceSection[] {
  const lines = md.replace(/\r\n?/g, '\n').split('\n');
  const out: GuidanceSection[] = [];
  const stack: string[] = [];
  const used = new Map<string, number>();
  let fence = false;
  let cur: { title: string; level: number; path: string[]; body: string[] } | undefined = { title: file, level: 1, path: [file], body: [] };
  const close = () => {
    if (!cur) return;
    const text = cur.body.join('\n').trim();
    if (text || cur.level > 0) {
      const base = slug(cur.title);
      const n = used.get(base) ?? 0;
      used.set(base, n + 1);
      const anchor = n ? `${base}-${n}` : base;
      if (text || out.length === 0 || cur.title !== file) out.push({ id: `${file}#${anchor}`, file, title: cur.title, path: cur.path, level: cur.level, text, hash: shortHash(cur.title + '\n' + text) });
    }
  };
  for (const line of lines) {
    if (line.trimStart().startsWith('```')) fence = !fence;
    let level = 0;
    if (!fence) while (level < line.length && line[level] === '#') level++;
    if (!fence && level >= 1 && level <= 4 && line[level] === ' ') {
      const title = line.slice(level + 1).trim().replace(/#+$/, '').trim();
      if (cur && cur.title === file && !cur.body.join('').trim()) cur = undefined; // empty preamble
      close();
      stack.length = Math.min(stack.length, level - 1);
      while (stack.length < level - 1) stack.push('');
      stack[level - 1] = title;
      cur = { title, level, path: stack.filter(Boolean).slice(), body: [] };
    } else cur?.body.push(line);
  }
  close();
  return out.filter((s) => s.text || s.level <= 2);
}

/** Build the BM25 index. Heading words count three times, so a section about a topic outranks a passing mention. */
export function buildIndex(sections: GuidanceSection[], k1 = 1.2, b = 0.75): Bm25Index {
  const postings: Record<string, number[]> = Object.create(null);
  const lengths: number[] = [];
  sections.forEach((s, i) => {
    const toks = [...tokenize(s.text), ...tokenize(s.path.join(' ')), ...tokenize(s.title), ...tokenize(s.title)];
    lengths.push(toks.length);
    const tf = new Map<string, number>();
    for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
    for (const [t, n] of [...tf].sort((x, y) => (x[0] < y[0] ? -1 : 1))) (postings[t] ??= []).push(i, n);
  });
  const sorted: Record<string, number[]> = {};
  for (const k of Object.keys(postings).sort()) sorted[k] = postings[k]!;
  const avgdl = lengths.length ? lengths.reduce((a, x) => a + x, 0) / lengths.length : 0;
  return { version: 1, k1, b, avgdl: Math.round(avgdl * 1000) / 1000, lengths, postings: sorted };
}

export interface SearchHit { index: number; score: number; matched: string[] }

/**
 * Rank sections for a query. Sections that hold every query term rank before sections holding only
 * some, then by BM25 score. Unknown terms are reported, never fatal.
 */
export function searchIndex(index: Bm25Index, query: string, opts: { limit?: number; require?: 'all' | 'any'; filter?: (i: number) => boolean } = {}): { hits: SearchHit[]; terms: string[]; unknown: string[] } {
  const terms = [...new Set(tokenize(query.slice(0, 2000)))].slice(0, 32);
  const N = index.lengths.length;
  const scores = new Map<number, { score: number; matched: Set<string> }>();
  const unknown: string[] = [];
  for (const t of terms) {
    const post = Object.prototype.hasOwnProperty.call(index.postings, t) ? index.postings[t]! : undefined;
    if (!post) { unknown.push(t); continue; }
    const df = post.length / 2;
    const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
    for (let j = 0; j + 1 < post.length; j += 2) {
      const d = post[j]!, tf = post[j + 1]!;
      if (opts.filter && !opts.filter(d)) continue;
      const dl = index.lengths[d] ?? 0;
      const s = idf * (tf * (index.k1 + 1)) / (tf + index.k1 * (1 - index.b + index.b * dl / (index.avgdl || 1)));
      const e = scores.get(d) ?? { score: 0, matched: new Set<string>() };
      e.score += s;
      e.matched.add(t);
      scores.set(d, e);
    }
  }
  const known = terms.length - unknown.length;
  let hits = [...scores].map(([index, e]) => ({ index, score: Math.round(e.score * 1000) / 1000, matched: [...e.matched] }));
  if (opts.require === 'all') hits = hits.filter((h) => h.matched.length === known);
  hits.sort((x, y) => (y.matched.length - x.matched.length) || (y.score - x.score) || (x.index - y.index));
  return { hits: hits.slice(0, Math.max(1, Math.min(opts.limit ?? 8, 50))), terms, unknown };
}
