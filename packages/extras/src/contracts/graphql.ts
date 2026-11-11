// GraphQL contracts in binaries and bundles: schema SDL, introspection results, and client
// operations (gql`` templates, query strings, precompiled DocumentNode objects).
// The lexer and parser follow the GraphQL October 2021 spec grammar, bounded in tokens and depth.

import { ParseError } from '../util.js';
import { parseJsValue, enclosingBrace, type JsValue } from './jsvalue.js';

// ---------- lexer ----------
type Tok = { k: 'name' | 'punct' | 'string' | 'number' | 'eof'; v: string; at: number };
const PUNCT = new Set(['!', '$', '&', '(', ')', ':', '=', '@', '[', ']', '{', '|', '}', '...']);

export function lexGraphql(s: string, maxTokens = 500_000, tolerant = false): Tok[] {
  const out: Tok[] = [];
  let p = 0;
  const n = s.length;
  while (p < n) {
    if (out.length >= maxTokens) throw new ParseError('graphql: too many tokens');
    if (!tolerant) { p = lexOne(s, p, out); continue; }
    const at = p;
    try { p = lexOne(s, p, out); } catch { out.push({ k: 'punct', v: '\u0000', at }); p = at + 1; }
  }
  out.push({ k: 'eof', v: '', at: n });
  return out;
}
function lexOne(s: string, p: number, out: Tok[]): number {
  const n = s.length;
  const c = s[p]!;
  if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',' || c === '\uFEFF') return p + 1;
  if (c === '#') { while (p < n && s[p] !== '\n' && s[p] !== '\r') p++; return p; }
  const at = p;
  if (c === '.' && s.startsWith('...', p)) { out.push({ k: 'punct', v: '...', at }); return p + 3; }
  if (PUNCT.has(c)) { out.push({ k: 'punct', v: c, at }); return p + 1; }
  if (/[_A-Za-z]/.test(c)) { while (p < n && /[_0-9A-Za-z]/.test(s[p]!)) p++; out.push({ k: 'name', v: s.slice(at, p), at }); return p; }
  if (c === '-' || (c >= '0' && c <= '9')) {
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(s.slice(p, p + 64));
    if (!m) throw new ParseError('graphql: bad number', p);
    out.push({ k: 'number', v: m[0], at });
    return p + m[0].length;
  }
  if (c === '"') {
    if (s.startsWith('"""', p)) {
      let e = p + 3;
      for (;;) { e = s.indexOf('"""', e); if (e < 0) throw new ParseError('graphql: unterminated block string', p); if (s[e - 1] === '\\') { e += 3; continue; } break; }
      out.push({ k: 'string', v: blockString(s.slice(p + 3, e).replace(/\\"""/g, '"""')), at });
      return e + 3;
    }
    let v = '';
    p++;
    for (;;) {
      if (p >= n || s[p] === '\n' || s[p] === '\r') throw new ParseError('graphql: unterminated string', at);
      const d = s[p]!;
      if (d === '"') { p++; break; }
      if (d === '\\') {
        const e = s[p + 1];
        if (e === 'u') { const h = s.slice(p + 2, p + 6); if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new ParseError('graphql: bad escape', p); v += String.fromCharCode(parseInt(h, 16)); p += 6; continue; }
        const r = e === undefined ? undefined : ESC[e];
        if (r === undefined) throw new ParseError('graphql: bad escape', p);
        v += r; p += 2; continue;
      }
      v += d; p++;
    }
    out.push({ k: 'string', v, at });
    return p;
  }
  throw new ParseError(`graphql: unexpected character ${JSON.stringify(c)}`, p);
}
const ESC: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
function blockString(raw: string): string {
  const lines = raw.split(/\r\n|\n|\r/);
  let common = Infinity;
  for (let i = 1; i < lines.length; i++) { const l = lines[i]!; const ind = l.length - l.replace(/^[ \t]+/, '').length; if (ind < l.length && ind < common) common = ind; }
  if (common !== Infinity) for (let i = 1; i < lines.length; i++) lines[i] = lines[i]!.slice(common);
  while (lines.length && !lines[0]!.trim()) lines.shift();
  while (lines.length && !lines[lines.length - 1]!.trim()) lines.pop();
  return lines.join('\n');
}

// ---------- model ----------
export interface GqlArg { name: string; type: string; default?: string }
export interface GqlField { name: string; type: string; args: GqlArg[]; deprecated?: string | true; description?: string }
export interface GqlType { kind: 'OBJECT' | 'INTERFACE' | 'INPUT_OBJECT' | 'ENUM' | 'UNION' | 'SCALAR'; name: string; fields: GqlField[]; interfaces: string[]; values: string[]; members: string[]; description?: string; extension?: boolean }
export interface GqlSchema { types: GqlType[]; directives: { name: string; args: GqlArg[]; locations: string[] }[]; queryType?: string; mutationType?: string; subscriptionType?: string }
export interface GqlOperation { kind: 'query' | 'mutation' | 'subscription' | 'fragment'; name: string; on?: string; variables: GqlArg[]; rootFields: string[]; fragmentSpreads: string[]; text: string }

class P {
  i = 0;
  depth = 0;
  constructor(readonly t: Tok[], readonly src: string) {}
  get cur(): Tok { return this.t[this.i]!; }
  peek(v: string, k?: Tok['k']): boolean { const c = this.cur; return c.v === v && (k ? c.k === k : c.k !== 'string'); }
  eat(v: string): boolean { if (this.peek(v) && this.cur.k !== 'eof') { this.i++; return true; } return false; }
  need(v: string): void { if (!this.eat(v)) throw new ParseError(`graphql: expected ${v}`, this.cur.at); }
  name(): string { const c = this.cur; if (c.k !== 'name') throw new ParseError('graphql: expected name', c.at); this.i++; return c.v; }
  enter(): void { if (++this.depth > 64) throw new ParseError('graphql: nesting too deep'); }
  type(): string {
    this.enter();
    let r: string;
    if (this.eat('[')) { r = `[${this.type()}]`; this.need(']'); } else r = this.name();
    if (this.eat('!')) r += '!';
    this.depth--;
    return r;
  }
  value(konst: boolean): string {
    this.enter();
    const c = this.cur;
    let r: string;
    if (!konst && this.eat('$')) r = '$' + this.name();
    else if (c.k === 'number' || c.k === 'name') { this.i++; r = c.v; }
    else if (c.k === 'string') { this.i++; r = JSON.stringify(c.v); }
    else if (this.eat('[')) { const a: string[] = []; while (!this.eat(']')) { if (this.cur.k === 'eof') throw new ParseError('graphql: unterminated list'); a.push(this.value(konst)); } r = `[${a.join(', ')}]`; }
    else if (this.eat('{')) { const a: string[] = []; while (!this.eat('}')) { if (this.cur.k === 'eof') throw new ParseError('graphql: unterminated object'); const k = this.name(); this.need(':'); a.push(`${k}: ${this.value(konst)}`); } r = `{${a.join(', ')}}`; }
    else throw new ParseError('graphql: expected value', c.at);
    this.depth--;
    return r;
  }
  directives(konst: boolean): { name: string; args: Record<string, string> }[] {
    const out: { name: string; args: Record<string, string> }[] = [];
    while (this.eat('@')) { const name = this.name(); const args: Record<string, string> = {}; if (this.eat('(')) { while (!this.eat(')')) { const k = this.name(); this.need(':'); args[k] = this.value(konst); } } out.push({ name, args }); }
    return out;
  }
  desc(): string | undefined { if (this.cur.k === 'string') { const v = this.cur.v; this.i++; return v; } return undefined; }
  argDefs(): GqlArg[] {
    const out: GqlArg[] = [];
    if (!this.eat('(')) return out;
    while (!this.eat(')')) { this.desc(); const name = this.name(); this.need(':'); const a: GqlArg = { name, type: this.type() }; if (this.eat('=')) a.default = this.value(true); this.directives(true); out.push(a); }
    return out;
  }
  fieldDefs(input: boolean): GqlField[] {
    const out: GqlField[] = [];
    if (!this.eat('{')) return out;
    while (!this.eat('}')) {
      const description = this.desc();
      const name = this.name();
      const args = input ? [] : this.argDefs();
      this.need(':');
      const f: GqlField = { name, type: this.type(), args };
      if (input && this.eat('=')) this.value(true);
      const dep = this.directives(true).find((d) => d.name === 'deprecated');
      if (dep) f.deprecated = dep.args.reason ? JSON.parse(dep.args.reason) as string : true;
      if (description) f.description = description;
      out.push(f);
    }
    return out;
  }
  selection(rootFields?: string[], spreads?: Set<string>): void {
    this.enter();
    this.need('{');
    while (!this.eat('}')) {
      if (this.cur.k === 'eof') throw new ParseError('graphql: unterminated selection');
      if (this.eat('...')) {
        if (this.peek('on')) { this.i++; this.name(); this.directives(false); this.selection(undefined, spreads); }
        else if (this.peek('{') || this.peek('@')) { this.directives(false); this.selection(undefined, spreads); }
        else { spreads?.add(this.name()); this.directives(false); }
        continue;
      }
      let nm = this.name();
      if (this.eat(':')) nm = `${nm}: ${this.name()}`;
      if (this.eat('(')) { while (!this.eat(')')) { this.name(); this.need(':'); this.value(false); } }
      this.directives(false);
      rootFields?.push(nm);
      if (this.peek('{')) this.selection(undefined, spreads);
    }
    this.depth--;
  }
}

/** Parse one type system definition at the parser cursor (returns undefined for schema/directive defs it records into `schema`). */
function typeDef(p: P, schema: GqlSchema): void {
  const description = p.desc();
  let extension = false;
  if (p.peek('extend')) { p.i++; extension = true; }
  const kw = p.name();
  if (kw === 'schema') {
    p.directives(true);
    p.need('{');
    while (!p.eat('}')) { const op = p.name(); p.need(':'); const t = p.name(); if (op === 'query') schema.queryType = t; else if (op === 'mutation') schema.mutationType = t; else if (op === 'subscription') schema.subscriptionType = t; else throw new ParseError('graphql: bad root operation'); }
    return;
  }
  if (kw === 'directive') {
    p.need('@');
    const name = p.name();
    const args = p.argDefs();
    if (p.peek('repeatable')) p.i++;
    if (!p.peek('on')) throw new ParseError('graphql: expected on');
    p.i++;
    p.eat('|');
    const locations = [p.name()];
    while (p.eat('|')) locations.push(p.name());
    schema.directives.push({ name, args, locations });
    return;
  }
  const kinds: Record<string, GqlType['kind']> = { type: 'OBJECT', interface: 'INTERFACE', input: 'INPUT_OBJECT', enum: 'ENUM', union: 'UNION', scalar: 'SCALAR' };
  const kind = kinds[kw];
  if (!kind) throw new ParseError(`graphql: unknown definition ${kw}`);
  const t: GqlType = { kind, name: p.name(), fields: [], interfaces: [], values: [], members: [] };
  if (description) t.description = description;
  if (extension) t.extension = true;
  if ((kind === 'OBJECT' || kind === 'INTERFACE') && p.peek('implements')) { p.i++; p.eat('&'); t.interfaces.push(p.name()); while (p.eat('&') || (p.cur.k === 'name' && !p.peek('{') && p.t[p.i + 1]?.v !== ':' && /^[A-Z_]/.test(p.cur.v) && !['type', 'interface', 'input', 'enum', 'union', 'scalar', 'schema', 'directive', 'extend'].includes(p.cur.v))) t.interfaces.push(p.name()); }
  p.directives(true);
  if (kind === 'OBJECT' || kind === 'INTERFACE' || kind === 'INPUT_OBJECT') t.fields = p.fieldDefs(kind === 'INPUT_OBJECT');
  else if (kind === 'ENUM') { if (p.eat('{')) while (!p.eat('}')) { p.desc(); t.values.push(p.name()); p.directives(true); } }
  else if (kind === 'UNION') { if (p.eat('=')) { p.eat('|'); t.members.push(p.name()); while (p.eat('|')) t.members.push(p.name()); } }
  schema.types.push(t);
}

const DEF_KW = new Set(['type', 'interface', 'input', 'enum', 'union', 'scalar', 'schema', 'directive', 'extend']);

/** Parse SDL text. With `tolerant`, unparseable stretches are skipped token by token. */
export function parseSdl(text: string, opts: { tolerant?: boolean; maxTypes?: number } = {}): GqlSchema {
  const schema: GqlSchema = { types: [], directives: [] };
  const toks = lexGraphql(text, 2_000_000, !!opts.tolerant);
  const p = new P(toks, text);
  const maxTypes = opts.maxTypes ?? 20000;
  while (p.cur.k !== 'eof' && schema.types.length < maxTypes) {
    const start = p.i;
    const c = p.cur;
    const startsDef = (c.k === 'name' && DEF_KW.has(c.v)) || (c.k === 'string' && p.t[p.i + 1]?.k === 'name' && DEF_KW.has(p.t[p.i + 1]!.v));
    if (!startsDef) { if (!opts.tolerant) throw new ParseError('graphql: expected definition', c.at); p.i++; continue; }
    try { p.depth = 0; typeDef(p, schema); } catch (e) { if (!opts.tolerant) throw e; p.i = start + 1; }
  }
  if (!schema.queryType && schema.types.some((t) => t.name === 'Query' && t.kind === 'OBJECT')) schema.queryType = 'Query';
  if (!schema.mutationType && schema.types.some((t) => t.name === 'Mutation' && t.kind === 'OBJECT')) schema.mutationType = 'Mutation';
  if (!schema.subscriptionType && schema.types.some((t) => t.name === 'Subscription' && t.kind === 'OBJECT')) schema.subscriptionType = 'Subscription';
  return schema;
}

/** Parse an executable definition (operation or fragment) at the start of `text`. */
export function parseOperation(text: string): GqlOperation & { end: number } {
  const toks = lexGraphql(text);
  const p = new P(toks, text);
  const kw = p.name();
  const rootFields: string[] = [];
  const spreads = new Set<string>();
  let op: GqlOperation;
  if (kw === 'fragment') {
    const name = p.name();
    if (!p.peek('on')) throw new ParseError('graphql: expected on');
    p.i++;
    const on = p.name();
    p.directives(false);
    p.selection(rootFields, spreads);
    op = { kind: 'fragment', name, on, variables: [], rootFields, fragmentSpreads: [...spreads], text: '' };
  } else if (kw === 'query' || kw === 'mutation' || kw === 'subscription') {
    const name = p.cur.k === 'name' ? p.name() : '';
    const variables: GqlArg[] = [];
    if (p.eat('(')) while (!p.eat(')')) { p.need('$'); const v: GqlArg = { name: p.name(), type: '' }; p.need(':'); v.type = p.type(); if (p.eat('=')) v.default = p.value(true); p.directives(true); variables.push(v); }
    p.directives(false);
    p.selection(rootFields, spreads);
    op = { kind: kw, name, variables, rootFields, fragmentSpreads: [...spreads], text: '' };
  } else throw new ParseError('graphql: not an operation');
  const end = p.t[p.i - 1]!.at + 1;
  return { ...op, text: text.slice(0, end), end };
}

// ---------- introspection ----------
type Obj = { [k: string]: JsValue };
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
function refName(t: unknown, d = 0): string {
  if (!isObj(t) || d > 16) return '?';
  if (t.kind === 'NON_NULL') return refName(t.ofType, d + 1) + '!';
  if (t.kind === 'LIST') return `[${refName(t.ofType, d + 1)}]`;
  return typeof t.name === 'string' ? t.name : '?';
}
/** Convert an introspection result ({__schema} or {data:{__schema}}) to the schema model. */
export function schemaFromIntrospection(v: unknown): GqlSchema | undefined {
  const root = isObj(v) && isObj(v.data) ? v.data : v;
  const s = isObj(root) ? root.__schema : undefined;
  if (!isObj(s) || !Array.isArray(s.types)) return undefined;
  const nm = (x: unknown): string | undefined => (isObj(x) && typeof x.name === 'string' ? x.name : undefined);
  const schema: GqlSchema = { types: [], directives: [], queryType: nm(s.queryType), mutationType: nm(s.mutationType), subscriptionType: nm(s.subscriptionType) };
  const args = (a: unknown): GqlArg[] => (Array.isArray(a) ? a.filter(isObj).map((x) => { const r: GqlArg = { name: String(x.name), type: refName(x.type) }; if (typeof x.defaultValue === 'string') r.default = x.defaultValue; return r; }) : []);
  for (const t of s.types.slice(0, 20000)) {
    if (!isObj(t) || typeof t.name !== 'string' || t.name.startsWith('__')) continue;
    const kind = String(t.kind) as GqlType['kind'];
    if (!['OBJECT', 'INTERFACE', 'INPUT_OBJECT', 'ENUM', 'UNION', 'SCALAR'].includes(kind)) continue;
    const fl = Array.isArray(t.fields) ? t.fields : Array.isArray(t.inputFields) ? t.inputFields : [];
    const gt: GqlType = {
      kind, name: t.name, interfaces: Array.isArray(t.interfaces) ? t.interfaces.map(nm).filter((x): x is string => !!x) : [],
      values: Array.isArray(t.enumValues) ? t.enumValues.map(nm).filter((x): x is string => !!x) : [],
      members: Array.isArray(t.possibleTypes) && kind === 'UNION' ? t.possibleTypes.map(nm).filter((x): x is string => !!x) : [],
      fields: fl.filter(isObj).map((f) => { const r: GqlField = { name: String(f.name), type: refName(f.type), args: kind === 'INPUT_OBJECT' ? [] : args(f.args) }; if (f.isDeprecated === true) r.deprecated = typeof f.deprecationReason === 'string' ? f.deprecationReason : true; if (typeof f.description === 'string') r.description = f.description; return r; }),
    };
    if (typeof t.description === 'string') gt.description = t.description;
    schema.types.push(gt);
  }
  if (Array.isArray(s.directives)) for (const d of s.directives) if (isObj(d) && typeof d.name === 'string') schema.directives.push({ name: d.name, args: args(d.args), locations: Array.isArray(d.locations) ? d.locations.map(String) : [] });
  return schema;
}

/** Render the schema model as SDL. */
export function schemaToSdl(s: GqlSchema, opts: { skipBuiltins?: boolean } = {}): string {
  const BUILTIN = new Set(['String', 'Int', 'Float', 'Boolean', 'ID']);
  const BUILTIN_DIR = new Set(['skip', 'include', 'deprecated', 'specifiedBy', 'oneOf']);
  const out: string[] = [];
  const std = (!s.queryType || s.queryType === 'Query') && (!s.mutationType || s.mutationType === 'Mutation') && (!s.subscriptionType || s.subscriptionType === 'Subscription');
  if (!std) { out.push('schema {'); if (s.queryType) out.push(`  query: ${s.queryType}`); if (s.mutationType) out.push(`  mutation: ${s.mutationType}`); if (s.subscriptionType) out.push(`  subscription: ${s.subscriptionType}`); out.push('}', ''); }
  const args = (a: GqlArg[]): string => (a.length ? `(${a.map((x) => `${x.name}: ${x.type}${x.default !== undefined ? ` = ${x.default}` : ''}`).join(', ')})` : '');
  for (const d of s.directives) if (!(opts.skipBuiltins !== false && BUILTIN_DIR.has(d.name))) out.push(`directive @${d.name}${args(d.args)} on ${d.locations.join(' | ')}`, '');
  for (const t of s.types) {
    if (opts.skipBuiltins !== false && t.kind === 'SCALAR' && BUILTIN.has(t.name)) continue;
    const ext = t.extension ? 'extend ' : '';
    if (t.kind === 'SCALAR') { out.push(`${ext}scalar ${t.name}`, ''); continue; }
    if (t.kind === 'UNION') { out.push(`${ext}union ${t.name} = ${t.members.join(' | ')}`, ''); continue; }
    if (t.kind === 'ENUM') { out.push(`${ext}enum ${t.name} {`, ...t.values.map((v) => `  ${v}`), '}', ''); continue; }
    const kw = t.kind === 'OBJECT' ? 'type' : t.kind === 'INTERFACE' ? 'interface' : 'input';
    out.push(`${ext}${kw} ${t.name}${t.interfaces.length ? ` implements ${t.interfaces.join(' & ')}` : ''} {`);
    for (const f of t.fields) out.push(`  ${f.name}${args(f.args)}: ${f.type}${f.deprecated ? ` @deprecated${f.deprecated !== true ? `(reason: ${JSON.stringify(f.deprecated)})` : ''}` : ''}`);
    out.push('}', '');
  }
  return out.join('\n');
}

// ---------- scanning ----------
export interface FoundSchema { offset: number; length: number; source: 'sdl' | 'introspection'; format?: 'json' | 'js-literal' | 'json-string'; queryType?: string; mutationType?: string; subscriptionType?: string; typeCount: number; schema: GqlSchema }
export interface FoundOperation extends GqlOperation { offset: number; source: 'text' | 'document-ast' }

const printable = (c: number): boolean => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160;
function region(text: string, at: number, maxBack: number, maxFwd: number): [number, number] {
  let a = at, b = at;
  const lo = Math.max(0, at - maxBack), hi = Math.min(text.length, at + maxFwd);
  while (a > lo && printable(text.charCodeAt(a - 1))) a--;
  while (b < hi && printable(text.charCodeAt(b))) b++;
  return [a, b];
}
/** Undo one level of JS string escaping when a region looks like an escaped string body. */
function unescapeIfNeeded(s: string): string {
  const esc = (s.match(/\\n/g) ?? []).length, nl = (s.match(/\n/g) ?? []).length;
  if (esc <= nl) return s;
  return s.replace(/\\(u[0-9a-fA-F]{4}|n|t|r|"|'|\\)/g, (_m, e: string) => (e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e[0] === 'u' ? String.fromCharCode(parseInt(e.slice(1), 16)) : e));
}

/** Find GraphQL schemas (SDL and introspection) in text. */
export function findGraphqlSchemas(text: string, opts: { max?: number; maxChars?: number } = {}): FoundSchema[] {
  const out: FoundSchema[] = [];
  const max = opts.max ?? 20, maxChars = opts.maxChars ?? 4 << 20;
  const covered: [number, number][] = [];
  const inCovered = (i: number): boolean => covered.some(([a, b]) => i >= a && i < b);
  // SDL: a root type or schema block
  const re = /\b(?:type[ \t\r\n]+(?:Query|Mutation|Subscription)\b[^{}\n]{0,200}\{|schema[ \t\r\n]*\{[ \t\r\n]*query[ \t\r\n]*:)/g;
  let n = 0;
  for (let m = re.exec(text); m && out.length < max && n < 2000; m = re.exec(text), n++) {
    if (inCovered(m.index)) continue;
    const [a, b] = region(text, m.index, maxChars, maxChars);
    const body = unescapeIfNeeded(text.slice(a, b));
    let schema: GqlSchema;
    try { schema = parseSdl(body, { tolerant: true }); } catch { continue; }
    const named = schema.types.filter((t) => !t.extension);
    if (!named.some((t) => t.name === (schema.queryType ?? 'Query')) && !schema.mutationType && !schema.subscriptionType) continue;
    if (named.length < 1) continue;
    out.push({ offset: a, length: b - a, source: 'sdl', queryType: schema.queryType, mutationType: schema.mutationType, subscriptionType: schema.subscriptionType, typeCount: schema.types.length, schema });
    covered.push([a, b]);
  }
  // introspection: "__schema" key in JSON, a JS literal, or a JSON string
  const ri = /(["']?)__schema\1\s*:\s*\{|\\"__schema\\"\s*:\s*\{/g;
  n = 0;
  for (let m = ri.exec(text); m && out.length < max && n < 2000; m = ri.exec(text), n++) {
    if (inCovered(m.index)) continue;
    const escaped = m[0].startsWith('\\');
    let open = enclosingBrace(text, m.index, 1 << 12);
    if (open < 0) continue;
    // {data:{__schema}} wrappers: step out once more when the parent object is a data key
    const outer = enclosingBrace(text, open, 1 << 12);
    if (outer >= 0 && /["']?data["']?\s*:\s*$/.test(text.slice(Math.max(outer + 1, open - 12), open))) open = outer;
    const tryAt = (v: unknown, at: number, end: number, format: FoundSchema['format']): boolean => {
      const schema = schemaFromIntrospection(v);
      if (!schema) return false;
      out.push({ offset: at, length: end - at, source: 'introspection', format, queryType: schema.queryType, mutationType: schema.mutationType, subscriptionType: schema.subscriptionType, typeCount: schema.types.length, schema });
      covered.push([at, end]);
      return true;
    };
    if (!escaped) {
      try {
        const { value, end } = parseJsValue(text, open, { maxChars });
        let strict = true;
        try { JSON.parse(text.slice(open, end)); } catch { strict = false; }
        if (tryAt(value, open, end, strict ? 'json' : 'js-literal')) continue;
      } catch { /* fall through */ }
    }
    // escaped JSON in a JS string: the quote before the opening brace
    for (let q = open - 1; q >= Math.max(0, open - 2); q--) {
      const qc = text[q];
      if (qc !== '"' && qc !== "'" && qc !== '`') continue;
      try {
        const { value: inner, end } = parseJsValue(text, q, { maxChars });
        if (typeof inner === 'string' && tryAt(JSON.parse(inner), q, end, 'json-string')) break;
      } catch { /* not it */ }
    }
  }
  return out;
}

/** Find GraphQL operations and fragments in text, plus precompiled DocumentNode literals. */
export function findGraphqlOperations(text: string, opts: { max?: number } = {}): FoundOperation[] {
  const out: FoundOperation[] = [];
  const max = opts.max ?? 5000;
  const seen = new Set<string>();
  const push = (o: FoundOperation): void => { const k = `${o.kind}:${o.name}:${o.offset}`; if (!seen.has(k) && out.length < max) { seen.add(k); out.push(o); } };
  const re = /(?:(query|mutation|subscription)[ \t\r\n]+[_A-Za-z][_0-9A-Za-z]*[ \t\r\n]*[({@]|fragment[ \t\r\n]+[_A-Za-z][_0-9A-Za-z]*[ \t\r\n]+on[ \t\r\n]+[_A-Za-z][_0-9A-Za-z]*[ \t\r\n]*[{@])/g;
  let n = 0;
  for (let m = re.exec(text); m && out.length < max && n < 50000; m = re.exec(text), n++) {
    const [, b] = region(text, m.index, 0, 64 << 10);
    let body = text.slice(m.index, b);
    // stop at the end of an enclosing JS string or template so the lexer does not run into code
    const prev = text[m.index - 1];
    if (prev === '"' || prev === "'") { const e = body.indexOf(prev); if (e > 0) body = body.slice(0, e); }
    if (prev === '`') { const e = body.search(/`|\$\{/); if (e > 0) body = body.slice(0, e); }
    body = unescapeIfNeeded(body);
    try {
      const op = parseOperationPrefix(body);
      if (op) push({ ...op, offset: m.index, source: 'text' });
    } catch { /* not GraphQL */ }
  }
  // precompiled documents: {kind:"Document",definitions:[...]}
  const rd = /(["']?)kind\1\s*:\s*(["'])Document\2\s*,/g;
  n = 0;
  for (let m = rd.exec(text); m && out.length < max && n < 5000; m = rd.exec(text), n++) {
    const open = enclosingBrace(text, m.index, 64);
    if (open < 0) continue;
    try {
      const { value } = parseJsValue(text, open, { maxChars: 4 << 20 });
      for (const op of operationsFromAst(value)) push({ ...op, offset: open, source: 'document-ast' });
    } catch { /* not a literal */ }
  }
  return out;
}
function parseOperationPrefix(body: string): GqlOperation | undefined {
  // lex only as far as the selection set closes: find a balanced prefix first
  let depth = 0, inStr = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (inStr) { if (c === '\\') i++; else if (c === '"' || c === '\n') inStr = false; continue; }
    if (c === '"') { inStr = true; continue; }
    if (c === '#') { const e = body.indexOf('\n', i); if (e < 0) break; i = e; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { const r = parseOperation(body.slice(0, i + 1)); const { end: _e, ...op } = r; return op; } if (depth < 0) return undefined; }
  }
  return undefined;
}

/** Operations from a graphql-js DocumentNode object (as precompiled by babel or graphql-tag loaders). */
export function operationsFromAst(doc: unknown): GqlOperation[] {
  const out: GqlOperation[] = [];
  if (!isObj(doc) || doc.kind !== 'Document' || !Array.isArray(doc.definitions)) return out;
  const nameOf = (x: unknown): string => (isObj(x) && typeof x.value === 'string' ? x.value : '');
  const typeOf = (t: unknown, d = 0): string => { if (!isObj(t) || d > 16) return '?'; if (t.kind === 'NonNullType') return typeOf(t.type, d + 1) + '!'; if (t.kind === 'ListType') return `[${typeOf(t.type, d + 1)}]`; return nameOf(t.name); };
  for (const def of doc.definitions.slice(0, 1000)) {
    if (!isObj(def)) continue;
    const sel = isObj(def.selectionSet) && Array.isArray(def.selectionSet.selections) ? def.selectionSet.selections : [];
    const rootFields: string[] = [], spreads = new Set<string>();
    const walk = (s: JsValue[], top: boolean, d: number): void => {
      if (d > 64) return;
      for (const x of s) {
        if (!isObj(x)) continue;
        if (x.kind === 'Field' && top) rootFields.push(isObj(x.alias) ? `${nameOf(x.alias)}: ${nameOf(x.name)}` : nameOf(x.name));
        if (x.kind === 'FragmentSpread') spreads.add(nameOf(x.name));
        if (isObj(x.selectionSet) && Array.isArray(x.selectionSet.selections)) walk(x.selectionSet.selections, false, d + 1);
      }
    };
    walk(sel, true, 0);
    if (def.kind === 'OperationDefinition' && (def.operation === 'query' || def.operation === 'mutation' || def.operation === 'subscription')) {
      const variables = Array.isArray(def.variableDefinitions) ? def.variableDefinitions.filter(isObj).map((v) => ({ name: nameOf(isObj(v.variable) ? v.variable.name : undefined), type: typeOf(v.type) })) : [];
      out.push({ kind: def.operation, name: nameOf(def.name), variables, rootFields, fragmentSpreads: [...spreads], text: '' });
    } else if (def.kind === 'FragmentDefinition') {
      out.push({ kind: 'fragment', name: nameOf(def.name), on: isObj(def.typeCondition) ? nameOf(def.typeCondition.name) : undefined, variables: [], rootFields, fragmentSpreads: [...spreads], text: '' });
    }
  }
  return out;
}
