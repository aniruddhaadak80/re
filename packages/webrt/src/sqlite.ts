// Pure TypeScript SQLite 3 file reader: header, schema, b-tree walking with overflow pages, record
// decoding, row counts and sample rows, plus a small read-only SELECT engine that never runs SQLite.
import { Reader, InputError } from './util.js';

export type SqlValue = null | number | bigint | string | Uint8Array;

export interface SqliteHeader { pageSize: number; pageCount: number; reserved: number; encoding: 'utf8' | 'utf16le' | 'utf16be'; schemaFormat: number; userVersion: number; applicationId: number; writeVersion: number; readVersion: number; freelistPages: number; sqliteVersion: number; fileChangeCounter: number }

export interface ColumnInfo { name: string; type: string; pk: boolean; notNull: boolean }

export interface SchemaObject { type: string; name: string; tblName: string; rootPage: number; sql: string | null }

export interface TableInfo { name: string; rootPage: number; sql: string | null; columns: ColumnInfo[]; withoutRowid: boolean; rowidAlias?: string; rowCount?: number; indexes: string[]; error?: string }

const MAX_DEPTH = 64;
const MAX_ROWS_SCANNED = 2_000_000;

export function isSqlite(bytes: Uint8Array): boolean {
  if (bytes.length < 16) return false;
  const magic = 'SQLite format 3\u0000';
  for (let i = 0; i < 16; i++) if (bytes[i] !== magic.charCodeAt(i)) return false;
  return true;
}

export class SqliteFile {
  readonly r: Reader;
  readonly header: SqliteHeader;
  readonly usable: number;
  private readonly td: TextDecoder;
  private schemaCache?: SchemaObject[];

  constructor(readonly bytes: Uint8Array) {
    if (!isSqlite(bytes)) throw new InputError('not a SQLite 3 database (bad magic)');
    if (bytes.length < 100) throw new InputError('truncated SQLite header');
    this.r = new Reader(bytes);
    const r = this.r;
    let pageSize = r.u16(16, false);
    if (pageSize === 1) pageSize = 65536;
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0) throw new InputError(`invalid page size ${pageSize}`);
    const reserved = r.u8(20);
    const enc = r.u32(56, false);
    this.header = {
      pageSize, reserved, pageCount: r.u32(28, false) || Math.floor(bytes.length / pageSize), encoding: enc === 2 ? 'utf16le' : enc === 3 ? 'utf16be' : 'utf8',
      schemaFormat: r.u32(44, false), userVersion: r.u32(60, false), applicationId: r.u32(68, false), writeVersion: r.u8(18), readVersion: r.u8(19), freelistPages: r.u32(36, false), sqliteVersion: r.u32(96, false), fileChangeCounter: r.u32(24, false),
    };
    this.usable = pageSize - reserved;
    if (this.usable < 480) throw new InputError('usable page size too small');
    this.td = new TextDecoder(this.header.encoding === 'utf8' ? 'utf-8' : this.header.encoding === 'utf16le' ? 'utf-16le' : 'utf-16be');
  }

  private pageOffset(n: number): number {
    if (!Number.isInteger(n) || n < 1 || n > this.header.pageCount) throw new InputError(`page ${n} out of range`);
    const off = (n - 1) * this.header.pageSize;
    if (off + this.header.pageSize > this.bytes.length) throw new InputError(`page ${n} past end of file`);
    return off;
  }

  private varint(off: number): [bigint | number, number] {
    let v = 0n;
    for (let i = 0; i < 9; i++) {
      const b = this.r.u8(off + i);
      if (i === 8) { v = (v << 8n) | BigInt(b); return [toNum(BigInt.asIntN(64, v)), 9]; }
      v = (v << 7n) | BigInt(b & 0x7f);
      if (!(b & 0x80)) return [toNum(BigInt.asIntN(64, v)), i + 1];
    }
    return [toNum(v), 9];
  }

  private payload(cellOff: number, total: number, isIndex: boolean, pageEnd: number): Uint8Array {
    const U = this.usable;
    const X = isIndex ? Math.floor(((U - 12) * 64) / 255) - 23 : U - 35;
    if (total < 0 || total > 1 << 30) throw new InputError(`payload size ${total} not sane`);
    if (total <= X) { if (cellOff + total > pageEnd) throw new InputError('cell payload runs past page'); return this.r.slice(cellOff, total); }
    const M = Math.floor(((U - 12) * 32) / 255) - 23;
    const K = M + ((total - M) % (U - 4));
    const local = K <= X ? K : M;
    const out = new Uint8Array(total);
    out.set(this.r.slice(cellOff, local), 0);
    let got = local;
    let next = this.r.u32(cellOff + local, false);
    let hops = 0;
    while (got < total) {
      if (next === 0 || ++hops > this.header.pageCount) throw new InputError('broken overflow chain');
      const po = this.pageOffset(next);
      next = this.r.u32(po, false);
      const n = Math.min(U - 4, total - got);
      out.set(this.r.slice(po + 4, n), got);
      got += n;
    }
    return out;
  }

  /** Decode a record into values. */
  decodeRecord(p: Uint8Array): SqlValue[] {
    const r = new Reader(p);
    const vi = (off: number): [number, number] => {
      let v = 0;
      for (let i = 0; i < 9; i++) {
        const b = r.u8(off + i);
        if (i === 8) return [v * 256 + b, 9];
        v = v * 128 + (b & 0x7f);
        if (!(b & 0x80)) return [v, i + 1];
      }
      return [v, 9];
    };
    const [hsize, hl] = vi(0);
    if (hsize > p.length || hsize < hl) throw new InputError('bad record header');
    const types: number[] = [];
    for (let o = hl; o < hsize && types.length < 4096;) { const [t, n] = vi(o); types.push(t); o += n; }
    const out: SqlValue[] = [];
    let o = hsize;
    for (const t of types) {
      switch (t) {
        case 0: out.push(null); break;
        case 1: out.push(r.dv.getInt8((r.need(o, 1), o))); o += 1; break;
        case 2: out.push(r.dv.getInt16((r.need(o, 2), o))); o += 2; break;
        case 3: { r.need(o, 3); const v = (p[o] as number) << 16 | (p[o + 1] as number) << 8 | (p[o + 2] as number); out.push(v & 0x800000 ? v - 0x1000000 : v); o += 3; break; }
        case 4: out.push(r.i32(o, false)); o += 4; break;
        case 5: { r.need(o, 6); const hi = r.dv.getInt16(o); const lo = r.u32(o + 2, false); out.push(hi * 4294967296 + lo); o += 6; break; }
        case 6: { r.need(o, 8); out.push(toNum(r.dv.getBigInt64(o))); o += 8; break; }
        case 7: out.push(r.f64(o, false)); o += 8; break;
        case 8: out.push(0); break;
        case 9: out.push(1); break;
        case 10: case 11: out.push(null); break;
        default: {
          const len = t >= 12 ? Math.floor((t - (t % 2 ? 13 : 12)) / 2) : 0;
          const b = r.slice(o, len);
          out.push(t % 2 ? this.td.decode(b) : b.slice());
          o += len;
        }
      }
    }
    return out;
  }

  /**
   * Walk a b-tree in key order. For table trees calls cb(rowid, payload); for index trees cb(undefined, payload).
   * countOnly skips payload decoding. Return false from cb to stop.
   */
  walkTree(root: number, cb: (rowid: number | bigint | undefined, payload: Uint8Array | undefined) => boolean | void, opts: { countOnly?: boolean } = {}): void {
    const seen = new Set<number>();
    let stop = false;
    const visit = (page: number, depth: number) => {
      if (stop) return;
      if (depth > MAX_DEPTH) throw new InputError('b-tree too deep');
      if (seen.has(page)) throw new InputError(`b-tree cycle at page ${page}`);
      seen.add(page);
      const po = this.pageOffset(page);
      const ho = page === 1 ? po + 100 : po;
      const type = this.r.u8(ho);
      const cells = this.r.u16(ho + 3, false);
      const interior = type === 2 || type === 5;
      if (![2, 5, 10, 13].includes(type)) throw new InputError(`page ${page} has unknown b-tree type ${type}`);
      const ptrs = ho + (interior ? 12 : 8);
      const pageEnd = po + this.header.pageSize;
      if (ptrs + cells * 2 > pageEnd) throw new InputError(`page ${page} cell count ${cells} overflows page`);
      for (let i = 0; i < cells && !stop; i++) {
        const c = po + this.r.u16(ptrs + i * 2, false);
        if (c < ptrs || c >= pageEnd) throw new InputError(`page ${page} cell ${i} pointer out of range`);
        if (type === 5) { visit(this.r.u32(c, false), depth + 1); continue; }
        if (type === 13) {
          const [plen, n1] = this.varint(c);
          const [rowid, n2] = this.varint(c + n1);
          const pl = opts.countOnly ? undefined : this.payload(c + n1 + n2, Number(plen), false, pageEnd);
          if (cb(rowid, pl) === false) stop = true;
          continue;
        }
        if (type === 2) {
          visit(this.r.u32(c, false), depth + 1);
          if (stop) return;
          const [plen, n1] = this.varint(c + 4);
          if (cb(undefined, opts.countOnly ? undefined : this.payload(c + 4 + n1, Number(plen), true, pageEnd)) === false) stop = true;
          continue;
        }
        const [plen, n1] = this.varint(c);
        if (cb(undefined, opts.countOnly ? undefined : this.payload(c + n1, Number(plen), true, pageEnd)) === false) stop = true;
      }
      if (interior && !stop) visit(this.r.u32(ho + 8, false), depth + 1);
    };
    visit(root, 0);
  }

  schema(): SchemaObject[] {
    if (this.schemaCache) return this.schemaCache;
    const out: SchemaObject[] = [];
    this.walkTree(1, (_rowid, p) => {
      if (!p) return;
      const v = this.decodeRecord(p);
      out.push({ type: String(v[0]), name: String(v[1]), tblName: String(v[2]), rootPage: Number(v[3] ?? 0), sql: v[4] === null || v[4] === undefined ? null : String(v[4]) });
      return out.length < 100_000;
    });
    this.schemaCache = out;
    return out;
  }

  tables(opts: { counts?: boolean } = {}): TableInfo[] {
    const schema = this.schema();
    const out: TableInfo[] = [];
    for (const o of schema) {
      if (o.type !== 'table') continue;
      const parsed = o.sql ? parseCreateTable(o.sql) : { columns: [], withoutRowid: false, pkOrder: [] };
      const alias = parsed.columns.find((c) => c.pk && c.type.toUpperCase() === 'INTEGER' && parsed.pkOrder.length === 1)?.name;
      const t: TableInfo = { name: o.name, rootPage: o.rootPage, sql: o.sql, columns: parsed.columns, withoutRowid: parsed.withoutRowid, rowidAlias: parsed.withoutRowid ? undefined : alias, indexes: schema.filter((x) => x.type === 'index' && x.tblName === o.name).map((x) => x.name) };
      if (opts.counts !== false && o.rootPage > 0) {
        try { let n = 0; this.walkTree(o.rootPage, () => { n++; return n < MAX_ROWS_SCANNED; }, { countOnly: true }); t.rowCount = n; }
        catch (e) { t.error = (e as Error).message; }
      }
      out.push(t);
    }
    return out;
  }

  /** Visit rows of a table as objects keyed by column name ("rowid" included for rowid tables). Return false to stop. */
  forEachRow(table: string, cb: (row: Record<string, SqlValue>) => boolean | void): number {
    const info = this.tables({ counts: false }).find((t) => t.name.toLowerCase() === table.toLowerCase());
    if (!info) throw new InputError(`no such table: ${table}`);
    const parsed = info.sql ? parseCreateTable(info.sql) : { columns: [], withoutRowid: false, pkOrder: [] as string[] };
    const cols = info.columns.map((c) => c.name);
    // WITHOUT ROWID: the record holds primary key columns first, then the rest in declaration order
    const order = info.withoutRowid ? [...parsed.pkOrder, ...cols.filter((c) => !parsed.pkOrder.includes(c))] : cols;
    let scanned = 0;
    this.walkTree(info.rootPage, (rowid, p) => {
      if (!p) return;
      const vals = this.decodeRecord(p);
      const row: Record<string, SqlValue> = {};
      if (!info.withoutRowid) row.rowid = rowid as number;
      order.forEach((c, i) => { row[c] = vals[i] === undefined ? null : (vals[i] as SqlValue); });
      for (let i = order.length; i < vals.length; i++) row[`col${i}`] = vals[i] as SqlValue;
      if (info.rowidAlias && row[info.rowidAlias] === null) row[info.rowidAlias] = rowid as number;
      scanned++;
      if (cb(row) === false) return false;
      return scanned < MAX_ROWS_SCANNED;
    });
    return scanned;
  }
}

function toNum(v: bigint): number | bigint {
  return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
}

// ---------- CREATE TABLE parsing ----------
function splitTopLevel(s: string): string[] {
  const out: string[] = [];
  let depth = 0, cur = '', q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    if (q) { cur += ch; if (ch === q) { if (s[i + 1] === q) { cur += s[++i]; } else q = null; } continue; }
    if (ch === "'" || ch === '"' || ch === '`') { q = ch; cur += ch; continue; }
    if (ch === '[') { const j = s.indexOf(']', i); cur += s.slice(i, j < 0 ? s.length : j + 1); i = j < 0 ? s.length : j; continue; }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function unquote(id: string): string {
  const s = id.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith('`') && s.endsWith('`'))) return s.slice(1, -1).replace(/""/g, '"');
  if (s.startsWith('[') && s.endsWith(']')) return s.slice(1, -1);
  if (s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  return s;
}

const CONSTRAINT_KW = /^(CONSTRAINT|PRIMARY|NOT|NULL|UNIQUE|CHECK|DEFAULT|COLLATE|REFERENCES|GENERATED|AS)$/i;

export function parseCreateTable(sql: string): { columns: ColumnInfo[]; withoutRowid: boolean; pkOrder: string[] } {
  const open = sql.indexOf('(');
  const close = sql.lastIndexOf(')');
  if (open < 0 || close < open) return { columns: [], withoutRowid: false, pkOrder: [] };
  const body = sql.slice(open + 1, close);
  const tail = sql.slice(close + 1);
  const withoutRowid = /WITHOUT\s+ROWID/i.test(tail);
  const columns: ColumnInfo[] = [];
  let pkOrder: string[] = [];
  for (const def of splitTopLevel(body).slice(0, 2000)) {
    if (/^(CONSTRAINT\s+\S+\s+)?(PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b/i.test(def)) {
      const m = /PRIMARY\s+KEY\s*\(([^)]*)\)/i.exec(def);
      if (m && m[1]) {
        pkOrder = splitTopLevel(m[1]).map((x) => unquote(x.split(/\s+/)[0] ?? ''));
        for (const c of columns) if (pkOrder.includes(c.name)) c.pk = true;
      }
      continue;
    }
    const tokens = def.match(/"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\]|'(?:[^']|'')*'|\S+/g) ?? [];
    const name = unquote(tokens[0] ?? '');
    const typeParts: string[] = [];
    let i = 1;
    for (; i < tokens.length && !CONSTRAINT_KW.test(tokens[i] as string); i++) typeParts.push(tokens[i] as string);
    const rest = tokens.slice(i).join(' ');
    const pk = /PRIMARY\s+KEY/i.test(rest);
    if (pk) pkOrder = [name];
    columns.push({ name, type: typeParts.join(' '), pk, notNull: /NOT\s+NULL/i.test(rest) });
  }
  return { columns, withoutRowid, pkOrder };
}

// ---------- read-only SELECT ----------
type Tok = { t: 'id' | 'num' | 'str' | 'op' | 'kw'; v: string };
const KW = new Set(['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'ORDER', 'BY', 'ASC', 'DESC', 'LIMIT', 'OFFSET', 'IS', 'NULL', 'LIKE', 'IN', 'COUNT', 'DISTINCT', 'AS', 'BETWEEN', 'GLOB']);
const FORBIDDEN = /^(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|REPLACE|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|ANALYZE|WITH|UNION|JOIN|LOAD_EXTENSION)$/i;

export function tokenizeSql(sql: string): Tok[] {
  if (sql.length > 10_000) throw new InputError('query too long');
  const toks: Tok[] = [];
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i] as string;
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '-' && sql[i + 1] === '-') { const j = sql.indexOf('\n', i); i = j < 0 ? sql.length : j; continue; }
    if (ch === '/' && sql[i + 1] === '*') { const j = sql.indexOf('*/', i + 2); if (j < 0) throw new InputError('unterminated comment'); i = j + 2; continue; }
    if (ch === "'") { let j = i + 1, v = ''; for (;;) { if (j >= sql.length) throw new InputError('unterminated string'); if (sql[j] === "'") { if (sql[j + 1] === "'") { v += "'"; j += 2; continue; } break; } v += sql[j]; j++; } toks.push({ t: 'str', v }); i = j + 1; continue; }
    if (ch === '"' || ch === '`' || ch === '[') { const end = ch === '[' ? ']' : ch; const j = sql.indexOf(end, i + 1); if (j < 0) throw new InputError('unterminated identifier'); toks.push({ t: 'id', v: sql.slice(i + 1, j) }); i = j + 1; continue; }
    const num = /^-?(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+|0x[0-9a-fA-F]+)/.exec(sql.slice(i, i + 64));
    if (num && (ch !== '-' || !toks.length || toks[toks.length - 1]?.t === 'op' || toks[toks.length - 1]?.t === 'kw')) { toks.push({ t: 'num', v: num[0] }); i += num[0].length; continue; }
    const op = /^(<=|>=|<>|!=|==|=|<|>|\(|\)|,|\*|;)/.exec(sql.slice(i, i + 2));
    if (op) { toks.push({ t: 'op', v: op[0] }); i += op[0].length; continue; }
    const id = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(sql.slice(i, i + 256));
    if (id) {
      const up = id[0].toUpperCase();
      if (FORBIDDEN.test(up)) throw new InputError(`only plain SELECT is allowed (found ${up})`);
      toks.push(KW.has(up) ? { t: 'kw', v: up } : { t: 'id', v: id[0] }); i += id[0].length; continue;
    }
    throw new InputError(`unexpected character ${JSON.stringify(ch)} at ${i}`);
  }
  // a single trailing semicolon is fine, anything after it is not
  const semi = toks.findIndex((t) => t.t === 'op' && t.v === ';');
  if (semi >= 0) { if (semi !== toks.length - 1) throw new InputError('only one statement is allowed'); toks.pop(); }
  return toks;
}

type Expr =
  | { k: 'lit'; v: SqlValue }
  | { k: 'col'; name: string }
  | { k: 'bin'; op: string; a: Expr; b: Expr }
  | { k: 'not'; a: Expr }
  | { k: 'isnull'; a: Expr; neg: boolean }
  | { k: 'like'; a: Expr; pattern: Expr; neg: boolean; glob: boolean }
  | { k: 'in'; a: Expr; list: Expr[]; neg: boolean }
  | { k: 'between'; a: Expr; lo: Expr; hi: Expr; neg: boolean };

export interface SelectPlan { table: string; columns: string[] | '*'; count: boolean; where?: Expr; orderBy?: { col: string; desc: boolean }; limit?: number; offset?: number }

export function parseSelect(sql: string): SelectPlan {
  const toks = tokenizeSql(sql);
  let p = 0;
  const peek = () => toks[p];
  const isKw = (v: string) => peek()?.t === 'kw' && peek()?.v === v;
  const isOp = (v: string) => peek()?.t === 'op' && peek()?.v === v;
  const expectKw = (v: string) => { if (!isKw(v)) throw new InputError(`expected ${v} at token ${p}`); p++; };
  const expectOp = (v: string) => { if (!isOp(v)) throw new InputError(`expected "${v}" at token ${p}`); p++; };
  const ident = (): string => { const t = peek(); if (!t || t.t !== 'id') throw new InputError(`expected a name at token ${p}`); p++; return t.v; };
  expectKw('SELECT');
  let count = false;
  let columns: string[] | '*' = [];
  if (isOp('*')) { p++; columns = '*'; }
  else if (isKw('COUNT')) { p++; expectOp('('); expectOp('*'); expectOp(')'); count = true; if (isKw('AS')) { p++; ident(); } }
  else {
    for (;;) { const c = ident(); (columns as string[]).push(c); if (isKw('AS')) throw new InputError('column aliases are not supported'); if (isOp(',')) { p++; continue; } break; }
    if ((columns as string[]).length > 500) throw new InputError('too many columns');
  }
  expectKw('FROM');
  const table = ident();
  const plan: SelectPlan = { table, columns, count };
  let depth = 0;
  const primary = (): Expr => {
    if (++depth > 64) throw new InputError('expression too deep');
    const t = peek();
    if (!t) throw new InputError('unexpected end of query');
    if (t.t === 'op' && t.v === '(') { p++; const e = orExpr(); expectOp(')'); depth--; return e; }
    if (t.t === 'num') { p++; depth--; return { k: 'lit', v: /^-?0x/i.test(t.v) ? parseInt(t.v, 16) : Number(t.v) }; }
    if (t.t === 'str') { p++; depth--; return { k: 'lit', v: t.v }; }
    if (t.t === 'kw' && t.v === 'NULL') { p++; depth--; return { k: 'lit', v: null }; }
    if (t.t === 'id') { p++; depth--; return { k: 'col', name: t.v }; }
    throw new InputError(`unexpected ${t.v} at token ${p}`);
  };
  const cmp = (): Expr => {
    const a = primary();
    if (isKw('IS')) { p++; let neg = false; if (isKw('NOT')) { p++; neg = true; } expectKw('NULL'); return { k: 'isnull', a, neg }; }
    let neg = false;
    if (isKw('NOT')) { p++; neg = true; }
    if (isKw('LIKE') || isKw('GLOB')) { const glob = isKw('GLOB'); p++; return { k: 'like', a, pattern: primary(), neg, glob }; }
    if (isKw('IN')) { p++; expectOp('('); const list: Expr[] = []; for (;;) { list.push(primary()); if (isOp(',')) { p++; continue; } break; } expectOp(')'); if (list.length > 1000) throw new InputError('IN list too long'); return { k: 'in', a, list, neg }; }
    if (isKw('BETWEEN')) { p++; const lo = primary(); expectKw('AND'); const hi = primary(); return { k: 'between', a, lo, hi, neg }; }
    if (neg) throw new InputError('NOT must be followed by LIKE, GLOB, IN or BETWEEN here');
    const t = peek();
    if (t?.t === 'op' && ['=', '==', '!=', '<>', '<', '<=', '>', '>='].includes(t.v)) { p++; return { k: 'bin', op: t.v, a, b: primary() }; }
    return a;
  };
  const notExpr = (): Expr => { if (isKw('NOT')) { p++; return { k: 'not', a: notExpr() }; } return cmp(); };
  const andExpr = (): Expr => { let e = notExpr(); while (isKw('AND')) { p++; e = { k: 'bin', op: 'AND', a: e, b: notExpr() }; } return e; };
  const orExpr = (): Expr => { let e = andExpr(); while (isKw('OR')) { p++; e = { k: 'bin', op: 'OR', a: e, b: andExpr() }; } return e; };
  if (isKw('WHERE')) { p++; plan.where = orExpr(); }
  if (isKw('ORDER')) { p++; expectKw('BY'); const col = ident(); let desc = false; if (isKw('ASC')) p++; else if (isKw('DESC')) { p++; desc = true; } plan.orderBy = { col, desc }; }
  if (isKw('LIMIT')) { p++; const t = peek(); if (t?.t !== 'num') throw new InputError('LIMIT needs a number'); p++; plan.limit = Math.max(0, Math.floor(Number(t.v))); if (isKw('OFFSET')) { p++; const o = peek(); if (o?.t !== 'num') throw new InputError('OFFSET needs a number'); p++; plan.offset = Math.max(0, Math.floor(Number(o.v))); } }
  if (p !== toks.length) throw new InputError(`unexpected ${toks[p]?.v} at token ${p}`);
  return plan;
}

function cmpVals(a: SqlValue, b: SqlValue): number {
  // SQLite ordering: NULL < numbers < text < blob
  const rank = (v: SqlValue) => (v === null ? 0 : typeof v === 'number' || typeof v === 'bigint' ? 1 : typeof v === 'string' ? 2 : 3);
  const ra = rank(a), rb = rank(b);
  if (ra !== rb) return ra - rb;
  if (ra === 1) { const x = a as number | bigint, y = b as number | bigint; return x < y ? -1 : x > y ? 1 : 0; }
  if (ra === 2) return (a as string) < (b as string) ? -1 : (a as string) > (b as string) ? 1 : 0;
  if (ra === 3) { const x = a as Uint8Array, y = b as Uint8Array; for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return (x[i] as number) - (y[i] as number); return x.length - y.length; }
  return 0;
}

function likeToRe(pattern: string, glob: boolean): RegExp {
  let re = '^';
  for (const ch of pattern.slice(0, 1000)) {
    if (!glob && ch === '%') re += '[\\s\\S]*';
    else if (!glob && ch === '_') re += '[\\s\\S]';
    else if (glob && ch === '*') re += '[\\s\\S]*';
    else if (glob && ch === '?') re += '[\\s\\S]';
    else re += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(re + '$', glob ? 's' : 'is');
}

function evalWhere(e: Expr, row: Record<string, SqlValue>): SqlValue | boolean {
  switch (e.k) {
    case 'lit': return e.v;
    case 'col': {
      const key = Object.keys(row).find((k) => k.toLowerCase() === e.name.toLowerCase());
      if (key === undefined) throw new InputError(`no such column: ${e.name}`);
      return row[key] as SqlValue;
    }
    case 'not': { const v = evalWhere(e.a, row); return v === null ? null : !truthy(v); }
    case 'isnull': { const v = evalWhere(e.a, row); return (v === null) !== e.neg; }
    case 'like': {
      const v = evalWhere(e.a, row), pt = evalWhere(e.pattern, row);
      if (v === null || pt === null) return null;
      return likeToRe(String(pt), e.glob).test(String(v)) !== e.neg;
    }
    case 'in': { const v = evalWhere(e.a, row) as SqlValue; if (v === null) return null; return e.list.some((x) => cmpVals(coerce(v), coerce(evalWhere(x, row) as SqlValue)) === 0) !== e.neg; }
    case 'between': { const v = evalWhere(e.a, row) as SqlValue; if (v === null) return null; const r = cmpVals(v, evalWhere(e.lo, row) as SqlValue) >= 0 && cmpVals(v, evalWhere(e.hi, row) as SqlValue) <= 0; return r !== e.neg; }
    case 'bin': {
      if (e.op === 'AND') { const a = evalWhere(e.a, row); if (a !== null && !truthy(a)) return false; const b = evalWhere(e.b, row); if (b !== null && !truthy(b)) return false; return a === null || b === null ? null : true; }
      if (e.op === 'OR') { const a = evalWhere(e.a, row); if (a !== null && truthy(a)) return true; const b = evalWhere(e.b, row); if (b !== null && truthy(b)) return true; return a === null || b === null ? null : false; }
      const a = evalWhere(e.a, row) as SqlValue, b = evalWhere(e.b, row) as SqlValue;
      if (a === null || b === null) return null;
      const c = cmpVals(coerce(a), coerce(b));
      switch (e.op) { case '=': case '==': return c === 0; case '!=': case '<>': return c !== 0; case '<': return c < 0; case '<=': return c <= 0; case '>': return c > 0; case '>=': return c >= 0; }
      return null;
    }
  }
}

function coerce(v: SqlValue | boolean): SqlValue { return typeof v === 'boolean' ? (v ? 1 : 0) : v; }
function truthy(v: SqlValue | boolean): boolean { if (typeof v === 'boolean') return v; if (v === null) return false; if (typeof v === 'number') return v !== 0; if (typeof v === 'bigint') return v !== 0n; if (typeof v === 'string') return Number(v) !== 0 && !Number.isNaN(Number(v)); return true; }

export interface QueryResult { columns: string[]; rows: SqlValue[][]; rowCount: number; scanned: number; truncated: boolean }

/** Run a read-only SELECT (one table, WHERE, ORDER BY one column, LIMIT/OFFSET). Rows are capped by maxRows. */
export function runSelect(db: SqliteFile, sql: string, opts: { maxRows?: number } = {}): QueryResult {
  const plan = parseSelect(sql);
  const cap = Math.min(opts.maxRows ?? 200, 10_000);
  const limit = Math.min(plan.limit ?? cap, cap);
  const offset = plan.offset ?? 0;
  const tinfo = db.tables({ counts: false }).find((t) => t.name.toLowerCase() === plan.table.toLowerCase());
  if (!tinfo) {
    const view = db.schema().find((o) => o.type === 'view' && o.name.toLowerCase() === plan.table.toLowerCase());
    throw new InputError(view ? `${plan.table} is a view; query its base table instead` : `no such table: ${plan.table}`);
  }
  const allCols = [...(tinfo.withoutRowid ? [] : ['rowid']), ...tinfo.columns.map((c) => c.name)];
  const cols = plan.count ? ['count'] : plan.columns === '*' ? tinfo.columns.map((c) => c.name) : plan.columns;
  if (!plan.count) for (const c of cols) if (!allCols.some((x) => x.toLowerCase() === c.toLowerCase())) throw new InputError(`no such column: ${c}`);
  const pick = (row: Record<string, SqlValue>) => cols.map((c) => { const k = Object.keys(row).find((x) => x.toLowerCase() === c.toLowerCase()); return k === undefined ? null : (row[k] as SqlValue); });
  let scanned = 0, matched = 0;
  const out: SqlValue[][] = [];
  const sortBuf: Record<string, SqlValue>[] = [];
  let truncated = false;
  db.forEachRow(tinfo.name, (row) => {
    scanned++;
    if (plan.where && !truthy(evalWhere(plan.where, row) as SqlValue)) return;
    matched++;
    if (plan.count) return;
    if (plan.orderBy) { if (sortBuf.length < 500_000) sortBuf.push(row); else truncated = true; return; }
    if (matched <= offset) return;
    if (out.length >= limit) { truncated = plan.limit === undefined || plan.limit > cap; return false; }
    out.push(pick(row));
  });
  if (plan.count) return { columns: ['count'], rows: [[matched]], rowCount: 1, scanned, truncated: false };
  if (plan.orderBy) {
    const ob = plan.orderBy;
    const key = (r: Record<string, SqlValue>) => { const k = Object.keys(r).find((x) => x.toLowerCase() === ob.col.toLowerCase()); if (k === undefined) throw new InputError(`no such column: ${ob.col}`); return r[k] as SqlValue; };
    sortBuf.sort((a, b) => (ob.desc ? -1 : 1) * cmpVals(key(a), key(b)));
    const slice = sortBuf.slice(offset, offset + limit);
    if (sortBuf.length - offset > limit && (plan.limit === undefined || plan.limit > cap)) truncated = true;
    for (const r of slice) out.push(pick(r));
  }
  return { columns: cols, rows: out, rowCount: out.length, scanned, truncated };
}

/** JSON-friendly view of a value: blobs become {blob: hex prefix, size}, bigints become strings. */
export function jsonValue(v: SqlValue): unknown {
  if (v instanceof Uint8Array) { let h = ''; for (const b of v.subarray(0, 64)) h += b.toString(16).padStart(2, '0'); return { blob: h, size: v.length }; }
  if (typeof v === 'bigint') return v.toString();
  return v;
}

export function sampleRows(db: SqliteFile, table: string, limit = 5): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  if (limit <= 0) return out;
  db.forEachRow(table, (r) => {
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(r)) o[k] = jsonValue(v);
    out.push(o);
    return out.length < limit;
  });
  return out;
}

