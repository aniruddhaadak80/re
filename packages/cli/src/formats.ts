// Output formats for every CLI command. A command produces one JSON value; these functions turn that
// value into TOON, YAML, JSON Lines, CSV, TSV, Markdown or JSON. Pure functions, no dependencies, so
// they also work in a browser.
//
// Limits: depth is capped at MAX_DEPTH (deeper values are written as JSON text), strings are written
// whole (commands already page their output), and cyclic values are refused.

export const OUTPUT_FORMATS = ['text', 'json', 'toon', 'yaml', 'jsonl', 'csv', 'tsv', 'md'] as const;
export type OutputFormat = (typeof OUTPUT_FORMATS)[number];
/** Formats a command cannot produce itself: the CLI asks it for JSON and converts. */
export const CONVERTED_FORMATS: readonly OutputFormat[] = ['toon', 'yaml', 'jsonl', 'csv', 'tsv'];
export const MAX_DEPTH = 64;

export function isOutputFormat(s: unknown): s is OutputFormat {
  return typeof s === 'string' && (OUTPUT_FORMATS as readonly string[]).includes(s);
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/**
 * Bring any value into plain JSON data the way JSON.stringify would: undefined and functions drop
 * out of objects and become null in arrays, non-finite numbers become null, -0 becomes 0, Dates
 * become ISO text, bigint becomes decimal text, toJSON is honoured. Cycles throw.
 */
export function normalize(v: unknown, seen: Set<object> = new Set(), depth = 0): Json {
  if (v === null || v === undefined) return null;
  if (typeof v === 'boolean' || typeof v === 'string') return v;
  if (typeof v === 'number') return Number.isFinite(v) ? (Object.is(v, -0) ? 0 : v) : null;
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'function' || typeof v === 'symbol') return null;
  if (typeof v === 'object') {
    const o = v as { toJSON?: () => unknown };
    if (typeof o.toJSON === 'function' && !(v instanceof Array)) return normalize(o.toJSON(), seen, depth);
    if (v instanceof Uint8Array) return Array.from(v);
    if (seen.has(v)) throw new TypeError('cannot write a cyclic value');
    if (depth > 4096) throw new RangeError('value is nested too deeply');
    seen.add(v);
    try {
      if (Array.isArray(v)) return v.map((x) => (x === undefined || typeof x === 'function' || typeof x === 'symbol' ? null : normalize(x, seen, depth + 1)));
      const out: Record<string, Json> = {};
      for (const [k, x] of Object.entries(v)) {
        if (x === undefined || typeof x === 'function' || typeof x === 'symbol') continue;
        out[k] = normalize(x, seen, depth + 1);
      }
      return out;
    } finally { seen.delete(v); }
  }
  return null;
}

const isPrim = (v: Json): v is null | boolean | number | string => v === null || typeof v !== 'object';
const isObj = (v: Json): v is { [k: string]: Json } => v !== null && typeof v === 'object' && !Array.isArray(v);
const numText = (n: number) => String(n);

// ---------------------------------------------------------------- TOON
// Token-Oriented Object Notation (https://github.com/toon-format/spec): YAML-like indentation for
// objects, `key[N]: a,b` for arrays of primitives, `key[N]{f1,f2}:` plus one row per line for arrays
// of objects that share the same primitive fields, and `- ` list items for everything else.

const TOON_KEY = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const NUMERIC_LIKE = /^-?(?:\d+)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
const LEADING_ZERO = /^-?0\d/;

function toonQuote(s: string): string {
  let out = '"';
  for (const ch of s) {
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else out += ch;
  }
  return out + '"';
}

/** True when a string must be quoted to read back as the same string. */
export function toonNeedsQuotes(s: string, delimiter = ','): boolean {
  if (s === '') return true;
  if (s !== s.trim()) return true;
  if (s === 'true' || s === 'false' || s === 'null') return true;
  if (NUMERIC_LIKE.test(s) || LEADING_ZERO.test(s)) return true;
  if (s.startsWith('-') || s.startsWith('#')) return true;
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 || c === 0x7f) return true;
    if (ch === ':' || ch === '"' || ch === '\\' || ch === '[' || ch === ']' || ch === '{' || ch === '}' || ch === delimiter) return true;
  }
  return false;
}

function toonScalar(v: null | boolean | number | string, delimiter = ','): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return numText(v);
  return toonNeedsQuotes(v, delimiter) ? toonQuote(v) : v;
}

const toonKey = (k: string) => (TOON_KEY.test(k) ? k : toonQuote(k));

/** Field list shared by every element when the array can be a table, else undefined. */
function tableFields(arr: Json[]): string[] | undefined {
  if (!arr.length || !arr.every(isObj)) return undefined;
  const first = Object.keys(arr[0] as object);
  if (!first.length) return undefined;
  for (const el of arr as { [k: string]: Json }[]) {
    const keys = Object.keys(el);
    if (keys.length !== first.length) return undefined;
    for (const k of first) if (!(k in el) || !isPrim(el[k]!)) return undefined;
  }
  return first;
}

function toonArray(key: string, arr: Json[], depth: number, out: string[], lead = ''): void {
  const pad = '  '.repeat(depth);
  const head = `${pad}${lead}${key}[${arr.length}]`;
  if (!arr.length) { out.push(`${head}:`); return; }
  if (arr.every(isPrim)) { out.push(`${head}: ${arr.map((x) => toonScalar(x as null | boolean | number | string)).join(',')}`); return; }
  // a keyless array inside a list item is never a table, and its items sit one level in
  const keyless = lead !== '' && key === '';
  const fields = keyless ? undefined : tableFields(arr);
  if (fields) {
    out.push(`${head}{${fields.map(toonKey).join(',')}}:`);
    const rowPad = '  '.repeat(depth + 1 + (lead ? 1 : 0));
    for (const el of arr as { [k: string]: Json }[]) out.push(rowPad + fields.map((f) => toonScalar(el[f] as null | boolean | number | string)).join(','));
    return;
  }
  out.push(`${head}:`);
  const itemDepth = depth + 1 + (lead && !keyless ? 1 : 0);
  for (const el of arr) toonListItem(el, itemDepth, out);
}

function toonListItem(v: Json, depth: number, out: string[]): void {
  const pad = '  '.repeat(depth);
  if (depth > MAX_DEPTH) { out.push(`${pad}- ${toonQuote(JSON.stringify(v))}`); return; }
  if (isPrim(v)) { out.push(`${pad}- ${toonScalar(v)}`); return; }
  if (Array.isArray(v)) { toonArray('', v, depth, out, '- '); return; }
  const entries = Object.entries(v);
  if (!entries.length) { out.push(`${pad}-`); return; }
  const [k0, v0] = entries[0]!;
  // first field sits on the hyphen line; the others line up under it
  if (isPrim(v0)) out.push(`${pad}- ${toonKey(k0)}: ${toonScalar(v0)}`);
  else if (Array.isArray(v0)) toonArray(toonKey(k0), v0, depth, out, '- ');
  else {
    out.push(`${pad}- ${toonKey(k0)}:`);
    toonObject(v0, depth + 2, out);
  }
  for (const [k, x] of entries.slice(1)) toonField(k, x, depth + 1, out);
}

function toonField(k: string, v: Json, depth: number, out: string[]): void {
  const pad = '  '.repeat(depth);
  if (depth > MAX_DEPTH && !isPrim(v)) { out.push(`${pad}${toonKey(k)}: ${toonQuote(JSON.stringify(v))}`); return; }
  if (isPrim(v)) out.push(`${pad}${toonKey(k)}: ${toonScalar(v)}`);
  else if (Array.isArray(v)) toonArray(toonKey(k), v, depth, out);
  else { out.push(`${pad}${toonKey(k)}:`); toonObject(v, depth + 1, out); }
}

function toonObject(o: { [k: string]: Json }, depth: number, out: string[]): void {
  for (const [k, v] of Object.entries(o)) toonField(k, v, depth, out);
}

/** Encode a value as TOON. */
export function toToon(value: unknown): string {
  const v = normalize(value);
  const out: string[] = [];
  if (isPrim(v)) return toonScalar(v);
  if (Array.isArray(v)) toonArray('', v, 0, out);
  else toonObject(v, 0, out);
  return out.join('\n');
}

// ---------------------------------------------------------------- YAML
// Block style YAML 1.2 that YAML 1.1 readers (PyYAML) read back the same: strings that a reader could
// take for a bool, null, number, date or anything else are double quoted, using JSON escapes, which
// YAML double quoted scalars accept.

const YAML_PLAIN = /^[A-Za-z_/][A-Za-z0-9_ ./@+()-]*$/;
const YAML_RESERVED = /^(?:y|n|yes|no|on|off|true|false|null|~|nan|inf|\.nan|\.inf|-\.inf)$/i;

function yamlString(s: string): string {
  if (YAML_PLAIN.test(s) && !YAML_RESERVED.test(s) && s === s.trimEnd() && !s.includes(' #') && !/^\d{4}-\d\d-\d\d/.test(s) && !/:\s/.test(s)) return s;
  return JSON.stringify(s);
}
function yamlScalar(v: null | boolean | number | string): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return numText(v);
  return yamlString(v);
}
const yamlKey = (k: string) => yamlString(k);

function yamlNode(v: Json, depth: number, out: string[], prefix: string): void {
  // prefix is what goes before the value on its first line: "key:" or "-"
  const pad = '  '.repeat(depth);
  if (isPrim(v)) { out.push(`${pad}${prefix} ${yamlScalar(v)}`); return; }
  if (depth > MAX_DEPTH) { out.push(`${pad}${prefix} ${JSON.stringify(JSON.stringify(v))}`); return; }
  if (Array.isArray(v) && !v.length) { out.push(`${pad}${prefix} []`); return; }
  if (!Array.isArray(v) && !Object.keys(v).length) { out.push(`${pad}${prefix} {}`); return; }
  const start = out.length;
  if (Array.isArray(v)) for (const x of v) yamlNode(x, depth + 1, out, '-');
  else for (const [k, x] of Object.entries(v)) yamlNode(x, depth + 1, out, `${yamlKey(k)}:`);
  // a list item's block starts on the dash line ("- key: value"); a mapping value starts on the next line
  if (prefix === '-') out[start] = `${pad}- ${out[start]!.slice(pad.length + 2)}`;
  else out.splice(start, 0, `${pad}${prefix}`);
}

/** Encode a value as a YAML document. */
export function toYaml(value: unknown): string {
  const v = normalize(value);
  if (isPrim(v)) return yamlScalar(v);
  const out: string[] = [];
  if (Array.isArray(v)) { if (!v.length) return '[]'; for (const x of v) yamlNode(x, 0, out, '-'); }
  else { const e = Object.entries(v); if (!e.length) return '{}'; for (const [k, x] of e) yamlNode(x, 0, out, `${yamlKey(k)}:`); }
  // "-" followed by a nested block on the next line is valid YAML; keep it compact and readable
  return out.join('\n');
}

// ---------------------------------------------------------------- rows (JSONL, CSV, TSV, Markdown)

/**
 * The row collection of a result: the value itself when it is an array, else the largest array of
 * objects among its own fields (tools, functions, results...), else the value as one row.
 * `key` names the field the rows came from, so a caller can say so.
 */
export function rowsOf(value: unknown): { key: string | null; rows: Json[] } {
  const v = normalize(value);
  if (Array.isArray(v)) return { key: null, rows: v };
  if (isObj(v)) {
    let best: string | null = null;
    let len = -1;
    for (const [k, x] of Object.entries(v)) if (Array.isArray(x) && x.length > len && x.some(isObj)) { best = k; len = x.length; }
    if (best !== null) return { key: best, rows: v[best] as Json[] };
    return { key: null, rows: [v] };
  }
  return { key: null, rows: [v] };
}

/** Flatten one row into dotted columns. Arrays and deep values become JSON text in one cell. */
export function flattenRow(row: Json, maxDepth = 3): Record<string, null | boolean | number | string> {
  const out: Record<string, null | boolean | number | string> = {};
  const walk = (v: Json, path: string, d: number) => {
    if (isPrim(v)) { out[path || 'value'] = v; return; }
    if (Array.isArray(v)) { out[path || 'value'] = v.every(isPrim) ? v.map((x) => (x === null ? '' : String(x))).join(';') : JSON.stringify(v); return; }
    if (d >= maxDepth) { out[path || 'value'] = JSON.stringify(v); return; }
    const e = Object.entries(v);
    if (!e.length && path) { out[path] = ''; return; }
    for (const [k, x] of e) walk(x, path ? `${path}.${k}` : k, d + 1);
  };
  walk(row, '', 0);
  return out;
}

function table(value: unknown): { columns: string[]; rows: Record<string, null | boolean | number | string>[] } {
  const flat = rowsOf(value).rows.map((r) => flattenRow(r));
  const columns: string[] = [];
  const seen = new Set<string>();
  for (const r of flat) for (const k of Object.keys(r)) if (!seen.has(k)) { seen.add(k); columns.push(k); }
  return { columns, rows: flat };
}

/** JSON Lines: one compact JSON value per row. */
export function toJsonl(value: unknown): string {
  return rowsOf(value).rows.map((r) => JSON.stringify(r)).join('\n');
}

/**
 * A cell that a spreadsheet would run as a formula (starts with = + - @ or a tab or carriage return)
 * gets a leading apostrophe, unless the cell is a plain number. Strings in reverse engineering output
 * come from the file under study, so they are hostile by default.
 */
export function neutralizeCell(s: string): string {
  if (!s) return s;
  const c = s[0]!;
  if ((c === '=' || c === '+' || c === '-' || c === '@' || c === '\t' || c === '\r') && !NUMERIC_LIKE.test(s)) return `'${s}`;
  return s;
}

const cellText = (v: null | boolean | number | string | undefined) => (v === null || v === undefined ? '' : typeof v === 'number' ? numText(v) : String(v));

/** RFC 4180 CSV with a header row and CRLF line ends. */
export function toCsv(value: unknown, opts: { safe?: boolean } = {}): string {
  const { columns, rows } = table(value);
  const safe = opts.safe !== false;
  const esc = (raw: string) => {
    const s = safe ? neutralizeCell(raw) : raw;
    return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [columns.map(esc).join(',')];
  for (const r of rows) lines.push(columns.map((c) => esc(cellText(r[c]))).join(','));
  return lines.join('\r\n') + '\r\n';
}

/** Tab separated values with a header row. Tab, newline, carriage return and backslash in a cell are written as \t \n \r \\. */
export function toTsv(value: unknown, opts: { safe?: boolean } = {}): string {
  const { columns, rows } = table(value);
  const safe = opts.safe !== false;
  const esc = (raw: string) => (safe ? neutralizeCell(raw) : raw).replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
  const lines = [columns.map(esc).join('\t')];
  for (const r of rows) lines.push(columns.map((c) => esc(cellText(r[c]))).join('\t'));
  return lines.join('\n') + '\n';
}

/** A Markdown table of the rows (GitHub flavour), or a fenced JSON block for a value with no rows. */
export function toMarkdownTable(value: unknown, title?: string): string {
  const { columns, rows } = table(value);
  const head = title ? `## ${title}\n\n` : '';
  if (!columns.length) return `${head}\`\`\`json\n${JSON.stringify(normalize(value), null, 2)}\n\`\`\`\n`;
  const esc = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>');
  return head + [`| ${columns.map(esc).join(' | ')} |`, `|${columns.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${columns.map((c) => esc(cellText(r[c]))).join(' | ')} |`)].join('\n') + '\n';
}

/** Convert one command result to the chosen format. */
export function render(value: unknown, format: OutputFormat, opts: { safe?: boolean; title?: string } = {}): string {
  switch (format) {
    case 'json': return JSON.stringify(normalize(value), null, 2);
    case 'toon': return toToon(value);
    case 'yaml': return toYaml(value);
    case 'jsonl': return toJsonl(value);
    case 'csv': return toCsv(value, opts);
    case 'tsv': return toTsv(value, opts);
    case 'md': return toMarkdownTable(value, opts.title);
    case 'text': return typeof value === 'string' ? value : JSON.stringify(normalize(value), null, 2);
  }
}

/**
 * Read what a command printed with --json: one JSON document, or JSON Lines (verify prints one object
 * per claim). Returns undefined when the text is neither.
 */
export function parseCommandJson(text: string): { ok: true; value: unknown } | { ok: false } {
  const t = text.trim();
  if (!t) return { ok: true, value: null };
  try { return { ok: true, value: JSON.parse(t) }; } catch { /* maybe JSON Lines */ }
  const lines = t.split(/\r?\n/).filter((l) => l.trim());
  const vals: unknown[] = [];
  for (const l of lines) { try { vals.push(JSON.parse(l)); } catch { return { ok: false }; } }
  return { ok: true, value: vals };
}
