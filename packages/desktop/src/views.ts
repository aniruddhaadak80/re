// Typed views of application state files (text, JSON, key files, XML, plist, SQLite, zip, gzip),
// secret redaction by name, and the desktop task checks that read those views. The check kinds
// follow the task format of rea's desktop tasks (file_present ... row_count) so task files written
// for it work here; RevLens adds ui_element checks on a saved accessibility tree.
// No Node imports: SQLite, inflate and gunzip are passed in by the Node entry.
import { InputError } from './proc.js';
import { parsePlist, isBinaryPlist } from './plist.js';
import { listZip, readZipEntry } from './zip.js';
import { findNodes, checkSelector, type UiSelector } from './uimodel.js';
import type { UiNode } from './gvariant.js';

export type View = unknown;
export interface ViewResult { format: string; view: View; truncated: boolean }
export interface ViewHelpers {
  sqlite?: (bytes: Uint8Array) => { tables: Record<string, { columns: string[]; rows: unknown[][] }>; truncated: boolean };
  inflateRaw?: (b: Uint8Array, max: number) => Uint8Array;
  gunzip?: (b: Uint8Array, max: number) => Uint8Array;
  maxBytes?: number;
}

// ---------------- XML ----------------

export interface XmlElement { name: string; attributes: Record<string, string>; children: (XmlElement | string)[] }

const ENT: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#\d{1,7}|[a-zA-Z]{2,8});/g, (m, e: string) => {
    if (e[0] === '#') { const n = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m; }
    return ENT[e] ?? m;
  });
}

/** Non-validating XML parser: elements, attributes, text and CDATA; comments, processing instructions and DOCTYPE skipped. Bounded depth and node count. */
export function parseXml(text: string, opts: { maxNodes?: number; maxDepth?: number } = {}): { root: XmlElement; truncated: boolean } {
  const maxNodes = opts.maxNodes ?? 200_000, maxDepth = opts.maxDepth ?? 256;
  let i = 0, nodes = 0, truncated = false;
  const stack: XmlElement[] = [];
  let root: XmlElement | undefined;
  const pushText = (t: string) => { const top = stack[stack.length - 1]; if (top && t) { if (nodes++ >= maxNodes) { truncated = true; return; } const last = top.children[top.children.length - 1]; if (typeof last === 'string') top.children[top.children.length - 1] = last + t; else top.children.push(t); } };
  while (i < text.length) {
    const lt = text.indexOf('<', i);
    if (lt < 0) { pushText(decodeEntities(text.slice(i))); break; }
    if (lt > i) pushText(decodeEntities(text.slice(i, lt)));
    if (text.startsWith('<!--', lt)) { const e = text.indexOf('-->', lt + 4); i = e < 0 ? text.length : e + 3; continue; }
    if (text.startsWith('<![CDATA[', lt)) { const e = text.indexOf(']]>', lt + 9); pushText(text.slice(lt + 9, e < 0 ? text.length : e)); i = e < 0 ? text.length : e + 3; continue; }
    if (text.startsWith('<?', lt)) { const e = text.indexOf('?>', lt + 2); i = e < 0 ? text.length : e + 2; continue; }
    if (text.startsWith('<!', lt)) {
      // DOCTYPE, possibly with an internal subset in brackets
      let j = lt + 2, depth = 0;
      for (; j < text.length; j++) { const c = text[j]; if (c === '[') depth++; else if (c === ']') depth--; else if (c === '>' && depth <= 0) break; }
      i = j + 1; continue;
    }
    if (text[lt + 1] === '/') {
      const e = text.indexOf('>', lt); const name = text.slice(lt + 2, e < 0 ? text.length : e).trim();
      const top = stack.pop();
      if (!top || top.name !== name) throw new InputError(`XML end tag </${name}> does not match <${top?.name ?? ''}>`);
      i = e < 0 ? text.length : e + 1; continue;
    }
    // start tag
    let j = lt + 1;
    while (j < text.length && !/[\s/>]/.test(text[j]!)) j++;
    const name = text.slice(lt + 1, j);
    if (!name) throw new InputError(`bad XML tag at ${lt}`);
    const attributes: Record<string, string> = Object.create(null);
    for (;;) {
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (j >= text.length) throw new InputError('unterminated XML tag');
      if (text[j] === '>' || (text[j] === '/' && text[j + 1] === '>')) break;
      let k = j; while (k < text.length && !/[\s=/>]/.test(text[k]!)) k++;
      const an = text.slice(j, k); j = k;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (text[j] !== '=') { attributes[an] = ''; continue; }
      j++; while (j < text.length && /\s/.test(text[j]!)) j++;
      const q = text[j];
      if (q !== '"' && q !== "'") throw new InputError(`unquoted XML attribute ${an}`);
      const e = text.indexOf(q, j + 1); if (e < 0) throw new InputError('unterminated XML attribute');
      attributes[an] = decodeEntities(text.slice(j + 1, e)); j = e + 1;
    }
    const selfClose = text[j] === '/';
    i = j + (selfClose ? 2 : 1);
    const el: XmlElement = { name, attributes, children: [] };
    if (nodes++ >= maxNodes) { truncated = true; break; }
    if (stack.length) stack[stack.length - 1]!.children.push(el); else if (!root) root = el; else throw new InputError('XML has more than one root element');
    if (!selfClose) { if (stack.length >= maxDepth) throw new InputError('XML nested too deep'); stack.push(el); }
  }
  if (!root) throw new InputError('no XML root element');
  if (stack.length && !truncated) throw new InputError(`unclosed XML element <${stack[stack.length - 1]!.name}>`);
  // drop whitespace-only text between elements
  const clean = (e: XmlElement) => { e.children = e.children.filter((c) => typeof c !== 'string' || c.trim() || e.children.every((x) => typeof x === 'string')); for (const c of e.children) if (typeof c !== 'string') clean(c); };
  clean(root);
  return { root, truncated };
}

/** Whole text of an element: every text node inside it, in order. */
export function wholeText(e: XmlElement | string, depth = 0): string {
  if (typeof e === 'string') return e;
  if (depth > 256) return '';
  return e.children.map((c) => wholeText(c, depth + 1)).join('');
}

// ---------------- key files ----------------

/** INI, .desktop and GKeyFile files: {groups: {GROUP: {KEY: VALUE}}}. Keys before any group go to the "" group. */
export function parseKeyFile(text: string): { groups: Record<string, Record<string, string>> } {
  const groups: Record<string, Record<string, string>> = Object.create(null);
  let cur = '';
  for (const raw of text.split(/\r?\n/).slice(0, 500_000)) {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith(';')) continue;
    if (l.startsWith('[') && l.endsWith(']')) { cur = l.slice(1, -1); groups[cur] ??= Object.create(null); continue; }
    const eq = l.indexOf('=');
    if (eq <= 0) continue;
    (groups[cur] ??= Object.create(null))[l.slice(0, eq).trim()] = l.slice(eq + 1).trim();
  }
  return { groups };
}

// ---------------- format detection and views ----------------

const td = new TextDecoder('utf-8', { fatal: false });
function looksText(b: Uint8Array): boolean { const n = Math.min(b.length, 8192); let bad = 0; for (let i = 0; i < n; i++) { const c = b[i]!; if (c === 0) return false; if (c < 9 || (c > 13 && c < 32)) bad++; } return bad <= n / 50; }

export function detectFormat(name: string, b: Uint8Array): string {
  if (b.length >= 16 && td.decode(b.subarray(0, 15)) === 'SQLite format 3') return 'sqlite';
  if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4) return 'zip';
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return 'gzip';
  if (isBinaryPlist(b)) return 'plist';
  if (!looksText(b)) return 'binary';
  const head = td.decode(b.subarray(0, 4096)).replace(/^\uFEFF/, '').trimStart();
  const lower = name.toLowerCase();
  if (/\.plist$/.test(lower) || (head.startsWith('<?xml') && head.includes('<plist')) || head.startsWith('<plist')) return 'plist';
  if (/\.(json|jsonc)$/.test(lower) || ((head.startsWith('{') || head.startsWith('[')) && !/\.(ini|conf|cfg|desktop)$/.test(lower))) return 'json';
  if (head.startsWith('<')) return 'xml';
  if (/\.(ini|desktop|conf|cfg|keyfile|rc)$/.test(lower) || /^\[[^\]\n]+\]\s*\n/.test(head)) return 'keyfile';
  return 'text';
}

/** Build the typed view of one file's bytes. */
export function viewOf(name: string, b: Uint8Array, h: ViewHelpers = {}, depth = 0): ViewResult {
  const max = h.maxBytes ?? 32 * 1024 * 1024;
  const truncated = b.length > max;
  const bytes = truncated ? b.subarray(0, max) : b;
  const fmt = detectFormat(name, bytes);
  const text = () => td.decode(bytes).replace(/^\uFEFF/, '');
  switch (fmt) {
    case 'json': try { return { format: 'json', view: JSON.parse(text()), truncated }; } catch { return { format: 'text', view: { lines: text().split(/\r?\n/) }, truncated }; }
    case 'plist': try { return { format: 'plist', view: JSON.parse(JSON.stringify(parsePlist(bytes))), truncated }; } catch { return { format: 'binary', view: null, truncated }; }
    case 'xml': try { const x = parseXml(text()); return { format: 'xml', view: { root: x.root }, truncated: truncated || x.truncated }; } catch { return { format: 'text', view: { lines: text().split(/\r?\n/) }, truncated }; }
    case 'keyfile': return { format: 'keyfile', view: parseKeyFile(text()), truncated };
    case 'text': { const lines = text().split(/\r?\n/); if (lines.length && lines[lines.length - 1] === '') lines.pop(); return { format: 'text', view: { lines }, truncated }; }
    case 'sqlite': if (!h.sqlite || truncated) return { format: 'sqlite', view: null, truncated }; try { const s = h.sqlite(b); return { format: 'sqlite', view: { tables: s.tables }, truncated: s.truncated }; } catch { return { format: 'sqlite', view: null, truncated }; }
    case 'gzip': if (!h.gunzip || depth > 2) return { format: 'gzip', view: null, truncated }; try { const inner = h.gunzip(b, max); const v = viewOf(name.replace(/\.gz$/i, ''), inner, h, depth + 1); return { ...v, format: `gzip+${v.format}` }; } catch { return { format: 'gzip', view: null, truncated }; }
    case 'zip': {
      if (depth > 1) return { format: 'zip', view: null, truncated };
      try {
        const list = listZip(b, 20_000);
        const entries = list.slice(0, 5000).map((e) => {
          let view: unknown = null, format = 'unknown', sha256: string | undefined;
          if (!e.name.endsWith('/') && e.size <= max) { try { const data = readZipEntry(b, e, h.inflateRaw, max); const v = viewOf(e.name, data, h, depth + 1); format = v.format; view = v.format === 'zip' || v.format === 'sqlite' ? null : v.view; } catch { format = 'unreadable'; } }
          return { name: e.name, size: e.size, sha256, format, view };
        });
        return { format: 'zip', view: { entries }, truncated: truncated || list.length > 5000 };
      } catch { return { format: 'binary', view: null, truncated }; }
    }
    default: return { format: 'binary', view: null, truncated };
  }
}

// ---------------- redaction ----------------

const SECRET_FILE = /(^|[/\\])(cookies(-journal)?|login data(-journal)?|web data(-journal)?|local state|\.netrc|\.pgpass|\.git-credentials|credentials(\.json)?|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|keychain[^/\\]*|[^/\\]*\.(key|pem|p12|pfx|kdbx|keystore|jks|gpg)|[^/\\]*(token|secret|password|passwd|credential)s?[^/\\]*)$/i;
const SECRET_KEY = /pass(word|wd|phrase)?$|secret|token|api[_-]?key|apikey|auth|cookie|session[_-]?(id|key)|credential|private[_-]?key|bearer|refresh/i;

/** True when a file should be withheld whole because its name says it holds secrets. */
export const isSecretFile = (path: string) => SECRET_FILE.test(path.slice(-300));
export const isSecretKey = (k: string) => k.length <= 200 && SECRET_KEY.test(k);

/** Replace the values of secret-looking keys in a JSON-like value; returns the paths it masked. */
export function redactValue(v: unknown, path = '', out: string[] = [], depth = 0): unknown {
  if (depth > 100) return v;
  if (Array.isArray(v)) return v.map((x, i) => redactValue(x, `${path}/${i}`, out, depth + 1));
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      const p = `${path}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`;
      if (isSecretKey(k) && (typeof x === 'string' || typeof x === 'number') && String(x).length) { o[k] = '[redacted]'; out.push(p); }
      else o[k] = redactValue(x, p, out, depth + 1);
    }
    return o;
  }
  return v;
}

/** Redact key=value and key: value lines whose key looks secret (INI, .env, YAML-ish, .desktop). */
export function redactLines(text: string, out: string[] = []): string {
  return text.split('\n').map((line, i) => {
    const m = line.length > 10_000 ? null : /^(\s*(?:export\s+)?["']?([\w.\- [\]]{1,120})["']?\s*[=:]\s*)(.+)$/.exec(line);
    if (m && isSecretKey(m[2]!.trim()) && m[3]!.trim() && !/^[{[]$/.test(m[3]!.trim())) { out.push(`line ${i + 1}: ${m[2]!.trim()}`); return `${m[1]}[redacted]`; }
    return line;
  }).join('\n');
}

// ---------------- task checks ----------------

export interface TaskCheck {
  id?: string; kind: string; file?: string;
  lines?: string[]; exact?: string; contains?: string; equals?: number; at_least?: number; at_most?: number;
  pointer?: string; value?: unknown; tolerance?: number; normalize_whitespace?: boolean; text_attribute?: string; matching?: string;
  table?: string; where?: Record<string, unknown>;
  /** ui_element (RevLens): a selector checked against a saved UI tree file */
  selector?: UiSelector; states?: string[]; notStates?: string[]; exists?: boolean;
}
export interface DesktopTask { name: string; prompt: string; checks: TaskCheck[]; app?: string; tags?: string[] }
export interface CheckResult { id: string; kind: string; file?: string; pass: boolean; detail: string; decided: boolean }

const KINDS = new Set(['file_present', 'file_absent', 'lines_present', 'lines_absent', 'line_count', 'value_equals', 'value_absent', 'text_equals', 'text_contains', 'member_count', 'row_present', 'row_absent', 'row_count', 'ui_element']);
const DATE_LIKE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d\d:\d\d:\d\d \d{4}$/;

/** Validate a task file; returns the problems found (empty when valid). */
export function validateTask(t: unknown): string[] {
  const p: string[] = [];
  if (!t || typeof t !== 'object') return ['task must be an object'];
  const o = t as DesktopTask;
  if (typeof o.name !== 'string' || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(o.name) || o.name === 'smoke') p.push('name must be lowercase letters, digits and hyphens (and not smoke)');
  if (typeof o.prompt !== 'string' || !o.prompt.trim() || o.prompt.length > 4000) p.push('prompt must be a non-empty string');
  if (!Array.isArray(o.checks) || o.checks.length < 1 || o.checks.length > 32) { p.push('checks must hold 1 to 32 checks'); return p; }
  const ids = new Set<string>();
  o.checks.forEach((c, i) => {
    const id = c?.id ?? `check-${i + 1}`;
    if (ids.has(id)) p.push(`${id}: duplicate id`); ids.add(id);
    if (!c || !KINDS.has(c.kind)) { p.push(`${id}: unknown kind ${String(c?.kind)}`); return; }
    if (c.kind !== 'ui_element') {
      if (typeof c.file !== 'string' || !c.file || c.file.startsWith('/') || c.file.split('/').some((s) => s === '.' || s === '..')) p.push(`${id}: file must be a relative path under the home without . or ..`);
    }
    if (['lines_present', 'lines_absent'].includes(c.kind) && (!Array.isArray(c.lines) || !c.lines.length)) p.push(`${id}: lines must be a non-empty list`);
    if (['line_count', 'member_count', 'row_count'].includes(c.kind) && [c.equals, c.at_least, c.at_most].filter((x) => x !== undefined).length !== 1) p.push(`${id}: give exactly one of equals, at_least and at_most`);
    if (c.kind === 'line_count' && (c.exact === undefined) === (c.contains === undefined)) p.push(`${id}: give exactly one of exact and contains`);
    if (['value_equals', 'value_absent', 'text_equals', 'text_contains', 'member_count'].includes(c.kind)) {
      if (typeof c.pointer !== 'string' || (!c.pointer.startsWith('/') && !(c.kind === 'member_count' && c.pointer === ''))) p.push(`${id}: pointer must start with /`);
    }
    if (c.tolerance !== undefined && (typeof c.tolerance !== 'number' || c.tolerance < 0 || typeof c.value !== 'number')) p.push(`${id}: tolerance needs a non-negative number and a number value`);
    if (c.kind === 'text_contains' && (typeof c.value !== 'string' || !(c.normalize_whitespace ? c.value.trim() : c.value))) p.push(`${id}: text_contains needs a non-empty value`);
    if (c.text_attribute !== undefined && !c.text_attribute) p.push(`${id}: text_attribute must not be empty`);
    if (typeof c.value === 'string' && DATE_LIKE.test(c.value)) p.push(`${id}: value looks like a date and time, which changes between runs`);
    if (['row_present', 'row_absent'].includes(c.kind) && (typeof c.table !== 'string' || !c.where || typeof c.where !== 'object')) p.push(`${id}: needs table and where`);
    if (c.kind === 'row_count' && typeof c.table !== 'string') p.push(`${id}: needs table`);
    if (c.kind === 'ui_element') { try { checkSelector(c.selector); } catch (e) { p.push(`${id}: ${(e as Error).message}`); } }
  });
  return p;
}

/** Split an RFC 6901 pointer into unescaped segments. */
export function pointerSegments(p: string): string[] {
  if (p === '') return [];
  if (!p.startsWith('/')) throw new InputError('pointer must start with /');
  return p.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
}

/** Parse a selector segment like [name=Object][@type=Part::Cut][>data/Title=X]. Returns undefined when it is not a selector. */
export function parseSelectorSegment(seg: string): { kind: 'field' | 'attr' | 'path'; key: string; value: string; attr?: string }[] | undefined {
  if (!seg.startsWith('[') || !seg.endsWith(']')) return undefined;
  const parts = seg.slice(1, -1).split('][');
  const out: { kind: 'field' | 'attr' | 'path'; key: string; value: string; attr?: string }[] = [];
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq <= 0) return undefined;
    const lhs = part.slice(0, eq), value = part.slice(eq + 1);
    if (lhs.startsWith('@')) { if (lhs.length < 2) return undefined; out.push({ kind: 'attr', key: lhs.slice(1), value }); }
    else if (lhs.startsWith('>')) {
      const path = lhs.slice(1);
      const at = path.indexOf('@');
      const steps = (at >= 0 ? path.slice(0, at) : path).split('/');
      if (!path || steps.length > 3 || steps.some((s) => !s)) return undefined;
      out.push({ kind: 'path', key: at >= 0 ? path.slice(0, at) : path, value, attr: at >= 0 ? path.slice(at + 1) : undefined });
    } else out.push({ kind: 'field', key: lhs, value });
  }
  return out;
}

const normWs = (s: string) => s.replace(/\s+/g, ' ').trim();
function isXmlEl(v: unknown): v is XmlElement { return !!v && typeof v === 'object' && typeof (v as XmlElement).name === 'string' && Array.isArray((v as XmlElement).children) && typeof (v as XmlElement).attributes === 'object'; }

function memberMatches(m: unknown, conds: NonNullable<ReturnType<typeof parseSelectorSegment>>): boolean {
  for (const c of conds) {
    if (!m || typeof m !== 'object') return false;
    if (c.kind === 'field') { if ((m as Record<string, unknown>)[c.key] !== c.value) return false; }
    else if (c.kind === 'attr') { const a = (m as XmlElement).attributes; if (!a || typeof a !== 'object' || a[c.key] !== c.value) return false; }
    else {
      const steps = c.key.split('/');
      if (isXmlEl(m)) {
        let cur: XmlElement[] = [m];
        for (const s of steps) cur = cur.flatMap((e) => e.children.filter((x): x is XmlElement => typeof x !== 'string' && x.name === s));
        if (!cur.some((e) => (c.attr !== undefined ? e.attributes[c.attr] === c.value : normWs(wholeText(e)) === c.value))) return false;
      } else {
        let cur: unknown = m;
        for (const s of steps) cur = cur && typeof cur === 'object' ? (cur as Record<string, unknown>)[s] : undefined;
        if (c.attr !== undefined) { const parent = steps.length > 1 ? cur : m; cur = parent && typeof parent === 'object' ? (steps.length > 1 ? (cur as Record<string, unknown>)?.[`${steps[steps.length - 1]}@${c.attr}`] : (m as Record<string, unknown>)[`${c.key}@${c.attr}`]) : undefined; }
        if (typeof cur !== 'string' || cur !== c.value) return false;
      }
    }
  }
  return true;
}

/** Resolve a pointer (with selector segments on arrays) in a view. found=false means the pointer names no value; error explains an ambiguous selector. */
export function resolvePointer(view: unknown, pointer: string): { found: boolean; value?: unknown; error?: string } {
  let cur: unknown = view;
  const segs = pointerSegments(pointer);
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i]!, last = i === segs.length - 1;
    if (Array.isArray(cur)) {
      const sel = parseSelectorSegment(s);
      if (sel) {
        const hits = cur.filter((m) => memberMatches(m, sel));
        if (hits.length > 1) return { found: false, error: `selector ${s} matches ${hits.length} members` };
        if (!hits.length) return last ? { found: false } : { found: false, error: `selector ${s} matches nothing` };
        cur = hits[0]; continue;
      }
      if (!/^(0|[1-9]\d*)$/.test(s)) return { found: false, error: `${s} is not an index or selector` };
      if (Number(s) >= cur.length) return { found: false };
      cur = cur[Number(s)]; continue;
    }
    if (cur && typeof cur === 'object') {
      if (!Object.prototype.hasOwnProperty.call(cur, s)) return { found: false };
      cur = (cur as Record<string, unknown>)[s]; continue;
    }
    return { found: false };
  }
  return { found: true, value: cur };
}

function jsonEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (depth > 100) return false;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null || typeof a !== 'object') return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === (b as unknown[]).length && a.every((x, i) => jsonEqual(x, (b as unknown[])[i], depth + 1));
  const ka = Object.keys(a as object).sort(), kb = Object.keys(b as object).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && jsonEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], depth + 1));
}

const cmp = (n: number, c: TaskCheck) => (c.equals !== undefined ? n === c.equals : c.at_least !== undefined ? n >= c.at_least : n <= (c.at_most ?? Infinity));
const cmpText = (c: TaskCheck) => (c.equals !== undefined ? `= ${c.equals}` : c.at_least !== undefined ? `>= ${c.at_least}` : `<= ${c.at_most}`);

export interface FileSource { read(rel: string): Promise<Uint8Array | undefined> }

/** Evaluate one check against files (through a reader) and an optional UI tree. */
export async function runCheck(c: TaskCheck, idx: number, src: FileSource, h: ViewHelpers, uiNodes?: UiNode[]): Promise<CheckResult> {
  const id = c.id ?? `check-${idx + 1}`;
  const r = (pass: boolean, detail: string, decided = true): CheckResult => ({ id, kind: c.kind, file: c.file, pass, detail, decided });
  if (c.kind === 'ui_element') {
    if (!uiNodes) return r(false, 'no UI tree given', false);
    const sel = checkSelector(c.selector);
    const hits = findNodes(uiNodes, sel);
    const n = hits[sel.index ?? 0];
    if (c.exists === false) return r(!n, n ? `found ${n.role} "${n.name}"` : 'absent');
    if (!n) return r(false, 'no element matches');
    const st = new Set(n.states ?? []);
    const miss = (c.states ?? []).filter((x) => !st.has(x)), extra = (c.notStates ?? []).filter((x) => st.has(x));
    if (c.value !== undefined && n.value !== String(c.value)) return r(false, `value ${n.value}`);
    return r(!miss.length && !extra.length, miss.length || extra.length ? `missing ${miss.join(',') || '-'}; unwanted ${extra.join(',') || '-'}` : `${n.role} "${n.name}" ok`);
  }
  const bytes = await src.read(c.file!);
  if (c.kind === 'file_present') return r(!!bytes, bytes ? 'present' : 'absent');
  if (c.kind === 'file_absent') return r(!bytes, bytes ? 'present' : 'absent');
  const vr: ViewResult = bytes ? viewOf(c.file!, bytes, h) : { format: 'absent', view: undefined, truncated: false };
  const absent = !bytes;
  const lines = (): string[] | undefined => (absent ? [] : vr.format === 'text' || vr.format === 'gzip+text' ? ((vr.view as { lines: string[] }).lines) : undefined);
  switch (c.kind) {
    case 'lines_present': { const l = lines(); if (!l) return r(false, `no text view (${vr.format})`); const set = new Set(l); const miss = c.lines!.filter((x) => !set.has(x)); return r(!miss.length, miss.length ? `missing ${JSON.stringify(miss.slice(0, 5))}` : 'all lines present'); }
    case 'lines_absent': { const l = lines(); if (!l) return r(false, `no text view (${vr.format})`); if (vr.truncated) return r(false, 'view truncated', false); const set = new Set(l); const hit = c.lines!.filter((x) => set.has(x)); return r(!hit.length, hit.length ? `present ${JSON.stringify(hit.slice(0, 5))}` : 'none present'); }
    case 'line_count': { const l = lines(); if (!l) return r(false, `no text view (${vr.format})`); if (vr.truncated) return r(false, 'view truncated', false); const n = l.filter((x) => (c.exact !== undefined ? x === c.exact : x.includes(c.contains!))).length; return r(cmp(n, c), `${n} lines, want ${cmpText(c)}`); }
    case 'row_present': case 'row_absent': case 'row_count': {
      if (absent) return c.kind === 'row_present' ? r(false, 'file absent') : c.kind === 'row_absent' ? r(true, 'file absent') : r(cmp(0, c), `0 rows, want ${cmpText(c)}`);
      if (vr.format !== 'sqlite' || !vr.view) return r(false, `no SQLite view (${vr.format})`);
      const t = (vr.view as { tables: Record<string, { columns: string[]; rows: unknown[][] }> }).tables[c.table!];
      if (!t) return c.kind === 'row_absent' ? r(true, 'no such table') : c.kind === 'row_count' ? r(cmp(0, c), 'no such table') : r(false, 'no such table');
      const where = Object.entries(c.where ?? {});
      const idx = where.map(([k]) => t.columns.indexOf(k));
      if (idx.some((x) => x < 0)) return r(false, `unknown column in where`);
      const n = t.rows.filter((row) => where.every(([, v], j) => jsonEqual(row[idx[j]!], v))).length;
      if (vr.truncated && c.kind !== 'row_present') return r(false, 'view truncated', false);
      if (c.kind === 'row_present') return r(n > 0, `${n} matching rows`);
      if (c.kind === 'row_absent') return r(n === 0, `${n} matching rows`);
      return r(cmp(n, c), `${n} rows, want ${cmpText(c)}`);
    }
  }
  // pointer checks
  if (absent) {
    if (c.kind === 'value_absent') return r(true, 'file absent');
    return r(false, 'file absent');
  }
  if (vr.view === null || vr.format === 'binary' || vr.format === 'text' || vr.format === 'gzip+text') return r(false, `no structured view (${vr.format})`);
  const res = resolvePointer(vr.view, c.pointer ?? '');
  if (res.error) return r(false, res.error, false);
  switch (c.kind) {
    case 'value_absent': if (vr.truncated && !res.found) return r(false, 'view truncated', false); return r(!res.found, res.found ? `value ${JSON.stringify(res.value).slice(0, 200)}` : 'absent');
    case 'value_equals': {
      if (!res.found) return r(false, 'pointer names no value');
      if (c.tolerance !== undefined) {
        const v = typeof res.value === 'number' ? res.value : typeof res.value === 'string' && /^-?\d+(\.\d+)?([eE][-+]?\d+)?$/.test(res.value.trim()) ? Number(res.value) : NaN;
        if (!Number.isFinite(v)) return r(false, 'value is not a number');
        return r(Math.abs(v - (c.value as number)) <= c.tolerance, `value ${v}`);
      }
      if (vr.truncated && res.value && typeof res.value === 'object') return r(false, 'view truncated', false);
      return r(jsonEqual(res.value, c.value), `value ${JSON.stringify(res.value).slice(0, 200)}`);
    }
    case 'text_equals': case 'text_contains': {
      if (!res.found || !isXmlEl(res.value)) return r(false, 'pointer names no XML element');
      if (vr.truncated) return r(false, 'view truncated', false);
      let t = c.text_attribute !== undefined ? res.value.attributes[c.text_attribute] ?? '' : wholeText(res.value);
      let want = String(c.value ?? '');
      if (c.normalize_whitespace) { t = normWs(t); want = normWs(want); }
      return r(c.kind === 'text_equals' ? t === want : t.includes(want), `text ${JSON.stringify(t.slice(0, 200))}`);
    }
    case 'member_count': {
      if (!res.found || !Array.isArray(res.value)) return r(false, 'pointer names no array');
      if (vr.truncated) return r(false, 'view truncated', false);
      let arr = res.value as unknown[];
      if (c.matching) { const sel = parseSelectorSegment(c.matching); if (!sel) return r(false, 'matching is not a selector'); arr = arr.filter((m) => memberMatches(m, sel)); }
      return r(cmp(arr.length, c), `${arr.length} members, want ${cmpText(c)}`);
    }
  }
  return r(false, `unknown kind ${c.kind}`);
}

export interface TaskRun { task: string; pass: boolean; passed: number; failed: number; undecided: number; results: CheckResult[]; answers: Record<string, 'pass' | 'fail'> }

/** Evaluate every check of a task. answers maps `<task>/<check>` to pass or fail, ready for the eval scorer. */
export async function runTask(t: DesktopTask, src: FileSource, h: ViewHelpers = {}, uiNodes?: UiNode[]): Promise<TaskRun> {
  const problems = validateTask(t);
  if (problems.length) throw new InputError(`invalid task: ${problems.slice(0, 5).join('; ')}`);
  const results: CheckResult[] = [];
  for (const [i, c] of t.checks.entries()) results.push(await runCheck(c, i, src, h, uiNodes));
  const answers: Record<string, 'pass' | 'fail'> = {};
  for (const r of results) answers[`${t.name}/${r.id}`] = r.pass ? 'pass' : 'fail';
  const passed = results.filter((r) => r.pass).length;
  return { task: t.name, pass: passed === results.length, passed, failed: results.length - passed, undecided: results.filter((r) => !r.decided).length, results, answers };
}

/** The same task as eval tasks in the shape @revlens/extras x_eval_score scores (EvalTask: id, question, file, tags, answerType, answer, reference). Each check is one task whose answer is "pass". */
export function toEvalTasks(t: DesktopTask): { id: string; question: string; file: string; tags: string[]; answerType: 'exact'; answer: string; reference: string; hint: string[] }[] {
  return t.checks.map((c, i) => {
    const id = c.id ?? `check-${i + 1}`;
    return { id: `${t.name}/${id}`, question: `${t.prompt} (check ${id}: ${c.kind}${c.file ? ` on ${c.file}` : ''})`, file: c.file ?? '', tags: ['desktop', 'desktop-task', t.name, ...(t.tags ?? [])], answerType: 'exact' as const, answer: 'pass', reference: `desktop_task_check ${c.kind}`, hint: ['desktop_task_check'] };
  });
}

/** Score answers the way x_eval_score does for exact answers: one point per check that passed. */
export function scoreTaskAnswers(t: DesktopTask, answers: Record<string, unknown>, agent?: string) {
  const tasks = toEvalTasks(t);
  const ids = new Set(tasks.map((x) => x.id));
  const unknown = Object.keys(answers).filter((k) => !ids.has(k));
  if (unknown.length) throw new InputError(`unknown task ids: ${unknown.slice(0, 10).join(', ')}`);
  const results = tasks.map((x) => { const got = answers[x.id]; const ok = String(got ?? '').trim().toLowerCase() === 'pass'; return { id: x.id, score: ok ? 1 : 0, correct: ok, expected: 'pass', got, note: got === undefined ? 'no answer' : undefined }; });
  const correct = results.filter((r) => r.correct).length;
  const byTag: Record<string, { tasks: number; correct: number; score: number }> = {};
  for (const [i, x] of tasks.entries()) for (const tag of x.tags) { const b = (byTag[tag] ??= { tasks: 0, correct: 0, score: 0 }); b.tasks++; b.correct += results[i]!.correct ? 1 : 0; b.score += results[i]!.score; }
  for (const b of Object.values(byTag)) b.score = Math.round((b.score / b.tasks) * 1000) / 1000;
  return { agent, tasks: tasks.length, answered: results.filter((r) => r.note !== 'no answer').length, correct, score: Math.round((correct / Math.max(1, tasks.length)) * 1000) / 1000, accuracy: Math.round((correct / Math.max(1, tasks.length)) * 1000) / 1000, byTag, results };
}
