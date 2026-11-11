// OpenAPI 3.x and Swagger 2.0 documents embedded in binaries (Go embed, resources) and JS
// bundles: JSON, YAML, minified JS object literals and JSON strings inside JS.

import { parseDocument } from 'yaml';
import { parseJsValue, enclosingBrace, type JsValue } from './jsvalue.js';

export interface OpenApiOperation { method: string; path: string; operationId?: string; summary?: string; deprecated?: boolean; tags?: string[]; parameters: string[]; requestBody?: string[]; responses: string[]; security?: string[] }
export interface OpenApiSummary {
  offset: number; length: number; format: 'json' | 'yaml' | 'js-literal' | 'json-string';
  spec: 'openapi' | 'swagger'; version: string; title?: string; apiVersion?: string;
  servers: string[]; pathCount: number; operations: OpenApiOperation[];
  securitySchemes: string[]; schemas: string[]; document: JsValue;
}

const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
type Obj = { [k: string]: JsValue };
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const strOf = (v: unknown): string | undefined => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : undefined);

function isSpec(v: unknown): v is Obj {
  if (!isObj(v)) return false;
  const ver = strOf(v.openapi) ?? strOf(v.swagger);
  return !!ver && /^[23](\.\d+)*$/.test(ver) && (isObj(v.paths) || isObj(v.info) || isObj(v.webhooks) || isObj(v.components));
}

function paramName(p: JsValue, doc: Obj): string | undefined {
  if (!isObj(p)) return undefined;
  if (typeof p.$ref === 'string') {
    const m = /^#\/(?:components\/parameters|parameters)\/(.+)$/.exec(p.$ref);
    const target = m ? (isObj(doc.components) && isObj(doc.components.parameters) ? doc.components.parameters[m[1]!] : isObj(doc.parameters) ? doc.parameters[m[1]!] : undefined) : undefined;
    return isObj(target) && typeof target.name === 'string' ? `${target.name} (${strOf(target.in) ?? '?'})` : p.$ref;
  }
  return typeof p.name === 'string' ? `${p.name} (${strOf(p.in) ?? '?'})` : undefined;
}

/** Summarize a parsed OpenAPI or Swagger document. */
export function summarizeOpenApi(doc: Obj, where: { offset: number; length: number; format: OpenApiSummary['format'] }): OpenApiSummary {
  const spec = doc.openapi !== undefined ? 'openapi' : 'swagger';
  const info = isObj(doc.info) ? doc.info : {};
  const servers: string[] = [];
  if (Array.isArray(doc.servers)) for (const s of doc.servers) if (isObj(s) && typeof s.url === 'string') servers.push(s.url);
  if (spec === 'swagger' && typeof doc.host === 'string') {
    const schemes = Array.isArray(doc.schemes) && doc.schemes.length ? doc.schemes : ['https'];
    for (const sc of schemes) servers.push(`${sc}://${doc.host}${strOf(doc.basePath) ?? ''}`);
  }
  const ops: OpenApiOperation[] = [];
  const paths = isObj(doc.paths) ? doc.paths : {};
  for (const [path, item] of Object.entries(paths)) {
    if (!isObj(item)) continue;
    const shared = Array.isArray(item.parameters) ? item.parameters : [];
    for (const m of METHODS) {
      const op = item[m];
      if (!isObj(op)) continue;
      const params = [...shared, ...(Array.isArray(op.parameters) ? op.parameters : [])].map((p) => paramName(p, doc)).filter((x): x is string => !!x);
      const o: OpenApiOperation = { method: m.toUpperCase(), path, parameters: [...new Set(params)], responses: isObj(op.responses) ? Object.keys(op.responses) : [] };
      if (typeof op.operationId === 'string') o.operationId = op.operationId;
      if (typeof op.summary === 'string') o.summary = op.summary;
      if (op.deprecated === true) o.deprecated = true;
      if (Array.isArray(op.tags)) o.tags = op.tags.filter((t): t is string => typeof t === 'string');
      if (isObj(op.requestBody) && isObj(op.requestBody.content)) o.requestBody = Object.keys(op.requestBody.content);
      const sec = Array.isArray(op.security) ? op.security : Array.isArray(doc.security) ? doc.security : undefined;
      if (sec) o.security = [...new Set(sec.flatMap((x) => (isObj(x) ? Object.keys(x) : [])))];
      ops.push(o);
      if (ops.length >= 20000) break;
    }
  }
  const comps = isObj(doc.components) ? doc.components : {};
  const sch = spec === 'openapi' ? comps.schemas : doc.definitions;
  const secs = spec === 'openapi' ? comps.securitySchemes : doc.securityDefinitions;
  return {
    ...where, spec, version: strOf(doc.openapi) ?? strOf(doc.swagger) ?? '', title: strOf(info.title), apiVersion: strOf(info.version),
    servers, pathCount: Object.keys(paths).length, operations: ops,
    securitySchemes: isObj(secs) ? Object.keys(secs) : [], schemas: isObj(sch) ? Object.keys(sch) : [], document: doc,
  };
}

const printable = (c: number): boolean => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160;

/** Parse YAML text that may be followed by unrelated bytes: drop lines from the first error and retry. */
function yamlPrefix(text: string): { doc: unknown; length: number } | undefined {
  let t = text;
  for (let attempt = 0; attempt < 4 && t.length; attempt++) {
    const d = parseDocument(t, { uniqueKeys: false, prettyErrors: false, strict: false });
    if (!d.errors.length) return { doc: d.toJS({ maxAliasCount: 100 }), length: t.length };
    const pos = d.errors[0]!.pos[0];
    const cut = t.lastIndexOf('\n', Math.max(0, pos - 1));
    if (cut <= 0) return undefined;
    // also drop the line before the error when it is a dangling key (trailing garbage joined it)
    t = t.slice(0, cut + 1);
  }
  return undefined;
}

/** Find OpenAPI / Swagger documents in text (latin1 decoded bytes or a JS bundle). */
export function findOpenApi(text: string, opts: { max?: number; maxDocChars?: number } = {}): OpenApiSummary[] {
  const out: OpenApiSummary[] = [];
  const max = opts.max ?? 50, maxDoc = opts.maxDocChars ?? 8 << 20;
  const covered: [number, number][] = [];
  const inCovered = (i: number): boolean => covered.some(([a, b]) => i >= a && i < b);
  const add = (doc: unknown, offset: number, length: number, format: OpenApiSummary['format']): boolean => {
    if (!isSpec(doc) || out.length >= max) return false;
    out.push(summarizeOpenApi(doc, { offset, length, format }));
    covered.push([offset, offset + length]);
    return true;
  };
  // JSON and JS literal forms: "openapi":"3..., openapi:"3..., 'swagger':'2.0'
  const re = /(["']?)(openapi|swagger)\1\s*:\s*["']?[23]\.\d|\\"(?:openapi|swagger)\\"\s*:\s*\\"[23]\.\d/g;
  let n = 0;
  for (let m = re.exec(text); m && out.length < max && n < 5000; m = re.exec(text), n++) {
    if (inCovered(m.index)) continue;
    const q = m[1] ?? '';
    if (!q && !m[0].startsWith('\\') && m.index > 0 && /[\w$]/.test(text[m.index - 1]!)) continue;
    const open = enclosingBrace(text, m.index, 1 << 16);
    if (open < 0) continue;
    if (!m[0].startsWith('\\')) try {
      const { value, end } = parseJsValue(text, open, { maxChars: maxDoc });
      const strict = (() => { try { JSON.parse(text.slice(open, end)); return true; } catch { return false; } })();
      if (add(value, open, end - open, strict ? 'json' : 'js-literal')) continue;
    } catch { /* maybe inside an escaped JS string */ }
    // escaped JSON inside a JS string literal: find the quote that opens the string
    const qpos = open - 1;
    const qc = text[qpos];
    if (qc === '"' || qc === "'" || qc === '`') {
      try {
        const { value: inner, end } = parseJsValue(text, qpos, { maxChars: maxDoc });
        if (typeof inner === 'string') add(JSON.parse(inner), qpos, end - qpos, 'json-string');
      } catch { /* not a document */ }
    }
  }
  // YAML form: openapi: 3.x or swagger: "2.0" at the start of a line or of a string region
  const ry = /(openapi|swagger)[ \t]*:[ \t]*["']?[23]\.\d[\w.\-]*["']?[ \t]*\r?\n/g;
  n = 0;
  for (let m = ry.exec(text); m && out.length < max && n < 5000; m = ry.exec(text), n++) {
    if (inCovered(m.index)) continue;
    let start = m.index;
    // walk back over earlier top level YAML lines (comments, keys) of the same document
    for (let guard = 0; guard < 200 && start > 0 && text[start - 1] === '\n'; guard++) {
      const prev = text.lastIndexOf('\n', start - 2) + 1;
      const line = text.slice(prev, start - 1);
      if (!/^(#.*|[A-Za-z_$][\w$-]*:.*|[ \t]+\S.*|---)?\r?$/.test(line) || [...line].some((c) => !printable(c.charCodeAt(0)))) break;
      start = prev;
    }
    let end = m.index;
    const lim = Math.min(text.length, m.index + maxDoc);
    while (end < lim && printable(text.charCodeAt(end))) end++;
    const r = yamlPrefix(text.slice(start, end));
    if (r) add(r.doc, start, r.length, 'yaml');
  }
  return out;
}
