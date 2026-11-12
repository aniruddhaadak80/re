// Map bundle positions and stack traces to original sources, and compare a bundle's source map with a
// source folder: which original files the bundle carries, which of them changed since, which folder
// files are missing from it, and which bundle sources the folder lacks. Browser safe.
import { SourceMapIndex, parseSourceMap, type RawSourceMap } from '../sourcemap.js';
import { unpackBundle, type BundleModule } from './bundle.js';
import { parseJs, walk, t } from './ast.js';
import { sourceKey, normPath } from './imports.js';
import { lineIndex, sha256Hex, InputError } from '../util.js';

export interface TracedLocation {
  generated: { line: number; column: number; url?: string; functionName?: string };
  original?: { source: string; path: string; line: number; column: number; name?: string; lineText?: string; enclosingFunction?: string };
  bundleModule?: { id: string; path?: string };
  note?: string;
}

/** Parse V8 ("at f (url:1:2)"), Firefox and Safari ("f@url:1:2") stack frames. Lines and columns stay 1-based as printed. */
export function parseStackTrace(stack: string, max = 500): { functionName?: string; url: string; line: number; column: number; raw: string }[] {
  const out: { functionName?: string; url: string; line: number; column: number; raw: string }[] = [];
  for (const rawLine of stack.split(/\r?\n/).slice(0, 5000)) {
    if (out.length >= max) break;
    const raw = rawLine.trim().slice(0, 2000);
    const m = /:(\d{1,9}):(\d{1,9})\)?$/.exec(raw);
    if (!m) continue;
    let head = raw.slice(0, m.index);
    let fn: string | undefined;
    if (head.startsWith('at ')) {
      head = head.slice(3);
      const paren = head.lastIndexOf(' (');
      if (paren >= 0) { fn = head.slice(0, paren).replace(/^async /, ''); head = head.slice(paren + 2); }
    } else {
      const at = head.indexOf('@');
      if (at >= 0) { fn = head.slice(0, at) || undefined; head = head.slice(at + 1); }
    }
    out.push({ functionName: fn, url: head, line: Number(m[1]), column: Number(m[2]), raw });
  }
  return out;
}

/** Innermost named function around a 1-based line and 0-based column of a source text. */
function enclosingFunctionName(ast: t.File, line: number, column: number): string | undefined {
  let best: { name: string; size: number } | undefined;
  walk(ast, ({ node, parent }) => {
    const loc = node.loc;
    if (!loc) return undefined;
    const before = loc.start.line < line || (loc.start.line === line && loc.start.column <= column);
    const after = loc.end.line > line || (loc.end.line === line && loc.end.column >= column);
    if (!before || !after) return 'skip';
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' || node.type === 'ClassMethod' || node.type === 'ObjectMethod' || node.type === 'ClassPrivateMethod') {
      let name: string | undefined;
      if ((node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') && node.id) name = node.id.name;
      else if ((node.type === 'ClassMethod' || node.type === 'ObjectMethod') && node.key.type === 'Identifier') name = node.key.name;
      else if (node.type === 'ClassPrivateMethod') name = `#${node.key.id.name}`;
      else if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') name = parent.id.name;
      else if (parent?.type === 'ObjectProperty' && parent.key.type === 'Identifier') name = parent.key.name;
      else if (parent?.type === 'AssignmentExpression' && parent.left.type === 'MemberExpression' && parent.left.property.type === 'Identifier') name = parent.left.property.name;
      const size = (node.end ?? 0) - (node.start ?? 0);
      if (name && (!best || size <= best.size)) best = { name, size };
    }
    return undefined;
  });
  return best?.name;
}

/**
 * Map generated positions (1-based line, 0-based column) or a whole stack trace to original sources,
 * with the original line text, the enclosing original function and, given the bundle code, the bundle
 * module the position falls in.
 */
export function traceSourceLocation(input: { sourceMap: string | RawSourceMap; positions?: { line: number; column: number }[]; stack?: string; bundleCode?: string; stackColumnsOneBased?: boolean }): { locations: TracedLocation[]; sources: number } {
  const map = parseSourceMap(input.sourceMap);
  const idx = new SourceMapIndex(map);
  const content = new Map<string, string>();
  for (const m of idx.maps) (m.sources ?? []).forEach((s, i) => { const c = m.sourcesContent?.[i]; if (typeof c === 'string' && s) content.set(String(s), c); });
  const asts = new Map<string, t.File | null>();
  let modules: BundleModule[] | undefined;
  let posOf: ((o: number) => { line: number; column: number }) | undefined;
  if (input.bundleCode) {
    try { modules = unpackBundle(input.bundleCode).modules; posOf = lineIndex(input.bundleCode); } catch { modules = undefined; }
  }
  const modRanges = modules && posOf ? modules.map((m) => ({ m, a: posOf!(m.start), b: posOf!(m.end) })) : [];
  const want: { line: number; column: number; url?: string; functionName?: string }[] = [];
  for (const p of (input.positions ?? []).slice(0, 5000)) want.push({ line: Math.floor(Number(p.line)), column: Math.floor(Number(p.column)) });
  if (input.stack) for (const f of parseStackTrace(input.stack)) want.push({ line: f.line, column: input.stackColumnsOneBased === false ? f.column : Math.max(0, f.column - 1), url: f.url, functionName: f.functionName });
  if (!want.length) throw new InputError('give positions or a stack trace');
  const locations: TracedLocation[] = want.map((g) => {
    const loc: TracedLocation = { generated: g };
    if (!Number.isFinite(g.line) || g.line < 1 || !Number.isFinite(g.column) || g.column < 0) { loc.note = 'not a valid position'; return loc; }
    const o = idx.originalPositionFor(g.line, g.column);
    if (o.source !== undefined && o.line !== undefined) {
      const text = content.get(o.source);
      const original: NonNullable<TracedLocation['original']> = { source: o.source, path: sourceKey(o.source, map.sourceRoot), line: o.line, column: o.column ?? 0, name: o.name };
      if (text !== undefined) {
        original.lineText = (text.split('\n')[o.line - 1] ?? '').slice(0, 400);
        if (!asts.has(o.source)) { try { asts.set(o.source, parseJs(text, { typescript: /\.(?:ts|tsx|mts|cts)$/.test(o.source) }).ast); } catch { asts.set(o.source, null); } }
        const ast = asts.get(o.source);
        if (ast) original.enclosingFunction = enclosingFunctionName(ast, o.line, o.column ?? 0);
      }
      loc.original = original;
    } else loc.note = 'no mapping at this position';
    const hit = modRanges.find((r) => (g.line > r.a.line || (g.line === r.a.line && g.column >= r.a.column)) && (g.line < r.b.line || (g.line === r.b.line && g.column <= r.b.column)));
    if (hit) loc.bundleModule = { id: hit.m.id, path: hit.m.path };
    return loc;
  });
  return { locations, sources: idx.maps.reduce((n, m) => n + (m.sources?.length ?? 0), 0) };
}

export interface SourceFileStatus {
  /** normalised path from the map */
  path: string;
  source: string;
  status: 'same' | 'changed' | 'missing-in-folder' | 'no-content';
  folderPath?: string;
  bundleSha256?: string;
  folderSha256?: string;
  linesAdded?: number;
  linesRemoved?: number;
  firstDifferentLine?: number;
  /** for maps without sourcesContent: mappings that point past the end of the folder file's lines or columns */
  mappingsOutOfRange?: number;
  /** for maps without sourcesContent: mapped names that are not at the mapped position in the folder file */
  namesNotFound?: number;
  mappedLines?: number;
  inNodeModules: boolean;
}

export interface SourceBundleComparison {
  sources: number;
  summary: { same: number; changed: number; missingInFolder: number; noContent: number; missingFromBundle: number; nodeModules: number };
  files: SourceFileStatus[];
  /** folder code files no bundle source maps to (tree shaken, not imported, or added after the build) */
  missingFromBundle: string[];
  warnings: string[];
}

const CODE_FILE = /\.(?:m?jsx?|cjs|tsx?|mts|cts|vue|svelte|css|scss|less)$/;
const SKIP_FILE = /(?:^|\/)(?:node_modules|dist|build|coverage|\.git)\/|\.d\.ts$|(?:^|\/)(?:__tests__|test|tests)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|\/)[^/]*\.config\.[cm]?[jt]s$/;

const BUNDLER_NAME = /^(?:__|init_|require_|import_|exports_|_interop|_export)|_exports$/;

function lineDiff(a: string, b: string): { added: number; removed: number; first?: number } {
  const al = a.replace(/\r\n/g, '\n').split('\n'), bl = b.replace(/\r\n/g, '\n').split('\n');
  let first: number | undefined;
  for (let i = 0; i < Math.max(al.length, bl.length); i++) if (al[i] !== bl[i]) { first = i + 1; break; }
  const count = new Map<string, number>();
  for (const l of al) count.set(l, (count.get(l) ?? 0) + 1);
  let added = 0;
  for (const l of bl) { const c = count.get(l) ?? 0; if (c > 0) count.set(l, c - 1); else added++; }
  let removed = 0;
  for (const c of count.values()) removed += c;
  return { added, removed, first };
}

/**
 * Compare the original sources a bundle's source map names with a folder of sources. Files are matched
 * by path, then by a unique path suffix. With sourcesContent the text is compared (line endings
 * normalised); without it the mappings are checked against the folder file instead.
 */
export function compareSourceToBundle(sourceMap: string | RawSourceMap, folder: { path: string; content: string }[], opts: { includeNodeModules?: boolean; limit?: number } = {}): SourceBundleComparison {
  const map = parseSourceMap(sourceMap);
  const idx = new SourceMapIndex(map);
  const warnings: string[] = [];
  const byPath = new Map<string, { path: string; content: string }>();
  for (const f of folder.slice(0, 50_000)) byPath.set(normPath(f.path), f);
  const suffixIndex = new Map<string, string[]>();
  for (const p of byPath.keys()) {
    const segs = p.split('/');
    for (let i = 0; i < segs.length; i++) { const k = segs.slice(i).join('/'); const l = suffixIndex.get(k) ?? suffixIndex.set(k, []).get(k)!; if (l.length < 5) l.push(p); }
  }
  const find = (key: string): string | undefined => {
    if (byPath.has(key)) return key;
    const segs = key.split('/');
    for (let i = 0; i < segs.length; i++) {
      const hits = suffixIndex.get(segs.slice(i).join('/'));
      if (hits?.length === 1) return hits[0];
      if (hits && hits.length > 1) return undefined;
    }
    return undefined;
  };
  // per source: mapped original positions and names, used when there is no sourcesContent
  const mappedBySource = new Map<string, { line: number; col: number; name?: string }[]>();
  for (const m of idx.eachMapping()) {
    if (m.source === undefined || m.origLine === undefined) continue;
    const l = mappedBySource.get(m.source) ?? mappedBySource.set(m.source, []).get(m.source)!;
    if (l.length < 200_000) l.push({ line: m.origLine, col: m.origCol ?? 0, name: m.name });
  }
  const files: SourceFileStatus[] = [];
  const matched = new Set<string>();
  const seen = new Set<string>();
  for (const part of idx.maps) {
    (part.sources ?? []).forEach((s, i) => {
      const source = String(s ?? '');
      const key = sourceKey(source, part.sourceRoot);
      if (!key || seen.has(key) || /^webpack\/(?:runtime|bootstrap)|^\(webpack\)/.test(key) || key.startsWith('<')) return;
      seen.add(key);
      const inNm = key.split('/').includes('node_modules');
      if (inNm && !opts.includeNodeModules) { files.push({ path: key, source, status: 'same', inNodeModules: true }); return; }
      const content = part.sourcesContent?.[i];
      const fp = find(key);
      if (fp) matched.add(fp);
      const st: SourceFileStatus = { path: key, source, status: 'missing-in-folder', folderPath: fp, inNodeModules: inNm };
      if (typeof content === 'string') st.bundleSha256 = sha256Hex(content.replace(/\r\n/g, '\n'));
      if (!fp) { files.push(st); return; }
      const f = byPath.get(fp)!;
      st.folderSha256 = sha256Hex(f.content.replace(/\r\n/g, '\n'));
      if (typeof content === 'string') {
        if (st.folderSha256 === st.bundleSha256) st.status = 'same';
        else { const d = lineDiff(content, f.content); st.status = 'changed'; st.linesAdded = d.added; st.linesRemoved = d.removed; st.firstDifferentLine = d.first; }
      } else {
        const lines = f.content.replace(/\r\n/g, '\n').split('\n');
        const mapped = mappedBySource.get(source) ?? [];
        let out = 0, names = 0;
        const used = new Set<number>();
        for (const m of mapped) {
          used.add(m.line);
          const text = lines[m.line - 1];
          if (text === undefined || m.col > text.length) { out++; continue; }
          // bundler helpers (esbuild init_x, require_x, __export, webpack __webpack_require__) carry names that are not in the source
          // esbuild maps export getters to 1:0, so a name only counts as missing when the whole file lacks it
          if (m.name && !BUNDLER_NAME.test(m.name) && !text.includes(m.name) && !f.content.includes(m.name)) names++;
        }
        st.mappingsOutOfRange = out; st.namesNotFound = names; st.mappedLines = used.size;
        st.status = out || names ? 'changed' : 'no-content';
        if (!(out || names)) warnings.push(`${key}: no sourcesContent; mappings fit the folder file, so it is likely unchanged`);
      }
      files.push(st);
    });
  }
  const missingFromBundle = [...byPath.keys()].filter((p) => CODE_FILE.test(p) && !SKIP_FILE.test(p) && !matched.has(p)).sort();
  const visible = files.filter((f) => opts.includeNodeModules || !f.inNodeModules);
  const summary = {
    same: visible.filter((f) => f.status === 'same').length,
    changed: visible.filter((f) => f.status === 'changed').length,
    missingInFolder: visible.filter((f) => f.status === 'missing-in-folder').length,
    noContent: visible.filter((f) => f.status === 'no-content').length,
    missingFromBundle: missingFromBundle.length,
    nodeModules: files.filter((f) => f.inNodeModules).length,
  };
  const lim = Math.max(1, Math.min(opts.limit ?? 2000, 20_000));
  return { sources: seen.size, summary, files: visible.slice(0, lim), missingFromBundle: missingFromBundle.slice(0, lim), warnings: warnings.slice(0, 200) };
}
