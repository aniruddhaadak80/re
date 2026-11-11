// Source map parsing (v3, including index maps with sections), VLQ mapping decode and source tree recovery.
import { safeRelPath, base64ToBytes, decodeUtf8, InputError } from './util.js';

export interface RawSourceMap {
  version?: number;
  file?: string;
  sourceRoot?: string;
  sources?: (string | null)[];
  sourcesContent?: (string | null)[];
  names?: string[];
  mappings?: string;
  sections?: { offset: { line: number; column: number }; map?: RawSourceMap; url?: string }[];
  x_google_ignoreList?: number[];
  ignoreList?: number[];
}

export interface Mapping { genLine: number; genCol: number; source?: number; origLine?: number; origCol?: number; name?: number }

export interface RecoveredFile { path: string; originalSource: string; size: number; content?: string; ignored?: boolean }

export interface SourceMapRecovery {
  file?: string;
  sourceRoot?: string;
  sources: number;
  withContent: number;
  coverage: number;
  mappings: number;
  names: number;
  files: RecoveredFile[];
  missing: string[];
  /** top level folders of the recovered tree with file counts, useful to spot node_modules and app code */
  tree: Record<string, number>;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64MAP = new Int8Array(128).fill(-1);
for (let i = 0; i < B64.length; i++) B64MAP[B64.charCodeAt(i)] = i;

/** Decode the VLQ "mappings" string. Caps at maxMappings entries. */
export function decodeMappings(mappings: string, maxMappings = 2_000_000): Mapping[] {
  const out: Mapping[] = [];
  let genLine = 0, genCol = 0, src = 0, oLine = 0, oCol = 0, name = 0;
  let i = 0;
  const fields: number[] = [];
  while (i < mappings.length && out.length < maxMappings) {
    const ch = mappings.charCodeAt(i);
    if (ch === 59 /* ; */) { genLine++; genCol = 0; i++; continue; }
    if (ch === 44 /* , */) { i++; continue; }
    fields.length = 0;
    while (i < mappings.length) {
      const c = mappings.charCodeAt(i);
      if (c === 44 || c === 59) break;
      let value = 0, shift = 0, digit: number;
      do {
        const cc = mappings.charCodeAt(i++);
        digit = cc < 128 ? (B64MAP[cc] as number) : -1;
        if (digit < 0) throw new InputError(`bad VLQ character at ${i - 1}`);
        value += (digit & 31) * 2 ** shift;
        shift += 5;
        if (shift > 35) throw new InputError('VLQ value too long');
      } while (digit & 32);
      const neg = value % 2 === 1;
      value = Math.floor(value / 2);
      fields.push(neg ? -value : value);
      if (fields.length > 5) break;
    }
    if (!fields.length) continue;
    genCol += fields[0] as number;
    const m: Mapping = { genLine, genCol };
    if (fields.length >= 4) {
      src += fields[1] as number; oLine += fields[2] as number; oCol += fields[3] as number;
      m.source = src; m.origLine = oLine; m.origCol = oCol;
      if (fields.length >= 5) { name += fields[4] as number; m.name = name; }
    }
    out.push(m);
  }
  return out;
}

export function parseSourceMap(input: string | RawSourceMap): RawSourceMap {
  if (typeof input !== 'string') return input;
  let s = input.trim();
  if (s.startsWith(")]}'")) s = s.slice(s.indexOf('\n') + 1);
  try { return JSON.parse(s) as RawSourceMap; } catch (e) { throw new InputError(`source map is not valid JSON: ${(e as Error).message}`); }
}

/** Flatten an index map (sections) into a list of plain maps with line offsets. */
function flatten(map: RawSourceMap, depth = 0): { map: RawSourceMap; line: number; column: number }[] {
  if (depth > 4) return [];
  if (!map.sections) return [{ map, line: 0, column: 0 }];
  const out: { map: RawSourceMap; line: number; column: number }[] = [];
  for (const s of map.sections.slice(0, 10_000)) {
    if (!s.map) continue;
    for (const f of flatten(s.map, depth + 1)) out.push({ map: f.map, line: f.line + (s.offset?.line ?? 0), column: f.column + (s.offset?.column ?? 0) });
  }
  return out;
}

/** Extract an inline base64 source map from a script's sourceMappingURL comment, if any. */
export function inlineSourceMap(js: string): RawSourceMap | undefined {
  const text = js.slice(-8 * 1024 * 1024);
  let m: { base64: boolean; payload: string } | undefined;
  let comma = -1;
  for (const [start, end] of sourceMappingComments(text, true)) {
    if (!text.startsWith('data:application/json', start)) continue;
    if (comma < start) comma = text.indexOf(',', start);
    if (comma < 0) break;
    if (comma >= end) continue;
    INLINE_PAYLOAD.lastIndex = comma + 1;
    if (!INLINE_PAYLOAD.test(text) || INLINE_PAYLOAD.lastIndex !== end) continue;
    m = { base64: text.slice(start, comma).endsWith(';base64'), payload: text.slice(comma + 1, end) };
    break;
  }
  if (!m) return undefined;
  try {
    const json = m.base64 ? decodeUtf8(base64ToBytes(m.payload)) : decodeURIComponent(m.payload);
    return parseSourceMap(json);
  } catch { return undefined; }
}

export function sourceMapUrl(js: string): string | undefined {
  const text = js.slice(-65536);
  let skip = -1;
  for (const [start, end] of sourceMappingComments(text, true)) {
    if (start < skip || start === end) continue;
    SPACE_G.lastIndex = start;
    const w = SPACE_G.exec(text);
    if (!w || w.index >= end) return text.slice(start, end);
    skip = w.index; // every later value that starts before this space also contains it
  }
  return undefined;
}

const MAPPING_KEY = 'sourceMappingURL=';
const INLINE_PAYLOAD = /[A-Za-z0-9+/=%._~-]+/y;
const HAS_SPACE = /\s/;
const SPACE_G = /\s/g;
const LINE_END = /[\n\r\u2028\u2029]/g;

/**
 * Where the values of `#` or `@` sourceMappingURL= comments sit, in order: the offset just after the `=`
 * and the end of its line (or of the whole text when perLine is false) with trailing white space left
 * out. Callers validate the value. A plain scan with per line caching instead of a backtracking regex, so
 * it stays linear on hostile input.
 */
export function* sourceMappingComments(text: string, perLine: boolean, needSlashes = false): Generator<[start: number, end: number]> {
  let lineEnd = -1;
  let trimmed = -1;
  for (let i = text.indexOf(MAPPING_KEY); i >= 0; i = text.indexOf(MAPPING_KEY, i + 1)) {
    let j = i - 1;
    while (j >= 0 && HAS_SPACE.test(text[j] as string)) j--;
    if (j < 0 || (text[j] !== '#' && text[j] !== '@')) continue;
    if (needSlashes && (text[j - 1] !== '/' || text[j - 2] !== '/')) continue;
    const start = i + MAPPING_KEY.length;
    if (start > lineEnd) {
      lineEnd = text.length;
      if (perLine) { LINE_END.lastIndex = start; const e = LINE_END.exec(text); if (e) lineEnd = e.index; }
      trimmed = lineEnd;
      while (trimmed > start && HAS_SPACE.test(text[trimmed - 1] as string)) trimmed--;
    }
    yield [start, Math.max(start, trimmed)];
  }
}

/** Recover original files from a source map: safe relative paths, sizes and (optionally) content. */
export function recoverSources(input: string | RawSourceMap, opts: { includeContent?: boolean; maxFiles?: number } = {}): SourceMapRecovery {
  const root = parseSourceMap(input);
  const parts = flatten(root);
  const files: RecoveredFile[] = [];
  const missing: string[] = [];
  let mappings = 0, names = 0, sources = 0;
  const used = new Map<string, number>();
  const maxFiles = opts.maxFiles ?? 20_000;
  for (const { map } of parts) {
    const srcs = map.sources ?? [];
    sources += srcs.length;
    names += map.names?.length ?? 0;
    mappings += typeof map.mappings === 'string' ? (map.mappings.match(/[,;]/g)?.length ?? 0) + 1 : 0;
    const ignore = new Set(map.ignoreList ?? map.x_google_ignoreList ?? []);
    srcs.forEach((src, i) => {
      if (files.length >= maxFiles) return;
      const original = String(src ?? `source-${i}`);
      const content = map.sourcesContent?.[i];
      const joined = map.sourceRoot && !/^[a-z]+:/i.test(original) ? `${map.sourceRoot.replace(/\/+$/, '')}/${original}` : original;
      let rel = safeRelPath(joined) || `source-${i}`;
      const n = used.get(rel) ?? 0;
      used.set(rel, n + 1);
      if (n) rel = rel.replace(/(\.[^./]+)?$/, `~${n}$1`);
      if (typeof content !== 'string') { missing.push(original); return; }
      files.push({ path: rel, originalSource: original, size: content.length, content: opts.includeContent ? content : undefined, ignored: ignore.has(i) || undefined });
    });
  }
  const tree: Record<string, number> = {};
  for (const f of files) {
    const segs = f.path.split('/');
    const nm = segs.indexOf('node_modules');
    const key = nm >= 0 ? `node_modules/${segs[nm + 1]?.startsWith('@') ? `${segs[nm + 1]}/${segs[nm + 2]}` : segs[nm + 1]}` : segs.length > 1 ? segs[0] as string : '.';
    tree[key] = (tree[key] ?? 0) + 1;
  }
  return { file: root.file, sourceRoot: root.sourceRoot, sources, withContent: files.length, coverage: sources ? Math.round((files.length / sources) * 100) : 0, mappings, names, files, missing: missing.slice(0, 1000), tree };
}

/** Index of decoded mappings for position lookups. */
export class SourceMapIndex {
  private readonly parts: { map: RawSourceMap; line: number; column: number; mappings: Mapping[] }[];
  constructor(input: string | RawSourceMap) {
    this.parts = flatten(parseSourceMap(input)).map((p) => ({ ...p, mappings: decodeMappings(p.map.mappings ?? '') }));
  }
  /** Original position for a 1-based generated line and 0-based column (greatest mapping at or before it on that line). */
  originalPositionFor(line: number, column: number): { source?: string; line?: number; column?: number; name?: string } {
    const gl = line - 1;
    let part = this.parts[0];
    for (const p of this.parts) if (p.line < gl || (p.line === gl && p.column <= column)) part = p;
    if (!part) return {};
    const l = gl - part.line, c = l === 0 ? column - part.column : column;
    let best: Mapping | undefined;
    // binary search on (genLine, genCol)
    const ms = part.mappings;
    let lo = 0, hi = ms.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const m = ms[mid] as Mapping;
      if (m.genLine < l || (m.genLine === l && m.genCol <= c)) { best = m; lo = mid + 1; } else hi = mid - 1;
    }
    if (!best || best.genLine !== l || best.source === undefined) return {};
    return { source: part.map.sources?.[best.source] ?? undefined, line: (best.origLine ?? 0) + 1, column: best.origCol, name: best.name !== undefined ? part.map.names?.[best.name] : undefined };
  }
  /** First mapped source in a generated range, scanning forward from the start. */
  sourceInRange(startLine: number, startCol: number, endLine: number, endCol: number): string | undefined {
    for (const part of this.parts) {
      for (const m of part.mappings) {
        const ml = m.genLine + part.line + 1, mc = m.genLine === 0 ? m.genCol + part.column : m.genCol;
        if (ml < startLine || (ml === startLine && mc < startCol)) continue;
        if (ml > endLine || (ml === endLine && mc > endCol)) break;
        if (m.source !== undefined) {
          const s = part.map.sources?.[m.source];
          if (s && !/webpack\/(runtime|bootstrap)/.test(s)) return s;
        }
      }
    }
    return undefined;
  }
}
