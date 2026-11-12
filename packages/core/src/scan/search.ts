// String search over the strings of a file: literal (default) or regex mode with a safe pattern
// check (no backreferences, no lookaround, no repeated groups that hold a quantifier or an
// alternation), a per string length cap and a time budget, so hostile files and patterns stay bounded.

import { extractStrings, tagOf } from '../analyzers/strings.js';
import { assertSafeRegex } from '../rules/yaralite.js';
import type { ExtractedString } from '../types.js';

export interface StringSearchOptions {
  pattern: string;
  mode?: 'literal' | 'regex';
  caseSensitive?: boolean;
  kinds?: ('ascii' | 'utf16')[];
  tags?: string[];
  minLength?: number;
  /** strings scanned at most (default 200000) */
  maxStrings?: number;
  /** characters of each string the regex sees (default 4096) */
  maxStringLength?: number;
  timeBudgetMs?: number;
  offset?: number;
  limit?: number;
}
export interface StringHit { value: string; offset: number; kind: 'ascii' | 'utf16'; tag?: string; match: { index: number; length: number; text: string }; fileOffset: number }
export interface StringSearchResult {
  schema: 'revlens/string-search@1';
  pattern: string;
  mode: 'literal' | 'regex';
  caseSensitive: boolean;
  scanned: number;
  total: number;
  hits: StringHit[];
  offset: number;
  limit: number;
  truncated: boolean;
  stoppedBy?: 'time' | 'strings';
  elapsedMs: number;
}

/** Check a caller regex: the yara-lite safety rules plus no lookaround and a length cap. Throws with the reason. */
export function assertSafeSearchRegex(src: string): void {
  if (src.length > 512) throw new Error('regex is longer than 512 characters');
  if (/\(\?<?[=!]/.test(src)) throw new Error('regex lookahead and lookbehind are not supported');
  assertSafeRegex(src);
  try { new RegExp(src, 'u'); } catch (e) { try { new RegExp(src); } catch { throw new Error(`regex does not compile: ${(e as Error).message}`); } }
}

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/** Search the strings of a file. */
export function searchStrings(bytes: Uint8Array | ExtractedString[], opts: StringSearchOptions): StringSearchResult {
  const t0 = now();
  const mode = opts.mode ?? 'literal';
  const cs = opts.caseSensitive ?? false;
  if (!opts.pattern) throw new Error('pattern must not be empty');
  let re: RegExp | undefined;
  let needle = '';
  if (mode === 'regex') { assertSafeSearchRegex(opts.pattern); re = new RegExp(opts.pattern, cs ? '' : 'i'); }
  else { if (opts.pattern.length > 4096) throw new Error('pattern is longer than 4096 characters'); needle = cs ? opts.pattern : opts.pattern.toLowerCase(); }
  const maxStrings = opts.maxStrings ?? 200_000;
  const maxLen = opts.maxStringLength ?? 4096;
  const budget = opts.timeBudgetMs ?? 2000;
  const strings = bytes instanceof Uint8Array ? extractStrings(bytes, opts.minLength ?? 4, maxStrings) : bytes.slice(0, maxStrings);
  const offset = Math.max(0, opts.offset ?? 0), limit = Math.max(0, Math.min(opts.limit ?? 200, 5000));
  const hits: StringHit[] = [];
  let total = 0, scanned = 0;
  let stoppedBy: 'time' | 'strings' | undefined;
  for (const s of strings) {
    if ((scanned & 255) === 0 && now() - t0 > budget) { stoppedBy = 'time'; break; }
    scanned++;
    if (opts.kinds && !opts.kinds.includes(s.kind)) continue;
    const tag = s.tag ?? (opts.tags ? tagOf(s.value) : undefined);
    if (opts.tags && (!tag || !opts.tags.includes(tag))) continue;
    const v = s.value.length > maxLen ? s.value.slice(0, maxLen) : s.value;
    let index = -1, len = 0;
    if (re) { const m = re.exec(v); if (m) { index = m.index; len = m[0].length; } }
    else { index = (cs ? v : v.toLowerCase()).indexOf(needle); len = needle.length; }
    if (index < 0) continue;
    total++;
    if (total > offset && hits.length < limit) {
      const charSize = s.kind === 'utf16' ? 2 : 1;
      hits.push({ value: s.value.length > 1024 ? s.value.slice(0, 1024) : s.value, offset: s.offset, kind: s.kind, ...(tag ? { tag } : {}), match: { index, length: len, text: v.slice(index, index + Math.min(len, 256)) }, fileOffset: s.offset + index * charSize });
    }
  }
  if (!stoppedBy && bytes instanceof Uint8Array && strings.length >= maxStrings) stoppedBy = 'strings';
  return { schema: 'revlens/string-search@1', pattern: opts.pattern, mode, caseSensitive: cs, scanned, total, hits, offset, limit, truncated: total > offset + hits.length || !!stoppedBy, ...(stoppedBy ? { stoppedBy } : {}), elapsedMs: Math.round((now() - t0) * 100) / 100 };
}
