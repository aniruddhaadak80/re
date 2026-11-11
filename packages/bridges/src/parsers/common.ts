// Small helpers shared by the output parsers. Pure, browser safe.

export const PARSE_LIMITS = {
  maxJsonChars: 64 * 1024 * 1024,
  maxLines: 2_000_000,
  maxItems: 200_000,
} as const;

/** Format a non negative integer address as 0x hex. Returns undefined for anything else. */
export function hex(n: unknown): string | undefined {
  if (typeof n === 'number' && Number.isSafeInteger(n) && n >= 0) return '0x' + n.toString(16);
  if (typeof n === 'bigint' && n >= 0n) return '0x' + n.toString(16);
  if (typeof n === 'string' && /^0x[0-9a-f]{1,16}$/i.test(n)) return n.toLowerCase();
  return undefined;
}

export function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

export function str(v: unknown, max = 4096): string | undefined {
  return typeof v === 'string' ? (v.length > max ? v.slice(0, max) : v) : undefined;
}

export function bool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (v === 'true') return true;
  if (v === 'false') return false;
  return undefined;
}

/**
 * Pull the JSON value out of tool output that may carry banners or warnings before or after it.
 * Tries the whole text, then from the first `{` or `[`, then each line from the end.
 * Returns undefined when nothing parses.
 */
export function extractJson(text: string): unknown {
  if (typeof text !== 'string' || text.length === 0 || text.length > PARSE_LIMITS.maxJsonChars) return undefined;
  const t = text.trim();
  const tryParse = (s: string) => { try { return { ok: true as const, v: JSON.parse(s) as unknown }; } catch { return { ok: false as const }; } };
  let r = tryParse(t);
  if (r.ok) return r.v;
  const first = t.search(/[[{]/);
  if (first > 0) {
    r = tryParse(t.slice(first));
    if (r.ok) return r.v;
  }
  const lines = t.split(/\r?\n/);
  for (let i = lines.length - 1, n = 0; i >= 0 && n < 50; i--, n++) {
    const l = lines[i]!.trim();
    if (!l || (l[0] !== '{' && l[0] !== '[')) continue;
    r = tryParse(l);
    if (r.ok) return r.v;
  }
  return undefined;
}

/** Split text into lines with a hard cap. */
export function lines(text: string, max: number = PARSE_LIMITS.maxLines): string[] {
  if (typeof text !== 'string' || !text) return [];
  const out = text.split(/\r?\n/);
  return out.length > max ? out.slice(0, max) : out;
}

/** Apply offset and limit paging to a list and report the total. */
export function page<T>(items: T[], offset = 0, limit = 200): { items: T[]; total: number; offset: number; limit: number; more: boolean } {
  const o = Math.max(0, Math.floor(Number.isFinite(offset) ? offset : 0));
  const l = Math.max(0, Math.min(Math.floor(Number.isFinite(limit) ? limit : 200), 10_000));
  const slice = items.slice(o, o + l);
  return { items: slice, total: items.length, offset: o, limit: l, more: o + slice.length < items.length };
}
