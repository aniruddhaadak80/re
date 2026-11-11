// Parsers for binwalk v2 text tables and binwalk v3 JSON logs.
import { extractJson, lines, num, str, PARSE_LIMITS } from './common.js';

export interface BinwalkHit {
  offset: number;
  offsetHex: string;
  description: string;
  /** short signature name when binwalk v3 provides it, otherwise the first words of the description */
  name: string;
  size?: number;
  confidence?: number;
}

function shortName(desc: string): string {
  const d = desc.toLowerCase();
  const head = d.split(',')[0]!.trim();
  return head.length > 64 ? head.slice(0, 64) : head;
}

/** Parse binwalk v2 signature scan output (DECIMAL HEXADECIMAL DESCRIPTION table). */
export function parseBinwalkTable(text: string): BinwalkHit[] {
  const out: BinwalkHit[] = [];
  const re = /^(\d{1,15})\s+0x([0-9A-Fa-f]{1,15})\s+(\S.{0,4095})$/;
  for (const l of lines(text)) {
    if (out.length >= PARSE_LIMITS.maxItems) break;
    const m = re.exec(l.trim());
    if (!m) continue;
    const offset = Number(m[1]);
    if (!Number.isSafeInteger(offset) || parseInt(m[2]!, 16) !== offset) continue;
    const description = m[3]!.trim();
    out.push({ offset, offsetHex: '0x' + offset.toString(16), description, name: shortName(description) });
  }
  return out;
}

/** Parse a binwalk v3 `--log` JSON file. Every `file_map` array found is flattened. */
export function parseBinwalkJson(input: string | unknown): BinwalkHit[] {
  const data = typeof input === 'string' ? extractJson(input) : input;
  const out: BinwalkHit[] = [];
  const seen = new Set<unknown>();
  const walk = (v: unknown, depth: number) => {
    if (depth > 8 || !v || typeof v !== 'object' || seen.has(v) || out.length >= PARSE_LIMITS.maxItems) return;
    seen.add(v);
    if (Array.isArray(v)) { for (const x of v.slice(0, 10_000)) walk(x, depth + 1); return; }
    const o = v as Record<string, unknown>;
    if (Array.isArray(o.file_map)) {
      for (const e of o.file_map.slice(0, PARSE_LIMITS.maxItems)) {
        const r = (e && typeof e === 'object' ? e : {}) as Record<string, unknown>;
        const offset = num(r.offset);
        if (offset === undefined || !Number.isSafeInteger(offset) || offset < 0) continue;
        const description = str(r.description, 4096) ?? '';
        const hit: BinwalkHit = { offset, offsetHex: '0x' + offset.toString(16), description, name: str(r.name, 64) ?? shortName(description) };
        const size = num(r.size); if (size !== undefined) hit.size = size;
        const c = num(r.confidence); if (c !== undefined) hit.confidence = c;
        out.push(hit);
      }
    }
    for (const k of Object.keys(o).slice(0, 200)) if (k !== 'file_map') walk(o[k], depth + 1);
  };
  walk(data, 0);
  return out.sort((a, b) => a.offset - b.offset);
}
