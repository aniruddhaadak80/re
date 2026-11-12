// rtl_433 style flex decoder specs: "n=name,m=OOK_PWM,s=300,l=900,r=5000,g=1500,bits>=24,
// preamble={8}aa,get=@0:{8}:id". Parsed into a structured spec, applied to pulse packages, and
// filtered and decoded like rtl_433's general purpose decoder. Independent implementation.

import { ParseError } from '../util.js';
import type { PulsePackage } from './pulses.js';
import { slice, rowCode, rowHex, manchesterDecode, dmDecode, uartDecode, type Modulation, type SlicedEvent } from './slicers.js';

export const MODULATIONS: Record<string, { mod: Modulation; desc: string }> = {
  OOK_PCM: { mod: 'OOK_PCM', desc: 'Pulse code: NRZ when short equals long (bit width), RZ when short is the pulse and long the bit period' },
  OOK_RZ: { mod: 'OOK_RZ', desc: 'Return to zero pulse code: short = pulse width, long = bit period' },
  OOK_PPM: { mod: 'OOK_PPM', desc: 'Pulse position: short gap = 0, long gap = 1' },
  OOK_PWM: { mod: 'OOK_PWM', desc: 'Pulse width: short pulse = 1, long pulse = 0, optional sync width' },
  OOK_MC_ZEROBIT: { mod: 'OOK_MC_ZEROBIT', desc: 'Manchester with a hard-coded leading zero bit (short = half bit)' },
  OOK_DMC: { mod: 'OOK_DMC', desc: 'Differential Manchester (short = half bit, long = full bit)' },
  FSK_PCM: { mod: 'FSK_PCM', desc: 'FSK pulse code (F1 = 1, F2 = 0), short = long = bit width' },
  FSK_PWM: { mod: 'FSK_PWM', desc: 'FSK pulse width (short F1 run = 1, long = 0)' },
  FSK_PPM: { mod: 'FSK_PPM', desc: 'FSK pulse position' },
  FSK_MC_ZEROBIT: { mod: 'FSK_MC_ZEROBIT', desc: 'FSK Manchester with leading zero bit' },
  FSK_DMC: { mod: 'FSK_DMC', desc: 'FSK differential Manchester' },
};

export interface FlexGetter { bitOffset: number; bits: number; name: string; map?: { value: number; text: string }[] }
export interface FlexSpec {
  name: string; modulation: Modulation;
  short: number; long: number; sync?: number; reset: number; gap?: number; tolerance?: number;
  minBits?: number; maxBits?: number; minRows?: number; maxRows?: number; minRepeats?: number; maxRepeats?: number;
  invert: boolean; reflect: boolean; unique: boolean; countOnly: boolean;
  match?: number[]; preamble?: number[];
  decode?: 'mc' | 'mc_thomas' | 'dm' | 'uart';
  getters: FlexGetter[];
  source: string;
}

/** Parse "{24}a5c3f1" or "a5c3f1" into bits. */
export function parseBitPattern(text: string): number[] {
  const m = /^\s*(?:\{(\d{1,4})\})?\s*([0-9a-fA-F]{1,1024})\s*$/.exec(text);
  if (!m) throw new ParseError(`bad bit pattern ${text.slice(0, 40)}`);
  const hex = m[2] as string;
  const len = m[1] !== undefined ? Number(m[1]) : hex.length * 4;
  if (len > hex.length * 4) throw new ParseError(`bit pattern ${text.slice(0, 40)} has fewer hex digits than bits`);
  const bits: number[] = [];
  for (const c of hex) { const v = parseInt(c, 16); for (let j = 3; j >= 0; j--) bits.push((v >> j) & 1); }
  return bits.slice(0, len);
}

/** Parse a flex spec string (comma separated key=value, as rtl_433 -X takes). */
export function parseFlexSpec(spec: string): FlexSpec {
  if (spec.length > 4096) throw new ParseError('flex spec too long');
  const out: FlexSpec = { name: 'flex', modulation: 'OOK_PCM', short: 0, long: 0, reset: 0, invert: false, reflect: false, unique: false, countOnly: false, getters: [], source: spec };
  // split on commas that are not inside [...] (get maps use spaces, but be tolerant)
  const parts: string[] = [];
  let depth = 0, cur = '';
  for (const ch of spec) {
    if (ch === '[') depth++;
    else if (ch === ']') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  if (cur) parts.push(cur);
  let haveMod = false;
  const numv = (k: string, v: string): number => { const x = Number(v); if (!Number.isFinite(x) || x < 0 || x > 1e8) throw new ParseError(`bad value for ${k}: ${v}`); return x; };
  for (const raw of parts) {
    const p = raw.trim();
    if (!p) continue;
    const m = /^([a-z_]+)\s*(>=|<=|=)?\s*(.*)$/i.exec(p);
    if (!m) throw new ParseError(`bad flex option ${p.slice(0, 40)}`);
    const key = (m[1] as string).toLowerCase(), op = m[2] ?? '', val = (m[3] ?? '').trim();
    switch (key) {
      case 'n': case 'name': out.name = val.slice(0, 64) || 'flex'; break;
      case 'm': case 'modulation': {
        const mm = MODULATIONS[val.toUpperCase()];
        if (!mm) throw new ParseError(`unknown modulation ${val}; one of ${Object.keys(MODULATIONS).join(', ')}`);
        out.modulation = mm.mod; haveMod = true; break;
      }
      case 's': case 'short': out.short = numv(key, val); break;
      case 'l': case 'long': out.long = numv(key, val); break;
      case 'y': case 'sync': out.sync = numv(key, val); break;
      case 'r': case 'reset': out.reset = numv(key, val); break;
      case 'g': case 'gap': out.gap = numv(key, val); break;
      case 't': case 'tolerance': out.tolerance = numv(key, val); break;
      case 'bits': if (op === '>=') out.minBits = numv(key, val); else if (op === '<=') out.maxBits = numv(key, val); else out.minBits = out.maxBits = numv(key, val); break;
      case 'rows': if (op === '>=') out.minRows = numv(key, val); else if (op === '<=') out.maxRows = numv(key, val); else out.minRows = out.maxRows = numv(key, val); break;
      case 'repeats': if (op === '>=') out.minRepeats = numv(key, val); else if (op === '<=') out.maxRepeats = numv(key, val); else out.minRepeats = out.maxRepeats = numv(key, val); break;
      case 'invert': out.invert = true; break;
      case 'reflect': out.reflect = true; break;
      case 'unique': out.unique = true; break;
      case 'countonly': out.countOnly = true; break;
      case 'match': out.match = parseBitPattern(val); break;
      case 'preamble': out.preamble = parseBitPattern(val); break;
      case 'decode_mc': out.decode = 'mc'; break;
      case 'decode_mc_thomas': out.decode = 'mc_thomas'; break;
      case 'decode_dm': out.decode = 'dm'; break;
      case 'decode_uart': out.decode = 'uart'; break;
      case 'get': out.getters.push(parseGetter(val)); if (out.getters.length > 64) throw new ParseError('too many get= fields'); break;
      case 'prio': case 'priority': break;
      default: throw new ParseError(`unknown flex option ${key}`);
    }
  }
  if (!haveMod) throw new ParseError('flex spec needs m=<modulation>');
  if (out.short <= 0) throw new ParseError('flex spec needs s=<short width in us>');
  if (out.long <= 0) out.long = out.short;
  if (out.reset <= 0) throw new ParseError('flex spec needs r=<reset limit in us>');
  return out;
}

function parseGetter(v: string): FlexGetter {
  // @offset:{bits}:name:[a:b c:d] ; parts may come in any order after the leading @offset
  const m = /^@(\d{1,5}):\{(\d{1,2})\}:([A-Za-z0-9_]{1,40})(?::\[([^\]]{0,2000})\])?$/.exec(v.trim());
  if (!m) throw new ParseError(`bad get= field ${v.slice(0, 60)}`);
  const bits = Number(m[2]);
  if (bits < 1 || bits > 32) throw new ParseError('get= field width must be 1 to 32 bits');
  const g: FlexGetter = { bitOffset: Number(m[1]), bits, name: m[3] as string };
  if (m[4] !== undefined) {
    g.map = [];
    for (const pair of (m[4] as string).trim().split(/\s+/).filter(Boolean).slice(0, 256)) {
      const k = pair.indexOf(':');
      if (k < 1) continue;
      const num = Number(pair.slice(0, k));
      if (Number.isFinite(num)) g.map.push({ value: num, text: pair.slice(k + 1) });
    }
  }
  return g;
}

export interface FlexRow { bits: number; hex: string; code: string; decoded?: { bits: number; hex: string; uartBytes?: number[] }; fields?: Record<string, number | string> }
export interface FlexEvent { model: string; package: number; startSample: number; endSample: number; timeSec: number; count: number; rows: FlexRow[]; codes: string[] }

const findPattern = (row: number[], pat: number[], from = 0): number => {
  outer: for (let k = from; k + pat.length <= row.length; k++) {
    for (let j = 0; j < pat.length; j++) if (row[k + j] !== pat[j]) continue outer;
    return k;
  }
  return -1;
};

/** Apply a flex spec to pulse packages: slice, filter and decode, like rtl_433 -X. */
export function runFlex(spec: FlexSpec, packages: PulsePackage[], rate: number, opts: { maxEvents?: number } = {}): FlexEvent[] {
  const events = slice(packages, spec.modulation, { short: spec.short, long: spec.long, sync: spec.sync, reset: spec.reset, gap: spec.gap, tolerance: spec.tolerance }, rate, opts.maxEvents ?? 1000);
  const out: FlexEvent[] = [];
  for (const ev of events) {
    const e = applyFilters(spec, ev, rate);
    if (e) out.push(e);
  }
  return out;
}

function applyFilters(spec: FlexSpec, ev: SlicedEvent, rate: number): FlexEvent | undefined {
  let rows = ev.rows.map((r) => r.slice());
  if (spec.invert) rows = rows.map((r) => r.map((b) => b ^ 1));
  if (spec.reflect) rows = rows.map((r) => { const o: number[] = []; for (let k = 0; k < r.length; k += 8) o.push(...r.slice(k, k + 8).reverse()); return o; });
  // row count limits use all rows; bit limits filter rows
  if (spec.minRows !== undefined && rows.length < spec.minRows) return undefined;
  if (spec.maxRows !== undefined && rows.length > spec.maxRows) return undefined;
  if (spec.minBits !== undefined || spec.maxBits !== undefined) {
    rows = rows.filter((r) => (spec.minBits === undefined || r.length >= spec.minBits) && (spec.maxBits === undefined || r.length <= spec.maxBits));
    if (!rows.length) return undefined;
  }
  if (spec.minRepeats !== undefined || spec.maxRepeats !== undefined) {
    const key = (r: number[]) => r.join('');
    const counts = new Map<string, number>();
    for (const r of rows) counts.set(key(r), (counts.get(key(r)) ?? 0) + 1);
    rows = rows.filter((r) => { const c = counts.get(key(r)) ?? 0; return (spec.minRepeats === undefined || c >= spec.minRepeats) && (spec.maxRepeats === undefined || c <= spec.maxRepeats); });
    if (!rows.length) return undefined;
  }
  if (spec.match) {
    const pat = spec.match;
    rows = rows.filter((r) => findPattern(r, pat) >= 0);
    if (!rows.length) return undefined;
  }
  if (spec.preamble) {
    const pat = spec.preamble;
    rows = rows.map((r) => { const k = findPattern(r, pat); return k < 0 ? undefined : r.slice(k + pat.length); }).filter((r): r is number[] => !!r);
    if (!rows.length) return undefined;
  }
  if (spec.unique) {
    const seen = new Set<string>();
    rows = rows.filter((r) => { const k = r.join(''); if (seen.has(k)) return false; seen.add(k); return true; });
  }
  const outRows: FlexRow[] = rows.map((r) => {
    const row: FlexRow = { bits: r.length, hex: rowHex(r), code: rowCode(r) };
    let data = r;
    if (spec.decode) {
      if (spec.decode === 'uart') { const u = uartDecode(r); row.decoded = { bits: u.bytes.length * 8, hex: u.bytes.map((x) => x.toString(16).padStart(2, '0')).join(''), uartBytes: u.bytes }; }
      else { data = spec.decode === 'dm' ? dmDecode(r) : manchesterDecode(r, spec.decode === 'mc_thomas'); row.decoded = { bits: data.length, hex: rowHex(data) }; }
    }
    if (spec.getters.length) {
      row.fields = {};
      for (const g of spec.getters) {
        if (g.bitOffset + g.bits > data.length) continue;
        let v = 0;
        for (let j = 0; j < g.bits; j++) v = v * 2 + (data[g.bitOffset + j] as number);
        const mapped = g.map?.find((x) => x.value === v);
        row.fields[g.name] = mapped ? mapped.text : v;
      }
    }
    return row;
  });
  return { model: spec.name, package: ev.package, startSample: ev.startSample, endSample: ev.endSample, timeSec: Math.round((ev.startSample / rate) * 1e6) / 1e6, count: 1, rows: spec.countOnly ? [] : outRows, codes: spec.countOnly ? [] : outRows.map((r) => r.code) };
}
