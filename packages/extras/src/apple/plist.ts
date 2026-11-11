// Property lists: binary (bplist00) and XML, keeping CF$UID references so NSKeyedArchiver
// archives can be resolved. Caps on object count, depth and data size.

import { View, ParseError, utf8, toHex } from '../util.js';

export type PValue = string | number | bigint | boolean | null | PUid | PData | PDate | PValue[] | { [k: string]: PValue };
export interface PUid { $uid: number }
export interface PData { $data: string; length: number }
export interface PDate { $date: string }

export const isUid = (x: unknown): x is PUid => !!x && typeof x === 'object' && typeof (x as PUid).$uid === 'number' && Object.keys(x).length === 1;

/** Parse a binary or XML property list. */
export function parsePlistAny(b: Uint8Array, opts: { maxObjects?: number; maxData?: number } = {}): PValue {
  if (b.length >= 8 && utf8(b.subarray(0, 6)) === 'bplist') return parseBplist(b, opts);
  const text = utf8(b.subarray(0, Math.min(b.length, 64 << 20)));
  if (/<plist[\s>]/.test(text.slice(0, 4096))) return parseXmlPlistText(text, opts);
  throw new ParseError('not a property list (bplist00 or <plist> expected)', 0);
}

/** Parse a bplist00 binary property list. */
export function parseBplist(b: Uint8Array, opts: { maxObjects?: number; maxData?: number } = {}): PValue {
  const v = new View(b, false);
  if (b.length < 40 || utf8(b.subarray(0, 6)) !== 'bplist') throw new ParseError('not a binary plist', 0);
  const t = b.length - 32;
  const offSize = v.u8(t + 6), refSize = v.u8(t + 7);
  const numObjects = v.u64n(t + 8), top = v.u64n(t + 16), tableOff = v.u64n(t + 24);
  if (![1, 2, 4, 8].includes(offSize) || ![1, 2, 4, 8].includes(refSize)) throw new ParseError('bad bplist trailer sizes', t);
  if (numObjects > (opts.maxObjects ?? 1_000_000) || !v.has(tableOff, numObjects * offSize)) throw new ParseError('bplist object table out of range', tableOff);
  const maxData = opts.maxData ?? 1 << 20;
  const offs: number[] = [];
  for (let i = 0; i < numObjects; i++) offs.push(v.uN(tableOff + i * offSize, offSize, false));
  const memo = new Map<number, PValue>();
  const active = new Set<number>();
  const readInt = (o: number, n: number): number => { let x = 0; for (let i = 0; i < n; i++) x = x * 256 + v.u8(o + i); return x; };
  const obj = (ref: number, depth: number): PValue => {
    if (ref >= numObjects) throw new ParseError(`bplist reference ${ref} out of range`);
    if (memo.has(ref)) return memo.get(ref)!;
    if (depth > 256 || active.has(ref)) throw new ParseError('bplist nesting too deep or cyclic');
    active.add(ref);
    const o = offs[ref]!;
    const m = v.u8(o), hi = m >> 4, lo = m & 15;
    const count = (): [number, number] => {
      if (lo !== 15) return [lo, o + 1];
      const im = v.u8(o + 1);
      if (im >> 4 !== 1) throw new ParseError('bad bplist count marker', o);
      const n = 1 << (im & 15);
      return [readInt(o + 2, n), o + 2 + n];
    };
    let r: PValue;
    switch (hi) {
      case 0: r = m === 8 ? false : m === 9 ? true : null; break;
      case 1: { const n = 1 << lo; r = n === 8 ? (() => { const x = v.u64(o + 1, false); return x > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt.asIntN(64, x) : Number(x); })() : n === 16 ? v.u64(o + 9, false) : readInt(o + 1, n); if (typeof r === 'bigint' && r >= -BigInt(Number.MAX_SAFE_INTEGER) && r <= BigInt(Number.MAX_SAFE_INTEGER)) r = Number(r); break; }
      case 2: r = lo === 2 ? v.dv.getFloat32(o + 1, false) : (v.need(o + 1, 8), v.dv.getFloat64(o + 1, false)); break;
      case 3: { v.need(o + 1, 8); r = { $date: new Date(Date.UTC(2001, 0, 1) + v.dv.getFloat64(o + 1, false) * 1000).toISOString() }; break; }
      case 4: { const [n, s] = count(); v.need(s, n); r = { $data: toHex(v.sub(s, Math.min(n, maxData))), length: n }; break; }
      case 5: { const [n, s] = count(); let x = ''; for (let i = 0; i < n; i++) x += String.fromCharCode(v.u8(s + i)); r = x; break; }
      case 6: { const [n, s] = count(); r = v.utf16(s, n, false); break; }
      case 8: r = { $uid: readInt(o + 1, lo + 1) }; break;
      case 10: case 12: { const [n, s] = count(); const a: PValue[] = []; for (let i = 0; i < n; i++) a.push(obj(v.uN(s + i * refSize, refSize, false), depth + 1)); r = a; break; }
      case 13: {
        const [n, s] = count();
        const d: { [k: string]: PValue } = {};
        for (let i = 0; i < n; i++) { const k = obj(v.uN(s + i * refSize, refSize, false), depth + 1); d[String(k)] = obj(v.uN(s + (n + i) * refSize, refSize, false), depth + 1); }
        r = d; break;
      }
      default: throw new ParseError(`unknown bplist marker 0x${m.toString(16)}`, o);
    }
    active.delete(ref);
    memo.set(ref, r);
    return r;
  };
  return obj(top, 0);
}

const ENT: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const unesc = (s: string): string => s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|amp|quot|apos);/g, (_, e: string) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENT[e]!));

/** Parse an XML property list (tokenizer, no regex backtracking over the whole document). */
export function parseXmlPlistText(xml: string, opts: { maxObjects?: number } = {}): PValue {
  let p = xml.indexOf('<plist');
  if (p < 0) throw new ParseError('no <plist> element');
  p = xml.indexOf('>', p) + 1;
  let objects = 0;
  const max = opts.maxObjects ?? 1_000_000;
  const tag = (): { name: string; close: boolean; empty: boolean } => {
    for (;;) {
      const lt = xml.indexOf('<', p);
      if (lt < 0) throw new ParseError('unexpected end of XML plist');
      const gt = xml.indexOf('>', lt);
      if (gt < 0) throw new ParseError('unterminated XML tag');
      p = gt + 1;
      const inner = xml.slice(lt + 1, gt).trim();
      if (inner.startsWith('!') || inner.startsWith('?')) continue;
      const close = inner.startsWith('/');
      const empty = inner.endsWith('/');
      const name = inner.replace(/^\//, '').replace(/\/$/, '').split(/\s/)[0]!;
      return { name, close, empty };
    }
  };
  const text = (name: string): string => { const end = xml.indexOf(`</${name}>`, p); if (end < 0) throw new ParseError(`unterminated <${name}>`); const s = xml.slice(p, end); p = end + name.length + 3; return unesc(s); };
  const value = (t: { name: string; close: boolean; empty: boolean }, depth: number): PValue => {
    if (++objects > max || depth > 256) throw new ParseError('XML plist too large or deep');
    switch (t.name) {
      case 'true': return true;
      case 'false': return false;
      case 'string': return t.empty ? '' : text('string');
      case 'integer': { const s = text('integer').trim(); const n = Number(s); if (Number.isSafeInteger(n)) return n; if (!/^[+-]?(?:\d{1,40}|0x[0-9a-f]{1,32})$/i.test(s)) throw new ParseError(`bad <integer> ${JSON.stringify(s.slice(0, 40))}`); return s.startsWith('-') ? -BigInt(s.slice(1)) : BigInt(s.replace(/^\+/, '')); }
      case 'real': return Number(text('real'));
      case 'date': return { $date: new Date(text('date').trim()).toISOString() };
      case 'data': { const s = t.empty ? '' : text('data').replace(/\s+/g, ''); let bin = ''; try { bin = atob(s); } catch { throw new ParseError('bad base64 in <data>'); } let h = ''; for (let i = 0; i < bin.length; i++) h += bin.charCodeAt(i).toString(16).padStart(2, '0'); return { $data: h, length: bin.length }; }
      case 'array': { const a: PValue[] = []; if (t.empty) return a; for (;;) { const n = tag(); if (n.close) return a; a.push(value(n, depth + 1)); } }
      case 'dict': {
        const d: { [k: string]: PValue } = {};
        if (t.empty) return d;
        for (;;) {
          const k = tag();
          if (k.close) break;
          if (k.name !== 'key') throw new ParseError('expected <key> in <dict>');
          const key = text('key');
          d[key] = value(tag(), depth + 1);
        }
        // CF$UID dictionaries are UIDs in XML archives
        const keys = Object.keys(d);
        if (keys.length === 1 && keys[0] === 'CF$UID' && typeof d['CF$UID'] === 'number') return { $uid: d['CF$UID'] as number };
        return d;
      }
      default: throw new ParseError(`unknown plist element <${t.name}>`);
    }
  };
  return value(tag(), 0);
}
