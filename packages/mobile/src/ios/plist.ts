// Property list parser: binary (bplist00) and XML. JSON-friendly output.
// Dates become ISO strings, data becomes { $data: base64 } (capped), UIDs become { $uid: n }.

import { Buf, ParseError, utf8 } from '../bytes.js';

export type PlistValue = string | number | boolean | null | PlistValue[] | { [k: string]: PlistValue };

export const PLIST_LIMITS = { maxObjects: 1_000_000, maxDepth: 128, maxDataBytes: 64 * 1024, maxXmlBytes: 64 * 1024 * 1024 };

function b64(b: Uint8Array): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = ((b[i] as number) << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += chars[(n >> 18) & 63]! + chars[(n >> 12) & 63]! + (i + 1 < b.length ? chars[(n >> 6) & 63]! : '=') + (i + 2 < b.length ? chars[n & 63]! : '=');
  }
  return out;
}

export function isBinaryPlist(b: Uint8Array): boolean {
  return b.length >= 40 && utf8(b.subarray(0, 6)) === 'bplist';
}

export function parsePlist(b: Uint8Array): PlistValue {
  if (isBinaryPlist(b)) return parseBinaryPlist(b);
  return parseXmlPlist(utf8(b.subarray(0, PLIST_LIMITS.maxXmlBytes)));
}

export function parseBinaryPlist(b: Uint8Array): PlistValue {
  const r = new Buf(b, false);
  if (!isBinaryPlist(b)) throw new ParseError('not a binary plist');
  const t = b.length - 32;
  const offSize = r.u8(t + 6);
  const refSize = r.u8(t + 7);
  const numObjects = Number(r.u64(t + 8));
  const top = Number(r.u64(t + 16));
  const tableOff = Number(r.u64(t + 24));
  if (![1, 2, 4, 8].includes(offSize) || ![1, 2, 4, 8].includes(refSize)) throw new ParseError('bad binary plist trailer');
  if (numObjects > PLIST_LIMITS.maxObjects || top >= numObjects) throw new ParseError('bad binary plist object count');
  r.check(tableOff, numObjects * offSize);
  const readN = (o: number, n: number): number => {
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + r.u8(o + i);
    return v;
  };
  const offsetOf = (i: number): number => readN(tableOff + i * offSize, offSize);
  const active = new Set<number>();
  let budget = PLIST_LIMITS.maxObjects * 4;
  const obj = (i: number, depth: number): PlistValue => {
    if (depth > PLIST_LIMITS.maxDepth) throw new ParseError('binary plist nesting too deep');
    if (i >= numObjects) throw new ParseError(`object ref ${i} out of range`);
    if (active.has(i)) throw new ParseError('binary plist has a reference cycle');
    if (--budget < 0) throw new ParseError('binary plist expands to too many objects');
    const o = offsetOf(i);
    const m = r.u8(o);
    const hi = m >> 4, lo = m & 0xf;
    const count = (): [number, number] => {
      if (lo !== 0xf) return [lo, o + 1];
      const im = r.u8(o + 1);
      if (im >> 4 !== 1) throw new ParseError('bad plist count marker');
      const n = 1 << (im & 0xf);
      return [readN(o + 2, n), o + 2 + n];
    };
    switch (hi) {
      case 0x0: return m === 0x08 ? false : m === 0x09 ? true : null;
      case 0x1: {
        const n = 1 << lo;
        if (n === 8) { const v = r.i64(o + 1); return Number(v); }
        if (n === 16) return Number(r.i64(o + 9));
        return readN(o + 1, n);
      }
      case 0x2: return lo === 2 ? r.f32(o + 1) : r.f64(o + 1);
      case 0x3: { const secs = r.f64(o + 1); return new Date(Date.UTC(2001, 0, 1) + secs * 1000).toISOString(); }
      case 0x4: { const [n, s] = count(); r.check(s, n); return { $data: b64(r.slice(s, Math.min(n, PLIST_LIMITS.maxDataBytes))), $length: n } as unknown as PlistValue; }
      case 0x5: { const [n, s] = count(); return utf8(r.slice(s, n)); }
      case 0x6: {
        const [n, s] = count();
        r.check(s, n * 2);
        let str = '';
        for (let k = 0; k < n; k++) str += String.fromCharCode(r.u16(s + k * 2));
        return str;
      }
      case 0x8: return { $uid: readN(o + 1, lo + 1) };
      case 0xa: case 0xc: {
        const [n, s] = count();
        active.add(i);
        const arr: PlistValue[] = [];
        for (let k = 0; k < n; k++) arr.push(obj(readN(s + k * refSize, refSize), depth + 1));
        active.delete(i);
        return arr;
      }
      case 0xd: {
        const [n, s] = count();
        active.add(i);
        const d: Record<string, PlistValue> = {};
        for (let k = 0; k < n; k++) {
          const key = obj(readN(s + k * refSize, refSize), depth + 1);
          const val = obj(readN(s + (n + k) * refSize, refSize), depth + 1);
          d[String(key)] = val;
        }
        active.delete(i);
        return d;
      }
      default: throw new ParseError(`unknown binary plist marker 0x${m.toString(16)}`);
    }
  };
  return obj(top, 0);
}

// ------------------------------------------------------------------ XML plist

interface Tok { kind: 'open' | 'close' | 'empty' | 'text'; name: string; text: string }

function* tokens(xml: string): Generator<Tok> {
  let i = 0;
  const n = xml.length;
  while (i < n) {
    const lt = xml.indexOf('<', i);
    if (lt < 0) { const t = xml.slice(i); if (t.trim()) yield { kind: 'text', name: '', text: t }; return; }
    if (lt > i) yield { kind: 'text', name: '', text: xml.slice(i, lt) };
    if (xml.startsWith('<!--', lt)) { const e = xml.indexOf('-->', lt + 4); i = e < 0 ? n : e + 3; continue; }
    if (xml.startsWith('<![CDATA[', lt)) {
      const e = xml.indexOf(']]>', lt + 9);
      yield { kind: 'text', name: '', text: xml.slice(lt + 9, e < 0 ? n : e) };
      i = e < 0 ? n : e + 3;
      continue;
    }
    if (xml[lt + 1] === '?' || xml[lt + 1] === '!') { const e = xml.indexOf('>', lt); i = e < 0 ? n : e + 1; continue; }
    const gt = xml.indexOf('>', lt);
    if (gt < 0) return;
    let inner = xml.slice(lt + 1, gt).trim();
    i = gt + 1;
    if (inner.startsWith('/')) { yield { kind: 'close', name: inner.slice(1).trim(), text: '' }; continue; }
    const empty = inner.endsWith('/');
    if (empty) inner = inner.slice(0, -1);
    const sp = inner.search(/\s/);
    const name = sp < 0 ? inner : inner.slice(0, sp);
    yield { kind: empty ? 'empty' : 'open', name, text: '' };
  }
}

function unescapeXml(s: string): string {
  return s.replace(/&(lt|gt|amp|quot|apos|#\d{1,7}|#x[0-9a-fA-F]{1,6});/g, (_m, e: string) => {
    switch (e) {
      case 'lt': return '<'; case 'gt': return '>'; case 'amp': return '&'; case 'quot': return '"'; case 'apos': return "'";
      default: {
        const cp = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
      }
    }
  });
}

export function parseXmlPlist(xml: string): PlistValue {
  const it = tokens(xml);
  let count = 0;
  const next = (): Tok | undefined => {
    for (;;) {
      const t = it.next();
      if (t.done) return undefined;
      if (++count > PLIST_LIMITS.maxObjects * 3) throw new ParseError('XML plist too large');
      if (t.value.kind === 'text' && !t.value.text.trim()) continue;
      return t.value;
    }
  };
  const readText = (name: string): string => {
    let text = '';
    for (;;) {
      const t = it.next();
      if (t.done) throw new ParseError(`unterminated <${name}>`);
      if (t.value.kind === 'text') text += t.value.text;
      else if (t.value.kind === 'close' && t.value.name === name) return unescapeXml(text);
      else throw new ParseError(`unexpected <${t.value.name}> inside <${name}>`);
    }
  };
  const value = (t: Tok, depth: number): PlistValue => {
    if (depth > PLIST_LIMITS.maxDepth) throw new ParseError('XML plist nesting too deep');
    if (t.kind === 'empty') {
      switch (t.name) {
        case 'true': return true; case 'false': return false;
        case 'dict': return {}; case 'array': return []; case 'string': return ''; case 'data': return { $data: '', $length: 0 } as unknown as PlistValue;
        default: return null;
      }
    }
    if (t.kind !== 'open') throw new ParseError(`unexpected token in plist: ${t.kind} ${t.name}`);
    switch (t.name) {
      case 'string': return readText('string');
      case 'integer': { const s = readText('integer').trim(); const v = Number(s); return Number.isFinite(v) ? v : s; }
      case 'real': return Number(readText('real').trim());
      case 'date': return readText('date').trim();
      case 'data': { const s = readText('data').replace(/\s+/g, ''); return { $data: s.slice(0, PLIST_LIMITS.maxDataBytes * 2), $length: Math.floor(s.length * 3 / 4) } as unknown as PlistValue; }
      case 'true': readText('true'); return true;
      case 'false': readText('false'); return false;
      case 'array': {
        const arr: PlistValue[] = [];
        for (;;) {
          const c = next();
          if (!c) throw new ParseError('unterminated <array>');
          if (c.kind === 'close' && c.name === 'array') return arr;
          arr.push(value(c, depth + 1));
        }
      }
      case 'dict': {
        const d: Record<string, PlistValue> = {};
        for (;;) {
          const c = next();
          if (!c) throw new ParseError('unterminated <dict>');
          if (c.kind === 'close' && c.name === 'dict') return d;
          if (c.kind !== 'open' || c.name !== 'key') throw new ParseError(`expected <key> in <dict>, got ${c.name || c.kind}`);
          const key = readText('key');
          const v = next();
          if (!v) throw new ParseError('dict key without value');
          d[key] = value(v, depth + 1);
        }
      }
      case 'plist': {
        const c = next();
        if (!c || (c.kind === 'close' && c.name === 'plist')) return null;
        const v = value(c, depth + 1);
        return v;
      }
      default: throw new ParseError(`unknown plist element <${t.name}>`);
    }
  };
  const first = next();
  if (!first) throw new ParseError('empty plist');
  return value(first, 0);
}
