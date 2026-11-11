// Property list reader for XML and binary (bplist00) plists. No Node imports. Bounds-checked,
// with caps on object count and nesting so hostile files cannot loop or blow the stack.
import { InputError } from './proc.js';

export type PlistValue = string | number | boolean | null | PlistValue[] | { [k: string]: PlistValue } | { $data: string } | { $date: string } | { $uid: number };

const MAX_OBJECTS = 1_000_000;
const MAX_DEPTH = 256;

export function isBinaryPlist(b: Uint8Array): boolean { return b.length >= 8 && String.fromCharCode(...b.subarray(0, 8)) === 'bplist00'; }

function toB64(b: Uint8Array): string {
  let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Parse a binary plist (bplist00). */
export function parseBinaryPlist(b: Uint8Array): PlistValue {
  if (!isBinaryPlist(b) || b.length < 40) throw new InputError('not a binary plist');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const t = b.length - 32;
  const offSize = b[t + 6]!, refSize = b[t + 7]!;
  const numObjects = Number(dv.getBigUint64(t + 8)), top = Number(dv.getBigUint64(t + 16)), tableOff = Number(dv.getBigUint64(t + 24));
  if (![1, 2, 4, 8].includes(offSize) || ![1, 2, 4, 8].includes(refSize)) throw new InputError('bad plist trailer sizes');
  if (numObjects > MAX_OBJECTS || top >= numObjects || tableOff + numObjects * offSize > t || tableOff < 8) throw new InputError('bad plist trailer');
  const readUint = (o: number, n: number): number => {
    if (o < 0 || o + n > b.length) throw new InputError('plist read out of bounds');
    let v = 0; for (let i = 0; i < n; i++) v = v * 256 + b[o + i]!; return v;
  };
  const offsetOf = (ref: number) => { if (ref >= numObjects) throw new InputError('plist object ref out of range'); return readUint(tableOff + ref * offSize, offSize); };
  let visited = 0;
  const lenAt = (o: number, info: number): { len: number; start: number } => {
    if (info !== 0xf) return { len: info, start: o + 1 };
    const m = b[o + 1]!;
    if ((m & 0xf0) !== 0x10) throw new InputError('bad plist length marker');
    const n = 1 << (m & 0xf);
    return { len: readUint(o + 2, n), start: o + 2 + n };
  };
  const read = (ref: number, depth: number, stack: Set<number>): PlistValue => {
    if (depth > MAX_DEPTH) throw new InputError('plist nesting too deep');
    if (++visited > MAX_OBJECTS * 2) throw new InputError('plist has too many references');
    if (stack.has(ref)) throw new InputError('plist reference cycle');
    const o = offsetOf(ref);
    if (o >= t) throw new InputError('plist object offset out of range');
    const marker = b[o]!, hi = marker >> 4, info = marker & 0xf;
    switch (hi) {
      case 0x0: return info === 8 ? false : info === 9 ? true : null;
      case 0x1: { const n = 1 << info; if (n === 8) return Number(dv.getBigInt64(o + 1)); if (n > 8) throw new InputError('plist int too large'); return readUint(o + 1, n); }
      case 0x2: { if (info === 2) return dv.getFloat32(o + 1); if (info === 3) return dv.getFloat64(o + 1); throw new InputError('bad plist real'); }
      case 0x3: { const secs = dv.getFloat64(o + 1); return { $date: new Date(Date.UTC(2001, 0, 1) + secs * 1000).toISOString() }; }
      case 0x4: { const { len, start } = lenAt(o, info); if (start + len > t) throw new InputError('plist data out of bounds'); return { $data: toB64(b.subarray(start, start + len)) }; }
      case 0x5: { const { len, start } = lenAt(o, info); if (start + len > t) throw new InputError('plist string out of bounds'); return new TextDecoder('latin1').decode(b.subarray(start, start + len)); }
      case 0x6: { const { len, start } = lenAt(o, info); if (start + len * 2 > t) throw new InputError('plist string out of bounds'); let s = ''; for (let i = 0; i < len; i++) s += String.fromCharCode(dv.getUint16(start + i * 2)); return s; }
      case 0x8: return { $uid: readUint(o + 1, info + 1) };
      case 0xa: case 0xc: {
        const { len, start } = lenAt(o, info);
        if (len > numObjects || start + len * refSize > t) throw new InputError('plist array out of bounds');
        stack.add(ref);
        const arr: PlistValue[] = [];
        for (let i = 0; i < len; i++) arr.push(read(readUint(start + i * refSize, refSize), depth + 1, stack));
        stack.delete(ref);
        return arr;
      }
      case 0xd: {
        const { len, start } = lenAt(o, info);
        if (len > numObjects || start + 2 * len * refSize > t) throw new InputError('plist dict out of bounds');
        stack.add(ref);
        const obj: Record<string, PlistValue> = Object.create(null);
        for (let i = 0; i < len; i++) {
          const k = read(readUint(start + i * refSize, refSize), depth + 1, stack);
          const v = read(readUint(start + (len + i) * refSize, refSize), depth + 1, stack);
          obj[String(k)] = v;
        }
        stack.delete(ref);
        return obj;
      }
      default: throw new InputError(`unknown plist object type 0x${marker.toString(16)}`);
    }
  };
  return read(top, 0, new Set());
}

const ENT: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const unescapeXml = (s: string) => s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|amp|lt|gt|quot|apos);/gi, (_m, e: string) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()] ?? _m));

/** Parse an XML plist with a small linear tokenizer (no DTD, no entities beyond the XML five). */
export function parseXmlPlist(text: string): PlistValue {
  if (text.length > 64 * 1024 * 1024) throw new InputError('plist too large');
  const tokens: { tag: string; close: boolean; self: boolean; text?: string }[] = [];
  let i = 0;
  while (i < text.length && tokens.length < MAX_OBJECTS * 2) {
    const lt = text.indexOf('<', i);
    if (lt < 0) break;
    if (lt > i) { const tx = text.slice(i, lt); if (tokens.length) tokens.push({ tag: '#text', close: false, self: true, text: tx }); }
    if (text.startsWith('<!--', lt)) { const e = text.indexOf('-->', lt + 4); i = e < 0 ? text.length : e + 3; continue; }
    if (text.startsWith('<?', lt) || text.startsWith('<!', lt)) { const e = text.indexOf('>', lt); i = e < 0 ? text.length : e + 1; continue; }
    const gt = text.indexOf('>', lt);
    if (gt < 0) throw new InputError('unterminated tag in plist');
    const raw = text.slice(lt + 1, gt).trim();
    const close = raw.startsWith('/');
    const self = raw.endsWith('/');
    const tag = raw.replace(/^\//, '').replace(/\/$/, '').split(/\s/)[0]!;
    tokens.push({ tag, close, self });
    i = gt + 1;
  }
  let p = 0;
  const textUntil = (tag: string): string => {
    let s = '';
    while (p < tokens.length && !(tokens[p]!.close && tokens[p]!.tag === tag)) { if (tokens[p]!.tag === '#text') s += tokens[p]!.text; p++; }
    p++;
    return unescapeXml(s);
  };
  const skipText = () => { while (p < tokens.length && tokens[p]!.tag === '#text') p++; };
  const value = (depth: number): PlistValue => {
    if (depth > MAX_DEPTH) throw new InputError('plist nesting too deep');
    skipText();
    const tk = tokens[p++];
    if (!tk) throw new InputError('unexpected end of plist');
    if (tk.close) throw new InputError(`unexpected </${tk.tag}>`);
    switch (tk.tag) {
      case 'plist': { const v = value(depth + 1); skipText(); if (tokens[p]?.close) p++; return v; }
      case 'dict': {
        const o: Record<string, PlistValue> = Object.create(null);
        if (tk.self) return o;
        for (;;) {
          skipText();
          const n = tokens[p];
          if (!n) throw new InputError('unterminated dict');
          if (n.close && n.tag === 'dict') { p++; return o; }
          if (n.tag !== 'key') throw new InputError(`expected key, got ${n.tag}`);
          p++;
          const k = textUntil('key');
          o[k] = value(depth + 1);
        }
      }
      case 'array': {
        const a: PlistValue[] = [];
        if (tk.self) return a;
        for (;;) {
          skipText();
          const n = tokens[p];
          if (!n) throw new InputError('unterminated array');
          if (n.close && n.tag === 'array') { p++; return a; }
          a.push(value(depth + 1));
        }
      }
      case 'string': return tk.self ? '' : textUntil('string');
      case 'integer': return Number(textUntil('integer').trim());
      case 'real': return Number(textUntil('real').trim());
      case 'true': if (!tk.self) textUntil('true'); return true;
      case 'false': if (!tk.self) textUntil('false'); return false;
      case 'date': { const d = textUntil('date').trim(); const t = Date.parse(d); return { $date: Number.isFinite(t) ? new Date(t).toISOString() : d }; }
      case 'data': return { $data: tk.self ? '' : textUntil('data').replace(/\s+/g, '') };
      default: throw new InputError(`unknown plist element <${tk.tag}>`);
    }
  };
  // start at <plist> or the first value element
  while (p < tokens.length && !['plist', 'dict', 'array', 'string'].includes(tokens[p]!.tag)) p++;
  return value(0);
}

/** Parse XML or binary plist bytes. */
export function parsePlist(bytes: Uint8Array): PlistValue {
  if (isBinaryPlist(bytes)) return parseBinaryPlist(bytes);
  const text = new TextDecoder().decode(bytes.subarray(0, 64 * 1024 * 1024));
  if (!/<plist|<dict/.test(text.slice(0, 4096))) throw new InputError('not a plist');
  return parseXmlPlist(text);
}
