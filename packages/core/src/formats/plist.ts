// Property lists: XML (DMG resource maps, Info.plist) and binary bplist00. Bounded on depth and object counts.

import { parseXml, type XmlNode } from './xml.js';
import { base64Decode, BinView, FormatError, isoUtc } from './util.js';
import { decodeUtf8 } from '../bytes.js';

export type PlistValue = string | number | boolean | Uint8Array | PlistValue[] | { [k: string]: PlistValue } | null;

function fromXml(n: XmlNode, depth: number): PlistValue {
  if (depth > 64) throw new FormatError('plist nesting is deeper than 64');
  switch (n.local) {
    case 'dict': {
      const out: Record<string, PlistValue> = Object.create(null) as Record<string, PlistValue>;
      const kids = n.children;
      for (let i = 0; i + 1 < kids.length; i += 2) {
        const k = kids[i] as XmlNode, v = kids[i + 1] as XmlNode;
        if (k.local !== 'key') { i--; continue; }
        out[k.text] = fromXml(v, depth + 1);
      }
      return out;
    }
    case 'array': return n.children.map((c) => fromXml(c, depth + 1));
    case 'string': return n.text;
    case 'key': return n.text;
    case 'integer': { const v = Number(n.text.trim()); return Number.isFinite(v) ? v : n.text.trim(); }
    case 'real': return Number(n.text.trim());
    case 'true': return true;
    case 'false': return false;
    case 'date': return n.text.trim();
    case 'data': return base64Decode(n.text);
    default: return null;
  }
}

/** Parse an XML property list. */
export function parsePlistXml(text: string): PlistValue {
  const doc = parseXml(text);
  const pl = doc.children.find((c) => c.local === 'plist') ?? doc;
  const first = pl.children[0];
  if (!first) throw new FormatError('empty plist');
  return fromXml(first, 0);
}

/** Parse a binary property list (bplist00). */
export function parsePlistBinary(bytes: Uint8Array, maxObjects = 1_000_000): PlistValue {
  const v = new BinView(bytes);
  if (bytes.length < 40 || v.ascii(0, 6) !== 'bplist') throw new FormatError('not a binary plist');
  const t = bytes.length - 32;
  const offSize = v.u8(t + 6), refSize = v.u8(t + 7);
  const numObjects = v.u64be(t + 8), top = v.u64be(t + 16), tableOff = v.u64be(t + 24);
  if (offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObjects > maxObjects || !v.has(tableOff, numObjects * offSize)) throw new FormatError('bad bplist trailer', t);
  const readN = (o: number, size: number): number => { let x = 0; for (let i = 0; i < size; i++) x = x * 256 + v.u8(o + i); return x; };
  const offsetOf = (ref: number): number => { if (ref >= numObjects) throw new FormatError('bplist reference out of range'); return readN(tableOff + ref * offSize, offSize); };
  let budget = maxObjects * 4;
  const obj = (ref: number, depth: number): PlistValue => {
    if (depth > 64 || --budget < 0) throw new FormatError('bplist is too deep or too large');
    const o = offsetOf(ref);
    const marker = v.u8(o);
    const hi = marker >> 4, lo = marker & 15;
    const count = (): [number, number] => {
      if (lo !== 15) return [lo, o + 1];
      const m = v.u8(o + 1);
      const sz = 1 << (m & 15);
      return [readN(o + 2, sz), o + 2 + sz];
    };
    switch (hi) {
      case 0: return lo === 8 ? false : lo === 9 ? true : null;
      case 1: { const sz = 1 << lo; return sz === 8 ? Number(v.dv.getBigInt64(o + 1, false)) : readN(o + 1, sz); }
      case 2: return lo === 2 ? v.dv.getFloat32(o + 1, false) : v.dv.getFloat64(o + 1, false);
      case 3: return isoUtc((v.dv.getFloat64(o + 1, false) + 978307200) * 1000);
      case 4: { const [n, s] = count(); return v.sub(s, n); }
      case 5: { const [n, s] = count(); let str = ""; const b = v.sub(s, n); for (let i = 0; i < b.length; i++) str += String.fromCharCode(b[i] as number); return str; }
      case 6: { const [n, s] = count(); const b = v.sub(s, n * 2); let str = ''; for (let i = 0; i < b.length; i += 2) str += String.fromCharCode(((b[i] as number) << 8) | (b[i + 1] as number)); return str; }
      case 7: { const [n, s] = count(); return decodeUtf8(v.sub(s, n)); }
      case 8: return readN(o + 1, lo + 1);
      case 10: { const [n, s] = count(); const out: PlistValue[] = []; for (let i = 0; i < n; i++) out.push(obj(readN(s + i * refSize, refSize), depth + 1)); return out; }
      case 13: {
        const [n, s] = count();
        const out: Record<string, PlistValue> = Object.create(null) as Record<string, PlistValue>;
        for (let i = 0; i < n; i++) {
          const k = obj(readN(s + i * refSize, refSize), depth + 1);
          out[String(k)] = obj(readN(s + (n + i) * refSize, refSize), depth + 1);
        }
        return out;
      }
      default: return null;
    }
  };
  return obj(top, 0);
}

/** Parse either plist flavour. */
export function parsePlist(bytes: Uint8Array): PlistValue {
  if (bytes.length >= 8 && bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6c) return parsePlistBinary(bytes);
  return parsePlistXml(decodeUtf8(bytes));
}

export function isDict(v: PlistValue | undefined): v is { [k: string]: PlistValue } {
  return !!v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array);
}
