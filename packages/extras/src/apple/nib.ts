// Compiled Interface Builder files in the NIBArchive format (what ibtool writes for .xib and
// storyboards): header, objects, keys, typed values and class names, plus a summary of
// classes, user visible strings and outlet/action connections. Keyed-archive nibs are
// handled by decodeKeyedArchive.

import { View, ParseError, utf8, toHex } from '../util.js';

export type NibValue = number | boolean | string | null | { $obj: number } | { $data: string; length: number } | bigint;
export interface NibObject { index: number; class: string; values: { key: string; value: NibValue; type: string }[] }
export interface NibArchive {
  formatVersion: number; coderVersion: number;
  counts: { objects: number; keys: number; values: number; classes: number };
  offsets: { objects: number; keys: number; values: number; classes: number };
  classes: string[]; keys: string[]; objects: NibObject[];
}

const TYPES = ['int8', 'int16', 'int32', 'int64', 'true', 'false', 'float', 'double', 'data', 'nil', 'object'];

/** True when bytes start with the NIBArchive magic. */
export function isNibArchive(b: Uint8Array): boolean { return b.length >= 50 && utf8(b.subarray(0, 10)) === 'NIBArchive'; }

/** Parse a NIBArchive file. */
export function parseNib(b: Uint8Array, opts: { maxItems?: number } = {}): NibArchive {
  if (!isNibArchive(b)) throw new ParseError('not a NIBArchive file', 0);
  const v = new View(b, true);
  const h = Array.from({ length: 10 }, (_, i) => v.u32(10 + i * 4));
  const [formatVersion, coderVersion, nObj, oObj, nKey, oKey, nVal, oVal, nCls, oCls] = h as [number, number, number, number, number, number, number, number, number, number];
  const max = opts.maxItems ?? 2_000_000;
  if (nObj > max || nKey > max || nVal > max || nCls > max) throw new ParseError('NIB counts over the limit');
  let p = 0;
  const varint = (): number => {
    let r = 0, shift = 0;
    for (let i = 0; i < 5; i++) {
      const c = v.u8(p++);
      r += (c & 0x7f) * 2 ** shift;
      if (c & 0x80) return r;
      shift += 7;
    }
    throw new ParseError('varint too long', p);
  };
  const classes: string[] = [];
  p = oCls;
  for (let i = 0; i < nCls; i++) {
    const len = varint(), extra = varint();
    if (extra > 64) throw new ParseError('too many class name extras', p);
    p += extra * 4;
    v.need(p, len);
    classes.push(stripNul(utf8(v.sub(p, len))));
    p += len;
  }
  const keys: string[] = [];
  p = oKey;
  for (let i = 0; i < nKey; i++) { const len = varint(); v.need(p, len); keys.push(utf8(v.sub(p, len))); p += len; }
  const values: { key: string; value: NibValue; type: string }[] = [];
  p = oVal;
  for (let i = 0; i < nVal; i++) {
    const k = varint();
    const t = v.u8(p++);
    let val: NibValue;
    switch (t) {
      case 0: val = v.dv.getInt8((v.need(p, 1), p)); p += 1; break;
      case 1: val = v.i16(p); p += 2; break;
      case 2: val = v.i32(p); p += 4; break;
      case 3: { v.need(p, 8); const x = v.dv.getBigInt64(p, true); val = x >= -BigInt(Number.MAX_SAFE_INTEGER) && x <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(x) : x; p += 8; break; }
      case 4: val = true; break;
      case 5: val = false; break;
      case 6: v.need(p, 4); val = v.dv.getFloat32(p, true); p += 4; break;
      case 7: v.need(p, 8); val = v.dv.getFloat64(p, true); p += 8; break;
      case 8: {
        const len = varint();
        v.need(p, len);
        const d = v.sub(p, len);
        p += len;
        // NSString contents are stored as data; show text when it decodes cleanly
        const s = utf8(d);
        val = len && !s.includes('\uFFFD') && !/[\x00-\x08\x0e-\x1f]/.test(s) ? s : { $data: toHex(d.subarray(0, 256)), length: len };
        break;
      }
      case 9: val = null; break;
      case 10: val = { $obj: v.u32(p) }; p += 4; break;
      default: throw new ParseError(`unknown NIB value type ${t}`, p - 1);
    }
    values.push({ key: keys[k] ?? `#${k}`, value: val, type: TYPES[t]! });
  }
  const objects: NibObject[] = [];
  p = oObj;
  for (let i = 0; i < nObj; i++) {
    const c = varint(), vi = varint(), vc = varint();
    objects.push({ index: i, class: classes[c] ?? `#${c}`, values: values.slice(vi, Math.min(values.length, vi + vc)) });
  }
  return { formatVersion, coderVersion, counts: { objects: nObj, keys: nKey, values: nVal, classes: nCls }, offsets: { objects: oObj, keys: oKey, values: oVal, classes: oCls }, classes, keys, objects };
}

const STRING_KEYS = new Set(['NSTitle', 'NSContents', 'NSPlaceholderString', 'NSToolTip', 'NSAlternateTitle', 'NSLabel', 'NSKeyEquiv', 'UIText', 'UITitle', 'UIPlaceholder', 'NSIdentifier', 'UIRestorationIdentifier', 'UIStoryboardIdentifier']);

/** Classes, strings and connections of a NIB archive, for a quick read of what the UI does. */
export function summarizeNib(n: NibArchive): { classHistogram: Record<string, number>; strings: { object: number; class: string; key: string; value: string }[]; connections: { object: number; class: string; label?: string; source?: number; destination?: number }[]; customClasses: string[] } {
  const hist: Record<string, number> = {};
  const strings: { object: number; class: string; key: string; value: string }[] = [];
  const connections: { object: number; class: string; label?: string; source?: number; destination?: number }[] = [];
  const custom = new Set<string>();
  const str = (x: NibValue | undefined): string | undefined => {
    if (typeof x === 'string') return x;
    if (x && typeof x === 'object' && '$obj' in x) { const o = n.objects[x.$obj]; const s = o?.values.find((y) => y.key === 'NS.bytes' || y.key === 'NS.string'); return typeof s?.value === 'string' ? s.value : undefined; }
    return undefined;
  };
  for (const o of n.objects) {
    hist[o.class] = (hist[o.class] ?? 0) + 1;
    for (const val of o.values) {
      if (STRING_KEYS.has(val.key)) { const s = str(val.value); if (s) strings.push({ object: o.index, class: o.class, key: val.key, value: s }); }
      if (val.key === 'NSClassName' || val.key === 'UIClassName' || val.key === 'NSOriginalClassName') { const s = str(val.value); if (s) custom.add(s); }
    }
    if (/Connector$|Connection$|OutletConnection|ActionConnection/.test(o.class)) {
      const get = (k: string): NibValue | undefined => o.values.find((x) => x.key === k)?.value;
      const ref = (x: NibValue | undefined): number | undefined => (x && typeof x === 'object' && '$obj' in x ? x.$obj : undefined);
      connections.push({ object: o.index, class: o.class, label: str(get('NSLabel') ?? get('UILabel')), source: ref(get('NSSource') ?? get('UISource')), destination: ref(get('NSDestination') ?? get('UIDestination')) });
    }
  }
  return { classHistogram: hist, strings, connections, customClasses: [...custom].sort() };
}

/** Drop trailing NUL characters without a regex (linear on any input). */
function stripNul(s: string): string { let e = s.length; while (e > 0 && s.charCodeAt(e - 1) === 0) e--; return s.slice(0, e); }
