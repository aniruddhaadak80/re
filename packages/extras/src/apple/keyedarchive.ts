// NSKeyedArchiver decoding: resolves $objects through CF$UID references from $top, maps
// common Foundation classes (arrays, dictionaries, sets, strings, data, dates, URLs, UUIDs)
// to plain JSON and keeps unknown classes as { $class, ...fields } with cycle markers.

import { ParseError } from '../util.js';
import { parsePlistAny, isUid, type PValue } from './plist.js';

export interface KeyedArchive {
  archiver: string; version: number | null; topKeys: string[]; objectCount: number;
  classes: { name: string; chain: string[]; uses: number }[];
  root: unknown; top: Record<string, unknown>;
}

/** True when a parsed plist looks like an NSKeyedArchiver archive. */
export function isKeyedArchive(p: PValue): boolean {
  return !!p && typeof p === 'object' && !Array.isArray(p) && Array.isArray((p as Record<string, PValue>).$objects) && typeof (p as Record<string, PValue>).$top === 'object';
}

/** Decode an NSKeyedArchiver plist (binary or XML bytes, or an already parsed plist). */
export function decodeKeyedArchive(input: Uint8Array | PValue, opts: { maxDepth?: number; maxNodes?: number } = {}): KeyedArchive {
  const p = input instanceof Uint8Array ? parsePlistAny(input) : input;
  if (!isKeyedArchive(p)) throw new ParseError('not an NSKeyedArchiver archive ($objects and $top expected)');
  const arch = p as Record<string, PValue>;
  const objects = arch.$objects as PValue[];
  const maxDepth = opts.maxDepth ?? 64;
  let budget = opts.maxNodes ?? 200000;
  const classUse = new Map<string, { chain: string[]; uses: number }>();
  const className = (ref: PValue): { name: string; chain: string[] } => {
    const c = isUid(ref) ? objects[ref.$uid] : undefined;
    if (!c || typeof c !== 'object' || Array.isArray(c)) return { name: '?', chain: [] };
    const cc = c as Record<string, PValue>;
    const chain = Array.isArray(cc.$classes) ? cc.$classes.map(String) : [];
    return { name: String(cc.$classname ?? chain[0] ?? '?'), chain };
  };
  const stack = new Set<number>();
  const resolve = (x: PValue, depth: number): unknown => {
    if (--budget < 0) throw new ParseError('keyed archive node budget exhausted');
    if (isUid(x)) {
      const id = x.$uid;
      if (id >= objects.length) throw new ParseError(`UID ${id} out of range`);
      if (stack.has(id) || depth > maxDepth) return { $ref: id };
      stack.add(id);
      try { return decodeObject(objects[id]!, id, depth + 1); } finally { stack.delete(id); }
    }
    if (Array.isArray(x)) return x.map((y) => resolve(y, depth + 1));
    if (x && typeof x === 'object' && !('$data' in x) && !('$date' in x)) {
      const o: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(x)) o[k] = resolve(val, depth + 1);
      return o;
    }
    return typeof x === 'bigint' ? x.toString() : x;
  };
  const decodeObject = (o: PValue, id: number, depth: number): unknown => {
    if (o === '$null') return null;
    if (!o || typeof o !== 'object' || Array.isArray(o) || '$data' in o || '$date' in o) return resolve(o, depth);
    const d = o as Record<string, PValue>;
    if (!('$class' in d)) return resolve(d, depth);
    const { name, chain } = className(d.$class);
    const u = classUse.get(name) ?? { chain, uses: 0 };
    u.uses++;
    classUse.set(name, u);
    const is = (n: string): boolean => name === n || chain.includes(n);
    const list = (k: string): unknown[] => (Array.isArray(d[k]) ? (d[k] as PValue[]).map((y) => resolve(y, depth)) : []);
    if (is('NSDictionary')) {
      const keys = list('NS.keys'), vals = list('NS.objects');
      const out: Record<string, unknown> = {};
      keys.forEach((k, i) => { out[typeof k === 'string' ? k : JSON.stringify(k)] = vals[i]; });
      return out;
    }
    if (is('NSArray') || is('NSOrderedSet')) return list('NS.objects');
    if (is('NSSet')) return { $set: list('NS.objects') };
    if (is('NSString') || is('NSMutableString')) return resolve(d['NS.string'] ?? (d['NS.bytes'] as PValue) ?? null, depth);
    if (is('NSData') || is('NSMutableData')) return resolve(d['NS.data'] ?? null, depth);
    if (is('NSDate')) { const t = d['NS.time']; return typeof t === 'number' ? { $date: new Date(Date.UTC(2001, 0, 1) + t * 1000).toISOString() } : null; }
    if (is('NSURL')) { const base = resolve(d['NS.base'] ?? null, depth), rel = resolve(d['NS.relative'] ?? null, depth); return { $url: base ? `${rel} -- ${JSON.stringify(base)}` : rel }; }
    if (is('NSUUID')) { const u8 = d['NS.uuidbytes'] as { $data?: string } | undefined; const h = u8?.$data ?? ''; return { $uuid: h.length === 32 ? `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`.toUpperCase() : h } ; }
    if (is('NSNull')) return null;
    if (is('NSValue') && d['NS.rectval'] !== undefined) return { $class: name, rect: resolve(d['NS.rectval'], depth) };
    const out: Record<string, unknown> = { $class: name };
    for (const [k, val] of Object.entries(d)) if (k !== '$class') out[k] = resolve(val, depth);
    void id;
    return out;
  };
  const top: Record<string, unknown> = {};
  const topObj = arch.$top as Record<string, PValue>;
  for (const [k, val] of Object.entries(topObj)) top[k] = resolve(val, 0);
  const rootKey = 'root' in topObj ? 'root' : Object.keys(topObj)[0];
  return {
    archiver: String(arch.$archiver ?? ''), version: typeof arch.$version === 'number' ? arch.$version : null,
    topKeys: Object.keys(topObj), objectCount: objects.length,
    classes: [...classUse.entries()].map(([name, x]) => ({ name, chain: x.chain, uses: x.uses })).sort((a, b) => b.uses - a.uses),
    root: rootKey !== undefined ? top[rootKey] : null, top,
  };
}
