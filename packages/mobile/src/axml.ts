// Android binary XML (AXML) and resource table (resources.arsc) decoder.
// Reference: frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h (format only, no code copied).

import { Buf, ParseError, utf8, utf16le } from './bytes.js';

export const RES = {
  STRING_POOL: 0x0001,
  TABLE: 0x0002,
  XML: 0x0003,
  XML_START_NAMESPACE: 0x0100,
  XML_END_NAMESPACE: 0x0101,
  XML_START_ELEMENT: 0x0102,
  XML_END_ELEMENT: 0x0103,
  XML_CDATA: 0x0104,
  XML_RESOURCE_MAP: 0x0180,
  TABLE_PACKAGE: 0x0200,
  TABLE_TYPE: 0x0201,
  TABLE_TYPE_SPEC: 0x0202,
  TABLE_LIBRARY: 0x0203,
} as const;

export const AXML_LIMITS = { maxStrings: 500_000, maxNodes: 200_000, maxDepth: 256, maxStringBytes: 1 << 16 };

/** Android framework attribute ids, used when an obfuscated manifest strips attribute names. */
export const ANDROID_ATTR_IDS: Record<number, string> = {
  0x01010000: 'theme', 0x01010001: 'label', 0x01010002: 'icon', 0x01010003: 'name',
  0x01010006: 'permission', 0x01010007: 'readPermission', 0x01010008: 'writePermission',
  0x01010009: 'protectionLevel', 0x0101000b: 'sharedUserId', 0x0101000c: 'hasCode',
  0x0101000e: 'enabled', 0x0101000f: 'debuggable', 0x01010010: 'exported', 0x01010011: 'process',
  0x01010012: 'taskAffinity', 0x01010018: 'authorities', 0x0101001b: 'grantUriPermissions',
  0x0101001c: 'priority', 0x0101001d: 'launchMode', 0x01010024: 'value', 0x01010025: 'resource',
  0x01010026: 'mimeType', 0x01010027: 'scheme', 0x01010028: 'host', 0x01010029: 'port',
  0x0101002a: 'path', 0x0101002b: 'pathPrefix', 0x0101002c: 'pathPattern',
  0x0101020c: 'minSdkVersion', 0x0101021b: 'versionCode', 0x0101021c: 'versionName',
  0x01010270: 'targetSdkVersion', 0x01010271: 'maxSdkVersion', 0x01010272: 'testOnly',
  0x01010280: 'allowBackup', 0x0101028e: 'required', 0x010102b7: 'installLocation',
  0x0101035a: 'largeHeap', 0x010104ea: 'extractNativeLibs', 0x010104ec: 'usesCleartextTraffic',
  0x010104ee: 'autoVerify', 0x01010527: 'networkSecurityConfig', 0x01010572: 'compileSdkVersion',
  0x01010573: 'compileSdkVersionCodename', 0x0101057a: 'appComponentFactory',
};

export interface StringPool {
  strings: string[];
  utf8: boolean;
  offset: number;
}

/** Parse a ResStringPool chunk at `off`. */
export function parseStringPool(r: Buf, off: number): StringPool {
  const headerSize = r.u16(off + 2);
  const size = r.u32(off + 4);
  const count = r.u32(off + 8);
  const flags = r.u32(off + 16);
  const stringsStart = r.u32(off + 20);
  if (count > AXML_LIMITS.maxStrings) throw new ParseError(`string pool claims ${count} strings`);
  const isUtf8 = (flags & 0x100) !== 0;
  const end = Math.min(r.length, off + size);
  const strings: string[] = new Array(count);
  const base = off + stringsStart;
  for (let i = 0; i < count; i++) {
    let s = '';
    try {
      const so = base + r.u32(off + headerSize + i * 4);
      if (so >= end) { strings[i] = ''; continue; }
      if (isUtf8) {
        let p = so;
        // utf16 length (skipped), then utf8 byte length
        let l = r.u8(p); p += (l & 0x80) ? 2 : 1;
        l = r.u8(p);
        if (l & 0x80) { l = ((l & 0x7f) << 8) | r.u8(p + 1); p += 2; } else p += 1;
        l = Math.min(l, AXML_LIMITS.maxStringBytes, end - p);
        s = utf8(r.slice(p, Math.max(0, l)));
      } else {
        let p = so;
        let l = r.u16(p); p += 2;
        if (l & 0x8000) { l = ((l & 0x7fff) << 16) | r.u16(p); p += 2; }
        l = Math.min(l * 2, AXML_LIMITS.maxStringBytes * 2, end - p);
        s = utf16le(r.slice(p, Math.max(0, l & ~1)));
      }
    } catch { s = ''; }
    strings[i] = s;
  }
  return { strings, utf8: isUtf8, offset: off };
}

export interface ResValue { type: number; data: number }

export interface XmlAttr {
  ns?: string;
  name: string;
  /** framework resource id of the attribute name when known */
  resId?: number;
  raw?: string;
  value: ResValue;
  /** human form, the way aapt and apktool print it */
  text: string;
}

export interface XmlNode {
  tag: string;
  ns?: string;
  attrs: XmlAttr[];
  children: XmlNode[];
  text?: string;
  line: number;
  offset: number;
}

export interface AxmlDocument {
  root: XmlNode | undefined;
  strings: string[];
  resourceIds: number[];
  namespaces: Record<string, string>;
}

export function isAxml(b: Uint8Array): boolean {
  return b.length >= 8 && b[0] === 0x03 && b[1] === 0x00 && b[2] === 0x08 && b[3] === 0x00;
}

/** Format a Res_value like aapt does. `strings` resolves TYPE_STRING. */
export function formatValue(v: ResValue, strings: string[], raw?: string): string {
  const d = v.data >>> 0;
  switch (v.type) {
    case 0x00: return d === 1 ? '@empty' : '@null';
    case 0x01: return d === 0 ? '@null' : `@0x${d.toString(16).padStart(8, '0')}`;
    case 0x02: return `?0x${d.toString(16).padStart(8, '0')}`;
    case 0x03: return raw ?? strings[d] ?? '';
    case 0x04: { const f = new DataView(new ArrayBuffer(4)); f.setUint32(0, d, true); return String(f.getFloat32(0, true)); }
    case 0x05: return complexToString(d, false);
    case 0x06: return complexToString(d, true);
    case 0x07: return `@0x${d.toString(16).padStart(8, '0')}`;
    case 0x10: return String(d | 0);
    case 0x11: return `0x${d.toString(16)}`;
    case 0x12: return d !== 0 ? 'true' : 'false';
    default:
      if (v.type >= 0x1c && v.type <= 0x1f) return `#${d.toString(16).padStart(8, '0')}`;
      return raw ?? `0x${d.toString(16)}`;
  }
}

function complexToString(d: number, fraction: boolean): string {
  const radixMult = [1 / (1 << 0), 1 / (1 << 7), 1 / (1 << 15), 1 / (1 << 23)];
  const mantissa = (d & 0xffffff00) | 0;
  const radix = (d >> 4) & 3;
  const val = (mantissa >> 8) * (radixMult[radix] as number);
  const unit = d & 0xf;
  const units = fraction ? ['%', '%p'] : ['px', 'dip', 'sp', 'pt', 'in', 'mm'];
  const num = Number.isInteger(val) ? val.toFixed(1) : String(Math.round(val * 1e6) / 1e6);
  return `${fraction ? Number(num) * 100 : num}${units[unit] ?? ''}`;
}

/** Decode a whole AXML document into a tree. */
export function parseAxml(bytes: Uint8Array): AxmlDocument {
  const r = new Buf(bytes);
  if (!isAxml(bytes)) throw new ParseError('not Android binary XML (missing 0x0003 chunk)');
  const total = Math.min(r.u32(4), bytes.length);
  let strings: string[] = [];
  let resourceIds: number[] = [];
  const namespaces: Record<string, string> = {};
  const nsPrefix = new Map<string, string>();
  const stack: XmlNode[] = [];
  let root: XmlNode | undefined;
  let nodes = 0;
  let off = r.u16(2);
  const str = (i: number): string | undefined => (i === 0xffffffff ? undefined : strings[i]);
  while (off + 8 <= total) {
    const type = r.u16(off);
    const hsize = r.u16(off + 2);
    const size = r.u32(off + 4);
    if (size < 8 || off + size > bytes.length) break;
    if (type === RES.STRING_POOL) strings = parseStringPool(r, off).strings;
    else if (type === RES.XML_RESOURCE_MAP) {
      const n = Math.min((size - hsize) >>> 2, AXML_LIMITS.maxStrings);
      resourceIds = new Array(n);
      for (let i = 0; i < n; i++) resourceIds[i] = r.u32(off + hsize + i * 4);
    } else if (type === RES.XML_START_NAMESPACE) {
      const prefix = str(r.u32(off + 16)) ?? '';
      const uri = str(r.u32(off + 20)) ?? '';
      namespaces[prefix] = uri;
      nsPrefix.set(uri, prefix);
    } else if (type === RES.XML_START_ELEMENT) {
      if (++nodes > AXML_LIMITS.maxNodes) throw new ParseError('too many XML elements');
      if (stack.length >= AXML_LIMITS.maxDepth) throw new ParseError('XML nesting is too deep');
      const line = r.u32(off + 8);
      const ext = off + hsize;
      const ns = str(r.u32(ext));
      const tag = str(r.u32(ext + 4)) ?? '';
      const attrStart = r.u16(ext + 8);
      const attrSize = r.u16(ext + 10) || 20;
      const attrCount = r.u16(ext + 12);
      const attrs: XmlAttr[] = [];
      for (let i = 0; i < attrCount; i++) {
        const a = ext + attrStart + i * attrSize;
        if (a + 20 > off + size) break;
        const ans = str(r.u32(a));
        const nameIdx = r.u32(a + 4);
        const rawIdx = r.u32(a + 8);
        const vtype = r.u8(a + 15);
        const vdata = r.u32(a + 16);
        const resId = nameIdx < resourceIds.length ? resourceIds[nameIdx] : undefined;
        let name = str(nameIdx) ?? '';
        if ((!name || /^[^a-zA-Z]/.test(name)) && resId !== undefined && ANDROID_ATTR_IDS[resId]) name = ANDROID_ATTR_IDS[resId] as string;
        const raw = str(rawIdx);
        const value = { type: vtype, data: vdata };
        const at: XmlAttr = { name, value, text: formatValue(value, strings, raw) };
        if (ans) at.ns = ans;
        if (resId !== undefined) at.resId = resId;
        if (raw !== undefined) at.raw = raw;
        attrs.push(at);
      }
      const node: XmlNode = { tag, attrs, children: [], line, offset: off };
      if (ns) node.ns = ns;
      const parent = stack[stack.length - 1];
      if (parent) parent.children.push(node); else if (!root) root = node;
      stack.push(node);
    } else if (type === RES.XML_END_ELEMENT) {
      stack.pop();
    } else if (type === RES.XML_CDATA) {
      const t = str(r.u32(off + hsize));
      const parent = stack[stack.length - 1];
      if (parent && t !== undefined) parent.text = (parent.text ?? '') + t;
    }
    off += size;
  }
  void nsPrefix;
  return { root, strings, resourceIds, namespaces };
}

/** Get an attribute's text by local name, android namespace preferred. */
export function attr(node: XmlNode, name: string): string | undefined {
  let fallback: string | undefined;
  for (const a of node.attrs) {
    if (a.name !== name) continue;
    if (a.ns === 'http://schemas.android.com/apk/res/android') return a.text;
    fallback ??= a.text;
  }
  return fallback;
}

export function attrValue(node: XmlNode, name: string): ResValue | undefined {
  return node.attrs.find((a) => a.name === name)?.value;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Render a decoded AXML tree back to readable XML text. */
export function axmlToXml(doc: AxmlDocument, maxChars = 4 * 1024 * 1024): string {
  const prefixFor = new Map<string, string>();
  for (const [p, u] of Object.entries(doc.namespaces)) prefixFor.set(u, p);
  const out: string[] = ['<?xml version="1.0" encoding="utf-8"?>'];
  let len = 0;
  const walk = (n: XmlNode, depth: number, isRoot: boolean): void => {
    if (len > maxChars) return;
    const pad = '  '.repeat(depth);
    const parts = [`${pad}<${n.tag}`];
    if (isRoot) for (const [p, u] of Object.entries(doc.namespaces)) parts.push(` xmlns:${p}="${esc(u)}"`);
    for (const a of n.attrs) {
      const p = a.ns ? prefixFor.get(a.ns) : undefined;
      parts.push(` ${p ? `${p}:` : ''}${a.name}="${esc(a.text)}"`);
    }
    if (n.children.length === 0 && !n.text) { parts.push(' />'); out.push(parts.join('')); len += parts.join('').length; return; }
    parts.push('>');
    out.push(parts.join(''));
    if (n.text) out.push(`${pad}  ${esc(n.text)}`);
    for (const c of n.children) walk(c, depth + 1, false);
    out.push(`${pad}</${n.tag}>`);
  };
  if (doc.root) walk(doc.root, 0, true);
  return out.join('\n');
}

// ---------------------------------------------------------------- resources.arsc

export interface ResEntry { id: number; type: string; key: string; value?: ResValue; text?: string; complex: boolean; config: string }

export interface ResourceTable {
  packages: { id: number; name: string; typeCount: number; entryCount: number }[];
  globalStrings: string[];
  /** first value seen for every resource id (default config wins when present) */
  entries: Map<number, ResEntry>;
  /** all values per id across configs, capped */
  byId: Map<number, ResEntry[]>;
}

function configString(r: Buf, off: number, size: number): string {
  if (size < 8) return 'default';
  const lang = r.u8(off + 8) ? String.fromCharCode(r.u8(off + 8), r.u8(off + 9)) : '';
  const country = size >= 12 && r.u8(off + 10) ? String.fromCharCode(r.u8(off + 10), r.u8(off + 11)) : '';
  const density = size >= 16 ? r.u16(off + 14) : 0;
  const sdk = size >= 28 ? r.u16(off + 24) : 0;
  const nightBits = size >= 32 ? (r.u8(off + 29) & 0x30) : 0;
  const parts: string[] = [];
  if (lang) parts.push(country ? `${lang}-r${country}` : lang);
  if (nightBits === 0x20) parts.push('night');
  if (density) parts.push(density === 0xffff ? 'nodpi' : density === 0xfffe ? 'anydpi' : `${density}dpi`);
  if (sdk) parts.push(`v${sdk}`);
  return parts.length ? parts.join('-') : 'default';
}

/** Parse resources.arsc enough to resolve ids to type, key and simple values. */
export function parseResourceTable(bytes: Uint8Array, maxEntries = 400_000): ResourceTable {
  const r = new Buf(bytes);
  if (bytes.length < 12 || r.u16(0) !== RES.TABLE) throw new ParseError('not a resources.arsc table');
  const out: ResourceTable = { packages: [], globalStrings: [], entries: new Map(), byId: new Map() };
  let off = r.u16(2);
  const end = Math.min(bytes.length, r.u32(4));
  let count = 0;
  while (off + 8 <= end) {
    const type = r.u16(off);
    const size = r.u32(off + 4);
    if (size < 8 || off + size > bytes.length) break;
    if (type === RES.STRING_POOL) out.globalStrings = parseStringPool(r, off).strings;
    else if (type === RES.TABLE_PACKAGE) {
      const pid = r.u32(off + 8);
      const name = utf16le(r.slice(off + 12, 256)).replace(/\0.*$/s, '');
      const typeStringsOff = r.u32(off + 268);
      const keyStringsOff = r.u32(off + 276);
      const typeNames = typeStringsOff ? parseStringPool(r, off + typeStringsOff).strings : [];
      const keyNames = keyStringsOff ? parseStringPool(r, off + keyStringsOff).strings : [];
      let p = off + r.u16(off + 2);
      const pend = off + size;
      let typeCount = 0, entryCount = 0;
      while (p + 8 <= pend) {
        const ct = r.u16(p);
        const chs = r.u16(p + 2);
        const cs = r.u32(p + 4);
        if (cs < 8 || p + cs > pend) break;
        if (ct === RES.TABLE_TYPE) {
          typeCount++;
          const tid = r.u8(p + 8);
          const flags = r.u8(p + 9);
          const n = r.u32(p + 12);
          const entriesStart = r.u32(p + 16);
          const cfgSize = r.u32(p + 20);
          const cfg = configString(r, p + 20, cfgSize);
          const tname = typeNames[tid - 1] ?? `type${tid}`;
          const sparse = (flags & 0x01) !== 0;
          const off16 = (flags & 0x02) !== 0;
          for (let i = 0; i < n && count < maxEntries; i++) {
            let idx = i;
            let eoff: number;
            if (sparse) {
              idx = r.u16(p + chs + i * 4);
              eoff = r.u16(p + chs + i * 4 + 2) * 4;
            } else if (off16) {
              const v = r.u16(p + chs + i * 2);
              if (v === 0xffff) continue;
              eoff = v * 4;
            } else {
              eoff = r.u32(p + chs + i * 4);
              if (eoff === 0xffffffff) continue;
            }
            const e = p + entriesStart + eoff;
            if (!r.has(e, 8)) continue;
            const id = ((pid & 0xff) << 24) | (tid << 16) | idx;
            const eflags = r.u16(e + 2);
            let entry: ResEntry;
            if (eflags & 0x08) {
              // compact entry: key index in first u16, data type in high byte of flags
              const key = keyNames[r.u16(e)] ?? '';
              const value = { type: (eflags >> 8) & 0xff, data: r.u32(e + 4) };
              entry = { id: id >>> 0, type: tname, key, value, text: formatValue(value, out.globalStrings), complex: false, config: cfg };
            } else {
              const esize = r.u16(e);
              const key = keyNames[r.u32(e + 4)] ?? '';
              const complex = (eflags & 0x01) !== 0;
              entry = { id: id >>> 0, type: tname, key, complex, config: cfg };
              if (!complex && r.has(e + esize, 8)) {
                entry.value = { type: r.u8(e + esize + 3), data: r.u32(e + esize + 4) };
                entry.text = formatValue(entry.value, out.globalStrings);
              }
            }
            count++;
            entryCount++;
            const list = out.byId.get(entry.id);
            if (list) { if (list.length < 64) list.push(entry); } else out.byId.set(entry.id, [entry]);
            const prev = out.entries.get(entry.id);
            if (!prev || (prev.config !== 'default' && cfg === 'default')) out.entries.set(entry.id, entry);
          }
        }
        p += cs;
      }
      out.packages.push({ id: pid, name, typeCount, entryCount });
    }
    off += size;
  }
  return out;
}

/** Resolve "@0x7f..." style text through the table, following references a few levels. */
export function resolveRef(table: ResourceTable | undefined, text: string, depth = 0): string {
  if (!table || depth > 8 || !text.startsWith('@0x')) return text;
  const id = parseInt(text.slice(3), 16) >>> 0;
  const e = table.entries.get(id);
  if (!e) return text;
  if (e.text !== undefined && e.value?.type === 0x01) return resolveRef(table, e.text, depth + 1);
  if (e.text !== undefined) return e.text;
  return `@${e.type}/${e.key}`;
}

/** Name of a resource id, like @string/app_name. */
export function resourceName(table: ResourceTable | undefined, text: string): string | undefined {
  if (!table || !text.startsWith('@0x')) return undefined;
  const e = table.entries.get(parseInt(text.slice(3), 16) >>> 0);
  return e ? `@${e.type}/${e.key}` : undefined;
}
