// GVariant serialized-format decoder (the normal form GLib writes into GVDB files such as the
// dconf database) and a printer that writes the same text as g_variant_print. Pure TS, written
// from the GVariant serialization specification (Ryan Lortie, "GVariant Serialization", 2010) and
// the behaviour of g_variant_print. No Node imports. Depth, count and size are capped.
import { InputError } from './proc.js';

export interface GType { t: string; s: string; align: number; fixed: number | undefined; el?: GType; members?: GType[] }
/** A decoded value: its type string and a JSON-friendly value (bigint-free; 64-bit numbers as strings when unsafe). */
export interface GVar { type: string; value: unknown; children?: GVar[]; nothing?: boolean }

const BASIC_FIXED: Record<string, [number, number]> = { b: [1, 1], y: [1, 1], n: [2, 2], q: [2, 2], i: [4, 4], u: [4, 4], h: [4, 4], x: [8, 8], t: [8, 8], d: [8, 8] };

/** Parse one complete type string ("a{sv}", "(ias)", "mi" ...) into a type tree with alignment and fixed size. */
export function parseGType(s: string): GType {
  if (s.length > 255) throw new InputError('GVariant type string too long');
  const p = { i: 0 };
  const t = one(s, p, 0);
  if (p.i !== s.length) throw new InputError(`bad GVariant type string ${JSON.stringify(s.slice(0, 40))}`);
  return t;
}

function one(s: string, p: { i: number }, depth: number): GType {
  if (depth > 64) throw new InputError('GVariant type nested too deep');
  const start = p.i;
  const c = s[p.i++];
  if (c === undefined) throw new InputError('truncated GVariant type string');
  if (c in BASIC_FIXED) { const [a, f] = BASIC_FIXED[c]!; return { t: c, s: c, align: a, fixed: f }; }
  if (c === 's' || c === 'o' || c === 'g') return { t: c, s: c, align: 1, fixed: undefined };
  if (c === 'v') return { t: 'v', s: 'v', align: 8, fixed: undefined };
  if (c === 'a' || c === 'm') { const el = one(s, p, depth + 1); return { t: c, s: s.slice(start, p.i), align: el.align, fixed: undefined, el }; }
  if (c === '(' || c === '{') {
    const close = c === '(' ? ')' : '}';
    const members: GType[] = [];
    while (s[p.i] !== close) { if (p.i >= s.length) throw new InputError('unterminated GVariant tuple type'); members.push(one(s, p, depth + 1)); if (members.length > 255) throw new InputError('too many tuple members'); }
    p.i++;
    if (c === '{' && (members.length !== 2 || !('bynqiuhxtdsog'.includes(members[0]!.t)))) throw new InputError('bad GVariant dict entry type');
    let align = 1, off = 0, fixed: number | undefined = 0;
    for (const m of members) { align = Math.max(align, m.align); if (fixed !== undefined && m.fixed !== undefined) { off = alignUp(off, m.align) + m.fixed; } else fixed = undefined; }
    if (fixed !== undefined) fixed = members.length === 0 ? 1 : alignUp(off, align);
    return { t: c, s: s.slice(start, p.i), align, fixed, members };
  }
  throw new InputError(`unknown GVariant type character ${JSON.stringify(c)}`);
}

const alignUp = (n: number, a: number) => (n + a - 1) & ~(a - 1);
const offsetSize = (n: number) => (n <= 0xff ? 1 : n <= 0xffff ? 2 : n <= 0xffffffff ? 4 : 8);

interface Ctx { le: boolean; nodes: number; maxNodes: number }

function readOffset(b: Uint8Array, at: number, size: number, le: boolean): number {
  let v = 0;
  for (let k = 0; k < size; k++) v += b[at + (le ? k : size - 1 - k)]! * 2 ** (8 * k);
  return v;
}

/** Decode serialized GVariant bytes of a known type. littleEndian defaults to true (GVDB files say which). */
export function decodeGVariant(type: string | GType, b: Uint8Array, opts: { littleEndian?: boolean; maxNodes?: number } = {}): GVar {
  const t = typeof type === 'string' ? parseGType(type) : type;
  return dec(t, b, { le: opts.littleEndian !== false, nodes: 0, maxNodes: Math.max(1, Math.min(opts.maxNodes ?? 1_000_000, 10_000_000)) }, 0);
}

function dec(t: GType, b: Uint8Array, c: Ctx, depth: number): GVar {
  if (depth > 128) throw new InputError('GVariant value nested too deep');
  if (++c.nodes > c.maxNodes) throw new InputError('GVariant value has too many parts');
  // a fixed-size value of the wrong size reads as the default value (the spec's rule for bad data)
  if (t.fixed !== undefined && b.length !== t.fixed) b = new Uint8Array(t.fixed);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  switch (t.t) {
    case 'b': return { type: 'b', value: b[0] !== 0 };
    case 'y': return { type: 'y', value: b[0]! };
    case 'n': return { type: 'n', value: dv.getInt16(0, c.le) };
    case 'q': return { type: 'q', value: dv.getUint16(0, c.le) };
    case 'i': return { type: 'i', value: dv.getInt32(0, c.le) };
    case 'h': return { type: 'h', value: dv.getInt32(0, c.le) };
    case 'u': return { type: 'u', value: dv.getUint32(0, c.le) };
    case 'x': { const v = dv.getBigInt64(0, c.le); return { type: 'x', value: big(v) }; }
    case 't': { const v = dv.getBigUint64(0, c.le); return { type: 't', value: big(v) }; }
    case 'd': return { type: 'd', value: dv.getFloat64(0, c.le) };
    case 's': case 'o': case 'g': {
      // string bytes then one nul; anything else is invalid and reads as the empty string
      const ok = b.length > 0 && b[b.length - 1] === 0 && b.indexOf(0) === b.length - 1;
      return { type: t.t, value: ok ? new TextDecoder('utf-8', { fatal: false }).decode(b.subarray(0, b.length - 1)) : '' };
    }
    case 'v': {
      const z = b.lastIndexOf(0);
      if (z < 0) return { type: 'v', value: undefined, children: [{ type: '()', value: [], children: [] }] };
      const ts = String.fromCharCode(...b.subarray(z + 1, z + 1 + 256));
      let inner: GType;
      try { inner = parseGType(ts); } catch { return { type: 'v', value: undefined, children: [{ type: '()', value: [], children: [] }] }; }
      const child = dec(inner, b.subarray(0, z), c, depth + 1);
      return { type: 'v', value: child.value, children: [child] };
    }
    case 'm': {
      const el = t.el!;
      if (b.length === 0) return { type: t.s, value: null, nothing: true, children: [] };
      if (el.fixed !== undefined) { if (b.length !== el.fixed) return { type: t.s, value: null, nothing: true, children: [] }; const ch = dec(el, b, c, depth + 1); return { type: t.s, value: ch.value, children: [ch] }; }
      const ch = dec(el, b.subarray(0, b.length - 1), c, depth + 1);
      return { type: t.s, value: ch.value, children: [ch] };
    }
    case 'a': {
      const el = t.el!;
      const kids: GVar[] = [];
      if (el.fixed !== undefined) {
        if (b.length % el.fixed !== 0) return arr(t, []);
        for (let o = 0; o < b.length; o += el.fixed) kids.push(dec(el, b.subarray(o, o + el.fixed), c, depth + 1));
        return arr(t, kids);
      }
      if (b.length === 0) return arr(t, []);
      const os = offsetSize(b.length);
      if (b.length < os) return arr(t, []);
      const last = readOffset(b, b.length - os, os, c.le);
      if (last > b.length || (b.length - last) % os !== 0) return arr(t, []);
      const n = (b.length - last) / os;
      let prev = 0;
      for (let k = 0; k < n; k++) {
        const end = readOffset(b, last + k * os, os, c.le);
        const start = alignUp(prev, el.align);
        if (end < start || end > last) return arr(t, kids); // malformed: stop at the bad frame
        kids.push(dec(el, b.subarray(start, end), c, depth + 1));
        prev = end;
      }
      return arr(t, kids);
    }
    case '(': case '{': {
      const ms = t.members!;
      const kids: GVar[] = [];
      const os = offsetSize(b.length);
      let pos = 0, frameEnd = b.length; // framing offsets are read from the end, first one last
      for (let k = 0; k < ms.length; k++) {
        const m = ms[k]!;
        pos = alignUp(pos, m.align);
        let end: number;
        if (m.fixed !== undefined) end = pos + m.fixed;
        else if (k === ms.length - 1) end = frameEnd;
        else { frameEnd -= os; if (frameEnd < 0) throw new InputError('GVariant tuple framing runs past the value'); end = readOffset(b, frameEnd, os, c.le); }
        if (end < pos || end > b.length) { kids.push(dec(m, new Uint8Array(0), c, depth + 1)); pos = Math.min(b.length, Math.max(pos, end)); continue; }
        kids.push(dec(m, b.subarray(pos, end), c, depth + 1));
        pos = end;
      }
      return { type: t.s, value: kids.map((x) => x.value), children: kids };
    }
  }
  throw new InputError(`cannot decode GVariant type ${t.s}`);
}

const big = (v: bigint) => (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString());

function arr(t: GType, kids: GVar[]): GVar {
  if (t.el!.t === '{') {
    const obj: Record<string, unknown> = {};
    for (const k of kids) obj[String((k.children![0]!).value)] = k.children![1]!.value;
    return { type: t.s, value: obj, children: kids };
  }
  return { type: t.s, value: kids.map((k) => k.value), children: kids };
}

// ---------------- printing (g_variant_print) ----------------

const NONPRINT = /[\p{Cc}\p{Cf}\p{Cn}\p{Cs}]/u;

function quoteString(s: string): string {
  const q = s.includes("'") ? '"' : "'";
  let out = q;
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === q || ch === '\\') out += '\\';
    if (!NONPRINT.test(ch)) { out += ch; continue; }
    out += '\\';
    const named: Record<number, string> = { 7: 'a', 8: 'b', 12: 'f', 10: 'n', 13: 'r', 9: 't', 11: 'v' };
    out += c < 0x10000 ? (named[c] ?? `u${c.toString(16).padStart(4, '0')}`) : `U${c.toString(16).padStart(8, '0')}`;
  }
  return out + q;
}

/** C printf "%.17g", which g_ascii_dtostr uses. */
export function formatG17(d: number): string {
  if (Number.isNaN(d)) return 'nan';
  if (!Number.isFinite(d)) return d > 0 ? 'inf' : '-inf';
  if (d === 0) return Object.is(d, -0) ? '-0' : '0';
  const [m0, x0] = d.toExponential(16).split('e') as [string, string];
  const e = Number(x0);
  if (e < -4 || e >= 17) {
    const m = m0.includes('.') ? m0.replace(/0+$/, '').replace(/\.$/, '') : m0;
    return `${m}e${e < 0 ? '-' : '+'}${String(Math.abs(e)).padStart(2, '0')}`;
  }
  let f = d.toFixed(16 - e);
  if (f.includes('.')) f = f.replace(/0+$/, '').replace(/\.$/, '');
  return f;
}

function isMaybeChain(t: string): number { let n = 0; while (t[n] === 'm') n++; return n; }

/** Print a decoded value the way g_variant_print(value, typeAnnotate) does. */
export function printGVariant(v: GVar, annotate = true): string {
  const t = v.type;
  switch (t[0]) {
    case 'm': {
      let out = annotate ? `@${t} ` : '';
      if (v.nothing) return out + 'nothing';
      const depth = isMaybeChain(t);
      let el: GVar | undefined = v, i = 0;
      for (; i < depth && el; i++) el = el.nothing ? undefined : el.children?.[0];
      if (!el) { for (; i > 1; i--) out += 'just '; return out + 'nothing'; }
      return out + printGVariant(el, false);
    }
    case 'a': {
      const kids = v.children ?? [];
      if (t[1] === 'y') {
        const bytes = kids.map((k) => k.value as number);
        const z = bytes.indexOf(0);
        if (bytes.length > 0 && z === bytes.length - 1) {
          const str = bytes.slice(0, -1);
          const esc = strescape(str);
          return str.includes(39) ? `b"${esc}"` : `b'${esc}'`;
        }
      }
      if (!kids.length) return (annotate ? `@${t} ` : '') + (t[1] === '{' ? '{}' : '[]');
      let a = annotate;
      if (t[1] === '{') {
        const parts = kids.map((e) => { const s = `${printGVariant(e.children![0]!, a)}: ${printGVariant(e.children![1]!, a)}`; a = false; return s; });
        return `{${parts.join(', ')}}`;
      }
      const parts = kids.map((e) => { const s = printGVariant(e, a); a = false; return s; });
      return `[${parts.join(', ')}]`;
    }
    case '(': {
      const kids = v.children ?? [];
      const parts = kids.map((k) => printGVariant(k, annotate));
      return kids.length === 1 ? `(${parts[0]},)` : `(${parts.join(', ')})`;
    }
    case '{': return `{${printGVariant(v.children![0]!, annotate)}, ${printGVariant(v.children![1]!, annotate)}}`;
    case 'v': return `<${printGVariant(v.children![0]!, true)}>`;
    case 'b': return v.value ? 'true' : 'false';
    case 's': return quoteString(String(v.value));
    case 'y': return (annotate ? 'byte ' : '') + `0x${(v.value as number).toString(16).padStart(2, '0')}`;
    case 'n': return (annotate ? 'int16 ' : '') + String(v.value);
    case 'q': return (annotate ? 'uint16 ' : '') + String(v.value);
    case 'i': return String(v.value);
    case 'h': return (annotate ? 'handle ' : '') + String(v.value);
    case 'u': return (annotate ? 'uint32 ' : '') + String(v.value);
    case 'x': return (annotate ? 'int64 ' : '') + String(v.value);
    case 't': return (annotate ? 'uint64 ' : '') + String(v.value);
    case 'd': { const s = formatG17(v.value as number); return /[.enN]/.test(s) ? s : s + '.0'; }
    case 'o': return (annotate ? 'objectpath ' : '') + `'${v.value}'`;
    case 'g': return (annotate ? 'signature ' : '') + `'${v.value}'`;
  }
  return '?';
}

/** g_strescape on bytes: escapes \b \f \n \r \t \v \\ and \", and non-printable bytes as octal. */
function strescape(bytes: number[]): string {
  let out = '';
  for (const c of bytes) {
    const named: Record<number, string> = { 8: '\\b', 12: '\\f', 10: '\\n', 13: '\\r', 9: '\\t', 11: '\\v', 92: '\\\\', 34: '\\"' };
    if (named[c]) out += named[c];
    else if (c < 0x20 || c >= 0x7f) out += '\\' + c.toString(8).padStart(3, '0');
    else out += String.fromCharCode(c);
  }
  return out;
}
