// Parser for the GVariant text format that `gdbus call` prints, used to read AT-SPI replies.
// Handles tuples, arrays, dicts, variants, strings, object paths, numbers, booleans and type
// annotations. No Node imports. Depth and size capped.
import { InputError } from './proc.js';

export type GValue = string | number | boolean | null | GValue[] | { [k: string]: GValue };

const TYPE_WORDS = new Set(['int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64', 'byte', 'double', 'objectpath', 'signature', 'handle', 'boolean', 'string']);

/** Parse one GVariant text value such as `([(':1.2', objectpath '/a')],)`. */
export function parseGVariant(text: string): GValue {
  if (text.length > 16 * 1024 * 1024) throw new InputError('GVariant text too large');
  let i = 0;
  const ws = () => { while (i < text.length && /\s/.test(text[i]!)) i++; };
  const value = (depth: number): GValue => {
    if (depth > 200) throw new InputError('GVariant nesting too deep');
    ws();
    const c = text[i];
    if (c === undefined) throw new InputError('unexpected end of GVariant');
    if (c === '@') { // @a(so) type annotation
      i++;
      let d = 0;
      while (i < text.length) { const ch = text[i]!; if (ch === '(' || ch === '{') d++; else if (ch === ')' || ch === '}') d--; else if (d === 0 && /\s/.test(ch)) break; i++; }
      return value(depth + 1);
    }
    if (c === '(' || c === '[') {
      const close = c === '(' ? ')' : ']';
      i++;
      const out: GValue[] = [];
      for (;;) {
        ws();
        if (text[i] === close) { i++; return out; }
        if (out.length > 1_000_000) throw new InputError('GVariant container too large');
        out.push(value(depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === close) { i++; return out; }
        throw new InputError(`expected , or ${close} at ${i}`);
      }
    }
    if (c === '{') {
      i++;
      const out: Record<string, GValue> = {};
      for (;;) {
        ws();
        if (text[i] === '}') { i++; return out; }
        const k = value(depth + 1); ws();
        if (text[i] !== ':') throw new InputError(`expected : at ${i}`);
        i++;
        Object.defineProperty(out, String(k), { value: value(depth + 1), enumerable: true, writable: true, configurable: true }); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return out; }
        throw new InputError(`expected , or } at ${i}`);
      }
    }
    if (c === '<') { i++; const v = value(depth + 1); ws(); if (text[i] !== '>') throw new InputError(`expected > at ${i}`); i++; return v; }
    if (c === "'" || c === '"' || (c === 'b' && (text[i + 1] === "'" || text[i + 1] === '"'))) {
      if (c === 'b') i++;
      const q = text[i]!; i++;
      let s = '';
      while (i < text.length && text[i] !== q) {
        if (text[i] === '\\' && i + 1 < text.length) {
          const n = text[i + 1]!;
          if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) { s += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 6; continue; }
          s += ({ n: '\n', t: '\t', r: '\r' } as Record<string, string>)[n] ?? n; i += 2; continue;
        }
        s += text[i++];
      }
      if (text[i] !== q) throw new InputError('unterminated GVariant string');
      i++;
      return s;
    }
    const w = /^[A-Za-z_][\w]*/.exec(text.slice(i, i + 32));
    if (w) {
      const word = w[0];
      if (TYPE_WORDS.has(word)) { i += word.length; return value(depth + 1); }
      if (word === 'true') { i += 4; return true; }
      if (word === 'false') { i += 5; return false; }
      if (word === 'nothing') { i += 7; return null; }
      if (word === 'just') { i += 4; return value(depth + 1); }
    }
    const num = /^[-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?|inf|nan)/.exec(text.slice(i, i + 64));
    if (num) { i += num[0].length; return Number(num[0]); }
    throw new InputError(`unexpected GVariant text at ${i}: ${text.slice(i, i + 20)}`);
  };
  const v = value(0);
  return v;
}

/** Unwrap a one-element reply tuple: `('x',)` gives 'x'. */
export function replyValue(text: string): GValue {
  const v = parseGVariant(text.trim());
  return Array.isArray(v) && v.length === 1 ? v[0]! : v;
}

/** Read AT-SPI GetChildren replies: a list of [busName, objectPath]. */
export function parseAccessibleRefs(text: string): { bus: string; path: string }[] {
  const v = replyValue(text);
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is GValue[] => Array.isArray(x) && x.length === 2).map((x) => ({ bus: String(x[0]), path: String(x[1]) })).slice(0, 100_000);
}

export interface UiNode { id: number; parent: number | null; depth: number; role: string; name: string; description?: string; value?: string; automationId?: string; className?: string; bounds?: { x: number; y: number; width: number; height: number }; states?: string[]; ref?: string; childCount?: number }
