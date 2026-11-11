// Erlang BEAM file reader: IFF chunks, atoms, exports, imports, locals, attributes and compile info.
import { unzlibSync } from 'fflate';
import { ByteReader, ParseError, LIMITS, latin1, utf8 } from '../util.js';

export interface BeamChunk { id: string; offset: number; size: number }
export interface BeamFunction { name: string; arity: number; label: number }
export interface BeamImport { module: string; name: string; arity: number }

export interface BeamFile {
  module: string;
  chunks: BeamChunk[];
  atoms: string[];
  exports: BeamFunction[];
  imports: BeamImport[];
  locals: BeamFunction[];
  code?: { instructionSet: number; maxOpcode: number; labels: number; functions: number; codeSize: number };
  attributes?: unknown;
  compileInfo?: unknown;
  literals?: { count: number; sample: unknown[] };
  strings?: number;
  hasDebugInfo: boolean;
  hasDocs: boolean;
  elixir: boolean;
}

export function isBeam(b: Uint8Array): boolean {
  return b.length >= 12 && latin1(b.subarray(0, 4)) === 'FOR1' && latin1(b.subarray(8, 12)) === 'BEAM';
}

function compactInt(r: ByteReader): number {
  // BEAM compact term encoding, used for atom lengths in OTP 28 AtU8 chunks.
  const b = r.u8();
  if ((b & 0x08) === 0) return b >> 4;
  if ((b & 0x10) === 0) return ((b & 0xe0) << 3) | r.u8();
  const n = (b >> 5) + 2;
  if (n > 7) throw new ParseError('compact integer too large', r.pos);
  let v = 0;
  for (let i = 0; i < n; i++) v = v * 256 + r.u8();
  return v;
}

/** Parse a .beam file. */
export function parseBeam(bytes: Uint8Array): BeamFile {
  if (!isBeam(bytes)) throw new ParseError('not a BEAM file (expected FOR1 ... BEAM)');
  const r = new ByteReader(bytes, 4, false);
  const formSize = r.u32();
  const end = Math.min(bytes.length, 8 + formSize);
  r.seek(12);
  const chunks: BeamChunk[] = [];
  while (r.pos + 8 <= end && chunks.length < 256) {
    const id = latin1(r.take(4));
    const size = r.u32();
    const offset = r.pos;
    if (offset + size > bytes.length) throw new ParseError(`chunk ${id} past end`, offset - 8);
    chunks.push({ id, offset, size });
    r.seek(Math.min(bytes.length, offset + ((size + 3) & ~3)));
  }
  const get = (id: string) => chunks.find((c) => c.id === id);
  const sub = (c: BeamChunk) => new ByteReader(bytes.subarray(c.offset, c.offset + c.size), 0, false);

  const atoms: string[] = [];
  const atomChunk = get('AtU8') ?? get('Atom');
  if (!atomChunk) throw new ParseError('BEAM file has no atom table');
  {
    const a = sub(atomChunk);
    let n = a.i32();
    const compact = n < 0;
    if (compact) n = -n;
    if (n > LIMITS.maxEntries * 10) throw new ParseError('too many atoms');
    for (let i = 0; i < n; i++) {
      const len = compact ? compactInt(a) : a.u8();
      const b = a.take(len);
      atoms.push(atomChunk.id === 'AtU8' ? utf8(b) : latin1(b));
    }
  }
  const atom = (i: number) => atoms[i - 1] ?? `<atom ${i}>`;
  const fnTable = (id: string): BeamFunction[] => {
    const c = get(id); if (!c) return [];
    const t = sub(c); const n = t.u32();
    if (n > c.size / 12) throw new ParseError(`${id} count too large`);
    const out: BeamFunction[] = [];
    for (let i = 0; i < n; i++) out.push({ name: atom(t.u32()), arity: t.u32(), label: t.u32() });
    return out;
  };
  const imports: BeamImport[] = [];
  const imp = get('ImpT');
  if (imp) {
    const t = sub(imp); const n = t.u32();
    if (n > imp.size / 12) throw new ParseError('ImpT count too large');
    for (let i = 0; i < n; i++) imports.push({ module: atom(t.u32()), name: atom(t.u32()), arity: t.u32() });
  }
  const file: BeamFile = {
    module: atoms[0] ?? '', chunks, atoms, exports: fnTable('ExpT'), imports, locals: fnTable('LocT'),
    hasDebugInfo: !!(get('Dbgi') ?? get('Abst')), hasDocs: !!get('Docs'), elixir: !!get('ExCk') || (atoms[0] ?? '').startsWith('Elixir.'),
  };
  const code = get('Code');
  if (code && code.size >= 20) {
    const t = sub(code);
    const headerSize = t.u32();
    file.code = { instructionSet: t.u32(), maxOpcode: t.u32(), labels: t.u32(), functions: t.u32(), codeSize: code.size - 4 - headerSize };
  }
  const str = get('StrT'); if (str) file.strings = str.size;
  const decodeEtf = (c: BeamChunk) => { try { return etf(bytes.subarray(c.offset, c.offset + c.size)); } catch (e) { return { error: e instanceof Error ? e.message : String(e) }; } };
  const attr = get('Attr'); if (attr) file.attributes = decodeEtf(attr);
  const cinf = get('CInf'); if (cinf) file.compileInfo = decodeEtf(cinf);
  const lit = get('LitT');
  if (lit && lit.size > 4) {
    try {
      const t = sub(lit);
      const usize = t.u32();
      if (usize > 64 * 1024 * 1024) throw new ParseError('literal table too large');
      const raw = usize === 0 ? bytes.subarray(lit.offset + 4, lit.offset + lit.size) : unzlibSync(bytes.subarray(lit.offset + 4, lit.offset + lit.size), { out: new Uint8Array(usize) });
      const lr = new ByteReader(raw, 0, false);
      const n = lr.u32();
      const sample: unknown[] = [];
      for (let i = 0; i < n && i < 20; i++) { const sz = lr.u32(); sample.push(etf(lr.take(sz))); }
      file.literals = { count: n, sample };
    } catch (e) { file.literals = { count: -1, sample: [e instanceof Error ? e.message : String(e)] }; }
  }
  return file;
}

/** Decode Erlang external term format into JSON friendly values. Atoms become {atom}, tuples {tuple}. */
export function etf(b: Uint8Array): unknown {
  const r = new ByteReader(b, 0, false);
  if (r.u8() !== 131) throw new ParseError('bad external term format version');
  let budget = 100000;
  const term = (depth: number): unknown => {
    if (depth > LIMITS.maxDepth || --budget < 0) throw new ParseError('term too deep or large');
    const tag = r.u8();
    switch (tag) {
      case 97: return r.u8();
      case 98: return r.i32();
      case 70: return r.f64();
      case 99: return Number(latin1(r.take(31)).replace(/\0.*$/s, ''));
      case 100: case 118: { const n = r.u16(); return { atom: utf8(r.take(n)) }; }
      case 115: case 119: { const n = r.u8(); return { atom: utf8(r.take(n)) }; }
      case 104: case 105: { const n = tag === 104 ? r.u8() : r.u32(); if (n > r.remaining()) throw new ParseError('tuple too large'); const items = []; for (let i = 0; i < n; i++) items.push(term(depth + 1)); return { tuple: items }; }
      case 106: return [];
      case 107: { const n = r.u16(); return latin1(r.take(n)); }
      case 108: {
        const n = r.u32(); if (n > r.remaining()) throw new ParseError('list too large');
        const items = []; for (let i = 0; i < n; i++) items.push(term(depth + 1));
        const tail = term(depth + 1);
        return Array.isArray(tail) && tail.length === 0 ? items : { improper: items, tail };
      }
      case 109: { const n = r.u32(); const d = r.take(n); return { binary: utf8(d.subarray(0, 256)), size: n }; }
      case 77: { const n = r.u32(); r.u8(); r.take(n); return { bitstring: n }; }
      case 110: case 111: {
        const n = tag === 110 ? r.u8() : r.u32(); const sign = r.u8();
        if (n > 1024) throw new ParseError('bignum too large');
        let v = 0n; const d = r.take(n);
        for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(d[i] as number);
        return (sign ? -v : v).toString();
      }
      case 116: { const n = r.u32(); if (n > r.remaining()) throw new ParseError('map too large'); const entries = []; for (let i = 0; i < n; i++) entries.push([term(depth + 1), term(depth + 1)]); return { map: entries }; }
      case 88: { term(depth + 1); r.skip(12); return { pid: true }; }
      case 90: { const n = r.u16(); term(depth + 1); r.skip(4 + 4 * n); return { ref: true }; }
      case 113: return { fun: [term(depth + 1), term(depth + 1), term(depth + 1)] };
      default: throw new ParseError(`unsupported term tag ${tag}`, r.pos - 1);
    }
  };
  return term(0);
}
