// Machine learning model files: GGUF (llama.cpp), safetensors and NumPy .npy headers.
// Reads metadata and the tensor table, checks that tensor data fits the file. No weights are loaded.

import { View, ParseError, utf8 } from '../util.js';

const GGML_TYPES: Record<number, { name: string; block: number; bytes: number }> = {
  0: { name: 'F32', block: 1, bytes: 4 }, 1: { name: 'F16', block: 1, bytes: 2 }, 2: { name: 'Q4_0', block: 32, bytes: 18 }, 3: { name: 'Q4_1', block: 32, bytes: 20 },
  6: { name: 'Q5_0', block: 32, bytes: 22 }, 7: { name: 'Q5_1', block: 32, bytes: 24 }, 8: { name: 'Q8_0', block: 32, bytes: 34 }, 9: { name: 'Q8_1', block: 32, bytes: 36 },
  10: { name: 'Q2_K', block: 256, bytes: 84 }, 11: { name: 'Q3_K', block: 256, bytes: 110 }, 12: { name: 'Q4_K', block: 256, bytes: 144 }, 13: { name: 'Q5_K', block: 256, bytes: 176 },
  14: { name: 'Q6_K', block: 256, bytes: 210 }, 15: { name: 'Q8_K', block: 256, bytes: 292 }, 16: { name: 'IQ2_XXS', block: 256, bytes: 66 }, 17: { name: 'IQ2_XS', block: 256, bytes: 74 },
  18: { name: 'IQ3_XXS', block: 256, bytes: 98 }, 19: { name: 'IQ1_S', block: 256, bytes: 50 }, 20: { name: 'IQ4_NL', block: 32, bytes: 18 }, 21: { name: 'IQ3_S', block: 256, bytes: 110 },
  22: { name: 'IQ2_S', block: 256, bytes: 82 }, 23: { name: 'IQ4_XS', block: 256, bytes: 136 }, 24: { name: 'I8', block: 1, bytes: 1 }, 25: { name: 'I16', block: 1, bytes: 2 },
  26: { name: 'I32', block: 1, bytes: 4 }, 27: { name: 'I64', block: 1, bytes: 8 }, 28: { name: 'F64', block: 1, bytes: 8 }, 29: { name: 'IQ1_M', block: 256, bytes: 56 },
  30: { name: 'BF16', block: 1, bytes: 2 }, 34: { name: 'TQ1_0', block: 256, bytes: 54 }, 35: { name: 'TQ2_0', block: 256, bytes: 66 }, 39: { name: 'MXFP4', block: 32, bytes: 17 },
};

export interface GgufTensor { name: string; shape: number[]; type: string; offset: number; fileOffset: number; bytes: number | null; inBounds: boolean | null }
export interface Gguf {
  format: 'gguf';
  version: number;
  tensorCount: number;
  metadataCount: number;
  metadata: Record<string, unknown>;
  architecture?: string;
  name?: string;
  alignment: number;
  dataOffset: number;
  tensors: GgufTensor[];
  tensorsTruncated: boolean;
  parameterCount: number;
  issues: string[];
}

const MAX_STR = 1 << 20;

/** Read a GGUF file header, metadata and tensor table. Arrays longer than `maxArray` are summarised. */
export function parseGguf(b: Uint8Array, opts: { maxTensors?: number; maxArray?: number } = {}): Gguf {
  const v = new View(b, true);
  if (b.length < 16 || v.u32(0) !== 0x46554747) throw new ParseError('GGUF magic not found', 0);
  const version = v.u32(4);
  if (version < 1 || version > 3) throw new ParseError(`unsupported GGUF version ${version}`, 4);
  const wide = version >= 2;
  let p = 8;
  const cnt = (): number => { const n = wide ? v.u64n(p) : v.u32(p); p += wide ? 8 : 4; return n; };
  const tensorCount = cnt();
  const kvCount = cnt();
  if (kvCount > 1_000_000 || tensorCount > 10_000_000) throw new ParseError('implausible GGUF counts', 8);
  const maxArray = opts.maxArray ?? 64;
  const str = (): string => { const n = cnt(); if (n > MAX_STR) throw new ParseError('GGUF string too long', p); const s = utf8(v.sub(p, n)); p += n; return s; };
  const scalar = (t: number): unknown => {
    switch (t) {
      case 0: return v.u8(p++);
      case 1: { const x = v.u8(p++); return x > 127 ? x - 256 : x; }
      case 2: { const x = v.u16(p); p += 2; return x; }
      case 3: { const x = v.i16(p); p += 2; return x; }
      case 4: { const x = v.u32(p); p += 4; return x; }
      case 5: { const x = v.i32(p); p += 4; return x; }
      case 6: { v.need(p, 4); const x = v.dv.getFloat32(p, true); p += 4; return Math.round(x * 1e7) / 1e7; }
      case 7: return v.u8(p++) !== 0;
      case 8: return str();
      case 10: { const x = v.u64(p); p += 8; return x <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(x) : x.toString(); }
      case 11: { v.need(p, 8); const x = v.dv.getBigInt64(p, true); p += 8; return Number(x); }
      case 12: { v.need(p, 8); const x = v.dv.getFloat64(p, true); p += 8; return x; }
      default: throw new ParseError(`unknown GGUF value type ${t}`, p);
    }
  };
  const value = (t: number, depth: number): unknown => {
    if (t !== 9) return scalar(t);
    if (depth > 4) throw new ParseError('GGUF arrays nested too deep', p);
    const it = v.u32(p); p += 4;
    const n = cnt();
    if (n > 50_000_000) throw new ParseError('GGUF array too long', p);
    const keep: unknown[] = [];
    for (let i = 0; i < n; i++) { const x = value(it, depth + 1); if (i < maxArray) keep.push(x); }
    return n <= maxArray ? keep : { type: it === 8 ? 'string' : `type-${it}`, length: n, first: keep };
  };
  const metadata: Record<string, unknown> = {};
  for (let i = 0; i < kvCount; i++) { const k = str(); const t = v.u32(p); p += 4; metadata[k] = value(t, 0); }
  const alignment = typeof metadata['general.alignment'] === 'number' ? (metadata['general.alignment'] as number) : 32;
  const issues: string[] = [];
  if (alignment <= 0 || alignment > 1 << 20 || (alignment & (alignment - 1))) issues.push(`alignment ${alignment} is not a power of two`);
  const maxT = opts.maxTensors ?? 5000;
  const raw: { name: string; shape: number[]; type: number; offset: number }[] = [];
  for (let i = 0; i < tensorCount; i++) {
    const name = str();
    const nd = v.u32(p); p += 4;
    if (nd > 8) throw new ParseError(`tensor ${name} has ${nd} dimensions`, p);
    const shape: number[] = [];
    for (let d = 0; d < nd; d++) shape.push(wide ? v.u64n(p + d * 8) : v.u32(p + d * 4));
    p += nd * (wide ? 8 : 4);
    const type = v.u32(p); p += 4;
    const offset = v.u64n(p); p += 8;
    raw.push({ name, shape, type, offset });
  }
  const al = alignment > 0 && alignment <= 1 << 20 ? alignment : 32;
  const dataOffset = Math.ceil(p / al) * al;
  let params = 0;
  const tensors: GgufTensor[] = [];
  for (const t of raw) {
    const n = t.shape.reduce((a, x) => a * x, 1);
    params += n;
    const tt = GGML_TYPES[t.type];
    const bytes = tt && n % tt.block === 0 ? (n / tt.block) * tt.bytes : null;
    const fileOffset = dataOffset + t.offset;
    const inBounds = bytes === null ? null : fileOffset + bytes <= b.length;
    if (inBounds === false) issues.push(`tensor ${t.name} data runs past end of file`);
    if (tensors.length < maxT) tensors.push({ name: t.name, shape: t.shape, type: tt?.name ?? `type-${t.type}`, offset: t.offset, fileOffset, bytes, inBounds });
  }
  return {
    format: 'gguf', version, tensorCount, metadataCount: kvCount, metadata, architecture: metadata['general.architecture'] as string | undefined,
    name: metadata['general.name'] as string | undefined, alignment, dataOffset, tensors, tensorsTruncated: raw.length > tensors.length, parameterCount: params, issues,
  };
}

const ST_DTYPES: Record<string, number> = { BOOL: 1, U8: 1, I8: 1, F8_E5M2: 1, F8_E4M3: 1, F8_E8M0: 1, I16: 2, U16: 2, F16: 2, BF16: 2, I32: 4, U32: 4, F32: 4, F64: 8, I64: 8, U64: 8, F4: 0.5 };

export interface Safetensors {
  format: 'safetensors';
  headerSize: number;
  metadata: Record<string, string>;
  tensors: { name: string; dtype: string; shape: number[]; start: number; end: number; fileOffset: number; sizeMatches: boolean | null }[];
  tensorsTruncated: boolean;
  parameterCount: number;
  issues: string[];
}

/** Read a safetensors header and check every tensor range against its dtype and shape. */
export function parseSafetensors(b: Uint8Array, opts: { maxTensors?: number } = {}): Safetensors {
  const v = new View(b, true);
  if (b.length < 10) throw new ParseError('too short for safetensors');
  const n = v.u64n(0);
  if (n < 2 || n > 100_000_000 || 8 + n > b.length) throw new ParseError('safetensors header size out of range', 0);
  if (b[8] !== 0x7b) throw new ParseError('safetensors header is not a JSON object', 8);
  let hdr: Record<string, unknown>;
  try { hdr = JSON.parse(utf8(v.sub(8, n))); } catch { throw new ParseError('safetensors header is not valid JSON', 8); }
  const dataStart = 8 + n;
  const issues: string[] = [];
  const meta = (hdr.__metadata__ ?? {}) as Record<string, string>;
  const all: Safetensors['tensors'] = [];
  let params = 0;
  for (const [name, x] of Object.entries(hdr)) {
    if (name === '__metadata__') continue;
    const t = x as { dtype?: string; shape?: number[]; data_offsets?: [number, number] };
    if (!t || typeof t.dtype !== 'string' || !Array.isArray(t.shape) || !Array.isArray(t.data_offsets)) { issues.push(`tensor ${name} has an invalid entry`); continue; }
    const [s, e] = t.data_offsets;
    const count = t.shape.reduce((a, d) => a * d, 1);
    params += count;
    const per = ST_DTYPES[t.dtype];
    const sizeMatches = per === undefined ? null : Math.ceil(count * per) === e - s;
    if (sizeMatches === false) issues.push(`tensor ${name} byte range does not match ${t.dtype} ${JSON.stringify(t.shape)}`);
    if (dataStart + e > b.length || s > e) issues.push(`tensor ${name} range is outside the file`);
    all.push({ name, dtype: t.dtype, shape: t.shape, start: s, end: e, fileOffset: dataStart + s, sizeMatches });
  }
  all.sort((a, c) => a.start - c.start);
  const max = opts.maxTensors ?? 5000;
  return { format: 'safetensors', headerSize: n, metadata: meta, tensors: all.slice(0, max), tensorsTruncated: all.length > max, parameterCount: params, issues };
}

export interface Npy { format: 'npy'; version: string; descr: string; fortranOrder: boolean; shape: number[]; dataOffset: number; header: string }

/** NumPy .npy header (versions 1 to 3). */
export function parseNpy(b: Uint8Array): Npy {
  const v = new View(b, true);
  if (b.length < 10 || b[0] !== 0x93 || utf8(b.subarray(1, 6)) !== 'NUMPY') throw new ParseError('NumPy magic not found', 0);
  const major = v.u8(6), minor = v.u8(7);
  const hl = major === 1 ? v.u16(8) : v.u32(8);
  const hs = major === 1 ? 10 : 12;
  const header = utf8(v.sub(hs, hl)).trim();
  const descr = header.match(/'descr'\s*:\s*'([^']{1,64})'/)?.[1] ?? '';
  const fortran = /'fortran_order'\s*:\s*True/.test(header);
  const shapeText = header.match(/'shape'\s*:\s*\(([^)]{0,512})\)/)?.[1] ?? '';
  const shape = shapeText.split(',').map((x) => x.trim()).filter(Boolean).map(Number);
  return { format: 'npy', version: `${major}.${minor}`, descr, fortranOrder: fortran, shape, dataOffset: hs + hl, header };
}

/** Detect and read any supported model file. */
export function inspectModel(b: Uint8Array, opts: { maxTensors?: number } = {}): Gguf | Safetensors | Npy | null {
  if (b.length >= 4 && b[0] === 0x47 && b[1] === 0x47 && b[2] === 0x55 && b[3] === 0x46) return parseGguf(b, opts);
  if (b.length >= 6 && b[0] === 0x93 && b[1] === 0x4e) return parseNpy(b);
  if (b.length >= 10 && b[8] === 0x7b) { try { return parseSafetensors(b, opts); } catch { return null; } }
  return null;
}
