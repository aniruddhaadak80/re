// Validates the JSON written by the RevLens Ghidra export script (schema revlens/ghidra-export@1).
import { bool, extractJson, num, str, PARSE_LIMITS } from './common.js';

export interface GhidraFunction {
  name: string;
  namespace?: string;
  address: string;
  size: number;
  signature?: string;
  thunk?: boolean;
  external?: boolean;
  callingConvention?: string;
  parameters?: number;
}

export interface GhidraDecompiled {
  function: GhidraFunction;
  ok: boolean;
  c?: string;
  error?: string;
}

export interface GhidraExport {
  schema: 'revlens/ghidra-export@1';
  program: string;
  language?: string;
  compiler?: string;
  format?: string;
  imageBase?: string;
  functionCount?: number;
  mode: string;
  functions?: GhidraFunction[];
  decompiled?: GhidraDecompiled[];
  selected?: number;
  error?: string;
}

function fn(v: unknown): GhidraFunction | undefined {
  const o = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
  const name = str(o.name, 2048);
  const address = str(o.address, 64);
  if (!name || !address || !/^0x[0-9a-f]{1,16}$/i.test(address)) return undefined;
  const f: GhidraFunction = { name, address: '0x' + address.slice(2).replace(/^0+(?=.)/, '').toLowerCase(), size: num(o.size) ?? 0 };
  const ns = str(o.namespace, 2048); if (ns) f.namespace = ns;
  const sig = str(o.signature, 4096); if (sig) f.signature = sig;
  const th = bool(o.thunk); if (th !== undefined) f.thunk = th;
  const ex = bool(o.external); if (ex !== undefined) f.external = ex;
  const cc = str(o.callingConvention, 64); if (cc) f.callingConvention = cc;
  const p = num(o.parameters); if (p !== undefined) f.parameters = p;
  return f;
}

/** Parse and validate the export script output. Returns undefined if it is not RevLens export JSON. */
export function parseGhidraExport(input: string | unknown): GhidraExport | undefined {
  const data = typeof input === 'string' ? extractJson(input) : input;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
  const o = data as Record<string, unknown>;
  if (o.schema !== 'revlens/ghidra-export@1') return undefined;
  const out: GhidraExport = { schema: 'revlens/ghidra-export@1', program: str(o.program, 4096) ?? '', mode: str(o.mode, 32) ?? '' };
  const lang = str(o.language, 256); if (lang) out.language = lang;
  const comp = str(o.compiler, 256); if (comp) out.compiler = comp;
  const fmt = str(o.format, 256); if (fmt) out.format = fmt;
  const ib = str(o.imageBase, 64); if (ib) out.imageBase = ib;
  const fc = num(o.functionCount); if (fc !== undefined) out.functionCount = fc;
  const err = str(o.error, 4096); if (err) out.error = err;
  if (Array.isArray(o.functions)) {
    out.functions = o.functions.slice(0, PARSE_LIMITS.maxItems).map(fn).filter((x): x is GhidraFunction => !!x);
  }
  if (Array.isArray(o.decompiled)) {
    out.decompiled = [];
    for (const d of o.decompiled.slice(0, 10_000)) {
      const r = (d && typeof d === 'object' ? d : {}) as Record<string, unknown>;
      const f = fn(r.function);
      if (!f) continue;
      const item: GhidraDecompiled = { function: f, ok: r.ok === true };
      const c = str(r.c, 4 * 1024 * 1024); if (c) item.c = c;
      const e = str(r.error, 4096); if (e) item.error = e;
      out.decompiled.push(item);
    }
  }
  const sel = num(o.selected); if (sel !== undefined) out.selected = sel;
  return out;
}
