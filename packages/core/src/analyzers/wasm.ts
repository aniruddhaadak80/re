import type { Analyzer } from '../types.js';
import { Reader } from '../bytes.js';

const SECTION_NAMES = ['custom', 'type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'code', 'data', 'datacount', 'tag'];
const KIND = ['func', 'table', 'memory', 'global'];

function uleb(r: Reader): number {
  let result = 0, shift = 0, byte = 0;
  do { byte = r.u8(); result |= (byte & 0x7f) << shift; shift += 7; } while (byte & 0x80);
  return result >>> 0;
}
function name(r: Reader): string {
  const len = uleb(r);
  const start = r.pos; r.skip(len);
  let s = '';
  for (let i = start; i < start + len; i++) s += String.fromCharCode(r.bytes[i] as number);
  return s;
}

export const wasmAnalyzer: Analyzer = {
  id: 'wasm',
  title: 'WebAssembly',
  description: 'Parses WASM sections, imports and exports, and notes the custom name and producers sections.',
  applies: (ctx) => ctx.format === 'wasm',
  run(ctx) {
    const { bytes, report } = ctx;
    const r = new Reader(bytes, true);
    r.seek(8); // magic + version
    report.file.arch = 'wasm';
    const imports: { library: string; symbols: string[] }[] = [];
    const exports: string[] = [];
    const sectionSummary: Record<string, number> = {};
    try {
      while (r.remaining() > 0) {
        const id = r.u8();
        const size = uleb(r);
        const end = r.pos + size;
        const sname = SECTION_NAMES[id] ?? `section${id}`;
        sectionSummary[sname] = (sectionSummary[sname] ?? 0) + 1;
        if (id === 2) { // import
          const count = uleb(r);
          const byModule: Record<string, string[]> = {};
          for (let i = 0; i < count && r.pos < end; i++) {
            const mod = name(r); const fld = name(r);
            const kind = r.u8(); uleb(r);
            (byModule[mod] ??= []).push(`${fld} (${KIND[kind] ?? kind})`);
          }
          for (const [m, syms] of Object.entries(byModule)) imports.push({ library: m, symbols: syms });
        } else if (id === 7) { // export
          const count = uleb(r);
          for (let i = 0; i < count && r.pos < end; i++) {
            const nm = name(r); const kind = r.u8(); uleb(r);
            exports.push(`${nm} (${KIND[kind] ?? kind})`);
          }
        } else if (id === 0) { // custom
          const nm = name(r);
          report.meta[`wasmCustom_${nm}`] = size;
        }
        r.seek(end);
      }
    } catch { /* truncated or exotic encoding; keep what we have */ }
    report.imports.push(...imports);
    report.exports.push(...exports);
    report.meta.wasm = { sections: sectionSummary, importModules: imports.length, exportCount: exports.length };
  },
};
