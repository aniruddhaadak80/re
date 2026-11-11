// One entry point for C++ (Itanium and MSVC), Rust (legacy and v0) and Swift detection.

import { demangleItanium } from './itanium.js';
import { demangleRustLegacy, demangleRustV0 } from './rust.js';
import { demangleMsvc } from './msvc.js';

export { demangleItanium } from './itanium.js';
export { demangleRustLegacy, demangleRustV0 } from './rust.js';
export { demangleMsvc } from './msvc.js';

export type ManglingScheme = 'itanium' | 'rust-legacy' | 'rust-v0' | 'msvc' | 'swift' | 'none';

export interface Demangled { input: string; scheme: ManglingScheme; output: string | null }

/** Detect the mangling scheme of a symbol name. */
export function manglingScheme(sym: string): ManglingScheme {
  const s = sym.replace(/^_(?=_[ZR])/, '');
  if (/^_R[0-9A-Za-z_]/.test(s)) return 'rust-v0';
  if (/^_ZN.*17h[0-9a-f]{16}E/.test(s)) return 'rust-legacy';
  if (/^_Z/.test(s)) return 'itanium';
  if (/^(\?|\.\?A)/.test(sym)) return 'msvc';
  if (/^_?\$s|^_?\$S|^_T0|^_?\$e/.test(sym)) return 'swift';
  return 'none';
}

/** Demangle any supported symbol; output is null when the scheme is recognized but parsing fails. */
export function demangle(sym: string): Demangled {
  const scheme = manglingScheme(sym);
  let output: string | null = null;
  switch (scheme) {
    case 'rust-v0': output = demangleRustV0(sym); break;
    case 'rust-legacy': output = demangleRustLegacy(sym) ?? demangleItanium(sym.replace(/^__Z/, '_Z')); break;
    case 'itanium': output = demangleItanium(sym.replace(/^__Z/, '_Z')); break;
    case 'msvc': output = demangleMsvc(sym); break;
    default: output = null;
  }
  return { input: sym, scheme, output };
}

/** Demangle many symbols with paging; returns only the ones that demangled unless includeFailed is set. */
export function demangleMany(syms: string[], opts: { offset?: number; limit?: number; includeFailed?: boolean } = {}): { total: number; items: Demangled[] } {
  const all = syms.map(demangle).filter((d) => d.scheme !== 'none' && (opts.includeFailed || d.output !== null));
  const off = Math.max(0, opts.offset ?? 0);
  const lim = Math.min(Math.max(1, opts.limit ?? 500), 10000);
  return { total: all.length, items: all.slice(off, off + lim) };
}
