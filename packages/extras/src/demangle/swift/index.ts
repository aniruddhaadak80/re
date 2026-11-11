// Swift symbol demangling: new mangling ($s, $S, _T0, @__swiftmacro_) and the old Swift 1-3 mangling (_T).
// Ported from the Swift project (swift-6.0.3-RELEASE), Apache License v2.0 with Runtime Library Exception.

import { Node, DemangleError } from './nodes.js';
import { Demangler } from './demangler.js';
import { demangleOldSymbolAsNode } from './old.js';
import { NodePrinter, DEFAULT_OPTIONS, SIMPLIFIED_OPTIONS, type DemangleOptions } from './printer.js';

export { Node } from './nodes.js';
export { DEFAULT_OPTIONS as SWIFT_DEFAULT_OPTIONS, SIMPLIFIED_OPTIONS as SWIFT_SIMPLIFIED_OPTIONS, type DemangleOptions as SwiftDemangleOptions } from './printer.js';

const MAX_SYMBOL = 16384;

function isMangledName(s: string): boolean {
  return /^(_T0|\$S|_\$S|\$s|_\$s|@__swiftmacro_)/.test(s);
}

/** Demangle a Swift symbol to its node tree, or null when it is not a valid Swift symbol. */
export function demangleSwiftTree(sym: string): Node | null {
  if (typeof sym !== 'string' || !sym || sym.length > MAX_SYMBOL) return null;
  try {
    const d = new Demangler();
    if (isMangledName(sym)) return d.demangleSymbol(sym) ?? null;
    return demangleOldSymbolAsNode(sym, d) ?? null;
  } catch (e) {
    if (e instanceof DemangleError || e instanceof TypeError || e instanceof RangeError || e instanceof Error) return null;
    throw e;
  }
}

/** Demangle a Swift symbol to text like swift-demangle; returns null when it does not demangle. */
export function demangleSwift(sym: string, opts: { simplified?: boolean; options?: Partial<DemangleOptions> } = {}): string | null {
  const root = demangleSwiftTree(sym);
  if (!root) return null;
  try {
    const o = { ...(opts.simplified ? SIMPLIFIED_OPTIONS : DEFAULT_OPTIONS), ...(opts.options ?? {}) };
    const s = new NodePrinter(o).printRoot(root);
    return s ? s : null;
  } catch {
    return null;
  }
}

/** The swift-demangle compatible form: the demangled text, or the input unchanged when it fails. */
export function swiftDemangleCompat(sym: string, opts: { simplified?: boolean } = {}): string {
  return demangleSwift(sym, opts) ?? sym;
}

NodePrinter.demangleSymbolAsString = (s: string) => demangleSwift(s) ?? '';
