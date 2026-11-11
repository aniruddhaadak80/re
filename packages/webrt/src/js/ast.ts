// Parsing and tree walking for JavaScript. Uses @babel/parser (MIT) and an iterative walker
// with hard caps so hostile inputs cannot blow the stack or run forever.
import { parse as babelParse, type ParserPlugin } from '@babel/parser';
import * as t from '@babel/types';
import { LIMITS, InputError } from '../util.js';

export type Node = t.Node;
export type File = t.File;

export interface ParseResult {
  ast: t.File;
  /** parser errors that were recovered from */
  errors: string[];
  sourceType: 'module' | 'script';
}

const BASE_PLUGINS: ParserPlugin[] = ['jsx', 'classProperties', 'classPrivateProperties', 'classPrivateMethods', 'dynamicImport', 'importMeta', 'topLevelAwait', 'optionalChaining', 'nullishCoalescingOperator', 'objectRestSpread', 'bigInt', 'numericSeparator', 'logicalAssignment', 'optionalCatchBinding', 'exportDefaultFrom', 'importAttributes'];

/** Parse JavaScript (or JSX) leniently. Throws InputError only when nothing could be parsed. */
export function parseJs(code: string, opts: { typescript?: boolean } = {}): ParseResult {
  if (code.length > LIMITS.maxJsBytes) throw new InputError(`script is ${code.length} chars, over the ${LIMITS.maxJsBytes} limit`);
  const plugins: ParserPlugin[] = opts.typescript ? [...BASE_PLUGINS.filter((p) => p !== 'jsx'), 'typescript'] : BASE_PLUGINS;
  let lastErr: unknown;
  for (const sourceType of ['module', 'script'] as const) {
    for (const errorRecovery of [false, true]) {
      try {
        const ast = babelParse(code, {
          sourceType, errorRecovery, plugins, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true,
          allowImportExportEverywhere: true, allowSuperOutsideMethod: true, allowUndeclaredExports: true, ranges: false, tokens: false,
        }) as t.File & { errors?: { message: string }[] };
        return { ast, errors: (ast.errors ?? []).slice(0, 50).map((e) => e.message), sourceType };
      } catch (e) { lastErr = e; }
    }
  }
  throw new InputError(`could not parse JavaScript: ${(lastErr as Error)?.message ?? lastErr}`);
}

export interface Visit {
  node: t.Node;
  parent: t.Node | null;
  key: string | null;
  index: number | null;
  depth: number;
  /** ancestors from root to parent (shared array, copy if you keep it) */
  ancestors: t.Node[];
}

/**
 * Depth-first pre-order walk over every node. The callback may return 'skip' to not descend.
 * Iterative, so deep inputs do not overflow the JS stack. Stops at LIMITS.maxAstNodes visits
 * and does not descend past LIMITS.maxAstDepth. Returns the visit count.
 */
export function walk(root: t.Node, cb: (v: Visit) => void | 'skip' | 'stop'): number {
  type Frame = { node: t.Node; parent: t.Node | null; key: string | null; index: number | null; depth: number; exit?: boolean };
  const stack: Frame[] = [{ node: root, parent: null, key: null, index: null, depth: 0 }];
  const ancestors: t.Node[] = [];
  let count = 0;
  while (stack.length) {
    const f = stack.pop() as Frame;
    if (f.exit) { ancestors.pop(); continue; }
    if (++count > LIMITS.maxAstNodes) break;
    while (ancestors.length > f.depth) ancestors.pop();
    const r = cb({ node: f.node, parent: f.parent, key: f.key, index: f.index, depth: f.depth, ancestors });
    if (r === 'stop') break;
    if (r === 'skip' || f.depth >= LIMITS.maxAstDepth) continue;
    const keys = t.VISITOR_KEYS[f.node.type];
    if (!keys) continue;
    ancestors.push(f.node);
    const children: Frame[] = [];
    for (const key of keys) {
      const v = (f.node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(v)) {
        v.forEach((c, i) => { if (c && typeof c === 'object' && typeof (c as t.Node).type === 'string') children.push({ node: c as t.Node, parent: f.node, key, index: i, depth: f.depth + 1 }); });
      } else if (v && typeof v === 'object' && typeof (v as t.Node).type === 'string') {
        children.push({ node: v as t.Node, parent: f.node, key, index: null, depth: f.depth + 1 });
      }
    }
    stack.push({ node: f.node, parent: null, key: null, index: null, depth: f.depth, exit: true });
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i] as Frame);
  }
  return count;
}

/** Replace a visited node in its parent. */
export function replaceAt(v: { parent: t.Node | null; key: string | null; index: number | null }, next: t.Node): void {
  if (!v.parent || v.key === null) return;
  const holder = (v.parent as unknown as Record<string, unknown>)[v.key];
  if (v.index !== null && Array.isArray(holder)) holder[v.index] = next;
  else (v.parent as unknown as Record<string, unknown>)[v.key] = next;
}

/** Static string value of a node, when it is a plain string (or template without expressions). */
export function staticString(n: t.Node | null | undefined): string | undefined {
  if (!n) return undefined;
  if (n.type === 'StringLiteral') return n.value;
  if (n.type === 'TemplateLiteral' && n.expressions.length === 0) return n.quasis.map((q) => q.value.cooked ?? q.value.raw).join('');
  if (n.type === 'BinaryExpression' && n.operator === '+') {
    const a = staticString(n.left as t.Node), b = staticString(n.right);
    if (a !== undefined && b !== undefined) return a + b;
  }
  return undefined;
}

/** Template literal rendered with ${...} placeholders for the dynamic parts. */
export function templateShape(n: t.Node | null | undefined): string | undefined {
  if (!n) return undefined;
  const s = staticString(n);
  if (s !== undefined) return s;
  if (n.type === 'TemplateLiteral') {
    let out = '';
    n.quasis.forEach((q, i) => { out += q.value.cooked ?? q.value.raw; if (i < n.expressions.length) out += '${}'; });
    return out;
  }
  if (n.type === 'BinaryExpression' && n.operator === '+') {
    const a = templateShape(n.left as t.Node) ?? '${}', b = templateShape(n.right) ?? '${}';
    if (a === '${}' && b === '${}') return undefined;
    return a + b;
  }
  return undefined;
}

/** a.b.c as a dotted name, computed string props included. */
export function memberName(n: t.Node | null | undefined, depth = 0): string | undefined {
  if (!n || depth > 32) return undefined;
  if (n.type === 'Identifier') return n.name;
  if (n.type === 'ThisExpression') return 'this';
  if (n.type === 'MetaProperty') return `${n.meta.name}.${n.property.name}`;
  if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
    const obj = memberName(n.object, depth + 1);
    if (obj === undefined) return undefined;
    if (!n.computed && n.property.type === 'Identifier') return `${obj}.${n.property.name}`;
    const s = staticString(n.property);
    if (s !== undefined) return `${obj}.${s}`;
    return undefined;
  }
  return undefined;
}

export function propKey(p: t.ObjectProperty | t.ObjectMethod): string | undefined {
  if (!p.computed && p.key.type === 'Identifier') return p.key.name;
  if (p.key.type === 'StringLiteral') return p.key.value;
  if (p.key.type === 'NumericLiteral') return String(p.key.value);
  return undefined;
}

export { t };
