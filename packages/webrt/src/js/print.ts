// Printing an AST back to readable code with @babel/generator (MIT).
import _generate from '@babel/generator';
import { parseJs, walk, t } from './ast.js';

type GenFn = (ast: t.Node, opts?: Record<string, unknown>, code?: string) => { code: string };
const generate: GenFn = ((_generate as unknown as { default?: GenFn }).default ?? (_generate as unknown as GenFn));

/** Drop the raw text Babel keeps on literals so strings and numbers print in their plain form. */
export function normalizeLiterals(ast: t.Node): number {
  let n = 0;
  walk(ast, ({ node }) => {
    if (node.type === 'StringLiteral' || node.type === 'NumericLiteral') {
      const ex = (node as { extra?: Record<string, unknown> }).extra;
      if (ex && typeof ex.raw === 'string') {
        if (node.type === 'StringLiteral' && /\\[xu]/.test(ex.raw)) n++;
        if (node.type === 'NumericLiteral' && /^0[xXoObB]/.test(ex.raw)) n++;
        (node as { extra?: unknown }).extra = undefined;
      }
    }
    if (node.type === 'TemplateElement') {
      if (node.value.cooked != null && /\\[xu]/.test(node.value.raw)) {
        const cooked = node.value.cooked;
        node.value.raw = cooked.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
        n++;
      }
    }
  });
  return n;
}

export function printAst(ast: t.Node, opts: { comments?: boolean } = {}): string {
  return generate(ast, { comments: opts.comments ?? true, compact: false, retainLines: false, jsescOption: { minimal: true, quotes: 'single' } }).code;
}

export interface BeautifyResult {
  code: string;
  lines: number;
  parserErrors: string[];
  /** literals rewritten from hex, octal or unicode escape form */
  literalsNormalized: number;
}

/** Reformat JavaScript with consistent indentation and decode hex and unicode escapes in literals. Does not change behavior. */
export function beautify(code: string, opts: { decodeEscapes?: boolean } = {}): BeautifyResult {
  const { ast, errors } = parseJs(code);
  const literalsNormalized = opts.decodeEscapes === false ? 0 : normalizeLiterals(ast);
  const out = printAst(ast);
  return { code: out, lines: out.split('\n').length, parserErrors: errors, literalsNormalized };
}
