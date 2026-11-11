// Static deobfuscation of common JavaScript obfuscation patterns.
// Nothing from the input is ever executed: string arrays, rotations and decoders are
// recognized structurally and replayed with a small bounded evaluator over literals.
import { parseJs, walk, replaceAt, staticString, propKey, t } from './ast.js';
import { normalizeLiterals, printAst } from './print.js';

export interface DeobfuscateResult {
  code: string;
  changed: boolean;
  parserErrors: string[];
  stringArray?: {
    arrayName: string;
    decoderName: string;
    length: number;
    encoding: 'none' | 'base64' | 'rc4';
    offset: number;
    rotated: number;
    wrappers: number;
  };
  stats: {
    stringsDecoded: number;
    literalsNormalized: number;
    constantsFolded: number;
    membersSimplified: number;
    deadBranchesRemoved: number;
    proxiesInlined: number;
    switchesUnflattened: number;
    sequencesSplit: number;
    helpersRemoved: number;
  };
  /** decoded strings in array order, capped */
  decodedStrings: string[];
  notes: string[];
}

type Val = string | number | boolean | null | undefined;
class EvalFail extends Error {}

const MAX_EVAL_STEPS = 200_000;
const MAX_ROTATIONS = 100_000;

// ---------- string array decoders (algorithms of javascript-obfuscator, reimplemented) ----------
function obfBase64(input: string, alphabet: string): string {
  let bits = '', out = '';
  let bc = 0, bs = 0;
  for (let i = 0; i < input.length; i++) {
    const c = alphabet.indexOf(input.charAt(i));
    if (c === -1 || c === 64) continue; // padding or junk
    bs = bc % 4 ? bs * 64 + c : c;
    if (bc++ % 4) bits += String.fromCharCode(0xff & (bs >> ((-2 * bc) & 6)));
  }
  for (let i = 0; i < bits.length; i++) out += '%' + ('00' + bits.charCodeAt(i).toString(16)).slice(-2);
  return decodeURIComponent(out);
}

function rc4(data: string, key: string): string {
  if (!key.length) throw new EvalFail('empty rc4 key');
  const s: number[] = [];
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + (s[i] as number) + key.charCodeAt(i % key.length)) % 256;
    const x = s[i] as number; s[i] = s[j] as number; s[j] = x;
  }
  let i = 0; j = 0; let out = '';
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) % 256; j = (j + (s[i] as number)) % 256;
    const x = s[i] as number; s[i] = s[j] as number; s[j] = x;
    out += String.fromCharCode(data.charCodeAt(k) ^ (s[((s[i] as number) + (s[j] as number)) % 256] as number));
  }
  return out;
}

interface Decoder { kind: 'decoder'; offset: number; encoding: 'none' | 'base64' | 'rc4'; alphabet: string }
interface Wrapper { kind: 'wrapper'; params: string[]; callee: string; args: t.Expression[] }
interface Alias { kind: 'alias'; target: string }
type Callable = Decoder | Wrapper | Alias;

interface Ctx { array: string[]; callables: Map<string, Callable>; steps: number }


function evalExpr(n: t.Node, env: Map<string, Val>, ctx: Ctx, depth = 0): Val {
  if (++ctx.steps > MAX_EVAL_STEPS || depth > 64) throw new EvalFail('eval budget');
  switch (n.type) {
    case 'NumericLiteral': return n.value;
    case 'StringLiteral': return n.value;
    case 'BooleanLiteral': return n.value;
    case 'NullLiteral': return null;
    case 'ParenthesizedExpression': return evalExpr(n.expression, env, ctx, depth + 1);
    case 'Identifier':
      if (env.has(n.name)) return env.get(n.name);
      if (n.name === 'undefined') return undefined;
      throw new EvalFail(`unbound ${n.name}`);
    case 'ArrayExpression':
      throw new EvalFail('array');
    case 'UnaryExpression': {
      if (n.operator === '!' && n.argument.type === 'ArrayExpression' && n.argument.elements.length === 0) return false;
      const a = evalExpr(n.argument, env, ctx, depth + 1);
      switch (n.operator) {
        case '-': return -(a as number);
        case '+': return +(a as number);
        case '!': return !a;
        case '~': return ~(a as number);
        case 'void': return undefined;
        default: throw new EvalFail('unary');
      }
    }
    case 'BinaryExpression': {
      const a = evalExpr(n.left, env, ctx, depth + 1) as never, b = evalExpr(n.right, env, ctx, depth + 1) as never;
      return binop(n.operator, a, b);
    }
    case 'LogicalExpression': {
      const a = evalExpr(n.left, env, ctx, depth + 1);
      if (n.operator === '&&') return a ? evalExpr(n.right, env, ctx, depth + 1) : a;
      if (n.operator === '||') return a ? a : evalExpr(n.right, env, ctx, depth + 1);
      return a ?? evalExpr(n.right, env, ctx, depth + 1);
    }
    case 'ConditionalExpression':
      return evalExpr(n.test, env, ctx, depth + 1) ? evalExpr(n.consequent, env, ctx, depth + 1) : evalExpr(n.alternate, env, ctx, depth + 1);
    case 'CallExpression': {
      if (n.callee.type !== 'Identifier') throw new EvalFail('callee');
      const args = n.arguments.map((a) => { if (a.type === 'SpreadElement' || a.type === 'ArgumentPlaceholder') throw new EvalFail('arg'); return evalExpr(a, env, ctx, depth + 1); });
      if (n.callee.name === 'parseInt' && !ctx.callables.has('parseInt')) return parseInt(String(args[0]), args[1] as number | undefined);
      return callFn(n.callee.name, args, ctx, depth + 1);
    }
    default: throw new EvalFail(`node ${n.type}`);
  }
}

function binop(op: string, a: never, b: never): Val {
  switch (op) {
    case '+': return (a as number) + (b as number);
    case '-': return (a as number) - (b as number);
    case '*': return (a as number) * (b as number);
    case '/': return (a as number) / (b as number);
    case '%': return (a as number) % (b as number);
    case '**': return (a as number) ** (b as number);
    case '|': return (a as number) | (b as number);
    case '&': return (a as number) & (b as number);
    case '^': return (a as number) ^ (b as number);
    case '<<': return (a as number) << (b as number);
    case '>>': return (a as number) >> (b as number);
    case '>>>': return (a as number) >>> (b as number);
    case '===': return a === b;
    case '!==': return a !== b;
    // eslint-disable-next-line eqeqeq
    case '==': return a == b;
    // eslint-disable-next-line eqeqeq
    case '!=': return a != b;
    case '<': return a < b;
    case '>': return a > b;
    case '<=': return a <= b;
    case '>=': return a >= b;
    default: throw new EvalFail('binop');
  }
}

function callFn(name: string, args: Val[], ctx: Ctx, depth: number): Val {
  if (depth > 48) throw new EvalFail('depth');
  const c = ctx.callables.get(name);
  if (!c) throw new EvalFail(`unknown fn ${name}`);
  if (c.kind === 'alias') return callFn(c.target, args, ctx, depth + 1);
  if (c.kind === 'wrapper') {
    const env = new Map<string, Val>();
    c.params.forEach((p, i) => env.set(p, args[i]));
    const inner = c.args.map((a) => evalExpr(a, env, ctx, depth + 1));
    return callFn(c.callee, inner, ctx, depth + 1);
  }
  const idx = (args[0] as number) - c.offset;
  if (!Number.isInteger(idx) || idx < 0 || idx >= ctx.array.length) return undefined;
  const raw = ctx.array[idx] as string;
  if (c.encoding === 'none') return raw;
  try {
    const b = obfBase64(raw, c.alphabet);
    if (c.encoding === 'base64') return b;
    return rc4(b, String(args[1]));
  } catch (e) {
    if (e instanceof EvalFail) throw e;
    throw new EvalFail('decode');
  }
}

// ---------- helpers ----------
function fnBody(n: t.Node): t.Statement[] | undefined {
  if ((n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression') && n.body.type === 'BlockStatement') return n.body.body;
  if (n.type === 'ArrowFunctionExpression' && n.body.type === 'BlockStatement') return n.body.body;
  return undefined;
}
function paramNames(n: t.Function): string[] | undefined {
  const out: string[] = [];
  for (const p of n.params) { if (p.type !== 'Identifier') return undefined; out.push(p.name); }
  return out;
}
function containsNode(root: t.Node, pred: (n: t.Node) => boolean): boolean {
  let found = false;
  walk(root, ({ node }) => { if (pred(node)) { found = true; return 'stop'; } });
  return found;
}
function isArithOver(n: t.Node, params: Set<string>, depth = 0): boolean {
  if (depth > 32) return false;
  switch (n.type) {
    case 'NumericLiteral': case 'StringLiteral': return true;
    case 'Identifier': return params.has(n.name);
    case 'UnaryExpression': return (n.operator === '-' || n.operator === '+') && isArithOver(n.argument, params, depth + 1);
    case 'BinaryExpression': return ['+', '-', '*', '/', '%', '^', '|', '&'].includes(n.operator) && n.left.type !== 'PrivateName' && isArithOver(n.left, params, depth + 1) && isArithOver(n.right, params, depth + 1);
    case 'ParenthesizedExpression': return isArithOver(n.expression, params, depth + 1);
    default: return false;
  }
}

interface FnDef { name: string; fn: t.Function; holder: t.Node }

function collectFunctions(ast: t.File): FnDef[] {
  const out: FnDef[] = [];
  walk(ast, ({ node }) => {
    if (node.type === 'FunctionDeclaration' && node.id) out.push({ name: node.id.name, fn: node, holder: node });
    else if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init && (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) out.push({ name: node.id.name, fn: node.init, holder: node });
  });
  return out;
}

/** Remove a statement or declarator node from wherever it sits. Returns true when removed. */
function removeNode(ast: t.File, target: t.Node): boolean {
  let done = false;
  walk(ast, (v) => {
    if (done) return 'stop';
    if (v.node !== target || !v.parent || v.key === null) return;
    const holder = (v.parent as unknown as Record<string, unknown>)[v.key];
    if (Array.isArray(holder) && v.index !== null) {
      holder.splice(v.index, 1);
      if (v.parent.type === 'VariableDeclaration' && v.parent.declarations.length === 0) {
        const decl = v.parent;
        done = true;
        removeNode(ast, decl);
        return 'stop';
      }
      done = true;
      return 'stop';
    }
    if (v.parent.type === 'ExpressionStatement') { done = removeNode(ast, v.parent); return 'stop'; }
    return;
  });
  return done;
}

function refCount(ast: t.File, name: string, exclude: Set<t.Node>): number {
  let n = 0;
  walk(ast, ({ node, parent, key }) => {
    if (exclude.has(node)) return 'skip';
    if (node.type === 'Identifier' && node.name === name) {
      if (parent && ((parent.type === 'FunctionDeclaration' && key === 'id') || (parent.type === 'VariableDeclarator' && key === 'id'))) return;
      if (parent && (parent.type === 'MemberExpression' || parent.type === 'OptionalMemberExpression') && key === 'property' && !parent.computed) return;
      if (parent && parent.type === 'ObjectProperty' && key === 'key' && !parent.computed) return;
      n++;
    }
  });
  return n;
}

// ---------- string array recovery ----------
interface ArrayInfo { name: string; strings: string[]; holder: t.Node }

function findStringArrays(ast: t.File): ArrayInfo[] {
  const out: ArrayInfo[] = [];
  const allStrings = (a: t.ArrayExpression) => a.elements.length > 0 && a.elements.every((e) => e && e.type === 'StringLiteral');
  walk(ast, ({ node }) => {
    // modern: function A(){ const x = [...]; A = function(){ return x; }; return A(); }
    if (node.type === 'FunctionDeclaration' && node.id) {
      const body = node.body.body;
      if (body.length <= 4) {
        for (const st of body) {
          if (st.type === 'VariableDeclaration') {
            for (const d of st.declarations) {
              if (d.init && d.init.type === 'ArrayExpression' && allStrings(d.init)) {
                const fname = node.id.name;
                const selfRef = containsNode(node.body, (n) => n.type === 'AssignmentExpression' && n.left.type === 'Identifier' && n.left.name === fname);
                if (selfRef) out.push({ name: fname, strings: d.init.elements.map((e) => (e as t.StringLiteral).value), holder: node });
              }
            }
          }
        }
      }
      return;
    }
    // classic: var A = [...] with many strings
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init?.type === 'ArrayExpression' && node.init.elements.length >= 2 && allStrings(node.init)) {
      out.push({ name: node.id.name, strings: node.init.elements.map((e) => (e as t.StringLiteral).value), holder: node });
    }
  });
  return out;
}

function findDecoder(fns: FnDef[], arr: ArrayInfo): (FnDef & { dec: Decoder }) | undefined {
  for (const f of fns) {
    if (f.name === arr.name) continue;
    const params = paramNames(f.fn);
    if (!params || params.length < 1 || params.length > 3) continue;
    const p0 = params[0] as string;
    const usesArray = containsNode(f.fn.body, (n) => n.type === 'Identifier' && n.name === arr.name);
    if (!usesArray) continue;
    let offset: number | undefined;
    walk(f.fn.body, ({ node }) => {
      if (offset !== undefined) return 'stop';
      if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && node.left.name === p0) {
        const r = node.right;
        if (node.operator === '=' && r.type === 'BinaryExpression' && r.operator === '-' && r.left.type === 'Identifier' && r.left.name === p0) {
          try { const v = evalExpr(r.right, new Map(), { array: [], callables: new Map(), steps: 0 }); if (typeof v === 'number') offset = v; } catch { /* ignore */ }
        } else if (node.operator === '-=') {
          try { const v = evalExpr(r, new Map(), { array: [], callables: new Map(), steps: 0 }); if (typeof v === 'number') offset = v; } catch { /* ignore */ }
        }
      }
    });
    if (offset === undefined) offset = 0;
    let alphabet = '';
    let has256 = false;
    walk(f.fn.body, ({ node }) => {
      if (node.type === 'StringLiteral' && node.value.length === 65 && /^[A-Za-z0-9+/=]{65}$/.test(node.value)) alphabet = node.value;
      if (node.type === 'NumericLiteral' && node.value === 256) has256 = true;
    });
    const encoding: Decoder['encoding'] = alphabet ? (has256 ? 'rc4' : 'base64') : 'none';
    return { ...f, dec: { kind: 'decoder', offset, encoding, alphabet } };
  }
  return undefined;
}

function registerWrappers(fns: FnDef[], ast: t.File, ctx: Ctx): { wrappers: Set<t.Node> } {
  const wrappers = new Set<t.Node>();
  for (let round = 0; round < 8; round++) {
    let added = 0;
    for (const f of fns) {
      if (ctx.callables.has(f.name)) continue;
      const body = fnBody(f.fn);
      const params = paramNames(f.fn);
      if (!params) continue;
      let expr: t.Node | undefined;
      if (body && body.length === 1 && body[0]?.type === 'ReturnStatement') expr = body[0].argument ?? undefined;
      else if (f.fn.type === 'ArrowFunctionExpression' && f.fn.body.type !== 'BlockStatement') expr = f.fn.body;
      if (!expr || expr.type !== 'CallExpression' || expr.callee.type !== 'Identifier' || !ctx.callables.has(expr.callee.name)) continue;
      const ps = new Set(params);
      const args = expr.arguments as t.Expression[];
      if (!args.every((a) => isArithOver(a, ps))) continue;
      ctx.callables.set(f.name, { kind: 'wrapper', params, callee: expr.callee.name, args });
      wrappers.add(f.holder);
      added++;
    }
    // aliases: const a = decoder;  a = decoder
    walk(ast, ({ node }) => {
      if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init?.type === 'Identifier' && ctx.callables.has(node.init.name) && !ctx.callables.has(node.id.name)) {
        ctx.callables.set(node.id.name, { kind: 'alias', target: node.init.name });
        wrappers.add(node);
        added++;
      }
    });
    if (!added) break;
  }
  return { wrappers };
}

function findRotation(ast: t.File, arr: ArrayInfo): { call: t.CallExpression; stmt?: t.Node; target?: number; expr?: t.Expression; count?: number } | undefined {
  let found: ReturnType<typeof findRotation>;
  walk(ast, ({ node, parent }) => {
    if (found) return 'stop';
    if (node.type !== 'CallExpression') return;
    const callee = node.callee;
    if (callee.type !== 'FunctionExpression' && callee.type !== 'ArrowFunctionExpression') return;
    const a0 = node.arguments[0], a1 = node.arguments[1];
    if (!a0 || a0.type !== 'Identifier' || a0.name !== arr.name || !a1) return;
    let num: number | undefined;
    try { const v = evalExpr(a1, new Map(), { array: [], callables: new Map(), steps: 0 }); if (typeof v === 'number') num = v; } catch { return; }
    if (num === undefined) return;
    const hasPushShift = containsNode(callee.body, (n) => (n.type === 'StringLiteral' && (n.value === 'push' || n.value === 'shift')) || (n.type === 'Identifier' && (n.name === 'push' || n.name === 'shift')));
    if (!hasPushShift) return;
    const params = paramNames(callee) ?? [];
    const targetParam = params[1];
    let checkVar: string | undefined;
    walk(callee.body, ({ node: m }) => {
      if (checkVar) return 'stop';
      if (m.type === 'BinaryExpression' && (m.operator === '===' || m.operator === '==') && m.right.type === 'Identifier' && m.right.name === targetParam && m.left.type === 'Identifier') checkVar = m.left.name;
    });
    let expr: t.Expression | undefined;
    if (checkVar) {
      walk(callee.body, ({ node: m }) => {
        if (m.type === 'VariableDeclarator' && m.id.type === 'Identifier' && m.id.name === checkVar && m.init) { expr = m.init; return 'stop'; }
        if (m.type === 'AssignmentExpression' && m.left.type === 'Identifier' && m.left.name === checkVar) { expr = m.right; return 'stop'; }
      });
    }
    const stmt = parent && parent.type === 'ExpressionStatement' ? parent : (parent?.type === 'UnaryExpression' ? parent : undefined);
    found = expr ? { call: node, stmt, target: num, expr } : { call: node, stmt, count: num };
  });
  return found;
}

function recoverStringArray(ast: t.File, res: DeobfuscateResult): void {
  const arrays = findStringArrays(ast);
  if (!arrays.length) return;
  const fns = collectFunctions(ast);
  for (const arr of arrays) {
    const decoder = findDecoder(fns, arr);
    if (!decoder) continue;
    const ctx: Ctx = { array: arr.strings.slice(), callables: new Map([[decoder.name, decoder.dec]]), steps: 0 };
    const { wrappers } = registerWrappers(fns, ast, ctx);
    const rot = findRotation(ast, arr);
    let rotated = 0;
    if (rot?.expr !== undefined && rot.target !== undefined) {
      // also register wrappers declared inside the rotation function (already collected globally)
      let ok = false;
      const limit = Math.min(MAX_ROTATIONS, ctx.array.length + 1);
      for (let i = 0; i < limit; i++) {
        ctx.steps = 0;
        try {
          const v = evalExpr(rot.expr, new Map(), ctx);
          if (v === rot.target) { ok = true; break; }
        } catch { /* decoding failed: rotate like the original catch block */ }
        ctx.array.push(ctx.array.shift() as string);
        rotated++;
      }
      if (!ok) { res.notes.push(`string array ${arr.name}: rotation checksum never matched, strings left in place`); continue; }
    } else if (rot?.count !== undefined) {
      const n = rot.count % Math.max(1, ctx.array.length);
      for (let i = 0; i < n; i++) ctx.array.push(ctx.array.shift() as string);
      rotated = n;
    }

    // replace call sites
    let decoded = 0;
    const seen = new Set<string>();
    const skip = new Set<t.Node>([decoder.holder, ...wrappers]);
    if (rot) skip.add(rot.call);
    walk(ast, (v) => {
      if (skip.has(v.node)) return 'skip';
      const n = v.node;
      if (n.type === 'CallExpression' && n.callee.type === 'Identifier' && ctx.callables.has(n.callee.name)) {
        ctx.steps = 0;
        try {
          const val = evalExpr(n, new Map(), ctx);
          if (typeof val === 'string') { replaceAt(v, t.stringLiteral(val)); decoded++; seen.add(val); return 'skip'; }
        } catch { /* leave it */ }
      }
      // classic form: arr[0x1] directly indexing the array
      if (n.type === 'MemberExpression' && n.computed && n.object.type === 'Identifier' && n.object.name === arr.name && n.property.type === 'NumericLiteral' && decoder.dec.encoding === 'none' && arr.holder.type === 'VariableDeclarator') {
        const s = ctx.array[n.property.value];
        if (typeof s === 'string') { replaceAt(v, t.stringLiteral(s)); decoded++; seen.add(s); }
      }
    });
    res.stats.stringsDecoded += decoded;

    // remove helpers that are no longer referenced
    let removed = 0;
    const defs: { name: string; node: t.Node }[] = [...wrappers].map((w) => ({ name: w.type === 'FunctionDeclaration' ? (w.id as t.Identifier).name : ((w as t.VariableDeclarator).id as t.Identifier).name, node: w }));
    for (let round = 0; round < 10; round++) {
      let changed = false;
      for (const d of defs.slice()) {
        if (refCount(ast, d.name, new Set([d.node])) === 0 && removeNode(ast, d.node)) { defs.splice(defs.indexOf(d), 1); removed++; changed = true; }
      }
      if (!changed) break;
    }
    const rotNode = rot ? (rot.stmt ?? rot.call) : undefined;
    const excl = new Set<t.Node>([decoder.holder]);
    if (rotNode) excl.add(rotNode);
    for (const d of defs) excl.add(d.node);
    if (refCount(ast, decoder.name, excl) === 0) {
      for (const d of defs) if (removeNode(ast, d.node)) removed++;
      if (rotNode && removeNode(ast, rotNode)) removed++;
      if (removeNode(ast, decoder.holder)) removed++;
      if (refCount(ast, arr.name, new Set([arr.holder])) === 0 && removeNode(ast, arr.holder)) removed++;
    }
    res.stats.helpersRemoved += removed;

    // strings seen at call sites first, then the rest of the array when it decodes without a per-call key
    const decodedStrings: string[] = [...seen].slice(0, 2000);
    if (decoder.dec.encoding !== 'rc4') {
      for (let i = 0; i < ctx.array.length && decodedStrings.length < 2000; i++) {
        ctx.steps = 0;
        try { const v = callFn(decoder.name, [i + decoder.dec.offset], ctx, 0); if (typeof v === 'string' && !seen.has(v)) decodedStrings.push(v); } catch { /* skip */ }
      }
    }
    res.decodedStrings = decodedStrings;
    res.stringArray = { arrayName: arr.name, decoderName: decoder.name, length: arr.strings.length, encoding: decoder.dec.encoding, offset: decoder.dec.offset, rotated, wrappers: wrappers.size };
    return; // one string array per file is the common case
  }
}

// ---------- generic cleanups ----------
const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const RESERVED = new Set(['break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends', 'finally', 'for', 'function', 'if', 'import', 'in', 'instanceof', 'new', 'return', 'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield', 'let', 'static', 'enum', 'await', 'implements', 'package', 'protected', 'interface', 'private', 'public', 'null', 'true', 'false']);

function literalOf(v: Val): t.Expression | undefined {
  if (typeof v === 'string') return t.stringLiteral(v);
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return undefined;
    if (v < 0 || Object.is(v, -0)) return Object.is(v, -0) ? undefined : t.unaryExpression('-', t.numericLiteral(-v));
    return t.numericLiteral(v);
  }
  if (v === null) return t.nullLiteral();
  return undefined;
}

function isConstLiteral(n: t.Node): boolean {
  if (n.type === 'StringLiteral' || n.type === 'NumericLiteral' || n.type === 'BooleanLiteral' || n.type === 'NullLiteral') return true;
  if (n.type === 'UnaryExpression' && (n.operator === '-' || n.operator === '!') && n.argument.type === 'NumericLiteral') return true;
  if (n.type === 'UnaryExpression' && n.operator === '!' && n.argument.type === 'ArrayExpression' && n.argument.elements.length === 0) return true;
  if (n.type === 'UnaryExpression' && n.operator === '!' && n.argument.type === 'UnaryExpression') return isConstLiteral(n.argument);
  return false;
}

function cleanupPass(ast: t.File, res: DeobfuscateResult): boolean {
  let changed = false;
  const emptyCtx = (): Ctx => ({ array: [], callables: new Map(), steps: 0 });
  walk(ast, (v) => {
    const n = v.node;
    // obj['name'] -> obj.name
    if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && n.computed && n.property.type === 'StringLiteral' && IDENT_RE.test(n.property.value) && !RESERVED.has(n.property.value)) {
      n.property = t.identifier(n.property.value); n.computed = false; res.stats.membersSimplified++; changed = true;
    }
    if ((n.type === 'ObjectProperty' || n.type === 'ObjectMethod' || n.type === 'ClassMethod') && !n.computed && n.key.type === 'StringLiteral' && IDENT_RE.test(n.key.value) && !RESERVED.has(n.key.value)) {
      n.key = t.identifier(n.key.value); res.stats.membersSimplified++; changed = true;
    }
    // !![] -> true, ![] -> false, !0 -> true, !1 -> false, constant binaries
    if ((n.type === 'UnaryExpression' && n.operator === '!' && isConstLiteral(n)) || (n.type === 'BinaryExpression' && isConstLiteral(n.left) && isConstLiteral(n.right) && n.operator !== 'in' && n.operator !== 'instanceof')) {
      try {
        const val = evalExpr(n, new Map(), emptyCtx());
        const lit = literalOf(val);
        if (lit && !(typeof val === 'string' && val.length > 10_000)) { replaceAt(v, lit); res.stats.constantsFolded++; changed = true; return 'skip'; }
      } catch { /* not foldable */ }
    }
    // constant if / conditional
    if (n.type === 'IfStatement' && (n.test.type === 'BooleanLiteral' || n.test.type === 'StringLiteral' || n.test.type === 'NumericLiteral')) {
      const truthy = !!(n.test as t.BooleanLiteral).value;
      const pick = truthy ? n.consequent : n.alternate;
      if (v.parent && v.key && Array.isArray((v.parent as unknown as Record<string, unknown>)[v.key]) && v.index !== null) {
        const list = (v.parent as unknown as Record<string, t.Statement[]>)[v.key] as t.Statement[];
        const repl: t.Statement[] = !pick ? [] : pick.type === 'BlockStatement' && !pick.body.some((s) => s.type === 'VariableDeclaration' && s.kind !== 'var') && !pick.body.some((s) => s.type === 'FunctionDeclaration' || s.type === 'ClassDeclaration') ? pick.body : [pick];
        list.splice(v.index, 1, ...repl);
      } else replaceAt(v, pick ?? t.emptyStatement());
      res.stats.deadBranchesRemoved++; changed = true; return 'stop'; // indexes shifted, restart
    }
    if (n.type === 'ConditionalExpression' && isConstLiteral(n.test)) {
      try { const val = evalExpr(n.test, new Map(), emptyCtx()); replaceAt(v, val ? n.consequent : n.alternate); res.stats.deadBranchesRemoved++; changed = true; return 'skip'; } catch { /* keep */ }
    }
    // return a(), b; -> a(); return b;
    if (n.type === 'ReturnStatement' && n.argument?.type === 'SequenceExpression' && v.parent && v.key && v.index !== null) {
      const list = (v.parent as unknown as Record<string, unknown>)[v.key];
      if (Array.isArray(list)) {
        const exprs = n.argument.expressions;
        list.splice(v.index, 1, ...exprs.slice(0, -1).map((e) => t.expressionStatement(e)), t.returnStatement(exprs[exprs.length - 1]));
        res.stats.sequencesSplit++; changed = true; return 'stop';
      }
    }
    // a(), b(); -> a(); b();
    if (n.type === 'ExpressionStatement' && n.expression.type === 'SequenceExpression' && v.parent && v.key && v.index !== null) {
      const list = (v.parent as unknown as Record<string, unknown>)[v.key];
      if (Array.isArray(list)) {
        list.splice(v.index, 1, ...n.expression.expressions.map((e) => t.expressionStatement(e)));
        res.stats.sequencesSplit++; changed = true; return 'stop';
      }
    }
    return undefined;
  });
  return changed;
}

/** Turn the switch-in-a-loop dispatcher ('2|0|1'.split('|')) back into straight-line code. */
function unflattenSwitches(ast: t.File, res: DeobfuscateResult): boolean {
  let changed = false;
  walk(ast, (v) => {
    const n = v.node;
    if (n.type !== 'BlockStatement' && n.type !== 'Program') return;
    const body = n.body;
    for (let i = 0; i < body.length; i++) {
      const s0 = body[i];
      if (!s0 || s0.type !== 'VariableDeclaration') continue;
      // order may be declared with the counter in the same declaration
      let orderName: string | undefined, order: string[] | undefined, counterName: string | undefined;
      const decls = [...s0.declarations];
      let next = i + 1;
      const s1 = body[next];
      if (decls.length < 2 && s1 && s1.type === 'VariableDeclaration') { decls.push(...s1.declarations); next++; }
      for (const d of decls) {
        if (d.id.type !== 'Identifier' || !d.init) continue;
        const init = d.init;
        if (init.type === 'CallExpression' && init.callee.type === 'MemberExpression' && (memberProp(init.callee) === 'split') && init.callee.object.type === 'StringLiteral' && staticString(init.arguments[0] as t.Node) !== undefined) {
          orderName = d.id.name; order = init.callee.object.value.split(staticString(init.arguments[0] as t.Node) as string);
        } else if (init.type === 'NumericLiteral' && init.value === 0) counterName = d.id.name;
      }
      if (!orderName || !order || !counterName || order.length > 10_000) continue;
      const loop = body[next];
      if (!loop || (loop.type !== 'WhileStatement' && loop.type !== 'ForStatement')) continue;
      const lb = loop.body;
      if (lb.type !== 'BlockStatement') continue;
      const sw = lb.body[0];
      if (!sw || sw.type !== 'SwitchStatement') continue;
      const disc = sw.discriminant;
      if (!(disc.type === 'MemberExpression' && disc.object.type === 'Identifier' && disc.object.name === orderName)) continue;
      const cases = new Map<string, t.Statement[]>();
      for (const c of sw.cases) {
        const k = c.test ? staticString(c.test) : undefined;
        if (k === undefined) { cases.clear(); break; }
        const stmts = c.consequent.filter((s) => s.type !== 'ContinueStatement');
        cases.set(k, stmts);
      }
      if (!cases.size || !order.every((k) => cases.has(k))) continue;
      const out: t.Statement[] = [];
      for (const k of order) out.push(...(cases.get(k) as t.Statement[]));
      body.splice(i, next - i + 1, ...out);
      res.stats.switchesUnflattened++;
      changed = true;
      return 'stop';
    }
    return undefined;
  });
  return changed;
}

function memberProp(m: t.MemberExpression): string | undefined {
  if (!m.computed && m.property.type === 'Identifier') return m.property.name;
  return staticString(m.property);
}

/** Inline objects that only hold string constants and one-line operator functions (control flow flattening proxies). */
function inlineProxies(ast: t.File, res: DeobfuscateResult): boolean {
  let changed = false;
  type Entry = { kind: 'str'; value: string } | { kind: 'fn'; params: string[]; expr: t.Expression };
  const candidates = new Map<string, { decl: t.VariableDeclarator; props: Map<string, Entry> }>();
  walk(ast, ({ node }) => {
    if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier' || node.init?.type !== 'ObjectExpression' || node.init.properties.length === 0) return;
    const props = new Map<string, Entry>();
    for (const p of node.init.properties) {
      if (p.type !== 'ObjectProperty') return;
      const k = propKey(p);
      if (k === undefined) return;
      const val = p.value;
      if (val.type === 'StringLiteral') props.set(k, { kind: 'str', value: val.value });
      else if (val.type === 'FunctionExpression' || val.type === 'ArrowFunctionExpression') {
        const ps = paramNames(val);
        const b = fnBody(val);
        let expr: t.Node | undefined;
        if (b && b.length === 1 && b[0]?.type === 'ReturnStatement') expr = b[0].argument ?? undefined;
        else if (val.type === 'ArrowFunctionExpression' && val.body.type !== 'BlockStatement') expr = val.body;
        if (!ps || !expr) return;
        const ok = (expr.type === 'BinaryExpression' || expr.type === 'LogicalExpression') && expr.left.type === 'Identifier' && expr.right.type === 'Identifier' && ps.includes(expr.left.name) && ps.includes(expr.right.name)
          || (expr.type === 'CallExpression' && expr.callee.type === 'Identifier' && ps.includes(expr.callee.name) && expr.arguments.every((a) => a.type === 'Identifier' && ps.includes(a.name)));
        if (!ok) return;
        props.set(k, { kind: 'fn', params: ps, expr: expr as t.Expression });
      } else return;
    }
    if (candidates.has(node.id.name)) { candidates.delete(node.id.name); return; }
    candidates.set(node.id.name, { decl: node, props });
  });
  if (!candidates.size) return false;
  // every use must be a read of a known key
  walk(ast, ({ node, parent, key }) => {
    if (node.type !== 'Identifier' || !candidates.has(node.name)) return;
    const c = candidates.get(node.name)!;
    if (parent === c.decl && key === 'id') return;
    if (parent && (parent.type === 'MemberExpression') && key === 'object') {
      const k = memberProp(parent);
      if (k !== undefined && c.props.has(k)) return;
    }
    if (parent && parent.type === 'MemberExpression' && key === 'property' && !parent.computed) return;
    if (parent && parent.type === 'ObjectProperty' && key === 'key') return;
    candidates.delete(node.name);
  });
  if (!candidates.size) return false;
  const substitute = (expr: t.Expression, params: string[], args: t.Node[]): t.Expression => {
    const clone = t.cloneNode(expr, true);
    const map = new Map(params.map((p, i) => [p, args[i]]));
    const holder = { root: clone as t.Node };
    walk(t.expressionStatement(clone), (v) => {
      if (v.node.type === 'Identifier' && map.has(v.node.name) && !(v.parent?.type === 'MemberExpression' && v.key === 'property' && !v.parent.computed)) {
        const a = map.get(v.node.name);
        const repl = a ? t.cloneNode(a as t.Expression, true) : t.identifier('undefined');
        if (v.node === holder.root) holder.root = repl; else replaceAt(v, repl);
        return 'skip';
      }
      return undefined;
    });
    return holder.root as t.Expression;
  };
  for (let round = 0; round < 20; round++) {
    let did = false;
    walk(ast, (v) => {
      const n = v.node;
      if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && n.callee.object.type === 'Identifier' && candidates.has(n.callee.object.name)) {
        const e = candidates.get(n.callee.object.name)!.props.get(memberProp(n.callee) ?? '');
        if (e?.kind === 'fn' && n.arguments.length >= e.params.length && n.arguments.every((a) => a.type !== 'SpreadElement')) {
          replaceAt(v, substitute(e.expr, e.params, n.arguments)); res.stats.proxiesInlined++; did = true; return 'skip';
        }
      }
      if (n.type === 'MemberExpression' && n.object.type === 'Identifier' && candidates.has(n.object.name) && !(v.parent?.type === 'CallExpression' && v.key === 'callee')) {
        const e = candidates.get(n.object.name)!.props.get(memberProp(n) ?? '');
        if (e?.kind === 'str') { replaceAt(v, t.stringLiteral(e.value)); res.stats.proxiesInlined++; did = true; return 'skip'; }
      }
      return undefined;
    });
    if (!did) break;
    changed = true;
  }
  for (const [name, c] of candidates) {
    if (refCount(ast, name, new Set([c.decl])) === 0 && removeNode(ast, c.decl)) res.stats.helpersRemoved++;
  }
  return changed;
}

/** Deobfuscate JavaScript: decode javascript-obfuscator string arrays (none, base64, rc4), fold constants, inline proxies, unflatten switch dispatchers, drop dead branches. */
export function deobfuscate(code: string): DeobfuscateResult {
  const { ast, errors } = parseJs(code);
  const res: DeobfuscateResult = {
    code: '', changed: false, parserErrors: errors, decodedStrings: [], notes: [],
    stats: { stringsDecoded: 0, literalsNormalized: 0, constantsFolded: 0, membersSimplified: 0, deadBranchesRemoved: 0, proxiesInlined: 0, switchesUnflattened: 0, sequencesSplit: 0, helpersRemoved: 0 },
  };
  res.stats.literalsNormalized = normalizeLiterals(ast);
  try { recoverStringArray(ast, res); } catch (e) { res.notes.push(`string array step failed: ${(e as Error).message}`); }
  for (let i = 0; i < 50; i++) {
    let changed = false;
    try {
      changed = cleanupPass(ast, res) || changed;
      changed = inlineProxies(ast, res) || changed;
      changed = unflattenSwitches(ast, res) || changed;
    } catch (e) { res.notes.push(`cleanup step failed: ${(e as Error).message}`); break; }
    if (!changed) break;
  }
  normalizeLiterals(ast);
  res.code = printAst(ast);
  const s = res.stats;
  res.changed = s.stringsDecoded + s.literalsNormalized + s.constantsFolded + s.membersSimplified + s.deadBranchesRemoved + s.proxiesInlined + s.switchesUnflattened + s.sequencesSplit + s.helpersRemoved > 0;
  return res;
}

