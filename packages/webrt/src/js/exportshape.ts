// Export shapes of JavaScript modules, packages and bundles, read from the AST (nothing is run):
// exported names, what each is (function, class, object, value, re-export), function arity in the
// Function.prototype.length sense, async and generator flags, class prototype and static members with
// their arities, and object keys. compareExportShapes lists what was added, removed or changed between
// two versions. CommonJS (module.exports, exports.x, Object.defineProperty), ES modules, webpack
// export getters and esbuild __export maps are understood; relative requires and re-exports are
// followed across the files given.
import { parseJs, walk, staticString, propKey, memberName, t } from './ast.js';
import { unpackBundle } from './bundle.js';
import { normPath } from './imports.js';
import { InputError } from '../util.js';

export interface MemberShape { name: string; kind: 'method' | 'getter' | 'setter' | 'accessor' | 'field'; static: boolean; arity?: number; async?: boolean; generator?: boolean; private?: boolean }
export interface ExportShape {
  kind: 'function' | 'class' | 'object' | 'value' | 'unknown';
  arity?: number;
  async?: boolean;
  generator?: boolean;
  /** class: base class expression as text */
  extends?: string;
  members?: MemberShape[];
  /** object: own keys; function or class: extra static properties assigned later */
  keys?: string[];
  valueType?: 'string' | 'number' | 'boolean' | 'bigint' | 'null' | 'undefined' | 'regexp' | 'array' | 'template';
  /** where the export is defined: file and line */
  from?: string;
  line?: number;
  /** re-export resolved through another file */
  via?: string;
}
export interface ModuleShapes {
  format: 'esm' | 'cjs' | 'none';
  /** name -> shape. CommonJS modules list their module.exports value under "module.exports" and its keys as names. */
  exports: Record<string, ExportShape>;
  /** export * from sources that could not be followed */
  starReexports: string[];
  warnings: string[];
}

type Binding =
  | { k: 'node'; node: t.Node; line: number }
  | { k: 'require'; spec: string; prop?: string; line: number }
  | { k: 'import'; spec: string; imported: string; line: number };

const MAX_DEPTH = 12;

/** Function.prototype.length: parameters before the first default value or rest element. */
export function arityOf(params: t.Node[]): number {
  let n = 0;
  for (const p of params) {
    if (p.type === 'AssignmentPattern' || p.type === 'RestElement') break;
    if (p.type === 'TSParameterProperty' && p.parameter.type === 'AssignmentPattern') break;
    n++;
  }
  return n;
}

function keyName(key: t.Node, computed: boolean): string | undefined {
  if (!computed && key.type === 'Identifier') return key.name;
  if (key.type === 'StringLiteral') return key.value;
  if (key.type === 'NumericLiteral') return String(key.value);
  if (key.type === 'PrivateName') return `#${key.id.name}`;
  if (computed && key.type === 'MemberExpression') { const m = memberName(key); if (m?.startsWith('Symbol.')) return `[${m}]`; }
  return undefined;
}

class ShapeReader {
  private cache = new Map<string, ModuleShapes>();
  private active = new Set<string>();
  constructor(private files: Map<string, string>) {}

  resolve(from: string, spec: string): string | undefined {
    if (!spec.startsWith('.') && !spec.startsWith('/')) return undefined;
    const dir = from.includes('/') ? from.slice(0, from.lastIndexOf('/')) : '';
    const base = normPath(spec.startsWith('/') ? spec : `${dir}/${spec}`);
    for (const c of [base, `${base}.js`, `${base}.cjs`, `${base}.mjs`, `${base}.json`, `${base}/index.js`, `${base}/index.cjs`, `${base}/index.mjs`]) if (this.files.has(c)) return c;
    return undefined;
  }

  module(path: string, depth = 0): ModuleShapes {
    const hit = this.cache.get(path);
    if (hit) return hit;
    if (this.active.has(path) || depth > MAX_DEPTH) return { format: 'none', exports: {}, starReexports: [], warnings: [`cycle or depth limit at ${path}`] };
    const code = this.files.get(path);
    if (code === undefined) return { format: 'none', exports: {}, starReexports: [], warnings: [`${path} not found`] };
    this.active.add(path);
    let r: ModuleShapes;
    try {
      if (path.endsWith('.json')) {
        let v: unknown;
        try { v = JSON.parse(code); } catch { v = undefined; }
        const keys = v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v as object) : [];
        r = { format: 'cjs', exports: { 'module.exports': { kind: v && typeof v === 'object' ? 'object' : 'value', keys, from: path } }, starReexports: [], warnings: [] };
      } else {
        const { ast } = parseJs(code);
        r = this.fromStatements(ast.program.body, path, depth);
      }
    } finally { this.active.delete(path); }
    this.cache.set(path, r);
    return r;
  }

  /** Shapes for a list of statements treated as one module scope (a file, or a bundle module body). */
  fromStatements(body: t.Statement[], path: string, depth: number, extra?: { exportsName?: string; moduleName?: string; requireName?: string; getters?: Map<string, t.Node> }): ModuleShapes {
    const bindings = new Map<string, Binding>();
    const warnings: string[] = [];
    const statics = new Map<string, MemberShape[]>(); // name -> members assigned later (X.prototype.y = fn, X.y = v)
    const reqName = extra?.requireName ?? 'require';
    const exportsName = extra?.exportsName ?? 'exports';
    const moduleName = extra?.moduleName ?? 'module';
    const requireSpec = (n: t.Node | null | undefined): string | undefined => {
      if (n?.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === reqName) {
        const a = n.arguments[0];
        return a?.type === 'NumericLiteral' ? String(a.value) : staticString(a as t.Node);
      }
      return undefined;
    };
    const bind = (name: string, b: Binding) => { if (!bindings.has(name)) bindings.set(name, b); };
    const addMember = (name: string, m: MemberShape) => { const l = statics.get(name) ?? statics.set(name, []).get(name)!; if (l.length < 2000 && !l.some((x) => x.name === m.name && x.static === m.static)) l.push(m); };
    const memberFrom = (name: string, v: t.Node, isStatic: boolean): MemberShape => {
      if (v.type === 'FunctionExpression' || v.type === 'ArrowFunctionExpression') return { name, kind: 'method', static: isStatic, arity: arityOf(v.params as t.Node[]), async: v.async || undefined, generator: (v.type === 'FunctionExpression' && v.generator) || undefined };
      return { name, kind: 'field', static: isStatic };
    };
    // pass 1: declarations
    const scanDecl = (st: t.Node) => {
      const line = st.loc?.start.line ?? 0;
      if (st.type === 'FunctionDeclaration' && st.id) bind(st.id.name, { k: 'node', node: st, line });
      else if (st.type === 'ClassDeclaration' && st.id) bind(st.id.name, { k: 'node', node: st, line });
      else if (st.type === 'VariableDeclaration') {
        for (const d of st.declarations) {
          const spec = requireSpec(d.init);
          if (d.id.type === 'Identifier') {
            if (spec !== undefined) bind(d.id.name, { k: 'require', spec, line });
            else if (d.init?.type === 'MemberExpression' && !d.init.computed && d.init.property.type === 'Identifier' && requireSpec(d.init.object) !== undefined) bind(d.id.name, { k: 'require', spec: requireSpec(d.init.object)!, prop: d.init.property.name, line });
            else if (d.init) bind(d.id.name, { k: 'node', node: d.init, line });
          } else if (d.id.type === 'ObjectPattern' && spec !== undefined) {
            for (const p of d.id.properties) if (p.type === 'ObjectProperty' && p.value.type === 'Identifier') { const k = propKey(p); if (k) bind(p.value.name, { k: 'require', spec, prop: k, line }); }
          }
        }
      } else if (st.type === 'ImportDeclaration') {
        for (const s of st.specifiers) bind(s.local.name, { k: 'import', spec: st.source.value, imported: s.type === 'ImportDefaultSpecifier' ? 'default' : s.type === 'ImportNamespaceSpecifier' ? '*' : s.imported.type === 'Identifier' ? s.imported.name : s.imported.value, line });
      } else if ((st.type === 'ExportNamedDeclaration' || st.type === 'ExportDefaultDeclaration') && st.declaration) scanDecl(st.declaration);
    };
    for (const st of body) scanDecl(st);
    // pass 2: prototype and static assignments: X.prototype.m = fn, X.s = v, Object.defineProperty(X.prototype, 'm', {...})
    for (const st of body) {
      if (st.type !== 'ExpressionStatement') continue;
      const e = st.expression;
      if (e.type === 'AssignmentExpression' && e.operator === '=' && e.left.type === 'MemberExpression') {
        const target = memberName(e.left.object);
        const prop = e.left.computed ? staticString(e.left.property) : e.left.property.type === 'Identifier' ? e.left.property.name : undefined;
        if (!target || !prop) continue;
        if (target.endsWith('.prototype')) { const owner = target.slice(0, -10); if (bindings.has(owner)) addMember(owner, memberFrom(prop, e.right, false)); }
        else if (bindings.has(target) && !target.includes('.')) addMember(target, memberFrom(prop, e.right, true));
      }
    }
    const describe = (b: Binding | undefined, d: number, seen = new Set<Binding>()): ExportShape => {
      if (!b || d > MAX_DEPTH || seen.has(b)) return { kind: 'unknown' };
      seen.add(b);
      if (b.k === 'require' || b.k === 'import') {
        const target = this.resolve(path, b.spec);
        if (!target) return { kind: 'unknown', via: b.spec, line: b.line, from: path };
        const m = this.module(target, depth + 1);
        const name = b.k === 'require' ? (b.prop ?? 'module.exports') : b.imported === 'default' && m.format === 'cjs' ? 'module.exports' : b.imported;
        if (name === '*') return { kind: 'object', keys: Object.keys(m.exports).filter((k) => k !== 'default').sort(), from: target, via: b.spec };
        const s = m.exports[name];
        return s ? { ...s, via: b.spec } : { kind: 'unknown', via: b.spec, from: target };
      }
      return { ...this.shapeOfNode(b.node, (n) => describe(n.type === 'Identifier' ? bindings.get(n.name) : { k: 'node', node: n, line: n.loc?.start.line ?? 0 }, d + 1, seen), path), line: b.line, from: path };
    };
    const withStatics = (name: string | undefined, s: ExportShape): ExportShape => {
      const extraM = name ? statics.get(name) : undefined;
      if (!extraM?.length) return s;
      if (s.kind === 'class' || s.kind === 'function') {
        const members = [...(s.members ?? [])];
        for (const m of extraM) if (!members.some((x) => x.name === m.name && x.static === m.static)) members.push(m);
        return { ...s, members: sortMembers(members) };
      }
      if (s.kind === 'object') return { ...s, keys: [...new Set([...(s.keys ?? []), ...extraM.filter((m) => m.static).map((m) => m.name)])].sort() };
      return s;
    };
    const ofExpr = (n: t.Node): ExportShape => (n.type === 'Identifier' ? withStatics(n.name, describe(bindings.get(n.name), 0)) : describe({ k: 'node', node: n, line: n.loc?.start.line ?? 0 }, 0));
    // pass 3: exports
    const exports: Record<string, ExportShape> = {};
    const starReexports: string[] = [];
    let esm = false, cjs = false;
    let moduleValue: ExportShape | undefined;
    const cjsProps: Record<string, ExportShape> = {};
    const isExportsObj = (n: t.Node) => { const m = memberName(n); return m === exportsName || m === `${moduleName}.exports`; };
    const scanCjs = (e: t.Node) => {
      if (e.type === 'AssignmentExpression' && e.operator === '=') {
        const l = memberName(e.left as t.Node);
        if (l === `${moduleName}.exports`) {
          cjs = true;
          moduleValue = ofExpr(e.right);
          for (const k of Object.keys(cjsProps)) delete cjsProps[k];
          if (e.right.type === 'ObjectExpression') {
            for (const p of e.right.properties) {
              if (p.type === 'SpreadElement') { const sp = ofExpr(p.argument); for (const k of sp.keys ?? []) cjsProps[k] = { kind: 'unknown' }; continue; }
              const k = propKey(p);
              if (!k) continue;
              cjsProps[k] = p.type === 'ObjectMethod' ? this.shapeOfNode(p, () => ({ kind: 'unknown' }), path) : ofExpr(p.value as t.Node);
            }
          }
          return;
        }
        if (e.left.type === 'MemberExpression' && isExportsObj(e.left.object)) {
          const k = e.left.computed ? staticString(e.left.property) : e.left.property.type === 'Identifier' ? e.left.property.name : undefined;
          if (k && k !== '__esModule') { cjs = true; cjsProps[k] = ofExpr(e.right); }
          // chained a = b = value: keep walking the right side
          if (e.right.type === 'AssignmentExpression') scanCjs(e.right);
        }
      }
      if (e.type === 'CallExpression' && memberName(e.callee as t.Node) === 'Object.defineProperty' && e.arguments.length >= 3 && isExportsObj(e.arguments[0] as t.Node)) {
        const k = staticString(e.arguments[1] as t.Node);
        const desc = e.arguments[2];
        if (k && k !== '__esModule' && desc?.type === 'ObjectExpression') {
          cjs = true;
          let shape: ExportShape = { kind: 'unknown' };
          for (const p of desc.properties) {
            if (p.type === 'SpreadElement') continue;
            const pk = propKey(p);
            if (pk === 'value' && p.type === 'ObjectProperty') shape = ofExpr(p.value as t.Node);
            // tsc/babel re-export getters: get: function () { return m.x; }
            if (pk === 'get') { const ret = getterReturn(p); if (ret) shape = this.followMember(ret, bindings, describe, path); }
          }
          cjsProps[k] = shape;
        }
      }
      // tsc __exportStar(require("./x"), exports)
      if (e.type === 'CallExpression' && e.callee.type === 'Identifier' && /^(?:__exportStar|_exportStar|__reExport)$/.test(e.callee.name)) {
        const spec = requireSpec(e.arguments[0] as t.Node);
        const tgt = spec ? this.resolve(path, spec) : undefined;
        if (tgt) { cjs = true; const m = this.module(tgt, depth + 1); for (const [k, v] of Object.entries(m.exports)) if (k !== 'module.exports' && k !== 'default' && !(k in cjsProps)) cjsProps[k] = { ...v, via: spec }; }
        else if (spec) starReexports.push(spec);
      }
    };
    for (const st of body) {
      if (st.type === 'ExpressionStatement') {
        let e: t.Node = st.expression;
        if (e.type === 'SequenceExpression') { for (const x of e.expressions) scanCjs(x); continue; }
        scanCjs(e);
        continue;
      }
      if (st.type === 'ExportNamedDeclaration') {
        esm = true;
        if (st.declaration) {
          const d = st.declaration;
          if ((d.type === 'FunctionDeclaration' || d.type === 'ClassDeclaration') && d.id) exports[d.id.name] = withStatics(d.id.name, describe(bindings.get(d.id.name), 0));
          if (d.type === 'VariableDeclaration') for (const v of d.declarations) if (v.id.type === 'Identifier') exports[v.id.name] = withStatics(v.id.name, describe(bindings.get(v.id.name), 0));
        }
        for (const s of st.specifiers) {
          const exported = s.exported.type === 'Identifier' ? s.exported.name : s.exported.value;
          if (s.type === 'ExportNamespaceSpecifier') { exports[exported] = st.source ? describe({ k: 'import', spec: st.source.value, imported: '*', line: st.loc?.start.line ?? 0 }, 0) : { kind: 'object' }; continue; }
          if (s.type !== 'ExportSpecifier') continue;
          const local = s.local.type === 'Identifier' ? s.local.name : String((s.local as unknown as t.StringLiteral).value);
          exports[exported] = st.source ? describe({ k: 'import', spec: st.source.value, imported: local, line: st.loc?.start.line ?? 0 }, 0) : withStatics(local, describe(bindings.get(local), 0));
        }
      } else if (st.type === 'ExportDefaultDeclaration') {
        esm = true;
        const d = st.declaration;
        if ((d.type === 'FunctionDeclaration' || d.type === 'ClassDeclaration') && d.id) exports.default = withStatics(d.id.name, describe(bindings.get(d.id.name), 0));
        else exports.default = ofExpr(d as t.Node);
      } else if (st.type === 'ExportAllDeclaration') {
        esm = true;
        const tgt = this.resolve(path, st.source.value);
        if (tgt) { const m = this.module(tgt, depth + 1); for (const [k, v] of Object.entries(m.exports)) if (k !== 'default' && !(k in exports)) exports[k] = { ...v, via: st.source.value }; starReexports.push(...m.starReexports); }
        else starReexports.push(st.source.value);
      }
    }
    // bundler export maps: webpack r.d(exports, { name: () => local }), esbuild __export(target, { name: () => local })
    for (const [name, getter] of extra?.getters ?? []) exports[name] = getter.type === 'Identifier' ? withStatics(getter.name, describe(bindings.get(getter.name), 0)) : ofExpr(getter);
    walk({ type: 'Program', body, directives: [], sourceType: 'module' } as unknown as t.Node, ({ node }) => {
      if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' || node.type === 'ClassDeclaration') return 'skip';
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === '__export' && node.arguments[1]?.type === 'ObjectExpression') {
        for (const p of node.arguments[1].properties) {
          if (p.type === 'SpreadElement') continue;
          const k = propKey(p);
          const ret = getterReturn(p);
          if (k && ret) { if (memberName(node.arguments[0] as t.Node) === `${moduleName}.exports` || esm || true) cjsProps[k] = ret.type === 'Identifier' ? withStatics(ret.name, describe(bindings.get(ret.name), 0)) : ofExpr(ret); }
        }
        cjs = cjs || !esm;
      }
      return undefined;
    });
    if (esm) return { format: 'esm', exports, starReexports, warnings };
    if (cjs || moduleValue) {
      const out: Record<string, ExportShape> = { ...exports };
      out['module.exports'] = moduleValue ?? { kind: 'object', keys: Object.keys(cjsProps).sort() };
      if (moduleValue && (moduleValue.kind === 'object')) out['module.exports'] = { ...moduleValue, keys: [...new Set([...(moduleValue.keys ?? []), ...Object.keys(cjsProps)])].sort() };
      if (moduleValue && (moduleValue.kind === 'function' || moduleValue.kind === 'class')) out['module.exports'] = { ...moduleValue, keys: [...new Set([...(moduleValue.keys ?? []), ...Object.keys(cjsProps)])].sort() };
      for (const [k, v] of Object.entries(cjsProps)) out[k] = v;
      if (moduleValue?.kind === 'object' && moduleValue.keys) for (const k of moduleValue.keys) if (!(k in out)) out[k] = { kind: 'unknown' };
      return { format: 'cjs', exports: out, starReexports, warnings };
    }
    return { format: Object.keys(exports).length ? 'esm' : 'none', exports, starReexports, warnings };
  }

  /** m.x where m is a required module, as used by tsc and babel re-export getters. */
  private followMember(n: t.Node, bindings: Map<string, Binding>, describe: (b: Binding | undefined, d: number) => ExportShape, _path: string): ExportShape {
    if (n.type === 'MemberExpression' && n.object.type === 'Identifier' && !n.computed && n.property.type === 'Identifier') {
      const b = bindings.get(n.object.name);
      if (b?.k === 'require') return describe({ ...b, prop: n.property.name }, 1);
      if (b?.k === 'import') return describe({ ...b, imported: n.property.name }, 1);
    }
    if (n.type === 'Identifier') return describe(bindings.get(n.name), 1);
    return { kind: 'unknown' };
  }

  shapeOfNode(n: t.Node, follow: (n: t.Node) => ExportShape, _path: string): ExportShape {
    switch (n.type) {
      case 'FunctionDeclaration': case 'FunctionExpression': case 'ArrowFunctionExpression': case 'ObjectMethod':
        return { kind: 'function', arity: arityOf(n.params as t.Node[]), async: n.async || undefined, generator: ('generator' in n && n.generator) || undefined };
      case 'ClassDeclaration': case 'ClassExpression': {
        const members: MemberShape[] = [];
        let arity = 0;
        for (const m of n.body.body) {
          if (m.type === 'ClassMethod') {
            const name = keyName(m.key, m.computed);
            if (!name) continue;
            if (m.kind === 'constructor') { arity = arityOf(m.params as t.Node[]); continue; }
            members.push({ name, kind: m.kind === 'get' ? 'getter' : m.kind === 'set' ? 'setter' : 'method', static: m.static, arity: m.kind === 'method' ? arityOf(m.params as t.Node[]) : undefined, async: m.async || undefined, generator: m.generator || undefined });
          } else if (m.type === 'ClassPrivateMethod') {
            members.push({ name: `#${m.key.id.name}`, kind: m.kind === 'get' ? 'getter' : m.kind === 'set' ? 'setter' : 'method', static: m.static, arity: m.kind === 'method' ? arityOf(m.params as t.Node[]) : undefined, private: true });
          } else if (m.type === 'ClassProperty' || m.type === 'ClassPrivateProperty' || m.type === 'ClassAccessorProperty') {
            const name = m.type === 'ClassPrivateProperty' ? `#${m.key.id.name}` : keyName(m.key as t.Node, 'computed' in m ? !!m.computed : false);
            if (!name) continue;
            const v = m.value;
            const fnVal = v && (v.type === 'ArrowFunctionExpression' || v.type === 'FunctionExpression');
            members.push({ name, kind: m.type === 'ClassAccessorProperty' ? 'accessor' : fnVal && m.static ? 'method' : 'field', static: !!m.static, arity: fnVal ? arityOf((v as t.ArrowFunctionExpression).params as t.Node[]) : undefined, private: m.type === 'ClassPrivateProperty' || undefined });
          }
        }
        // a getter and a setter with the same name are one accessor property
        const merged: MemberShape[] = [];
        for (const m of members) {
          const twin = merged.find((x) => x.name === m.name && x.static === m.static && ((x.kind === 'getter' && m.kind === 'setter') || (x.kind === 'setter' && m.kind === 'getter')));
          if (twin) { twin.kind = 'accessor'; continue; }
          merged.push({ ...m });
        }
        const ext = n.superClass ? (memberName(n.superClass) ?? (n.superClass.type === 'CallExpression' ? `${memberName(n.superClass.callee as t.Node) ?? '?'}(...)` : '?')) : undefined;
        return { kind: 'class', arity, extends: ext, members: sortMembers(merged) };
      }
      case 'ObjectExpression': {
        const keys: string[] = [];
        for (const p of n.properties) { if (p.type === 'SpreadElement') { const s = follow(p.argument); keys.push(...(s.keys ?? [])); continue; } const k = propKey(p); if (k) keys.push(k); }
        return { kind: 'object', keys: [...new Set(keys)].sort() };
      }
      case 'StringLiteral': return { kind: 'value', valueType: 'string' };
      case 'TemplateLiteral': return { kind: 'value', valueType: 'template' };
      case 'NumericLiteral': return { kind: 'value', valueType: 'number' };
      case 'BooleanLiteral': return { kind: 'value', valueType: 'boolean' };
      case 'BigIntLiteral': return { kind: 'value', valueType: 'bigint' };
      case 'NullLiteral': return { kind: 'value', valueType: 'null' };
      case 'RegExpLiteral': return { kind: 'value', valueType: 'regexp' };
      case 'ArrayExpression': return { kind: 'value', valueType: 'array' };
      case 'UnaryExpression': return n.operator === 'void' ? { kind: 'value', valueType: 'undefined' } : n.operator === '!' ? { kind: 'value', valueType: 'boolean' } : n.operator === '-' || n.operator === '+' || n.operator === '~' ? { kind: 'value', valueType: 'number' } : n.operator === 'typeof' ? { kind: 'value', valueType: 'string' } : { kind: 'unknown' };
      case 'Identifier': return n.name === 'undefined' ? { kind: 'value', valueType: 'undefined' } : follow(n);
      case 'ParenthesizedExpression': return this.shapeOfNode(n.expression, follow, _path);
      case 'SequenceExpression': { const last = n.expressions[n.expressions.length - 1]; return last ? this.shapeOfNode(last, follow, _path) : { kind: 'unknown' }; }
      case 'CallExpression': {
        // Object.freeze({...}) and friends keep the shape of their argument
        const c = memberName(n.callee as t.Node);
        if ((c === 'Object.freeze' || c === 'Object.seal') && n.arguments[0]) return this.shapeOfNode(n.arguments[0] as t.Node, follow, _path);
        if (c === 'Object.assign' && n.arguments.length) { const keys: string[] = []; for (const a of n.arguments) keys.push(...(this.shapeOfNode(a as t.Node, follow, _path).keys ?? [])); return { kind: 'object', keys: [...new Set(keys)].sort() }; }
        if (c === 'Symbol') return { kind: 'unknown' };
        return follow(n);
      }
      case 'NewExpression': return { kind: 'object' };
      default: return { kind: 'unknown' };
    }
  }
}

function sortMembers(m: MemberShape[]): MemberShape[] { return m.sort((a, b) => Number(a.static) - Number(b.static) || a.name.localeCompare(b.name)); }

function getterReturn(p: t.ObjectProperty | t.ObjectMethod): t.Node | undefined {
  const fn = p.type === 'ObjectMethod' ? p : p.value;
  if (fn.type !== 'ArrowFunctionExpression' && fn.type !== 'FunctionExpression' && fn.type !== 'ObjectMethod') return undefined;
  if (fn.body.type !== 'BlockStatement') return fn.body;
  const ret = fn.body.body.find((s) => s.type === 'ReturnStatement') as t.ReturnStatement | undefined;
  return ret?.argument ?? undefined;
}

/** Export shapes of one module text. Relative imports are followed through `files` when given. */
export function moduleExportShapes(code: string, opts: { path?: string; files?: { path: string; code: string }[] } = {}): ModuleShapes {
  const path = normPath(opts.path ?? 'index.js');
  const files = new Map<string, string>();
  for (const f of opts.files ?? []) files.set(normPath(f.path), f.code);
  files.set(path, code);
  return new ShapeReader(files).module(path);
}

/** Export shapes of a package given its files: the entry comes from package.json exports ".", main or module, then index.js. */
export function packageExportShapes(files: { path: string; code: string }[], opts: { entry?: string; condition?: 'require' | 'import' } = {}): ModuleShapes & { entry: string; name?: string; version?: string } {
  const map = new Map<string, string>();
  for (const f of files.slice(0, 50_000)) map.set(normPath(f.path), f.code);
  let pkg: Record<string, unknown> = {};
  try { pkg = JSON.parse(map.get('package.json') ?? '{}') as Record<string, unknown>; } catch { /* no package.json */ }
  const pickExport = (v: unknown, depth = 0): string | undefined => {
    if (depth > 6) return undefined;
    if (typeof v === 'string') return v;
    if (Array.isArray(v)) { for (const x of v) { const r = pickExport(x, depth + 1); if (r) return r; } return undefined; }
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if ('.' in o) return pickExport(o['.'], depth + 1);
      for (const k of [opts.condition ?? 'require', 'node', 'default', opts.condition === 'import' ? 'import' : 'require', 'import']) if (k in o) { const r = pickExport(o[k], depth + 1); if (r) return r; }
    }
    return undefined;
  };
  const reader = new ShapeReader(map);
  const cand = opts.entry ?? pickExport(pkg.exports) ?? (opts.condition === 'import' && typeof pkg.module === 'string' ? pkg.module : undefined) ?? (typeof pkg.main === 'string' ? pkg.main : undefined) ?? 'index.js';
  const entry = reader.resolve('', cand.startsWith('.') || cand.startsWith('/') ? cand : `./${cand}`);
  if (!entry) throw new InputError(`package entry ${cand} not found among the files`);
  return { ...reader.module(entry), entry, name: typeof pkg.name === 'string' ? pkg.name : undefined, version: typeof pkg.version === 'string' ? pkg.version : undefined };
}

/** Export shapes per module of a bundle (webpack getters, esbuild __export, CommonJS bodies) plus the bundle's own top-level exports. */
export function bundleExportShapes(code: string): { bundler: string; top: ModuleShapes; modules: { id: string; path?: string; shapes: ModuleShapes }[] } {
  const b = unpackBundle(code);
  const { ast } = parseJs(code);
  const reader = new ShapeReader(new Map([['bundle.js', code]]));
  const top = reader.fromStatements(ast.program.body, 'bundle.js', 0);
  const modules: { id: string; path?: string; shapes: ModuleShapes }[] = [];
  const byRange = b.modules.map((m) => ({ m, fn: undefined as t.Node | undefined }));
  walk(ast, ({ node }) => {
    if (node.type !== 'FunctionExpression' && node.type !== 'ArrowFunctionExpression' && node.type !== 'ObjectMethod') return undefined;
    const slot = byRange.find((r) => !r.fn && (node.start ?? -1) >= r.m.start && (node.end ?? -1) <= r.m.end);
    if (slot) slot.fn = node;
    return undefined;
  });
  for (const { m, fn } of byRange) {
    if (!fn || (fn.type !== 'FunctionExpression' && fn.type !== 'ArrowFunctionExpression' && fn.type !== 'ObjectMethod') || fn.body.type !== 'BlockStatement') continue;
    const params = fn.params.map((p) => (p.type === 'Identifier' ? p.name : ''));
    const kind = b.bundler;
    const moduleName = kind === 'esbuild' ? params[1] : kind === 'browserify' ? params[1] : params[0];
    const exportsName = kind === 'esbuild' ? params[0] : kind === 'browserify' ? params[2] : params[1];
    const requireName = kind === 'esbuild' ? 'require' : kind === 'browserify' ? params[0] : params[2];
    const getters = new Map<string, t.Node>();
    walk(fn.body, ({ node }) => {
      if (node.type !== 'CallExpression') return undefined;
      const c = node.callee;
      const isD = c.type === 'MemberExpression' && !c.computed && c.property.type === 'Identifier' && c.property.name === 'd' && c.object.type === 'Identifier' && c.object.name === requireName;
      if (!isD) return undefined;
      const spec = node.arguments[1];
      if (spec?.type === 'ObjectExpression') for (const p of spec.properties) { if (p.type === 'SpreadElement') continue; const k = propKey(p); const r = getterReturn(p); if (k && r) getters.set(k, r); }
      if (node.arguments[1]?.type === 'StringLiteral' && node.arguments[2]) { const r = getterReturn({ type: 'ObjectProperty', value: node.arguments[2] } as t.ObjectProperty); if (r) getters.set((node.arguments[1] as t.StringLiteral).value, r); }
      return undefined;
    });
    const shapes = reader.fromStatements(fn.body.body, m.path ?? `module-${m.id}.js`, 0, { moduleName, exportsName, requireName, getters });
    modules.push({ id: m.id, path: m.path, shapes });
  }
  return { bundler: b.bundler, top, modules };
}

export interface ShapeChange { name: string; change: 'added' | 'removed' | 'kind' | 'arity' | 'async' | 'generator' | 'extends' | 'members' | 'keys' | 'valueType'; before?: unknown; after?: unknown; membersAdded?: string[]; membersRemoved?: string[]; membersChanged?: { name: string; before: string; after: string }[] }
export interface ShapeComparison { added: string[]; removed: string[]; changed: ShapeChange[]; same: number; breaking: number; score: number }

const memberSig = (m: MemberShape) => `${m.static ? 'static ' : ''}${m.kind}${m.arity !== undefined ? `/${m.arity}` : ''}${m.async ? ' async' : ''}${m.generator ? ' *' : ''}`;

/** Compare two sets of export shapes. Removed exports, kind changes, higher arity and removed members count as breaking. */
export function compareExportShapes(a: Record<string, ExportShape>, b: Record<string, ExportShape>): ShapeComparison {
  const added = Object.keys(b).filter((k) => !(k in a)).sort();
  const removed = Object.keys(a).filter((k) => !(k in b)).sort();
  const changed: ShapeChange[] = [];
  let same = 0, breaking = removed.length;
  for (const k of Object.keys(a).filter((x) => x in b).sort()) {
    const x = a[k]!, y = b[k]!;
    const before = changed.length;
    if (x.kind !== y.kind && x.kind !== 'unknown' && y.kind !== 'unknown') { changed.push({ name: k, change: 'kind', before: x.kind, after: y.kind }); breaking++; }
    else {
      if (x.arity !== y.arity && x.arity !== undefined && y.arity !== undefined) { changed.push({ name: k, change: 'arity', before: x.arity, after: y.arity }); if ((y.arity ?? 0) > (x.arity ?? 0)) breaking++; }
      if (!!x.async !== !!y.async) { changed.push({ name: k, change: 'async', before: !!x.async, after: !!y.async }); breaking++; }
      if (!!x.generator !== !!y.generator) { changed.push({ name: k, change: 'generator', before: !!x.generator, after: !!y.generator }); breaking++; }
      if ((x.extends ?? '') !== (y.extends ?? '')) changed.push({ name: k, change: 'extends', before: x.extends, after: y.extends });
      if (x.valueType !== y.valueType && x.valueType && y.valueType) changed.push({ name: k, change: 'valueType', before: x.valueType, after: y.valueType });
      if (x.members || y.members) {
        const key = (m: MemberShape) => `${m.static ? 'static ' : ''}${m.name}`;
        const mx = new Map((x.members ?? []).map((m) => [key(m), m])), my = new Map((y.members ?? []).map((m) => [key(m), m]));
        const ma = [...my.keys()].filter((n) => !mx.has(n)), mr = [...mx.keys()].filter((n) => !my.has(n));
        const mc = [...mx.keys()].filter((n) => my.has(n) && memberSig(mx.get(n)!) !== memberSig(my.get(n)!)).map((n) => ({ name: n, before: memberSig(mx.get(n)!), after: memberSig(my.get(n)!) }));
        if (ma.length || mr.length || mc.length) { changed.push({ name: k, change: 'members', membersAdded: ma, membersRemoved: mr, membersChanged: mc }); breaking += mr.filter((n) => !n.includes('#')).length ? 1 : 0; }
      }
      if (x.keys || y.keys) {
        const kx = new Set(x.keys ?? []), ky = new Set(y.keys ?? []);
        const ka = [...ky].filter((n) => !kx.has(n)), kr = [...kx].filter((n) => !ky.has(n));
        if (ka.length || kr.length) { changed.push({ name: k, change: 'keys', membersAdded: ka, membersRemoved: kr }); if (kr.length) breaking++; }
      }
    }
    if (changed.length === before) same++;
  }
  const total = new Set([...Object.keys(a), ...Object.keys(b)]).size;
  return { added, removed, changed, same, breaking, score: total ? Math.round((same / total) * 1000) / 1000 : 1 };
}
