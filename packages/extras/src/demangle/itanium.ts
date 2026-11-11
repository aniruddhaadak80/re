// Itanium C++ ABI demangler (GCC, Clang, ICC on ELF and Mach-O).
// Output follows GNU c++filt (libiberty) formatting so results can be diffed against it.
// Recursive descent with a depth cap, an input length cap and a node budget.

type N =
  | { k: 'name'; s: string; ctorName?: string }
  | { k: 'nested'; q: N; n: N }
  | { k: 'tmpl'; n: N; args: N[] }
  | { k: 'ptr'; t: N; op: '*' | '&' | '&&' }
  | { k: 'cv'; t: N; q: string }
  | { k: 'fn'; ret: N | null; params: N[]; cv: string; ref: string; noexcept?: string }
  | { k: 'arr'; t: N; dim: string }
  | { k: 'memptr'; cls: N; t: N }
  | { k: 'vector'; t: N; dim: string }
  | { k: 'pack'; items: N[] }
  | { k: 'expand'; t: N }
  | { k: 'special'; s: string; t: N }
  | { k: 'ctorvt'; a: N; b: N }
  | { k: 'enc'; name: N; fn: { ret: N | null; params: N[]; cv: string; ref: string } | null }
  | { k: 'local'; enc: N; entity: N }
  | { k: 'abi'; n: N; tag: string }
  | { k: 'raw'; s: string; simple?: boolean };

class Fail extends Error {}

const BUILTIN: Record<string, string> = {
  v: 'void', w: 'wchar_t', b: 'bool', c: 'char', a: 'signed char', h: 'unsigned char', s: 'short', t: 'unsigned short',
  i: 'int', j: 'unsigned int', l: 'long', m: 'unsigned long', x: 'long long', y: 'unsigned long long', n: '__int128',
  o: 'unsigned __int128', f: 'float', d: 'double', e: 'long double', g: '__float128', z: '...',
};
const DBUILTIN: Record<string, string> = {
  d: 'decimal64', e: 'decimal128', f: 'decimal32', h: 'half', i: 'char32_t', s: 'char16_t', u: 'char8_t', a: 'auto', c: 'decltype(auto)', n: 'decltype(nullptr)',
};
const LIT_SUFFIX: Record<string, string> = { i: '', j: 'u', l: 'l', m: 'ul', x: 'll', y: 'ull' };

const OPS: Record<string, [string, number]> = {
  nw: ['new', -1], na: ['new[]', -1], dl: ['delete', 1], da: ['delete[]', 1], ps: ['+', 1], ng: ['-', 1], ad: ['&', 1], de: ['*', 1],
  co: ['~', 1], pl: ['+', 2], mi: ['-', 2], ml: ['*', 2], dv: ['/', 2], rm: ['%', 2], an: ['&', 2], or: ['|', 2], eo: ['^', 2],
  aS: ['=', 2], pL: ['+=', 2], mI: ['-=', 2], mL: ['*=', 2], dV: ['/=', 2], rM: ['%=', 2], aN: ['&=', 2], oR: ['|=', 2], eO: ['^=', 2],
  ls: ['<<', 2], rs: ['>>', 2], lS: ['<<=', 2], rS: ['>>=', 2], eq: ['==', 2], ne: ['!=', 2], lt: ['<', 2], gt: ['>', 2], le: ['<=', 2],
  ge: ['>=', 2], ss: ['<=>', 2], nt: ['!', 1], aa: ['&&', 2], oo: ['||', 2], pp: ['++', 1], mm: ['--', 1], cm: [',', 2], pm: ['->*', 2],
  pt: ['->', 2], cl: ['()', -1], ix: ['[]', 2], qu: ['?', 3], st: ['sizeof ', 1], sz: ['sizeof ', 1], at: ['alignof ', 1], az: ['alignof ', 1],
  aw: ['co_await', 1],
};

const STD_SUBS: Record<string, [string, string, string]> = {
  // simple, full (used before a ctor/dtor), ctor name
  a: ['std::allocator', 'std::allocator', 'allocator'],
  b: ['std::basic_string', 'std::basic_string', 'basic_string'],
  s: ['std::string', 'std::basic_string<char, std::char_traits<char>, std::allocator<char> >', 'basic_string'],
  i: ['std::istream', 'std::basic_istream<char, std::char_traits<char> >', 'basic_istream'],
  o: ['std::ostream', 'std::basic_ostream<char, std::char_traits<char> >', 'basic_ostream'],
  d: ['std::iostream', 'std::basic_iostream<char, std::char_traits<char> >', 'basic_iostream'],
};

const MAX_LEN = 16384;
const MAX_DEPTH = 256;
const MAX_NODES = 200000;

class Parser {
  p = 0;
  subs: N[] = [];
  tparams: N[] = [];
  depth = 0;
  nodes = 0;
  endsWithTemplateArgs = false;
  lastNameKind: 'ctor' | 'conv' | 'other' = 'other';
  constructor(readonly s: string) {}

  peek(o = 0): string { return this.s[this.p + o] ?? ''; }
  eat(c: string): boolean { if (this.s.startsWith(c, this.p)) { this.p += c.length; return true; } return false; }
  need(c: string): void { if (!this.eat(c)) throw new Fail(); }
  mk<T extends N>(n: T): T { if (++this.nodes > MAX_NODES) throw new Fail(); return n; }
  enter(): void { if (++this.depth > MAX_DEPTH) throw new Fail(); }

  number(): number {
    let neg = false;
    if (this.eat('n')) neg = true;
    const st = this.p;
    while (/[0-9]/.test(this.peek())) this.p++;
    if (st === this.p) throw new Fail();
    const v = Number(this.s.slice(st, this.p));
    return neg ? -v : v;
  }
  seqId(): number {
    // base 36 digits followed by _, empty means 0
    if (this.eat('_')) return 0;
    let v = 0;
    const st = this.p;
    while (/[0-9A-Z]/.test(this.peek())) { v = v * 36 + parseInt(this.peek(), 36); this.p++; }
    if (st === this.p) throw new Fail();
    this.need('_');
    return v + 1;
  }

  // <mangled-name> ::= _Z <encoding> [. <clone-suffix>]*
  encoding(top: boolean): N {
    this.enter();
    const savedParams = this.tparams;
    try {
      const c = this.peek();
      if (c === 'T' || (c === 'G' && /[VRT]/.test(this.peek(1)))) return this.specialName();
      const saveT = this.tparams;
      this.pendingQuals = { cv: '', ref: '' };
      const name = this.name(true);
      const q = this.pendingQuals;
      this.pendingQuals = { cv: '', ref: '' };
      const ends = this.endsWithTemplateArgs;
      const kind = this.lastNameKind;
      if (this.atEnd() || (!top && (this.peek() === 'E' || this.peek() === '.'))) {
        return this.mk({ k: 'enc', name, fn: null });
      }
      let ret: N | null = null;
      if (ends && kind === 'other') ret = this.type();
      const params: N[] = [];
      while (!this.atEnd() && this.peek() !== 'E' && this.peek() !== '.') params.push(this.type());
      if (!params.length) throw new Fail();
      void saveT;
      return this.mk({ k: 'enc', name, fn: { ret, params, cv: q.cv, ref: q.ref } });
    } finally { this.depth--; if (!top) this.tparams = savedParams; }
  }
  atEnd(): boolean { return this.p >= this.s.length; }
  pendingQuals = { cv: '', ref: '' };

  specialName(): N {
    if (this.eat('TV')) return this.mk({ k: 'special', s: 'vtable for ', t: this.type() });
    if (this.eat('TT')) return this.mk({ k: 'special', s: 'VTT for ', t: this.type() });
    if (this.eat('TI')) return this.mk({ k: 'special', s: 'typeinfo for ', t: this.type() });
    if (this.eat('TS')) return this.mk({ k: 'special', s: 'typeinfo name for ', t: this.type() });
    if (this.eat('TA')) return this.mk({ k: 'special', s: 'template parameter object for ', t: this.templateArg() });
    if (this.eat('Th')) { this.callOffsetBody('h'); return this.mk({ k: 'special', s: 'non-virtual thunk to ', t: this.encoding(false) }); }
    if (this.eat('Tv')) { this.callOffsetBody('v'); return this.mk({ k: 'special', s: 'virtual thunk to ', t: this.encoding(false) }); }
    if (this.eat('Tc')) { this.callOffset(); this.callOffset(); return this.mk({ k: 'special', s: 'covariant return thunk to ', t: this.encoding(false) }); }
    if (this.eat('TC')) {
      const a = this.type();
      this.number();
      this.need('_');
      const b = this.type();
      return this.mk({ k: 'ctorvt', a, b });
    }
    if (this.eat('TH')) return this.mk({ k: 'special', s: 'TLS init function for ', t: this.name(false) });
    if (this.eat('TW')) return this.mk({ k: 'special', s: 'TLS wrapper function for ', t: this.name(false) });
    if (this.eat('GV')) return this.mk({ k: 'special', s: 'guard variable for ', t: this.name(false) });
    if (this.eat('GR')) {
      const n = this.name(false);
      let idx = 0;
      if (this.peek() !== '_') idx = this.seqId(); else this.p++;
      void idx;
      return this.mk({ k: 'special', s: `reference temporary #${idx === 0 ? 0 : idx - 1} for `, t: n });
    }
    if (this.eat('GTt')) return this.mk({ k: 'special', s: 'transaction clone for ', t: this.encoding(false) });
    if (this.eat('GTn')) return this.mk({ k: 'special', s: 'non-transaction clone for ', t: this.encoding(false) });
    throw new Fail();
  }
  callOffset(): void { const c = this.peek(); this.p++; this.callOffsetBody(c); }
  callOffsetBody(c: string): void {
    if (c === 'h') { this.number(); this.need('_'); }
    else if (c === 'v') { this.number(); this.need('_'); this.number(); this.need('_'); }
    else throw new Fail();
  }

  // <name>
  name(top: boolean): N {
    this.enter();
    try {
      this.lastNameKind = 'other';
      this.endsWithTemplateArgs = false;
      const c = this.peek();
      if (c === 'N') return this.nestedName(top);
      if (c === 'Z') return this.localName(top);
      let isSubst = false;
      let r: N;
      if (c === 'S' && this.peek(1) !== 't') {
        r = this.substitution(false);
        isSubst = true;
      } else {
        this.eat('St') ? (r = this.mk({ k: 'nested', q: { k: 'name', s: 'std' }, n: this.unqualifiedName(null) })) : (r = this.unqualifiedName(null));
      }
      const kind = this.lastNameKind;
      if (this.peek() === 'I') {
        if (!isSubst) this.subs.push(r);
        const args = this.templateArgs(top);
        this.lastNameKind = kind;
        r = this.mk({ k: 'tmpl', n: r, args });
        this.endsWithTemplateArgs = true;
      } else if (isSubst) throw new Fail();
      return r;
    } finally { this.depth--; }
  }

  nestedName(top: boolean): N {
    this.need('N');
    let cv = '';
    for (;;) {
      if (this.eat('r')) cv = ' restrict' + cv;
      else if (this.eat('V')) cv = ' volatile' + cv;
      else if (this.eat('K')) cv = ' const' + cv;
      else break;
    }
    // libiberty prints const before volatile
    cv = qualOrder(cv);
    let ref = '';
    if (this.eat('R')) ref = ' &'; else if (this.eat('O')) ref = ' &&';
    let so: N | null = null;
    let kind: 'ctor' | 'conv' | 'other' = 'other';
    while (!this.eat('E')) {
      this.endsWithTemplateArgs = false;
      const c = this.peek();
      if (c === '') throw new Fail();
      if (c === 'T') {
        if (so) throw new Fail();
        so = this.templateParam();
      } else if (c === 'I') {
        if (!so) throw new Fail();
        const args = this.templateArgs(top);
        so = this.mk({ k: 'tmpl', n: so, args });
        this.endsWithTemplateArgs = true;
      } else if (c === 'D' && (this.peek(1) === 't' || this.peek(1) === 'T')) {
        if (so) throw new Fail();
        so = this.decltype();
      } else if (c === 'S' && this.peek(1) === 't') {
        this.p += 2;
        if (so) throw new Fail();
        so = this.mk({ k: 'name', s: 'std' });
        continue;
      } else if (c === 'S') {
        if (so) throw new Fail();
        const nextIsCtor = true;
        so = this.substitution(nextIsCtor);
        continue;
      } else {
        this.lastNameKind = 'other';
        const u = this.unqualifiedName(so);
        kind = this.lastNameKind;
        so = so ? this.mk({ k: 'nested', q: so, n: u }) : u;
      }
      this.subs.push(so);
      this.eat('M');
    }
    if (!so) throw new Fail();
    this.subs.pop();
    this.lastNameKind = kind;
    if (top) this.pendingQuals = { cv, ref };
    return so;
  }

  localName(top: boolean): N {
    this.need('Z');
    const saved = this.pendingQuals;
    const enc = this.encoding(false);
    this.pendingQuals = saved;
    // c++filt never prints the return type of the function a local entity lives in
    if (enc.k === 'enc' && enc.fn) enc.fn = { ...enc.fn, ret: null };
    this.need('E');
    if (this.eat('s')) {
      this.discriminator();
      return this.mk({ k: 'local', enc, entity: { k: 'name', s: 'string literal' } });
    }
    if (this.eat('d')) {
      // default argument scope
      let num = 1;
      if (this.peek() !== '_') num = this.number() + 2;
      this.need('_');
      const e = this.name(top);
      return this.mk({ k: 'local', enc, entity: { k: 'nested', q: { k: 'name', s: `{default arg#${num}}` }, n: e } });
    }
    const e = this.name(top);
    this.discriminator();
    return this.mk({ k: 'local', enc, entity: e });
  }
  discriminator(): void {
    if (this.eat('__')) { this.number(); this.need('_'); }
    else if (this.peek() === '_' && /[0-9]/.test(this.peek(1))) { this.p++; this.number(); }
  }

  unqualifiedName(scope: N | null): N {
    const c = this.peek();
    let r: N;
    if (/[0-9]/.test(c)) r = this.sourceName();
    else if (c === 'L') { this.p++; r = this.sourceName(); this.discriminator(); }
    else if (c === 'C' || (c === 'D' && /[0-2459]/.test(this.peek(1)))) r = this.ctorDtor(scope);
    else if (c === 'U') r = this.unnamedType();
    else if (c === 'D' && this.peek(1) === 'C') {
      this.p += 2;
      const names: string[] = [];
      while (!this.eat('E')) names.push((this.sourceName() as { s: string }).s);
      r = this.mk({ k: 'name', s: `[${names.join(', ')}]` });
    } else if (/[a-z]/.test(c)) r = this.operatorName();
    else throw new Fail();
    while (this.eat('B')) {
      const tag = this.sourceName() as { s: string };
      r = this.mk({ k: 'abi', n: r, tag: tag.s });
    }
    return r;
  }

  sourceName(): N {
    const len = this.number();
    if (len <= 0 || this.p + len > this.s.length) throw new Fail();
    const id = this.s.slice(this.p, this.p + len);
    this.p += len;
    if (id.startsWith('_GLOBAL_') && /^_GLOBAL_[._$]N/.test(id)) return this.mk({ k: 'name', s: '(anonymous namespace)' });
    return this.mk({ k: 'name', s: id });
  }

  ctorDtor(scope: N | null): N {
    let base = scope ? lastName(scope) : '';
    if (!base) throw new Fail();
    if (this.eat('C')) {
      this.eat('I');
      if (!/[1-5]/.test(this.peek())) throw new Fail();
      this.p++;
      this.lastNameKind = 'ctor';
      return this.mk({ k: 'name', s: base });
    }
    this.need('D');
    if (!/[0-5]/.test(this.peek())) throw new Fail();
    this.p++;
    this.lastNameKind = 'ctor';
    base = '~' + base;
    return this.mk({ k: 'name', s: base });
  }

  unnamedType(): N {
    if (this.eat('Ut')) {
      let n = 1;
      if (this.peek() !== '_') n = this.number() + 2; else n = 1;
      this.need('_');
      return this.mk({ k: 'name', s: `{unnamed type#${n}}` });
    }
    if (this.eat('Ul')) {
      const params: N[] = [];
      const prevLambda = this.inLambda;
      this.inLambda = true;
      try { while (!this.eat('E')) params.push(this.type()); } finally { this.inLambda = prevLambda; }
      let n = 1;
      if (this.peek() !== '_') n = this.number() + 2;
      this.need('_');
      const ps = params.length === 1 && params[0]?.k === 'name' && params[0].s === 'void' ? '' : params.map(pr).join(', ');
      return this.mk({ k: 'name', s: `{lambda(${ps})#${n}}` });
    }
    throw new Fail();
  }

  operatorName(): N {
    const two = this.s.slice(this.p, this.p + 2);
    if (two === 'cv') {
      this.p += 2;
      const t = this.type();
      this.lastNameKind = 'conv';
      return this.mk({ k: 'name', s: 'operator ' + pr(t) });
    }
    if (two === 'li') { this.p += 2; const n = this.sourceName() as { s: string }; return this.mk({ k: 'name', s: `operator"" ${n.s}` }); }
    if (two[0] === 'v' && /[0-9]/.test(two[1] ?? '')) { this.p += 2; const n = this.sourceName() as { s: string }; return this.mk({ k: 'name', s: 'operator ' + n.s }); }
    const op = OPS[two];
    if (!op) throw new Fail();
    this.p += 2;
    const sym = op[0];
    return this.mk({ k: 'name', s: /^[a-z]/.test(sym) ? 'operator ' + sym.trim() : 'operator' + sym });
  }

  substitution(beforeCtorPossible: boolean): N {
    this.need('S');
    const c = this.peek();
    if (STD_SUBS[c]) {
      this.p++;
      const [simple, full, ctorName] = STD_SUBS[c] as [string, string, string];
      // c++filt runs in verbose mode, which always prints the full expansion
      void simple; void beforeCtorPossible;
      return this.mk({ k: 'name', s: full, ctorName });
    }
    const id = this.seqId();
    const r = this.subs[id];
    if (!r) throw new Fail();
    return r;
  }

  inLambda = false;
  templateParam(): N {
    this.need('T');
    const id = this.seqId();
    if (this.inLambda) return this.mk({ k: 'name', s: `auto:${id + 1}` });
    const r = this.tparams[id];
    if (!r) {
      // forward reference inside a conversion operator or unresolved: keep symbolic
      return this.mk({ k: 'name', s: id === 0 ? 'T_' : `T${id - 1}_` });
    }
    return r;
  }

  templateArgs(tag: boolean): N[] {
    this.need('I');
    const args: N[] = [];
    const list: N[] = [];
    if (tag) this.tparams = list;
    while (!this.eat('E')) {
      const a = this.templateArg();
      args.push(a);
      if (tag) { list.push(a); this.tparams = list; }
      if (args.length > 4096) throw new Fail();
    }
    if (tag) { this.tparamsTop = this.tparams; }
    return args;
  }
  tparamsTop: N[] = [];

  templateArg(): N {
    const c = this.peek();
    if (c === 'X') { this.p++; const e = this.expression(); this.need('E'); return e; }
    if (c === 'L') return this.exprPrimary();
    if (c === 'J') {
      this.p++;
      const items: N[] = [];
      while (!this.eat('E')) items.push(this.templateArg());
      return this.mk({ k: 'pack', items });
    }
    return this.type();
  }

  exprPrimary(): N {
    this.need('L');
    if (this.peek() === '_' && this.peek(1) === 'Z') {
      this.p += 2;
      const e = this.encoding(false);
      this.need('E');
      return e;
    }
    if (this.eat('Z')) { const e = this.encoding(false); this.need('E'); return e; }
    const t = this.type();
    let neg = false;
    if (this.eat('n')) neg = true;
    const st = this.p;
    while (this.peek() !== 'E' && this.peek() !== '') this.p++;
    const lit = this.s.slice(st, this.p);
    this.need('E');
    const tn = t.k === 'name' ? t.s : '';
    if (tn === 'bool' && (lit === '0' || lit === '1')) return this.mk({ k: 'raw', s: lit === '1' ? 'true' : 'false' });
    const code = Object.entries(BUILTIN).find(([, v]) => v === tn)?.[0];
    if (code && LIT_SUFFIX[code] !== undefined && /^[0-9]+$/.test(lit)) return this.mk({ k: 'raw', s: (neg ? '-' : '') + lit + LIT_SUFFIX[code] });
    if (tn === 'decltype(nullptr)' && lit === '') return this.mk({ k: 'raw', s: '(decltype(nullptr))0' });
    return this.mk({ k: 'raw', s: `(${pr(t)})${neg ? '-' : ''}${lit}` });
  }

  decltype(): N {
    this.need('D');
    if (!this.eat('t') && !this.eat('T')) throw new Fail();
    const e = this.expression();
    this.need('E');
    return this.mk({ k: 'raw', s: `decltype (${pr(e)})` });
  }

  expression(): N {
    this.enter();
    try {
      const c = this.peek();
      if (c === 'L') return this.exprPrimary();
      if (c === 'T') return this.templateParam();
      if (this.eat('fp')) {
        while (/[rVK]/.test(this.peek())) this.p++;
        const n = this.peek() === '_' ? 0 : this.number() + 1;
        this.need('_');
        return this.mk({ k: 'raw', s: `{parm#${n + 1}}`, simple: true });
      }
      if (this.eat('sZ')) {
        const t = this.peek() === 'T' ? this.templateParam() : this.expression();
        if (t.k === 'pack') return this.mk({ k: 'raw', s: String(t.items.length) });
        return this.mk({ k: 'raw', s: `sizeof...(${pr(t)})` });
      }
      if (this.eat('st')) { const t = this.type(); return this.mk({ k: 'raw', s: `sizeof (${pr(t)})` }); }
      if (this.eat('at')) { const t = this.type(); return this.mk({ k: 'raw', s: `alignof (${pr(t)})` }); }
      if (this.eat('cv')) {
        const t = this.type();
        if (this.eat('_')) { const xs: N[] = []; while (!this.eat('E')) xs.push(this.expression()); return this.mk({ k: 'raw', s: `${pr(t)}(${xs.map(pr).join(', ')})` }); }
        const e = this.expression();
        return this.mk({ k: 'raw', s: `(${pr(t)})${sub(e)}` });
      }
      if (this.eat('cl')) {
        const f = this.expression();
        const xs: N[] = [];
        while (!this.eat('E')) xs.push(this.expression());
        return this.mk({ k: 'raw', s: `${sub(f)}(${xs.map(pr).join(', ')})` });
      }
      if (this.eat('dt') || this.eat('pt')) {
        const op = this.s[this.p - 1] === 't' && this.s[this.p - 2] === 'd' ? '.' : '->';
        const a = this.expression();
        const b = this.unresolvedName();
        return this.mk({ k: 'raw', s: `${sub(a)}${op}${pr(b)}` });
      }
      if (this.eat('sr')) { this.p -= 2; return this.unresolvedName(); }
      const gs = this.eat('gs');
      if (this.eat('nw') || this.eat('na')) {
        const arr = this.s[this.p - 1] === 'a';
        const place: N[] = [];
        while (!this.eat('_')) place.push(this.expression());
        const t = this.type();
        let init = '';
        if (this.eat('pi')) { const xs: N[] = []; while (!this.eat('E')) xs.push(this.expression()); init = `(${xs.map(pr).join(', ')})`; }
        else this.need('E');
        const head = (gs ? '::' : '') + (arr ? 'new[]' : 'new');
        return this.mk({ k: 'raw', s: `${head} ${place.length ? `(${place.map(pr).join(', ')}) ` : ''}${pr(t)}${init}` });
      }
      if (gs) this.p -= 2;
      if (this.eat('sp')) { const e = this.expression(); return this.mk({ k: 'raw', s: `${pr(e)}...` }); }
      const two = this.s.slice(this.p, this.p + 2);
      const op = OPS[two];
      if (op && op[1] >= 1) {
        this.p += 2;
        if (op[1] === 1) {
          const a = this.expression();
          // libiberty prints &f for the address of a function literal, without its parameters
          if (a.k === 'enc') {
            if (!a.fn || (!a.fn.ret && !a.fn.cv && !a.fn.ref)) return this.mk({ k: 'raw', s: `${op[0]}${pr(a.name)}` });
            return this.mk({ k: 'raw', s: `${op[0]}(${pr(a)})` });
          }
          return this.mk({ k: 'raw', s: `${op[0]}${sub(a)}` });
        }
        if (op[1] === 2) { const a = this.expression(); const b = this.expression(); return this.mk({ k: 'raw', s: `${sub(a)}${op[0]}${sub(b)}` }); }
        const a = this.expression(); const b = this.expression(); const d = this.expression();
        return this.mk({ k: 'raw', s: `${sub(a)}?${sub(b)}:${sub(d)}` });
      }
      return this.unresolvedName();
    } finally { this.depth--; }
  }

  unresolvedName(): N {
    this.eat('gs');
    if (this.eat('sr')) {
      if (this.eat('N')) {
        let q = this.unresolvedType();
        while (!this.eat('E')) q = this.mk({ k: 'nested', q, n: this.simpleId() });
        return this.mk({ k: 'nested', q, n: this.baseUnresolved() });
      }
      let q: N;
      if (/[0-9]/.test(this.peek())) {
        q = this.simpleId();
        while (!this.eat('E')) q = this.mk({ k: 'nested', q, n: this.simpleId() });
      } else q = this.unresolvedType();
      return this.mk({ k: 'nested', q, n: this.baseUnresolved() });
    }
    return this.baseUnresolved();
  }
  unresolvedType(): N {
    const c = this.peek();
    let q: N;
    if (c === 'T') { q = this.templateParam(); this.subs.push(q); }
    else if (c === 'D') { q = this.decltype(); this.subs.push(q); }
    else if (c === 'S') q = this.substitution(false);
    else return this.simpleId();
    if (this.peek() === 'I') { q = this.mk({ k: 'tmpl', n: q, args: this.templateArgs(false) }); this.subs.push(q); }
    return q;
  }
  simpleId(): N {
    let n = this.sourceName();
    if (this.peek() === 'I') n = this.mk({ k: 'tmpl', n, args: this.templateArgs(false) });
    return n;
  }
  baseUnresolved(): N {
    if (/[0-9]/.test(this.peek())) return this.simpleId();
    if (this.eat('dn')) { const t = /[0-9]/.test(this.peek()) ? this.simpleId() : this.type(); return this.mk({ k: 'raw', s: '~' + pr(t) }); }
    this.eat('on');
    let n = this.operatorName();
    if (this.peek() === 'I') n = this.mk({ k: 'tmpl', n, args: this.templateArgs(false) });
    return n;
  }

  type(): N {
    this.enter();
    try { return this.typeInner(); } finally { this.depth--; }
  }
  typeInner(): N {
    const c = this.peek();
    if (BUILTIN[c]) { this.p++; return this.mk({ k: 'name', s: BUILTIN[c] as string }); }
    let r: N;
    switch (c) {
      case 'u': {
        this.p++;
        const n = this.sourceName();
        if (this.peek() === 'I') { r = this.mk({ k: 'tmpl', n, args: this.templateArgs(false) }); } else r = n;
        break;
      }
      case 'D': {
        const d = this.peek(1);
        if (DBUILTIN[d]) { this.p += 2; return this.mk({ k: 'name', s: DBUILTIN[d] as string }); }
        if (d === 'F') {
          // DF <number> _ : _FloatN
          this.p += 2;
          const n = this.number();
          if (this.eat('x')) return this.mk({ k: 'name', s: `_Float${n}x` });
          this.need('_');
          return this.mk({ k: 'name', s: `_Float${n}` });
        }
        if (d === 'B' || d === 'U') {
          this.p += 2;
          const signedB = d === 'B';
          let n: string;
          if (/[0-9]/.test(this.peek())) n = String(this.number()); else n = pr(this.expression());
          this.need('_');
          return this.mk({ k: 'name', s: `${signedB ? '' : 'unsigned '}_BitInt(${n})` });
        }
        if (d === 'p') { this.p += 2; r = this.mk({ k: 'expand', t: this.type() }); break; }
        if (d === 't' || d === 'T') { r = this.decltype(); break; }
        if (d === 'v') {
          this.p += 2;
          let dim = '';
          if (/[0-9]/.test(this.peek())) dim = String(this.number());
          else { this.need('_'); dim = pr(this.expression()); }
          this.need('_');
          r = this.mk({ k: 'vector', t: this.type(), dim });
          break;
        }
        if (d === 'x' || d === 'o' || d === 'O' || d === 'w') {
          // exception specs on function types: Do noexcept, DO <expr> E, Dw <types> E, Dx transaction_safe
          this.p += 2;
          let noexcept = '';
          if (d === 'o') noexcept = ' noexcept';
          else if (d === 'O') { const e = this.expression(); this.need('E'); noexcept = ` noexcept(${pr(e)})`; }
          else if (d === 'w') { const ts: N[] = []; while (!this.eat('E')) ts.push(this.type()); noexcept = ` throw(${ts.map(pr).join(', ')})`; }
          const f = this.type();
          if (f.k === 'fn') f.noexcept = (f.noexcept ?? '') + noexcept;
          return f;
        }
        throw new Fail();
      }
      case 'r': case 'V': case 'K': {
        let q = '';
        for (;;) {
          if (this.eat('r')) q += ' restrict';
          else if (this.eat('V')) q += ' volatile';
          else if (this.eat('K')) q += ' const';
          else break;
        }
        q = qualOrder(q);
        const t = this.type();
        if (t.k === 'fn') { if (this.subs[this.subs.length - 1] === t) this.subs.pop(); r = { ...t, cv: q + t.cv }; } else r = applyCv(t, q);
        break;
      }
      case 'U': {
        this.p++;
        const n = this.sourceName() as { s: string };
        if (this.peek() === 'I') this.templateArgs(false);
        const t = this.type();
        r = this.mk({ k: 'cv', t, q: ' ' + n.s });
        break;
      }
      case 'P': { this.p++; r = this.mk({ k: 'ptr', t: this.type(), op: '*' }); break; }
      case 'R': case 'O': {
        this.p++;
        const t = this.type();
        let op: '&' | '&&' = c === 'R' ? '&' : '&&';
        let inner = t;
        // reference collapsing
        if (inner.k === 'ptr' && (inner.op === '&' || inner.op === '&&')) { if (inner.op === '&') op = '&'; inner = inner.t; }
        r = this.mk({ k: 'ptr', t: inner, op });
        break;
      }
      case 'F': {
        this.p++;
        this.eat('Y');
        const ret = this.type();
        const params: N[] = [];
        let ref = '';
        for (;;) {
          if (this.eat('E')) break;
          if (this.peek() === 'R' && this.peek(1) === 'E') { this.p += 2; ref = ' &'; break; }
          if (this.peek() === 'O' && this.peek(1) === 'E') { this.p += 2; ref = ' &&'; break; }
          if (this.peek() === '') throw new Fail();
          params.push(this.type());
        }
        r = this.mk({ k: 'fn', ret, params, cv: '', ref });
        break;
      }
      case 'A': {
        this.p++;
        let dim = '';
        if (/[0-9]/.test(this.peek())) dim = String(this.number());
        else if (this.peek() !== '_') dim = pr(this.expression());
        this.need('_');
        r = this.mk({ k: 'arr', t: this.type(), dim });
        break;
      }
      case 'M': {
        this.p++;
        const cls = this.type();
        const t = this.type();
        r = this.mk({ k: 'memptr', cls, t });
        break;
      }
      case 'T': {
        if (/[sue]/.test(this.peek(1))) { this.p += 2; r = this.name(false); break; }
        r = this.templateParam();
        if (this.peek() === 'I') {
          this.subs.push(r);
          r = this.mk({ k: 'tmpl', n: r, args: this.templateArgs(false) });
        }
        break;
      }
      case 'S': {
        if (this.peek(1) !== 't') {
          const sub = this.substitution(false);
          if (this.peek() === 'I') {
            r = this.mk({ k: 'tmpl', n: sub, args: this.templateArgs(false) });
            break;
          }
          return sub;
        }
        r = this.name(false);
        break;
      }
      case 'C': { this.p++; r = this.mk({ k: 'cv', t: this.type(), q: ' _Complex' }); break; }
      case 'G': { this.p++; r = this.mk({ k: 'cv', t: this.type(), q: ' _Imaginary' }); break; }
      default:
        if (c === 'N' || c === 'Z' || /[0-9]/.test(c)) { r = this.name(false); break; }
        throw new Fail();
    }
    this.subs.push(r);
    return r;
  }
}

function applyCv(t: N, q: string): N {
  if (t.k === 'arr') return { k: 'arr', t: applyCv(t.t, q), dim: t.dim };
  if (t.k === 'cv') return { k: 'cv', t: t.t, q: qualOrder(t.q + q) };
  return { k: 'cv', t, q };
}
function collapse(n: N): N {
  let cur = n;
  while (cur.k === 'ptr' && cur.op !== '*' && cur.t.k === 'ptr' && cur.t.op !== '*') {
    const op: '&' | '&&' = cur.op === '&' || cur.t.op === '&' ? '&' : '&&';
    cur = { k: 'ptr', t: cur.t.t, op };
  }
  return cur;
}
function findPack(n: N, depth = 0): N | null {
  if (depth > 64) return null;
  switch (n.k) {
    case 'pack': return n;
    case 'ptr': case 'cv': case 'arr': case 'vector': return findPack(n.t, depth + 1);
    case 'memptr': return findPack(n.cls, depth + 1) ?? findPack(n.t, depth + 1);
    case 'tmpl': { for (const a of n.args) { const f = findPack(a, depth + 1); if (f) return f; } return null; }
    case 'fn': { for (const a of n.params) { const f = findPack(a, depth + 1); if (f) return f; } return n.ret ? findPack(n.ret, depth + 1) : null; }
    default: return null;
  }
}
function replaceNode(n: N, from: N, to: N, depth = 0): N {
  if (n === from) return to;
  if (depth > 64) return n;
  switch (n.k) {
    case 'ptr': return collapse({ k: 'ptr', t: replaceNode(n.t, from, to, depth + 1), op: n.op });
    case 'cv': return applyCv(replaceNode(n.t, from, to, depth + 1), n.q);
    case 'arr': return { k: 'arr', t: replaceNode(n.t, from, to, depth + 1), dim: n.dim };
    case 'vector': return { k: 'vector', t: replaceNode(n.t, from, to, depth + 1), dim: n.dim };
    case 'memptr': return { k: 'memptr', cls: replaceNode(n.cls, from, to, depth + 1), t: replaceNode(n.t, from, to, depth + 1) };
    case 'tmpl': return { k: 'tmpl', n: n.n, args: n.args.map((a) => replaceNode(a, from, to, depth + 1)) };
    case 'fn': return { ...n, ret: n.ret ? replaceNode(n.ret, from, to, depth + 1) : null, params: n.params.map((a) => replaceNode(a, from, to, depth + 1)) };
    default: return n;
  }
}
function expandItems(n: N): N[] | null {
  const pk = findPack(n);
  if (!pk || pk.k !== 'pack') return null;
  return pk.items.map((it) => replaceNode(n, pk, it));
}

function qualOrder(q: string): string {
  let out = '';
  if (q.includes(' const')) out += ' const';
  if (q.includes(' volatile')) out += ' volatile';
  if (q.includes(' restrict')) out += ' restrict';
  return out;
}

function lastName(n: N): string {
  switch (n.k) {
    case 'name': return n.ctorName ?? n.s;
    case 'nested': return lastName(n.n);
    case 'tmpl': return lastName(n.n);
    case 'abi': return lastName(n.n);
    case 'local': return lastName(n.entity);
    default: return '';
  }
}

// ---------- printing ----------
function hasRHS(n: N): boolean {
  if (n.k === 'fn' || n.k === 'arr') return true;
  if (n.k === 'ptr' || n.k === 'memptr') return false;
  if (n.k === 'cv') return hasRHS(n.t);
  return false;
}
function isFnOrArr(n: N): boolean { return n.k === 'fn' || n.k === 'arr' || (n.k === 'cv' && isFnOrArr(n.t)); }

function left(n: N): string {
  switch (n.k) {
    case 'ptr': {
      if (isFnOrArr(n.t)) {
        const l = left(n.t);
        return l + (n.t.k === 'arr' || (n.t.k === 'cv' && n.t.t.k === 'arr') ? ' (' : '(') + n.op;
      }
      return left(n.t) + n.op;
    }
    case 'memptr': {
      if (isFnOrArr(n.t)) return left(n.t) + '(' + pr(n.cls) + '::*';
      return left(n.t) + ' ' + pr(n.cls) + '::*';
    }
    case 'cv': {
      if (isFnOrArr(n.t)) return left(n.t);
      return left(n.t) + n.q;
    }
    case 'fn': return n.ret ? left(n.ret) + (hasRHS(n.ret) ? '' : ' ') : '';
    case 'arr': return left(n.t);
    default: return pr(n);
  }
}
function right(n: N): string {
  switch (n.k) {
    case 'ptr': return isFnOrArr(n.t) ? ')' + right(n.t) : right(n.t);
    case 'memptr': return isFnOrArr(n.t) ? ')' + right(n.t) : right(n.t);
    case 'cv': return isFnOrArr(n.t) ? right(n.t) + n.q : right(n.t);
    case 'fn': return '(' + params(n.params) + ')' + n.cv + n.ref + (n.noexcept ?? '') + (n.ret ? right(n.ret) : '');
    case 'arr': return ' [' + n.dim + ']' + right(n.t).replace(/^ \[/, '[');
    default: return '';
  }
}
function params(ps: N[]): string {
  if (ps.length === 1 && ps[0]?.k === 'name' && ps[0].s === 'void') return '';
  return ps.map(pr).filter((s) => s !== '').join(', ');
}
function isSimple(n: N): boolean {
  return n.k === 'name' || n.k === 'nested' || (n.k === 'raw' && n.simple === true);
}
function sub(n: N): string { return isSimple(n) ? pr(n) : '(' + pr(n) + ')'; }
function targs(args: N[]): string {
  // Mirrors libiberty: an empty trailing pack removes its ", " but leaves the
  // last seen character as a space, so no space is added before the closing '>'.
  let out = '';
  let last = '<';
  args.forEach((a, i) => {
    const s = pr(a);
    if (i === 0) { out += s; if (s) last = s[s.length - 1] as string; return; }
    if (s === '') { last = ' '; return; }
    out += ', ' + s;
    last = s[s.length - 1] as string;
  });
  return '<' + out + (last === '>' ? ' >' : '>');
}

export function pr(n: N): string {
  switch (n.k) {
    case 'name': return n.s;
    case 'raw': return n.s;
    case 'nested': return pr(n.q) + '::' + pr(n.n);
    case 'tmpl': { const h = pr(n.n); return h + (h.endsWith('<') ? ' ' : '') + targs(n.args); }
    case 'abi': return pr(n.n) + `[abi:${n.tag}]`;
    case 'ptr': { const c = collapse(n); if (c !== n) return pr(c); return left(n) + right(n); }
    case 'memptr': case 'cv': case 'fn': case 'arr': return left(n) + right(n);
    case 'vector': return `${pr(n.t)} __vector(${n.dim})`;
    case 'pack': return n.items.map(pr).join(', ');
    case 'expand': { const items = expandItems(n.t); return items ? items.map(pr).join(', ') : pr(n.t) + '...'; }
    case 'special': return n.s + pr(n.t);
    case 'ctorvt': return `construction vtable for ${pr(n.b)}-in-${pr(n.a)}`;
    case 'local': return pr(n.enc) + '::' + pr(n.entity);
    case 'enc': {
      if (!n.fn) return pr(n.name);
      const { ret, params: ps, cv, ref } = n.fn;
      let s = '';
      if (ret) s += left(ret) + (hasRHS(ret) ? '' : ' ');
      s += pr(n.name) + '(' + params(ps) + ')';
      if (ret) s += right(ret);
      return s + cv + ref;
    }
  }
}

export interface DemangleResult { input: string; demangled: string | null; scheme: 'itanium' }

/** Demangle one Itanium C++ symbol. Returns null when the input is not a valid mangled name. */
export function demangleItanium(sym: string): string | null {
  if (typeof sym !== 'string' || sym.length > MAX_LEN) return null;
  let s = sym;
  if (s.startsWith('__Z')) s = s.slice(1);
  if (!s.startsWith('_Z')) {
    // block invocation and type names are not handled here
    return null;
  }
  // split clone suffixes like .cold or .isra.0
  let body = s.slice(2);
  let suffix = '';
  const m = /^([^.]*)((?:\.[A-Za-z_]+(?:\.[0-9]+)*|\.[0-9]+)+)$/.exec(body);
  if (m && m[1]) {
    body = m[1];
    const parts = (m[2] as string).match(/\.[A-Za-z_]+(?:\.[0-9]+)*|\.[0-9]+/g) ?? [];
    suffix = parts.map((p) => ` [clone ${p}]`).join('');
  }
  const p = new Parser(body);
  try {
    const enc = p.encoding(true);
    if (!p.atEnd()) return null;
    return pr(enc) + suffix;
  } catch {
    return null;
  }
}
