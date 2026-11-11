// Microsoft Visual C++ symbol demangler (the ?name@scope@@... scheme used in PE files and PDBs).
// Output follows LLVM llvm-undname formatting. Covers functions, data, operators, templates,
// back references, pointers, references, member pointers, arrays, string literals, RTTI,
// vftables, dynamic initializers and adjustor thunks. Rare C++/CLI forms are not covered.

class Fail extends Error {}

const MAX_LEN = 8192;
const MAX_DEPTH = 200;

const PRIM: Record<string, string> = {
  C: 'signed char', D: 'char', E: 'unsigned char', F: 'short', G: 'unsigned short', H: 'int', I: 'unsigned int',
  J: 'long', K: 'unsigned long', M: 'float', N: 'double', O: 'long double', X: 'void',
};
const PRIM_EXT: Record<string, string> = {
  N: 'bool', J: '__int64', K: 'unsigned __int64', W: 'wchar_t', S: 'char16_t', U: 'char32_t', Q: 'char8_t', L: '__int128', M: 'unsigned __int128',
};
const CALLCONV: Record<string, string> = {
  A: '__cdecl', B: '__cdecl', C: '__pascal', D: '__pascal', E: '__thiscall', F: '__thiscall', G: '__stdcall', H: '__stdcall',
  I: '__fastcall', J: '__fastcall', K: '', M: '__clrcall', O: '__eabi', Q: '__vectorcall', S: '__swift_1', W: '__swift_2',
};
const OPS: Record<string, string> = {
  '2': 'operator new', '3': 'operator delete', '4': 'operator=', '5': 'operator>>', '6': 'operator<<', '7': 'operator!',
  '8': 'operator==', '9': 'operator!=', A: 'operator[]', C: 'operator->', D: 'operator*', E: 'operator++', F: 'operator--',
  G: 'operator-', H: 'operator+', I: 'operator&', J: 'operator->*', K: 'operator/', L: 'operator%', M: 'operator<',
  N: 'operator<=', O: 'operator>', P: 'operator>=', Q: 'operator,', R: 'operator()', S: 'operator~', T: 'operator^',
  U: 'operator|', V: 'operator&&', W: 'operator||', X: 'operator*=', Y: 'operator+=', Z: 'operator-=',
};
const OPS_U: Record<string, string> = {
  '0': 'operator/=', '1': 'operator%=', '2': 'operator>>=', '3': 'operator<<=', '4': 'operator&=', '5': 'operator|=', '6': 'operator^=',
  '7': "`vftable'", '8': "`vbtable'", '9': "`vcall'", A: "`typeof'", B: "`local static guard'", C: "`string'",
  D: "`vbase dtor'", E: "`vector deleting dtor'", F: "`default ctor closure'", G: "`scalar deleting dtor'",
  H: "`vector ctor iterator'", I: "`vector dtor iterator'", J: "`vector vbase ctor iterator'", K: "`virtual displacement map'",
  L: "`eh vector ctor iterator'", M: "`eh vector dtor iterator'", N: "`eh vector vbase ctor iterator'", O: "`copy ctor closure'",
  S: "`local vftable'", T: "`local vftable ctor closure'", U: 'operator new[]', V: 'operator delete[]', X: "`placement delete closure'",
  Y: "`placement delete[] closure'",
};
const OPS_UU: Record<string, string> = {
  A: "`managed vector ctor iterator'", B: "`managed vector dtor iterator'", C: "`EH vector copy ctor iterator'",
  D: "`EH vector vbase copy ctor iterator'", E: '`dynamic initializer for', F: '`dynamic atexit destructor for',
  G: "`vector copy ctor iterator'", H: "`vector vbase copy ctor iterator'", I: "`managed vector copy ctor iterator'",
  J: "`local static thread guard'", K: 'operator ""', L: 'operator co_await', M: 'operator<=>',
};

type T =
  | { k: 'prim'; s: string }
  | { k: 'named'; tag: string; name: string }
  | { k: 'ptr'; op: string; cv: string; to: T; cls?: string; ptrQuals: string }
  | { k: 'fn'; cc: string; ret: T | null; params: T[]; cv?: string; ref?: string }
  | { k: 'arr'; dims: number[]; t: T }
  | { k: 'cv'; t: T; cv: string };

function cvText(c: string): string { return c === 'B' ? 'const' : c === 'C' ? 'volatile' : c === 'D' ? 'const volatile' : ''; }

class P {
  p = 0;
  depth = 0;
  names: string[] = [];
  types: T[] = [];
  lastThunk = 0;
  constructor(readonly s: string) {}
  peek(o = 0): string { return this.s[this.p + o] ?? ''; }
  eat(c: string): boolean { if (this.s.startsWith(c, this.p)) { this.p += c.length; return true; } return false; }
  need(c: string): void { if (!this.eat(c)) throw new Fail(); }
  next(): string { const c = this.s[this.p]; if (c === undefined) throw new Fail(); this.p++; return c; }
  enter(): void { if (++this.depth > MAX_DEPTH) throw new Fail(); }

  number(): number {
    const neg = this.eat('?');
    const c = this.next();
    let v: number;
    if (c >= '0' && c <= '9') v = c.charCodeAt(0) - 47;
    else {
      this.p--;
      v = 0;
      let n = 0;
      while (!this.eat('@')) {
        const d = this.next();
        if (d < 'A' || d > 'P') throw new Fail();
        v = v * 16 + (d.charCodeAt(0) - 65);
        if (++n > 16) throw new Fail();
      }
    }
    return neg ? -v : v;
  }

  bigNumber(): string {
    const neg = this.eat('?');
    const c = this.next();
    let v = 0n;
    if (c >= '0' && c <= '9') v = BigInt(c.charCodeAt(0) - 47);
    else {
      this.p--;
      let n = 0;
      while (!this.eat('@')) {
        const d = this.next();
        if (d < 'A' || d > 'P') throw new Fail();
        v = v * 16n + BigInt(d.charCodeAt(0) - 65);
        if (++n > 16) throw new Fail();
      }
    }
    return (neg ? '-' : '') + v.toString();
  }

  memoName(n: string): void { if (this.names.length < 10 && !this.names.includes(n)) this.names.push(n); }

  simpleName(memo = true): string {
    const at = this.s.indexOf('@', this.p);
    if (at < 0) throw new Fail();
    const n = this.s.slice(this.p, at);
    if (!n) throw new Fail();
    this.p = at + 1;
    if (memo) this.memoName(n);
    return n;
  }

  templateName(): string {
    this.need('?$');
    const saveNames = this.names, saveTypes = this.types;
    this.names = [];
    this.types = [];
    let base: string;
    if (this.peek() === '?') { this.p++; base = this.operatorName().name; } else base = this.simpleName();
    const args: string[] = [];
    while (!this.eat('@')) {
      args.push(this.templateArg());
      if (args.length > 256) throw new Fail();
    }
    this.names = saveNames;
    this.types = saveTypes;
    return `${base}<${args.filter((a) => a !== '').join(', ')}>`;
  }

  templateArg(): string {
    if (this.eat('$$V') || this.eat('$$Z') || this.eat('$S')) return '';
    if (this.eat('$0')) return this.bigNumber();
    if (this.eat('$1')) {
      if (this.peek() === '?') { const r = this.symbol(); return '&' + r; }
      return '&' + this.fullName();
    }
    if (this.eat('$E?')) { this.p--; return this.symbol(); }
    if (this.eat('$$C')) { const cv = this.next(); const t = this.type(); return printType(cvWrap(t, cv), ''); }
    if (this.eat('$$T')) return 'std::nullptr_t';
    return printType(this.type(), '');
  }

  operatorName(): { name: string; kind: 'ctor' | 'dtor' | 'conv' | 'op' } {
    const c = this.next();
    if (c === '0') return { name: '', kind: 'ctor' };
    if (c === '1') return { name: '', kind: 'dtor' };
    if (c === 'B') return { name: 'operator', kind: 'conv' };
    if (c === '_') {
      const d = this.next();
      if (d === '_') {
        const e = this.next();
        const n = OPS_UU[e];
        if (!n) throw new Fail();
        if (e === 'K') return { name: 'operator ""' + this.simpleName(false), kind: 'op' };
        return { name: n, kind: 'op' };
      }
      if (d === 'R') {
        const e = this.next();
        if (e === '0') { const t = this.type(); return { name: `${printType(t, '')} \`RTTI Type Descriptor'`, kind: 'op' }; }
        if (e === '1') {
          const a = this.number(), b = this.number(), cc = this.number(), dd = this.number();
          return { name: `\`RTTI Base Class Descriptor at (${a}, ${b}, ${cc}, ${dd})'`, kind: 'op' };
        }
        if (e === '2') return { name: "`RTTI Base Class Array'", kind: 'op' };
        if (e === '3') return { name: "`RTTI Class Hierarchy Descriptor'", kind: 'op' };
        if (e === '4') return { name: "`RTTI Complete Object Locator'", kind: 'op' };
        throw new Fail();
      }
      const n = OPS_U[d];
      if (!n) throw new Fail();
      return { name: n, kind: 'op' };
    }
    const n = OPS[c];
    if (!n) throw new Fail();
    return { name: n, kind: 'op' };
  }

  fragment(): string {
    const c = this.peek();
    if (c >= '0' && c <= '9') {
      this.p++;
      const n = this.names[c.charCodeAt(0) - 48];
      if (n === undefined) throw new Fail();
      return n;
    }
    if (c === '?') {
      if (this.peek(1) === '$') { const t = this.templateName(); this.memoName(t); return t; }
      if (this.peek(1) === 'A' && (this.s.startsWith('?A0x', this.p) || this.s.startsWith('?A@', this.p))) {
        this.p += 2;
        if (this.peek() !== '@') this.simpleName(false); else this.p++;
        const n = "`anonymous namespace'";
        this.memoName(n);
        return n;
      }
      if (this.peek(1) === '?') {
        this.p++;
        const inner = this.symbol();
        return '`' + inner + "'";
      }
      this.p++;
      const n = this.number();
      return '`' + n + "'";
    }
    return this.simpleName();
  }

  fullName(): string {
    const parts: string[] = [];
    while (!this.eat('@')) {
      parts.push(this.fragment());
      if (parts.length > 64) throw new Fail();
    }
    return parts.reverse().join('::');
  }

  symbol(): string {
    this.enter();
    try {
      this.need('?');
      if (this.s.startsWith('?_C@_', this.p)) { this.p = this.s.length; return "`string'"; }
      let first: string;
      let kind: 'ctor' | 'dtor' | 'conv' | 'op' | 'name' = 'name';
      if (this.peek() === '?' && this.peek(1) === '$') {
        first = this.templateName();
        this.memoName(first);
      } else if (this.peek() === '?') {
        this.p++;
        const op = this.operatorName();
        first = op.name;
        kind = op.kind;
        if (first.startsWith('`dynamic')) {
          let target: string;
          if (this.peek() === '?') { target = '`' + this.symbol() + "'"; this.eat('@'); }
          else { target = "'" + this.fullName() + "'"; }
          return this.encoding(`${first} ${target}'`, 'op');
        }
      } else first = this.simpleName();
      const scope = this.fullName();
      const cls = lastScope(scope);
      let name: string;
      if (kind === 'ctor') name = (scope ? scope + '::' : '') + cls;
      else if (kind === 'dtor') name = (scope ? scope + '::' : '') + '~' + cls;
      else name = (scope ? scope + '::' : '') + first;
      return this.encoding(name, kind);
    } finally { this.depth--; }
  }

  encoding(name: string, kind: string): string {
    const c = this.next();
    if (c >= '0' && c <= '4') {
      const t = this.type();
      const access = c === '0' ? 'private: static ' : c === '1' ? 'protected: static ' : c === '2' ? 'public: static ' : '';
      if (t.k === 'ptr' && t.cls !== undefined) {
        while (this.eat('E') || this.eat('I') || this.eat('F')) { /* pointer modifiers */ }
        const sc2 = this.next();
        if ('QRSTUV'.includes(sc2)) this.fullName();
        return access + printType(t, name);
      }
      const sc = this.storage();
      return access + printType(t.k === 'ptr' ? t : cvWrap(t, sc), name);
    }
    if (c === '6' || c === '7') {
      const cv = this.next();
      let s = name;
      const fors: string[] = [];
      while (this.p < this.s.length && !this.eat('@')) { fors.push(this.fullName()); if (fors.length > 16) throw new Fail(); }
      if (fors.length) s += `{for \`${fors.join("'s `")}'}`;
      return (cvText(cv) ? cvText(cv) + ' ' : '') + s;
    }
    if (c === '8' || c === '9') return name;
    if (c === '$') throw new Fail();
    const idx = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(c);
    if (idx < 0) throw new Fail();
    let access = '';
    let isStatic = false, isVirtual = false, isMember = true, isThunk = false;
    if (c === 'Y' || c === 'Z') isMember = false;
    else {
      const group = Math.floor(idx / 8);
      access = ['private: ', 'protected: ', 'public: '][group] ?? '';
      const sub = idx % 8;
      if (sub === 2 || sub === 3) isStatic = true;
      if (sub === 4 || sub === 5) isVirtual = true;
      if (sub === 6 || sub === 7) { isVirtual = true; isThunk = true; }
    }
    let thisCv = '', ref = '';
    if (isThunk) this.lastThunk = this.number();
    if (isMember && !isStatic) {
      let q = '';
      for (;;) {
        if (this.eat('E')) continue;
        if (this.eat('I')) { q += ' __restrict'; continue; }
        if (this.eat('F')) { q += ' __unaligned'; continue; }
        if (this.eat('G')) { ref = ' &'; continue; }
        if (this.eat('H')) { ref = ' &&'; continue; }
        break;
      }
      const cvc = this.next();
      thisCv = (cvText(cvc) ? ' ' + cvText(cvc) : '') + q;
    }
    const cc = CALLCONV[this.next()];
    if (cc === undefined) throw new Fail();
    let ret: T | null = null;
    if (!this.eat('@')) {
      if (this.eat('?')) { const cv = this.next(); ret = cvWrap(this.type(), cv); }
      else ret = this.type();
    }
    const params = this.params();
    if (!this.eat('Z')) { if (!this.eat('_E')) throw new Fail(); }
    let nm = name;
    if (kind === 'conv' && ret) { nm = name + ' ' + printType(ret, ''); ret = null; }
    if (isThunk) nm += `\`adjustor{${this.lastThunk}}'`;
    const pre = (isThunk ? '[thunk]: ' : '') + access + (isStatic ? 'static ' : '') + (isVirtual && !isThunk ? 'virtual ' : '');
    const fn: T = { k: 'fn', cc, ret, params, cv: thisCv, ref };
    return pre + printType(fn, nm);
  }

  storage(): string {
    let c = this.next();
    while (c === 'E' || c === 'I' || c === 'F') c = this.next();
    return c;
  }

  params(): T[] {
    if (this.eat('X')) return [];
    const ps: T[] = [];
    for (;;) {
      if (this.eat('@')) break;
      if (this.eat('Z')) { ps.push({ k: 'prim', s: '...' }); break; }
      const c = this.peek();
      if (c >= '0' && c <= '9') {
        this.p++;
        const t = this.types[c.charCodeAt(0) - 48];
        if (!t) throw new Fail();
        ps.push(t);
        continue;
      }
      const st = this.p;
      const t = this.type();
      if (this.p - st > 1 && this.types.length < 10) this.types.push(t);
      ps.push(t);
      if (ps.length > 512) throw new Fail();
    }
    return ps;
  }

  type(): T {
    this.enter();
    try { return this.typeInner(); } finally { this.depth--; }
  }

  typeInner(): T {
    const c = this.next();
    if (c === '_') {
      const d = this.next();
      const s = PRIM_EXT[d];
      if (!s) throw new Fail();
      return { k: 'prim', s };
    }
    if (c === '$') {
      if (this.eat('$Q')) return this.pointer('&&');
      if (this.eat('$R')) return this.pointer('&&', 'volatile');
      if (this.eat('$T')) return { k: 'prim', s: 'std::nullptr_t' };
      if (this.eat('$B')) {
        this.need('Y');
        const n = this.number();
        if (n < 1 || n > 32) throw new Fail();
        const dims: number[] = [];
        for (let i = 0; i < n; i++) dims.push(this.number());
        return { k: 'arr', dims, t: this.type() };
      }
      if (this.eat('$A6')) return this.funcType();
      if (this.eat('$A8@@')) return this.funcType();
      if (this.eat('$C')) { const cv = this.next(); return cvWrap(this.type(), cv); }
      if (this.eat('$Y')) return { k: 'prim', s: this.fullName() };
      throw new Fail();
    }
    if (PRIM[c]) return { k: 'prim', s: PRIM[c] as string };
    switch (c) {
      case 'T': return { k: 'named', tag: 'union', name: this.fullName() };
      case 'U': return { k: 'named', tag: 'struct', name: this.fullName() };
      case 'V': return { k: 'named', tag: 'class', name: this.fullName() };
      case 'W': { this.next(); return { k: 'named', tag: 'enum', name: this.fullName() }; }
      case 'P': return this.pointer('*');
      case 'Q': return this.pointer('*', 'const');
      case 'R': return this.pointer('*', 'volatile');
      case 'S': return this.pointer('*', 'const volatile');
      case 'A': return this.pointer('&');
      case 'B': return this.pointer('&', 'volatile');
      case 'Y': {
        const n = this.number();
        if (n < 1 || n > 32) throw new Fail();
        const dims: number[] = [];
        for (let i = 0; i < n; i++) dims.push(this.number());
        return { k: 'arr', dims, t: this.type() };
      }
      case '?': { const cv = this.next(); return cvWrap(this.type(), cv); }
      default: throw new Fail();
    }
  }

  funcType(): T {
    const cc = CALLCONV[this.next()];
    if (cc === undefined) throw new Fail();
    let ret: T | null = null;
    if (!this.eat('@')) ret = this.eat('?') ? cvWrap(this.type(), this.next()) : this.type();
    const params = this.params();
    if (!this.eat('Z')) throw new Fail();
    return { k: 'fn', cc, ret, params };
  }

  pointer(op: string, ptrCv = ''): T {
    let ptrQuals = ptrCv ? ' ' + ptrCv : '';
    if (this.peek() === '6') { this.p++; const f = this.funcType(); return { k: 'ptr', op, cv: '', to: f, ptrQuals }; }
    if (this.peek() === '8') {
      this.p++;
      const cls = this.fullName();
      const cvc = this.next();
      const f = this.funcType();
      if (f.k === 'fn') f.cv = cvText(cvc) ? ' ' + cvText(cvc) : '';
      return { k: 'ptr', op: '::*', cv: '', to: f, cls, ptrQuals };
    }
    for (;;) {
      if (this.eat('E')) continue;
      if (this.eat('I')) { ptrQuals += ' __restrict'; continue; }
      if (this.eat('F')) { ptrQuals += ' __unaligned'; continue; }
      break;
    }
    const cvc = this.next();
    if ('QRSTUV'.includes(cvc)) {
      const cls = this.fullName();
      const to = this.type();
      const cv = cvText(String.fromCharCode(cvc.charCodeAt(0) - 16));
      return { k: 'ptr', op: '::*', cv, to, cls, ptrQuals };
    }
    if (!'ABCD'.includes(cvc)) throw new Fail();
    let to: T;
    if (this.peek() === 'Y') { this.p++; const n = this.number(); const dims: number[] = []; for (let i = 0; i < n; i++) dims.push(this.number()); to = { k: 'arr', dims, t: this.type() }; }
    else to = this.type();
    return { k: 'ptr', op, cv: cvText(cvc), to, ptrQuals };
  }
}

function lastScope(scope: string): string {
  let depth = 0;
  for (let i = scope.length - 1; i > 0; i--) {
    const ch = scope[i];
    if (ch === '>') depth++;
    else if (ch === '<') depth--;
    else if (depth === 0 && ch === ':' && scope[i - 1] === ':') return scope.slice(i + 1);
  }
  return scope;
}

function decodeMsvcString(body: string): string | null {
  const m = /^\?\?_C@_([01])/.exec(body);
  if (!m) return null;
  const wide = m[1] === '1';
  let p = m[0].length;
  const readNum = (): number => {
    const c = body[p] ?? '';
    if (c >= '0' && c <= '9') { p++; return c.charCodeAt(0) - 47; }
    let v = 0;
    while (body[p] !== '@') { const d = body[p++]; if (!d || d < 'A' || d > 'P') throw new Fail(); v = v * 16 + d.charCodeAt(0) - 65; }
    p++;
    return v;
  };
  readNum();
  const at = body.indexOf('@', p);
  if (at < 0) return null;
  p = at + 1;
  const bytes: number[] = [];
  const SPECIAL = ",/\\:. \n\t'-";
  while (p < body.length && body[p] !== '@') {
    const c = body[p++] as string;
    if (c !== '?') { bytes.push(c.charCodeAt(0)); continue; }
    const d = body[p++] ?? '';
    if (d === '$') { const a = body[p++] ?? 'A', b = body[p++] ?? 'A'; bytes.push((a.charCodeAt(0) - 65) * 16 + (b.charCodeAt(0) - 65)); }
    else if (d >= '0' && d <= '9') bytes.push(SPECIAL.charCodeAt(d.charCodeAt(0) - 48));
    else if (d >= 'a' && d <= 'z') bytes.push(0xe1 + d.charCodeAt(0) - 97);
    else if (d >= 'A' && d <= 'Z') bytes.push(0xc1 + d.charCodeAt(0) - 65);
    else return null;
    if (bytes.length > 4096) return null;
  }
  let str = '';
  if (wide) { for (let i = 0; i + 1 < bytes.length; i += 2) str += String.fromCharCode((bytes[i] as number) | ((bytes[i + 1] as number) << 8)); }
  else str = String.fromCharCode(...bytes);
  str = str.replace(/\0+$/, '');
  const esc = str.replace(/[\\"]/g, (x) => '\\' + x).replace(/\n/g, '\\n').replace(/\t/g, '\\t').replace(/[\x00-\x1f]/g, (x) => '\\x' + x.charCodeAt(0).toString(16).padStart(2, '0'));
  return (wide ? 'L"' : '"') + esc + '"';
}

function cvWrap(t: T, c: string): T {
  const q = cvText(c);
  if (!q) return t;
  if (t.k === 'ptr') return { ...t, ptrQuals: t.ptrQuals + ' ' + q };
  return { k: 'cv', t, cv: q };
}

function printType(t: T, inner: string): string {
  const sp = (s: string): string => (s ? ' ' + s : '');
  switch (t.k) {
    case 'prim': return t.s + sp(inner);
    case 'named': return t.tag + ' ' + t.name + sp(inner);
    case 'cv': return printType(t.t, '') + ' ' + t.cv + sp(inner);
    case 'arr': return `${printType(t.t, '')}${inner ? ' ' + inner : ''}${t.dims.map((d) => `[${d === 0 ? '' : d}]`).join('')}`;
    case 'fn': {
      const ret = t.ret ? printType(t.ret, '') + ' ' : '';
      const ps = t.params.length ? t.params.map((p) => printType(p, '')).join(', ') : 'void';
      return `${ret}${t.cc}${inner ? (t.cc ? ' ' : '') + inner : ''}(${ps})${t.cv ?? ''}${t.ref ?? ''}`;
    }
    case 'ptr': {
      const op = t.cls ? `${t.cls}::*` : t.op;
      const q = t.ptrQuals.trim();
      const decl = op + (q ? q + (inner ? ' ' : '') : '') + inner;
      if (t.to.k === 'fn') {
        const f = t.to;
        const ret = f.ret ? printType(f.ret, '') + ' ' : '';
        const ps = f.params.length ? f.params.map((p) => printType(p, '')).join(', ') : 'void';
        return `${ret}(${f.cc ? f.cc + ' ' : ''}${decl})(${ps})${f.cv ?? ''}`;
      }
      if (t.to.k === 'arr') {
        const el = printType(t.to.t, '');
        return `${el}${t.cv ? ' ' + t.cv : ''} (${decl})${t.to.dims.map((d) => `[${d}]`).join('')}`;
      }
      const base = printType(t.to, '') + (t.cv ? ' ' + t.cv : '');
      return /[*&]$/.test(base) ? `${base}${decl}` : `${base} ${decl}`;
    }
  }
}

/** Demangle one MSVC C++ symbol. Returns null when the input is not a supported mangled name. */
export function demangleMsvc(sym: string): string | null {
  if (typeof sym !== 'string' || sym.length > MAX_LEN) return null;
  if (sym.startsWith('??_C@_')) { try { return decodeMsvcString(sym); } catch { return null; } }
  if (sym.startsWith('.?A')) {
    const p = new P(sym);
    p.p = 3;
    try { const t = p.type(); if (p.p !== sym.length) return null; return printType(t, '') + " `RTTI Type Descriptor Name'"; } catch { return null; }
  }
  if (!sym.startsWith('?')) return null;
  const p = new P(sym);
  try {
    const r = p.symbol();
    if (p.p !== sym.length) return null;
    return r.replace(/\s+/g, ' ').trim();
  } catch {
    return null;
  }
}
