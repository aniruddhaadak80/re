// Rust symbol demangling: legacy (_ZN...17h<hash>E) and v0 (_R...).
// Output follows GNU c++filt (libiberty rust-demangle) so it can be diffed against it:
// legacy keeps the ::h<hash> suffix, v0 shows crate disambiguators as name[hex] and
// integer constants as value: type.

const MAX_LEN = 16384;
const MAX_DEPTH = 300;

// ---------- legacy ----------
const LEGACY_ESC: Record<string, string> = { SP: '@', BP: '*', RF: '&', LT: '<', GT: '>', LP: '(', RP: ')', C: ',' };

function legacyIdent(id: string): string | null {
  let s = id;
  if (s.startsWith('_$')) s = s.slice(1);
  let out = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i] as string;
    if (c === '$') {
      const end = s.indexOf('$', i + 1);
      if (end < 0) return null;
      const code = s.slice(i + 1, end);
      if (LEGACY_ESC[code] !== undefined) out += LEGACY_ESC[code];
      else if (/^u[0-9a-f]{1,6}$/.test(code)) {
        const cp = parseInt(code.slice(1), 16);
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null;
        out += String.fromCodePoint(cp);
      } else return null;
      i = end + 1;
    } else if (c === '.') {
      if (s[i + 1] === '.') { out += '::'; i += 2; } else { out += '.'; i++; }
    } else { out += c; i++; }
  }
  return out;
}

/** Demangle a legacy Rust symbol. Returns null when it is not one. */
export function demangleRustLegacy(sym: string): string | null {
  let s = sym;
  if (s.startsWith('__ZN')) s = s.slice(1);
  if (!s.startsWith('_ZN') || s.length > MAX_LEN) return null;
  let p = 3;
  const parts: string[] = [];
  while (p < s.length && s[p] !== 'E') {
    const m = /^[0-9]+/.exec(s.slice(p));
    if (!m) return null;
    const len = Number(m[0]);
    p += m[0].length;
    if (len === 0 || p + len > s.length) return null;
    parts.push(s.slice(p, p + len));
    p += len;
  }
  if (s[p] !== 'E') return null;
  const rest = s.slice(p + 1);
  if (rest && !/^\.[A-Za-z0-9_.$]*$/.test(rest)) return null;
  const last = parts[parts.length - 1];
  if (!last || !/^h[0-9a-f]{16}$/.test(last)) return null;
  const out: string[] = [];
  for (const part of parts) {
    const d = legacyIdent(part);
    if (d === null) return null;
    out.push(d);
  }
  return out.join('::');
}

// ---------- v0 ----------
class Fail extends Error {}

const BASIC: Record<string, string> = {
  a: 'i8', b: 'bool', c: 'char', d: 'f64', e: 'str', f: 'f32', h: 'u8', i: 'isize', j: 'usize', l: 'i32', m: 'u32',
  n: 'i128', o: 'u128', s: 'i16', t: 'u16', u: '()', v: '...', x: 'i64', y: 'u64', z: '!', p: '_',
};

function punycodeDecode(input: string): string {
  // RFC 3492 with '_' as the delimiter, as Rust v0 uses
  const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const d = input.lastIndexOf('_');
  const out: number[] = [];
  if (d > 0) for (const ch of input.slice(0, d)) out.push(ch.charCodeAt(0));
  let pos = d > 0 ? d + 1 : 0;
  const digit = (c: string): number => {
    const code = c.charCodeAt(0);
    if (code >= 97 && code <= 122) return code - 97;
    if (code >= 48 && code <= 57) return code - 22;
    throw new Fail();
  };
  const adapt = (delta: number, num: number, first: boolean): number => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / num);
    let k = 0;
    while (delta > ((base - tmin) * tmax) >> 1) { delta = Math.floor(delta / (base - tmin)); k += base; }
    return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));
  };
  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= input.length) throw new Fail();
      const dg = digit(input[pos++] as string);
      i += dg * w;
      if (i > 0x7fffffff) throw new Fail();
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (dg < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff || out.length > 4096) throw new Fail();
    out.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...out);
}

class V0 {
  p = 0;
  depth = 0;
  out = '';
  boundLifetimes = 0;
  constructor(readonly s: string, readonly verbose = true) {}
  peek(): string { return this.s[this.p] ?? ''; }
  eat(c: string): boolean { if (this.s[this.p] === c) { this.p++; return true; } return false; }
  next(): string { const c = this.s[this.p]; if (c === undefined) throw new Fail(); this.p++; return c; }
  enter(): void { if (++this.depth > MAX_DEPTH) throw new Fail(); }
  leave(): void { this.depth--; }
  emit(t: string): void { this.out += t; if (this.out.length > 1 << 20) throw new Fail(); }

  base62Big(): bigint {
    if (this.eat('_')) return 0n;
    let x = 0n;
    for (let n = 0; ; n++) {
      if (n > 24) throw new Fail();
      const c = this.next();
      if (c === '_') return x + 1n;
      let d: number;
      if (c >= '0' && c <= '9') d = c.charCodeAt(0) - 48;
      else if (c >= 'a' && c <= 'z') d = c.charCodeAt(0) - 97 + 10;
      else if (c >= 'A' && c <= 'Z') d = c.charCodeAt(0) - 65 + 36;
      else throw new Fail();
      x = x * 62n + BigInt(d);
    }
  }
  base62(): number {
    const v = this.base62Big();
    if (v > BigInt(MAX_LEN * 64)) throw new Fail();
    return Number(v);
  }
  optBase62(tag: string): bigint { return this.eat(tag) ? this.base62Big() + 1n : 0n; }
  decimal(): number {
    const st = this.p;
    if (this.peek() === '0') { this.p++; return 0; }
    while (/[0-9]/.test(this.peek())) this.p++;
    if (st === this.p) throw new Fail();
    const v = Number(this.s.slice(st, this.p));
    if (v > MAX_LEN) throw new Fail();
    return v;
  }
  ident(): { name: string; dis: bigint } {
    const dis = this.optBase62('s');
    const puny = this.eat('u');
    const len = this.decimal();
    this.eat('_');
    if (this.p + len > this.s.length) throw new Fail();
    let raw = this.s.slice(this.p, this.p + len);
    this.p += len;
    if (puny) raw = punycodeDecode(raw);
    return { name: raw, dis };
  }

  backref(fn: () => void): void {
    const st = this.p - 1;
    const target = this.base62();
    if (target >= st) throw new Fail();
    const save = this.p;
    this.p = target;
    this.enter();
    try { fn(); } finally { this.leave(); this.p = save; }
  }

  path(inValue: boolean): void {
    this.enter();
    try {
      const tag = this.next();
      switch (tag) {
        case 'C': {
          const { name, dis } = this.ident();
          this.emit(name);
          if (this.verbose) this.emit(`[${dis.toString(16)}]`);
          return;
        }
        case 'N': {
          const ns = this.next();
          this.path(inValue);
          const { name, dis } = this.ident();
          if (ns >= 'A' && ns <= 'Z') {
            this.emit('::{');
            this.emit(ns === 'C' ? 'closure' : ns === 'S' ? 'shim' : ns);
            if (name) this.emit(':' + name);
            this.emit(`#${dis}}`);
          } else if (name) {
            this.emit('::' + name);
          }
          return;
        }
        case 'M': case 'X': case 'Y': {
          if (tag !== 'Y') { this.optBase62('s'); this.skipPath(); }
          this.emit('<');
          this.type();
          if (tag !== 'M') { this.emit(' as '); this.path(false); }
          this.emit('>');
          return;
        }
        case 'I': {
          this.path(inValue);
          if (inValue) this.emit('::');
          this.emit('<');
          let first = true;
          while (!this.eat('E')) {
            if (!first) this.emit(', ');
            first = false;
            this.genericArg();
          }
          this.emit('>');
          return;
        }
        case 'B': this.backref(() => this.path(inValue)); return;
        default: throw new Fail();
      }
    } finally { this.leave(); }
  }

  skipPath(): void {
    const saved = this.out;
    this.path(false);
    this.out = saved;
  }

  genericArg(): void {
    if (this.eat('L')) { this.lifetime(this.base62()); return; }
    if (this.eat('K')) { this.konst(); return; }
    this.type();
  }

  lifetime(i: number): void {
    if (i === 0) { this.emit("'_"); return; }
    const depth = this.boundLifetimes - i;
    if (depth < 0) throw new Fail();
    if (depth < 26) this.emit("'" + String.fromCharCode(97 + depth));
    else this.emit(`'_${depth}`);
  }

  binder(): number {
    if (!this.eat('G')) return 0;
    const n = this.base62() + 1;
    if (n > 1000) throw new Fail();
    this.emit('for<');
    for (let i = 0; i < n; i++) {
      if (i) this.emit(', ');
      this.boundLifetimes++;
      this.lifetime(1);
    }
    this.emit('> ');
    return n;
  }

  type(): void {
    this.enter();
    try {
      const c = this.next();
      if (BASIC[c]) { this.emit(BASIC[c] as string); return; }
      switch (c) {
        case 'R': case 'Q': {
          this.emit(c === 'R' ? '&' : '&mut ');
          if (this.eat('L')) {
            const lt = this.base62();
            if (lt) { this.lifetime(lt); this.emit(' '); }
          }
          this.type();
          return;
        }
        case 'P': this.emit('*const '); this.type(); return;
        case 'O': this.emit('*mut '); this.type(); return;
        case 'A': this.emit('['); this.type(); this.emit('; '); this.konst(); this.emit(']'); return;
        case 'S': this.emit('['); this.type(); this.emit(']'); return;
        case 'T': {
          this.emit('(');
          let n = 0;
          while (!this.eat('E')) { if (n) this.emit(', '); this.type(); n++; }
          if (n === 1) this.emit(',');
          this.emit(')');
          return;
        }
        case 'F': {
          const saved = this.boundLifetimes;
          this.binder();
          if (this.eat('U')) this.emit('unsafe ');
          if (this.eat('K')) {
            let abi: string;
            if (this.eat('C')) abi = 'C';
            else { abi = this.ident().name.replace(/_/g, '-'); }
            this.emit(`extern "${abi}" `);
          }
          this.emit('fn(');
          let n = 0;
          while (!this.eat('E')) { if (n) this.emit(', '); this.type(); n++; }
          this.emit(')');
          if (this.peek() === 'u') { this.p++; } else { this.emit(' -> '); this.type(); }
          this.boundLifetimes = saved;
          return;
        }
        case 'D': {
          this.emit('dyn ');
          const saved = this.boundLifetimes;
          this.binder();
          let n = 0;
          while (!this.eat('E')) {
            if (n) this.emit(' + ');
            this.dynTrait();
            n++;
          }
          this.boundLifetimes = saved;
          if (!this.eat('L')) throw new Fail();
          const lt = this.base62();
          if (lt) { this.emit(' + '); this.lifetime(lt); }
          return;
        }
        case 'B': this.backref(() => this.type()); return;
        default:
          this.p--;
          this.path(false);
      }
    } finally { this.leave(); }
  }

  dynTrait(): void {
    const start = this.out.length;
    this.path(false);
    let open = false;
    while (this.eat('p')) {
      if (!open) {
        if (this.out.endsWith('>') && this.out.length > start) { this.out = this.out.slice(0, -1); this.emit(', '); }
        else this.emit('<');
        open = true;
      } else this.emit(', ');
      const { name } = this.ident();
      this.emit(name + ' = ');
      this.type();
    }
    if (open) this.emit('>');
  }

  konst(): void {
    this.enter();
    try {
      if (this.eat('p')) { this.emit('_'); return; }
      if (this.eat('B')) { this.backref(() => this.konst()); return; }
      const t = this.next();
      const neg = this.eat('n');
      const st = this.p;
      while (/[0-9a-f]/.test(this.peek())) this.p++;
      const hex = this.s.slice(st, this.p);
      if (!this.eat('_')) throw new Fail();
      if (t === 'b') { this.emit(hex === '0' || hex === '' ? 'false' : 'true'); return; }
      if (t === 'c') {
        const cp = parseInt(hex || '0', 16);
        if (cp > 0x10ffff) throw new Fail();
        this.emit(`'${String.fromCodePoint(cp)}'`);
        return;
      }
      if ('hmyjtoalxsni'.includes(t)) {
        const v = BigInt('0x' + (hex || '0'));
        this.emit((neg ? '-' : '') + v.toString() + (this.verbose ? ': ' + (BASIC[t] as string) : ''));
        return;
      }
      throw new Fail();
    } finally { this.leave(); }
  }
}

/** Demangle a Rust v0 symbol (_R...). Returns null when it is not one. */
export function demangleRustV0(sym: string, verbose = true): string | null {
  let s = sym;
  if (s.startsWith('__R')) s = s.slice(1);
  if (!s.startsWith('_R') || s.length > MAX_LEN) return null;
  const dot = s.indexOf('.');
  const body = dot >= 0 ? s.slice(2, dot) : s.slice(2);
  const v = new V0(body, verbose);
  try {
    if (/[0-9]/.test(v.peek())) v.decimal();
    v.path(true);
    if (v.p < body.length) {
      const saved = v.out;
      v.path(false);
      v.out = saved;
    }
    if (v.p !== body.length) return null;
    return v.out;
  } catch {
    return null;
  }
}
