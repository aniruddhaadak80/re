// .NET member diff and P/Invoke to native export matching.

import { ParseError } from '../util.js';
import { listTypes, methodIl, pinvokes, type DotnetAssembly } from './assembly.js';
import { getBlob, row } from './metadata.js';
import { decodeMethodSig } from './signature.js';
import { nativeExports, probingNames, type NativeLibrary } from './native.js';

export interface NetMember { name: string; signature: string; access: string; static: boolean; extra?: string; paramCount?: number }
export interface NetTypeSnap { fullName: string; kind: string; visibility: string; extends?: string; interfaces: string[]; methods: Map<string, NetMember & { body?: string }>; fields: Map<string, NetMember> }

const fnv = (s: string): string => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(16).padStart(8, '0'); };

/** Member signatures of every TypeDef, keyed by full name; method keys are name(paramTypes) with generic arity. */
export function snapshotAssembly(asm: DotnetAssembly, opts: { bodies?: boolean; deadline?: number } = {}): { types: Map<string, NetTypeSnap>; truncated: boolean } {
  const out = new Map<string, NetTypeSnap>();
  let truncated = false;
  for (const t of listTypes(asm, { members: true })) {
    if (opts.deadline && Date.now() > opts.deadline) { truncated = true; break; }
    const s: NetTypeSnap = { fullName: t.fullName, kind: t.kind, visibility: t.visibility, extends: t.extends, interfaces: [...t.interfaces].sort(), methods: new Map(), fields: new Map() };
    for (const m of t.methods) {
      const rid = parseInt(m.token, 16) & 0xffffff;
      const r = row(asm.md, 0x06, rid);
      const sig = r ? decodeMethodSig(getBlob(asm.md, r.Signature as number), asm.typeName) : undefined;
      const blob = r ? getBlob(asm.md, r.Signature as number) : new Uint8Array();
      const gen = blob.length > 1 && blob[0]! & 0x10 ? `\`\`${blob[1]}` : '';
      const params = sig ? sig.params.join(', ') : '?';
      let key = `${m.name}${gen}(${params})`;
      // conversion operators (and any other collision) overload on the return type
      if (sig && (m.name === 'op_Explicit' || m.name === 'op_Implicit' || s.methods.has(key))) key += ` : ${sig.ret}`;
      const e: NetMember & { body?: string } = { name: m.name, signature: sig ? `${sig.ret} ${m.name}${gen}(${params})` : key, access: m.access, static: m.static, paramCount: sig?.params.length };
      if (m.abstract) e.extra = 'abstract';
      if (m.pinvoke) e.extra = 'pinvoke';
      if (opts.bodies && m.rva) {
        try { const il = methodIl(asm, rid); e.body = fnv(il.instructions.map((i) => `${i.label} ${i.opcode} ${(i as { text?: string }).text ?? ''}`).join('\n')); } catch { e.body = 'unreadable'; }
      }
      s.methods.set(key, e);
    }
    for (const f of t.fields) s.fields.set(f.name, { name: f.name, signature: `${f.type} ${f.name}`, access: f.access, static: f.static });
    if (!out.has(t.fullName)) out.set(t.fullName, s);
  }
  return { types: out, truncated };
}

export interface NetTypeChange {
  type: string;
  kind?: { from: string; to: string }; visibility?: { from: string; to: string }; extends?: { from?: string; to?: string }; interfaces?: { added: string[]; removed: string[] };
  methods: { added: string[]; removed: string[]; changed: { key: string; from: string; to: string }[]; bodyChanged: string[] };
  fields: { added: string[]; removed: string[]; changed: { name: string; from: string; to: string }[] };
}
export interface NetDiff {
  types: { a: number; b: number; added: string[]; removed: string[]; changed: number; unchanged: number };
  methods: { added: number; removed: number; changed: number; bodyChanged: number };
  fields: { added: number; removed: number; changed: number };
  changes: NetTypeChange[]; truncated: boolean;
}

const desc = (m: NetMember): string => `${m.access}${m.static ? ' static' : ''}${m.extra ? ' ' + m.extra : ''} ${m.signature}`;

/** Diff two assemblies at type and member level (optionally comparing IL bodies with resolved operands). */
export function compareAssemblies(a: DotnetAssembly, b: DotnetAssembly, opts: { bodies?: boolean; filter?: string; maxChanges?: number; budgetMs?: number; publicOnly?: boolean } = {}): NetDiff {
  const deadline = Date.now() + (opts.budgetMs ?? 60_000);
  const sa = snapshotAssembly(a, { bodies: opts.bodies, deadline }), sb = snapshotAssembly(b, { bodies: opts.bodies, deadline });
  const f = opts.filter?.toLowerCase();
  const pub = (t: NetTypeSnap): boolean => !opts.publicOnly || /public/.test(t.visibility);
  const pubM = (m: NetMember): boolean => !opts.publicOnly || m.access === 'public' || m.access === 'family' || m.access === 'famorassem';
  const keep = (n: string): boolean => !f || n.toLowerCase().includes(f);
  const d: NetDiff = { types: { a: sa.types.size, b: sb.types.size, added: [], removed: [], changed: 0, unchanged: 0 }, methods: { added: 0, removed: 0, changed: 0, bodyChanged: 0 }, fields: { added: 0, removed: 0, changed: 0 }, changes: [], truncated: sa.truncated || sb.truncated };
  for (const [n, t] of sb.types) if (!sa.types.has(n) && keep(n) && pub(t)) d.types.added.push(n);
  for (const [n, t] of sa.types) if (!sb.types.has(n) && keep(n) && pub(t)) d.types.removed.push(n);
  for (const [n, x] of sa.types) {
    const y = sb.types.get(n);
    if (!y || !keep(n) || (!pub(x) && !pub(y))) continue;
    const c: NetTypeChange = { type: n, methods: { added: [], removed: [], changed: [], bodyChanged: [] }, fields: { added: [], removed: [], changed: [] } };
    if (x.kind !== y.kind) c.kind = { from: x.kind, to: y.kind };
    if (x.visibility !== y.visibility) c.visibility = { from: x.visibility, to: y.visibility };
    if (x.extends !== y.extends) c.extends = { from: x.extends, to: y.extends };
    const ia = new Set(x.interfaces), ib = new Set(y.interfaces);
    const add = y.interfaces.filter((i) => !ia.has(i)), rem = x.interfaces.filter((i) => !ib.has(i));
    if (add.length || rem.length) c.interfaces = { added: add, removed: rem };
    for (const [k, m] of y.methods) { if (!pubM(m)) continue; const o = x.methods.get(k); if (!o) c.methods.added.push(desc(m)); else { if (desc(o) !== desc(m)) c.methods.changed.push({ key: k, from: desc(o), to: desc(m) }); if (opts.bodies && o.body !== m.body) c.methods.bodyChanged.push(k); } }
    for (const [k, m] of x.methods) if (pubM(m) && !y.methods.has(k)) c.methods.removed.push(desc(m));
    for (const [k, fl] of y.fields) { if (!pubM(fl)) continue; const o = x.fields.get(k); if (!o) c.fields.added.push(desc(fl)); else if (desc(o) !== desc(fl)) c.fields.changed.push({ name: k, from: desc(o), to: desc(fl) }); }
    for (const [k, fl] of x.fields) if (pubM(fl) && !y.fields.has(k)) c.fields.removed.push(desc(fl));
    const any = c.kind || c.visibility || c.extends || c.interfaces || c.methods.added.length || c.methods.removed.length || c.methods.changed.length || c.methods.bodyChanged.length || c.fields.added.length || c.fields.removed.length || c.fields.changed.length;
    if (!any) { d.types.unchanged++; continue; }
    d.types.changed++;
    d.methods.added += c.methods.added.length; d.methods.removed += c.methods.removed.length; d.methods.changed += c.methods.changed.length; d.methods.bodyChanged += c.methods.bodyChanged.length;
    d.fields.added += c.fields.added.length; d.fields.removed += c.fields.removed.length; d.fields.changed += c.fields.changed.length;
    if (d.changes.length < (opts.maxChanges ?? 5000)) d.changes.push(c); else d.truncated = true;
  }
  return d;
}

export interface PInvokeBinding { library: string; entry: string; member: string; token: string; charset: string; exactSpelling: boolean; callConv: string; setLastError: boolean; status: 'resolved' | 'missing-export' | 'library-not-shipped'; matches: { file: string; platform: string; export: string; address?: string; ordinal?: number; forwarder?: string }[] }

const CHARSET = ['NotSpec', 'Ansi', 'Unicode', 'Auto'];
const CALLCONV: Record<number, string> = { 0x100: 'Winapi', 0x200: 'Cdecl', 0x300: 'StdCall', 0x400: 'ThisCall', 0x500: 'FastCall' };

/** Match every DllImport (ImplMap row) to the exports of the native libraries shipped with the assembly. */
export function mapPInvokes(asm: DotnetAssembly, libs: { name: string; bytes: Uint8Array }[]): { bindings: PInvokeBinding[]; libraries: { file: string; format: string; arch?: string; exports: number; referenced: number; error?: string }[]; summary: Record<string, number> } {
  const parsed: { file: string; base: string; lib?: NativeLibrary; error?: string }[] = libs.map((l) => {
    const base = l.name.replace(/^.*[\\/]/, '');
    try { return { file: l.name, base, lib: nativeExports(l.bytes) }; } catch (e) { return { file: l.name, base, error: (e as Error).message }; }
  });
  const refs = new Map<string, Set<string>>();
  const bindings: PInvokeBinding[] = pinvokes(asm).map((p) => {
    const charset = CHARSET[(p.flags >> 1) & 3] ?? '?';
    const exact = (p.flags & 1) !== 0;
    const b: PInvokeBinding = { library: p.library, entry: p.entry, member: p.member, token: p.token, charset, exactSpelling: exact, callConv: CALLCONV[p.flags & 0x700] ?? 'default', setLastError: (p.flags & 0x40) !== 0, status: 'library-not-shipped', matches: [] };
    const names = new Set(probingNames(p.library).map((n) => n.toLowerCase()));
    const cands = parsed.filter((x) => names.has(x.base.toLowerCase()) || x.lib?.soname && names.has(x.lib.soname.toLowerCase()));
    if (!cands.length) return b;
    b.status = 'missing-export';
    for (const c of cands) {
      if (!c.lib) continue;
      const platform = c.lib.format === 'pe' ? `windows-${c.lib.arch ?? '?'}` : c.lib.format === 'macho' ? `macos-${c.lib.arch ?? '?'}` : `linux-${c.lib.arch ?? '?'}`;
      // Windows also probes the A and W suffixed names when ExactSpelling is off
      const tries = [p.entry];
      if (c.lib.format === 'pe' && !exact) tries.push(p.entry + (charset === 'Unicode' ? 'W' : 'A'));
      if (/^#\d+$/.test(p.entry)) tries.push(p.entry);
      const hit = c.lib.exports.find((e) => tries.includes(e.name) || (/^#\d+$/.test(p.entry) && e.ordinal === Number(p.entry.slice(1))));
      if (hit) {
        b.status = 'resolved';
        b.matches.push({ file: c.file, platform, export: hit.name, address: hit.address, ordinal: hit.ordinal, forwarder: hit.forwarder });
        const s = refs.get(c.file) ?? new Set(); s.add(hit.name); refs.set(c.file, s);
      }
    }
    return b;
  });
  const summary: Record<string, number> = { total: bindings.length, resolved: 0, 'missing-export': 0, 'library-not-shipped': 0 };
  for (const b of bindings) summary[b.status] = (summary[b.status] ?? 0) + 1;
  return {
    bindings, summary,
    libraries: parsed.map((x) => ({ file: x.file, format: x.lib?.format ?? 'unknown', arch: x.lib?.arch, exports: x.lib?.exports.length ?? 0, referenced: refs.get(x.file)?.size ?? 0, error: x.error })),
  };
}

export { ParseError };
