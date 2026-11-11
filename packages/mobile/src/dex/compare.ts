// Member level diff of two DEX sets (two APK versions, two classes.dex): classes, methods,
// fields, access flags, superclass and interfaces, and optionally method bodies compared as
// rendered smali (so index renumbering between builds does not count as a change).

import { accessString, renderMethodBody } from './disasm.js';
import { toJavaName, type DexFile } from './parse.js';

export interface MemberSig { name: string; descriptor: string; access: string }
export interface ClassSnapshot { name: string; access: string; superclass?: string; interfaces: string[]; methods: Map<string, MemberSig & { body?: string }>; fields: Map<string, MemberSig>; dex: string }
export interface ClassChange {
  class: string;
  access?: { from: string; to: string };
  superclass?: { from?: string; to?: string };
  interfaces?: { added: string[]; removed: string[] };
  methods: { added: MemberSig[]; removed: MemberSig[]; accessChanged: { name: string; descriptor: string; from: string; to: string }[]; bodyChanged: string[] };
  fields: { added: MemberSig[]; removed: MemberSig[]; accessChanged: { name: string; descriptor: string; from: string; to: string }[] };
}
export interface DexDiff {
  classes: { a: number; b: number; added: string[]; removed: string[]; changed: number; unchanged: number };
  methods: { added: number; removed: number; accessChanged: number; bodyChanged: number };
  fields: { added: number; removed: number; accessChanged: number };
  changes: ClassChange[];
  truncated: boolean;
}

const hashText = (s: string): string => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(16).padStart(8, '0'); };

/** Snapshot the member signatures of every class in a DEX set. */
export function snapshotDex(dexes: DexFile[], opts: { bodies?: boolean; maxClasses?: number; deadline?: number } = {}): { classes: Map<string, ClassSnapshot>; truncated: boolean } {
  const out = new Map<string, ClassSnapshot>();
  const max = opts.maxClasses ?? 200_000;
  let truncated = false;
  for (const d of dexes) {
    for (const cd of d.classes) {
      if (out.size >= max || (opts.deadline && Date.now() > opts.deadline)) { truncated = true; break; }
      if (out.has(cd.name)) continue; // first definition wins, as at runtime
      const s: ClassSnapshot = { name: toJavaName(cd.name), access: accessString(cd.access, 'c'), superclass: cd.superclass ? toJavaName(cd.superclass) : undefined, interfaces: cd.interfaces.map(toJavaName), methods: new Map(), fields: new Map(), dex: d.name };
      const data = d.classData(cd);
      for (const f of [...data.staticFields, ...data.instanceFields]) {
        const id = d.field(f.fieldIdx);
        s.fields.set(`${id.name}:${id.type}`, { name: id.name, descriptor: id.type, access: accessString(f.access, 'f') });
      }
      for (const [m, isStatic] of [...data.directMethods.map((x) => [x, (x.access & 0x8) !== 0] as const), ...data.virtualMethods.map((x) => [x, false] as const)]) {
        const id = d.method(m.methodIdx);
        const desc = `(${id.proto.params.join('')})${id.proto.ret}`;
        const e: MemberSig & { body?: string } = { name: id.name, descriptor: desc, access: accessString(m.access, 'm') };
        if (opts.bodies && m.codeOff) {
          try { const ci = d.code(m.codeOff); if (ci) e.body = hashText(renderMethodBody(d, ci, isStatic).join('\n')); } catch { e.body = 'unreadable'; }
        }
        s.methods.set(`${id.name}${desc}`, e);
      }
      out.set(cd.name, s);
    }
  }
  return { classes: out, truncated };
}

/** Diff two DEX sets at member level. */
export function compareDex(a: DexFile[], b: DexFile[], opts: { bodies?: boolean; filter?: string; maxChanges?: number; budgetMs?: number } = {}): DexDiff {
  const deadline = Date.now() + (opts.budgetMs ?? 60_000);
  const sa = snapshotDex(a, { bodies: opts.bodies, deadline }), sb = snapshotDex(b, { bodies: opts.bodies, deadline });
  const f = opts.filter?.toLowerCase();
  const keep = (n: string): boolean => !f || toJavaName(n).toLowerCase().includes(f);
  const diff: DexDiff = { classes: { a: sa.classes.size, b: sb.classes.size, added: [], removed: [], changed: 0, unchanged: 0 }, methods: { added: 0, removed: 0, accessChanged: 0, bodyChanged: 0 }, fields: { added: 0, removed: 0, accessChanged: 0 }, changes: [], truncated: sa.truncated || sb.truncated };
  const maxChanges = opts.maxChanges ?? 5000;
  for (const n of sb.classes.keys()) if (!sa.classes.has(n) && keep(n)) diff.classes.added.push(toJavaName(n));
  for (const n of sa.classes.keys()) if (!sb.classes.has(n) && keep(n)) diff.classes.removed.push(toJavaName(n));
  for (const [n, x] of sa.classes) {
    const y = sb.classes.get(n);
    if (!y || !keep(n)) continue;
    const c: ClassChange = { class: x.name, methods: { added: [], removed: [], accessChanged: [], bodyChanged: [] }, fields: { added: [], removed: [], accessChanged: [] } };
    if (x.access !== y.access) c.access = { from: x.access, to: y.access };
    if (x.superclass !== y.superclass) c.superclass = { from: x.superclass, to: y.superclass };
    const ia = new Set(x.interfaces), ib = new Set(y.interfaces);
    const iAdd = y.interfaces.filter((i) => !ia.has(i)), iRem = x.interfaces.filter((i) => !ib.has(i));
    if (iAdd.length || iRem.length) c.interfaces = { added: iAdd, removed: iRem };
    for (const [k, m] of y.methods) { const o = x.methods.get(k); if (!o) c.methods.added.push(strip(m)); else { if (o.access !== m.access) c.methods.accessChanged.push({ name: m.name, descriptor: m.descriptor, from: o.access, to: m.access }); if (opts.bodies && o.body !== m.body) c.methods.bodyChanged.push(k); } }
    for (const [k, m] of x.methods) if (!y.methods.has(k)) c.methods.removed.push(strip(m));
    for (const [k, fl] of y.fields) { const o = x.fields.get(k); if (!o) c.fields.added.push(fl); else if (o.access !== fl.access) c.fields.accessChanged.push({ name: fl.name, descriptor: fl.descriptor, from: o.access, to: fl.access }); }
    for (const [k, fl] of x.fields) if (!y.fields.has(k)) c.fields.removed.push(fl);
    const any = c.access || c.superclass || c.interfaces || c.methods.added.length || c.methods.removed.length || c.methods.accessChanged.length || c.methods.bodyChanged.length || c.fields.added.length || c.fields.removed.length || c.fields.accessChanged.length;
    if (!any) { diff.classes.unchanged++; continue; }
    diff.classes.changed++;
    diff.methods.added += c.methods.added.length; diff.methods.removed += c.methods.removed.length; diff.methods.accessChanged += c.methods.accessChanged.length; diff.methods.bodyChanged += c.methods.bodyChanged.length;
    diff.fields.added += c.fields.added.length; diff.fields.removed += c.fields.removed.length; diff.fields.accessChanged += c.fields.accessChanged.length;
    if (diff.changes.length < maxChanges) diff.changes.push(c); else diff.truncated = true;
  }
  return diff;
}
const strip = (m: MemberSig & { body?: string }): MemberSig => ({ name: m.name, descriptor: m.descriptor, access: m.access });
