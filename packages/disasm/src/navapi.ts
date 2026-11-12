// Navigation and annotation tools: context of an address, names, containing function, next and
// previous objects, comments, inline comments, bookmarks and analyst names (in process, per binary
// content, exportable as JSON), function info, name search with linear time regex, name listing,
// instruction operand tokens, the one call function dossier and the API boundary view.
import type { AnalyzedFunction, BasicBlock, FunctionInfo, Insn } from './types.js';
import type { Program } from './analysis/program.js';
import { openProgram, resolveFunction, summarizeFunction, type BinaryInput } from './api.js';
import { liftFunction } from './analysis/lift.js';
import { liftDebugFor } from './debug/liftdebug.js';
import { stringAt } from './analysis/strings.js';
import { SafeRegex } from './saferegex.js';
import { clampInt, hx, parseAddr, splitOperands, parseImm } from './util.js';

// ---------------- annotations ----------------

export interface Annotations {
  comments: Map<number, string>;
  inline: Map<number, string>;
  bookmarks: Map<number, string | null>;
  names: Map<number, string>;
  /** function names replaced by analyst names, to restore on unset */
  replaced: Map<number, string>;
}
const stores = new Map<string, Annotations>();
const MAX_NAME = 1024;
const MAX_COMMENT = 65536;
const MAX_ENTRIES = 200000;

function contentKey(p: Program): string {
  if (p.contentKey) return p.contentKey;
  const b = p.img.bytes;
  let h = 2166136261;
  for (let i = 0; i < b.length; i++) { h ^= b[i]!; h = Math.imul(h, 16777619); }
  p.contentKey = `${b.length}:${(h >>> 0).toString(16)}:${p.img.fileOffset}:${p.img.arch}`;
  return p.contentKey;
}

/** The annotation store of a program's bytes (created on first use and linked to its names). */
export function annotationsOf(p: Program): Annotations {
  const k = contentKey(p);
  let a = stores.get(k);
  if (!a) { a = { comments: new Map(), inline: new Map(), bookmarks: new Map(), names: new Map(), replaced: new Map() }; stores.set(k, a); }
  if (p.userNames !== a.names) {
    p.userNames = a.names;
    for (const [addr, n] of a.names) { const f = p.functions.get(addr); if (f && f.name !== n) { if (!a.replaced.has(addr)) a.replaced.set(addr, f.name); f.name = n; } }
  }
  return a;
}

/** Drop every annotation store (tests). */
export function clearAnnotations(): void { stores.clear(); }

async function prog(input: BinaryInput): Promise<Program> {
  const p = await openProgram(input);
  if (stores.size) annotationsOf(p);
  return p;
}

function addrOf(p: Program, input: { address?: unknown; fileOffset?: unknown }): number {
  if (input.fileOffset !== undefined && input.fileOffset !== null && input.fileOffset !== '') {
    const off = parseAddr(input.fileOffset);
    if (off === undefined) throw new Error(`bad file offset: ${String(input.fileOffset)}`);
    const a = fileOffsetToAddr(p, off);
    if (a === undefined) throw new Error(`file offset ${hx(off)} is not mapped to memory (header, overlay or outside the image)`);
    return a;
  }
  const a = parseAddr(input.address);
  if (a !== undefined) return a;
  if (typeof input.address === 'string' && input.address) {
    const f = resolveFunction(p, input.address);
    if (f) return f.addr;
    const s = p.img.symbols.find((x) => x.name === input.address);
    if (s) return s.addr;
    for (const [addr, n] of p.userNames) if (n === input.address) return addr;
  }
  throw new Error(`bad address: ${String(input.address)}`);
}

/** Virtual address of a file offset, or undefined when no loaded region holds it. */
export function fileOffsetToAddr(p: Program, off: number): number | undefined {
  const rel = off - p.img.fileOffset;
  for (const r of p.mem.regions) if (r.fsize > 0 && rel >= r.offset && rel < r.offset + r.fsize) return r.start + (rel - r.offset);
  return undefined;
}

const fileOff = (p: Program, a: number) => { const o = p.mem.toOffset(a); return o >= 0 ? o + p.img.fileOffset : undefined; };

function requireMapped(p: Program, a: number): void {
  if (!p.mem.isMapped(a)) throw new Error(`address ${hx(a)} is not mapped`);
}

/** Function and the exact instruction holding addr, from CFG analysis (not a guess from nearby symbols). */
function locate(p: Program, a: number): { f?: FunctionInfo; af?: AnalyzedFunction; block?: BasicBlock; insn?: Insn } {
  p.discover();
  const tryFn = (f: FunctionInfo | undefined) => {
    if (!f) return undefined;
    const af = p.analyze(f.addr);
    if (!af) return undefined;
    for (const b of af.blocks) if (a >= b.start && a < b.end) {
      const insn = b.insns.find((i) => a >= i.address && a < i.address + i.size);
      return { f, af, block: b, insn };
    }
    return undefined;
  };
  const direct = tryFn(p.functions.get(a)) ?? tryFn(p.functionContaining(a));
  if (direct) return direct;
  // nearest preceding function starts (functions without sizes)
  const arr = p.sortedFunctionAddrs();
  let lo = 0, hi = arr.length - 1, best = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (arr[mid]! <= a) { best = mid; lo = mid + 1; } else hi = mid - 1; }
  for (let k = best; k >= 0 && k > best - 4; k--) { const r = tryFn(p.functions.get(arr[k]!)); if (r) return r; }
  return {};
}

// ---------------- names ----------------

/** Primary name at an address: analyst name, function, symbol, import stub or slot, DWARF global; null when unnamed. */
export async function disasmAddressName(input: BinaryInput & { address?: string | number; fileOffset?: string | number }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  p.discover();
  const user = p.userNames.get(a);
  const f = p.functions.get(a);
  const s = p.symAt.get(a);
  const stub = p.importByStub.get(a);
  const slot = p.importBySlot.get(a);
  const g = p.dwarf().globals.find((x) => x.addr === a && !x.declaration);
  let name: string | null = null, kind: string | null = null, source: string | null = null;
  if (user) { name = user; kind = 'user'; source = 'analyst'; }
  else if (stub) { name = stub.name; kind = 'import-stub'; source = stub.library ?? 'import'; }
  else if (f) { name = f.name; kind = 'function'; source = f.source; }
  else if (s) { name = s.name; kind = s.kind === 'object' ? 'data' : s.kind === 'func' ? 'function' : 'symbol'; source = s.source; }
  else if (slot) { name = slot.name; kind = 'import-slot'; source = slot.library ?? 'import'; }
  else if (g) { name = g.name; kind = 'data'; source = 'dwarf'; }
  return { address: hx(a), fileOffset: fileOff(p, a), mapped: p.mem.isMapped(a), name, kind, source, ...(user && (f || s) ? { originalName: (annotationsOf(p).replaced.get(a) ?? s?.name) } : {}) };
}

/** Assign an analyst name to a mapped address; empty name clears it. Returns readback. */
export async function disasmSetName(input: BinaryInput & { address: string | number; name: string; force?: boolean }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  requireMapped(p, a);
  const st = annotationsOf(p);
  const name = String(input.name ?? '');
  if (name.length > MAX_NAME) throw new Error(`name longer than ${MAX_NAME} characters`);
  if (/[\u0000-\u001f]/.test(name)) throw new Error('name has control characters');
  p.discover();
  const f = p.functions.get(a);
  if (!name) {
    st.names.delete(a);
    if (f && st.replaced.has(a)) { f.name = st.replaced.get(a)!; st.replaced.delete(a); }
    return { address: hx(a), cleared: true, readback: (await disasmAddressName({ ...input, address: hx(a) })).name };
  }
  for (const [other, n] of st.names) {
    if (n === name && other !== a) {
      if (!input.force) throw new Error(`name "${name}" is already used at ${hx(other)} (pass force to move it)`);
      st.names.delete(other);
      const of = p.functions.get(other);
      if (of && st.replaced.has(other)) { of.name = st.replaced.get(other)!; st.replaced.delete(other); }
    }
  }
  if (st.names.size >= MAX_ENTRIES && !st.names.has(a)) throw new Error('too many names');
  st.names.set(a, name);
  if (f) { if (!st.replaced.has(a)) st.replaced.set(a, f.name); f.name = name; }
  const rb = await disasmAddressName({ ...input, address: hx(a) });
  return { address: hx(a), name, readback: rb.name, matches: rb.name === name };
}

type CommentKind = 'regular' | 'inline';
const commentMap = (st: Annotations, kind: unknown) => (kind === 'inline' ? st.inline : st.comments);

/** Read the comment (regular or inline) at an address; null when absent. */
export async function disasmGetComment(input: BinaryInput & { address?: string | number; fileOffset?: string | number; kind?: CommentKind }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  const st = annotationsOf(p);
  return { address: hx(a), kind: input.kind === 'inline' ? 'inline' : 'regular', comment: commentMap(st, input.kind).get(a) ?? null };
}

/** Write a comment (regular or inline) at a mapped address; empty text clears. Returns readback. */
export async function disasmSetComment(input: BinaryInput & { address?: string | number; fileOffset?: string | number; comment: string; kind?: CommentKind }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  requireMapped(p, a);
  const st = annotationsOf(p);
  const m = commentMap(st, input.kind);
  const text = String(input.comment ?? '');
  if (text.length > MAX_COMMENT) throw new Error(`comment longer than ${MAX_COMMENT} characters`);
  if (!text) m.delete(a);
  else { if (m.size >= MAX_ENTRIES && !m.has(a)) throw new Error('too many comments'); m.set(a, text); }
  const rb = m.get(a) ?? null;
  return { address: hx(a), kind: input.kind === 'inline' ? 'inline' : 'regular', cleared: !text, readback: rb, matches: text ? rb === text : rb === null };
}

/** Every comment (regular, inline or both) with the function it sits in. */
export async function disasmListComments(input: BinaryInput & { kind?: CommentKind | 'all'; offset?: number; limit?: number }) {
  const p = await prog(input);
  const st = annotationsOf(p);
  const rows: { address: string; kind: string; comment: string; function?: string }[] = [];
  const add = (m: Map<number, string>, kind: string) => { for (const [a, c] of m) rows.push({ address: hx(a), kind, comment: c, function: p.functionContaining(a)?.name }); };
  if (input.kind !== 'inline') add(st.comments, 'regular');
  if (input.kind === 'inline' || input.kind === 'all' || input.kind === undefined) add(st.inline, 'inline');
  rows.sort((x, y) => parseInt(x.address, 16) - parseInt(y.address, 16));
  return page(rows, input.offset, input.limit, 200, 5000);
}

/** Create or update a bookmark; omit name to keep an existing name, empty name clears the name. */
export async function disasmSetBookmark(input: BinaryInput & { address?: string | number; fileOffset?: string | number; name?: string }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  requireMapped(p, a);
  const st = annotationsOf(p);
  if (input.name !== undefined && String(input.name).length > MAX_NAME) throw new Error(`bookmark name longer than ${MAX_NAME} characters`);
  const prev = st.bookmarks.get(a);
  const name = input.name === undefined ? (prev ?? null) : String(input.name) === '' ? null : String(input.name);
  if (st.bookmarks.size >= MAX_ENTRIES && !st.bookmarks.has(a)) throw new Error('too many bookmarks');
  st.bookmarks.set(a, name);
  return { address: hx(a), name, created: prev === undefined, readback: st.bookmarks.has(a), matches: st.bookmarks.get(a) === name };
}

/** Remove the bookmark at an address; reports whether it is now absent. */
export async function disasmUnsetBookmark(input: BinaryInput & { address?: string | number; fileOffset?: string | number }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  const st = annotationsOf(p);
  const had = st.bookmarks.delete(a);
  return { address: hx(a), removed: had, absent: !st.bookmarks.has(a) };
}

/** Every bookmark as address and name (null for unnamed). */
export async function disasmListBookmarks(input: BinaryInput & { offset?: number; limit?: number }) {
  const p = await prog(input);
  const st = annotationsOf(p);
  const rows = [...st.bookmarks].sort((x, y) => x[0] - y[0]).map(([a, n]) => ({ address: hx(a), name: n, function: p.functionContaining(a)?.name }));
  return page(rows, input.offset, input.limit, 200, 5000);
}

/** Export, import or clear the annotations (comments, inline comments, bookmarks, names) of a binary as JSON. */
export async function disasmAnnotations(input: BinaryInput & { action?: 'export' | 'import' | 'clear'; data?: unknown; merge?: boolean }) {
  const p = await prog(input);
  const st = annotationsOf(p);
  const action = input.action ?? 'export';
  if (action === 'clear') {
    for (const [a, n] of st.replaced) { const f = p.functions.get(a); if (f) f.name = n; }
    st.comments.clear(); st.inline.clear(); st.bookmarks.clear(); st.names.clear(); st.replaced.clear();
    return { cleared: true };
  }
  if (action === 'import') {
    const d = (typeof input.data === 'string' ? JSON.parse(input.data) : input.data) as { comments?: Record<string, string>; inline?: Record<string, string>; bookmarks?: Record<string, string | null>; names?: Record<string, string> } | undefined;
    if (!d || typeof d !== 'object') throw new Error('pass data: the JSON an export returned');
    if (!input.merge) { st.comments.clear(); st.inline.clear(); st.bookmarks.clear(); }
    let n = 0;
    const each = (o: Record<string, unknown> | undefined, f: (a: number, v: unknown) => void) => {
      for (const [k, v] of Object.entries(o ?? {})) { const a = parseAddr(k); if (a === undefined || !p.mem.isMapped(a)) continue; if (++n > MAX_ENTRIES) throw new Error('too many entries'); f(a, v); }
    };
    each(d.comments, (a, v) => { if (typeof v === 'string' && v && v.length <= MAX_COMMENT) st.comments.set(a, v); });
    each(d.inline, (a, v) => { if (typeof v === 'string' && v && v.length <= MAX_COMMENT) st.inline.set(a, v); });
    each(d.bookmarks, (a, v) => { st.bookmarks.set(a, typeof v === 'string' && v ? v.slice(0, MAX_NAME) : null); });
    for (const [k, v] of Object.entries(d.names ?? {})) if (typeof v === 'string' && v) { try { await disasmSetName({ ...input, address: k, name: v, force: true }); } catch { /* skip unmapped */ } }
    return { imported: true, comments: st.comments.size, inline: st.inline.size, bookmarks: st.bookmarks.size, names: st.names.size };
  }
  const obj = <T>(m: Map<number, T>) => Object.fromEntries([...m].sort((x, y) => x[0] - y[0]).map(([a, v]) => [hx(a), v]));
  return { format: 'revlens-disasm-annotations/1', binary: { format: p.img.format, arch: p.img.arch, key: contentKey(p) }, comments: obj(st.comments), inline: obj(st.inline), bookmarks: obj(st.bookmarks), names: obj(st.names) };
}

// ---------------- containing function, next / previous ----------------

/** Function containing an address (interior instruction or entry). Distinguishes outside-segments from not-in-function. */
export async function disasmContainingFunction(input: BinaryInput & { address?: string | number; fileOffset?: string | number }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  if (!p.mem.isMapped(a)) return { address: hx(a), status: 'outside-segments', function: null };
  const imp = p.importByStub.get(a);
  const loc = locate(p, a);
  if (!loc.f || !loc.af) {
    return { address: hx(a), section: p.mem.sectionName(a), status: 'not-in-function', function: null, ...(imp ? { importStub: imp.name } : {}), executable: p.mem.isExec(a) };
  }
  const af = loc.af;
  return {
    address: hx(a), section: p.mem.sectionName(a), status: 'in-function',
    function: { name: af.name, addr: hx(af.addr), offset: a - af.addr, ...(af.isImportStub ? { importStub: true } : {}) },
    instruction: loc.insn ? { addr: hx(loc.insn.address), size: loc.insn.size, text: (loc.insn.mnemonic + ' ' + loc.insn.operands).trim(), interior: loc.insn.address !== a } : null,
    block: loc.block ? { start: hx(loc.block.start), end: hx(loc.block.end) } : null,
    bodyRanges: bodyRanges(af).map(([s, e]) => ({ start: hx(s), endInclusive: hx(e - 1) })),
  };
}

/** Merged [start, end) ranges covered by a function's decoded instructions. */
export function bodyRanges(af: AnalyzedFunction): [number, number][] {
  const r = af.blocks.map((b) => [b.start, b.end] as [number, number]).sort((x, y) => x[0] - y[0]);
  const out: [number, number][] = [];
  for (const [s, e] of r) { const last = out[out.length - 1]; if (last && s <= last[1]) last[1] = Math.max(last[1], e); else out.push([s, e]); }
  return out;
}

type Unit = 'object' | 'instruction' | 'function' | 'symbol' | 'bookmark' | 'comment';

function objectStarts(p: Program, a: number, unit: Unit, forward: boolean): { addr: number; kind: string; name?: string }[] {
  p.discover();
  const out: { addr: number; kind: string; name?: string }[] = [];
  const st = stores.size ? annotationsOf(p) : undefined;
  if (unit === 'bookmark') { for (const [b, n] of st?.bookmarks ?? []) out.push({ addr: b, kind: 'bookmark', name: n ?? undefined }); return out; }
  if (unit === 'comment') { for (const b of st?.comments.keys() ?? []) out.push({ addr: b, kind: 'comment' }); for (const b of st?.inline.keys() ?? []) out.push({ addr: b, kind: 'comment' }); return out; }
  if (unit === 'function' || unit === 'object') for (const f of p.functions.values()) out.push({ addr: f.addr, kind: 'function', name: f.name });
  if (unit === 'symbol' || unit === 'object') for (const s of p.symbolsSorted()) out.push({ addr: s.addr, kind: s.kind === 'object' ? 'data' : 'symbol', name: s.name });
  if (unit === 'instruction' || unit === 'object') {
    const loc = locate(p, a);
    if (loc.af) for (const b of loc.af.blocks) for (const i of b.insns) out.push({ addr: i.address, kind: 'instruction' });
    else if (p.mem.isExec(a) && forward) for (const i of p.decodeAt(a, 2)) out.push({ addr: i.address, kind: 'instruction' });
  }
  return out;
}

async function step(input: BinaryInput & { address?: string | number; fileOffset?: string | number; unit?: Unit }, forward: boolean) {
  const p = await prog(input);
  const a = addrOf(p, input);
  const unit = (input.unit ?? 'object') as Unit;
  const cands = objectStarts(p, a, unit, forward).filter((c) => (forward ? c.addr > a : c.addr < a) && p.mem.isMapped(c.addr));
  if (!cands.length) return { address: hx(a), unit, [forward ? 'next' : 'previous']: null, note: forward ? 'no analyzed object after this address' : 'no analyzed object before this address' };
  cands.sort((x, y) => (forward ? x.addr - y.addr : y.addr - x.addr) || (x.kind === 'function' ? -1 : 1));
  const c = cands[0]!;
  return { address: hx(a), unit, [forward ? 'next' : 'previous']: hx(c.addr), kind: c.kind, name: c.name ?? p.nameOf(c.addr), distance: Math.abs(c.addr - a), section: p.mem.sectionName(c.addr) };
}

/** Next analyzed object start after an address (instruction, function, data symbol; or unit function, symbol, bookmark, comment). */
export async function disasmNextAddress(input: BinaryInput & { address?: string | number; fileOffset?: string | number; unit?: Unit }) { return step(input, true); }
/** Previous analyzed object start before an address. */
export async function disasmPrevAddress(input: BinaryInput & { address?: string | number; fileOffset?: string | number; unit?: Unit }) { return step(input, false); }

// ---------------- context ----------------

/**
 * Navigation context for an address or file offset: mapping (section, permissions, file offset),
 * containing function and block with the instructions around it, the nearest symbols before and
 * after, incoming references (to the address and to its function), outgoing references (from the
 * instruction and its block), strings at and near the address, and analyst annotations.
 */
export async function disasmContext(input: BinaryInput & { address?: string | number; fileOffset?: string | number; radius?: number; window?: number; budgetMs?: number }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  const radius = clampInt(input.radius, 256, 0, 65536);
  const win = clampInt(input.window, 6, 0, 64);
  const reg = p.mem.find(a);
  const mapping = reg ? { section: reg.name, start: hx(reg.start), end: hx(reg.end), exec: reg.exec, write: reg.write, fileBacked: a - reg.start < reg.fsize } : null;
  const base = { address: hx(a), fileOffset: fileOff(p, a), mapped: !!reg, mapping };
  if (!reg) return { ...base, note: 'address is outside every loaded segment' };
  p.discover();
  const loc = locate(p, a);
  const syms = p.symbolsSorted();
  let lo = 0, hi = syms.length - 1, idx = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (syms[mid]!.addr <= a) { idx = mid; lo = mid + 1; } else hi = mid - 1; }
  const near = (k: number) => syms[k] ? { name: syms[k]!.name, addr: hx(syms[k]!.addr), kind: syms[k]!.kind, distance: syms[k]!.addr - a } : undefined;
  const before = [idx - 2, idx - 1, idx].map(near).filter(Boolean);
  const after = [idx + 1, idx + 2, idx + 3].map(near).filter(Boolean);
  const idxx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  const refsTo = (t: number) => (idxx.to.get(t) ?? []).slice(0, 100).map((r) => ({ from: hx(r.from), kind: r.kind, function: p.functions.get(r.func)?.name ?? hx(r.func) }));
  const st = stores.size ? annotationsOf(p) : undefined;
  let fn: Record<string, unknown> | null = null;
  let around: Record<string, unknown>[] = [];
  let out: Record<string, unknown>[] = [];
  if (loc.af) {
    const af = loc.af;
    const all = af.blocks.slice().sort((x, y) => x.start - y.start).flatMap((b) => b.insns);
    const k = all.findIndex((i) => a >= i.address && a < i.address + i.size);
    around = all.slice(Math.max(0, k - win), k + win + 1).map((i) => ({ addr: hx(i.address), text: (i.mnemonic + ' ' + i.operands).trim(), ...(i.address === loc.insn?.address ? { here: true } : {}), ...(st?.inline.get(i.address) ? { comment: st.inline.get(i.address) } : {}) }));
    const blk = loc.block!;
    for (const i of blk.insns) {
      const call = af.calls.find((c) => c.at === i.address);
      if (call) out.push({ at: hx(i.address), kind: call.tail ? 'jump' : 'call', target: call.target !== undefined ? hx(call.target) : undefined, name: call.name ?? (call.candidates ? `one of ${call.candidates.length}` : '(indirect)') });
      for (const d of af.dataRefs.filter((x) => x.at === i.address)) out.push({ at: hx(i.address), kind: d.kind, target: hx(d.addr), name: d.value });
    }
    for (const e of blk.succ) out.push({ at: hx(blk.end), kind: 'flow-' + e.kind, target: hx(e.to) });
    fn = { name: af.name, addr: hx(af.addr), offset: a - af.addr, size: af.size ?? af.codeSize, blocks: af.blocks.length, block: { start: hx(blk.start), end: hx(blk.end), exit: blk.exit }, callers: refsTo(af.addr).filter((r) => r.kind === 'call' || r.kind === 'jump' || r.kind === 'code-ref').slice(0, 30), debug: p.debugFunction(af.addr)?.prototype };
  } else if (reg.exec) {
    around = p.decodeAt(a, win + 1).map((i) => ({ addr: hx(i.address), text: (i.mnemonic + ' ' + i.operands).trim() }));
  }
  // strings at and near the address
  const strings: { addr: string; value: string; distance: number; referenced: boolean }[] = [];
  const here = stringAt(p.mem, a, 4);
  if (here) strings.push({ addr: hx(a), value: here.value.slice(0, 200), distance: 0, referenced: idxx.to.has(a) });
  if (loc.af) for (const d of loc.af.dataRefs) if (d.kind === 'string' && strings.length < 40 && !strings.some((s) => s.addr === hx(d.addr))) strings.push({ addr: hx(d.addr), value: (d.value ?? '').slice(0, 200), distance: d.addr - a, referenced: true });
  for (const [t, list] of idxx.to) {
    if (strings.length >= 60) break;
    if (Math.abs(t - a) > radius || t === a || !list.some((r) => r.kind === 'string')) continue;
    const s = stringAt(p.mem, t, 4);
    if (s && !strings.some((x) => x.addr === hx(t))) strings.push({ addr: hx(t), value: s.value.slice(0, 200), distance: t - a, referenced: true });
  }
  strings.sort((x, y) => Math.abs(x.distance) - Math.abs(y.distance));
  return {
    ...base, name: p.nameOf(a) ?? null, symbolized: p.symbolize(a) ?? null,
    function: fn, status: loc.af ? 'in-function' : 'not-in-function',
    instruction: loc.insn ? { addr: hx(loc.insn.address), bytes: loc.insn.bytes, text: (loc.insn.mnemonic + ' ' + loc.insn.operands).trim(), interior: loc.insn.address !== a } : null,
    around, nearbySymbols: { before, after },
    xrefsIn: refsTo(a), xrefsOut: out.slice(0, 100), strings: strings.slice(0, 40),
    annotations: st ? { comment: st.comments.get(a) ?? null, inline: st.inline.get(a) ?? null, bookmark: st.bookmarks.has(a) ? st.bookmarks.get(a) ?? '' : null, name: st.names.get(a) ?? null } : null,
    xrefIndexComplete: idxx.complete,
  };
}

// ---------------- names listing and search ----------------

/** Every name: functions, data symbols, imports (external), exports and analyst names, with kind and source. */
export async function disasmListNames(input: BinaryInput & { kind?: string; filter?: string; offset?: number; limit?: number }) {
  const p = await prog(input);
  p.discover();
  const rows: { addr?: string; name: string; kind: string; binding: string; source: string; size?: number }[] = [];
  const seen = new Set<string>();
  const add = (r: (typeof rows)[number]) => { const k = (r.addr ?? '') + '|' + r.name + '|' + r.kind; if (!seen.has(k)) { seen.add(k); rows.push(r); } };
  for (const [a, n] of p.userNames) add({ addr: hx(a), name: n, kind: 'user', binding: 'analyst', source: 'analyst' });
  for (const f of p.functions.values()) add({ addr: hx(f.addr), name: f.name, kind: f.isImportStub ? 'import-stub' : 'function', binding: f.isImportStub ? 'external' : f.source === 'dynsym' || f.source === 'export' ? 'dynamic' : 'primary', source: f.source, size: f.size });
  for (const s of p.img.symbols) {
    if (s.kind === 'func' && p.functions.has(s.addr) && p.functions.get(s.addr)!.name === s.name) continue;
    add({ addr: hx(s.addr), name: s.name, kind: s.kind === 'object' ? 'data' : s.kind === 'func' ? 'function' : 'symbol', binding: s.source === 'dynsym' || s.source === 'export' ? 'dynamic' : s.local ? 'local' : 'primary', source: s.source, size: s.size });
  }
  for (const i of p.img.imports) add({ addr: i.slot !== undefined ? hx(i.slot) : i.stub !== undefined ? hx(i.stub) : undefined, name: i.name, kind: 'import', binding: 'external', source: i.library ?? 'import' });
  for (const g of p.dwarf().globals) if (!g.declaration && g.addr) add({ addr: hx(g.addr), name: g.name, kind: 'data', binding: g.external ? 'primary' : 'local', source: 'dwarf' });
  let list = rows;
  if (input.kind) list = list.filter((r) => r.kind === input.kind || r.binding === input.kind);
  if (input.filter) { const q = String(input.filter).toLowerCase(); list = list.filter((r) => r.name.toLowerCase().includes(q)); }
  list.sort((x, y) => (x.addr ? parseInt(x.addr, 16) : Infinity) - (y.addr ? parseInt(y.addr, 16) : Infinity) || x.name.localeCompare(y.name));
  const counts: Record<string, number> = {};
  for (const r of rows) counts[r.kind] = (counts[r.kind] ?? 0) + 1;
  return { counts, ...page(list, input.offset, input.limit, 200, 10000) };
}

/** Search function names (and secondary names: other symbols at the entry, DWARF linkage names) by substring or linear time regex. */
export async function disasmSearchFunctions(input: BinaryInput & { pattern: string; regex?: boolean; caseSensitive?: boolean; includeImports?: boolean; offset?: number; limit?: number }) {
  const p = await prog(input);
  p.discover();
  const pat = String(input.pattern ?? '');
  if (!pat) throw new Error('pass pattern');
  const cs = !!input.caseSensitive;
  let test: (s: string) => boolean;
  if (input.regex) { const re = new SafeRegex(pat, { caseInsensitive: !cs }); test = (s) => re.test(s); }
  else { const q = cs ? pat : pat.toLowerCase(); test = (s) => (cs ? s : s.toLowerCase()).includes(q); }
  const aliases = new Map<number, Set<string>>();
  const addAlias = (a: number, n: string) => { let s = aliases.get(a); if (!s) aliases.set(a, (s = new Set())); s.add(n); };
  for (const s of p.img.symbols) if (s.kind === 'func') addAlias(s.addr, s.name);
  for (const f of p.dwarf().functions) if (f.low) { addAlias(f.low, f.name); if (f.linkageName) addAlias(f.low, f.linkageName); if (f.qualifiedName) addAlias(f.low, f.qualifiedName); }
  const st = stores.size ? annotationsOf(p) : undefined;
  for (const [a, n] of st?.replaced ?? []) addAlias(a, n);
  const rows: { addr: string; name: string; matchedName: boolean; matchedAliases: string[]; size?: number; source: string; importStub?: boolean }[] = [];
  for (const f of [...p.functions.values()].sort((x, y) => x.addr - y.addr)) {
    if (f.isImportStub && !input.includeImports) continue;
    const m = test(f.name);
    const al = [...(aliases.get(f.addr) ?? [])].filter((n) => n !== f.name && test(n));
    if (m || al.length) rows.push({ addr: hx(f.addr), name: f.name, matchedName: m, matchedAliases: al, size: f.size ?? p.analysisSizeHint(f.addr), source: f.source, ...(f.isImportStub ? { importStub: true } : {}) });
  }
  return { pattern: pat, mode: input.regex ? 'regex' : 'literal', caseSensitive: cs, complete: p.discoveryComplete, ...page(rows, input.offset, input.limit, 200, 10000) };
}

// ---------------- instruction ----------------

interface Tok { kind: 'register' | 'immediate' | 'memory' | 'address' | 'shift' | 'other'; text: string; value?: string; base?: string; index?: string; scale?: number; displacement?: number; size?: number; segment?: string }

const X86_REG = /^(?:[re]?[abcd]x|[abcd][lh]|[re]?[sd]il?|[re]?[sb]pl?|r(?:[89]|1[0-5])[dwb]?|[re]?ip|[c-gs]s|[xyz]mm\d+|k[0-7]|st\(\d\)|cr\d|dr\d|mm\d)$/;
const ARM_REG = /^(?:[xwvqdshb]\d+|[xw]zr|w?sp|lr|pc|fp|ip|r\d+|cpsr|nzcv|v\d+\.\d*[bhsd])$/;

function tokenize(arch: string, ops: string): Tok[] {
  const out: Tok[] = [];
  for (const raw of splitOperands(ops)) {
    const t = raw.trim();
    const mem = t.indexOf('[');
    if (mem >= 0 || /^-?(0x[0-9a-f]+)?\((r\d+)\)$/.test(t)) {
      const tok: Tok = { kind: 'memory', text: t };
      const sz = /\b(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword) ptr\b/.exec(t);
      if (sz) tok.size = ({ byte: 1, word: 2, dword: 4, qword: 8, tbyte: 10, xmmword: 16, ymmword: 32, zmmword: 64 } as Record<string, number>)[sz[1]!];
      const seg = /\b([c-gs]s):\[/.exec(t); if (seg) tok.segment = seg[1];
      if (mem >= 0) {
        const inner = t.slice(mem + 1, t.lastIndexOf(']')).replace(/#/g, '');
        if (arch === 'arm64' || arch === 'arm') {
          const parts = inner.split(',').map((x) => x.trim());
          tok.base = parts[0];
          for (const q of parts.slice(1)) { const v = parseImm(q); if (v !== undefined) tok.displacement = v; else if (/^(lsl|uxtw|sxtw|sxtx)/.test(q)) { const k = /(\d+)$/.exec(q); if (k) tok.scale = 2 ** Number(k[1]); } else tok.index = q; }
        } else {
          for (const term of inner.replace(/\s+/g, '').replace(/-/g, '+-').split('+').filter(Boolean)) {
            const sc = /^([a-z0-9]+)\*(\d)$/.exec(term);
            if (sc) { tok.index = sc[1]; tok.scale = Number(sc[2]); continue; }
            const v = parseImm(term);
            if (v !== undefined) tok.displacement = (tok.displacement ?? 0) + v;
            else if (!tok.base) tok.base = term; else tok.index = term;
          }
        }
      } else {
        const m = /^(-?0x[0-9a-f]+)?\((r\d+)\)$/.exec(t)!;
        tok.base = m[2]; tok.displacement = m[1] ? parseImm(m[1]) : 0;
      }
      out.push(tok);
      continue;
    }
    const v = parseImm(t);
    if (v !== undefined) { out.push({ kind: 'immediate', text: t, value: v < 0 ? '-' + hx(-v) : hx(v) }); continue; }
    const r = t.replace(/^#/, '').replace(/!$/, '');
    if (X86_REG.test(r) || ARM_REG.test(r) || /^(?:r\d+|cr\d|f\d+|lr|ctr)$/.test(r)) { out.push({ kind: 'register', text: t }); continue; }
    if (/^(lsl|lsr|asr|ror|uxt[bhw]|sxt[bhwx])\b/.test(t)) { out.push({ kind: 'shift', text: t }); continue; }
    out.push({ kind: 'other', text: t });
  }
  return out;
}

/** One instruction at an address: bytes, mnemonic, ordered operand tokens (registers, immediates, memory with base/index/scale/displacement), flow, outgoing and typed incoming references. */
export async function disasmInstruction(input: BinaryInput & { address?: string | number; fileOffset?: string | number; thumb?: boolean; budgetMs?: number }) {
  const p = await prog(input);
  const a = addrOf(p, input);
  if (!p.mem.isMapped(a)) return { address: hx(a), status: 'outside-segments' };
  const loc = locate(p, a);
  let insn = loc.insn;
  let containing = false;
  if (insn && insn.address !== a) containing = true;
  if (!insn) {
    if (!p.mem.isExec(a)) {
      const s = stringAt(p.mem, a, 4);
      const sym = p.symAt.get(a);
      const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
      return { address: hx(a), status: 'data', section: p.mem.sectionName(a), name: sym?.name ?? null, string: s?.value ?? null, incoming: (idx.to.get(a) ?? []).slice(0, 200).map((r) => ({ from: hx(r.from), kind: r.kind, function: p.functions.get(r.func)?.name })) };
    }
    insn = p.decodeAt(a, 1, input.thumb)[0];
    if (!insn) return { address: hx(a), status: 'undecodable' };
  }
  const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  const outgoing: Record<string, unknown>[] = [];
  if (insn.target !== undefined) outgoing.push({ kind: insn.flow === 'call' ? 'call' : insn.flow === 'cjump' ? 'branch' : 'jump', target: hx(insn.target), name: p.nameOf(insn.target) });
  if (insn.memAddr !== undefined) { const r = p.classifyRef(insn.address, insn.memAddr, insn); const imp = p.importBySlot.get(insn.memAddr); outgoing.push({ kind: imp ? 'import-slot' : r?.kind ?? 'memory', target: hx(insn.memAddr), name: imp?.name ?? r?.value ?? p.symbolize(insn.memAddr) }); }
  const call = loc.af?.calls.find((c) => c.at === insn!.address);
  if (call?.candidates) outgoing.push({ kind: 'indirect-candidates', resolvedBy: call.resolvedBy, targets: call.candidates.slice(0, 64).map((t) => ({ addr: hx(t), name: p.nameOf(t) })) });
  const st = stores.size ? annotationsOf(p) : undefined;
  return {
    query: hx(a), address: hx(insn.address), status: containing ? 'containing-instruction' : 'instruction', size: insn.size, bytes: insn.bytes,
    mnemonic: insn.mnemonic, operands: tokenize(p.arch, insn.operands), text: (insn.mnemonic + ' ' + insn.operands).trim(), flow: insn.flow,
    ...(insn.memSize ? { memorySize: insn.memSize } : {}), ...(insn.thumb ? { thumb: true } : {}),
    function: loc.af ? { name: loc.af.name, addr: hx(loc.af.addr) } : null,
    outgoing, incoming: (idx.to.get(insn.address) ?? []).slice(0, 200).map((r) => ({ from: hx(r.from), kind: r.kind, function: p.functions.get(r.func)?.name })),
    incomingComplete: idx.complete,
    comment: st?.comments.get(insn.address) ?? null, inlineComment: st?.inline.get(insn.address) ?? null,
  };
}

// ---------------- function info, dossier, API boundary ----------------

/** Function metadata: entry, name, signature and calling convention, parameters and locals (DWARF when present, else from value flow), size, blocks and inclusive body ranges. */
export async function disasmFunctionInfo(input: BinaryInput & { function: string | number }) {
  const p = await prog(input);
  const f = resolveFunction(p, input.function);
  if (!f) throw new Error(`function not found: ${input.function}`);
  const af = p.analyze(f.addr);
  if (!af) throw new Error(`cannot analyze ${f.name}`);
  return functionInfo(p, af);
}

function functionInfo(p: Program, af: AnalyzedFunction) {
  const fl = p.flow(af.addr);
  const df = p.debugFunction(af.addr);
  const abi = p.abi();
  const ranges = bodyRanges(af);
  const bodyBytes = ranges.reduce((n, [s, e]) => n + (e - s), 0);
  const span = ranges.length ? ranges[ranges.length - 1]![1] - ranges[0]![0] : 0;
  const params = df ? df.params.map((x, i) => ({ index: i, name: x.name, type: x.type, location: x.location?.reg ?? (x.location?.fbreg !== undefined ? `frame ${x.location.fbreg}` : undefined) }))
    : (fl?.params ?? []).map((r, i) => ({ index: i, name: 'a' + (i + 1), type: 'int64_t', location: r }));
  const locals = df ? df.locals.map((x) => ({ name: x.name, type: x.type, location: x.location?.fbreg !== undefined ? `frame ${x.location.fbreg}` : x.location?.breg ? `${x.location.breg.reg}${x.location.breg.offset >= 0 ? '+' : ''}${x.location.breg.offset}` : x.location?.reg ?? (x.location?.list ? 'location list' : undefined) }))
    : (fl?.stackVars ?? []).filter((v) => v.kind !== 'saved-reg').map((v) => ({ name: v.name, type: v.width === 8 ? 'int64_t' : v.width === 4 ? 'int32_t' : v.width === 2 ? 'int16_t' : v.width === 1 ? 'int8_t' : `uint8_t[${v.width}]`, location: `stack ${v.off < 0 ? '-' : '+'}${hx(Math.abs(v.off))} from entry sp`, displacement: v.off, kind: v.kind }));
  return {
    entry: hx(af.addr), name: af.name, source: af.source,
    signature: df?.prototype ?? `${fl && fl.returns.every((r) => r.value.t === 'entry' && r.value.r === abi.retReg) && fl.returns.length ? 'void' : 'int64_t'} ${af.name}(${(fl?.params ?? []).map((_r, i) => `int64_t a${i + 1}`).join(', ')})`,
    signatureSource: df ? 'dwarf' : fl ? 'value-flow' : 'unknown',
    callingConvention: abi.name, params, locals, localsSource: df ? 'dwarf' : fl ? 'stack-tracking' : 'unknown',
    size: af.size ?? null, bodyBytes, span, blocks: af.blocks.length, instructions: af.insnCount,
    bodyRanges: ranges.map(([s, e]) => ({ start: hx(s), endInclusive: hx(e - 1) })),
    exits: af.blocks.filter((b) => b.exit).map((b) => ({ at: hx(b.insns[b.insns.length - 1]?.address ?? b.start), kind: b.exit })),
    truncated: af.truncated, ...(df?.line !== undefined ? { line: df.line } : {}),
  };
}

/** One call dossier: identity and body ranges, signature, pseudo code, assembly (paged), calls, callers, references, strings, names, comments, bookmarks and switches. */
export async function disasmAnalyzeFunction(input: BinaryInput & { function: string | number; maxLines?: number; asmLimit?: number; asmOffset?: number; detail?: 'summary' | 'complete'; budgetMs?: number }) {
  const p = await prog(input);
  const f = resolveFunction(p, input.function);
  if (!f) throw new Error(`function not found: ${input.function}`);
  const af = p.resolveIndirect(f.addr);
  if (!af) throw new Error(`cannot analyze ${f.name}`);
  const info = functionInfo(p, af);
  const summary = summarizeFunction(p, af);
  const fl = p.flow(af.addr);
  const lift = liftFunction(p, af, clampInt(input.maxLines, 300, 10, 5000), fl, liftDebugFor(p, af, fl));
  const idx = p.xrefs(clampInt(input.budgetMs, 8000, 100, 60000));
  const callers = [...new Map((idx.to.get(af.addr) ?? []).filter((r) => r.kind !== 'string').map((r) => [r.from, { from: hx(r.from), kind: r.kind, function: p.functions.get(r.func)?.name ?? hx(r.func), functionAddr: hx(r.func) }])).values()];
  const st = stores.size ? annotationsOf(p) : undefined;
  const inRange = (a: number) => af.blocks.some((b) => a >= b.start && a < b.end);
  const comments = st ? [...st.comments].filter(([a]) => inRange(a) || a === af.addr).map(([a, c]) => ({ address: hx(a), kind: 'regular', comment: c })).concat([...st.inline].filter(([a]) => inRange(a)).map(([a, c]) => ({ address: hx(a), kind: 'inline', comment: c }))) : [];
  const bookmarks = st ? [...st.bookmarks].filter(([a]) => inRange(a)).map(([a, n]) => ({ address: hx(a), name: n })) : [];
  const all = af.blocks.slice().sort((x, y) => x.start - y.start).flatMap((b) => b.insns);
  const aoff = clampInt(input.asmOffset, 0, 0, 1e9), alim = clampInt(input.asmLimit, 200, 1, 5000);
  const asm = all.slice(aoff, aoff + alim).map((i) => ({ addr: hx(i.address), bytes: i.bytes, text: (i.mnemonic + ' ' + i.operands).trim(), ...(st?.inline.get(i.address) ? { comment: st.inline.get(i.address) } : {}) }));
  const names = [...new Set(af.calls.map((c) => c.name).filter(Boolean) as string[])];
  const refs = af.dataRefs.slice(0, 500).map((d) => ({ at: hx(d.at), kind: d.kind, target: hx(d.addr), value: d.value }));
  const lines = lift.text.split('\n');
  const dossier = {
    identity: { name: af.name, entry: info.entry, source: af.source, bodyRanges: info.bodyRanges, size: info.size, bodyBytes: info.bodyBytes },
    signature: info.signature, signatureSource: info.signatureSource, callingConvention: info.callingConvention, params: info.params, locals: info.locals,
    summary,
    pseudocode: input.detail === 'summary' ? undefined : lift.text, pseudocodeLines: lines.length, structured: lift.structured,
    assembly: input.detail === 'summary' ? undefined : { total: all.length, offset: aoff, limit: alim, hasMore: aoff + alim < all.length, insns: asm },
    calls: af.calls.slice(0, 300).map((c) => ({ at: hx(c.at), target: c.target !== undefined ? hx(c.target) : undefined, name: c.name, indirect: c.indirect || undefined, tail: c.tail, ...(c.candidates ? { candidates: c.candidates.slice(0, 32).map(hx), resolvedBy: c.resolvedBy } : {}) })),
    callers: callers.slice(0, 200), callersComplete: idx.complete,
    references: refs, strings: summary.strings, names,
    comments, bookmarks, switches: (af.switches ?? []).length,
    valueFlow: fl ? { available: true, params: fl.params, stackVars: fl.stackVars.length, complete: fl.complete } : { available: false },
    limitations: [
      ...(af.truncated ? ['analysis stopped at the instruction cap; the body may be longer'] : []),
      ...(af.unresolvedIndirect ? [`${af.unresolvedIndirect} indirect branches or calls not resolved`] : []),
      ...(af.blocks.some((b) => b.exit === 'noreturn') ? ['some calls were treated as not returning (known no-return callees)'] : []),
    ],
  };
  return dossier;
}

/**
 * API boundary of one function (a command or message dispatcher): jump tables with case values and
 * targets, the default target from the bounds check, calls through tables of code pointers, import
 * calls (the external API it touches), unresolved indirect branches, and a confidence score with the
 * instruction addresses as evidence.
 */
export async function disasmApiBoundary(input: BinaryInput & { function: string | number; maxCases?: number }) {
  const p = await prog(input);
  const f = resolveFunction(p, input.function);
  if (!f) throw new Error(`function not found: ${input.function}`);
  const af = p.resolveIndirect(f.addr);
  if (!af) throw new Error(`cannot analyze ${f.name}`);
  const maxCases = clampInt(input.maxCases, 512, 1, 65536);
  const blockOf = (a: number) => af.blocks.find((b) => a >= b.start && a < b.end);
  const dispatches = (af.switches ?? []).map((s) => {
    const sb = blockOf(s.at);
    let def: number | undefined;
    if (s.boundAt !== undefined) {
      const bb = blockOf(s.boundAt);
      const other = bb?.succ.find((e) => e.to !== sb?.start && !(sb && e.to === sb.start));
      if (bb && bb !== sb && other && !s.targets.includes(other.to)) def = other.to;
      else if (bb && bb !== sb) { const o = bb.succ.find((e) => e.kind === 'true' || e.kind === 'jump'); if (o && o.to !== sb?.start) def = o.to; }
    }
    const cases = s.targets.slice(0, maxCases).map((t, i) => ({ value: i + (s.bias ?? 0), target: hx(t), name: s.kind === 'call-table' ? p.nameOf(t) ?? null : p.nameOf(t) ?? null }));
    return {
      at: hx(s.at), kind: s.kind, table: hx(s.table), entrySize: s.entrySize, entries: s.count, bound: s.bound, ...(s.boundAt !== undefined ? { boundAt: hx(s.boundAt) } : {}),
      indexRegister: s.indexReg ?? null, bias: s.bias ?? 0, cases, distinctTargets: new Set(s.targets).size,
      defaultTarget: def !== undefined ? { target: hx(def), evidence: s.boundAt !== undefined ? hx(s.boundAt) : null } : null,
      confidence: s.bound === 'cmp' ? 0.95 : s.bound === 'mask' ? 0.8 : s.bound === 'const' ? 0.7 : 0.5,
      evidence: [hx(s.at), ...(s.boundAt !== undefined ? [hx(s.boundAt)] : [])],
    };
  });
  const imports = af.calls.filter((c) => c.name && ((c.target !== undefined && p.importByStub.has(c.target)) || (c.indirect && c.name))).map((c) => ({ at: hx(c.at), name: c.name! }));
  const resolvedIndirect = af.calls.filter((c) => c.indirect && (c.candidates || c.target !== undefined)).map((c) => ({ at: hx(c.at), resolvedBy: c.resolvedBy, targets: (c.candidates ?? (c.target !== undefined ? [c.target] : [])).slice(0, 64).map((t) => ({ addr: hx(t), name: p.nameOf(t) ?? null })) }));
  const unresolved: { at: string; kind: string; text: string }[] = [];
  for (const b of af.blocks) for (const i of b.insns) {
    if (i.flow === 'ijump' && !af.switches?.some((s) => s.at === i.address) && b.exit !== 'tail') unresolved.push({ at: hx(i.address), kind: 'indirect-jump', text: (i.mnemonic + ' ' + i.operands).trim() });
    if (i.flow === 'icall') { const c = af.calls.find((x) => x.at === i.address); if (c && !c.candidates && c.target === undefined && !c.name) unresolved.push({ at: hx(i.address), kind: 'indirect-call', text: (i.mnemonic + ' ' + i.operands).trim() }); }
  }
  const sites = dispatches.length + resolvedIndirect.length + unresolved.length;
  const confidence = sites === 0 ? (imports.length ? 0.6 : 0.3) : Number(((dispatches.reduce((n, d) => n + d.confidence, 0) + resolvedIndirect.length * 0.75) / sites).toFixed(2));
  return {
    function: { name: af.name, addr: hx(af.addr) },
    role: dispatches.some((d) => d.kind === 'switch' && d.distinctTargets > 2) ? 'dispatcher' : imports.length ? 'api-caller' : 'internal',
    confidence, dispatches, importCalls: imports, resolvedIndirectCalls: resolvedIndirect,
    unsupported: unresolved,
    unknowns: [
      ...dispatches.filter((d) => d.defaultTarget === null).map((d) => `no default target proven for the table at ${d.at}`),
      ...dispatches.filter((d) => d.bound !== 'cmp').map((d) => `case count at ${d.at} comes from a ${d.bound} bound, not a compare`),
      ...unresolved.map((u) => `${u.kind} at ${u.at} not resolved`),
    ],
  };
}

function page<T>(items: T[], offset: unknown, limit: unknown, defLimit: number, maxLimit: number) {
  const off = clampInt(offset, 0, 0, Number.MAX_SAFE_INTEGER);
  const lim = clampInt(limit, defLimit, 1, maxLimit);
  return { total: items.length, offset: off, limit: lim, hasMore: off + lim < items.length, items: items.slice(off, off + lim) };
}
