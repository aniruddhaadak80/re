// Program: a loaded binary plus lazy, cached analyses (functions, CFG, xrefs, call graph).
import type { AnalyzedFunction, BasicBlock, BinaryImage, CallSite, DataRef, Decoder, Edge, FunctionInfo, ImportRef, Insn, Sym } from '../types.js';
import { Memory } from '../loader/memory.js';
import { loadImage, type LoadOptions } from '../loader/index.js';
import { loadDecoders, type DecoderOptions } from '../backends/index.js';
import { stringAt } from './strings.js';
import { trackBlock } from './refs.js';
import { Budget, hx } from '../util.js';

export interface OpenOptions extends LoadOptions, DecoderOptions {
  /** time budget for whole program function discovery, ms (default 4000) */
  discoveryMs?: number;
  /** skip call target and prologue discovery (symbols, hints and entry only) */
  quickDiscovery?: boolean;
  /** max instructions decoded per function (default 20000) */
  maxFunctionInsns?: number;
  /** analyzed functions kept in memory, counted in instructions (default 250000) */
  cacheInsns?: number;
}

const NORETURN = new Set([
  'exit', '_exit', 'exit_group', 'abort', '__stack_chk_fail', '__assert_fail', '__assert_rtn', '__cxa_throw', '__cxa_rethrow',
  'longjmp', '_longjmp', 'siglongjmp', 'pthread_exit', 'err', 'errx', 'verr', 'verrx', '__libc_fatal', '__fortify_fail',
  '_Unwind_Resume', 'ExitProcess', 'ExitThread', 'TerminateProcess', 'RaiseException', '_CxxThrowException', '__report_gsfailure',
  'runtime.gopanic', 'runtime.throw', 'runtime.fatal', 'runtime.fatalthrow', 'runtime.fatalpanic', 'runtime.panicIndex',
  'runtime.panicIndexU', 'runtime.panicSliceAlen', 'runtime.panicSliceB', 'runtime.panicdivide', 'runtime.panicmem',
  'runtime.panicshift', 'runtime.goPanicIndex', 'runtime.goPanicSliceAlen', 'runtime.morestack', 'runtime.abort',
  'core::panicking::panic', 'std::process::exit', '__ubsan_handle_builtin_unreachable', 'rust_panic', '__rust_start_panic',
]);

/** Normalizes a symbol name for matching: strips leading underscores, version suffixes and __imp_ prefixes. */
export function normName(n: string): string {
  let s = n;
  if (s.startsWith('__imp_')) s = s.slice(6);
  const at = s.indexOf('@');
  if (at > 0) s = s.slice(0, at);
  s = s.replace(/^_+/, '');
  return s.toLowerCase();
}

export class Program {
  readonly img: BinaryImage;
  readonly mem: Memory;
  readonly decoder: Decoder | undefined;
  readonly decoderErrors: string[];
  readonly opts: OpenOptions;
  readonly importBySlot = new Map<number, ImportRef>();
  readonly importByStub = new Map<number, ImportRef>();
  /** best symbol per address (functions and data) */
  readonly symAt = new Map<number, Sym>();
  private sortedSyms: Sym[] = [];
  readonly functions = new Map<number, FunctionInfo>();
  private sortedFuncs: number[] | undefined;
  private readonly cache = new Map<number, AnalyzedFunction>();
  private cacheInsns = 0;
  private discovered = false;
  discoveryComplete = true;
  discoveryNotes: string[] = [];
  private xrefIndex: { to: Map<number, { from: number; func: number; kind: string }[]>; complete: boolean; analyzed: number } | undefined;

  private constructor(img: BinaryImage, decoder: Decoder | undefined, errors: string[], opts: OpenOptions) {
    this.img = img;
    this.mem = new Memory(img);
    this.decoder = decoder;
    this.decoderErrors = errors;
    this.opts = opts;
    for (const imp of img.imports) {
      if (imp.slot !== undefined && !this.importBySlot.has(imp.slot)) this.importBySlot.set(imp.slot, imp);
      if (imp.stub !== undefined && !this.importByStub.has(imp.stub)) this.importByStub.set(imp.stub, imp);
    }
    const rank = (s: Sym) => (({ symtab: 0, dynsym: 1, export: 1, macho: 0, coff: 0, gopclntab: 2 } as Record<string, number>)[s.source] ?? 5) + (s.local ? 0.5 : 0) + (s.name.includes('.') && s.source !== 'gopclntab' ? 0.25 : 0);
    for (const s of img.symbols) {
      const cur = this.symAt.get(s.addr);
      if (!cur || (cur.kind !== 'func' && s.kind === 'func') || (cur.kind === s.kind && rank(s) < rank(cur))) this.symAt.set(s.addr, s);
    }
    this.sortedSyms = [...this.symAt.values()].sort((a, b) => a.addr - b.addr);
  }

  /** Load a binary and its decoder. */
  static async open(bytes: Uint8Array, opts: OpenOptions = {}): Promise<Program> {
    const img = loadImage(bytes, opts);
    const set = await loadDecoders(opts);
    const dec = set.get(img.arch);
    const p = new Program(img, dec, set.errors, opts);
    p.resolveStubs();
    return p;
  }

  get arch() { return this.img.arch; }

  // ---------- decoding ----------

  /** Decode up to n instructions at addr (Thumb when the address is known Thumb code or thumb=true). */
  decodeAt(addr: number, n: number, thumb?: boolean): Insn[] {
    if (!this.decoder) return [];
    const isThumb = this.img.arch === 'arm' && (thumb ?? this.isThumb(addr));
    const per = this.img.arch === 'x86' || this.img.arch === 'x86_64' ? 15 : 4;
    const out: Insn[] = [];
    let cur = addr;
    while (out.length < n) {
      const want = Math.min(n - out.length, 512);
      const bytes = this.mem.view(cur, want * per);
      if (bytes.length === 0) break;
      const got = this.decoder.decode(this.img.arch, bytes, cur, want, isThumb);
      if (got.length === 0) break;
      for (const g of got) out.push(g);
      const last = got[got.length - 1]!;
      cur = last.address + last.size;
      if (last.flow === 'invalid') break;
      if (got.length < want && bytes.length < want * per) break;
    }
    return out.slice(0, n);
  }

  isThumb(addr: number): boolean {
    if (this.img.arch !== 'arm') return false;
    const f = this.functions.get(addr) ?? this.functionContaining(addr);
    if (f) return !!f.thumb;
    if (this.img.format === 'pe') return true;
    if (this.img.entry === addr) return !!this.img.entryThumb;
    return !!this.symAt.get(addr)?.thumb;
  }

  // ---------- import stubs ----------

  private resolveStubs(): void {
    const img = this.img;
    if (!this.decoder) return;
    if (img.format === 'elf') {
      const gotplt = img.sections.find((s) => s.name === '.got.plt') ?? img.sections.find((s) => s.name === '.got');
      for (const sec of img.sections) {
        if (!sec.exec || !sec.name.startsWith('.plt') && sec.name !== '.iplt') continue;
        const insns = this.decoder.decode(img.arch, this.mem.view(sec.vaddr, Math.min(sec.size, 1 << 20)), sec.vaddr, 200000, false);
        trackBlock(img.arch, insns, () => false, (a) => this.mem.readU32(a, img.endian === 'le'));
        const ent = img.arch === 'arm' ? 4 : 16;
        let entryStart = sec.vaddr;
        let pending = false;
        for (const ins of insns) {
          let slot = ins.memAddr;
          if (slot === undefined && img.arch === 'x86' && gotplt) {
            const mm = ins.operands.match(/\[ebx \+ (0x[0-9a-f]+)\]/);
            if (mm) slot = gotplt.vaddr + parseInt(mm[1]!.slice(2), 16);
          }
          if (img.arch === 'arm') {
            // ARM PLT entries are variable (12 or 16 bytes); an entry starts after the previous indirect jump
            if (slot !== undefined && ins.flow === 'ijump') {
              const imp = this.importBySlot.get(slot);
              if (imp && !this.importByStub.has(entryStart)) { imp.stub ??= entryStart; this.importByStub.set(entryStart, imp); }
            }
            if (pending && (ins.operands.startsWith('ip, pc') || ins.mnemonic === 'bx' || ins.operands.startsWith('ip, #'))) { entryStart = ins.address; pending = false; }
            if (ins.flow === 'ijump' || ins.flow === 'ret') { entryStart = ins.address + ins.size; pending = true; }
            continue;
          }
          if (slot === undefined) continue;
          const imp = this.importBySlot.get(slot);
          if (!imp) continue;
          const stub = sec.vaddr + Math.floor((ins.address - sec.vaddr) / ent) * ent;
          if (!this.importByStub.has(stub)) { imp.stub ??= stub; this.importByStub.set(stub, imp); }
        }
      }
    } else if (img.format === 'pe' && (img.arch === 'x86_64' || img.arch === 'x86')) {
      // jmp [IAT] thunks: FF 25 disp32
      for (const sec of img.sections) {
        if (!sec.exec) continue;
        const b = this.mem.view(sec.vaddr, sec.size);
        for (let i = 0; i + 6 <= b.length; i++) {
          if (b[i] !== 0xff || b[i + 1] !== 0x25) continue;
          const d = (b[i + 2]! | (b[i + 3]! << 8) | (b[i + 4]! << 16) | (b[i + 5]! << 24));
          const slot = img.arch === 'x86_64' ? sec.vaddr + i + 6 + d : d >>> 0;
          const imp = this.importBySlot.get(slot);
          if (imp && !this.importByStub.has(sec.vaddr + i)) this.importByStub.set(sec.vaddr + i, { ...imp, stub: sec.vaddr + i });
        }
      }
    }
  }

  // ---------- names ----------

  /** Name for an address: function, symbol, import stub or slot. */
  nameOf(addr: number): string | undefined {
    const stub = this.importByStub.get(addr);
    if (stub) return stub.name;
    const f = this.functions.get(addr);
    if (f) return f.name;
    const s = this.symAt.get(addr);
    if (s) return s.name;
    return undefined;
  }

  /** "name" or "name+0x10" for any address near a symbol, else undefined. */
  symbolize(addr: number): string | undefined {
    const exact = this.nameOf(addr);
    if (exact) return exact;
    const slot = this.importBySlot.get(addr);
    if (slot) return '[' + slot.name + ']';
    const arr = this.sortedSyms;
    let lo = 0, hi = arr.length - 1, best = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (arr[mid]!.addr <= addr) { best = mid; lo = mid + 1; } else hi = mid - 1; }
    if (best >= 0) {
      const s = arr[best]!;
      const lim = s.size ?? 0x1000;
      if (addr - s.addr < lim) return `${s.name}+${hx(addr - s.addr)}`;
    }
    return undefined;
  }

  // ---------- function discovery ----------

  private addFunction(f: FunctionInfo): boolean {
    if (!this.mem.isExec(f.addr)) return false;
    const cur = this.functions.get(f.addr);
    if (cur) {
      if (!cur.size && f.size) cur.size = f.size;
      if (cur.name.startsWith('sub_') && !f.name.startsWith('sub_')) { cur.name = f.name; cur.source = f.source; }
      if (f.thumb) cur.thumb = true;
      return false;
    }
    this.functions.set(f.addr, f);
    this.sortedFuncs = undefined;
    return true;
  }

  /** Discover functions (cached). */
  discover(): Map<number, FunctionInfo> {
    if (this.discovered) return this.functions;
    this.discovered = true;
    const img = this.img;
    for (const s of this.symAt.values()) if (s.kind === 'func') this.addFunction({ addr: s.addr, name: s.name, size: s.size, source: s.source, thumb: s.thumb });
    for (const s of img.symbols) if (s.kind === 'func') this.addFunction({ addr: s.addr, name: s.name, size: s.size, source: s.source, thumb: s.thumb });
    for (const [stub, imp] of this.importByStub) this.addFunction({ addr: stub, name: imp.name, source: 'import', isImportStub: true });
    for (const h of img.hints) {
      const name = this.symAt.get(h.addr)?.name ?? `sub_${h.addr.toString(16)}`;
      this.addFunction({ addr: h.addr, name, size: h.size, source: h.source, thumb: h.thumb });
    }
    if (img.entry !== undefined) this.addFunction({ addr: img.entry, name: this.symAt.get(img.entry)?.name ?? 'entry', source: 'entry', thumb: img.entryThumb });
    if (this.opts.quickDiscovery || !this.decoder) { this.discoveryComplete = !this.decoder ? false : true; if (this.decoder) this.findMainFromStart(); return this.functions; }

    const budget = new Budget(this.opts.discoveryMs ?? 4000);
    if (img.goVersionHint) {
      // the Go pclntab lists every function; following calls would only add work
      this.findMainFromStart();
      return this.functions;
    }
    // follow direct calls from every known function
    const queue = [...this.functions.keys()];
    const seen = new Set<number>();
    let qi = 0;
    while (qi < queue.length) {
      if (budget.expired || this.functions.size > 300000) { this.discoveryComplete = false; this.discoveryNotes.push(`call discovery stopped after ${qi} of ${queue.length} functions (budget)`); break; }
      const a = queue[qi++]!;
      if (seen.has(a)) continue;
      seen.add(a);
      const f = this.functions.get(a);
      if (!f || f.isImportStub) continue;
      const af = this.analyze(a);
      if (!af) continue;
      for (const c of af.calls) {
        if (c.target === undefined || c.indirect) continue;
        if (this.addFunction({ addr: c.target, name: this.symAt.get(c.target)?.name ?? `sub_${c.target.toString(16)}`, source: 'call', thumb: this.calleeThumb(af, c) })) queue.push(c.target);
      }
    }
    // prologue scan in gaps when the image looks stripped
    if (!budget.expired) this.prologueScan(budget);
    this.findMainFromStart();
    return this.functions;
  }

  private calleeThumb(af: AnalyzedFunction, c: CallSite): boolean | undefined {
    if (this.img.arch !== 'arm') return undefined;
    for (const b of af.blocks) for (const i of b.insns) if (i.address === c.at) return i.mnemonic.startsWith('blx') ? !af.thumb : !!af.thumb;
    return af.thumb;
  }

  private prologueScan(budget: Budget): void {
    const arch = this.img.arch;
    const execRegs = this.mem.execRegions();
    const codeSize = execRegs.reduce((n, r) => n + r.fsize, 0);
    const named = [...this.functions.values()].filter((f) => f.source !== 'call').length;
    if (named > 0 && codeSize / Math.max(1, this.functions.size) < 4096) return; // enough coverage already
    const covered = (a: number) => {
      const f = this.functionContaining(a);
      return !!f;
    };
    let added = 0;
    for (const r of execRegs) {
      const b = this.mem.view(r.start, r.fsize);
      for (let i = 0; i + 8 <= b.length; i += arch === 'arm64' ? 4 : 1) {
        if (budget.expired || added > 50000) { this.discoveryComplete = false; return; }
        let hit = false;
        if (arch === 'x86_64') hit = (b[i] === 0xf3 && b[i + 1] === 0x0f && b[i + 2] === 0x1e && b[i + 3] === 0xfa) || (b[i] === 0x55 && b[i + 1] === 0x48 && b[i + 2] === 0x89 && b[i + 3] === 0xe5);
        else if (arch === 'x86') hit = (b[i] === 0x55 && b[i + 1] === 0x89 && b[i + 2] === 0xe5) || (b[i] === 0xf3 && b[i + 1] === 0x0f && b[i + 2] === 0x1e && b[i + 3] === 0xfb);
        else if (arch === 'arm64') {
          const w = (b[i]! | (b[i + 1]! << 8) | (b[i + 2]! << 16) | (b[i + 3]! << 24)) >>> 0;
          hit = ((w & 0xffc07fff) >>> 0) === 0xa9807bfd || w === 0xd503233f || w === 0xd503237f;
        }
        if (!hit) continue;
        const a = r.start + i;
        if (covered(a)) continue;
        if (this.addFunction({ addr: a, name: `sub_${a.toString(16)}`, source: 'prologue' })) {
          added++;
          const af = this.analyze(a);
          if (af) i = Math.max(i, a - r.start + Math.max(0, af.codeSize - 1));
        }
      }
    }
  }

  /** analyzed extent of a function when it has been analyzed */
  analysisSizeHint(addr: number): number | undefined {
    const af = this.cache.get(addr);
    if (!af || !af.blocks.length) return undefined;
    return Math.max(...af.blocks.map((b) => b.end)) - addr;
  }

  /** ELF without symbols: main is the first argument _start passes to __libc_start_main. */
  private findMainFromStart(): void {
    const img = this.img;
    if (img.format !== 'elf' || img.entry === undefined) return;
    if ([...this.functions.values()].some((f) => f.name === 'main')) return;
    if (!img.imports.some((i) => normName(i.name) === 'libc_start_main')) return;
    const af = this.analyze(img.entry);
    if (!af) return;
    const insns = af.blocks.flatMap((b) => b.insns);
    const callIdx = insns.findIndex((i) => (i.flow === 'call' || i.flow === 'icall') && ((i.viaMemory && i.memAddr !== undefined && normName(this.importBySlot.get(i.memAddr)?.name ?? '') === 'libc_start_main') || (i.target !== undefined && normName(this.importByStub.get(i.target)?.name ?? '') === 'libc_start_main')));
    if (callIdx < 0) return;
    const argReg = img.arch === 'x86_64' ? /^(rdi|edi)\b/ : img.arch === 'arm64' ? /^x0\b/ : img.arch === 'arm' ? /^r0\b/ : null;
    let cand: number | undefined;
    for (let k = callIdx - 1; k >= 0 && k >= callIdx - 24; k--) {
      const i = insns[k]!;
      const v = i.memAddr ?? i.imms.find((x) => this.mem.isExec(x));
      if (v === undefined || !this.mem.isExec(v)) continue;
      if (argReg ? argReg.test(i.operands) : i.mnemonic === 'push') { cand = v; if (argReg || img.arch !== 'x86') break; }
    }
    if (img.arch === 'x86') {
      // cdecl: main is pushed last before the call
      for (let k = callIdx - 1; k >= 0 && k >= callIdx - 16; k--) {
        const i = insns[k]!;
        if (i.mnemonic !== 'push') continue;
        const v = i.memAddr ?? i.imms[0];
        if (v !== undefined && this.mem.isExec(v)) { cand = v; break; }
        // push dword ptr [ebx+x] style (PIC GOT load) or push reg: give up on non immediate pushes
        break;
      }
    }
    if (cand === undefined) return;
    const cur = this.functions.get(cand);
    if (cur) { if (cur.name.startsWith('sub_')) { cur.name = 'main'; cur.source = 'entry'; } }
    else this.addFunction({ addr: cand, name: 'main', source: 'entry' });
  }

  sortedFunctionAddrs(): number[] {
    this.sortedFuncs ??= [...this.functions.keys()].sort((a, b) => a - b);
    return this.sortedFuncs;
  }

  /** Function whose range contains addr (using sizes or analyzed extents). */
  functionContaining(addr: number): FunctionInfo | undefined {
    const exact = this.functions.get(addr);
    if (exact) return exact;
    const arr = this.sortedFunctionAddrs();
    let lo = 0, hi = arr.length - 1, best = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (arr[mid]! <= addr) { best = mid; lo = mid + 1; } else hi = mid - 1; }
    for (let k = best; k >= 0 && k > best - 8; k--) {
      const f = this.functions.get(arr[k]!)!;
      if (f.size && addr < f.addr + f.size) return f;
      const af = this.cache.get(f.addr);
      if (af && af.blocks.some((b) => addr >= b.start && addr < b.end)) return f;
      if (f.size) break;
    }
    return undefined;
  }

  // ---------- per function analysis ----------

  /** Build the CFG of the function at addr (cached). Creates a function entry when unknown. */
  analyze(addr: number): AnalyzedFunction | undefined {
    const cached = this.cache.get(addr);
    if (cached) { this.cache.delete(addr); this.cache.set(addr, cached); return cached; }
    if (!this.decoder || !this.mem.isExec(addr)) return undefined;
    let info = this.functions.get(addr);
    if (!info) {
      const s = this.symAt.get(addr);
      info = { addr, name: s?.name ?? `sub_${addr.toString(16)}`, source: 'call', thumb: this.img.arch === 'arm' ? this.isThumb(addr) : undefined };
    }
    const af = this.buildCfg(info);
    this.cache.set(addr, af);
    this.cacheInsns += af.insnCount;
    const cap = this.opts.cacheInsns ?? 250_000;
    while (this.cacheInsns > cap && this.cache.size > 1) {
      const first = this.cache.keys().next().value as number;
      this.cacheInsns -= this.cache.get(first)!.insnCount;
      this.cache.delete(first);
    }
    return af;
  }

  private isNoReturn(target: number | undefined, slot?: number): boolean {
    let n: string | undefined;
    if (slot !== undefined) n = this.importBySlot.get(slot)?.name;
    else if (target !== undefined) n = this.nameOf(target);
    if (!n) return false;
    const base = n.startsWith('__imp_') ? n.slice(6) : n;
    const at = base.indexOf('@');
    const clean = (at > 0 ? base.slice(0, at) : base);
    return NORETURN.has(clean) || NORETURN.has(clean.replace(/^_/, ''));
  }

  private buildCfg(info: FunctionInfo): AnalyzedFunction {
    const arch = this.img.arch;
    const maxInsns = this.opts.maxFunctionInsns ?? 20000;
    const thumb = arch === 'arm' ? !!info.thumb : undefined;
    const start = info.addr;
    const limitEnd = info.size ? start + info.size : undefined;
    const insnAt = new Map<number, Insn>();
    const leaders = new Set<number>([start]);
    const work = [start];
    let total = 0;
    let truncated = false;
    const isOtherFunc = (t: number) => t !== start && (this.functions.has(t) || this.importByStub.has(t));
    const inRange = (t: number) => (limitEnd === undefined ? true : t >= start && t < limitEnd);
    const tails = new Set<number>();
    const pre = new Map<number, Insn>();
    while (work.length) {
      let pc = work.pop()!;
      if (insnAt.has(pc)) continue;
      // decode linearly until a terminator
      for (;;) {
        if (total >= maxInsns) { truncated = true; break; }
        let batch: Insn[];
        const cachedRun = pre.get(pc);
        if (cachedRun) {
          batch = [];
          let q: Insn | undefined = cachedRun;
          while (q && batch.length < 64) { batch.push(q); q = pre.get(q.address + q.size); }
        } else {
          batch = this.decodeAt(pc, 32, thumb);
          for (const q of batch) pre.set(q.address, q);
        }
        if (!batch.length) break;
        let stop = false;
        for (const ins of batch) {
          if (insnAt.has(ins.address)) { leaders.add(ins.address); stop = true; break; }
          if (limitEnd !== undefined && ins.address >= limitEnd && ins.address !== start) { stop = true; break; }
          insnAt.set(ins.address, ins);
          total++;
          const next = ins.address + ins.size;
          if (ins.flow === 'call' && ins.target === next) ins.flow = 'seq'; // call $+5 (PIC base idiom)
          if (ins.flow === 'jump' && ins.target !== undefined) {
            if (isOtherFunc(ins.target) || !inRange(ins.target) || !this.mem.isExec(ins.target)) tails.add(ins.address);
            else { leaders.add(ins.target); work.push(ins.target); }
            stop = true; break;
          }
          if (ins.flow === 'cjump') {
            if (ins.target !== undefined && this.mem.isExec(ins.target) && inRange(ins.target) && !isOtherFunc(ins.target)) { leaders.add(ins.target); work.push(ins.target); }
            leaders.add(next);
            work.push(next);
            stop = true; break;
          }
          if (ins.flow === 'ret' || ins.flow === 'ijump' || ins.flow === 'trap' || ins.flow === 'invalid') { stop = true; break; }
          if ((ins.flow === 'call' || ins.flow === 'icall') && this.isNoReturn(ins.target, ins.viaMemory ? ins.memAddr : undefined)) { stop = true; break; }
          if (total >= maxInsns) { truncated = true; stop = true; break; }
        }
        if (stop || truncated) break;
        const last = batch[batch.length - 1]!;
        pc = last.address + last.size;
        if (insnAt.has(pc)) { leaders.add(pc); break; }
        if (limitEnd !== undefined && pc >= limitEnd) break;
        if (pc !== start && this.functions.has(pc)) break; // ran into the next function
      }
    }

    // split into blocks
    const addrs = [...insnAt.keys()].sort((a, b) => a - b);
    const blocks: BasicBlock[] = [];
    let cur: BasicBlock | undefined;
    for (const a of addrs) {
      const ins = insnAt.get(a)!;
      if (!cur || leaders.has(a) || cur.end !== a) {
        cur = { start: a, end: a, insns: [], succ: [], pred: [] };
        blocks.push(cur);
      }
      cur.insns.push(ins);
      cur.end = a + ins.size;
      const f = ins.flow;
      if (f === 'jump' || f === 'cjump' || f === 'ret' || f === 'ijump' || f === 'trap' || f === 'invalid') cur = undefined;
      else if ((f === 'call' || f === 'icall') && this.isNoReturn(ins.target, ins.viaMemory ? ins.memAddr : undefined)) cur = undefined;
    }
    const blockAt = new Map(blocks.map((b) => [b.start, b] as const));
    const slotCheck = (a: number) => this.importBySlot.has(a) || this.isGotLike(a);
    const read32 = (a: number) => this.mem.readU32(a, this.img.endian === 'le');
    if (arch === 'x86') trackBlock(arch, blocks.flatMap((b) => b.insns), slotCheck, read32, (t) => this.pcThunkReg(t));
    for (const b of blocks) {
      if (arch !== 'x86') trackBlock(arch, b.insns, slotCheck, read32);
      const last = b.insns[b.insns.length - 1]!;
      const next = last.address + last.size;
      const addEdge = (to: number, kind: Edge['kind']) => { if (blockAt.has(to)) b.succ.push({ from: b.start, to, kind }); };
      switch (last.flow) {
        case 'jump':
          if (last.target !== undefined && blockAt.has(last.target) && !tails.has(last.address)) addEdge(last.target, 'jump');
          else b.exit = 'tail';
          break;
        case 'cjump':
          if (last.target !== undefined) addEdge(last.target, 'true');
          addEdge(next, 'false');
          break;
        case 'ret': b.exit = 'ret'; break;
        case 'ijump': b.exit = last.viaMemory && last.memAddr !== undefined && this.importBySlot.has(last.memAddr) ? 'tail' : 'indirect'; break;
        case 'trap': b.exit = 'trap'; break;
        case 'invalid': b.exit = 'invalid'; break;
        default:
          if ((last.flow === 'call' || last.flow === 'icall') && this.isNoReturn(last.target, last.viaMemory ? last.memAddr : undefined)) b.exit = 'noreturn';
          else if (blockAt.has(next)) addEdge(next, 'fallthrough');
          else b.exit = 'tail';
      }
    }
    for (const b of blocks) for (const e of b.succ) blockAt.get(e.to)?.pred.push(b.start);

    // calls, data refs, constants
    const calls: CallSite[] = [];
    const dataRefs: DataRef[] = [];
    const consts = new Set<number>();
    let unresolved = 0;
    let codeSize = 0;
    for (const b of blocks) {
      codeSize += b.end - b.start;
      for (const ins of b.insns) {
        if (ins.flow === 'call' || ins.flow === 'icall' || (ins.flow === 'jump' && b.exit === 'tail' && ins === b.insns[b.insns.length - 1]) || (ins.flow === 'ijump' && ins.viaMemory)) {
          const tail = ins.flow === 'jump' || ins.flow === 'ijump';
          if (ins.target !== undefined) {
            calls.push({ at: ins.address, target: ins.target, name: this.nameOf(ins.target), indirect: false, tail: tail || undefined });
          } else if (ins.viaMemory && ins.memAddr !== undefined && this.importBySlot.has(ins.memAddr)) {
            calls.push({ at: ins.address, name: this.importBySlot.get(ins.memAddr)!.name, indirect: true, tail: tail || undefined });
          } else if (!tail) {
            calls.push({ at: ins.address, indirect: true });
            unresolved++;
          }
        } else if (ins.flow === 'ijump') unresolved++;
        if (ins.memAddr !== undefined && !ins.viaMemory) {
          const r = this.classifyRef(ins.address, ins.memAddr, ins);
          if (r) dataRefs.push(r);
        } else if (ins.memAddr !== undefined && ins.viaMemory && this.importBySlot.has(ins.memAddr)) {
          dataRefs.push({ at: ins.address, addr: ins.memAddr, kind: 'import-slot', value: this.importBySlot.get(ins.memAddr)!.name });
        }
        for (const v of ins.imms) {
          const minAddr = this.img.bits === 64 ? 0x10000 : 0x1000;
          if (v >= minAddr && this.mem.isMapped(v) && ins.memAddr !== v) {
            const r = this.classifyRef(ins.address, v, ins);
            if (r) { dataRefs.push(r); continue; }
          }
          if (Math.abs(v) > 0xff && consts.size < 256) consts.add(v);
        }
      }
    }
    return {
      ...info, blocks, calls, dataRefs, constants: [...consts], insnCount: total, codeSize, truncated, unresolvedIndirect: unresolved,
    };
  }

  private thunkCache = new Map<number, string | undefined>();
  /** x86-32: returns the register a __x86.get_pc_thunk style function loads with the return address */
  private pcThunkReg(target: number): string | undefined {
    if (this.thunkCache.has(target)) return this.thunkCache.get(target);
    let r: string | undefined;
    const two = this.decodeAt(target, 2);
    const m = two[0] && /^mov$/.test(two[0].mnemonic) ? /^(e[a-z]{2}), (dword ptr )?\[esp\]$/.exec(two[0].operands) : null;
    if (m && two[1]?.flow === 'ret') r = m[1];
    this.thunkCache.set(target, r);
    return r;
  }

  private isGotLike(a: number): boolean {
    const n = this.mem.sectionName(a);
    return n === '.got' || n === '.got.plt' || n === '__got' || n === '__la_symbol_ptr' || n === '.idata';
  }

  classifyRef(at: number, addr: number, ins?: Insn): DataRef | undefined {
    const imp = this.importBySlot.get(addr);
    if (imp) return { at, addr, kind: 'import-slot', value: imp.name };
    if (!this.mem.isMapped(addr)) return undefined;
    const exec = this.mem.isExec(addr);
    if (!exec || this.mem.sectionName(addr)?.includes('rodata') || this.mem.sectionName(addr) === '.rdata') {
      const s = stringAt(this.mem, addr);
      if (s) return { at, addr, kind: 'string', value: s.value };
      // one level of indirection: a pointer (GOT entry, literal pool, string table) to a string
      const p = this.mem.readPtr(addr, this.img.bits, this.img.endian === 'le');
      if (p !== undefined && p !== 0 && p !== addr && this.mem.isMapped(p) && !this.mem.isExec(p)) {
        const s2 = stringAt(this.mem, p);
        if (s2) return { at, addr: p, kind: 'string', value: s2.value };
      }
    }
    if (exec) {
      // literal pools (ARM) live in code: check for a pointer to a string there too
      if (this.img.arch === 'arm' && ins && ins.mnemonic.startsWith('ldr')) {
        const p = this.mem.readU32(addr, this.img.endian === 'le');
        if (p !== undefined) {
          const s2 = this.mem.isMapped(p) ? stringAt(this.mem, p) : undefined;
          if (s2) return { at, addr: p, kind: 'string', value: s2.value };
        }
        return { at, addr, kind: 'data' };
      }
      return { at, addr, kind: 'code', value: this.symbolize(addr) };
    }
    return { at, addr, kind: 'data', value: this.symbolize(addr) };
  }

  // ---------- program wide indexes ----------

  /** Build (or return) the cross reference index over all discovered functions, within a time budget. */
  xrefs(budgetMs = 8000): { to: Map<number, { from: number; func: number; kind: string }[]>; complete: boolean; analyzed: number } {
    if (this.xrefIndex && this.xrefIndex.complete) return this.xrefIndex;
    this.discover();
    const budget = new Budget(budgetMs);
    const to = this.xrefIndex?.to ?? new Map<number, { from: number; func: number; kind: string }[]>();
    const add = (target: number, from: number, func: number, kind: string) => {
      let l = to.get(target);
      if (!l) { l = []; to.set(target, l); }
      if (l.length < 5000) l.push({ from, func, kind });
    };
    let analyzed = 0;
    let complete = true;
    const done = new Set<number>(this.xrefDone);
    for (const a of this.sortedFunctionAddrs()) {
      if (done.has(a)) { analyzed++; continue; }
      if (budget.expired) { complete = false; break; }
      const f = this.functions.get(a)!;
      if (f.isImportStub) { done.add(a); continue; }
      const af = this.analyze(a);
      done.add(a);
      analyzed++;
      if (!af) continue;
      for (const c of af.calls) {
        if (c.target !== undefined) add(c.target, c.at, a, c.tail ? 'jump' : 'call');
      }
      for (const b of af.blocks) {
        const last = b.insns[b.insns.length - 1]!;
        if (last.flow === 'cjump' && last.target !== undefined && !this.functions.has(last.target)) { /* intra function */ }
      }
      for (const d of af.dataRefs) add(d.addr, d.at, a, d.kind === 'string' ? 'string' : d.kind === 'import-slot' ? 'import' : d.kind === 'code' ? 'code-ref' : 'data');
    }
    this.xrefDone = done;
    this.xrefIndex = { to, complete, analyzed };
    return this.xrefIndex;
  }
  private xrefDone = new Set<number>();
}
