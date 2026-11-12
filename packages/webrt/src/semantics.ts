// Semantic runtime tracing of JavaScript through the debugger alone: the Node inspector or Chromium's
// DevTools protocol. Chosen functions get a breakpoint at their first statement and at every return
// position (Debugger.getPossibleBreakpoints with restrictToFunction); each hit records the arguments
// (read from the local scope with Runtime.getProperties) or the return value (callFrames[0].returnValue),
// a stack with async parents, and the call depth, then resumes. Scripts are caught before they run with
// the beforeScriptExecution instrumentation breakpoint, so functions that run during load are traced
// too. Optional logpoint mode uses conditional breakpoints that print a summary instead of pausing.
// Timers come from EventBreakpoints instrumentation (Chromium) or breakpoints on node:timers (Node);
// fetch and XHR initiators with stacks come from Network.requestWillBeSent. Node only.
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { CdpClient, cdpTargets, checkDevtoolsEndpoint } from './cdp.js';
import { executionAllowed } from './inspector.js';
import { parseJs, walk, t } from './js/ast.js';
import { InputError } from './util.js';

export interface Cdp { send(method: string, params?: Record<string, unknown>): Promise<any>; on(event: string, cb: (p: any) => void): void }

export interface FunctionSelector {
  /** function name: a declaration, a variable bound to a function, an object or class method (also "Class.method") */
  name?: string;
  /** only scripts whose URL contains this text */
  url?: string;
  /** or a location: 1-based line and 0-based column of any position inside the function */
  line?: number;
  column?: number;
}

export interface TraceEvent {
  seq: number;
  kind: 'enter' | 'exit' | 'timer' | 'request' | 'log';
  fn?: string;
  /** milliseconds since tracing started */
  t: number;
  depth?: number;
  args?: Record<string, string>;
  returnValue?: string;
  timer?: string;
  request?: { method: string; url: string; type?: string; requestId?: string };
  location?: { url: string; line: number; column: number; scriptId?: string };
  stack?: string[];
  asyncStack?: string[];
}

export interface TracedFunction { id: number; name: string; url: string; scriptId: string; line: number; column: number; endLine: number; params: string[]; returnPoints: number; calls: number; returns: number; disabledAfter?: number }

export interface SemanticTrace {
  target: { kind: 'chromium' | 'node'; url?: string; version?: string };
  mode: 'pause' | 'logpoint';
  durationMs: number;
  functions: TracedFunction[];
  events: TraceEvent[];
  eventCount: number;
  scripts: { scriptId: string; url: string; sha256?: string; length?: number; sourceMapURL?: string }[];
  summary: { calls: Record<string, number>; timers: Record<string, number>; requests: number; unmatchedSelectors: string[] };
  warnings: string[];
}

export interface TraceOptions {
  functions: (string | FunctionSelector)[];
  mode?: 'pause' | 'logpoint';
  durationMs?: number;
  maxEvents?: number;
  /** stop tracing a function after this many calls (default 200) */
  maxHitsPerFunction?: number;
  timers?: boolean;
  network?: boolean;
  /** stack frames kept per event (default 8) */
  stackDepth?: number;
  /** include scripts whose URL starts with node: or is empty (default false) */
  includeInternal?: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Named functions in a script with their ranges, for picking breakpoint locations. */
export function findFunctions(code: string): { name: string; aliases: string[]; line: number; column: number; endLine: number; endColumn: number; bodyLine: number; bodyColumn: number; params: string[] }[] {
  let ast: t.File;
  try { ast = parseJs(code).ast; } catch { return []; }
  const out: ReturnType<typeof findFunctions> = [];
  walk(ast, ({ node, parent, ancestors }) => {
    if (out.length >= 20_000) return 'stop';
    const isFn = node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' || node.type === 'ClassMethod' || node.type === 'ObjectMethod' || node.type === 'ClassPrivateMethod';
    if (!isFn || !node.loc) return undefined;
    const names: string[] = [];
    const n = node as t.Function;
    if ((node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') && node.id) names.push(node.id.name);
    if ((node.type === 'ClassMethod' || node.type === 'ObjectMethod') && node.key.type === 'Identifier') names.push(node.key.name);
    if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') names.push(parent.id.name);
    if (parent?.type === 'ObjectProperty' && parent.key.type === 'Identifier') names.push(parent.key.name);
    if (parent?.type === 'AssignmentExpression' && parent.left.type === 'MemberExpression' && parent.left.property.type === 'Identifier') {
      names.push(parent.left.property.name);
      if (parent.left.object.type === 'Identifier') names.push(`${parent.left.object.name}.${parent.left.property.name}`);
    }
    if (parent?.type === 'ClassProperty' && parent.key.type === 'Identifier') names.push(parent.key.name);
    // Class.method and object.method qualified names
    if (node.type === 'ClassMethod' || parent?.type === 'ClassProperty') {
      const cls = [...ancestors].reverse().find((a) => a.type === 'ClassDeclaration' || a.type === 'ClassExpression') as t.ClassDeclaration | undefined;
      const k = node.type === 'ClassMethod' ? node.key : (parent as t.ClassProperty).key;
      if (cls?.id && k.type === 'Identifier') names.push(`${cls.id.name}.${k.name}`);
    }
    if (!names.length) return undefined;
    // esbuild and rollup rename clashing bindings to name2, name3: keep the plain name as an alias
    for (const nm of [...names]) { const plain = /^([A-Za-z_$][\w$]*?[A-Za-z_$])\d{1,3}$/.exec(nm)?.[1]; if (plain && !names.includes(plain)) names.push(plain); }
    const body = n.body;
    const first = body.type === 'BlockStatement' ? body.body[0] : body;
    const at = first?.loc?.start ?? (body.loc ? { line: body.loc.start.line, column: body.loc.start.column + 1 } : node.loc.start);
    out.push({ name: names[0]!, aliases: [...new Set(names)], line: node.loc.start.line, column: node.loc.start.column, endLine: node.loc.end.line, endColumn: node.loc.end.column, bodyLine: at.line, bodyColumn: at.column, params: n.params.map((p) => (p.type === 'Identifier' ? p.name : p.type === 'AssignmentPattern' && p.left.type === 'Identifier' ? p.left.name : p.type === 'RestElement' && p.argument.type === 'Identifier' ? `...${p.argument.name}` : '')).filter(Boolean) });
    return undefined;
  });
  return out;
}

/** Short text for a CDP RemoteObject. */
export function summarize(o: any, max = 200): string {
  if (!o || typeof o !== 'object') return String(o);
  if (o.type === 'undefined') return 'undefined';
  if (o.unserializableValue !== undefined) return String(o.unserializableValue);
  if (o.type === 'string') return JSON.stringify(String(o.value ?? '').slice(0, max));
  if (o.type === 'number' || o.type === 'boolean') return String(o.value);
  if (o.subtype === 'null') return 'null';
  if (o.type === 'function') return `function ${String(o.description ?? '').split('(')[0]!.replace(/^(?:async )?function\s*/, '').slice(0, 60) || '(anonymous)'}`;
  const p = o.preview;
  if (p && Array.isArray(p.properties)) {
    const props = p.properties.slice(0, 6).map((x: any) => (o.subtype === 'array' ? '' : `${x.name}: `) + (x.type === 'string' ? JSON.stringify(String(x.value ?? '').slice(0, 40)) : x.type === 'object' ? (x.subtype === 'null' ? 'null' : String(x.value ?? 'Object').slice(0, 40)) : String(x.value ?? x.type)));
    const more = p.overflow ? ', ...' : '';
    return o.subtype === 'array' ? `${o.description ?? 'Array'} [${props.join(', ')}${more}]`.slice(0, max) : `${o.className && o.className !== 'Object' ? o.className + ' ' : ''}{${props.join(', ')}${more}}`.slice(0, max);
  }
  return String(o.description ?? o.className ?? o.type).slice(0, max);
}

function frames(stack: any, depth: number): string[] {
  return (stack?.callFrames ?? []).slice(0, depth).map((f: any) => `${f.functionName || '(anonymous)'} ${f.url}:${Number(f.lineNumber) + 1}:${Number(f.columnNumber) + 1}`);
}
function asyncFrames(stack: any, depth: number): string[] {
  const out: string[] = [];
  for (let p = stack, n = 0; p && n < 8; p = p.parent, n++) {
    if (p.description) out.push(`-- ${p.description} --`);
    out.push(...frames(p, depth));
    if (out.length > depth * 3) break;
  }
  return out;
}

/** Run a semantic trace over an already connected CDP session (a Node inspector or a Chromium page). */
export class SemanticTracer {
  private t0 = Date.now();
  private events: TraceEvent[] = [];
  private seq = 0;
  private fns: TracedFunction[] = [];
  private bp = new Map<string, { fn: number; kind: 'enter' | 'exit' }[]>();
  private fnBps = new Map<number, string[]>();
  private depth = 0;
  private scripts = new Map<string, SemanticTrace['scripts'][number]>();
  private handled = new Set<string>();
  private selectors: FunctionSelector[];
  private matchedSelectors = new Set<number>();
  readonly warnings: string[] = [];
  private stopped = false;
  private timerCounts: Record<string, number> = {};
  private callBps = new Map<string, { label: string; kind: 'timer' | 'request' }>();
  private startBp?: string;
  /** scriptId to URL for every parsed script: paused call frames carry only the scriptId */
  private urlOf = new Map<string, string>();
  private frameUrl(f: any): string { return String(f.url || this.urlOf.get(String(f.location?.scriptId)) || ''); }
  private pframes(cfs: any[]): string[] { return cfs.slice(0, this.stackDepth).map((f: any) => `${f.functionName || '(anonymous)'} ${this.frameUrl(f)}:${f.location.lineNumber + 1}:${f.location.columnNumber + 1}`); }
  private requests = 0;

  constructor(private cdp: Cdp, private opts: TraceOptions, private kind: 'chromium' | 'node') {
    this.selectors = opts.functions.slice(0, 200).map((f) => (typeof f === 'string' ? { name: f } : f));
    if (!this.selectors.length) throw new InputError('give at least one function to trace');
  }
  private get max(): number { return Math.max(1, Math.min(this.opts.maxEvents ?? 2000, 100_000)); }
  private get stackDepth(): number { return Math.max(0, Math.min(this.opts.stackDepth ?? 8, 50)); }
  private push(e: Omit<TraceEvent, 'seq' | 't'>): void { if (this.events.length < this.max) this.events.push({ seq: this.seq++, t: Date.now() - this.t0, ...e }); }

  /** Enable domains and catch every script before it runs. */
  async start(): Promise<void> {
    const c = this.cdp;
    c.on('Debugger.scriptParsed', (p) => {
      const url = String(p.url ?? '');
      if (this.urlOf.size < 200_000) this.urlOf.set(String(p.scriptId), url);
      if (!this.opts.includeInternal && (url === '' || url.startsWith('node:internal') || url.startsWith('pptr:') || url.startsWith('__playwright'))) return;
      if (this.scripts.size < 5000) this.scripts.set(String(p.scriptId), { scriptId: String(p.scriptId), url: url.slice(0, 4000), length: p.length, sourceMapURL: p.sourceMapURL || undefined });
    });
    c.on('Debugger.paused', (p) => { this.onPaused(p).catch((e) => { this.warnings.push(`pause: ${(e as Error).message.slice(0, 160)}`); c.send('Debugger.resume').catch(() => undefined); }); });
    if (this.opts.mode === 'logpoint') c.on('Runtime.consoleAPICalled', (p) => this.onConsole(p));
    await c.send('Runtime.enable');
    await c.send('Debugger.enable', { maxScriptsCacheSize: 100_000_000 });
    await c.send('Debugger.setAsyncCallStackDepth', { maxDepth: 16 }).catch(() => undefined);
    // evaluations run before the instrumentation breakpoint exists, so they do not pause themselves
    // Node has no DOM instrumentation: break on calls of the timer and request functions themselves
    if (this.kind === 'node') {
      const targets: [string, string, 'timer' | 'request'][] = [];
      if (this.opts.timers !== false) targets.push(['globalThis.setTimeout', 'setTimeout', 'timer'], ['globalThis.setInterval', 'setInterval', 'timer'], ['globalThis.setImmediate', 'setImmediate', 'timer'], ['globalThis.queueMicrotask', 'queueMicrotask', 'timer']);
      if (this.opts.network !== false) targets.push(['globalThis.fetch', 'fetch', 'request'], ["process.getBuiltinModule?.('node:http')?.request", 'http.request', 'request'], ["process.getBuiltinModule?.('node:http')?.get", 'http.get', 'request'], ["process.getBuiltinModule?.('node:https')?.request", 'https.request', 'request'], ["process.getBuiltinModule?.('node:https')?.get", 'https.get', 'request']);
      for (const [expr, label, kind] of targets) {
        const r = await c.send('Runtime.evaluate', { expression: expr, objectGroup: 'revlens-trace', silent: true }).catch(() => undefined);
        const oid = r?.result?.type === 'function' ? r.result.objectId : undefined;
        if (!oid) continue;
        const b = await c.send('Debugger.setBreakpointOnFunctionCall', { objectId: oid }).catch(() => undefined);
        if (b?.breakpointId) this.callBps.set(b.breakpointId, { label, kind });
      }
    }
    await c.send('Debugger.setInstrumentationBreakpoint', { instrumentation: 'beforeScriptExecution' });
    // Node compiles CommonJS modules with compileFunction, which skips that instrumentation pause; a
    // breakpoint on the first line of every non-internal script pauses there instead
    if (this.kind === 'node') {
      const r = await c.send('Debugger.setBreakpointByUrl', { urlRegex: '^(?!node:).+', lineNumber: 0, columnNumber: 0 }).catch(() => undefined);
      if (r?.breakpointId) this.startBp = r.breakpointId;
    }
    if (this.opts.timers !== false && this.kind === 'chromium') {
      for (const ev of ['setTimeout', 'setInterval', 'setTimeout.callback', 'setInterval.callback', 'requestAnimationFrame', 'requestAnimationFrame.callback']) {
        await c.send('EventBreakpoints.setInstrumentationBreakpoint', { eventName: ev }).catch(() => c.send('DOMDebugger.setInstrumentationBreakpoint', { eventName: ev }).catch(() => this.warnings.push(`timer breakpoint ${ev} not supported`)));
      }
    }
    if (this.opts.network !== false) {
      c.on('Network.requestWillBeSent', (p) => {
        const type = String(p.type ?? '');
        if (this.kind === 'chromium' && type && type !== 'Fetch' && type !== 'XHR' && type !== 'EventSource' && type !== 'Ping') return;
        // Node reports requests it already announced through the http.request breakpoint: keep one
        const prev = [...this.events].reverse().find((e) => e.kind === 'request');
        if (this.kind === 'node' && prev?.request && prev.request.url === String(p.request?.url ?? '') && Date.now() - this.t0 - prev.t < 2_000) { prev.request.method = String(p.request?.method ?? ''); prev.request.requestId = p.requestId; return; }
        this.requests++;
        this.push({ kind: 'request', request: { method: String(p.request?.method ?? 'GET'), url: String(p.request?.url ?? '').slice(0, 2000), type: type || undefined, requestId: p.requestId }, stack: frames(p.initiator?.stack, this.stackDepth), asyncStack: p.initiator?.stack?.parent ? asyncFrames(p.initiator.stack.parent, this.stackDepth) : undefined, location: p.initiator?.url ? { url: String(p.initiator.url), line: Number(p.initiator.lineNumber ?? 0) + 1, column: Number(p.initiator.columnNumber ?? 0) } : undefined });
      });
      await c.send('Network.enable', {}).catch(() => this.warnings.push('Network domain not available (Node needs --experimental-network-inspection)'));
    }
    // scripts parsed before we attached (Node internals, an already loaded page): set breakpoints now
    await sleep(50);
    for (const s of [...this.scripts.values()]) await this.instrument(s.scriptId);
  }

  /** Find selected functions in a script and set entry and return breakpoints. */
  private async instrument(scriptId: string): Promise<void> {
    if (this.handled.has(scriptId) || this.stopped) return;
    this.handled.add(scriptId);
    const info = this.scripts.get(scriptId);
    const url = info?.url ?? '';
    const builtin = url.startsWith('node:') || url.startsWith('extensions::') || url.startsWith('chrome');
    // Node and browser internals are only searched when a selector names them by URL
    const wanted = this.selectors.map((s, i) => ({ s, i })).filter(({ s }) => (s.url ? url.includes(s.url) : !builtin));
    if (!wanted.length && (builtin || !info)) return;
    let src: string;
    try { src = String((await this.cdp.send('Debugger.getScriptSource', { scriptId })).scriptSource ?? ''); } catch { return; }
    if (info) info.sha256 = createHash('sha256').update(src).digest('hex');
    if (!wanted.length || src.length > 16 * 1024 * 1024) return;
    const fns = findFunctions(src);
    for (const { s, i } of wanted) {
      const hits = fns.filter((f) => (s.name ? f.aliases.includes(s.name) : true) && (s.line === undefined || (s.line >= f.line && s.line <= f.endLine && (s.line !== f.line || (s.column ?? 0) >= f.column))));
      // with a location, keep the innermost function only
      const chosen = s.line !== undefined ? hits.sort((a, b) => (a.endLine - a.line) - (b.endLine - b.line)).slice(0, 1) : hits.slice(0, 20);
      for (const f of chosen) {
        if (this.fns.some((x) => x.scriptId === scriptId && x.line === f.line && x.column === f.column)) continue;
        this.matchedSelectors.add(i);
        const id = this.fns.length;
        const tf: TracedFunction = { id, name: s.name && f.aliases.includes(s.name) ? s.name : f.name, url, scriptId, line: f.line, column: f.column, endLine: f.endLine, params: f.params, returnPoints: 0, calls: 0, returns: 0 };
        this.fns.push(tf);
        const ids: string[] = [];
        const at = (line: number, col: number) => ({ scriptId, lineNumber: line - 1, columnNumber: col });
        const cond = this.opts.mode === 'logpoint' ? this.logpointCondition(id, f.params) : undefined;
        try {
          const r = await this.cdp.send('Debugger.setBreakpoint', { location: at(f.bodyLine, f.bodyColumn), condition: cond });
          ids.push(r.breakpointId);
          const l = this.bp.get(r.breakpointId) ?? []; l.push({ fn: id, kind: 'enter' }); this.bp.set(r.breakpointId, l);
        } catch (e) { this.warnings.push(`breakpoint ${tf.name}: ${(e as Error).message.slice(0, 120)}`); }
        if (this.opts.mode !== 'logpoint') {
          try {
            const pos = await this.cdp.send('Debugger.getPossibleBreakpoints', { start: at(f.bodyLine, f.bodyColumn), end: at(f.endLine, f.endColumn + 1), restrictToFunction: true });
            for (const loc of (pos.locations ?? []).filter((x: any) => x.type === 'return').slice(0, 200)) {
              const r = await this.cdp.send('Debugger.setBreakpoint', { location: { scriptId, lineNumber: loc.lineNumber, columnNumber: loc.columnNumber } }).catch(() => undefined);
              if (!r) continue;
              ids.push(r.breakpointId); tf.returnPoints++;
              const l = this.bp.get(r.breakpointId) ?? []; l.push({ fn: id, kind: 'exit' }); this.bp.set(r.breakpointId, l);
            }
          } catch (e) { this.warnings.push(`return points ${tf.name}: ${(e as Error).message.slice(0, 120)}`); }
        }
        this.fnBps.set(id, ids);
      }
    }
  }

  /** DevTools style logpoint: print a marker and argument summaries, never pause. */
  private logpointCondition(id: number, params: string[]): string {
    const names = params.filter((p) => /^(?:\.\.\.)?[A-Za-z_$][\w$]*$/.test(p)).map((p) => p.replace(/^\.\.\./, ''));
    const parts = names.map((n) => `${JSON.stringify(n)}, (() => { try { const v = ${n}; return v === null ? 'null' : typeof v === 'object' ? Object.prototype.toString.call(v) : typeof v === 'function' ? 'function' : typeof v === 'string' ? JSON.stringify(v.slice(0, 200)) : String(v); } catch (e) { return '?'; } })()`);
    return `(console.debug("\\u0001revlens-trace", ${id}${parts.length ? ', ' + parts.join(', ') : ''}), false)`;
  }

  private onConsole(p: any): void {
    const a = p.args ?? [];
    if (a[0]?.value !== '\u0001revlens-trace') return;
    const fn = this.fns[Number(a[1]?.value)];
    if (!fn) return;
    fn.calls++;
    const args: Record<string, string> = {};
    for (let i = 2; i + 1 < a.length; i += 2) args[String(a[i].value)] = String(a[i + 1].value ?? '').slice(0, 300);
    this.push({ kind: 'enter', fn: fn.name, args, stack: frames(p.stackTrace, this.stackDepth).slice(0), location: { url: fn.url, line: fn.line, column: fn.column, scriptId: fn.scriptId } });
    this.limit(fn);
  }

  private limit(fn: TracedFunction): void {
    const max = this.opts.maxHitsPerFunction ?? 200;
    if (fn.calls >= max && fn.disabledAfter === undefined) {
      fn.disabledAfter = fn.calls;
      for (const b of this.fnBps.get(fn.id) ?? []) this.cdp.send('Debugger.removeBreakpoint', { breakpointId: b }).catch(() => undefined);
    }
  }

  private async onPaused(p: any): Promise<void> {
    const c = this.cdp;
    try {
      const top = p.callFrames?.[0];
      if (p.reason === 'instrumentation' && p.data?.scriptId) { await this.instrument(String(p.data.scriptId)); return; }
      if (p.reason === 'EventListener' || p.reason === 'instrumentation') {
        const name = String(p.data?.eventName ?? p.data?.instrumentation ?? '').replace(/^instrumentation:/, '');
        // timers started by the automation layer itself (scripts without a URL) are not the page's
        const userCode = (p.callFrames ?? []).some((f: any) => this.frameUrl(f));
        if (name && (userCode || this.opts.includeInternal)) { this.timerCounts[name] = (this.timerCounts[name] ?? 0) + 1; this.push({ kind: 'timer', timer: name, stack: this.pframes(p.callFrames ?? []), asyncStack: p.asyncStackTrace ? asyncFrames(p.asyncStackTrace, this.stackDepth) : undefined }); }
        return;
      }
      const ours = (p.hitBreakpoints ?? []).some((b: string) => this.bp.has(b) || this.callBps.has(b));
      if (!ours) {
        // "Break on start" of --inspect-brk, a debugger statement, or a module paused before it runs:
        // set breakpoints in every script parsed so far before letting it go on
        for (const sc of [...this.scripts.keys()]) await this.instrument(sc);
        return;
      }
      for (const bid of p.hitBreakpoints ?? []) {
        const cb = this.callBps.get(bid);
        if (cb) {
          // drop the runtime's own frames (setTimeout itself, http internals) so the stack starts at the caller
          const cfs = (p.callFrames ?? []) as any[];
          const firstUser = this.opts.includeInternal ? 0 : cfs.findIndex((f) => { const u = this.frameUrl(f); return u && !u.startsWith('node:'); });
          if (firstUser < 0) continue;
          const stack = this.pframes(cfs.slice(firstUser));
          const asyncStack = p.asyncStackTrace ? asyncFrames(p.asyncStackTrace, this.stackDepth) : undefined;
          if (cb.kind === 'timer') { this.timerCounts[cb.label] = (this.timerCounts[cb.label] ?? 0) + 1; this.push({ kind: 'timer', timer: cb.label, stack, asyncStack }); }
          else {
            // the first argument of fetch/http.request: a URL string, a URL object or an options object
            let urlText = '?';
            const local = p.callFrames?.[0]?.scopeChain?.find((x: any) => x.type === 'local');
            if (local?.object?.objectId) {
              const props = await this.cdp.send('Runtime.getProperties', { objectId: local.object.objectId, ownProperties: true, generatePreview: true }).catch(() => ({ result: [] }));
              const first = (props.result ?? []).find((x: any) => ['input', 'url', 'options', 'resource'].includes(String(x.name)));
              if (first?.value) urlText = first.value.type === 'string' ? String(first.value.value).slice(0, 2000) : summarize(first.value, 300);
            }
            // http.get calls http.request: one request, both names
            const prev = [...this.events].reverse().find((e) => e.kind === 'request');
            if (prev?.request && prev.request.url === urlText && Date.now() - this.t0 - prev.t < 300) { prev.request.type = `${prev.request.type}+${cb.label}`; continue; }
            this.requests++;
            this.push({ kind: 'request', request: { method: '', url: urlText, type: cb.label }, stack, asyncStack });
          }
          continue;
        }
        for (const h of this.bp.get(bid) ?? []) {
          const fn = this.fns[h.fn]!;
          const stack = this.pframes(p.callFrames ?? []);
          const location = { url: fn.url, line: Number(top?.location?.lineNumber ?? 0) + 1, column: Number(top?.location?.columnNumber ?? 0), scriptId: fn.scriptId };
          if (h.kind === 'enter') {
            fn.calls++;
            if (fn.url.startsWith('node:timers')) this.timerCounts[fn.name] = (this.timerCounts[fn.name] ?? 0) + 1;
            const args: Record<string, string> = {};
            const local = top?.scopeChain?.find((s: any) => s.type === 'local');
            if (local?.object?.objectId) {
              const props = await c.send('Runtime.getProperties', { objectId: local.object.objectId, ownProperties: true, generatePreview: true }).catch(() => ({ result: [] }));
              const byName = new Map<string, any>((props.result ?? []).map((x: any) => [String(x.name), x.value]));
              for (const pn of fn.params) { const n = pn.replace(/^\.\.\./, ''); if (byName.has(n)) args[pn] = summarize(byName.get(n)); }
            }
            this.depth++;
            this.push({ kind: 'enter', fn: fn.name, depth: this.depth, args, stack, asyncStack: p.asyncStackTrace ? asyncFrames(p.asyncStackTrace, this.stackDepth) : undefined, location });
            this.limit(fn);
          } else {
            fn.returns++;
            this.push({ kind: 'exit', fn: fn.name, depth: this.depth, returnValue: top?.returnValue ? summarize(top.returnValue) : 'undefined', location });
            this.depth = Math.max(0, this.depth - 1);
          }
        }
      }
    } finally {
      await c.send('Debugger.resume').catch(() => undefined);
    }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await this.cdp.send('Debugger.removeInstrumentationBreakpoint', { instrumentation: 'beforeScriptExecution' }).catch(() => undefined);
    if (this.startBp) await this.cdp.send('Debugger.removeBreakpoint', { breakpointId: this.startBp }).catch(() => undefined);
    for (const b of this.callBps.keys()) await this.cdp.send('Debugger.removeBreakpoint', { breakpointId: b }).catch(() => undefined);
    for (const ids of this.fnBps.values()) for (const b of ids) await this.cdp.send('Debugger.removeBreakpoint', { breakpointId: b }).catch(() => undefined);
    await this.cdp.send('Debugger.resume').catch(() => undefined);
  }

  result(target: SemanticTrace['target'], durationMs: number): SemanticTrace {
    const calls: Record<string, number> = {};
    for (const f of this.fns) calls[f.name] = (calls[f.name] ?? 0) + f.calls;
    const unmatched = this.selectors.map((s, i) => ({ s, i })).filter(({ i }) => !this.matchedSelectors.has(i)).map(({ s }) => s.name ?? `${s.url ?? '*'}:${s.line}`);
    return { target, mode: this.opts.mode ?? 'pause', durationMs, functions: this.fns, events: this.events, eventCount: this.seq, scripts: [...this.scripts.values()], summary: { calls, timers: this.timerCounts, requests: this.requests, unmatchedSelectors: unmatched }, warnings: this.warnings.slice(0, 200) };
  }
}

/**
 * Trace a Node.js program: run `script` under the inspector (needs allowExecution) or attach to a
 * process that already listens (port or wsUrl). The program is resumed after breakpoints are in place.
 */
export async function traceNodeSemantics(opts: TraceOptions & { allowExecution?: boolean; script?: string; args?: string[]; cwd?: string; port?: number; wsUrl?: string; timeoutMs?: number }): Promise<SemanticTrace & { exitCode?: number | null; stdout?: string; stderr?: string }> {
  if (!executionAllowed(opts.allowExecution)) throw new InputError('tracing a Node program needs allowExecution: true (or REVLENS_ALLOW_EXECUTION=1)');
  if (!Array.isArray(opts.functions) || !opts.functions.length) throw new InputError('give at least one function to trace');
  const duration = Math.max(100, Math.min(opts.durationMs ?? 5_000, 120_000));
  let child: ChildProcess | undefined;
  let wsUrl = opts.wsUrl;
  let stdout = '', stderr = '';
  let exitCode: number | null | undefined;
  const exited = new Promise<void>((ok) => { if (!opts.script) ok(); else setTimeout(ok, duration + 5_000).unref?.(); });
  if (opts.script) {
    child = spawn(process.execPath, ['--inspect-brk=127.0.0.1:0', '--experimental-network-inspection', opts.script, ...(opts.args ?? []).map(String).slice(0, 100)], { cwd: opts.cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_OPTIONS: '' } });
    child.stdout!.on('data', (d) => { if (stdout.length < 1_000_000) stdout += d; });
    wsUrl = await new Promise<string>((ok, bad) => {
      const timer = setTimeout(() => bad(new InputError('the program did not open its inspector in 10 s')), 10_000);
      child!.stderr!.on('data', (d) => {
        if (stderr.length < 1_000_000) stderr += d;
        const m = /Debugger listening on (ws:\/\/[^\s]+)/.exec(stderr);
        if (m) { clearTimeout(timer); ok(m[1]!); }
      });
      child!.once('exit', (code) => { clearTimeout(timer); bad(new InputError(`program exited (${code}) before the inspector opened: ${stderr.slice(0, 300)}`)); });
    });
    child.once('exit', (code) => { exitCode = code; });
  } else if (!wsUrl) {
    const port = opts.port ?? 9229;
    const t = await cdpTargets(`http://127.0.0.1:${port}`, { timeoutMs: 2_000 });
    wsUrl = t.targets.find((x) => x.webSocketDebuggerUrl)?.webSocketDebuggerUrl;
    if (!wsUrl) throw new InputError(`no inspector target on port ${port}`);
  } else checkDevtoolsEndpoint(wsUrl);
  let client: CdpClient;
  try { client = await CdpClient.connect(wsUrl!, 5_000); } catch (e) { child?.kill('SIGKILL'); throw e; }
  let tracer: SemanticTracer;
  try { tracer = new SemanticTracer(client, opts, 'node'); } catch (e) { client.close(); child?.kill('SIGKILL'); throw e; }
  const t0 = Date.now();
  let version: string | undefined;
  try {
    version = (await client.send('Runtime.evaluate', { expression: 'process.version', returnByValue: true }).catch(() => undefined))?.result?.value;
    await tracer.start();
    // a program started with --inspect-brk waits here until the debugger lets it go
    await client.send('Runtime.runIfWaitingForDebugger').catch(() => undefined);
    const end = Date.now() + duration;
    while (Date.now() < end && exitCode === undefined) await sleep(25);
    await tracer.stop();
  } finally {
    client.close();
    if (child && exitCode === undefined) { await Promise.race([new Promise((r) => child!.once('exit', r)), sleep(1_500)]); if (exitCode === undefined) child.kill('SIGKILL'); }
    await Promise.race([exited, sleep(10)]);
  }
  const r = tracer.result({ kind: 'node', url: opts.script, version }, Date.now() - t0);
  return { ...r, exitCode, stdout: opts.script ? stdout.split('\n').filter((l) => !l.startsWith('\u0001revlens-trace')).join('\n').slice(0, 20_000) : undefined, stderr: opts.script ? stderr.replace(/Debugger (listening|attached)[^\n]*\n?|For help, see[^\n]*\n?|Waiting for the debugger[^\n]*\n?/g, '').slice(0, 20_000) : undefined };
}

export type PageAction = { action: 'click' | 'fill' | 'wait' | 'press' | 'goto'; selector?: string; text?: string; ms?: number; key?: string; url?: string };

/** Trace a page in Chromium (Playwright for the browser, CDP for everything traced). */
export async function traceBrowserSemantics(url: string, opts: TraceOptions & { executablePath?: string; actions?: PageAction[]; timeoutMs?: number; allowFileUrls?: boolean }): Promise<SemanticTrace> {
  let u: URL;
  try { u = new URL(url); } catch { throw new InputError(`not a valid URL: ${url}`); }
  if (!/^https?:$/.test(u.protocol) && !(opts.allowFileUrls && u.protocol === 'file:')) throw new InputError('only http and https pages can be traced');
  if (!Array.isArray(opts.functions) || !opts.functions.length) throw new InputError('give at least one function to trace');
  let pw: any;
  try { pw = await import('playwright' as string); } catch { throw new InputError('browser tracing needs the optional "playwright" package'); }
  const duration = Math.max(100, Math.min(opts.durationMs ?? 3_000, 120_000));
  const browser = await pw.chromium.launch({ executablePath: opts.executablePath, timeout: 30_000, args: ['--disable-dev-shm-usage', '--no-first-run'] });
  const hard = setTimeout(() => { browser.close().catch(() => undefined); }, Math.max(duration + 60_000, opts.timeoutMs ?? 0));
  const t0 = Date.now();
  try {
    const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    const tracer = new SemanticTracer(cdp, opts, 'chromium');
    await tracer.start();
    await page.goto(url, { waitUntil: 'load', timeout: 30_000 });
    for (const a of (opts.actions ?? []).slice(0, 50)) {
      try {
        if (a.action === 'click' && a.selector) await page.locator(a.selector).first().click({ timeout: 10_000 });
        else if (a.action === 'fill' && a.selector) await page.locator(a.selector).first().fill(String(a.text ?? ''), { timeout: 10_000 });
        else if (a.action === 'press') await page.keyboard.press(String(a.key ?? 'Enter'));
        else if (a.action === 'goto' && a.url) await page.goto(new URL(a.url, url).href, { waitUntil: 'load', timeout: 30_000 });
        else await page.waitForTimeout(Math.max(0, Math.min(a.ms ?? 300, 30_000)));
      } catch (e) { tracer.warnings.push(`action ${a.action} ${a.selector ?? ''}: ${(e as Error).message.split('\n')[0]!.slice(0, 160)}`); }
    }
    await page.waitForTimeout(duration);
    await tracer.stop();
    return tracer.result({ kind: 'chromium', url, version: browser.version() }, Date.now() - t0);
  } finally {
    clearTimeout(hard);
    await browser.close().catch(() => undefined);
  }
}
