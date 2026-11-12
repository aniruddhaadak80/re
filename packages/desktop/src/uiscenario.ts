// Native UI action tracing and scripted UI scenarios.
//  - traceUi: listen to accessibility events for a while (AT-SPI signals on Linux, UIAutomation
//    event handlers on Windows, tree polling on macOS or when asked), optionally performing actions
//    while listening, and diff the tree before and after.
//  - runUiScenario: find elements by role and name, click through the accessibility action or the
//    pointer, type, press keys, wait and assert element state; each step saves a tree and a screenshot.
import { mkdir, writeFile, mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { InputError } from './proc.js';
import { requireExecution, powershell } from './exec.js';
import { Atspi, parseRef } from './atspi.js';
import { compareUiTrees, findNode, findNodes, checkSelector, describeSelector, summarizeEvents, normalizeRole, type UiEvent, type UiSelector, type UiTreeDiff } from './uimodel.js';
import { sessionHandle, actOnComputer, type ComputerAction } from './computer.js';
import { parseKeyCombo } from './keys.js';
import { sha256Hex } from './audit.js';
import type { UiNode } from './gvariant.js';
import type { DMessage } from './dbuswire.js';
import type { Driver } from './drivers.js';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
type Tree = { nodes: UiNode[]; truncated: boolean; backend: string };

async function grabTree(o: { busAddress?: string; pid?: number; app?: string; maxNodes?: number; details?: boolean }): Promise<Tree> {
  const { captureUiTree } = await import('./node.js');
  const t = await captureUiTree({ allowExecution: true, busAddress: o.busAddress, pid: o.pid, app: o.app, maxNodes: Math.max(1, Math.min(o.maxNodes ?? 1500, 5000)), maxDepth: 40, details: o.details ?? true });
  return { nodes: t.nodes, truncated: t.truncated, backend: t.backend };
}

// ---------------- trace ----------------

export interface TraceOptions {
  allowExecution?: boolean;
  /** computer session id: uses its accessibility bus and lets `during` drive it */
  session?: string;
  busAddress?: string; pid?: number; app?: string;
  durationMs?: number;
  /** events (default where the platform has them) or poll (tree snapshots diffed every intervalMs) */
  mode?: 'events' | 'poll';
  intervalMs?: number;
  /** AT-SPI event classes to subscribe to (default object:, window:, focus:) */
  classes?: string[];
  maxEvents?: number;
  /** computer actions to run (in order) once listening has started */
  during?: ComputerAction[];
  /** accessibility action to run on an element once listening has started */
  elementAction?: { selector: UiSelector; action?: string };
  /** capture the tree before and after and diff them (default true) */
  treeDiff?: boolean;
  maxNodes?: number;
}

export interface TraceResult {
  platform: string; backend: string; mode: 'events' | 'poll'; durationMs: number;
  events: UiEvent[]; truncated: boolean; summary: ReturnType<typeof summarizeEvents>;
  actions: { what: string; ok: boolean; error?: string; t: number }[];
  diff?: UiTreeDiff; warnings: string[];
}

/** Watch accessibility events of one app (or all) for a bounded time. */
export async function traceUi(o: TraceOptions): Promise<TraceResult> {
  requireExecution(o.allowExecution, 'tracing another app\'s UI');
  const dur = Math.max(100, Math.min(Number(o.durationMs ?? 3000), 120_000));
  const maxEvents = Math.max(1, Math.min(Number(o.maxEvents ?? 2000), 50_000));
  const sess = o.session ? sessionHandle(o.session) : undefined;
  const bus = o.busAddress ?? sess?.a11yAddress;
  const platform = process.platform;
  const mode: 'events' | 'poll' = o.mode ?? (platform === 'darwin' ? 'poll' : 'events');
  const warnings: string[] = [];
  const actions: TraceResult['actions'] = [];
  const before = o.treeDiff !== false ? await grabTree({ busAddress: bus, pid: o.pid, app: o.app, maxNodes: o.maxNodes }).catch((e) => { warnings.push(`tree before: ${(e as Error).message}`); return undefined; }) : undefined;
  const t0 = Date.now();
  const runActions = async () => {
    for (const a of (o.during ?? []).slice(0, 100)) {
      if (!o.session) { actions.push({ what: a.action, ok: false, error: 'during needs a session', t: Date.now() - t0 }); break; }
      try { await actOnComputer(o.session, a); actions.push({ what: a.action, ok: true, t: Date.now() - t0 }); } catch (e) { actions.push({ what: a.action, ok: false, error: (e as Error).message.slice(0, 300), t: Date.now() - t0 }); }
    }
    if (o.elementAction) {
      const sel = checkSelector(o.elementAction.selector);
      try {
        const tree = await grabTree({ busAddress: bus, pid: o.pid, app: o.app, maxNodes: o.maxNodes, details: false });
        const n = findNode(tree.nodes, sel);
        if (!n?.ref) throw new InputError(`no element matches ${describeSelector(sel)}`);
        const a = await Atspi.open(bus); try { const name = await a.doAction(parseRef(n.ref), o.elementAction.action); actions.push({ what: `${name} on ${describeSelector(sel)}`, ok: true, t: Date.now() - t0 }); } finally { a.close(); }
      } catch (e) { actions.push({ what: `action on ${describeSelector(sel)}`, ok: false, error: (e as Error).message.slice(0, 300), t: Date.now() - t0 }); }
    }
  };
  let events: UiEvent[] = [], truncated = false, backend = '';
  if (mode === 'events' && platform === 'linux') {
    backend = 'at-spi';
    const a = await Atspi.open(bus);
    try {
      let allowBuses: Set<string> | undefined;
      if (o.pid || o.app) {
        const apps = await a.apps();
        allowBuses = new Set(apps.filter((x) => (!o.pid || x.pid === o.pid) && (!o.app || x.name.toLowerCase().includes(o.app.toLowerCase()))).map((x) => x.bus));
        if (!allowBuses.size) warnings.push('no accessible application matches the pid or app filter yet; events from apps that start later are kept when their pid matches');
      }
      const raw: { m: DMessage; t: number }[] = [];
      const stop = await a.listen((o.classes?.length ? o.classes : ['object:', 'window:', 'focus:']).slice(0, 16).map(String), (m) => { if (raw.length < maxEvents) raw.push({ m, t: Date.now() }); else truncated = true; });
      await runActions();
      const left = dur - (Date.now() - t0);
      if (left > 0) await sleep(left);
      await stop();
      const cache = new Map<string, { role: string; name: string }>(), pids = new Map<string, number | undefined>();
      for (const r of raw) {
        if (allowBuses && r.m.sender && !allowBuses.has(r.m.sender)) {
          if (!o.pid) continue;
          if (!pids.has(r.m.sender)) pids.set(r.m.sender, await a.client.pidOf(r.m.sender));
          if (pids.get(r.m.sender) !== o.pid) continue;
        }
        const e = await a.toEvent(r.m, t0, cache, pids); e.t = r.t - t0; events.push(e);
      }
    } finally { a.close(); }
  } else if (mode === 'events' && platform === 'win32') {
    backend = 'uia';
    const p = uiaTrace({ pid: o.pid, durationMs: dur, maxEvents });
    await sleep(800); // let the handlers attach before acting
    await runActions();
    const r = await p;
    events = r.events; truncated = r.truncated; warnings.push(...r.warnings);
  } else {
    backend = 'poll';
    const interval = Math.max(100, Math.min(Number(o.intervalMs ?? 500), 10_000));
    let prev = before ?? await grabTree({ busAddress: bus, pid: o.pid, app: o.app, maxNodes: o.maxNodes });
    const act = runActions();
    while (Date.now() - t0 < dur && events.length < maxEvents) {
      await sleep(interval);
      const cur = await grabTree({ busAddress: bus, pid: o.pid, app: o.app, maxNodes: o.maxNodes }).catch(() => undefined);
      if (!cur) continue;
      events.push(...diffToEvents(compareUiTrees(prev, cur), Date.now() - t0));
      prev = cur;
    }
    await act;
    if (events.length > maxEvents) { truncated = true; events = events.slice(0, maxEvents); }
  }
  const after = before ? await grabTree({ busAddress: bus, pid: o.pid, app: o.app, maxNodes: o.maxNodes }).catch((e) => { warnings.push(`tree after: ${(e as Error).message}`); return undefined; }) : undefined;
  const diff = before && after ? compareUiTrees(before, after, { limit: 500 }) : undefined;
  if (sess) await sess.audit.record({ action: 'ui_trace', args: { durationMs: dur, pid: o.pid ?? null, app: o.app ?? null, mode }, ok: true, result: { events: events.length, actions: actions.length } }).catch(() => undefined);
  return { platform, backend, mode, durationMs: Date.now() - t0, events, truncated, summary: summarizeEvents(events), actions, diff, warnings };
}

/** Turn a tree diff into synthetic events (poll mode). */
export function diffToEvents(d: UiTreeDiff, t: number): UiEvent[] {
  const out: UiEvent[] = [];
  for (const a of d.added) out.push({ t, type: 'object:children-changed:add', source: { role: a.role, name: a.name, ref: a.key } });
  for (const r of d.removed) out.push({ t, type: 'object:children-changed:remove', source: { role: r.role, name: r.name, ref: r.key } });
  for (const c of d.changed) for (const ch of c.changes) {
    if (ch.field === 'states') { for (const s of ch.after as string[]) out.push({ t, type: `object:state-changed:${s}`, source: { role: c.role, name: c.name, ref: c.key }, detail1: 1 }); for (const s of ch.before as string[]) out.push({ t, type: `object:state-changed:${s}`, source: { role: c.role, name: c.name, ref: c.key }, detail1: 0 }); }
    else if (ch.field === 'name') out.push({ t, type: 'object:property-change:accessible-name', source: { role: c.role, name: c.name, ref: c.key }, data: ch.after });
    else if (ch.field === 'value') out.push({ t, type: 'object:property-change:accessible-value', source: { role: c.role, name: c.name, ref: c.key }, data: ch.after });
    else if (ch.field === 'text') out.push({ t, type: 'object:text-changed:replace', source: { role: c.role, name: c.name, ref: c.key }, data: ch.after });
    else if (ch.field === 'bounds') out.push({ t, type: 'object:bounds-changed', source: { role: c.role, name: c.name, ref: c.key }, data: ch.after });
  }
  return out;
}

/** Windows: UIAutomation focus, structure and property events for a pid, collected by a PowerShell helper. */
async function uiaTrace(o: { pid?: number; durationMs: number; maxEvents: number }): Promise<{ events: UiEvent[]; truncated: boolean; warnings: string[] }> {
  const cs = `using System; using System.Collections.Generic; using System.Windows.Automation; using System.Diagnostics;
public class RevLensUiaTrace {
  public List<string> Lines = new List<string>(); Stopwatch sw = Stopwatch.StartNew(); int pid; int max;
  public RevLensUiaTrace(int pid, int max) { this.pid = pid; this.max = max; }
  static string Esc(string s) { if (s == null) return ""; var b = new System.Text.StringBuilder(); foreach (char c in s) { if (c == '"' || c == '\\\\') b.Append('\\\\').Append(c); else if (c < 32) b.Append(' '); else b.Append(c); } return b.ToString(); }
  void Add(string type, AutomationElement e, string data) {
    lock (Lines) { if (Lines.Count >= max) return; string role = "", name = ""; int p = 0;
      try { role = e.Current.ControlType.ProgrammaticName.Replace("ControlType.", ""); name = e.Current.Name; p = e.Current.ProcessId; } catch {}
      if (pid != 0 && p != pid) return;
      Lines.Add("{\\"t\\":" + sw.ElapsedMilliseconds + ",\\"type\\":\\"" + type + "\\",\\"role\\":\\"" + Esc(role) + "\\",\\"name\\":\\"" + Esc(name) + "\\",\\"pid\\":" + p + ",\\"data\\":\\"" + Esc(data) + "\\"}"); }
  }
  public void Start() {
    var root = AutomationElement.RootElement;
    Automation.AddAutomationFocusChangedEventHandler((s, a) => Add("focus:", s as AutomationElement, ""));
    Automation.AddStructureChangedEventHandler(root, TreeScope.Subtree, (s, a) => Add("object:children-changed:" + (a.StructureChangeType.ToString().StartsWith("ChildAdded") || a.StructureChangeType.ToString().StartsWith("ChildrenBulkAdded") ? "add" : a.StructureChangeType.ToString().StartsWith("ChildRemoved") || a.StructureChangeType.ToString().StartsWith("ChildrenBulkRemoved") ? "remove" : a.StructureChangeType.ToString().ToLower()), s as AutomationElement, ""));
    Automation.AddAutomationPropertyChangedEventHandler(root, TreeScope.Subtree, (s, a) => { string n = a.Property.ProgrammaticName; string t = n.Contains("Name") ? "object:property-change:accessible-name" : n.Contains("ToggleState") ? "object:state-changed:checked" : n.Contains("Value") ? "object:property-change:accessible-value" : n.Contains("HasKeyboardFocus") ? "object:state-changed:focused" : "object:property-change:" + n; Add(t, s as AutomationElement, a.NewValue == null ? "" : a.NewValue.ToString()); }, AutomationElement.NameProperty, ValuePattern.ValueProperty, TogglePattern.ToggleStateProperty, AutomationElement.HasKeyboardFocusProperty);
    Automation.AddAutomationEventHandler(InvokePattern.InvokedEvent, root, TreeScope.Subtree, (s, a) => Add("object:invoked", s as AutomationElement, ""));
    Automation.AddAutomationEventHandler(WindowPattern.WindowOpenedEvent, root, TreeScope.Subtree, (s, a) => Add("window:create", s as AutomationElement, ""));
  }
}`;
  const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes; Add-Type -ReferencedAssemblies UIAutomationClient, UIAutomationTypes, WindowsBase -TypeDefinition @'\n${cs}\n'@; $t = New-Object RevLensUiaTrace(${o.pid ?? 0}, ${o.maxEvents}); $t.Start(); Start-Sleep -Milliseconds ${o.durationMs}; [System.Windows.Automation.Automation]::RemoveAllEventHandlers(); '[' + ($t.Lines -join ',') + ']'`;
  const r = await powershell(script, o.durationMs + 60_000);
  if (r.code !== 0) throw new InputError(`UIAutomation trace failed: ${r.stderr.trim().slice(0, 300)}`);
  let arr: { t: number; type: string; role: string; name: string; pid: number; data: string }[] = [];
  try { arr = JSON.parse(r.stdout.trim().replace(/^\uFEFF/, '') || '[]'); } catch { return { events: [], truncated: false, warnings: ['UIAutomation trace output was not JSON'] }; }
  return { events: arr.map((e) => ({ t: e.t, type: e.type, source: { role: e.role, name: e.name, pid: e.pid }, data: e.data || undefined })), truncated: arr.length >= o.maxEvents, warnings: [] };
}

// ---------------- scenario ----------------

export interface ScenarioStep {
  /** optional label used in folder names and reports */
  label?: string;
  find?: UiSelector;
  click?: UiSelector; method?: 'action' | 'pointer' | 'auto'; action?: string;
  type?: string; into?: UiSelector; secret?: boolean;
  key?: string;
  wait?: number;
  waitFor?: UiSelector; gone?: boolean; timeoutMs?: number;
  assert?: UiSelector; exists?: boolean; count?: number; name?: string; states?: string[]; notStates?: string[]; text?: string; textContains?: string; value?: string;
  screenshot?: boolean | string;
  computer?: ComputerAction;
}

export interface StepResult {
  index: number; kind: string; label?: string; ok: boolean; error?: string; ms: number;
  element?: { role: string; name: string; ref?: string; bounds?: UiNode['bounds']; states?: string[]; text?: string };
  how?: string; dir?: string; tree?: string; treeSha256?: string; screenshot?: string; screenshotSha256?: string;
  changes?: { added: number; removed: number; changed: number; sample: { role: string; name: string; changes: { field: string; before: unknown; after: unknown }[] }[] };
}

export interface ScenarioOptions {
  allowExecution?: boolean; session?: string; busAddress?: string; pid?: number; app?: string;
  steps: ScenarioStep[]; stopOnFailure?: boolean; outDir?: string; maxNodes?: number;
  /** capture tree and screenshot after each step (default true) */
  capture?: boolean;
}

function stepKind(s: ScenarioStep): string {
  const kinds = (['find', 'click', 'type', 'key', 'wait', 'waitFor', 'assert', 'screenshot', 'computer'] as const).filter((k) => s[k] !== undefined && !(k === 'type' && s.click));
  if (kinds.length !== 1) throw new InputError(`each step needs exactly one of find, click, type, key, wait, waitFor, assert, screenshot or computer (got ${kinds.join(', ') || 'none'})`);
  return kinds[0]!;
}

const center = (b: NonNullable<UiNode['bounds']>) => ({ x: b.x + Math.floor(b.width / 2), y: b.y + Math.floor(b.height / 2) });
const nodeText = (n: UiNode) => (n as UiNode & { text?: string }).text;

/** Run a scripted scenario against a live app and capture evidence for each step. */
export async function runUiScenario(o: ScenarioOptions): Promise<{ ok: boolean; passed: number; failed: number; skipped: number; outDir: string; report: string; steps: StepResult[] }> {
  requireExecution(o.allowExecution, 'running a UI scenario');
  if (!Array.isArray(o.steps) || !o.steps.length || o.steps.length > 500) throw new InputError('steps must be a list of 1 to 500 steps');
  const kinds = o.steps.map(stepKind);
  const sess = o.session ? sessionHandle(o.session) : undefined;
  const bus = o.busAddress ?? sess?.a11yAddress;
  const driver: Driver | undefined = sess?.driver;
  const linux = process.platform === 'linux';
  const outDir = o.outDir ?? (sess ? join(sess.workDir, `scenario-${Date.now()}`) : await mkdtemp(join(tmpdir(), 'revlens-scenario-')));
  await mkdir(outDir, { recursive: true });
  const capture = o.capture !== false;
  const atspi = linux ? await Atspi.open(bus) : undefined;
  const results: StepResult[] = [];
  let prev: Tree | undefined;
  const tree = () => grabTree({ busAddress: bus, pid: o.pid, app: o.app, maxNodes: o.maxNodes, details: true });
  const need = async (sel: UiSelector) => { const t = await tree(); const n = findNode(t.nodes, sel); if (!n) throw new InputError(`no element matches ${describeSelector(sel)}`); return { n, t }; };
  try {
    let failed = false;
    for (let i = 0; i < o.steps.length; i++) {
      const s = o.steps[i]!, kind = kinds[i]!;
      const r: StepResult = { index: i, kind, label: s.label, ok: true, ms: 0 };
      if (failed && o.stopOnFailure !== false) { r.ok = false; r.error = 'skipped after an earlier failure'; results.push(r); continue; }
      const t0 = Date.now();
      try {
        const el = (n: UiNode) => { r.element = { role: n.role, name: n.name, ref: n.ref, bounds: n.bounds, states: n.states, text: nodeText(n)?.slice(0, 500) }; };
        switch (kind) {
          case 'find': { const { n } = await need(checkSelector(s.find)); el(n); break; }
          case 'click': {
            const sel = checkSelector(s.click);
            const { n } = await need(sel); el(n);
            const method = s.method ?? 'auto';
            if ((method === 'action' || method === 'auto') && atspi && n.ref) {
              try { r.how = `accessibility action ${await atspi.doAction(parseRef(n.ref), s.action)}`; break; }
              catch (e) { if (method === 'action') throw e; }
            }
            if (!driver) throw new InputError('pointer clicks need a computer session (session)');
            if (!n.bounds || n.bounds.width <= 0 || n.bounds.height <= 0) throw new InputError('element has no screen bounds to click');
            const c = center(n.bounds); await driver.click({ x: c.x, y: c.y, button: 'left', count: 1 }); r.how = `pointer click at ${c.x},${c.y}`;
            break;
          }
          case 'type': {
            const text = String(s.type);
            if (text.length > 100_000) throw new InputError('text too long');
            if (s.into) {
              const { n } = await need(checkSelector(s.into)); el(n);
              if (atspi && n.ref && (s.method ?? 'auto') !== 'pointer') {
                const ref = parseRef(n.ref);
                const ok = await atspi.setText(ref, text).catch(() => false);
                if (ok) { r.how = 'EditableText.SetTextContents'; break; }
                await atspi.grabFocus(ref).catch(() => false);
              } else if (driver && n.bounds) { const c = center(n.bounds); await driver.click({ x: c.x, y: c.y, button: 'left', count: 1 }); }
            }
            if (!driver) throw new InputError('typing with keys needs a computer session (session)');
            await driver.type(text, 12); r.how = r.how ? `${r.how}, then keys` : 'keys';
            break;
          }
          case 'key': { if (!driver) throw new InputError('key presses need a computer session (session)'); const c = parseKeyCombo(String(s.key)); await driver.key(c); r.how = [...c.mods, c.key].join('+'); break; }
          case 'wait': { await sleep(Math.max(0, Math.min(Number(s.wait), 60_000))); break; }
          case 'waitFor': {
            const sel = checkSelector(s.waitFor);
            const end = Date.now() + Math.max(0, Math.min(Number(s.timeoutMs ?? 10_000), 120_000));
            for (;;) {
              const t = await tree().catch(() => undefined);
              const n = t && findNode(t.nodes, sel);
              if (s.gone ? t && !n : n) { if (n) el(n); break; }
              if (Date.now() >= end) throw new InputError(`timed out waiting for ${s.gone ? 'the end of ' : ''}${describeSelector(sel)}`);
              await sleep(250);
            }
            break;
          }
          case 'assert': {
            const sel = checkSelector(s.assert);
            const t = await tree();
            const all = findNodes(t.nodes, sel);
            const n = all[sel.index ?? 0];
            if (s.count !== undefined && all.length !== s.count) throw new InputError(`expected ${s.count} elements matching ${describeSelector(sel)}, found ${all.length}`);
            if (s.exists === false) { if (n) throw new InputError(`expected no element matching ${describeSelector(sel)}, found ${n.role} "${n.name}"`); break; }
            if (!n) throw new InputError(`no element matches ${describeSelector(sel)}`);
            el(n);
            if (s.name !== undefined && n.name !== s.name) throw new InputError(`name is "${n.name}", expected "${s.name}"`);
            const st = new Set(n.states ?? []);
            for (const x of s.states ?? []) if (!st.has(x)) throw new InputError(`state ${x} missing (has ${[...st].join(', ') || 'none'})`);
            for (const x of s.notStates ?? []) if (st.has(x)) throw new InputError(`state ${x} present`);
            let txt = nodeText(n);
            if ((s.text !== undefined || s.textContains !== undefined) && txt === undefined && atspi && n.ref) txt = await atspi.getText(parseRef(n.ref)).catch(() => undefined);
            if (txt === undefined && n.value !== undefined) txt = n.value;
            if (s.text !== undefined && txt !== s.text) throw new InputError(`text is ${JSON.stringify(txt)}, expected ${JSON.stringify(s.text)}`);
            if (s.textContains !== undefined && !(txt ?? '').includes(s.textContains)) throw new InputError(`text ${JSON.stringify(txt)} does not contain ${JSON.stringify(s.textContains)}`);
            if (s.value !== undefined && n.value !== s.value) throw new InputError(`value is ${JSON.stringify(n.value)}, expected ${JSON.stringify(s.value)}`);
            break;
          }
          case 'screenshot': break;
          case 'computer': { if (!o.session) throw new InputError('computer steps need a session'); await actOnComputer(o.session, s.computer!); r.how = s.computer!.action; break; }
        }
      } catch (e) { r.ok = false; r.error = (e as Error).message.slice(0, 500); failed = true; }
      r.ms = Date.now() - t0;
      if (capture || kind === 'screenshot') {
        const dir = join(outDir, `step-${String(i + 1).padStart(3, '0')}-${(s.label ?? kind).replace(/[^\w.-]+/g, '_').slice(0, 40)}`);
        await mkdir(dir, { recursive: true });
        r.dir = dir;
        if (capture) {
          if (kind !== 'wait' && kind !== 'screenshot') await sleep(150); // let the app react
          const t = await tree().catch(() => undefined);
          if (t) {
            const json = JSON.stringify(t, null, 1); r.tree = join(dir, 'ui-tree.json'); r.treeSha256 = sha256Hex(json); await writeFile(r.tree, json);
            if (prev) { const d = compareUiTrees(prev, t, { limit: 50 }); r.changes = { added: d.added.length, removed: d.removed.length, changed: d.changed.length, sample: d.changed.slice(0, 10).map((c) => ({ role: c.role, name: c.name, changes: c.changes })) }; }
            prev = t;
          }
        }
        if (driver) { try { const sh = await driver.screenshot(); r.screenshot = join(dir, 'screenshot.png'); r.screenshotSha256 = sha256Hex(sh.png); await writeFile(r.screenshot, sh.png); } catch { /* no screenshot */ } }
      }
      results.push(r);
      if (sess) await sess.audit.record({ action: `scenario:${kind}`, args: { step: i, label: s.label ?? null, selector: s.find ?? s.click ?? s.assert ?? s.waitFor ?? s.into ?? null, text: s.type !== undefined ? (s.secret ? { length: String(s.type).length } : String(s.type).slice(0, 200)) : null, key: s.key ?? null }, ok: r.ok, error: r.error, ms: r.ms, result: { how: r.how ?? null, element: r.element ? `${normalizeRole(r.element.role)} ${r.element.name}` : null, screenshot: r.screenshotSha256 ?? null, tree: r.treeSha256 ?? null } }).catch(() => undefined);
    }
  } finally { atspi?.close(); }
  const passed = results.filter((r) => r.ok).length, skipped = results.filter((r) => r.error === 'skipped after an earlier failure').length;
  const out = { ok: passed === results.length, passed, failed: results.length - passed - skipped, skipped, outDir, report: join(outDir, 'scenario.json'), steps: results };
  await writeFile(out.report, JSON.stringify({ kind: 'revlens-ui-scenario', version: 1, ranAt: new Date().toISOString(), steps: o.steps.map((s) => (s.secret && s.type ? { ...s, type: `[${s.type.length} chars]` } : s)), results: out }, null, 1));
  return out;
}


