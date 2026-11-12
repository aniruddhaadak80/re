// Native UI model helpers shared by the AT-SPI, macOS AX and Windows UIA backends: state names,
// role normalisation, element selectors, tree comparison and trace event normalisation.
// No Node imports, so it runs in a browser worker on saved trees.
import type { UiNode } from './gvariant.js';
import { InputError } from './proc.js';

/** AT-SPI state names by bit index (AtspiStateType in at-spi2-core). */
export const ATSPI_STATES = ['invalid', 'active', 'armed', 'busy', 'checked', 'collapsed', 'defunct', 'editable', 'enabled', 'expandable', 'expanded', 'focusable', 'focused', 'has-tooltip', 'horizontal', 'iconified', 'modal', 'multi-line', 'multiselectable', 'opaque', 'pressed', 'resizable', 'selectable', 'selected', 'sensitive', 'showing', 'single-line', 'stale', 'transient', 'vertical', 'visible', 'manages-descendants', 'indeterminate', 'required', 'truncated', 'animated', 'invalid-entry', 'supports-autocompletion', 'selectable-text', 'is-default', 'visited', 'checkable', 'has-popup', 'read-only'];

/** Decode the two 32-bit words AT-SPI GetState returns into state names. */
export function decodeAtspiStates(words: unknown): string[] {
  if (!Array.isArray(words)) return [];
  const out: string[] = [];
  for (let w = 0; w < Math.min(words.length, 2); w++) {
    const v = Number(words[w]) >>> 0;
    for (let b = 0; b < 32; b++) if (v & (1 << b)) { const name = ATSPI_STATES[w * 32 + b]; if (name) out.push(name); }
  }
  return out;
}

const ROLE_ALIAS: Record<string, string> = {
  pushbutton: 'button', togglebutton: 'button', button: 'button',
  edit: 'entry', textfield: 'entry', entry: 'entry', passwordtext: 'entry', searchfield: 'entry', textarea: 'entry',
  checkbox: 'checkbox', checkmenuitem: 'checkbox',
  radiobutton: 'radiobutton', combobox: 'combobox', popupbutton: 'combobox',
  statictext: 'label', label: 'label',
  window: 'window', frame: 'window', dialog: 'dialog',
  menuitem: 'menuitem', menu: 'menu', menubar: 'menubar', list: 'list', listitem: 'listitem', table: 'table', heading: 'heading', link: 'link',
  documentweb: 'document', document: 'document', webarea: 'document', application: 'application', slider: 'slider', tab: 'tab', pagetab: 'tab', tablist: 'tablist', pagetablist: 'tablist',
};

/** Fold platform role spellings ("push button", "AXButton", "ControlType.Button") into one word. */
export function normalizeRole(role: string): string {
  const r = String(role ?? '').toLowerCase().replace(/^controltype\./, '').replace(/^ax/, '').replace(/[\s_-]+/g, '');
  return ROLE_ALIAS[r] ?? r;
}

/** Element selector. Matching is exact, prefix or substring; no regular expressions, so a hostile name cannot stall it. */
export interface UiSelector {
  role?: string; name?: string; nameContains?: string; namePrefix?: string; automationId?: string; description?: string;
  /** every listed state must be present (AT-SPI names, or UIA/AX equivalents mapped by the backend) */
  states?: string[];
  /** every listed state must be absent */
  notStates?: string[];
  /** pick the nth match (0 based) */
  index?: number;
  /** match only inside the first element this selector finds */
  within?: UiSelector;
}

export function checkSelector(s: unknown, depth = 0): UiSelector {
  if (depth > 4) throw new InputError('selector nested too deep');
  if (!s || typeof s !== 'object' || Array.isArray(s)) throw new InputError('selector must be an object');
  const o = s as Record<string, unknown>;
  const out: UiSelector = {};
  for (const k of ['role', 'name', 'nameContains', 'namePrefix', 'automationId', 'description'] as const) if (o[k] !== undefined) { if (typeof o[k] !== 'string' || (o[k] as string).length > 1000) throw new InputError(`selector ${k} must be a short string`); out[k] = o[k] as string; }
  for (const k of ['states', 'notStates'] as const) if (o[k] !== undefined) { if (!Array.isArray(o[k]) || (o[k] as unknown[]).length > 32) throw new InputError(`selector ${k} must be a list`); out[k] = (o[k] as unknown[]).map(String); }
  if (o.index !== undefined) { const n = Number(o.index); if (!Number.isInteger(n) || n < 0 || n > 100_000) throw new InputError('selector index must be a small integer'); out.index = n; }
  if (o.within !== undefined) out.within = checkSelector(o.within, depth + 1);
  if (!Object.keys(out).some((k) => k !== 'index' && k !== 'within')) throw new InputError('selector needs at least one of role, name, nameContains, namePrefix, automationId, description or states');
  return out;
}

function nodeMatches(n: UiNode, s: UiSelector): boolean {
  if (s.role !== undefined && normalizeRole(n.role) !== normalizeRole(s.role)) return false;
  if (s.name !== undefined && n.name !== s.name) return false;
  if (s.nameContains !== undefined && !n.name.toLowerCase().includes(s.nameContains.toLowerCase())) return false;
  if (s.namePrefix !== undefined && !n.name.startsWith(s.namePrefix)) return false;
  if (s.automationId !== undefined && n.automationId !== s.automationId) return false;
  if (s.description !== undefined && n.description !== s.description) return false;
  const st = new Set(n.states ?? []);
  if (s.states && !s.states.every((x) => st.has(x))) return false;
  if (s.notStates && s.notStates.some((x) => st.has(x))) return false;
  return true;
}

function isInside(nodes: UiNode[], id: number, ancestor: number): boolean {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  let cur = byId.get(id);
  for (let i = 0; cur && i < 10_000; i++) { if (cur.parent === ancestor) return true; cur = cur.parent === null ? undefined : byId.get(cur.parent); }
  return false;
}

/** All nodes a selector matches, in tree order (index is applied by findNode). */
export function findNodes(nodes: UiNode[], sel: UiSelector): UiNode[] {
  let pool = nodes;
  if (sel.within) {
    const scope = findNode(nodes, sel.within);
    if (!scope) return [];
    pool = nodes.filter((n) => isInside(nodes, n.id, scope.id));
  }
  return pool.filter((n) => nodeMatches(n, sel));
}

export function findNode(nodes: UiNode[], sel: UiSelector): UiNode | undefined {
  return findNodes(nodes, sel)[sel.index ?? 0];
}

export const describeSelector = (s: UiSelector): string => [s.role && `role=${s.role}`, s.name !== undefined && `name="${s.name}"`, s.nameContains && `name~"${s.nameContains}"`, s.namePrefix && `name^="${s.namePrefix}"`, s.automationId && `id=${s.automationId}`, s.states?.length && `states=${s.states.join('+')}`, s.index !== undefined && `#${s.index}`].filter(Boolean).join(' ');

// ---------------- tree comparison ----------------

export interface UiTreeLike { nodes: UiNode[]; backend?: string; app?: string; pid?: number }
export interface UiChange { key: string; role: string; name: string; changes: { field: string; before: unknown; after: unknown }[] }
export interface UiTreeDiff {
  nodesBefore: number; nodesAfter: number;
  added: { key: string; role: string; name: string }[];
  removed: { key: string; role: string; name: string }[];
  changed: UiChange[];
  same: number;
  similarity: number;
  truncated: boolean;
}

/** Stable keys: the path of role:name steps from the root, with a sibling counter for repeats. */
export function nodeKeys(nodes: UiNode[]): Map<number, string> {
  const keys = new Map<number, string>();
  const counters = new Map<string, number>();
  const sorted = [...nodes].sort((a, b) => a.depth - b.depth || a.id - b.id);
  for (const n of sorted) {
    const parentKey = n.parent === null ? '' : keys.get(n.parent) ?? `?${n.parent}`;
    const step = `${normalizeRole(n.role)}:${n.name.slice(0, 80).replace(/\//g, '%2F')}`;
    const ck = `${parentKey}/${step}`;
    const i = counters.get(ck) ?? 0; counters.set(ck, i + 1);
    keys.set(n.id, i ? `${ck}[${i}]` : ck);
  }
  return keys;
}

const FIELDS = ['name', 'description', 'value', 'text', 'states', 'bounds', 'actions', 'childCount'] as const;
const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/** Compare two UI trees from desktop_ui_tree (any backend): elements added, removed and changed. */
export function compareUiTrees(a: UiTreeLike, b: UiTreeLike, opts: { limit?: number; ignore?: string[] } = {}): UiTreeDiff {
  if (!a || !Array.isArray(a.nodes) || !b || !Array.isArray(b.nodes)) throw new InputError('both inputs must be UI trees with a nodes list');
  if (a.nodes.length > 200_000 || b.nodes.length > 200_000) throw new InputError('UI tree too large');
  const lim = Math.max(1, Math.min(opts.limit ?? 2000, 100_000));
  const ignore = new Set(opts.ignore ?? []);
  const ka = nodeKeys(a.nodes), kb = nodeKeys(b.nodes);
  const ma = new Map<string, UiNode>(), mb = new Map<string, UiNode>();
  for (const n of a.nodes) ma.set(ka.get(n.id)!, n);
  for (const n of b.nodes) mb.set(kb.get(n.id)!, n);
  const out: UiTreeDiff = { nodesBefore: a.nodes.length, nodesAfter: b.nodes.length, added: [], removed: [], changed: [], same: 0, similarity: 1, truncated: false };
  for (const [k, n] of ma) if (!mb.has(k)) out.removed.push({ key: k, role: n.role, name: n.name });
  for (const [k, n] of mb) if (!ma.has(k)) out.added.push({ key: k, role: n.role, name: n.name });
  for (const [k, n] of ma) {
    const m = mb.get(k);
    if (!m) continue;
    const changes: UiChange['changes'] = [];
    for (const f of FIELDS) {
      if (ignore.has(f)) continue;
      const x = f === 'states' ? [...(n.states ?? [])].sort() : (n as unknown as Record<string, unknown>)[f];
      const y = f === 'states' ? [...(m.states ?? [])].sort() : (m as unknown as Record<string, unknown>)[f];
      if (!same(x, y)) {
        if (f === 'states') changes.push({ field: 'states', before: (x as string[]).filter((s) => !(y as string[]).includes(s)), after: (y as string[]).filter((s) => !(x as string[]).includes(s)) });
        else changes.push({ field: f, before: x, after: y });
      }
    }
    if (changes.length) out.changed.push({ key: k, role: m.role, name: m.name, changes }); else out.same++;
  }
  const total = new Set([...ma.keys(), ...mb.keys()]).size;
  out.similarity = total ? Math.round((out.same / total) * 1000) / 1000 : 1;
  out.truncated = out.added.length > lim || out.removed.length > lim || out.changed.length > lim;
  out.added = out.added.slice(0, lim); out.removed = out.removed.slice(0, lim); out.changed = out.changed.slice(0, lim);
  return out;
}

// ---------------- trace events ----------------

export interface UiEvent {
  /** milliseconds since the trace started */
  t: number;
  /** AT-SPI style name such as object:state-changed:focused, window:activate, focus:; UIA and AX names are mapped onto the same scheme where they match */
  type: string;
  source: { ref?: string; role?: string; name?: string; pid?: number };
  detail1?: number; detail2?: number; data?: unknown;
  raw?: string;
}

/** AT-SPI signal (interface org.a11y.atspi.Event.Object, member StateChanged, detail focused) to event type object:state-changed:focused. */
export function atspiEventType(iface: string | undefined, member: string | undefined, detail: unknown): string {
  const cat = String(iface ?? '').replace(/^org\.a11y\.atspi\.Event\./, '').toLowerCase();
  const kebab = String(member ?? '').replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
  const d = typeof detail === 'string' && detail ? `:${detail}` : '';
  return `${cat}:${kebab}${d}`;
}

/** Summarise a list of events: counts by type and the elements that changed state. */
export function summarizeEvents(events: UiEvent[]): { total: number; byType: Record<string, number>; stateChanges: { name?: string; role?: string; state: string; on: boolean }[]; textChanges: { name?: string; op: string; text: string }[] } {
  const byType: Record<string, number> = {};
  const stateChanges: { name?: string; role?: string; state: string; on: boolean }[] = [];
  const textChanges: { name?: string; op: string; text: string }[] = [];
  for (const e of events) {
    byType[e.type] = (byType[e.type] ?? 0) + 1;
    if (e.type.startsWith('object:state-changed:') && stateChanges.length < 500) stateChanges.push({ name: e.source.name, role: e.source.role, state: e.type.slice(21), on: e.detail1 === 1 });
    if (e.type.startsWith('object:text-changed:') && textChanges.length < 500) textChanges.push({ name: e.source.name, op: e.type.slice(20), text: String(e.data ?? '') });
  }
  return { total: events.length, byType, stateChanges, textChanges };
}
