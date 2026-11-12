// AT-SPI 2 over RevLens's own D-Bus client: tree walks, element details, actions, text entry and
// event subscriptions on the accessibility bus. One socket for the whole walk.
import { DBusClient } from './dbus.js';
import { run } from './exec.js';
import { InputError } from './proc.js';
import type { UiNode } from './gvariant.js';
import type { DMessage, DValue } from './dbuswire.js';
import { decodeAtspiStates, atspiEventType, type UiEvent } from './uimodel.js';

export interface Ref { bus: string; path: string }
const REGISTRY = 'org.a11y.atspi.Registry';
const ROOT = '/org/a11y/atspi/accessible/root';
const I = (s: string) => `org.a11y.atspi.${s}`;
export const refString = (r: Ref) => `${r.bus}${r.path}`;
export function parseRef(s: string): Ref {
  const i = String(s).indexOf('/');
  if (i <= 0 || s.length > 1000) throw new InputError(`bad element ref ${String(s).slice(0, 80)}`);
  return { bus: s.slice(0, i), path: s.slice(i) };
}
const refs = (v: DValue | undefined): Ref[] => (Array.isArray(v) ? v.filter((x): x is DValue[] => Array.isArray(x) && x.length === 2).map((x) => ({ bus: String(x[0]), path: String(x[1]) })) : []);

/** Find the accessibility bus address: explicit, AT_SPI_BUS_ADDRESS, org.a11y.Bus on the session bus, or the AT_SPI_BUS property on the X root window. */
export async function resolveA11yAddress(explicit?: string, env: NodeJS.ProcessEnv = process.env): Promise<string> {
  const ok = (a: string) => /^unix:[\w=,./%;:-]+$/i.test(a);
  if (explicit) { if (!ok(explicit)) throw new InputError('bad AT-SPI bus address'); return explicit; }
  if (env.AT_SPI_BUS_ADDRESS && ok(env.AT_SPI_BUS_ADDRESS)) return env.AT_SPI_BUS_ADDRESS;
  if (env.DBUS_SESSION_BUS_ADDRESS) {
    try {
      const c = await DBusClient.connect(env.DBUS_SESSION_BUS_ADDRESS, 3000);
      try { const r = await c.call({ destination: 'org.a11y.Bus', path: '/org/a11y/bus', interface: 'org.a11y.Bus', member: 'GetAddress' }, 5000); if (ok(String(r[0]))) return String(r[0]); } finally { c.close(); }
    } catch { /* try X next */ }
  }
  if (env.DISPLAY) {
    const r = await run('xprop', ['-root', 'AT_SPI_BUS'], { timeoutMs: 3000, env }).catch(() => undefined);
    const m = r && /=\s*"([^"]+)"/.exec(r.stdout);
    if (m && ok(m[1]!)) return m[1]!;
  }
  throw new InputError('no accessibility bus found: set AT_SPI_BUS_ADDRESS, or start at-spi-bus-launcher on the session bus');
}

export interface NodeDetails { role: string; name: string; description?: string; childCount: number; states: string[]; interfaces: string[]; bounds?: UiNode['bounds']; actions?: string[]; text?: string; value?: number }

export class Atspi {
  private constructor(public client: DBusClient, public address: string) {}
  static async open(address?: string, env?: NodeJS.ProcessEnv): Promise<Atspi> {
    const a = await resolveA11yAddress(address, env);
    return new Atspi(await DBusClient.connect(a), a);
  }
  close() { this.client.close(); }

  private call(r: Ref, iface: string, member: string, signature?: string, body?: DValue[], timeoutMs = 3000) {
    return this.client.call({ destination: r.bus, path: r.path, interface: I(iface), member, signature, body }, timeoutMs);
  }

  async apps(): Promise<(Ref & { name: string; pid?: number })[]> {
    const kids = refs((await this.client.call({ destination: REGISTRY, path: ROOT, interface: I('Accessible'), member: 'GetChildren' }, 5000))[0]);
    return Promise.all(kids.slice(0, 1000).map(async (k) => ({ ...k, name: String(await this.client.getProperty(k.bus, k.path, I('Accessible'), 'Name').catch(() => '')), pid: await this.client.pidOf(k.bus) })));
  }

  children(r: Ref) { return this.call(r, 'Accessible', 'GetChildren').then((v) => refs(v[0])); }

  /** Read one element. details adds states, interfaces, actions, text and value. */
  async details(r: Ref, opts: { text?: boolean } = {}): Promise<NodeDetails> {
    const [role, props, state, ifaces] = await Promise.all([
      this.call(r, 'Accessible', 'GetRoleName').then((v) => String(v[0] ?? '')).catch(() => ''),
      this.client.call({ destination: r.bus, path: r.path, interface: 'org.freedesktop.DBus.Properties', member: 'GetAll', signature: 's', body: [I('Accessible')] }, 3000).then((v) => (v[0] && typeof v[0] === 'object' ? v[0] : {}) as Record<string, DValue>).catch(() => ({} as Record<string, DValue>)),
      this.call(r, 'Accessible', 'GetState').then((v) => decodeAtspiStates(v[0])).catch(() => [] as string[]),
      this.call(r, 'Accessible', 'GetInterfaces').then((v) => (Array.isArray(v[0]) ? (v[0] as DValue[]).map((x) => String(x).replace(/^org\.a11y\.atspi\./, '')) : [])).catch(() => [] as string[]),
    ]);
    const d: NodeDetails = { role, name: String(props.Name ?? ''), description: props.Description ? String(props.Description) : undefined, childCount: Number(props.ChildCount ?? 0), states: state, interfaces: ifaces };
    const extra: Promise<void>[] = [];
    const has = (x: string) => !ifaces.length || ifaces.includes(x); // an empty list means the query failed: try them all
    const extents = () => this.call(r, 'Component', 'GetExtents', 'u', [0]).then((v) => { const e = v[0]; if (Array.isArray(e) && e.length === 4) d.bounds = { x: Number(e[0]), y: Number(e[1]), width: Number(e[2]), height: Number(e[3]) }; });
    if (has('Component')) extra.push(extents().catch(() => extents()).catch(() => undefined)); // one retry: busy apps time out under load
    if (has('Action')) extra.push(this.call(r, 'Action', 'GetActions').then((v) => { if (Array.isArray(v[0])) d.actions = (v[0] as DValue[]).slice(0, 32).map((a) => String(Array.isArray(a) ? a[0] : a)); }).catch(() => undefined));
    if (opts.text !== false && has('Text')) extra.push(this.call(r, 'Text', 'GetText', 'ii', [0, -1]).then((v) => { d.text = String(v[0] ?? '').slice(0, 4000); }).catch(() => undefined));
    if (has('Value')) extra.push(this.client.getProperty(r.bus, r.path, I('Value'), 'CurrentValue').then((v) => { if (typeof v === 'number') d.value = v; }).catch(() => undefined));
    await Promise.all(extra);
    return d;
  }

  /** Breadth-first walk of the matching applications. */
  async tree(o: { app?: string; pid?: number; maxNodes: number; maxDepth: number; details?: boolean }): Promise<{ nodes: UiNode[]; truncated: boolean; apps: number }> {
    const apps = await this.apps();
    const queue: (Ref & { parent: number | null; depth: number })[] = [];
    for (const a of apps) {
      if (o.app && !a.name.toLowerCase().includes(o.app.toLowerCase())) continue;
      if (o.pid && a.pid !== o.pid) continue;
      queue.push({ bus: a.bus, path: a.path, parent: null, depth: 0 });
    }
    const nodes: UiNode[] = [];
    const seen = new Set<string>();
    while (queue.length && nodes.length < o.maxNodes) {
      const batch = queue.splice(0, Math.min(o.details ? 12 : 32, o.maxNodes - nodes.length));
      const res = await Promise.all(batch.map(async (cur) => {
        const [d, kids] = await Promise.all([
          o.details ? this.details(cur) : this.basic(cur),
          cur.depth < o.maxDepth ? this.children(cur).catch(() => [] as Ref[]) : Promise.resolve([] as Ref[]),
        ]);
        return { cur, d, kids };
      }));
      for (const { cur, d, kids } of res) {
        const id = nodes.length;
        const n: UiNode = { id, parent: cur.parent, depth: cur.depth, role: d.role, name: d.name, description: d.description, ref: refString(cur), childCount: d.childCount || kids.length };
        if (d.bounds) n.bounds = d.bounds;
        if (d.states.length) n.states = d.states;
        if (d.actions?.length) (n as UiNode & { actions?: string[] }).actions = d.actions;
        if (d.text !== undefined) (n as UiNode & { text?: string }).text = d.text;
        if (d.value !== undefined) n.value = String(d.value);
        nodes.push(n);
        for (const k of kids) { const key = refString(k); if (!seen.has(key)) { seen.add(key); queue.push({ ...k, parent: id, depth: cur.depth + 1 }); } }
      }
    }
    return { nodes, truncated: queue.length > 0, apps: apps.length };
  }

  private async basic(r: Ref): Promise<NodeDetails> {
    const [role, props, ext, state] = await Promise.all([
      this.call(r, 'Accessible', 'GetRoleName').then((v) => String(v[0] ?? '')).catch(() => ''),
      this.client.call({ destination: r.bus, path: r.path, interface: 'org.freedesktop.DBus.Properties', member: 'GetAll', signature: 's', body: [I('Accessible')] }, 3000).then((v) => (v[0] && typeof v[0] === 'object' ? v[0] : {}) as Record<string, DValue>).catch(() => ({} as Record<string, DValue>)),
      this.call(r, 'Component', 'GetExtents', 'u', [0]).then((v) => v[0]).catch(() => undefined),
      this.call(r, 'Accessible', 'GetState').then((v) => decodeAtspiStates(v[0])).catch(() => [] as string[]),
    ]);
    const d: NodeDetails = { role, name: String(props.Name ?? ''), description: props.Description ? String(props.Description) : undefined, childCount: Number(props.ChildCount ?? 0), states: state, interfaces: [] };
    if (Array.isArray(ext) && ext.length === 4) d.bounds = { x: Number(ext[0]), y: Number(ext[1]), width: Number(ext[2]), height: Number(ext[3]) };
    return d;
  }

  /** Run an accessibility action by name ("click", "press", "activate"...) or index. Returns the action that ran. */
  async doAction(r: Ref, action?: string | number): Promise<string> {
    const list = (await this.call(r, 'Action', 'GetActions').catch(() => [[]]))[0];
    const names = Array.isArray(list) ? (list as DValue[]).map((a) => String(Array.isArray(a) ? a[0] : a)) : [];
    if (!names.length) throw new InputError('element has no accessibility actions');
    let idx = 0;
    if (typeof action === 'number') idx = action;
    else if (typeof action === 'string') idx = names.indexOf(action);
    else { const pref = ['click', 'press', 'activate', 'jump', 'toggle', 'open']; idx = Math.max(0, names.findIndex((n) => pref.includes(n.toLowerCase()))); }
    if (idx < 0 || idx >= names.length) throw new InputError(`no action ${String(action)}; element has ${names.join(', ')}`);
    const ok = await this.call(r, 'Action', 'DoAction', 'i', [idx], 5000);
    if (ok[0] === false) throw new InputError(`action ${names[idx]} reported failure`);
    return names[idx]!;
  }

  async setText(r: Ref, text: string): Promise<boolean> {
    const v = await this.call(r, 'EditableText', 'SetTextContents', 's', [text], 5000);
    return v[0] !== false;
  }

  async getText(r: Ref): Promise<string> { return String((await this.call(r, 'Text', 'GetText', 'ii', [0, -1]))[0] ?? ''); }

  async grabFocus(r: Ref): Promise<boolean> { return (await this.call(r, 'Component', 'GrabFocus'))[0] !== false; }

  /** Ask the registry to forward these event classes (object:, window:, focus:) and listen to them. Returns a stop function. */
  async listen(classes: string[], onEvent: (raw: DMessage) => void): Promise<() => Promise<void>> {
    const reg = { destination: REGISTRY, path: '/org/a11y/atspi/registry', interface: I('Registry') };
    const done: string[] = [];
    for (const c of classes) {
      try { await this.client.call({ ...reg, member: 'RegisterEvent', signature: 'sass', body: [c, [], ''] }); }
      catch { await this.client.call({ ...reg, member: 'RegisterEvent', signature: 's', body: [c] }); }
      done.push(c);
      const cat = c.replace(/:.*$/, '');
      await this.client.addMatch(`type='signal',interface='org.a11y.atspi.Event.${cat.charAt(0).toUpperCase()}${cat.slice(1)}'`);
    }
    const off = this.client.onMessage((m) => { if (m.type === 4 && m.interface?.startsWith('org.a11y.atspi.Event.')) onEvent(m); });
    return async () => {
      off();
      for (const c of done) await this.client.call({ ...reg, member: 'DeregisterEvent', signature: 's', body: [c] }).catch(() => undefined);
    };
  }

  /** Turn a raw AT-SPI signal into a UiEvent (looks the source element up once and caches it). */
  async toEvent(m: DMessage, t0: number, cache: Map<string, { role: string; name: string }>, pidCache: Map<string, number | undefined>): Promise<UiEvent> {
    const ref = `${m.sender ?? ''}${m.path ?? ''}`;
    let info = cache.get(ref);
    if (!info && m.sender && m.path && cache.size < 20_000) {
      const r = { bus: m.sender, path: m.path };
      const [role, name] = await Promise.all([this.call(r, 'Accessible', 'GetRoleName', undefined, undefined, 1000).then((v) => String(v[0] ?? '')).catch(() => ''), this.client.getProperty(r.bus, r.path, I('Accessible'), 'Name', 1000).then(String).catch(() => '')]);
      info = { role, name }; cache.set(ref, info);
    }
    if (m.sender && !pidCache.has(m.sender)) pidCache.set(m.sender, await this.client.pidOf(m.sender));
    const [detail, d1, d2, data] = m.body as [DValue, DValue, DValue, DValue];
    let dataOut: unknown = data;
    if (Array.isArray(data) && data.length === 2 && typeof data[0] === 'string' && typeof data[1] === 'string' && String(data[1]).startsWith('/')) dataOut = { ref: `${data[0]}${data[1]}` };
    return { t: Date.now() - t0, type: atspiEventType(m.interface, m.member, detail), source: { ref, role: info?.role, name: info?.name, pid: m.sender ? pidCache.get(m.sender) : undefined }, detail1: typeof d1 === 'number' ? d1 : undefined, detail2: typeof d2 === 'number' ? d2 : undefined, data: typeof dataOut === 'string' ? dataOut.slice(0, 2000) : dataOut };
  }
}
