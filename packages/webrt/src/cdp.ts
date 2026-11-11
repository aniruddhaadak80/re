// Chrome DevTools Protocol helpers shared by the browser target listing and the Node inspector attach.
// Node only. Uses the global WebSocket (Node 22+) or the optional "ws" package.
import { InputError } from './util.js';

export interface CdpTarget { id: string; type: string; title: string; url: string; webSocketDebuggerUrl?: string; devtoolsFrontendUrl?: string; attached?: boolean }
export interface CdpVersion { browser?: string; protocolVersion?: string; userAgent?: string; v8Version?: string; webKitVersion?: string; webSocketDebuggerUrl?: string }

const LOOPBACK = /^(?:127\.\d+\.\d+\.\d+|localhost|\[?::1\]?)$/i;

/** Check a DevTools HTTP endpoint and refuse non-loopback hosts unless allowed. */
export function checkDevtoolsEndpoint(endpoint: string, allowRemote = false): URL {
  let u: URL;
  try { u = new URL(/^\d+$/.test(endpoint) ? `http://127.0.0.1:${endpoint}` : endpoint); } catch { throw new InputError(`not a valid DevTools endpoint: ${endpoint}`); }
  if (!/^(?:https?|wss?):$/.test(u.protocol)) throw new InputError('DevTools endpoint must be http(s) or ws(s)');
  if (!allowRemote && !LOOPBACK.test(u.hostname)) throw new InputError(`DevTools endpoint ${u.hostname} is not loopback; pass allowRemote to connect to another host`);
  return u;
}

async function getJson(url: string, timeoutMs: number): Promise<unknown> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ac.signal, redirect: 'error' });
    if (!r.ok) throw new InputError(`${url} answered ${r.status}`);
    const text = await r.text();
    if (text.length > 4 * 1024 * 1024) throw new InputError('DevTools answer too large');
    return JSON.parse(text);
  } finally { clearTimeout(timer); }
}

/** List debuggable targets (pages, workers, service workers, Node contexts) on a DevTools HTTP endpoint such as http://127.0.0.1:9222. */
export async function cdpTargets(endpoint: string, opts: { allowRemote?: boolean; timeoutMs?: number } = {}): Promise<{ endpoint: string; version: CdpVersion; targets: CdpTarget[] }> {
  const u = checkDevtoolsEndpoint(endpoint, opts.allowRemote);
  const base = `${u.protocol.replace('ws', 'http')}//${u.host}`;
  const to = Math.max(500, Math.min(opts.timeoutMs ?? 5_000, 60_000));
  const version = (await getJson(`${base}/json/version`, to).catch(() => ({}))) as Record<string, string>;
  const list = await getJson(`${base}/json/list`, to);
  if (!Array.isArray(list)) throw new InputError('unexpected /json/list answer');
  return {
    endpoint: base,
    version: { browser: version.Browser, protocolVersion: version['Protocol-Version'], userAgent: version['User-Agent'], v8Version: version['V8-Version'], webKitVersion: version['WebKit-Version'], webSocketDebuggerUrl: version.webSocketDebuggerUrl },
    targets: list.slice(0, 1000).map((t: any) => ({ id: String(t.id ?? ''), type: String(t.type ?? ''), title: String(t.title ?? '').slice(0, 500), url: String(t.url ?? '').slice(0, 4000), webSocketDebuggerUrl: t.webSocketDebuggerUrl, devtoolsFrontendUrl: t.devtoolsFrontendUrl, attached: t.attached })),
  };
}

/** A tiny CDP client over one WebSocket. Every command has a timeout. */
export class CdpClient {
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private listeners = new Map<string, ((p: any) => void)[]>();
  private constructor(private ws: any) {}

  static async connect(wsUrl: string, timeoutMs = 5_000): Promise<CdpClient> {
    let WS: any = (globalThis as { WebSocket?: unknown }).WebSocket;
    if (!WS) { try { WS = (await import('ws' as string)).default; } catch { throw new InputError('no WebSocket available: use Node 22 or install the "ws" package'); } }
    const ws = new WS(wsUrl);
    const c = new CdpClient(ws);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { reject(new InputError(`could not connect to ${wsUrl} in ${timeoutMs} ms`)); try { ws.close(); } catch { /* ignore */ } }, timeoutMs);
      const onOpen = () => { clearTimeout(timer); resolve(); };
      const onErr = (e: any) => { clearTimeout(timer); reject(new InputError(`WebSocket error: ${e?.message ?? 'connect failed'}`)); };
      if (ws.addEventListener) { ws.addEventListener('open', onOpen, { once: true }); ws.addEventListener('error', onErr, { once: true }); }
      else { ws.once('open', onOpen); ws.once('error', onErr); }
    });
    const onMsg = (ev: any) => c.onMessage(typeof ev === 'string' ? ev : typeof ev?.data === 'string' ? ev.data : String(ev?.data ?? ev));
    if (ws.addEventListener) ws.addEventListener('message', onMsg); else ws.on('message', (d: any) => onMsg(String(d)));
    const onClose = () => { for (const [, p] of c.pending) { clearTimeout(p.timer); p.reject(new Error('connection closed')); } c.pending.clear(); };
    if (ws.addEventListener) ws.addEventListener('close', onClose); else ws.on('close', onClose);
    return c;
  }

  private onMessage(text: string): void {
    if (text.length > 64 * 1024 * 1024) return;
    let m: any;
    try { m = JSON.parse(text); } catch { return; }
    if (typeof m.id === 'number') {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id); clearTimeout(p.timer);
      if (m.error) p.reject(new Error(`${m.error.message ?? 'CDP error'} (${m.error.code ?? ''})`)); else p.resolve(m.result ?? {});
    } else if (typeof m.method === 'string') {
      for (const l of this.listeners.get(m.method) ?? []) { try { l(m.params); } catch { /* listener errors are ignored */ } }
    }
  }

  on(method: string, cb: (params: any) => void): void { (this.listeners.get(method) ?? this.listeners.set(method, []).get(method)!).push(cb); }

  send(method: string, params: Record<string, unknown> = {}, timeoutMs = 10_000): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`${method} timed out`)); }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try { this.ws.send(JSON.stringify({ id, method, params })); } catch (e) { clearTimeout(timer); this.pending.delete(id); reject(e as Error); }
    });
  }

  close(): void { try { this.ws.close(); } catch { /* ignore */ } }
}
