// Small D-Bus client for Node over a Unix socket: EXTERNAL auth, Hello, method calls with
// timeouts, match rules and signal delivery. Used for AT-SPI (one socket instead of one gdbus
// process per call) and to hold an event registration open while tracing.
import { createConnection, type Socket } from 'node:net';
import { encodeMessage, decodeMessage, messageLength, MSG, FLAG, type DMessage, type DValue } from './dbuswire.js';
import { InputError } from './proc.js';

export class DBusError extends Error { constructor(public errorName: string, message: string) { super(`${errorName}: ${message}`); this.name = 'DBusError'; } }

/** Parse a D-Bus address list ("unix:path=/x,guid=..;unix:abstract=y") into socket paths to try. */
export function parseAddress(address: string): { path: string; abstract: boolean }[] {
  const out: { path: string; abstract: boolean }[] = [];
  for (const part of address.split(';').slice(0, 16)) {
    const colon = part.indexOf(':');
    if (colon < 0 || part.slice(0, colon) !== 'unix') continue;
    const kv: Record<string, string> = {};
    for (const p of part.slice(colon + 1).split(',')) { const eq = p.indexOf('='); if (eq > 0) kv[p.slice(0, eq)] = decodeURIComponent(p.slice(eq + 1)); }
    if (kv.path) out.push({ path: kv.path, abstract: false });
    else if (kv.abstract) out.push({ path: kv.abstract, abstract: true });
  }
  if (!out.length) throw new InputError(`no usable unix transport in D-Bus address ${address.slice(0, 200)}`);
  return out;
}

type Pending = { resolve: (m: DMessage) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> };

export class DBusClient {
  uniqueName = '';
  private serial = 1;
  private pending = new Map<number, Pending>();
  private buf = new Uint8Array(0);
  private listeners = new Set<(m: DMessage) => void>();
  private closed = false;
  private constructor(private sock: Socket, public address: string) {}

  /** Connect, authenticate and say Hello. */
  static async connect(address: string, timeoutMs = 5000): Promise<DBusClient> {
    let last: Error | undefined;
    for (const t of parseAddress(address)) {
      try { return await DBusClient.connectOne(address, t, timeoutMs); } catch (e) { last = e as Error; }
    }
    throw last ?? new InputError('cannot connect');
  }

  private static connectOne(address: string, t: { path: string; abstract: boolean }, timeoutMs: number): Promise<DBusClient> {
    return new Promise((resolve, reject) => {
      const sock = createConnection({ path: t.abstract ? '\0' + t.path : t.path });
      let stage = 0, text = '';
      const timer = setTimeout(() => { sock.destroy(); reject(new InputError('D-Bus connect timed out')); }, timeoutMs);
      const fail = (e: Error) => { clearTimeout(timer); sock.destroy(); reject(e); };
      sock.on('error', fail);
      sock.on('connect', () => {
        const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
        const hex = Buffer.from(String(uid)).toString('hex');
        sock.write(Buffer.concat([Buffer.from([0]), Buffer.from(`AUTH EXTERNAL ${hex}\r\n`)]));
      });
      const onData = (d: Buffer) => {
        if (stage !== 0) return;
        text += d.toString('latin1');
        if (text.length > 4096) { fail(new InputError('D-Bus auth reply too long')); return; }
        const nl = text.indexOf('\r\n');
        if (nl < 0) return;
        const line = text.slice(0, nl);
        if (!line.startsWith('OK ')) { fail(new InputError(`D-Bus auth refused: ${line.slice(0, 100)}`)); return; }
        stage = 1;
        sock.off('data', onData);
        sock.write('BEGIN\r\n');
        const c = new DBusClient(sock, address);
        sock.off('error', fail);
        sock.on('error', (e) => c.shutdown(e));
        sock.on('close', () => c.shutdown(new Error('D-Bus connection closed')));
        sock.on('data', (b) => c.onData(b));
        const rest = Buffer.from(text.slice(nl + 2), 'latin1');
        if (rest.length) c.onData(rest);
        c.call({ destination: 'org.freedesktop.DBus', path: '/org/freedesktop/DBus', interface: 'org.freedesktop.DBus', member: 'Hello' }, timeoutMs)
          .then((r) => { clearTimeout(timer); c.uniqueName = String(r[0]); resolve(c); })
          .catch(fail);
      };
      sock.on('data', onData);
    });
  }

  private onData(b: Uint8Array) {
    const merged = new Uint8Array(this.buf.length + b.length); merged.set(this.buf); merged.set(b, this.buf.length); this.buf = merged;
    for (;;) {
      let n: number;
      try { n = messageLength(this.buf); } catch (e) { this.shutdown(e as Error); return; }
      if (!n || n > this.buf.length) return;
      const raw = this.buf.subarray(0, n);
      this.buf = this.buf.slice(n);
      let m: DMessage;
      try { m = decodeMessage(raw); } catch { continue; } // skip a message we cannot read
      if ((m.type === MSG.return || m.type === MSG.error) && m.replySerial !== undefined) {
        const p = this.pending.get(m.replySerial);
        if (p) { this.pending.delete(m.replySerial); clearTimeout(p.timer); if (m.type === MSG.error) p.reject(new DBusError(m.errorName ?? 'error', String(m.body[0] ?? ''))); else p.resolve(m); }
      } else if (m.type === MSG.signal || m.type === MSG.call) {
        for (const l of this.listeners) { try { l(m); } catch { /* listener error */ } }
      }
    }
  }

  private shutdown(e: Error) {
    if (this.closed) return;
    this.closed = true;
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(e); }
    this.pending.clear();
    this.sock.destroy();
  }

  /** Call a method and return the reply body. */
  async call(m: { destination?: string; path: string; interface?: string; member: string; signature?: string; body?: DValue[] }, timeoutMs = 5000): Promise<DValue[]> {
    return (await this.callMessage(m, timeoutMs)).body;
  }

  callMessage(m: { destination?: string; path: string; interface?: string; member: string; signature?: string; body?: DValue[] }, timeoutMs = 5000): Promise<DMessage> {
    if (this.closed) return Promise.reject(new Error('D-Bus connection closed'));
    const serial = this.serial++;
    const bytes = encodeMessage({ type: MSG.call, flags: 0, serial, ...m });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(serial); reject(new DBusError('org.freedesktop.DBus.Error.Timeout', `${m.interface ?? ''}.${m.member} on ${m.destination ?? ''}${m.path} timed out`)); }, Math.max(50, Math.min(timeoutMs, 120_000)));
      this.pending.set(serial, { resolve, reject, timer });
      this.sock.write(bytes);
    });
  }

  /** Send a signal or a call without waiting for a reply. */
  send(m: Omit<DMessage, 'serial' | 'flags' | 'body'> & { body?: DValue[]; flags?: number }) {
    if (this.closed) return;
    this.sock.write(encodeMessage({ flags: m.type === MSG.call ? FLAG.noReply : 0, ...m, serial: this.serial++ }));
  }

  onMessage(f: (m: DMessage) => void): () => void { this.listeners.add(f); return () => this.listeners.delete(f); }

  addMatch(rule: string) { return this.call({ destination: 'org.freedesktop.DBus', path: '/org/freedesktop/DBus', interface: 'org.freedesktop.DBus', member: 'AddMatch', signature: 's', body: [rule] }); }

  async getProperty(dest: string, path: string, iface: string, name: string, timeoutMs = 3000): Promise<DValue> {
    const r = await this.call({ destination: dest, path, interface: 'org.freedesktop.DBus.Properties', member: 'Get', signature: 'ss', body: [iface, name] }, timeoutMs);
    return r[0] ?? null;
  }

  async pidOf(busName: string): Promise<number | undefined> {
    try { const r = await this.call({ destination: 'org.freedesktop.DBus', path: '/org/freedesktop/DBus', interface: 'org.freedesktop.DBus', member: 'GetConnectionUnixProcessID', signature: 's', body: [busName] }, 3000); return Number(r[0]); } catch { return undefined; }
  }

  get isClosed() { return this.closed; }
  close() { this.shutdown(new Error('closed')); }
}
