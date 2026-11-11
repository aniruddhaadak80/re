// RevLens MCP server over Streamable HTTP. Listens on 127.0.0.1 by default. Each MCP session gets its own
// server instance. Optional bearer token, Host and Origin checks against DNS rebinding, body size cap and
// a session cap, so a browser page or another machine cannot drive the tools by accident.
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { closeAllSessions } from '@revlens/engine/node';

export interface HttpOptions {
  /** interface to bind. Default 127.0.0.1. Anything that is not loopback needs allowRemote and a token. */
  host?: string;
  /** port. Default 7337. 0 picks a free port. */
  port?: number;
  /** URL path of the MCP endpoint. Default /mcp. */
  path?: string;
  /** bearer token clients must send as "Authorization: Bearer <token>". */
  token?: string;
  /** allow a non loopback bind address. Requires token. */
  allowRemote?: boolean;
  /** extra Host header values to accept (for example a reverse proxy name). */
  allowedHosts?: string[];
  /** Origin header values to accept. Requests with any other Origin are refused. Requests without Origin pass. */
  allowedOrigins?: string[];
  /** maximum request body in bytes. Default 4 MiB. */
  maxBodyBytes?: number;
  /** maximum live sessions. Default 32. */
  maxSessions?: number;
  /** close a session after this many ms without requests. Default 30 minutes. */
  idleMs?: number;
}

export interface HttpHandle {
  server: Server;
  url: string;
  port: number;
  sessions: () => number;
  close: () => Promise<void>;
}

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
export function isLoopback(host: string): boolean {
  return LOOPBACK.has(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

function sameToken(given: string, want: string): boolean {
  const a = createHash('sha256').update(given).digest();
  const b = createHash('sha256').update(want).digest();
  return timingSafeEqual(a, b);
}

function send(res: ServerResponse, status: number, message: string): void {
  if (res.headersSent) { res.end(); return; }
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
}

function readBody(req: IncomingMessage, max: number): Promise<unknown> {
  return new Promise((resolveBody, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > max) { reject(Object.assign(new Error(`request body larger than ${max} bytes`), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) { resolveBody(undefined); return; }
      try { resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('body is not valid JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

/** Start the MCP server on Streamable HTTP. Resolves once it is listening. */
export async function startHttpServer(opts: HttpOptions = {}): Promise<HttpHandle> {
  const host = opts.host ?? '127.0.0.1';
  const path = opts.path ?? '/mcp';
  const maxBody = opts.maxBodyBytes ?? 4 * 1024 * 1024;
  const maxSessions = opts.maxSessions ?? 32;
  const idleMs = opts.idleMs ?? 30 * 60_000;
  if (!isLoopback(host)) {
    if (!opts.allowRemote) throw new Error(`refusing to listen on ${host}: pass --allow-remote (and a --token) to accept connections from other machines`);
    if (!opts.token) throw new Error('a token is required when listening on a non loopback address');
  }
  if (opts.token !== undefined && opts.token.length < 16) throw new Error('token must be at least 16 characters');

  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; last: number }>();
  let port = opts.port ?? 7337;

  const hostOk = (h: string | undefined): boolean => {
    if (!h) return false;
    const name = h.startsWith('[') ? h.slice(1, h.indexOf(']')) : h.split(':')[0]!;
    if (opts.allowedHosts?.some((a) => a === h || a === name)) return true;
    if (isLoopback(name)) return true;
    return !isLoopback(host) && (name === host || host === '0.0.0.0' || host === '::');
  };

  const server = createHttpServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (url.pathname !== path) { send(res, 404, 'not found'); return; }
      if (!hostOk(req.headers.host)) { send(res, 403, 'Host header not allowed'); return; }
      const origin = req.headers.origin;
      if (origin && !(opts.allowedOrigins ?? []).includes(origin)) { send(res, 403, 'Origin not allowed'); return; }
      if (opts.token) {
        const auth = req.headers.authorization ?? '';
        const m = /^Bearer (\S{1,512})$/.exec(auth);
        if (!m || !sameToken(m[1]!, opts.token)) { res.setHeader('www-authenticate', 'Bearer'); send(res, 401, 'missing or wrong bearer token'); return; }
      }
      const sid = req.headers['mcp-session-id'];
      const id = Array.isArray(sid) ? sid[0] : sid;
      if (req.method === 'POST') {
        const body = await readBody(req, maxBody);
        if (id) {
          const s = sessions.get(id);
          if (!s) { send(res, 404, 'unknown session'); return; }
          s.last = Date.now();
          await s.transport.handleRequest(req, res, body);
          return;
        }
        if (sessions.size >= maxSessions) { send(res, 503, 'too many sessions'); return; }
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newId) => { sessions.set(newId, { transport, last: Date.now() }); },
        });
        transport.onclose = () => { if (transport.sessionId) sessions.delete(transport.sessionId); };
        const { server: mcp } = createServer();
        await mcp.connect(transport);
        await transport.handleRequest(req, res, body);
        return;
      }
      if (req.method === 'GET' || req.method === 'DELETE') {
        const s = id ? sessions.get(id) : undefined;
        if (!s) { send(res, id ? 404 : 400, id ? 'unknown session' : 'missing mcp-session-id'); return; }
        s.last = Date.now();
        await s.transport.handleRequest(req, res);
        return;
      }
      res.setHeader('allow', 'GET, POST, DELETE');
      send(res, 405, 'method not allowed');
    } catch (e) {
      send(res, (e as { status?: number }).status ?? 500, (e as Error).message);
    }
  });
  server.headersTimeout = 30_000;
  server.requestTimeout = 0; // SSE streams stay open

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, s] of sessions) if (now - s.last > idleMs) { sessions.delete(k); void s.transport.close(); }
  }, Math.min(idleMs, 60_000));
  sweep.unref();

  await new Promise<void>((ok, fail) => { server.once('error', fail); server.listen(port, host, () => { server.off('error', fail); ok(); }); });
  const addr = server.address();
  if (addr && typeof addr === 'object') port = addr.port;
  const shown = host.includes(':') ? `[${host}]` : host;
  return {
    server,
    port,
    url: `http://${shown}:${port}${path}`,
    sessions: () => sessions.size,
    close: async () => {
      clearInterval(sweep);
      await Promise.all([...sessions.values()].map((s) => s.transport.close()));
      sessions.clear();
      // bridge sessions (radare2, gdb, lldb, Frida) belong to this process, so they end with the server
      await closeAllSessions().catch(() => 0);
      await new Promise<void>((ok) => server.close(() => ok()));
    },
  };
}

/** Parse --http, --host, --port, --token, --allow-remote, --allowed-origin and --path from argv. */
export function httpOptionsFromArgv(argv: string[], env: NodeJS.ProcessEnv = process.env): HttpOptions | undefined {
  if (!argv.includes('--http')) return undefined;
  const val = (name: string): string | undefined => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const portText = val('--port');
  const port = portText === undefined ? undefined : Number(portText);
  if (port !== undefined && !(Number.isInteger(port) && port >= 0 && port <= 65535)) throw new Error('--port must be 0 to 65535');
  const origins: string[] = [];
  argv.forEach((a, i) => { if (a === '--allowed-origin' && argv[i + 1]) origins.push(argv[i + 1]!); });
  return {
    host: val('--host'),
    port,
    path: val('--path'),
    token: val('--token') ?? env.REVLENS_MCP_TOKEN,
    allowRemote: argv.includes('--allow-remote'),
    allowedOrigins: origins,
  };
}
