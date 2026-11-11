// The MCP server over Streamable HTTP: a real SDK client lists tools and calls one on a fixture, and the
// listener refuses wrong tokens, foreign Host and Origin headers, remote binds without a token, and big bodies.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { startHttpServer, httpOptionsFromArgv, isLoopback, type HttpHandle } from '../src/http.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const TOKEN = 'test-token-0123456789abcdef';
const handles: HttpHandle[] = [];
after(async () => { for (const h of handles) await h.close(); });

const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } };
const post = (url: string, headers: Record<string, string>, body: unknown = init) =>
  fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

test('an SDK client lists tools and calls analyze_file over HTTP with a token', async () => {
  const h = await startHttpServer({ port: 0, token: TOKEN });
  handles.push(h);
  assert.match(h.url, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
  const client = new Client({ name: 'http-test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(h.url), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
  const { tools } = await client.listTools();
  assert.ok(tools.some((t) => t.name === 'analyze_file'));
  assert.ok(tools.some((t) => t.name === 'disasm_pseudocode'));
  assert.equal(h.sessions(), 1);
  const r = await client.callTool({ name: 'analyze_file', arguments: { path: join(root, 'samples', 'disasm', 'hello-x64.elf') } }) as { content: { text: string }[] };
  assert.match(r.content[0]!.text, /"format": "elf"/);
  await client.close();
});

test('wrong or missing token is refused with 401', async () => {
  const h = await startHttpServer({ port: 0, token: TOKEN });
  handles.push(h);
  assert.equal((await post(h.url, {})).status, 401);
  assert.equal((await post(h.url, { authorization: 'Bearer nope-nope-nope-nope' })).status, 401);
  assert.equal(h.sessions(), 0);
});

test('foreign Host and Origin headers are refused (DNS rebinding)', async () => {
  const h = await startHttpServer({ port: 0 });
  handles.push(h);
  assert.equal((await post(h.url, { origin: 'https://evil.example' })).status, 403);
  const res = await new Promise<number>((ok, fail) => {
    import('node:http').then(({ request }) => {
      const rq = request({ host: '127.0.0.1', port: h.port, path: '/mcp', method: 'POST', headers: { host: 'evil.example', 'content-type': 'application/json' } }, (r) => { r.resume(); ok(r.statusCode ?? 0); });
      rq.on('error', fail);
      rq.end(JSON.stringify(init));
    }, fail);
  });
  assert.equal(res, 403);
  assert.equal((await post(h.url.replace('/mcp', '/other'), {})).status, 404);
});

test('oversized bodies and bad JSON are refused, unknown sessions get 404', async () => {
  const h = await startHttpServer({ port: 0, maxBodyBytes: 1024 });
  handles.push(h);
  const big = await post(h.url, {}, JSON.stringify({ pad: 'x'.repeat(4096) })).catch(() => undefined);
  assert.ok(!big || big.status === 413);
  assert.equal((await post(h.url, {}, '{not json')).status, 400);
  assert.equal((await post(h.url, { 'mcp-session-id': 'nope' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' })).status, 404);
});

test('remote binds need --allow-remote and a token; short tokens are refused', async () => {
  await assert.rejects(startHttpServer({ host: '0.0.0.0', port: 0 }), /allow-remote/);
  await assert.rejects(startHttpServer({ host: '0.0.0.0', port: 0, allowRemote: true }), /token is required/);
  await assert.rejects(startHttpServer({ port: 0, token: 'short' }), /at least 16/);
  assert.ok(isLoopback('127.0.0.1') && isLoopback('::1') && isLoopback('127.1.2.3') && !isLoopback('0.0.0.0'));
});

test('argv parsing', () => {
  assert.equal(httpOptionsFromArgv(['mcp']), undefined);
  const o = httpOptionsFromArgv(['mcp', '--http', '--port', '9000', '--allowed-origin', 'http://localhost:3000'], { REVLENS_MCP_TOKEN: TOKEN });
  assert.equal(o?.port, 9000);
  assert.equal(o?.token, TOKEN);
  assert.deepEqual(o?.allowedOrigins, ['http://localhost:3000']);
  assert.throws(() => httpOptionsFromArgv(['--http', '--port', '70000']), /port/);
});
