import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { browserCapture } from '../src/node.js';

async function browserAvailable(): Promise<boolean> {
  try {
    const pw: any = await import('playwright' as string);
    const b = await pw.chromium.launch({ timeout: 15_000 });
    await b.close();
    return true;
  } catch { return false; }
}

test('browser capture rejects non-http URLs before launching anything', async () => {
  await assert.rejects(browserCapture('file:///etc/passwd'), /http/);
  await assert.rejects(browserCapture('javascript:alert(1)'), /http/);
});

test('browser capture records requests, scripts, console, storage and analyses scripts', async (t) => {
  if (!(await browserAvailable())) { t.skip('no Playwright browser installed (npx playwright install chromium)'); return; }
  const server = createServer((req, res) => {
    if (req.url === '/') { res.setHeader('content-type', 'text/html'); res.end('<html><head><title>fixture</title><script src="/app.js"></script></head><body><script>localStorage.setItem("revlens","1");console.log("inline ran")</script></body></html>'); return; }
    if (req.url === '/app.js') { res.setHeader('content-type', 'text/javascript'); res.end('fetch("/api/v1/ping").then(r=>r.text());console.log("app ran");'); return; }
    if (req.url === '/api/v1/ping') { res.setHeader('content-type', 'application/json'); res.setHeader('set-cookie', 'sid=abc; HttpOnly'); res.end('{"ok":true}'); return; }
    res.statusCode = 404; res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  try {
    const r = await browserCapture(`http://127.0.0.1:${port}/`, { timeoutMs: 30_000, settleMs: 500 });
    assert.equal(r.title, 'fixture');
    const urls = r.har.log.entries.map((e: any) => new URL(e.request.url).pathname);
    assert.ok(urls.includes('/app.js') && urls.includes('/api/v1/ping'));
    const app = r.scripts.find((s) => s.url.endsWith('/app.js'))!;
    assert.ok(app.endpoints!.calls.some((c) => c.url === '/api/v1/ping'));
    assert.ok(r.console.some((c) => c.text === 'app ran'));
    assert.deepEqual(r.storage.localStorage, ['revlens']);
    assert.ok(r.cookies.some((c) => c.name === 'sid' && c.httpOnly));
    const ping = r.har.log.entries.find((e: any) => e.request.url.endsWith('/api/v1/ping')) as any;
    assert.equal(ping.response.headers.find((h: any) => h.name === 'set-cookie').value, '[redacted]');
  } finally { server.close(); }
});
