// Tiny deterministic web app used by the RevLens webrt round 3 tests: endpoint join, semantic tracing,
// scenario recording and replay environments. Responses never contain times or random values, so a
// recording and its replay can be compared byte for byte. Written for RevLens (MIT).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css' };

export function createEnvApp() {
  const items = [{ id: 1, name: 'alpha', price: 3 }, { id: 2, name: 'beta', price: 4 }];
  const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
  return createServer(async (req, res) => {
    const url = new URL(req.url, 'http://local');
    const p = url.pathname;
    if (req.method === 'GET' && (p === '/' || p === '/index.html' || p === '/app.js' || p === '/style.css')) {
      const file = p === '/' ? 'index.html' : p.slice(1);
      const ext = file.slice(file.lastIndexOf('.'));
      res.writeHead(200, { 'content-type': TYPES[ext] ?? 'application/octet-stream', 'cache-control': 'no-store' });
      res.end(await readFile(join(here, 'public', file)));
      return;
    }
    if (req.method === 'GET' && p === '/api/items') return json(res, 200, { items, total: items.length });
    const m = /^\/api\/items\/(\d+)$/.exec(p);
    if (req.method === 'GET' && m) { const it = items.find((x) => x.id === Number(m[1])); return it ? json(res, 200, it) : json(res, 404, { error: 'not found' }); }
    if (req.method === 'POST' && p === '/api/items') {
      let body = '';
      for await (const c of req) body += c;
      let name = 'unnamed';
      try { name = String(JSON.parse(body).name ?? 'unnamed').slice(0, 40); } catch { /* keep default */ }
      const it = { id: items.length + 1, name, price: name.length };
      items.push(it);
      return json(res, 201, it);
    }
    if (req.method === 'GET' && p === '/api/session') return json(res, 200, { user: 'demo', roles: ['reader'] });
    if (req.method === 'GET' && p === '/api/search') { const q = url.searchParams.get('q') ?? ''; return json(res, 200, { q, page: Number(url.searchParams.get('page') ?? 1), hits: items.filter((x) => x.name.includes(q)).map((x) => x.id) }); }
    if (req.method === 'GET' && p.startsWith('/api/dyn/')) return json(res, 200, { echo: p.slice(9) });
    if (req.method === 'GET' && p === '/api/ping') return json(res, 200, { pong: true });
    json(res, 404, { error: 'not found' });
  });
}

// node server.mjs [port] starts it on 127.0.0.1
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const s = createEnvApp();
  s.listen(Number(process.argv[2] ?? 0), '127.0.0.1', () => console.log(`envapp on http://127.0.0.1:${s.address().port}/`));
}
