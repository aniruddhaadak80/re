#!/usr/bin/env node
// A minimal npm registry in one file, for testing the publish path without a real registry or
// verdaccio. It accepts `npm publish` (PUT with base64 attachments), serves packuments and tarballs,
// and keeps everything in memory. Any token is accepted. Not for real use.
//
//   node scripts/release/local-registry.mjs [--port 0]     prints {"url": "..."} on stdout
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

export function startRegistry({ port = 0, host = '127.0.0.1', maxBody = 256 * 1024 * 1024 } = {}) {
  const docs = new Map();
  const tarballs = new Map();
  const server = createServer((req, res) => {
    const send = (code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    const url = new URL(req.url, 'http://x');
    const path = decodeURIComponent(url.pathname).replace(/^\/+/, '');
    if (req.method === 'GET' && path.includes('/-/')) {
      const t = tarballs.get(path);
      if (!t) return send(404, { error: 'not found' });
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': t.length });
      return res.end(t);
    }
    if (req.method === 'GET') {
      const d = docs.get(path);
      return d ? send(200, d) : send(404, { error: 'not found' });
    }
    if (req.method === 'PUT') {
      const chunks = []; let size = 0;
      req.on('data', (c) => { size += c.length; if (size > maxBody) req.destroy(); else chunks.push(c); });
      req.on('end', () => {
        let body;
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(400, { error: 'bad json' }); }
        const name = body.name;
        if (typeof name !== 'string' || name !== path) return send(400, { error: `name ${name} does not match path ${path}` });
        const doc = docs.get(name) ?? { name, versions: {}, 'dist-tags': {}, time: {} };
        const base = `http://${req.headers.host}`;
        for (const [v, meta] of Object.entries(body.versions ?? {})) {
          if (doc.versions[v]) return send(409, { error: `${name}@${v} exists` });
          const file = `${name.split('/').pop()}-${v}.tgz`;
          const att = body._attachments?.[file] ?? Object.values(body._attachments ?? {})[0];
          if (!att) return send(400, { error: 'no attachment' });
          const buf = Buffer.from(att.data, 'base64');
          const key = `${name}/-/${file}`;
          tarballs.set(key, buf);
          meta.dist = { ...(meta.dist ?? {}), tarball: `${base}/${key}`, shasum: createHash('sha1').update(buf).digest('hex'), integrity: `sha512-${createHash('sha512').update(buf).digest('base64')}` };
          doc.versions[v] = meta;
          doc.time[v] = new Date().toISOString();
        }
        Object.assign(doc['dist-tags'], body['dist-tags'] ?? {});
        docs.set(name, doc);
        send(201, { ok: true });
      });
      return;
    }
    send(405, { error: 'method not allowed' });
  });
  return new Promise((ok) => server.listen(port, host, () => {
    const a = server.address();
    ok({ url: `http://${host}:${a.port}/`, docs, close: () => new Promise((r) => server.close(r)) });
  }));
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split(/[\\/]/).pop())) {
  const i = process.argv.indexOf('--port');
  const r = await startRegistry({ port: i > 0 ? Number(process.argv[i + 1]) : 0 });
  process.stdout.write(JSON.stringify({ url: r.url }) + '\n');
}
