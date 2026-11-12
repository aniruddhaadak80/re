// Node program traced by the RevLens semantic tracer tests. Written for RevLens (MIT).
import { createServer } from 'node:http';

export function add(a, b = 10) { return a + b; }

export class Calc {
  constructor(scale) { this.scale = scale; }
  mul(x, y) { if (x === 0) return 0; return x * y * this.scale; }
}

function describe(user) { return `${user.name} (${user.tags.length} tags)`; }

const server = createServer((req, res) => { res.end('ok'); });
server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port;
  const c = new Calc(2);
  const out = [add(1, 2), add(5), c.mul(3, 4), c.mul(0, 9), describe({ name: 'ann', tags: ['a', 'b'] })];
  await new Promise((r) => setTimeout(r, 20));
  const body = await new Promise((resolve) => {
    import('node:http').then(({ get }) => get(`http://127.0.0.1:${port}/ping?x=1`, (res) => { let d = ''; res.on('data', (x) => (d += x)); res.on('end', () => resolve(d)); }));
  });
  console.log(JSON.stringify({ out, body }));
  server.close();
});
