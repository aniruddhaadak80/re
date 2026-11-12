// web_env_compare against the real envapp server: the environment is built from a HAR recorded from
// the live server, probes are recorded from fresh server instances, and every expected outcome follows
// from what the live server itself answered (the ground truth), not from the replay.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import fc from 'fast-check';
import { TOOLS } from '../src/node.js';
import { compareEnvironmentWithProbes, buildEnvironment } from '../src/index.js';
// @ts-expect-error plain JavaScript fixture server
import { createEnvApp } from '../../../samples/webrt/envapp/server.mjs';

const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
type Call = [method: string, path: string, body?: string];
let work = '';
before(() => { work = mkdtempSync(join(tmpdir(), 'revlens-envcmp-')); });
after(() => { rmSync(work, { recursive: true, force: true }); });

/** Start a fresh envapp, make the calls in order, return a HAR of what the server answered. */
async function record(calls: Call[]): Promise<any> {
  const server: Server = createEnvApp();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const entries: any[] = [];
  try {
    let t = Date.parse('2026-01-01T00:00:00Z');
    for (const [method, path, body] of calls) {
      const res = await fetch(base + path, { method, body, headers: body ? { 'content-type': 'application/json' } : undefined });
      const text = await res.text();
      entries.push({ startedDateTime: new Date(t += 10).toISOString(), request: { method, url: base + path, headers: [], postData: body ? { mimeType: 'application/json', text: body } : undefined }, response: { status: res.status, statusText: res.statusText, headers: [...res.headers].map(([name, value]) => ({ name, value })), content: { mimeType: res.headers.get('content-type') ?? '', text } } });
    }
  } finally { server.close(); }
  return { log: { version: '1.2', creator: { name: 'revlens-test', version: '1' }, entries } };
}
const save = (name: string, obj: unknown) => { const p = join(work, name); writeFileSync(p, JSON.stringify(obj)); return p; };

const BASE: Call[] = [['GET', '/api/items'], ['POST', '/api/items', '{"name":"gamma"}'], ['GET', '/api/items/3'], ['GET', '/api/search?q=al&page=1']];

test('web_env_compare: same sequence agrees, changed calls disagree at the right path, unknown calls are no-tool', { timeout: 60_000 }, async () => {
  const cap = save('capture.har', await record(BASE));
  const envDir = join(work, 'env');
  await tool('web_env_build').run({ capturePath: cap, outDir: envDir, name: 'envapp' });
  const same = save('probe-same.har', await record(BASE));
  const changed = await record([['GET', '/api/items'], ['GET', '/api/search?q=be&page=1'], ['GET', '/api/nothing'], ['POST', '/api/items', '{"name":"delta"}']]);
  // ground truth from the live server
  assert.equal(JSON.parse(changed.log.entries[1].response.content.text).hits[0], 2);
  assert.equal(changed.log.entries[2].response.status, 404);
  const r = await tool('web_env_compare').run({ path: envDir, probes: [same, save('probe-changed.har', changed)] }) as any;
  const [a, b] = r.probes;
  assert.equal(a.compared, 4); assert.equal(a.agreed, 4); assert.equal(a.agreement, 1);
  assert.deepEqual(b.calls.map((c: any) => c.outcome), ['agree', 'disagree', 'no-tool', 'disagree']);
  // search with another q replays the recorded q=al answer (query-names rule): hits differ
  assert.equal(b.calls[1].rule, 'query-names');
  assert.deepEqual(b.calls[1].difference, { path: '$.hits[0]', app: '2', env: '1' });
  // a create with another body replays the recorded create: the name differs, the new id agrees
  assert.deepEqual(b.calls[3].difference, { path: '$.name', app: '"delta"', env: '"gamma"' });
  assert.equal(r.summary.compared, 7); assert.equal(r.summary.agreed, 5); assert.equal(r.summary.noTool, 1);
  // the export zip compares the same way
  const zip = join(work, 'env.zip');
  await tool('web_env_export').run({ path: envDir, outZip: zip });
  const z = await tool('web_env_compare').run({ path: zip, probes: [same] }) as any;
  assert.equal(z.probes[0].agreement, 1);
});

test('ids from a re-seeded application are mapped and translated in later requests', async () => {
  const cap = await record(BASE);
  const built = buildEnvironment(cap, { name: 'envapp' });
  const bodies = new Map(built.files.map((f) => [f.path, f.bytes]));
  // the same run against an application seeded with ids 101, 102 and creating 103
  const shift = (o: any): any => (Array.isArray(o) ? o.map(shift) : o && typeof o === 'object' ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, k === 'id' ? (v as number) + 100 : shift(v)])) : o);
  const probe = JSON.parse(JSON.stringify(cap));
  probe.log.entries = probe.log.entries.slice(0, 3);
  for (const e of probe.log.entries) { e.response.content.text = JSON.stringify(shift(JSON.parse(e.response.content.text))); e.request.url = e.request.url.replace('/api/items/3', '/api/items/103'); }
  const r = await compareEnvironmentWithProbes(built.manifest, (f) => bodies.get(f), [{ name: 'shifted', capture: probe }]);
  assert.deepEqual(r.probes[0]!.calls.map((c) => c.outcome), ['agree', 'agree', 'agree']);
  assert.equal(r.probes[0]!.calls[2]!.rule, 'exact', '/api/items/103 is translated to the recorded /api/items/3');
  assert.equal(r.probes[0]!.mappedIds, 3);
  // without the mapping the same probe would disagree: an unrelated id is not mapped
  probe.log.entries[2].request.url = probe.log.entries[2].request.url.replace('/api/items/103', '/api/items/104');
  const r2 = await compareEnvironmentWithProbes(built.manifest, (f) => bodies.get(f), [{ name: 'shifted', capture: probe }]);
  assert.equal(r2.probes[0]!.calls[2]!.rule, 'template');
});

test('hostile probes are refused or bounded', async () => {
  const built = buildEnvironment(await record(BASE.slice(0, 1)), { name: 'x' });
  await assert.rejects(compareEnvironmentWithProbes(built.manifest, () => undefined, []), /at least one probe/);
  await assert.rejects(compareEnvironmentWithProbes(built.manifest, () => undefined, [{ name: 'p', capture: { nope: 1 } }]), /not a HAR/);
  await assert.rejects(tool('web_env_compare').run({ path: work, probes: [] }), /at least one probe/);
  await fc.assert(fc.asyncProperty(fc.array(fc.record({ request: fc.record({ method: fc.constantFrom('GET', 'POST', ''), url: fc.oneof(fc.webUrl(), fc.string()), postData: fc.option(fc.record({ text: fc.string() })) }), response: fc.record({ status: fc.integer({ min: 0, max: 599 }), content: fc.record({ text: fc.oneof(fc.json(), fc.string()) }) }) }), { maxLength: 30 }), async (entries) => {
    const t0 = Date.now();
    await compareEnvironmentWithProbes(built.manifest, () => new TextEncoder().encode('{"a":1}'), [{ name: 'p', capture: { log: { entries } } }]);
    return Date.now() - t0 < 3000;
  }), { numRuns: 150 });
  // deeply nested JSON on both sides stays bounded
  const deep = '{"id":0,"x":'.repeat(5000) + '1' + '}'.repeat(5000);
  const big = { log: { entries: [{ request: { method: 'GET', url: 'http://h/api/items' }, response: { status: 200, content: { text: `{"items":[${deep}]}` } } }] } };
  const t0 = Date.now();
  const r = await compareEnvironmentWithProbes(built.manifest, () => new TextEncoder().encode(`{"items":[${deep}]}`), [{ name: 'deep', capture: big }]);
  assert.equal(r.probes[0]!.calls[0]!.outcome, 'agree');
  assert.ok(Date.now() - t0 < 3000);
});
