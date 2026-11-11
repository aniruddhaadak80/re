import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SqliteFile, runSelect, sampleRows, parseSelect, analyzeHar } from '../src/index.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const DB = join(S, 'fixture.sqlite');
const db = () => new SqliteFile(new Uint8Array(readFileSync(DB)));

/** Ask the real SQLite (python3 stdlib) for the same answer when python3 is available. */
function py(sql: string): unknown[][] | undefined {
  try {
    const out = execFileSync('python3', ['-c', 'import sqlite3,sys,json;c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True);print(json.dumps(c.execute(sys.argv[2]).fetchall()))', DB, sql], { timeout: 20_000, encoding: 'utf8' });
    return JSON.parse(out) as unknown[][];
  } catch { return undefined; }
}

test('sqlite: schema, columns and row counts match python3 sqlite3', () => {
  const d = db();
  assert.equal(d.header.pageSize, 1024);
  assert.equal(d.header.encoding, 'utf8');
  const t = d.tables();
  assert.deepEqual(t.map((x) => x.name), ['users', 'events', 'sqlite_sequence', 'kv']);
  const users = t.find((x) => x.name === 'users')!;
  assert.deepEqual(users.columns.map((c) => `${c.name} ${c.type}${c.pk ? ' pk' : ''}`), ['id INTEGER pk', 'name TEXT', 'email TEXT', 'score REAL', 'avatar BLOB']);
  assert.equal(users.rowidAlias, 'id');
  assert.equal(users.rowCount, 300);
  assert.equal(t.find((x) => x.name === 'events')!.rowCount, 1000);
  assert.deepEqual(t.find((x) => x.name === 'events')!.indexes, ['idx_events_user']);
  assert.equal(t.find((x) => x.name === 'kv')!.withoutRowid, true);
  const schema = d.schema();
  assert.deepEqual(schema.filter((o) => o.type === 'view').map((o) => o.name), ['active_users']);
  const ref = py("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY rowid");
  if (ref) assert.deepEqual(t.map((x) => [x.name, x.sql]), ref);
  const counts = py('SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM kv)');
  if (counts) assert.deepEqual(counts[0], [300, 1000, 3]);
});

test('sqlite: rows, overflow pages, blobs and WITHOUT ROWID tables', () => {
  const d = db();
  const s = sampleRows(d, 'users', 5);
  assert.deepEqual(s[4], { rowid: 5, id: 5, name: 'user5', email: 'user5@example.com', score: 7.5, avatar: { blob: '05ab', size: 2 } });
  assert.equal(s[2]?.email, null); // i % 3 == 0 has NULL email
  const big = runSelect(d, 'SELECT payload FROM events WHERE id = 8');
  assert.equal((big.rows[0]?.[0] as string).length, 5000); // spans overflow pages at 1 KiB page size
  assert.deepEqual(sampleRows(d, 'kv', 5), [{ k: 'lang', v: 'bn' }, { k: 'theme', v: 'dark' }, { k: 'version', v: '1.0.0' }]);
});

test('sqlite: SELECT engine agrees with SQLite on filters, ordering and limits', () => {
  const d = db();
  const queries = [
    "SELECT COUNT(*) FROM events WHERE kind = 'purchase'",
    'SELECT id, name, score FROM users WHERE email IS NULL AND score > 400 ORDER BY score DESC LIMIT 3',
    "SELECT k, v FROM kv WHERE k LIKE 'L%' OR v = 'dark' ORDER BY k",
    'SELECT id FROM users WHERE id IN (1, 2, 3, 250) AND NOT score < 2 ORDER BY id',
    'SELECT id, user_id FROM events WHERE id BETWEEN 10 AND 14 ORDER BY id DESC',
    'SELECT name FROM users ORDER BY name LIMIT 4 OFFSET 2',
  ];
  const expect: Record<string, unknown[][]> = {
    [queries[0]!]: [[333]],
    [queries[1]!]: [[300, 'user300', 450], [297, 'user297', 445.5], [294, 'user294', 441]],
  };
  for (const q of queries) {
    const ours = runSelect(d, q).rows;
    const ref = py(q) ?? expect[q];
    if (ref) assert.deepEqual(ours, ref, q);
  }
});

test('sqlite: parser refuses anything that is not one plain SELECT', () => {
  for (const bad of ['DELETE FROM users', 'SELECT * FROM users; DROP TABLE users', "ATTACH 'x' AS y", 'PRAGMA writable_schema=1', 'WITH RECURSIVE c(x) AS (SELECT 1) SELECT x FROM c', 'SELECT * FROM users UNION SELECT * FROM kv', 'UPDATE kv SET v=1', 'SELECT load_extension(1) FROM kv']) {
    assert.throws(() => parseSelect(bad), undefined, bad);
  }
  assert.throws(() => runSelect(db(), 'SELECT * FROM active_users'), /view/);
  assert.equal(runSelect(db(), 'SELECT id FROM users', { maxRows: 7 }).rows.length, 7);
});

test('har: real Playwright HAR files (redirect chain and fulfilled routes)', () => {
  const r = analyzeHar(readFileSync(join(S, 'har-redirect.har'), 'utf8'));
  assert.equal(r.entries, 3);
  assert.equal(r.creator, 'Playwright 1.23.0-next');
  assert.deepEqual(r.redirects.map((x) => `${x.status} ${x.from} -> ${x.to}`), ['301 https://theverge.com/ -> http://www.theverge.com/', '301 http://www.theverge.com/ -> https://www.theverge.com/']);
  assert.deepEqual(r.statuses, { 200: 1, 301: 2 });
  const f = analyzeHar(readFileSync(join(S, 'har-fulfill.har'), 'utf8'));
  assert.equal(f.entries, 5);
  assert.deepEqual(f.methods, { GET: 4, POST: 1 });
  assert.deepEqual(f.hosts.map((h) => [h.host, h.requests]), [['no.playwright', 5]]);
  assert.ok(f.endpoints.some((e) => e.method === 'POST' && e.pattern === '/style.css'));
  assert.deepEqual(f.scripts.map((s) => s.url), ['http://no.playwright/script.js', 'http://no.playwright/script2.js']);
  assert.ok(f.missingSecurityHeaders.some((m) => m.url === 'http://no.playwright/' && m.missing.includes('content-security-policy')));
  assert.throws(() => analyzeHar('{"nope":1}'), /HAR/);
});
