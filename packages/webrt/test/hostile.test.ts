import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { analyzePcap, readAsar, SqliteFile, runSelect, decodeMappings, recoverSources, deobfuscate, unpackBundle, findEndpoints, analyzeHar, parseClientHello, parseDns, safeRelPath, InputError, auditElectron, readFuses, FUSE_SENTINEL } from '../src/index.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const load = (f: string) => new Uint8Array(readFileSync(join(S, f)));

/** Only InputError (clean rejection) or success are acceptable. */
function safe(fn: () => unknown): void {
  try { fn(); } catch (e) { if (!(e instanceof InputError) && !(e instanceof SyntaxError) && !(e instanceof URIError)) throw e; }
}

test('random bytes never crash the binary parsers', () => {
  fc.assert(fc.property(fc.uint8Array({ maxLength: 4096 }), (b) => {
    safe(() => analyzePcap(b));
    safe(() => readAsar(b));
    safe(() => new SqliteFile(b).tables());
    safe(() => parseClientHello(b));
    safe(() => parseDns(b));
    safe(() => readFuses(b));
  }), { numRuns: 400 });
});

test('truncated and bit-flipped real files are rejected cleanly', () => {
  for (const f of ['dns_udp.pcap', 'chrome-34-google.pcap', 'pcapng-multi-interface.pcapng', 'electron/app.asar', 'fixture.sqlite']) {
    const b = load(f);
    for (const cut of [0, 3, 15, 24, 40, 99, 100, 101, Math.floor(b.length / 3), b.length - 1]) {
      const t = b.slice(0, Math.max(0, cut));
      safe(() => analyzePcap(t)); safe(() => readAsar(t)); safe(() => { const d = new SqliteFile(t); d.tables(); runSelect(d, 'SELECT * FROM users LIMIT 5'); });
    }
    fc.assert(fc.property(fc.integer({ min: 0, max: b.length - 1 }), fc.integer({ min: 0, max: 255 }), (pos, val) => {
      const m = b.slice(); m[pos] = val;
      safe(() => analyzePcap(m)); safe(() => readAsar(m)); safe(() => { const d = new SqliteFile(m); d.tables(); runSelect(d, 'SELECT * FROM events WHERE id > 990'); });
    }), { numRuns: 150 });
  }
});

test('huge counts and loops are bounded', () => {
  // pcap record claiming a 1 GB packet
  const p = new Uint8Array(40);
  new DataView(p.buffer).setUint32(0, 0xa1b2c3d4, false); new DataView(p.buffer).setUint32(20, 1, true);
  new DataView(p.buffer).setUint32(24 + 8, 0x40000000, true);
  const r = analyzePcap(p);
  assert.equal(r.packetCount, 0); assert.ok(r.warnings.length > 0);
  // DNS name compression pointer loop
  const dns = new Uint8Array([0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]);
  assert.equal(parseDns(dns), undefined);
  // ASAR header claiming a 4 GB header
  const a = new Uint8Array(32); const dv = new DataView(a.buffer);
  dv.setUint32(0, 4, true); dv.setUint32(4, 0xffffffff, true); dv.setUint32(8, 0xfffffffb, true); dv.setUint32(12, 0xfffffff0, true);
  assert.throws(() => readAsar(a), InputError);
  // sqlite page that points at itself as a child
  const db = load('fixture.sqlite').slice();
  const users = new SqliteFile(db).tables().find((t) => t.name === 'events')!;
  const off = (users.rootPage - 1) * 1024;
  if (db[off] === 5) { new DataView(db.buffer).setUint32(off + 8, users.rootPage, false); assert.throws(() => new SqliteFile(db).forEachRow('events', () => true), InputError); }
  // VLQ garbage and absurd source maps
  assert.throws(() => decodeMappings('!!!!'), InputError);
  assert.throws(() => decodeMappings('gggggggggggggggg'), InputError);
  const sm = recoverSources({ version: 3, sources: Array.from({ length: 50_000 }, (_, i) => `../../../etc/x${i}`), sourcesContent: Array.from({ length: 50_000 }, () => 'x'), mappings: '' }, { maxFiles: 100 });
  assert.equal(sm.files.length, 100);
  for (const f of sm.files) assert.ok(!f.path.includes('..'));
  // fuse wire with a length byte past the end
  const fw = new Uint8Array([...new TextEncoder().encode(FUSE_SENTINEL), 0x01, 0xff, 0x31]);
  assert.equal(Object.keys(readFuses(fw)!.fuses).length, 1);
});

test('deeply nested and pathological JavaScript stays within limits', () => {
  const deep = '['.repeat(5000) + ']'.repeat(5000);
  safe(() => deobfuscate(deep));
  safe(() => findEndpoints('x' + '+x'.repeat(20000)));
  safe(() => unpackBundle('(function(){})([' + 'function(a,b,c){},'.repeat(3000) + '])'));
  // a fake string array whose rotation never matches must not loop forever
  const never = "function A(){const a=['x','y'];A=function(){return a;};return A();}function D(i){i=i-1;const a=A();return a[i];}(function(f,t){const g=f();while(!![]){try{const v=parseInt(D(1));if(v===t)break;else g.push(g.shift());}catch(e){g.push(g.shift());}}}(A,12345));console.log(D(1));";
  const d = deobfuscate(never);
  assert.ok(d.notes.some((n) => n.includes('never matched')));
  fc.assert(fc.property(fc.string({ maxLength: 300 }), (s) => { safe(() => deobfuscate(s)); safe(() => findEndpoints(s)); safe(() => auditElectron({ files: [{ path: 'm.js', code: s }] })); }), { numRuns: 200 });
});

test('SQL parser and HAR reader reject hostile input', () => {
  const d = new SqliteFile(load('fixture.sqlite'));
  safe(() => runSelect(d, 'SELECT * FROM users WHERE ' + '('.repeat(500) + '1' + ')'.repeat(500)));
  assert.throws(() => runSelect(d, 'SELECT * FROM users WHERE ' + '('.repeat(500) + '1' + ')'.repeat(500)), InputError);
  fc.assert(fc.property(fc.string({ maxLength: 200 }), (s) => { safe(() => runSelect(d, s)); safe(() => analyzeHar(s)); }), { numRuns: 300 });
  assert.equal(safeRelPath('webpack:///../../etc/passwd'), 'etc/passwd');
  assert.equal(safeRelPath('C:\\Windows\\..\\x.js'), 'Windows/x.js');
  assert.equal(safeRelPath('/../..'), '');
});
