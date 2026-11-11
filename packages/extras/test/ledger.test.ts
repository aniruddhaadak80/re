// Evidence ledger: claims bound to byte hashes, verify, tamper detection, hash chain, persistence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Ledger, evidenceFor, TOOLS, resetLedger } from '../src/node.js';
import { fx, S } from './helpers.js';

const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

test('evidence hashes are plain SHA-256 of the file and of the byte range (checked with node:crypto)', () => {
  const b = fx('hello-res.exe');
  const e = evidenceFor(b, 0, 64, 'hello-res.exe');
  assert.equal(e.fileSha256, sha(b));
  assert.equal(e.sha256, sha(b.subarray(0, 64)));
  assert.equal(e.preview, Buffer.from(b.subarray(0, 32)).toString('hex'));
  assert.throws(() => evidenceFor(b, b.length - 2, 10));
});

test('claims verify against the same bytes and are refuted after one byte changes', async () => {
  const b = fx('hello-res.exe');
  const l = new Ledger();
  const c = l.claim({ statement: 'The file is a PE (MZ at offset 0)', evidence: [evidenceFor(b, 0, 2, 'a.exe')], check: { kind: 'bytes-at', offset: 0, hex: '4d5a' } });
  const u = l.unknown({ statement: 'What does revlens_add do?' });
  let r = await l.verify(async () => b);
  assert.equal(r[0]!.verdict, 'VERIFIED');
  assert.equal(l.items().find((x) => x.id === c.id)!.status, 'verified');
  const t = b.slice(); t[1] = 0x00;
  r = await l.verify(async () => t);
  assert.equal(r[0]!.verdict, 'REFUTED');
  r = await l.verify(async () => undefined);
  assert.equal(r[0]!.verdict, 'UNVERIFIABLE');
  assert.equal(l.items().find((x) => x.id === c.id)!.status, 'stale');
  l.update(u.id, 'resolved', 'it adds two ints', [c.id]);
  const s = l.summary();
  assert.equal(s.claims, 1); assert.equal(s.unknowns, 1); assert.equal(s.openUnknowns, 0);
  assert.equal(l.items().find((x) => x.id === c.id)!.history.length, 4);
});

test('export and import keep the hash chain; any edit is detected', () => {
  const b = fx('board.dtb');
  const l = new Ledger();
  l.claim({ statement: 'DTB magic', evidence: [evidenceFor(b, 0, 4, 'board.dtb')] });
  l.unknown({ statement: 'Which UART driver?' });
  const ex = l.export();
  assert.equal(Ledger.checkChain(ex.entries), -1);
  const again = Ledger.import(JSON.parse(JSON.stringify(ex)));
  assert.equal(again.head, l.head);
  const forged = JSON.parse(JSON.stringify(ex));
  forged.entries[0].statement = 'DTB magic (edited)';
  assert.throws(() => Ledger.import(forged), /hash chain broken at entry 0/);
  const reordered = JSON.parse(JSON.stringify(ex));
  reordered.entries.reverse();
  assert.throws(() => Ledger.import(reordered));
  assert.match(l.toMarkdown(), /\| C1 \| claim \| asserted \| DTB magic \|/);
});

test('ledger tools persist to ledgerPath and re-verify a moved file', async () => {
  resetLedger();
  const dir = mkdtempSync(join(tmpdir(), 'revlens-ledger-'));
  const ledgerPath = join(dir, 'case.ledger.json');
  const file = join(dir, 'x.elf');
  copyFileSync(join(S, 'demo-x64.elf'), file);
  const rec = await tool('x_ledger_record').run({ path: file, statement: 'ELF magic', ranges: [{ offset: 0, length: 4 }], check: { kind: 'contains-string', value: 'revlens' }, ledgerPath }) as { id: string };
  assert.equal(rec.id, 'C1');
  await tool('x_ledger_unknown').run({ statement: 'Who calls early_init?', ledgerPath });
  let v = await tool('x_ledger_verify').run({ ledgerPath }) as { results: { verdict: string }[] };
  assert.equal(v.results[0]!.verdict, 'VERIFIED');
  const moved = join(dir, 'moved.elf');
  copyFileSync(file, moved);
  const b = new Uint8Array(readFileSync(file)); b[0] = 0; writeFileSync(file, b);
  v = await tool('x_ledger_verify').run({ ledgerPath }) as { results: { verdict: string }[] };
  assert.equal(v.results[0]!.verdict, 'REFUTED');
  v = await tool('x_ledger_verify').run({ ledgerPath, files: { [file]: moved } }) as { results: { verdict: string }[] };
  assert.equal(v.results[0]!.verdict, 'VERIFIED');
  const list = await tool('x_ledger_list').run({ ledgerPath }) as { summary: { claims: number; unknowns: number; entries: number } };
  assert.equal(list.summary.claims, 1); assert.equal(list.summary.unknowns, 1);
  const saved = JSON.parse(readFileSync(ledgerPath, 'utf8'));
  assert.equal(saved.schema, 'revlens/ledger@1');
  assert.equal(Ledger.checkChain(saved.entries), -1);
  const md = await tool('x_ledger_export').run({ ledgerPath, format: 'markdown' }) as { markdown: string };
  assert.match(md.markdown, /ELF magic/);
});

test('ledger input limits', () => {
  const l = new Ledger(3);
  assert.throws(() => l.claim({ statement: '', evidence: [] }));
  assert.throws(() => l.claim({ statement: 'x', evidence: [] }));
  assert.throws(() => l.update('nope', 'resolved'));
  assert.throws(() => l.claim({ statement: 'x', evidence: [], check: { kind: 'sha256-is', value: 'a' }, links: ['missing'] }));
  l.unknown({ statement: 'a' }); l.unknown({ statement: 'b' }); l.unknown({ statement: 'c' });
  assert.throws(() => l.unknown({ statement: 'd' }), /capped/);
});
