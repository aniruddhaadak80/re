// Property based fuzzing with fast-check. Random bytes, text and rule sources must never crash
// the analyzers, hang yara-lite, or leak markup into the HTML report.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { analyze, scanRules, parseRules, toHTML, toSARIF, STARTER_RULES } from '../src/index.js';

const enc = (s: string) => new TextEncoder().encode(s);
const RUNS = Number(process.env.REVLENS_FUZZ_RUNS ?? 60);

test('fuzz: analyze accepts any bytes and returns a well formed report', async () => {
  await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 4096 }), fc.string({ maxLength: 40 }), async (bytes, name) => {
    const r = await analyze(bytes, { name: name || 'x' });
    assert.equal(r.file.size, bytes.length);
    assert.ok(Array.isArray(r.findings));
    JSON.stringify(toSARIF(r));
  }), { numRuns: RUNS });
});

test('fuzz: analyze accepts any JavaScript like text', async () => {
  const piece = fc.constantFrom('eval(', 'atob(', '_0x1a2b', 'sk-', '@', '.', '/', 'http://', '"', '<', '>', '$=~[];', 'UPX!', '\n', ' ', 'a');
  await fc.assert(fc.asyncProperty(fc.array(piece, { maxLength: 400 }), async (parts) => {
    const r = await analyze(enc(parts.join('')), { name: 'fuzz.js' });
    assert.ok(r.timings.total >= 0);
  }), { numRuns: RUNS });
});

test('fuzz: yara-lite parses or rejects any rule text with an Error', () => {
  const piece = fc.constantFrom('rule ', 'R', ' { ', ' } ', 'meta: ', 'strings: ', 'condition: ', '$a = ', '"x"', '{ 41 [0-] 42 }', '/a+/', '(', ')', ' and ', ' or ', 'not ', 'any of them', '#a > 1', '/*', '*/', '//', '\n', '__proto__ = "1"');
  fc.assert(fc.property(fc.array(piece, { maxLength: 80 }), fc.uint8Array({ maxLength: 512 }), (parts, data) => {
    const text = parts.join('');
    try { scanRules(data, text); } catch (e) { assert.ok(e instanceof Error); }
    try { for (const r of parseRules(text)) assert.equal(Object.getPrototypeOf(r.meta), Object.prototype); } catch (e) { assert.ok(e instanceof Error); }
  }), { numRuns: RUNS * 4 });
  assert.ok(Array.isArray(scanRules(new Uint8Array(0), STARTER_RULES)));
});

test('fuzz: toHTML never echoes markup from the file name', async () => {
  await fc.assert(fc.asyncProperty(fc.string({ maxLength: 60 }), async (s) => {
    const name = `<x${s}>`;
    const html = toHTML(await analyze(enc(s), { name }));
    assert.ok(!html.includes(name), 'raw name is escaped');
  }), { numRuns: RUNS });
});
