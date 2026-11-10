// Hostile input tests: every case here used to take quadratic or exponential time, or could
// inject markup, before 0.1.1. Each one must finish quickly and stay escaped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, scanRules, parseRules, assertSafeRegex, toHTML, STARTER_RULES, YARA_LIMITS } from '../src/index.js';

const enc = (s: string) => new TextEncoder().encode(s);
const timed = async (label: string, ms: number, fn: () => unknown) => {
  const t = performance.now();
  await fn();
  const took = performance.now() - t;
  assert.ok(took < ms, `${label} took ${Math.round(took)} ms, budget ${ms} ms`);
};

test('analyzers stay fast on pathological text', async () => {
  const cases: [string, string][] = [
    ['hex identifiers below threshold', 'var _0xabcd = 1; '.repeat(39) + 'x'.repeat(200_000)],
    ['openai key prefix flood', 'sk-'.repeat(200_000)],
    ['email dots before an at sign', 'a.'.repeat(100_000) + '@'],
    ['paths that never end in a segment', '/a'.repeat(100_000) + '/'],
    ['jsfuck like lines', ('[]()!+'.repeat(30) + '\n').repeat(5_000)],
  ];
  for (const [label, text] of cases) await timed(label, 8_000, () => analyze(enc(text), { name: 'hostile.js' }));
});

test('yara-lite rejects regexes that can backtrack exponentially', () => {
  for (const bad of ['(a+)+$', '(a|aa)*b', '(?:x*y?)+', '(\\w+\\s?)*$', '(a)\\1']) {
    assert.throws(() => assertSafeRegex(bad), /exponential|backreference/, bad);
    assert.throws(() => parseRules(`rule R { strings: $r = /${bad}/ condition: $r }`), /rule R/);
  }
  for (const ok of ['hel+o\\s+w', '(?:\\d{1,3}\\.){3}\\d{1,3}', 'eval\\s*\\(\\s*(atob|unescape)\\s*\\(', '-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+\\/=]{40,}']) {
    assert.doesNotThrow(() => assertSafeRegex(ok), ok);
  }
  assert.doesNotThrow(() => parseRules(STARTER_RULES));
});

test('yara-lite bounds hostile rule text and hostile data', async () => {
  assert.throws(() => parseRules('x'.repeat(YARA_LIMITS.maxRuleText + 1)), /limit/);
  await timed('unterminated comments', 3_000, () => parseRules('/*'.repeat(200_000)));
  await timed('unterminated strings', 3_000, () => parseRules('rule R { strings: ' + '$a = "'.repeat(50_000) + ' condition: true }'));
  await timed('rule header flood', 3_000, () => parseRules('rule a : ' + 'x '.repeat(100_000)));
  const nested = 'rule N { strings: $a = "q" condition: ' + '('.repeat(60) + '$a' + ')'.repeat(60) + ' }';
  await timed('nested parentheses', 3_000, () => { try { scanRules(enc('q'), nested); } catch { /* too complex is fine */ } });
  const data = new Uint8Array(2_000_000).fill(0x41);
  await timed('hex jumps over repetitive data', 8_000, () => scanRules(data, 'rule H { strings: $h = { 41 [0-] 41 [0-] 41 [0-] 42 } condition: $h }'));
  await timed('long needle over repetitive data', 8_000, () => scanRules(data, `rule T { strings: $t = "${'A'.repeat(1000)}B" condition: $t }`));
});

test('toHTML escapes everything that comes from the file', async () => {
  const name = '<img src=x onerror=alert(1)>"\'`.js';
  const r = await analyze(enc('const x = "<script>alert(1)</script>"; eval(atob("YWxlcnQoMSk="));'), { name });
  r.components.push({ name: '<b>evil</b>', version: '"><svg onload=alert(1)>', ecosystem: 'npm', confidence: 1 } as (typeof r.components)[number]);
  const html = toHTML(r);
  assert.ok(!html.includes('<img src=x'), 'file name is escaped');
  assert.ok(!html.includes('<b>evil</b>') && !html.includes('<svg onload'), 'component fields are escaped');
  assert.ok(!/<script/i.test(html), 'no script tags');
  assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
});
