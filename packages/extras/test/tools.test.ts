// Tool, CLI and analyzer contracts: schemas, names, paging, JSON safety, CLI output, findings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { analyze, detectFormat, type AnalyzerContext } from '@revlens/core';
import { TOOLS, CLI_COMMANDS, ANALYZERS, renderText, jsonSafe } from '../src/node.js';
import { fx, S, cached } from './helpers.js';

test('TOOLS: x_ prefix, unique snake_case names, described schemas, path or bytes input', () => {
  const names = TOOLS.map((t) => t.name);
  assert.equal(new Set(names).size, names.length);
  assert.ok(TOOLS.length >= 30);
  for (const t of TOOLS) {
    assert.match(t.name, /^x_[a-z0-9_]+$/);
    assert.ok(t.description.length > 30, t.name);
    assert.doesNotMatch(t.description, /\u2014|!/, t.name);
    for (const [k, s] of Object.entries(t.inputSchema)) { assert.ok(['string', 'number', 'boolean', 'array', 'object'].includes(s.type), `${t.name}.${k}`); assert.ok(s.description.length > 3); }
  }
});

test('every file tool returns JSON serialisable output on its fixture', async () => {
  const cases: [string, Record<string, unknown>][] = [
    ['x_container', { path: join(S, 'hello-arm64.macho') }], ['x_checksec', { path: join(S, 'hello-res.exe') }], ['x_pe_inspect', { path: join(S, 'hello-res.exe') }],
    ['x_pe_resources', { path: join(S, 'hello-res.exe') }], ['x_elf_inspect', { path: join(S, 'demo-x64.elf') }], ['x_macho_inspect', { path: join(S, 'hello-arm64.macho') }],
    ['x_kernel_module', { path: join(S, 'demo-x64.elf'), config: true }], ['x_firmware_parse', { path: join(S, 'board.dtb'), kind: 'fdt' }], ['x_search_bytes', { path: join(S, 'fw-blob.bin'), text: 'RevLens' }],
    ['x_address_map', { path: join(S, 'hello-res.exe'), at: 1024 }], ['x_go_symbols', { path: join(S, 'go-hello-stripped.elf'), limit: 5 }], ['x_model_inspect', { path: join(S, 'tiny.npy') }],
  ];
  for (const [n, i] of cases) {
    const out = await TOOLS.find((t) => t.name === n)!.run(i);
    const s = JSON.stringify(out);
    assert.ok(s && s.length > 2, n);
    assert.deepEqual(JSON.parse(s), JSON.parse(JSON.stringify(jsonSafe(out))), n);
  }
});

test('paging: x_go_symbols honours offset and limit', async () => {
  const t = TOOLS.find((x) => x.name === 'x_go_symbols')!;
  const a = await t.run({ path: join(S, 'go-hello-stripped.elf'), offset: 0, limit: 10 }) as { functions: { total: number; items: { name: string }[] } };
  const b = await t.run({ path: join(S, 'go-hello-stripped.elf'), offset: 5, limit: 10 }) as { functions: { items: { name: string }[] } };
  assert.equal(a.functions.items.length, 10);
  assert.equal(a.functions.items[5]!.name, b.functions.items[0]!.name);
  assert.ok(a.functions.total > 1000);
});

test('tools accept base64 bytes instead of a path', async () => {
  const b = Buffer.from(fx('add.jsc')).toString('base64');
  const r = await TOOLS.find((x) => x.name === 'x_v8_inspect')!.run({ bytes: b }) as { kind: string };
  assert.equal(r.kind, 'v8-code-cache');
});

async function capture(f: () => Promise<number>): Promise<{ code: number; out: string }> {
  const orig = console.log; let out = '';
  console.log = (...a: unknown[]) => { out += a.join(' ') + '\n'; };
  try { const code = await f(); return { code, out }; } finally { console.log = orig; }
}

test('CLI_COMMANDS: names, usage, --json output and text output', async () => {
  assert.ok(CLI_COMMANDS.length >= 25);
  for (const c of CLI_COMMANDS) { assert.match(c.name, /^x-[a-z0-9-]+$/); assert.match(c.usage, /^revlens x-/); }
  const cs = CLI_COMMANDS.find((c) => c.name === 'x-checksec')!;
  const j = await capture(() => cs.run([join(S, 'demo-x64.elf'), '--json']));
  assert.equal(j.code, 0);
  assert.equal(JSON.parse(j.out).format, 'elf');
  const t = await capture(() => cs.run([join(S, 'demo-x64.elf')]));
  assert.match(t.out, /RELRO/);
  const d = await capture(() => CLI_COMMANDS.find((c) => c.name === 'x-demangle')!.run(['_ZN3foo3barEv', '--json']));
  assert.equal(JSON.parse(d.out).items[0].output, 'foo::bar()');
  const errOrig = console.error; console.error = () => {};
  try { assert.equal(await cs.run(['/no/such/file']), 1); } finally { console.error = errOrig; }
  assert.match(renderText({ a: [1, 2], b: { c: 'd' } }), /a: 1, 2\nb: \n  c: d/);
});

async function runAll(bytes: Uint8Array, name: string) {
  const report = await analyze(bytes, { name });
  const ctx = { bytes, name, format: detectFormat(bytes, name), options: { maxStrings: 400, recurse: false, maxDepth: 1 }, depth: 0, report } as AnalyzerContext;
  for (const a of ANALYZERS) if (a.applies(ctx)) await a.run(ctx);
  return report;
}

test('analyzers add meta.extras and findings through the core Analyzer contract', async () => {
  const pe = await runAll(fx('hello-res.exe'), 'hello-res.exe');
  const m = pe.meta.extras as Record<string, any>;
  assert.equal(m.versionInfo.fileVersion, '1.2.3.4');
  assert.ok(pe.findings.some((f) => f.id === 'extras.pe-unsigned'));
  JSON.stringify(pe);
  const go = await runAll(fx('go-hello-stripped.elf'), 'go');
  assert.ok((go.meta.extras as any).go.functions > 1000);
  const rust = await runAll(fx('jiter-0.5.0.so'), 'jiter.so');
  assert.equal((rust.meta.extras as any).rust.rustcVersion, '1.79.0 (129f3b996 2024-06-10)');
  const fw = await runAll(fx('fw-blob.bin'), 'fw.bin');
  assert.ok(fw.findings.some((f) => f.id === 'extras.firmware-images'));
  const jsc = await runAll(fx('add.jsc'), 'add.jsc');
  assert.equal((jsc.meta.extras as any).jsEngine.kind, 'v8-code-cache');
  const lnk = await runAll(fx('notepad.lnk'), 'notepad.lnk');
  assert.equal((lnk.meta.extras as any).lnk.target, 'C:\\Windows\\System32\\notepad.exe');
  assert.ok(!lnk.findings.some((f) => f.id === 'extras.lnk-lolbin'));
  const signed = cached('strings64.exe');
  if (signed) {
    const r = await runAll(signed, 'strings64.exe');
    assert.equal((r.meta.extras as any).authenticode[0].digestMatches, true);
    const bad = signed.slice(); bad[0x600] = bad[0x600]! ^ 1;
    const r2 = await runAll(bad, 'strings64.exe');
    assert.ok(r2.findings.some((f) => f.id === 'extras.authenticode-digest-mismatch' && f.severity === 'high'));
  }
});
