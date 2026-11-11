// TOOLS, CLI_COMMANDS and Analyzers wired end to end on the real fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sample, bytes } from './helpers.js';
import { TOOLS, CLI_COMMANDS, ANALYZERS, runManagedAnalyzers } from '../src/index.js';
import { analyze } from '../../core/src/index.js';

const tool = (n: string) => { const t = TOOLS.find((x) => x.name === n); assert.ok(t, n); return t!; };
const BROTLI = sample('dotnet', 'System.IO.Compression.Brotli.dll');

test('tools: names, schemas and descriptions', () => {
  assert.deepEqual(TOOLS.map((t) => t.name), ['managed_dotnet_info', 'managed_dotnet_types', 'managed_dotnet_method_il', 'managed_dotnet_search', 'managed_pyc_disasm', 'managed_pyinstaller_list', 'managed_pyinstaller_extract', 'managed_lua_info', 'managed_beam_info', 'managed_evm_disasm', 'managed_evm_selectors', 'managed_pinvoke_map', 'managed_compare_members']);
  for (const t of TOOLS) {
    assert.match(t.name, /^managed_[a-z_]+$/);
    assert.ok(t.description.length > 30);
    for (const [, s] of Object.entries(t.inputSchema)) assert.ok(['string', 'number', 'boolean', 'array', 'object'].includes(s.type) && s.description);
  }
});

test('tools: .NET tools give tokens and offsets', async () => {
  const info = await tool('managed_dotnet_info').run({ path: BROTLI }) as any;
  assert.equal(info.assembly.name, 'System.IO.Compression.Brotli');
  const types = await tool('managed_dotnet_types').run({ path: BROTLI, filter: 'BrotliEncoder', members: true, limit: 5 }) as any;
  assert.ok(types.items.length >= 1 && types.items[0].methods.length > 0 && types.items[0].methods.some((m: any) => m.fileOffset > 0));
  const il = await tool('managed_dotnet_method_il').run({ path: BROTLI, method: 'System.IO.Compression.BrotliEncoder::Dispose', format: 'text' }) as any;
  assert.match(il.text, /IL_0000: /);
  const s = await tool('managed_dotnet_search').run({ path: BROTLI, query: 'BrotliEncoderCompress', kind: 'pinvoke' }) as any;
  assert.ok(s.items.length >= 2);
  const x = await tool('managed_dotnet_search').run({ path: BROTLI, query: 'BrotliEncoderCompressStream', kind: 'xref' }) as any;
  assert.ok(x.items.length >= 1 && x.items[0].label.startsWith('IL_'));
  const b64 = await tool('managed_dotnet_info').run({ bytesBase64: Buffer.from(bytes(BROTLI)).toString('base64') }) as any;
  assert.equal(b64.assembly.version, '8.0.0.0');
});

test('tools: python, lua, beam and evm tools', async () => {
  const pyc = await tool('managed_pyc_disasm').run({ path: sample('python', 'sample_mod.3.11.pyc'), codePath: '<module>/risky', format: 'json' }) as any;
  assert.equal(pyc.code.name, 'risky');
  assert.ok(pyc.instructions.items.some((i: any) => i.opname === 'LOAD_GLOBAL'));
  const list = await tool('managed_pyinstaller_list').run({ path: sample('pyinstaller', 'mini-carchive.bin') }) as any;
  assert.deepEqual(list.entryPoints, ['fixture_main']);
  assert.equal(list.pyz.modules, 2);
  const dir = mkdtempSync(join(tmpdir(), 'revlens-managed-'));
  try {
    const ex = await tool('managed_pyinstaller_extract').run({ path: sample('pyinstaller', 'mini-carchive.bin'), outDir: dir }) as any;
    assert.equal(ex.written, 7);
    assert.ok(readdirSync(join(dir, 'PYZ.pyz_extracted', 'fixture_pkg')).includes('helper.pyc'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const one = await tool('managed_pyinstaller_extract').run({ path: sample('pyinstaller', 'mini-carchive.bin'), entry: 'data.txt' }) as any;
  assert.equal(Buffer.from(one.base64, 'base64').toString(), 'plain data file\n');
  const lua = await tool('managed_lua_info').run({ path: sample('lua', 'sample.5.4.luac') }) as any;
  assert.equal(lua.functionCount, 3);
  assert.match(lua.listing, /VARARGPREP/);
  const beam = await tool('managed_beam_info').run({ path: sample('beam', 'elixir_sup.beam') }) as any;
  assert.equal(beam.module, 'elixir_sup');
  const sel = await tool('managed_evm_selectors').run({ path: sample('evm', 'RevToken.runtime.hex') }) as any;
  assert.equal(sel.selectors.length, 9);
  const dis = await tool('managed_evm_disasm').run({ hex: '0x6080604052', limit: 2 }) as any;
  assert.deepEqual(dis.instructions.items.map((i: any) => i.op), ['PUSH1', 'PUSH1']);
  assert.equal(dis.instructions.total, 3);
});

async function cli(name: string, argv: string[]): Promise<{ code: number; out: string }> {
  const cmd = CLI_COMMANDS.find((c) => c.name === name)!;
  const lines: string[] = [];
  const orig = console.log;
  console.log = (s: string) => { lines.push(String(s)); };
  try { return { code: await cmd.run(argv), out: lines.join('\n') }; } finally { console.log = orig; }
}

test('cli: commands print text and JSON', async () => {
  assert.deepEqual(CLI_COMMANDS.map((c) => c.name), ['dotnet', 'pyc', 'pyinstaller', 'lua', 'beam', 'evm', 'pinvoke-map', 'compare-members']);
  let r = await cli('dotnet', [BROTLI]);
  assert.equal(r.code, 0); assert.match(r.out, /targetFramework: \.NETCoreApp,Version=v8\.0/);
  r = await cli('dotnet', [BROTLI, 'il', '0x06000001', '--json']);
  assert.equal(JSON.parse(r.out).token, '0x06000001');
  r = await cli('pyc', [sample('python', 'sample_mod.3.13.pyc')]);
  assert.match(r.out, /^# Python 3\.13/);
  r = await cli('pyinstaller', [sample('pyinstaller', 'mini-carchive.bin')]);
  assert.match(r.out, /PYZ 2 modules/);
  r = await cli('lua', [sample('lua', 'sample.luajit2.1.luac')]);
  assert.match(r.out, /^luajit luajit2\.1/);
  r = await cli('beam', [sample('beam', 'Elixir.Version.beam'), '--json']);
  assert.equal(JSON.parse(r.out).module, 'Elixir.Version');
  r = await cli('evm', [sample('evm', 'RevToken.runtime.hex')]);
  assert.match(r.out, /0xa9059cbb transfer\(address,uint256\)/);
  r = await cli('evm', []);
  assert.equal(r.code, 2);
});

test('analyzers: plug into a core report and fill report.meta.managed', async () => {
  assert.deepEqual(ANALYZERS.map((a) => a.id), ['managed-dotnet', 'managed-python', 'managed-lua', 'managed-beam', 'managed-evm']);
  const cases: [string, string, string][] = [
    [BROTLI, 'dotnet', 'managed.dotnet.identity'],
    [sample('python', 'sample_mod.3.10.pyc'), 'python', 'managed.python.pyc'],
    [sample('pyinstaller', 'mini-carchive.bin'), 'python', 'managed.python.pyinstaller'],
    [sample('lua', 'sample.5.2.luac'), 'lua', 'managed.lua.chunk'],
    [sample('beam', 'elixir_sup.beam'), 'beam', 'managed.beam.module'],
    [sample('evm', 'RevProxy.runtime.hex'), 'evm', 'managed.evm.proxy'],
  ];
  for (const [file, key, finding] of cases) {
    const b = bytes(file);
    const report = await analyze(b, { name: file, analyzers: [] });
    await runManagedAnalyzers(b, report, file);
    const m = report.meta.managed as Record<string, unknown>;
    assert.ok(m && m[key], `${file} -> meta.managed.${key}`);
    assert.ok(report.findings.some((f) => f.id === finding), `${file} -> ${finding}`);
    JSON.stringify(report);
  }
});
