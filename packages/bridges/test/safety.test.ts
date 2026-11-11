// Safety tests: no shell, argument arrays, timeouts, output caps, the allowExecution gate,
// input validation, and parsers that stay fast on hostile input (no ReDoS).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { runTool, spawnPlan, checkArgs, UnsafeArgumentError, EXEC_LIMITS } from '../src/exec.ts';
import {
  parseR2Functions, parseR2Disasm, parseR2Xrefs, parseObjdumpDisasm, parseObjdumpSections, parseObjdumpSymbols, parseGdbBatch,
  parseLldbBatch, parseBinwalkTable, parseBinwalkJson, parseFridaDevices, parseFridaOutput, parseFridaPs, parseAdbDevices,
  parseAdbPackages, parseAdbPmPath, parseGhidraExport, extractJson, buildHookScript, HookParamError,
} from '../src/index.ts';
import { TOOLS } from '../src/tools.ts';
import { gdbArgs, lldbArgs } from '../src/providers/dynamic.ts';
import { checkR2Target } from '../src/providers/radare2.ts';
import { stripJsonc } from '../src/setup.ts';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, '..', 'src');
const node = process.execPath;

function srcFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? srcFiles(join(dir, e.name)) : e.name.endsWith('.ts') ? [join(dir, e.name)] : []);
}

test('source never uses a shell or exec/execSync', () => {
  for (const f of srcFiles(SRC)) {
    const s = readFileSync(f, 'utf8');
    assert.doesNotMatch(s, /shell:\s*true/, f);
    assert.doesNotMatch(s, /\bexecSync\b|(?<![.\w])exec\(|spawnSync\(/, f);
    assert.doesNotMatch(s, /\beval\(|new Function\(/, f);
  }
  const exec = readFileSync(join(SRC, 'exec.ts'), 'utf8');
  assert.match(exec, /shell: false/);
});

test('arguments pass through verbatim, shell metacharacters are not interpreted', async () => {
  const evil = ['$(touch /tmp/revlens-pwned)', '`id`', 'a; rm -rf /', '| cat /etc/passwd', '&& echo hi', "'\"", '*'];
  const r = await runTool(node, ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', ...evil]);
  assert.equal(r.code, 0);
  assert.deepEqual(JSON.parse(r.stdout), evil);
  assert.equal(existsSync('/tmp/revlens-pwned'), false);
});

test('timeouts kill the child and are reported', async () => {
  const r = await runTool(node, ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 400 });
  assert.equal(r.timedOut, true);
  assert.ok(r.durationMs < 5000);
});

test('timeouts kill grandchildren too (process group)', async () => {
  const r = await runTool(node, ['-e', `require('child_process').spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], {stdio:'inherit'}); setInterval(()=>{},1000)`], { timeoutMs: 500 });
  assert.equal(r.timedOut, true);
});

test('output is capped per stream', async () => {
  const r = await runTool(node, ['-e', 'process.stdout.write("x".repeat(5_000_000))'], { maxOutputBytes: 1000 });
  assert.equal(r.stdout.length, 1000);
  assert.equal(r.truncated, true);
});

test('spawn errors do not throw', async () => {
  const r = await runTool('/nonexistent/revlens-tool', ['x']);
  assert.match(r.error!, /ENOENT/);
  assert.notEqual(r.code, 0);
});

test('argument checks: NUL bytes, huge args and counts are refused', async () => {
  assert.throws(() => checkArgs(['a\0b']), UnsafeArgumentError);
  assert.throws(() => checkArgs(['x'.repeat(EXEC_LIMITS.maxArgLength + 1)]), UnsafeArgumentError);
  assert.throws(() => checkArgs(new Array(EXEC_LIMITS.maxArgs + 1).fill('a')), UnsafeArgumentError);
  const r = await runTool(node, ['a\0b']);
  assert.match(r.error!, /NUL/);
});

test('Windows .bat launchers refuse cmd metacharacters and quote the rest', () => {
  assert.throws(() => spawnPlan('C:/jadx/bin/jadx.bat', ['a&calc'], 'win32'), UnsafeArgumentError);
  assert.throws(() => spawnPlan('C:/g/analyzeHeadless.bat', ['%PATH%'], 'win32'), UnsafeArgumentError);
  const p = spawnPlan('C:/jadx/bin/jadx.bat', ['-d', 'C:/out dir', 'app.apk'], 'win32');
  assert.equal(p.verbatim, true);
  assert.deepEqual(p.args.slice(0, 3), ['/d', '/s', '/c']);
  assert.equal(p.args[3], '""C:/jadx/bin/jadx.bat" "-d" "C:/out dir" "app.apk""');
  assert.deepEqual(spawnPlan('/usr/bin/r2', ['-q', 'x'], 'linux'), { file: '/usr/bin/r2', args: ['-q', 'x'], verbatim: false });
});

test('dynamic tools refuse to run without allowExecution: true', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'rl-safe-'));
  const f = join(dir, 'prog');
  writeFileSync(f, 'x');
  try {
    for (const name of ['bridge_frida_run', 'bridge_gdb_run']) {
      const t = TOOLS.find((x) => x.name === name)!;
      for (const allow of [undefined, false, 'true', 1]) {
        const r = await t.run({ path: f, spawn: f, pid: 1, template: 'module-list', breakpoints: ['main'], allowExecution: allow }) as Record<string, unknown>;
        assert.equal(r.ok, false, `${name} ${String(allow)}`);
        assert.equal(r.blocked, true);
        assert.match(String(r.error), /allowExecution: true/);
      }
    }
    const lldb = await TOOLS.find((x) => x.name === 'bridge_gdb_run')!.run({ path: f, breakpoints: ['main'], debugger: 'lldb' }) as Record<string, unknown>;
    assert.equal(lldb.blocked, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('tool inputs that could inject commands are rejected as input errors', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'rl-safe-'));
  const f = join(dir, 'prog');
  writeFileSync(f, 'x');
  try {
    const bad: [string, Record<string, unknown>][] = [
      ['bridge_r2_disasm', { path: f, function: 'main; !id' }],
      ['bridge_r2_decompile', { path: f, function: 'main @ 0x0' }],
      ['bridge_r2_xrefs', { path: f, function: 'a|b' }],
      ['bridge_gdb_run', { path: f, breakpoints: ['main\nshell id'], allowExecution: true }],
      ['bridge_gdb_run', { path: f, breakpoints: ['main'], registers: ['x0; shell id'], allowExecution: true }],
      ['bridge_gdb_run', { path: f, breakpoints: ['main'], memory: { base: '$sp; shell id' }, allowExecution: true }],
      ['bridge_gdb_run', { path: f, breakpoints: ['main'], args: ['a\nshell id'], allowExecution: true }],
      ['bridge_frida_run', { template: 'trace-native-export', params: { export: 'open"); Process.kill(1); ("' }, pid: 1, allowExecution: true }],
      ['bridge_frida_run', { template: 'module-list', name: '-l evil.js', allowExecution: true }],
      ['bridge_frida_run', { template: 'module-list', allowExecution: true }],
      ['bridge_frida_run', { template: 'nope', pid: 1, allowExecution: true }],
      ['bridge_adb_pull_apk', { package: 'com.x; reboot' }],
      ['bridge_adb_logcat', { tag: 'a b' }],
      ['bridge_jadx_search', { path: f, query: '' }],
      ['bridge_jadx_decompile', { path: f, className: '../../etc/passwd' }],
      ['bridge_ilspy_decompile', { path: f, typeName: 'A; rm' }],
      ['bridge_objdump', { path: f, function: '--help' }],
      ['bridge_objdump', { path: f, startAddress: '1; id' }],
      ['bridge_ghidra_decompile', { path: f, functions: ['a b'] }],
      ['bridge_r2_functions', { path: join(dir, 'missing') }],
      ['bridge_r2_functions', { path: 'a\0b' }],
      ['bridge_setup_mcp', { client: 'notepad' }],
    ];
    for (const [name, input] of bad) {
      const t = TOOLS.find((x) => x.name === name)!;
      const r = await t.run(input) as Record<string, unknown>;
      // Either the input was refused, or the tool is not installed here; it must never run.
      if (r.available === false) continue;
      assert.equal(r.ok, false, `${name} ${JSON.stringify(input)} -> ${JSON.stringify(r).slice(0, 300)}`);
      assert.ok(r.inputError === true || r.blocked === true, `${name} ${JSON.stringify(r)}`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.throws(() => checkR2Target('main;?'), /function must be/);
  assert.equal(checkR2Target('sym.check_password'), 'sym.check_password');
});

test('debugger argument builders keep program arguments out of the command language', () => {
  const plan = { breakpoints: ['main', '0x401000'], registers: ['x0'], bt: 4, mem: { base: '$sp', count: 8 }, stops: 2, args: ['--weird', '$(id)'] };
  const g = gdbArgs('/bin/prog', plan);
  assert.ok(g.includes('break *0x401000'));
  assert.deepEqual(g.slice(g.indexOf('--args')), ['--args', '/bin/prog', '--weird', '$(id)']);
  const l = lldbArgs('/bin/prog', plan);
  assert.ok(l.includes('breakpoint set -a 0x401000'));
  assert.deepEqual(l.slice(l.lastIndexOf('--')), ['--', '/bin/prog', '--weird', '$(id)']);
  assert.ok(!l.some((a) => a.includes('$(id)') && a !== '$(id)'));
});

test('hook parameters are embedded as JSON, never as code', () => {
  assert.throws(() => buildHookScript('trace-native-export', { export: "x'); Process.exit(); ('" }), HookParamError);
  assert.throws(() => buildHookScript('java-method-log', { className: 'a.B;', method: 'm' }), HookParamError);
  const s = buildHookScript('trace-native-export', { export: 'SSL_write', module: 'libssl.so.3', args: 99 });
  assert.match(s, /"SSL_write"/);
  assert.match(s, /i < 8;/);
});

// ---- ReDoS and hostile input ----

function fast(label: string, fn: () => unknown, ms = 1500) {
  const t0 = performance.now();
  fn();
  const dt = performance.now() - t0;
  assert.ok(dt < ms, `${label} took ${dt.toFixed(0)} ms`);
}

const TEXT_PARSERS: [string, (s: string) => unknown][] = [
  ['objdump -d', parseObjdumpDisasm], ['objdump -h', parseObjdumpSections], ['objdump -t', parseObjdumpSymbols],
  ['gdb', parseGdbBatch], ['lldb', parseLldbBatch], ['binwalk', parseBinwalkTable], ['frida devices', parseFridaDevices],
  ['frida output', (s) => parseFridaOutput(s)], ['adb devices', parseAdbDevices], ['adb packages', parseAdbPackages], ['adb pm path', parseAdbPmPath],
  ['stripJsonc', stripJsonc],
];

test('parsers stay linear on long pathological lines (trailing whitespace, repeats, no terminator)', () => {
  const n = 200_000;
  const evil = [
    'a' + ' '.repeat(n) + 'x',
    ' '.repeat(n),
    '0'.repeat(n) + ' ',
    '#1 ' + 'a'.repeat(n) + ' (' + '('.repeat(n),
    '0x1 <' + '<'.repeat(n),
    'x0 ' + '0x1'.repeat(n / 3) + ' ',
    '   frame #0: 0x1 ' + '`'.repeat(n),
    'Breakpoint 1, ' + 'a'.repeat(n),
    '1 0x1 ' + ' \t'.repeat(n / 2),
    '-'.repeat(n) + '\n' + '- '.repeat(n / 2),
    'package:' + '/'.repeat(n) + '='.repeat(n),
    '0000000000000828 g     F .text\t' + ' '.repeat(n) + '0',
    '  1 .text ' + '0'.repeat(n),
    '"' + '\\'.repeat(n),
    '/*' + '*'.repeat(n),
  ];
  for (const [name, p] of TEXT_PARSERS) for (const e of evil) fast(`${name} on ${JSON.stringify(e.slice(0, 20))}`, () => p(e));
});

test('JSON parsers survive deep, huge and odd JSON', () => {
  const deep = '['.repeat(5000) + ']'.repeat(5000);
  for (const p of [parseR2Functions, parseR2Disasm, parseR2Xrefs, parseFridaPs, parseBinwalkJson, parseGhidraExport]) {
    fast('deep', () => p(deep));
    fast('garbage', () => p('{"addr": "x", "ops": 5, "functions": {"length": 1e12}}'));
    fast('big', () => p(JSON.stringify(new Array(100_000).fill({ addr: 1, name: 'a', from: 2, pid: 3, offset: 4, file_map: [] }))));
  }
  assert.equal(extractJson('x'.repeat(1_000_000)), undefined);
});

test('random input never throws (fast-check)', () => {
  fc.assert(fc.property(fc.string({ maxLength: 2000 }), (s) => {
    for (const [, p] of TEXT_PARSERS) p(s);
    for (const p of [parseR2Functions, parseR2Disasm, parseR2Xrefs, parseFridaPs, parseBinwalkJson, parseGhidraExport]) p(s);
  }), { numRuns: 300 });
  fc.assert(fc.property(fc.jsonValue({ maxDepth: 6 }), (v) => {
    parseR2Functions(v); parseR2Disasm(v); parseR2Xrefs(v); parseFridaPs(v); parseBinwalkJson(v); parseGhidraExport(v);
  }), { numRuns: 300 });
});
