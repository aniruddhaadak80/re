// Integration tests: run the real tools on samples/bridges fixtures when they are installed, and
// skip with the reason when they are not. Values were cross checked between tools by hand:
// radare2 6.2.6 + r2ghidra, Ghidra 12.2, GNU objdump 2.44, llvm-objdump 19, gdb 16.3, lldb 19.1.7,
// jadx 1.5.6, ilspycmd 9.1, binwalk 2.4.3, frida-tools 17.26.2.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { detectAll } from '../src/detect.ts';
import { runTool } from '../src/exec.ts';
import { TOOLS } from '../src/tools.ts';
import type { ToolId } from '../src/types.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const S = (f: string) => join(repo, 'samples', 'bridges', f);
const ELF = S('crackme-aarch64.elf');
// Static musl builds of src/crackme.c (zig cc), one per CPU, so the debuggers need no dynamic loader.
const STATIC = process.arch === 'x64' ? S('crackme-x86_64-static.elf') : S('crackme-aarch64-static.elf');
const ARG0 = process.arch === 'x64' ? 'rdi' : 'x0';
const ARG1 = process.arch === 'x64' ? 'rsi' : 'x1';
const cache = process.env.REVLENS_CACHE_DIR ?? mkdtempSync(join(tmpdir(), 'rl-int-'));
process.env.REVLENS_CACHE_DIR = cache;
process.on('exit', () => { if (!process.env.REVLENS_KEEP_CACHE) try { rmSync(cache, { recursive: true, force: true }); } catch { /* ignore */ } });

const dets = await detectAll();
const staticOk = process.platform === 'linux' && (process.arch === 'arm64' || process.arch === 'x64');
function skipUnless(...ids: ToolId[]): string | false {
  for (const id of ids) {
    const d = dets.get(id);
    if (!d?.available) return `${id} not installed${d?.problems?.length ? `: ${d.problems.join(' ')}` : ''}`;
  }
  return false;
}
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const run = async (n: string, input: Record<string, unknown>) => (await tool(n).run(input)) as any;

test('every tool reports {available:false, install} when its program is missing', async () => {
  const code = `const { TOOLS } = await import(${JSON.stringify(pathToFileURL(join(repo, 'packages/bridges/src/tools.ts')).href)});
const out = {};
for (const t of TOOLS) {
  if (t.name === 'bridge_doctor' || t.name === 'bridge_setup_mcp' || t.name === 'bridge_frida_templates') continue;
  out[t.name] = await t.run({ path: ${JSON.stringify(ELF)}, function: 'main', functions: ['main'], query: 'x', package: 'com.example.app', breakpoints: ['main'], template: 'module-list', pid: 1, allowExecution: true });
}
process.stdout.write(JSON.stringify(out));`;
  const r = await runTool(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { cwd: repo, env: { ...process.env, REVLENS_BRIDGES_DISABLE: 'all' }, timeoutMs: 60_000 });
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout) as Record<string, any>;
  assert.ok(Object.keys(out).length >= 20);
  for (const [name, v] of Object.entries(out)) {
    assert.equal(v.available, false, name);
    assert.ok(v.install?.homepage?.startsWith('https://'), name);
    assert.ok(typeof v.reason === 'string' && v.reason.length > 0, name);
  }
});

test('doctor inventory lists every tool with install commands for missing ones', async () => {
  const inv = await run('bridge_doctor', {});
  assert.equal(inv.schema, 'revlens/bridges-inventory@1');
  assert.equal(inv.tools.length, 19);
  for (const t of inv.tools) if (!t.available) assert.ok(t.install?.homepage, t.id);
  assert.equal(inv.summary.total, 19);
});

test('radare2: add_numbers at 0x828 size 32, check_password called from main at 0x98c, r2ghidra C', { skip: skipUnless('radare2') }, async () => {
  const f = await run('bridge_r2_functions', { path: ELF, filter: 'numbers' });
  assert.equal(f.ok, true);
  assert.deepEqual(f.functions.map((x: any) => [x.name, x.address, x.size]), [['sym.add_numbers', '0x828', 32]]);
  const x = await run('bridge_r2_xrefs', { path: ELF, function: 'check_password' });
  assert.equal(x.target, '0x848');
  assert.ok(x.xrefs.some((r: any) => r.from === '0x98c' && r.type === 'CALL' && r.function === 'main'));
  const d = await run('bridge_r2_disasm', { path: ELF, function: 'add_numbers' });
  assert.equal(d.function.address, '0x828');
  assert.equal(d.instructions[0].address, '0x828');
  assert.equal(d.instructions[0].bytes, 'ff4300d1');
  const c = await run('bridge_r2_decompile', { path: ELF, function: 'check_password' });
  assert.equal(c.ok, true);
  if (dets.get('radare2')?.details?.ghidraPlugin === true) {
    assert.equal(c.decompiler, 'r2ghidra');
    assert.match(c.code, /strcmp/);
  } else assert.equal(c.decompiler, 'pdc');
  const s = await run('bridge_r2_strings', { path: ELF });
  assert.ok(s.strings.some((v: any) => v.value === 'revlens-open-sesame' && v.vaddr === '0xa08'));
});

// GNU objdump is built for one host architecture unless binutils-multiarch is installed, so on an x64 runner it
// may not decode the AArch64 fixture at all. Those comparisons are skipped with that reason.
const GNU_NO_ARCH = 'GNU objdump on this host cannot decode AArch64 (install binutils-multiarch)';

test('objdump and radare2 agree on addresses and bytes of add_numbers', { skip: skipUnless('objdump', 'radare2') }, async (t) => {
  const o = await run('bridge_objdump', { path: ELF, function: 'add_numbers', engine: 'objdump' });
  if (!o.functions?.length) { t.skip(GNU_NO_ARCH); return; }
  const r = await run('bridge_r2_disasm', { path: ELF, function: 'add_numbers' });
  const oi = o.functions[0].instructions;
  assert.equal(o.functions[0].address, '0x828');
  assert.equal(oi.length, r.instructions.length);
  oi.forEach((ins: any, i: number) => {
    assert.equal(ins.address, r.instructions[i].address);
    assert.equal(ins.bytes, r.instructions[i].bytes.match(/../g).reverse().join(''));
  });
  const sec = await run('bridge_objdump', { path: ELF, mode: 'sections' });
  assert.ok(sec.sections.some((s: any) => s.name === '.text' && s.vma === '0x700'));
});

test('llvm-objdump gives the same add_numbers bytes as GNU objdump', { skip: skipUnless('llvm-objdump', 'objdump') }, async (t) => {
  const g = await run('bridge_objdump', { path: ELF, function: 'add_numbers', engine: 'objdump' });
  const l = await run('bridge_objdump', { path: ELF, function: 'add_numbers', engine: 'llvm-objdump' });
  assert.equal(l.tool, 'llvm-objdump');
  assert.equal(l.functions[0]?.address, '0x828', JSON.stringify(l).slice(0, 400));
  if (!g.functions?.length) { t.skip(GNU_NO_ARCH); return; }
  assert.deepEqual(l.functions[0].instructions.map((i: any) => [i.address, i.bytes]), g.functions[0].instructions.map((i: any) => [i.address, i.bytes]));
});

test('Ghidra headless: image base 0x100000 plus the r2 addresses, decompiles check_password and add_numbers', { skip: skipUnless('ghidra'), timeout: 20 * 60_000 }, async () => {
  const f = await run('bridge_ghidra_functions', { path: ELF });
  assert.equal(f.ok, true, f.error);
  assert.equal(parseInt(f.program.imageBase, 16), 0x100000);
  const add = f.functions.find((x: any) => x.name === 'add_numbers');
  assert.deepEqual([add.address, add.size], ['0x100828', 32]);
  assert.equal(f.functions.find((x: any) => x.name === 'check_password').address, '0x100848');
  if (dets.get('ghidra')?.details?.decompiler !== true) return;
  const d = await run('bridge_ghidra_decompile', { path: ELF, functions: ['check_password', '0x100828'] });
  assert.equal(d.ok, true, d.error);
  assert.equal(d.cached, true);
  const chk = d.results.find((r: any) => r.function.name === 'check_password');
  assert.match(chk.c, /strcmp\(param_1,SECRET\)/);
  const a = d.results.find((r: any) => r.function.name === 'add_numbers');
  assert.match(a.c, /return param_1 \+ param_2;/);
  assert.deepEqual(d.notFound, []);
});

test('jadx: decompiles Hello from the DEX and JAR, search finds the API host', { skip: skipUnless('jadx'), timeout: 5 * 60_000 }, async () => {
  for (const file of ['hello.dex', 'hello.jar']) {
    const l = await run('bridge_jadx_decompile', { path: S(file) });
    assert.equal(l.ok, true, l.error);
    assert.deepEqual(l.classes.map((c: any) => c.className), ['dev.revlens.fixture.Hello']);
  }
  const src = await run('bridge_jadx_decompile', { path: S('hello.dex'), className: 'dev.revlens.fixture.Hello' });
  // the DEX was built without debug info, so jadx names the parameters itself
  assert.match(src.source, /public static int addNumbers\(int i, int i2\)/);
  assert.match(src.source, /return i \+ i2;/);
  assert.match(src.source, /API_HOST = "https:\/\/api\.example\.invalid\/v1"/);
  const s = await run('bridge_jadx_search', { path: S('hello.dex'), query: 'API.EXAMPLE.invalid' });
  assert.ok(s.hits.some((h: any) => h.className === 'dev.revlens.fixture.Hello' && h.text.includes('https://api.example.invalid/v1')));
});

test('ILSpy: lists Greeter and decompiles AddNumbers and the secret', { skip: skipUnless('ilspy'), timeout: 5 * 60_000 }, async () => {
  const l = await run('bridge_ilspy_decompile', { path: S('hello-dotnet.dll') });
  assert.equal(l.ok, true, l.error);
  assert.deepEqual(l.types, [{ kind: 'class', name: 'RevLens.Samples.Greeter' }]);
  const c = await run('bridge_ilspy_decompile', { path: S('hello-dotnet.dll'), typeName: 'RevLens.Samples.Greeter' });
  assert.match(c.code, /public static int AddNumbers\(int a, int b\)/);
  assert.match(c.code, /"revlens-dotnet-key"/);
});

test('binwalk finds the planted files at their offsets', { skip: skipUnless('binwalk') }, async () => {
  const b = await run('bridge_binwalk', { path: S('firmware-sample.bin') });
  assert.equal(b.ok, true, b.error);
  const at = new Map(b.hits.map((h: any) => [h.offset, h.description.toLowerCase()]));
  assert.match(String(at.get(256)), /gzip/);
  assert.match(String(at.get(1024)), /zip/);
  assert.match(String(at.get(2048)), /png/);
});

test('gdb on the static binary: first two args 2 and 41 (x0/x1 or rdi/rsi) at add_numbers, backtrace into main', { skip: skipUnless('gdb') || (!staticOk && 'static fixtures are Linux arm64 and x64 only') }, async () => {
  const g = await run('bridge_gdb_run', { path: STATIC, args: ['a'], breakpoints: ['add_numbers', 'check_password'], registers: [ARG0, ARG1], memory: { base: '$sp', count: 16 }, allowExecution: true });
  assert.equal(g.ok, true, g.error);
  assert.equal(g.stopCount, 2);
  assert.deepEqual([g.stops[0].registers[ARG0], g.stops[0].registers[ARG1]], ['0x2', '0x29']);
  assert.deepEqual(g.stops[0].backtrace.map((f: any) => f.function), ['add_numbers', 'main']);
  assert.equal(g.stops[0].memory.length, 2);
  assert.equal(g.stops[1].function, 'check_password');
  assert.equal(g.exitCode, 1);
});

test('lldb on the static binary: same registers as gdb', { skip: skipUnless('lldb') || (!staticOk && 'static fixtures are Linux arm64 and x64 only') }, async () => {
  const l = await run('bridge_gdb_run', { debugger: 'lldb', path: STATIC, args: ['a'], breakpoints: ['add_numbers'], registers: [ARG0, ARG1], allowExecution: true });
  assert.equal(l.ok, true, l.error);
  assert.equal(l.stopCount, 1);
  assert.deepEqual([parseInt(l.stops[0].registers[ARG0], 16), parseInt(l.stops[0].registers[ARG1], 16)], [2, 41]);
  assert.equal(l.stops[0].backtrace[1].function, 'main');
  assert.equal(l.exitCode, 1);
});

test('Frida: ps sees a child process; attach with module-list and trace getpid', { skip: skipUnless('frida'), timeout: 120_000 }, async () => {
  const py = process.platform === 'win32' ? 'python' : 'python3';
  const child = spawn(py, ['-c', 'import os,time\nwhile True:\n  os.getpid(); time.sleep(0.05)'], { stdio: 'ignore' });
  try {
    await new Promise((r) => setTimeout(r, 1000));
    const ps = await run('bridge_frida_ps', {});
    assert.equal(ps.ok, true, ps.error);
    assert.ok(ps.processes.some((p: any) => p.pid === child.pid));
    const m = await run('bridge_frida_run', { template: 'module-list', pid: child.pid, durationMs: 1500, allowExecution: true });
    assert.equal(m.ok, true, m.error);
    assert.equal(m.events[0].type, 'process');
    assert.equal(m.events[0].pid, child.pid);
    assert.ok(m.events.some((e: any) => e.type === 'module' && /libc|python/.test(e.name)));
    if (process.platform !== 'linux') return;
    const t = await run('bridge_frida_run', { template: 'trace-native-export', params: { export: 'getpid', args: 0 }, pid: child.pid, durationMs: 2000, allowExecution: true });
    assert.equal(t.ok, true, t.error);
    const calls = t.events.filter((e: any) => e.type === 'call');
    assert.ok(calls.length > 3, `calls ${calls.length}`);
    // getpid returns the pid we attached to
    assert.equal(parseInt(calls[0].ret, 16), child.pid);
  } finally { child.kill('SIGKILL'); }
});

test('adb devices runs and parses (no device needed)', { skip: skipUnless('adb') }, async () => {
  const r = await run('bridge_adb_devices', {});
  assert.equal(r.ok, true, r.error);
  assert.ok(Array.isArray(r.devices));
});

test('opt in analyzers: skipped by default, r2 analyzer fills report.meta.bridges.r2 when enabled', { skip: skipUnless('radare2') }, async () => {
  const { r2Analyzer, ANALYZERS } = await import('../src/analyzer.ts');
  const { readFileSync } = await import('node:fs');
  const report: any = { findings: [], meta: {}, timings: {} };
  const ctx: any = { bytes: new Uint8Array(readFileSync(ELF)), name: 'crackme', format: 'elf', depth: 0, report, options: { maxStrings: 100, recurse: false, maxDepth: 1 } };
  const prev = process.env.REVLENS_BRIDGES;
  delete process.env.REVLENS_BRIDGES;
  assert.equal(ANALYZERS.some((a) => a.applies(ctx)), false);
  ctx.options.analyzers = ['bridges-r2'];
  assert.equal(r2Analyzer.applies(ctx), true);
  await r2Analyzer.run(ctx);
  if (prev !== undefined) process.env.REVLENS_BRIDGES = prev;
  const m = report.meta.bridges.r2;
  assert.equal(m.available, true);
  assert.ok(m.functions.some((f: any) => f.name === 'sym.add_numbers' && f.address === '0x828'));
  assert.equal(m.info.machine, 'ARM aarch64');
  assert.equal(report.findings[0].id, 'bridges.r2.functions');
  JSON.stringify(report);
});
