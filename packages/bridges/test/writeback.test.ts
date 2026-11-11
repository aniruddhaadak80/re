// Write-back of RevLens names into Ghidra, IDA and radare2 projects, and export back out.
// - Names JSON validation (hostile values refused), image base reading checked against radare2.
// - radare2: apply into a project, check with independent r2 queries, export, round trip.
// - Ghidra 12.2 headless: apply into the cached project, decompile shows the new names, export,
//   then the Ghidra export (rebased to 0x100000) applied to radare2 lands on the same functions.
// - IDA: no IDA in the sandbox, so the IDAPython scripts run under python3 against stub IDA
//   modules that record every API call; this checks the script logic, not IDA itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { validateNames, declaredImageBase, mapAddress, NamesError } from '../src/names.ts';
import { namesToR2Script, r2Name } from '../src/writeback/providers.ts';
import { IDA_APPLY_SCRIPT, IDA_NAMES_EXPORT_SCRIPT } from '../src/writeback/scripts.ts';
import { detectAll } from '../src/detect.ts';
import { runTool } from '../src/exec.ts';
import { TOOLS } from '../src/tools.ts';
import type { ToolId } from '../src/types.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const S = (f: string) => join(repo, 'samples', 'bridges', f);
const ELF = S('crackme-aarch64.elf');
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const run = async (n: string, i: Record<string, unknown>) => (await tool(n).run(i)) as any;
const dets = await detectAll();
const skipUnless = (...ids: ToolId[]): string | false => { for (const id of ids) if (!dets.get(id)?.available) return `${id} not installed`; return false; };
const work = mkdtempSync(join(tmpdir(), 'rl-wb-'));
process.env.REVLENS_CACHE_DIR = join(work, 'cache');
process.on('exit', () => { try { rmSync(work, { recursive: true, force: true }); } catch { /* ignore */ } });

// The crackme's functions (recorded/r2-aflj.json): add_numbers 0x828, check_password 0x848; the
// "revlens-open-sesame" string is at 0xa08 in .rodata (r2 iz).
const NAMES = {
  schema: 'revlens/names@1',
  functions: [
    { address: '0x848', name: 'verify_secret', signature: 'int verify_secret(char *input)', comment: 'compares the input with the secret' },
    { address: '0x828', name: 'sum_two' },
  ],
  comments: [{ address: '0x868', text: 'length check; | not a pipe', kind: 'eol' }, { address: '0x848', text: 'pre note', kind: 'pre' }],
  labels: [{ address: '0xa08', name: 'g_secret' }],
  types: [{ name: 'rl_pair', c: 'struct rl_pair { int a; char *b; };' }],
};

// ---------------- names JSON ----------------

test('names: valid file normalises addresses and defaults', () => {
  const n = validateNames({ functions: [{ address: '0x00848', name: 'f' }, { address: 2088, name: 'g' }], comments: [{ address: '0x10', text: 'x' }] });
  assert.equal(n.schema, 'revlens/names@1');
  assert.deepEqual(n.functions.map((f) => f.address), ['0x848', '0x828']);
  assert.equal(n.comments[0]!.kind, 'eol');
  assert.deepEqual(validateNames(JSON.stringify(NAMES)).types[0], { name: 'rl_pair', c: 'struct rl_pair { int a; char *b; };' });
});

test('names: hostile values are refused with every problem listed', () => {
  const bad = {
    schema: 'other',
    functions: [{ address: 'main', name: 'x' }, { address: '0x1', name: 'a;!id' }, { address: '0x2', name: 'ok', signature: 'int f(void); !id' }, { address: '0x3' }],
    comments: [{ address: '0x4', text: '' }, { address: '0x5', text: 'x', kind: 'shell' }],
    labels: [{ address: '0x6', name: 'has space' }],
    types: [{ c: 'struct s { char *p; }; " ; !id' }, { c: '#include </etc/passwd>' }],
  };
  try { validateNames(bad); assert.fail('should throw'); } catch (e) {
    assert.ok(e instanceof NamesError);
    assert.ok(e.problems.length >= 9, e.problems.join('\n'));
  }
  assert.throws(() => validateNames('{nope'), NamesError);
  assert.throws(() => validateNames({ functions: new Array(200_001).fill({ address: '0x1', name: 'a' }) }), /more than/);
});

test('names: random input never crashes the validator', () => {
  fc.assert(fc.property(fc.anything(), (v) => { try { validateNames(v); } catch (e) { assert.ok(e instanceof NamesError); } }), { numRuns: 300 });
});

test('image base: ELF and PE values match radare2 baddr', () => {
  // r2 -q -c 'i~baddr' gives 0x0 for the PIE, 0x1000000 for the static build, 0x400000 for the DLL
  assert.equal(declaredImageBase(readFileSync(ELF)), 0n);
  assert.equal(declaredImageBase(readFileSync(S('crackme-aarch64-static.elf'))), 0x1000000n);
  assert.equal(declaredImageBase(readFileSync(S('crackme-x86_64-static.elf'))), 0x1000000n);
  assert.equal(declaredImageBase(readFileSync(S('hello-dotnet.dll'))), 0x400000n);
  assert.equal(declaredImageBase(Buffer.from('not a binary')), undefined);
  assert.equal(mapAddress('0x848', {}, 0n, 0x100000n), 0x100848n);
  assert.equal(mapAddress('0x100848', { imageBase: '0x100000' }, 0n, 0n), 0x848n);
  assert.equal(mapAddress('0x848', { addressing: 'rva' }, 0x400000n, 0x10000000n), 0x10000848n);
});

test('r2 script: names become safe, comments go through base64, nothing chains commands', () => {
  const n = validateNames({ ...NAMES, functions: [...NAMES.functions, { address: '0x8c8', name: 'ns::check<int>~x' }] });
  const { script, renamed } = namesToR2Script(n, 0n, 0n);
  assert.deepEqual(renamed, [{ from: 'ns::check<int>~x', to: 'ns::check_int__x' }]);
  assert.equal(r2Name('9lives'), '_9lives');
  for (const line of script.trim().split('\n')) {
    if (line.startsWith('"')) assert.match(line, /^"[^"]*"$/, line);
    else assert.doesNotMatch(line, /[;|>`!~"]/, line);
  }
  assert.ok(script.includes(`CCu base64:${Buffer.from('length check; | not a pipe').toString('base64')}`));
});

// ---------------- radare2 ----------------

test('radare2: apply names into a project, verify with r2 itself, export them back', { skip: skipUnless('radare2') }, async () => {
  const dir = join(work, 'r2p');
  const a = await run('bridge_r2_apply_names', { path: ELF, names: NAMES, projectsDir: dir, project: 'crackme' });
  assert.equal(a.ok, true, JSON.stringify(a));
  assert.equal(a.project.created, true);
  // independent check: open the project in r2 and query it
  const q = join(work, 'q.r2');
  writeFileSync(q, [`e dir.projects=${dir}`, 'e prj.vc=false', 'P crackme', 'e scr.color=0', 'afij @ 0x848', '?e ==', 'afij @ 0x828', '?e ==', 'CC.@0x868', '?e ==', 'afs @ 0x848', '?e ==', 'ts', '?e ==', 'fs revlens', 'f'].join('\n'));
  const r = await runTool(dets.get('radare2')!.path!, ['-q', '-N', '-e', 'scr.color=0', '-i', q, ELF], { env: { ...process.env, TERM: 'dumb' } });
  const [f1, f2, cc, sig, ts, flags] = r.stdout.split('==\n');
  assert.equal(JSON.parse(f1!)[0].name, 'verify_secret');
  assert.equal(JSON.parse(f2!)[0].name, 'sum_two');
  assert.equal(cc!.trim(), 'length check; | not a pipe');
  assert.match(sig!, /int verify_secret\s*\(char \*input\)/);
  assert.match(ts!, /rl_pair/);
  assert.match(flags!, /0x00000a08 1 g_secret/);
  // second apply reuses the project
  const again = await run('bridge_r2_apply_names', { path: ELF, names: { functions: [{ address: '0x8c8', name: 'fnv_hash' }] }, projectsDir: dir, project: 'crackme' });
  assert.equal(again.project.created, false);
  const x = await run('bridge_r2_export_names', { path: ELF, projectsDir: dir, project: 'crackme', outPath: join(work, 'r2-names.json') });
  assert.equal(x.ok, true, JSON.stringify(x));
  const byAddr = Object.fromEntries(x.names.functions.map((f: any) => [f.address, f.name]));
  assert.deepEqual(byAddr, { '0x828': 'sum_two', '0x848': 'verify_secret', '0x8c8': 'fnv_hash' });
  assert.ok(x.names.comments.some((c: any) => c.address === '0x868' && c.text === 'length check; | not a pipe'));
  assert.deepEqual(x.names.labels, [{ address: '0xa08', name: 'g_secret' }]);
  assert.equal(x.names.binary.sha256, '739ea7f531bed6ffae645db6072ccb57c7cd911337dd42513beace148d9db1d3');
  assert.deepEqual(JSON.parse(readFileSync(join(work, 'r2-names.json'), 'utf8')).functions.length, 3);
});

// ---------------- Ghidra ----------------

test('Ghidra: apply names, decompile shows them, export, and the export maps back onto radare2', { skip: skipUnless('ghidra') || (dets.get('ghidra')?.details?.decompiler === false && 'Ghidra decompiler missing') }, async () => {
  const a = await run('bridge_ghidra_apply_names', { path: ELF, names: NAMES, timeoutMs: 900_000 });
  assert.equal(a.ok, true, JSON.stringify(a));
  assert.equal(a.report.imageBase, '0x100000');
  assert.deepEqual({ r: a.report.functionsRenamed, s: a.report.signatures, c: a.report.comments, l: a.report.labels, t: a.report.types }, { r: 2, s: 1, c: 3, l: 1, t: 1 });
  const d = await run('bridge_ghidra_decompile', { path: ELF, functions: ['main'] });
  const c = d.results[0].c as string;
  assert.match(c, /sum_two\(param_1,0x29\)/);
  assert.match(c, /verify_secret\(/);
  const x = await run('bridge_ghidra_export_names', { path: ELF });
  assert.equal(x.ok, true, JSON.stringify(x));
  assert.equal(x.names.imageBase, '0x100000');
  const fns = Object.fromEntries(x.names.functions.map((f: any) => [f.address, f]));
  assert.equal(fns['0x100848'].name, 'verify_secret');
  assert.equal(fns['0x100848'].signature, 'int verify_secret(char * input)');
  assert.equal(fns['0x100828'].name, 'sum_two');
  assert.deepEqual(x.names.comments, [
    { address: '0x100848', text: 'pre note', kind: 'pre' },
    { address: '0x100848', text: 'compares the input with the secret', kind: 'plate' },
    { address: '0x100868', text: 'length check; | not a pipe', kind: 'eol' },
  ]);
  assert.deepEqual(x.names.labels, [{ address: '0x100a08', name: 'g_secret' }]);
  assert.deepEqual(x.names.types, [{ name: 'rl_pair', c: 'struct rl_pair { int a; char * b; };' }]);
  if (skipUnless('radare2')) return;
  // Ghidra addresses carry its 0x100000 base; imageBase in the export maps them back to 0x8xx
  const dir = join(work, 'r2-from-ghidra');
  const r = await run('bridge_r2_apply_names', { path: ELF, names: x.names, projectsDir: dir, project: 'fromghidra' });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.match(r.script, /s 0x848\naf\nafn verify_secret/);
  const back = await run('bridge_r2_export_names', { path: ELF, projectsDir: dir, project: 'fromghidra' });
  const names = Object.fromEntries(back.names.functions.map((f: any) => [f.address, f.name]));
  assert.equal(names['0x848'], 'verify_secret');
  assert.equal(names['0x828'], 'sum_two');
});

// ---------------- IDA (scripts under stub modules) ----------------

const STUBS: Record<string, string> = {
  '_rec.py': `import json, os\ncalls = []\ndef rec(*a):\n    calls.append([str(x) for x in a])\ndef dump():\n    with open(os.environ["STUB_OUT"], "w") as fh:\n        json.dump(calls, fh)\n`,
  'idc.py': `from _rec import rec\nPT_SILENT = 1\nE_PREV = 1000\nE_NEXT = 2000\ndef parse_decls(c, f):\n    rec("parse_decls", c)\n    return 0\ndef SetType(ea, d):\n    rec("SetType", hex(ea), d)\n    return True\ndef set_cmt(ea, t, r):\n    rec("set_cmt", hex(ea), t, r)\n    return True\ndef update_extra_cmt(ea, n, line):\n    rec("extra", hex(ea), n, line)\ndef get_type(ea):\n    return "int __fastcall verify_secret(char *input)" if ea == 0x848 else None\ndef get_cmt(ea, r):\n    return "length check" if (ea, r) == (0x868, 0) else None\ndef get_ordinal_qty():\n    return 1\ndef print_decls(o, f):\n    return "struct rl_pair\\n{\\n  int a;\\n  char *b;\\n};"\n`,
  'ida_name.py': `from _rec import rec\nSN_NOWARN = 1\nSN_FORCE = 2\ndef set_name(ea, n, f):\n    rec("set_name", hex(ea), n)\n    return True\ndef get_name(ea):\n    return {0x848: "verify_secret", 0x828: "sub_828", 0x700: "start"}.get(ea, "x")\n`,
  'ida_funcs.py': `from _rec import rec\nclass F:\n    def __init__(s, a, b):\n        s.start_ea = a\n        s.end_ea = b\n_f = {0x848: F(0x848, 0x8c8), 0x828: F(0x828, 0x848), 0x700: F(0x700, 0x730)}\ndef get_func(ea):\n    for f in _f.values():\n        if f.start_ea <= ea < f.end_ea:\n            return f\n    return None\ndef add_func(ea):\n    rec("add_func", hex(ea))\n    _f[ea] = F(ea, ea + 4)\n    return True\ndef set_func_cmt(f, t, r):\n    rec("set_func_cmt", hex(f.start_ea), t)\n    return True\ndef get_func_cmt(f, r):\n    return "compares" if f and f.start_ea == 0x848 else None\n`,
  'ida_bytes.py': `def get_flags(ea):\n    return ea\ndef has_user_name(fl):\n    return fl in (0x848, 0xa08)\n`,
  'ida_auto.py': `def auto_wait():\n    pass\n`,
  'ida_nalt.py': `def get_imagebase():\n    return 0\n`,
  'ida_loader.py': `from _rec import rec\ndef save_database(p, f):\n    rec("save_database", p)\n`,
  'ida_pro.py': `import _rec\ndef qexit(c):\n    _rec.dump()\n`,
  'idautils.py': `def Functions():\n    return [0x700, 0x828, 0x848]\ndef Heads(a, b):\n    return range(a, b, 4)\ndef Names():\n    return [(0x848, "verify_secret"), (0xa08, "g_secret"), (0x700, "start")]\n`,
};

async function runIdaScript(script: string, args: Record<string, unknown>): Promise<{ calls: string[][]; code: number | null; stderr: string }> {
  const dir = mkdtempSync(join(work, 'ida-'));
  for (const [f, src] of Object.entries(STUBS)) writeFileSync(join(dir, f), src);
  writeFileSync(join(dir, 'script.py'), script);
  const out = join(dir, 'calls.json');
  const py = process.platform === 'win32' ? 'python' : 'python3';
  const r = await runTool(py, [join(dir, 'script.py')], { env: { ...process.env, PYTHONPATH: dir, STUB_OUT: out, REVLENS_IDA_ARGS: JSON.stringify(args) }, cwd: dir });
  let calls: string[][] = [];
  try { calls = JSON.parse(readFileSync(out, 'utf8')); } catch { /* none */ }
  return { calls, code: r.code, stderr: r.stderr };
}

const pyOk = (await runTool(process.platform === 'win32' ? 'python' : 'python3', ['-c', 'print(1)'])).code === 0;

test('IDA apply script: names, prototypes, comments, labels, types and save, with the image base mapped', { skip: !pyOk && 'python3 not found' }, async () => {
  const dir = mkdtempSync(join(work, 'ida-apply-'));
  const names = join(dir, 'names.json');
  const report = join(dir, 'report.json');
  // Ghidra style addresses (base 0x100000) applied to an IDA database whose base is 0
  writeFileSync(names, JSON.stringify({ ...validateNames(NAMES), imageBase: '0x100000', functions: [{ address: '0x100848', name: 'verify_secret', signature: 'int verify_secret(char *input)', comment: 'c1' }, { address: '0x100900', name: 'made_up' }],
    comments: [{ address: '0x100868', text: 'eol one', kind: 'eol' }, { address: '0x100848', text: 'line1\nline2', kind: 'pre' }, { address: '0x10086c', text: 'rep', kind: 'repeatable' }], labels: [{ address: '0x100a08', name: 'g_secret' }] }));
  const r = await runIdaScript(IDA_APPLY_SCRIPT, { names, report, fileBase: '0x0', save: join(dir, 'out.i64') });
  assert.equal(r.code, 0, r.stderr);
  const rep = JSON.parse(readFileSync(report, 'utf8'));
  assert.deepEqual({ r: rep.functionsRenamed, c: rep.functionsCreated, s: rep.signatures, cm: rep.comments, l: rep.labels, t: rep.types, e: rep.errors.length },
    { r: 2, c: 1, s: 1, cm: 4, l: 1, t: 1, e: 0 });
  const has = (...want: string[]) => r.calls.some((c) => want.every((w, i) => c[i] === w));
  assert.ok(has('parse_decls', 'struct rl_pair { int a; char *b; };'));
  assert.ok(has('set_name', '0x848', 'verify_secret'));
  assert.ok(has('add_func', '0x900'));
  assert.ok(has('SetType', '0x848', 'int verify_secret(char *input);'));
  assert.ok(has('set_func_cmt', '0x848', 'c1'));
  assert.ok(has('set_cmt', '0x868', 'eol one', '0'));
  assert.ok(has('set_cmt', '0x86c', 'rep', '1'));
  assert.ok(has('extra', '0x848', '1000', 'line1') && has('extra', '0x848', '1001', 'line2'));
  assert.ok(has('set_name', '0xa08', 'g_secret'));
  assert.ok(has('save_database', join(dir, 'out.i64')));
});

test('IDA export script: user names only, prototypes, comments, labels and local types', { skip: !pyOk && 'python3 not found' }, async () => {
  const dir = mkdtempSync(join(work, 'ida-export-'));
  const out = join(dir, 'names.json');
  const r = await runIdaScript(IDA_NAMES_EXPORT_SCRIPT, { out, all: false });
  assert.equal(r.code, 0, r.stderr);
  const n = validateNames(readFileSync(out, 'utf8'));
  assert.equal(n.source, 'ida');
  assert.deepEqual(n.functions, [{ address: '0x848', name: 'verify_secret', signature: 'int __fastcall verify_secret(char *input)', comment: 'compares' }]);
  assert.deepEqual(n.comments, [{ address: '0x868', text: 'length check', kind: 'eol' }]);
  assert.deepEqual(n.labels, [{ address: '0xa08', name: 'g_secret' }]);
  assert.equal(n.types.length, 1);
  assert.match(n.types[0]!.c, /struct rl_pair/);
});

// ---------------- safety and missing tools ----------------

test('write-back tools refuse bad names before running anything', async () => {
  for (const name of ['bridge_r2_apply_names', 'bridge_ghidra_apply_names', 'bridge_ida_apply_names']) {
    const r = await run(name, { path: ELF, names: { functions: [{ address: '0x848', name: 'x;!touch /tmp/rl' }] }, outDatabase: join(work, 'x.i64') });
    if (r.available === false) continue;
    assert.equal(r.inputError, true, name);
    assert.ok(r.problems.length >= 1);
  }
});

test('write-back tools answer {available:false, install} when the tool is missing', async () => {
  const code = `const { TOOLS } = await import(${JSON.stringify(join(repo, 'packages/bridges/src/tools.ts'))});
const out = {};
for (const n of ['bridge_ghidra_apply_names', 'bridge_ghidra_export_names', 'bridge_ida_apply_names', 'bridge_ida_export_names', 'bridge_r2_apply_names', 'bridge_r2_export_names']) {
  out[n] = await TOOLS.find((t) => t.name === n).run({ path: ${JSON.stringify(ELF)}, names: ${JSON.stringify(NAMES)}, outDatabase: '/tmp/x.i64' });
}
process.stdout.write(JSON.stringify(out));`;
  const r = await runTool(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { cwd: repo, env: { ...process.env, REVLENS_BRIDGES_DISABLE: 'all' }, timeoutMs: 60_000 });
  assert.equal(r.code, 0, r.stderr);
  for (const [n, v] of Object.entries(JSON.parse(r.stdout) as Record<string, any>)) {
    assert.equal(v.available, false, n);
    assert.ok(v.install?.homepage, n);
  }
});
