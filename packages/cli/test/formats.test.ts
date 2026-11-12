// Output formats, completions and evidence bundles.
//
// References, all independent of the code under test:
//   TOON   the reference decoder @toon-format/toon (skipped when not installed)
//   YAML   the `yaml` package (YAML 1.2) and PyYAML safe_load (YAML 1.1) through python3
//   CSV    Python's csv module, TSV a small Python reader for the \t \n \r \\ escapes
//   JSONL  Python's json module, line by line
//   hashes node:crypto and sha256sum
//   completions real bash (zsh, fish and pwsh when installed)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import fc from 'fast-check';
import YAML from 'yaml';
import { toToon, toYaml, toCsv, toTsv, toJsonl, toMarkdownTable, normalize, rowsOf, flattenRow, neutralizeCell, parseCommandJson, toonNeedsQuotes, render, OUTPUT_FORMATS } from '../src/formats.js';
import { completionScript } from '../src/completions.js';
import { canonicalJson, checkBundle, EVIDENCE_SCHEMA } from '../src/evidence.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const CLI = join(root, 'packages/cli/src/index.ts');
const ELF = join(root, 'samples/ls-linux.elf');
const cli = (args: string[], opts: { input?: string } = {}) => spawnSync(process.execPath, ['--import', 'tsx', CLI, ...args], { encoding: 'utf8', maxBuffer: 256 << 20, cwd: root, input: opts.input, env: { ...process.env, NO_COLOR: '1' } });
const has = (cmd: string, args = ['--version']) => { try { execFileSync(cmd, args, { stdio: 'ignore', timeout: 10_000 }); return true; } catch { return false; } };
const pyYaml = has('python3', ['-c', 'import yaml']);
const python = has('python3');
let toonRef: { decode: (s: string) => unknown } | undefined;
try { toonRef = await import('@toon-format/toon' as string); } catch { toonRef = undefined; }

const py = (code: string, input: string) => execFileSync('python3', ['-c', code], { input, encoding: 'utf8', maxBuffer: 256 << 20 });

// ------------------------------------------------------------------ pure encoders

test('TOON decodes back to the same data with the reference decoder', { skip: !toonRef && '@toon-format/toon is not installed' }, () => {
  const fixed: unknown[] = [
    { name: 'ls', tags: ['a', 'b c', '1'], items: [{ id: 1, name: 'x' }, { id: 2, name: 'y,z' }], mixed: [1, { a: 1, b: [{ x: 1 }] }, [2, 3]], s: '', q: 'he said "hi"\n', '-k': '- x', t: 'true', n: '05', e: [], o: {} },
    [[1, 2], [{ a: 1 }], [[3]]], [{ x: [{ y: [1, { z: 2 }] }] }], 'str', 42, null, [], {},
  ];
  for (const v of fixed) assert.deepEqual(toonRef!.decode(toToon(v)), normalize(v), toToon(v));
  fc.assert(fc.property(fc.jsonValue({ maxDepth: 6 }), (v) => isDeepStrictEqual(toonRef!.decode(toToon(v)), normalize(v))), { numRuns: 2000 });
});

test('TOON writes tables for uniform rows and quotes what would read back differently', () => {
  assert.equal(toToon({ f: [{ a: 1, b: 'x' }, { a: 2, b: 'y' }] }), 'f[2]{a,b}:\n  1,x\n  2,y');
  assert.equal(toToon({ p: [1, 'a', true, null] }), 'p[4]: 1,a,true,null');
  for (const s of ['', ' a', 'true', '12', '1e5', '05', '-x', 'a:b', 'a,b', '[x]', '#c', 'a\nb']) assert.ok(toonNeedsQuotes(s), s);
  for (const s of ['abc', 'a b', 'main.c', 'Lcom/a/B;']) assert.ok(!toonNeedsQuotes(s), s);
});

test('YAML reads back the same with the yaml package (1.2) and PyYAML (1.1)', () => {
  const v = { a: [{ b: 1, c: [{ d: 2 }, [3, [4]]] }, []], e: {}, yes: 'yes', no: 'off', date: '2024-01-02', num: '1.5', colon: 'a: b', hash: 'x #y', nl: 'a\nb', ctl: '\u0001', uni: 'é\u2028' };
  assert.deepEqual(YAML.parse(toYaml(v)), v);
  fc.assert(fc.property(fc.jsonValue({ maxDepth: 6 }), (x) => isDeepStrictEqual(YAML.parse(toYaml(x)), normalize(x))), { numRuns: 2000 });
  if (pyYaml) {
    const samples = fc.sample(fc.jsonValue({ maxDepth: 4 }), 300).map((x) => normalize(x));
    const docs = samples.map((x) => toYaml(x));
    const back = JSON.parse(py('import sys, json, yaml\ndocs = json.load(sys.stdin)\nprint(json.dumps([yaml.safe_load(d) for d in docs]))', JSON.stringify(docs)));
    // PyYAML reads -0.0 and big integers its own way; compare after a JSON round trip on both sides
    for (let i = 0; i < samples.length; i++) assert.deepEqual(JSON.parse(JSON.stringify(back[i])), JSON.parse(JSON.stringify(samples[i])), docs[i]);
    assert.deepEqual(JSON.parse(py('import sys, json, yaml\nprint(json.dumps(yaml.safe_load(sys.stdin.read())))', toYaml(v))), v);
  }
});

test('rows, flattening and spreadsheet formula guard', () => {
  assert.deepEqual(rowsOf({ total: 2, tools: [{ a: 1 }, { a: 2 }], tags: ['x'] }), { key: 'tools', rows: [{ a: 1 }, { a: 2 }] });
  assert.deepEqual(rowsOf({ a: 1 }).rows, [{ a: 1 }]);
  assert.deepEqual(flattenRow({ a: { b: 1, c: { d: [1, 2] } }, e: [{ x: 1 }] }), { 'a.b': 1, 'a.c.d': '1;2', e: '[{"x":1}]' });
  assert.equal(neutralizeCell('=HYPERLINK("x")'), `'=HYPERLINK("x")`);
  assert.equal(neutralizeCell('-12.5'), '-12.5');
  assert.equal(neutralizeCell('@SUM(A1)'), "'@SUM(A1)");
  assert.equal(toCsv([{ a: '=1+1' }], { safe: false }), 'a\r\n=1+1\r\n');
});

test('CSV and TSV read back with Python and hostile cells stay inside their cell', { skip: !python && 'python3 missing' }, () => {
  fc.assert(fc.property(fc.array(fc.record({ a: fc.string({ maxLength: 20 }), b: fc.oneof(fc.integer(), fc.string({ unit: 'grapheme', maxLength: 10 })), c: fc.boolean() }), { minLength: 1, maxLength: 20 }), (rows) => {
    const csv = toCsv(rows, { safe: false });
    const back = JSON.parse(py('import sys, csv, io, json\nprint(json.dumps(list(csv.reader(io.StringIO(sys.stdin.read(), newline="")))))', csv));
    assert.deepEqual(back[0], ['a', 'b', 'c']);
    assert.equal(back.length, rows.length + 1);
    rows.forEach((r, i) => assert.deepEqual(back[i + 1], [r.a, String(r.b), String(r.c)]));
    const tsv = toTsv(rows, { safe: false });
    const tback = JSON.parse(py(String.raw`import sys, json, re
def un(s): return re.sub(r'\\(.)', lambda m: {'t':'\t','n':'\n','r':'\r','\\':'\\'}.get(m.group(1), m.group(0)), s)
lines = sys.stdin.read().split('\n')[:-1]
print(json.dumps([[un(c) for c in l.split('\t')] for l in lines]))`, tsv));
    rows.forEach((r, i) => assert.deepEqual(tback[i + 1], [r.a, String(r.b), String(r.c)]));
    return true;
  }), { numRuns: 60 });
});

test('encoders refuse cycles and survive deep and huge values in time', () => {
  const a: Record<string, unknown> = {}; a.self = a;
  assert.throws(() => toToon(a), /cyclic/);
  let deep: unknown = 1;
  for (let i = 0; i < 200; i++) deep = [{ k: deep }];
  for (const f of OUTPUT_FORMATS) { const t = performance.now(); render(deep, f); assert.ok(performance.now() - t < 5000, f); }
  if (toonRef) assert.deepEqual(toonRef.decode(toToon(deep)), normalize(deep));
  assert.deepEqual(YAML.parse(toYaml(deep), { maxAliasCount: -1 }), normalize(deep));
  let deeper: unknown = 1;
  for (let i = 0; i < 100_000; i++) deeper = [deeper];
  for (const f of OUTPUT_FORMATS) assert.throws(() => render(deeper, f), /nested more than/);
  const wide = Array.from({ length: 50_000 }, (_, i) => ({ i, s: `x${i}` }));
  const t = performance.now();
  for (const f of OUTPUT_FORMATS) render(wide, f);
  assert.ok(performance.now() - t < 15_000);
  fc.assert(fc.property(fc.anything({ maxDepth: 4 }), (x) => { for (const f of OUTPUT_FORMATS) { try { render(x, f); } catch (e) { if (!/cyclic|nested more/.test((e as Error).message)) throw e; } } return true; }), { numRuns: 300 });
});

test('parseCommandJson reads one document or JSON Lines', () => {
  assert.deepEqual(parseCommandJson('{"a":1}\n'), { ok: true, value: { a: 1 } });
  assert.deepEqual(parseCommandJson('{"a":1}\n{"a":2}\n'), { ok: true, value: [{ a: 1 }, { a: 2 }] });
  assert.deepEqual(parseCommandJson('hello'), { ok: false });
  assert.match(toMarkdownTable([{ a: 'x|y' }]), /x\\\|y/);
  assert.equal(toJsonl({ rows: [{ a: 1 }, { a: 2 }] }), '{"a":1}\n{"a":2}');
});

// ------------------------------------------------------------------ the CLI on a real file

test('every format of analyze on a real ELF carries the same facts as --json', { timeout: 240_000 }, () => {
  const j = cli(['analyze', ELF, '--json']);
  assert.equal(j.status, 0, j.stderr);
  const rep = JSON.parse(j.stdout);
  const sha = createHash('sha256').update(readFileSync(ELF)).digest('hex');
  assert.equal(rep.file.hashes.sha256, sha);
  if (has('sha256sum')) assert.equal(execFileSync('sha256sum', [ELF], { encoding: 'utf8' }).split(' ')[0], sha);
  const strip = (r: Record<string, unknown>) => { const { generatedAt, timings, ...rest } = r; void generatedAt; void timings; return rest; };
  if (toonRef) {
    const t = cli(['analyze', ELF, '--format', 'toon']);
    assert.equal(t.status, 0, t.stderr);
    assert.deepEqual(strip(toonRef.decode(t.stdout) as Record<string, unknown>), strip(rep));
  }
  const y = cli(['analyze', ELF, '--yaml']);
  assert.deepEqual(strip(YAML.parse(y.stdout)), strip(rep));
  const sec = cli(['analyze', ELF, '--csv']);
  assert.equal(sec.status, 0);
  // the largest list of objects in a report is what csv shows; check a row against the JSON
  const key = rowsOf(rep).key!;
  if (python) {
    const rows = JSON.parse(py('import sys, csv, io, json\nprint(json.dumps(list(csv.DictReader(io.StringIO(sys.stdin.read(), newline="")))))', sec.stdout));
    assert.equal(rows.length, rep[key].length);
    const firstCol = Object.keys(flattenRow(rep[key][0]))[0]!;
    assert.equal(rows[0][firstCol], String(flattenRow(rep[key][0])[firstCol]));
  }
});

test('package commands and core lists convert too, and --out gets the converted text', { timeout: 240_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'fmt-'));
  try {
    const j = JSON.parse(cli(['analyzers', '--json']).stdout) as { id: string }[];
    const out = join(dir, 'a.jsonl');
    const r = cli(['analyzers', '--format=jsonl', '--out', out]);
    assert.equal(r.status, 0, r.stderr);
    const lines = readFileSync(out, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.deepEqual(lines, j);
    const tsv = cli(['analyzers', '--tsv']).stdout.split('\n');
    assert.equal(tsv[0], 'id\ttitle\tdescription\tpackage');
    assert.equal(tsv.length - 2, j.length);
    // a package command (bridges doctor) asked for yaml
    const d = cli(['doctor', '--output-format', 'yaml']);
    assert.equal(d.status, 0, d.stderr);
    const dj = JSON.parse(cli(['doctor', '--json']).stdout);
    const dy = YAML.parse(d.stdout);
    // two runs: the clock and probe timings differ, the inventory does not
    assert.equal(dy.schema, dj.schema);
    assert.deepEqual(dy.tools.map((x: { id: string; available: boolean }) => [x.id, x.available]), dj.tools.map((x: { id: string; available: boolean }) => [x.id, x.available]));
    // discover keeps --format for the file format
    const disc = cli(['discover', 'decompile', '--format', 'elf', '--json']);
    assert.equal(disc.status, 0, disc.stderr);
    assert.ok(Array.isArray(JSON.parse(disc.stdout).tools));
    // verify prints JSON Lines; csv gets one row per claim
    const v = cli(['verify', ELF, 'format=elf', 'section=.text', 'section=.nope', '--csv']);
    const vr = v.stdout.trim().split('\r\n');
    assert.equal(vr.length, 4);
    assert.match(vr[0]!, /^verdict,/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ evidence bundles

test('--evidence-out writes a bundle that evidence-import checks, and tampering is caught', { timeout: 240_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ev-'));
  try {
    const r = cli(['verify', ELF, 'section=.text', '--evidence-out', dir + '/']);
    assert.equal(r.status, 0, r.stderr);
    const file = r.stderr.match(/evidence written to (.+)/)![1]!.trim();
    const b = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(b.schema, EVIDENCE_SCHEMA);
    assert.equal(b.command, 'verify');
    assert.equal(b.inputs[0].sha256, createHash('sha256').update(readFileSync(ELF)).digest('hex'));
    assert.equal(b.output.sha256, createHash('sha256').update(canonicalJson(b.output.value)).digest('hex'));
    assert.equal(b.output.value.verdict, 'VERIFIED');
    const ok = cli(['evidence-import', file, '--json']);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.equal(JSON.parse(ok.stdout).outputIntact, true);
    // record into a ledger file, then the ledger tool verifies those claims against the bytes
    const ledger = join(dir, 'ledger.json');
    const rec = cli(['evidence-import', file, '--ledger', ledger, '--json']);
    assert.equal(rec.status, 0, rec.stderr);
    assert.equal(JSON.parse(rec.stdout).recorded, 1);
    assert.ok(existsSync(ledger));
    // the exported ledger imports again through the same command
    const again = cli(['evidence-import', ledger, '--json']);
    assert.equal(again.status, 0, again.stderr);
    assert.ok(JSON.parse(again.stdout).imported >= 1);
    // edit the result: caught
    b.output.value.verdict = 'REFUTED';
    const bad = join(dir, 'bad.json');
    writeFileSync(bad, JSON.stringify(b));
    const t = cli(['evidence-import', bad, '--json']);
    assert.equal(t.status, 3);
    assert.equal(JSON.parse(t.stdout).outputIntact, false);
    // a changed input: caught
    const copy = join(dir, 'copy.elf');
    writeFileSync(copy, readFileSync(ELF));
    const r2 = cli(['analyzers', '--evidence-out', join(dir, 'x.json')]);
    assert.equal(r2.status, 0);
    const b2 = checkBundle({ ...b, output: { kind: 'text', text: 'x', sha256: createHash('sha256').update('x').digest('hex') }, inputs: [{ arg: copy, path: copy, size: 1, sha256: '0'.repeat(64) }] });
    assert.equal(b2.inputs[0]!.status, 'changed');
    assert.equal(checkBundle({ schema: 'other' }).problems.length > 0, true);
    fc.assert(fc.property(fc.anything({ maxDepth: 3 }), (x) => { checkBundle(x); return true; }), { numRuns: 300 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ completions

test('bash completion completes commands, subcommands and formats in a real bash', { skip: !has('bash') && 'bash missing', timeout: 120_000 }, () => {
  const r = cli(['completions', 'bash', '--alias', 'rl-alias']);
  assert.equal(r.status, 0, r.stderr);
  const dir = mkdtempSync(join(tmpdir(), 'comp-'));
  try {
    const f = join(dir, 'c.bash');
    writeFileSync(f, r.stdout);
    execFileSync('bash', ['-n', f]);
    const fn = /complete -o filenames -F (\S+) /.exec(r.stdout)![1]!;
    const ask = (words: string[]) => execFileSync('bash', ['-c', `source "$1"; COMP_WORDS=(${words.map((w) => `'${w}'`).join(' ')}); COMP_CWORD=${words.length - 1}; ${fn}; printf '%s\\n' "\${COMPREPLY[@]}"`, 'x', f], { encoding: 'utf8', cwd: dir }).trim().split('\n');
    assert.ok(ask(['revlens', 'ana']).includes('analyze'));
    assert.ok(ask(['revlens', 'ana']).includes('analyzers'));
    assert.deepEqual(ask(['revlens', 'analyze', '--format', 'ts']), ['tsv']);
    assert.deepEqual(ask(['revlens', 'completions', 'z']), ['zsh']);
    assert.ok(ask(['revlens', 'disasm', '']).length > 3, 'disasm subcommands');
    assert.ok(ask(['revlens', 'analyze', '--to']).includes('--toon'));
    assert.match(r.stdout, /complete -o filenames -F \S+ rl-alias/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('zsh, fish and PowerShell scripts parse in their shells', { timeout: 120_000 }, (t) => {
  const spec = { programs: ['revlens'], commands: [{ name: 'analyze', summary: "it's: fine" }, { name: 'disasm', summary: 'x', sub: [{ name: 'functions', summary: 'list' }] }], flags: ['json', 'format'], formats: ['json', 'toon'] };
  for (const [sh, args] of [['zsh', ['-n']], ['fish', ['--no-execute']], ['pwsh', ['-NoProfile', '-Command', '-']]] as const) {
    const script = completionScript(sh === 'pwsh' ? 'powershell' : sh, spec);
    assert.ok(script.includes('analyze'));
    if (!has(sh)) { t.diagnostic(`${sh} not installed, syntax not checked`); continue; }
    const dir = mkdtempSync(join(tmpdir(), 'comp-'));
    try {
      const f = join(dir, 's');
      writeFileSync(f, script);
      if (sh === 'pwsh') execFileSync(sh, args as unknown as string[], { input: `$ErrorActionPreference='Stop'; . '${f}'`, encoding: 'utf8' });
      else execFileSync(sh, [...args, f]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  // names that are not safe shell words are dropped instead of being pasted into the script
  const evil = completionScript('bash', { ...spec, commands: [{ name: '$(touch x)', summary: '`id`' }, { name: 'ok', summary: '$(id)' }] });
  assert.ok(!evil.includes('$(touch') && !evil.includes('`id`') && !evil.includes('$(id)'));
});
