// Eval harness: an oracle agent that only uses RevLens TOOLS must score 1.0 against ground
// truth that came from independent reference tools. This cross-checks tools and tasks together.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { TOOLS, EVAL_TASKS, publicTasks, scoreAnswers, scoreTask } from '../src/node.js';
import { ROOT, cached } from './helpers.js';

const run = async (name: string, input: Record<string, unknown>): Promise<any> => TOOLS.find((t) => t.name === name)!.run(input);

async function oracle(id: string, file: string): Promise<unknown> {
  const path = join(ROOT, file);
  switch (id) {
    case 'pe-file-version': return (await run('x_pe_resources', { path })).versionInfo.fileVersion;
    case 'pe-company': return (await run('x_pe_resources', { path })).versionInfo.strings.CompanyName;
    case 'pe-exports': return (await run('x_pe_inspect', { path })).exports.functions.map((f: { name: string }) => f.name);
    case 'pe-imports': { const { parseBin } = await import('../src/node.js'); void parseBin; const { ANALYZERS } = await import('../src/node.js'); void ANALYZERS; const core = await import('@revlens/core'); const { readFileSync } = await import('node:fs'); const r = await core.analyze(new Uint8Array(readFileSync(path)), { name: file }); return r.imports.map((i) => i.library); }
    case 'pe-authentihash': { const { authenticodeDigest } = await import('../src/node.js'); const { readFileSync } = await import('node:fs'); return authenticodeDigest(new Uint8Array(readFileSync(path))); }
    case 'pe-manifest-level': return (await run('x_pe_resources', { path })).manifest.requestedExecutionLevel;
    case 'elf-needed': return (await run('x_elf_inspect', { path })).dynamic.needed;
    case 'elf-entry': return (await run('x_container', { path })).entry;
    case 'elf-fde-count': return (await run('x_elf_unwind', { path, limit: 1 })).total;
    case 'elf-relro': { const c = await run('x_checksec', { path }); const g = (n: string) => c.checks.find((x: { name: string }) => x.name === n).value; return `relro=${g('RELRO') !== 'none' ? 'yes' : 'no'} nx=${g('NX') ? 'yes' : 'no'}`; }
    case 'cxx-demangle-sum': return (await run('x_demangle', { path, filter: 'revlens::demo::sum' })).items[0].demangled;
    case 'msvc-demangle-scale': return (await run('x_demangle', { symbols: ['?scale@demo@revlens@@YANNM_J@Z'] })).items[0].output;
    case 'go-main-addr': return (await run('x_go_symbols', { path, filter: 'main.main' })).functions.items.find((f: { name: string }) => f.name === 'main.main').entry;
    case 'rust-version': return (await run('x_rust_info', { path })).rustcVersion;
    case 'rust-crates': return (await run('x_rust_info', { path })).crates.map((c: { name: string }) => c.name);
    case 'macho-cdhash': return (await run('x_macho_inspect', { path })).codeSignature.codeDirectories[0].cdhash;
    case 'macho-dylibs': return (await run('x_macho_inspect', { path })).dylibs.map((d: { name: string }) => d.name);
    case 'fw-dtb-offset': return (await run('x_firmware_scan', { path })).items.find((h: { type: string }) => h.type === 'fdt').offset;
    case 'fw-uimage-name': { const h = (await run('x_firmware_scan', { path })).items.find((x: { type: string }) => x.type === 'uimage'); return (await run('x_firmware_parse', { path, kind: 'uimage', at: h.offset })).name; }
    case 'dtb-model': return (await run('x_firmware_parse', { path, kind: 'fdt' })).root.props.model.text;
    case 'ihex-start': return (await run('x_firmware_parse', { path, kind: 'ihex' })).regions[0].start;
    case 'gguf-arch': return (await run('x_model_inspect', { path })).architecture;
    case 'gguf-tensors': return (await run('x_model_inspect', { path })).tensors.items.map((t: { name: string }) => t.name);
    case 'lnk-target': return (await run('x_lnk_inspect', { path })).target;
    case 'lnk-args': return (await run('x_lnk_inspect', { path })).arguments;
    case 'v8-source-length': return (await run('x_v8_inspect', { path })).sourceLength;
    case 'ptx-kernels': return (await run('x_gpu_inspect', { path })).ptx.entries.map((e: { name: string }) => e.name);
    case 'amdgpu-target': return (await run('x_gpu_inspect', { path })).amdgpu.target;
    case 'spirv-stage': return (await run('x_gpu_inspect', { path })).spirv.entryPoints[0].executionModel;
    case 'spirv-localsize': return (await run('x_gpu_inspect', { path })).spirv.executionModes.find((m: { mode: number }) => m.mode === 17).operands.join(',');
    default: return undefined;
  }
}

test('public tasks hide answers and references', () => {
  const p = publicTasks();
  assert.equal(p.length, EVAL_TASKS.length);
  assert.ok(p.length >= 25);
  for (const t of p) { assert.equal('answer' in t, false); assert.equal('reference' in t, false); }
  assert.ok(publicTasks('pe').every((t) => t.tags.includes('pe')));
});

test('an oracle agent using only RevLens tools scores 1.0 on every task', async () => {
  const answers: Record<string, unknown> = {};
  for (const t of EVAL_TASKS) answers[t.id] = await oracle(t.id, t.file);
  const s = scoreAnswers(answers, { agent: 'revlens-oracle' });
  const wrong = s.results.filter((r) => !r.correct);
  assert.deepEqual(wrong, []);
  assert.equal(s.score, 1);
  assert.equal(s.accuracy, 1);
  void cached;
});

test('scoring rules: hex and int normalise, sets get F1 credit, unknown ids are rejected', () => {
  const base = { id: 't', question: '', file: '', tags: [], reference: '' };
  assert.equal(scoreTask({ ...base, answerType: 'hex', answer: '0x493de0' }, '493DE0').correct, true);
  assert.equal(scoreTask({ ...base, answerType: 'hex', answer: '0x493de0' }, 4799968).correct, true);
  assert.equal(scoreTask({ ...base, answerType: 'int', answer: 478 }, '478').correct, true);
  const set = scoreTask({ ...base, answerType: 'set', answer: ['a', 'b', 'c', 'd'] }, 'a, b, x');
  assert.equal(set.correct, false);
  assert.ok(set.score > 0.5 && set.score < 0.6);
  assert.equal(scoreTask({ ...base, answerType: 'exact', answer: 'asInvoker' }, ' ASINVOKER ').correct, true);
  assert.equal(scoreTask({ ...base, answerType: 'contains', answer: ['1.79.0'] }, 'rustc 1.79.0 (abc)').correct, true);
  assert.throws(() => scoreAnswers({ 'no-such-task': 1 }));
  const empty = scoreAnswers({});
  assert.equal(empty.score, 0); assert.equal(empty.answered, 0);
});

test('x_eval_tasks and x_eval_score tools round trip', async () => {
  const tasks = await run('x_eval_tasks', { tag: 'gpu' });
  assert.ok(tasks.tasks.length >= 4);
  const s = await run('x_eval_score', { answers: { 'amdgpu-target': 'gfx906', 'spirv-stage': 'Vertex' } });
  assert.equal(s.results.find((r: { id: string }) => r.id === 'amdgpu-target').correct, true);
  assert.equal(s.results.find((r: { id: string }) => r.id === 'spirv-stage').correct, false);
});
