#!/usr/bin/env node
// Time equivalent offline operations in rea (run from source through its own tsx, because its compiled
// runtime needs a native tsrs build step that is not available on this host) and RevLens (built dist).
// Each side runs one command PARITY_N times inside one process; the first two runs are warm-up and the
// median of the rest is reported, so module loading and transpiling are not counted. Import time and
// CPU are reported separately.
// Usage: node scripts/parity/bench.mjs [--rea /workspace/work/rea-src] [--n 7] [--only name]
// Writes docs/parity/data/bench.json.
import { execFileSync } from 'node:child_process';
import { writeFileSync, unlinkSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const REA = resolve(opt('--rea', '/workspace/work/rea-src'));
const ROOT = resolve('.');
const N = Number(opt('--n', '7'));
const ONLY = opt('--only');
const S = join(ROOT, 'samples');
const OUT = join(ROOT, 'docs/parity/data/bench.json');

const PAIRS = [
  { operation: 'ELF notes', fixture: 'samples/ls-linux.elf', rea: ['inspect-elf-notes', `${S}/ls-linux.elf`], rl: ['extras', 'x-elf', `${S}/ls-linux.elf`, '--json'], note: 'RevLens also returns the dynamic section and init arrays.' },
  { operation: 'binary hardening', fixture: 'samples/ls-linux.elf', rea: ['inspect-binary-hardening', `${S}/ls-linux.elf`], rl: ['extras', 'x-checksec', `${S}/ls-linux.elf`, '--json'] },
  { operation: 'ELF unwind ranges', fixture: 'samples/ls-linux.elf', rea: ['inspect-elf-unwind-ranges', `${S}/ls-linux.elf`], rl: ['extras', 'x-unwind', `${S}/ls-linux.elf`, '--json'] },
  { operation: 'Python pyc', fixture: 'samples/managed/python/sample_mod.3.12.pyc', rea: ['inspect-python-pyc', `${S}/managed/python/sample_mod.3.12.pyc`], rl: ['managed', 'pyc', `${S}/managed/python/sample_mod.3.12.pyc`, '--json'], note: 'RevLens also disassembles every code object.' },
  { operation: 'Erlang BEAM', fixture: 'samples/managed/beam/elixir_sup.beam', rea: ['inspect-erlang-beam', `${S}/managed/beam/elixir_sup.beam`], rl: ['managed', 'beam', `${S}/managed/beam/elixir_sup.beam`, '--json'] },
  { operation: '.NET metadata summary', fixture: 'samples/managed/dotnet/RevDemoLib-1.0.0.dll', rea: ['inspect-managed-artifact', `${S}/managed/dotnet/RevDemoLib-1.0.0.dll`], rl: ['managed', 'dotnet', `${S}/managed/dotnet/RevDemoLib-1.0.0.dll`, '--json'] },
  { operation: 'PE resources', fixture: 'samples/extras/hello-res.exe', rea: ['inspect-pe-resources', `${S}/extras/hello-res.exe`], rl: ['extras', 'x-pe-resources', `${S}/extras/hello-res.exe`, '--json'] },
  { operation: 'PE imports (deep PE view)', fixture: 'samples/disasm/hello-x64.exe', rea: ['inspect-pe-imports', `${S}/disasm/hello-x64.exe`], rl: ['extras', 'x-pe', `${S}/disasm/hello-x64.exe`, '--json'], note: 'x-pe returns the whole deep PE view, not only imports.' },
  { operation: 'Windows shortcut', fixture: 'samples/extras/notepad.lnk', rea: ['inspect-windows-shortcut', `${S}/extras/notepad.lnk`], rl: ['extras', 'x-lnk', `${S}/extras/notepad.lnk`, '--json'] },
  { operation: 'devicetree', fixture: 'samples/extras/board.dtb', rea: ['inspect-devicetree', `${S}/extras/board.dtb`], rl: ['extras', 'x-firmware-parse', `${S}/extras/board.dtb`, '--kind', 'fdt', '--json'] },
  { operation: 'GGUF model header', fixture: 'samples/extras/tiny.gguf', rea: ['inspect-model-artifact', `${S}/extras/tiny.gguf`], rl: ['extras', 'x-model', `${S}/extras/tiny.gguf`, '--json'] },
  { operation: 'V8 code cache', fixture: 'samples/extras/add.jsc', rea: ['inspect-v8-code-cache', `${S}/extras/add.jsc`], rl: ['extras', 'x-v8', `${S}/extras/add.jsc`, '--json'] },
];

const REA_HELPER = `
const t0 = performance.now();
const { createCli, closeCliResources } = await import("./src/cli.ts");
const importMs = performance.now();
const n = Number(process.env.PARITY_N ?? 5);
const argv = process.argv.slice(2);
const times = [];
const write = process.stdout.write.bind(process.stdout);
let bytes = 0;
process.stdout.write = (c) => { bytes += String(c).length; return true; };
for (let i = 0; i < n; i++) {
  const cli = createCli(process.env);
  const t = performance.now();
  await cli.serve(argv);
  times.push(performance.now() - t);
}
await closeCliResources();
process.stdout.write = write;
const cpu = process.cpuUsage();
console.log(JSON.stringify({ importMs, times, bytes: Math.round(bytes / n), exitCode: process.exitCode ?? 0, cpuMs: (cpu.user + cpu.system) / 1000, maxRssKiB: process.resourceUsage().maxRSS }));
process.exit(0);
`;

const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.floor(s.length / 2)] : NaN; };
const last = (s) => s.trim().split('\n').filter((l) => l.startsWith('{')).pop();

function runRea(argv) {
  const helper = join(REA, `.parity-bench-${process.pid}.ts`);
  writeFileSync(helper, REA_HELPER);
  try {
    const out = execFileSync(process.execPath, ['--import', 'tsx', helper, ...argv, '--format', 'json'], { cwd: REA, timeout: 600_000, maxBuffer: 64 << 20, env: { ...process.env, PARITY_N: String(N), REA_LOG_LEVEL: 'silent' }, stdio: ['ignore', 'pipe', 'pipe'] });
    return JSON.parse(last(out.toString()));
  } catch (e) { return { error: String(e.stderr ?? e.message).slice(0, 400) }; }
  finally { try { unlinkSync(helper); } catch { /* flaky mount */ } }
}
function runRl(argv) {
  try {
    const out = execFileSync(process.execPath, [join(ROOT, 'scripts/parity/revlens-loop.mjs'), ...argv], { cwd: ROOT, timeout: 600_000, maxBuffer: 64 << 20, env: { ...process.env, PARITY_N: String(N), PARITY_ROOT: ROOT }, stdio: ['ignore', 'pipe', 'pipe'] });
    return JSON.parse(last(out.toString()));
  } catch (e) { return { error: String(e.stderr ?? e.message).slice(0, 400) }; }
}

const prev = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : { rows: [] };
const rows = [];
for (const pair of PAIRS) {
  if (ONLY && pair.operation !== ONLY) { const old = prev.rows.find((r) => r.operation === pair.operation); if (old) rows.push(old); continue; }
  const a = runRea(pair.rea);
  const b = runRl(pair.rl);
  const ma = a.times ? median(a.times.slice(2)) : undefined;
  const mb = b.times ? median(b.times.slice(2)) : undefined;
  const fmt = (r, mm) => r.error ? `failed: ${r.error.split('\n').find((l) => l.trim()) ?? 'error'}` : `${mm.toFixed(1)} ms (exit ${r.exitCode}, ${r.bytes} B out, import ${Math.round(r.importMs)} ms, RSS ${Math.round(r.maxRssKiB / 1024)} MiB)`;
  const row = {
    operation: pair.operation, fixture: pair.fixture,
    rea: fmt(a, ma), revlens: fmt(b, mb),
    ratio: ma && mb && !a.error && !b.error ? `${(ma / mb).toFixed(1)}x` : undefined,
    raw: { rea: a, revlens: b }, note: pair.note,
  };
  rows.push(row);
  console.log(JSON.stringify({ operation: row.operation, rea: row.rea, revlens: row.revlens, ratio: row.ratio }));
}
const host = `${process.platform} ${process.arch}, Node ${process.version}`;
const result = {
  note: `Warm in-process medians over ${N - 2} runs after 2 warm-up runs, ${host}. rea ${JSON.parse(readFileSync(join(REA, 'package.json'), 'utf8')).version} runs from TypeScript source through its own tsx (its compiled runtime could not be built here: the compile step needs the tsrs native binary, which its optional dependencies did not provide for this platform, and the package asks for Node ^22.23.4 while the host has ${process.version}); RevLens runs from its tsc output. Warm medians exclude transpiling and module loading, so the comparison is fair for the work itself; import time is shown per side. Both sides read the same file and print JSON; rea output includes Evidence identity and source ranges, so byte counts differ.`,
  rows,
  notes: [
    'This sandbox has slow file system reads, so cold process start times swing by seconds; they are not used for the ratio.',
    'Operations that need external programs on one side only (TShark, sigrok, WABT, Ghidra, Hopper, swift-demangle) are not compared.',
    ...rows.filter((r) => r.note).map((r) => `${r.operation}: ${r.note}`),
    ...rows.filter((r) => r.ratio && parseFloat(r.ratio) < 1.5).map((r) => `${r.operation}: RevLens is not clearly faster here (${r.ratio}); worth profiling in round 4.`),
    'Import time and memory: rea loads its whole CLI (and here, transpiles it); RevLens loads its engine. Resident memory after the runs is listed per row.',
  ],
};
writeFileSync(OUT, JSON.stringify(result, null, 1) + '\n');
