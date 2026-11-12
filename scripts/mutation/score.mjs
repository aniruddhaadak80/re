#!/usr/bin/env node
// Print the mutation score of a Stryker JSON report (mutation-testing-report-schema) as Markdown.
//   node scripts/mutation/score.mjs scripts/mutation/reports/core/mutation.json [--json]
import { readFileSync } from 'node:fs';

export function score(report) {
  const c = { Killed: 0, Survived: 0, Timeout: 0, NoCoverage: 0, CompileError: 0, RuntimeError: 0, Ignored: 0, Pending: 0 };
  const files = [];
  for (const [name, f] of Object.entries(report.files ?? {})) {
    const fc = { Killed: 0, Survived: 0, Timeout: 0, NoCoverage: 0 };
    for (const m of f.mutants ?? []) { c[m.status] = (c[m.status] ?? 0) + 1; if (m.status in fc) fc[m.status]++; }
    const det = fc.Killed + fc.Timeout; const valid = det + fc.Survived + fc.NoCoverage;
    files.push({ name, score: valid ? (100 * det) / valid : null, ...fc });
  }
  const detected = c.Killed + c.Timeout;
  const valid = detected + c.Survived + c.NoCoverage;
  const covered = detected + c.Survived;
  return { counts: c, mutationScore: valid ? (100 * detected) / valid : null, coveredScore: covered ? (100 * detected) / covered : null, files };
}

if (process.argv[1]?.endsWith('score.mjs')) {
  const s = score(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  if (process.argv.includes('--json')) process.stdout.write(JSON.stringify(s, null, 2) + '\n');
  else {
    const f = (x) => (x === null ? 'n/a' : x.toFixed(2) + '%');
    const out = [`### Mutation score ${f(s.mutationScore)} (covered code ${f(s.coveredScore)})`, '', '| killed | timeout | survived | no coverage | ignored or errors |', '|---|---|---|---|---|', `| ${s.counts.Killed} | ${s.counts.Timeout} | ${s.counts.Survived} | ${s.counts.NoCoverage} | ${s.counts.Ignored + s.counts.CompileError + s.counts.RuntimeError} |`, '', '| file | score | survived |', '|---|---|---|'];
    for (const x of s.files.sort((a, b) => (a.score ?? 101) - (b.score ?? 101)).slice(0, 25)) out.push(`| ${x.name} | ${f(x.score)} | ${x.Survived} |`);
    process.stdout.write(out.join('\n') + '\n');
  }
}
