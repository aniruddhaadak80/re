// Stryker mutation testing, one config for every target package.
//
//   npm install --prefix scripts/mutation
//   MUTATE_PACKAGE=core node scripts/mutation/run.mjs            # or bridges, cli, mcp
//
// The tap runner starts each test file with `node --import tsx`, so the TypeScript sources are
// mutated directly and no build step is needed. Coverage is per test file. The threshold for a
// package comes from thresholds.json next to this file; a score under "break" fails the run.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = process.env.MUTATE_PACKAGE || 'core';
const targets = JSON.parse(readFileSync(join(here, 'targets.json'), 'utf8'));
const t = targets[pkg];
if (!t) throw new Error(`no mutation target named ${pkg}; known: ${Object.keys(targets).join(', ')}`);

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  packageManager: 'npm',
  testRunner: 'tap',
  plugins: [join(here, 'node_modules/@stryker-mutator/tap-runner/dist/src/index.js')],
  tap: {
    testFiles: t.testFiles,
    nodeArgs: ['--import', 'tsx', '--test-reporter=tap', '-r', '{{hookFile}}', '{{testFile}}'],
    forceBail: true,
  },
  mutate: t.mutate,
  // Copy only what the tests read into the sandbox; node_modules is linked, not copied.
  ignorePatterns: ['/apps', '/docs', '/content', '/examples', '/dist-sea', '/samples/.cache', '**/dist', '/scripts/mutation/node_modules', '/scripts/mutation/reports', '/scripts/mutation/.stryker-tmp'],
  coverageAnalysis: 'perTest',
  concurrency: Number(process.env.MUTATE_CONCURRENCY || 2),
  timeoutMS: 20000,
  timeoutFactor: 2,
  thresholds: t.thresholds,
  reporters: ['clear-text', 'progress-append-only', 'html', 'json'],
  htmlReporter: { fileName: `scripts/mutation/reports/${pkg}/mutation.html` },
  jsonReporter: { fileName: `scripts/mutation/reports/${pkg}/mutation.json` },
  tempDirName: `scripts/mutation/.stryker-tmp/${pkg}`,
  cleanTempDir: 'always',
  incremental: process.env.MUTATE_INCREMENTAL === '1',
  ignoreStatic: process.env.MUTATE_IGNORE_STATIC === '1',
  incrementalFile: `scripts/mutation/reports/${pkg}/incremental.json`,
};
