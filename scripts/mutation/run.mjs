#!/usr/bin/env node
// Run Stryker for one target from the repository root: MUTATE_PACKAGE=<name> node scripts/mutation/run.mjs
// Extra arguments go to `stryker run`. Exit code is Stryker's (non zero when the score is under "break").
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const bin = join(here, 'node_modules/@stryker-mutator/core/bin/stryker.js');
if (!existsSync(bin)) { process.stderr.write('Stryker is not installed. Run: npm install --prefix scripts/mutation\n'); process.exit(2); }
const r = spawnSync(process.execPath, [bin, 'run', join(here, 'stryker.config.mjs'), ...process.argv.slice(2)], { cwd: root, stdio: 'inherit', env: process.env });
process.exit(r.status ?? 1);
