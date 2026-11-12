// Tests for the release scripts. The unit tests always run. The round trip (stage, publish to an
// in-process registry, install the CLI from it into an empty folder and run it) runs when
// RELEASE_E2E=1, because it needs the built packages and network access for third party deps.
//
//   node --test scripts/release/release.test.mjs
//   RELEASE_E2E=1 node --test scripts/release/release.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { listPackages, rewriteManifest, scopedName, verifyStaged } from './packages.mjs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

test('workspace packages come in dependency order and none is private', () => {
  const pkgs = listPackages();
  assert.ok(pkgs.length >= 3);
  const seen = new Set();
  for (const p of pkgs) {
    for (const d of p.internalDeps) assert.ok(seen.has(d), `${p.name} is listed before its dependency ${d}`);
    seen.add(p.name);
    assert.equal(JSON.parse(readFileSync(join(root, p.dir, 'package.json'), 'utf8')).private, undefined);
  }
  const cliPkg = JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8'));
  assert.equal(pkgs.at(-1).name, cliPkg.name, 'the CLI depends on the most and is published last');
});

test('scopedName moves scoped and plain names into the new scope', () => {
  assert.equal(scopedName('@x/core', '@owner'), '@owner/core');
  assert.equal(scopedName('tool', '@owner'), '@owner/tool');
  assert.throws(() => scopedName('@x/core', 'owner'));
  assert.throws(() => scopedName('@x/core', '@Owner'));
});

test('rewriteManifest aliases internal deps and keeps the rest', () => {
  const versions = new Map([['@x/core', '2.1.0'], ['@x/engine', '2.1.0']]);
  const out = rewriteManifest({ name: 'tool', version: '2.1.0', bin: { tool: './dist/index.js' }, repository: { type: 'git', url: 'https://github.com/o/r.git' }, dependencies: { '@x/core': '2.1.0', '@x/engine': '^2.1.0', zod: '^4.0.0' }, peerDependencies: { '@x/core': '*' } }, { scope: '@owner', registry: 'https://npm.pkg.github.com', versions });
  assert.equal(out.name, '@owner/tool');
  assert.deepEqual(out.dependencies, { '@x/core': 'npm:@owner/core@2.1.0', '@x/engine': 'npm:@owner/engine@2.1.0', zod: '^4.0.0' });
  assert.equal(out.peerDependencies['@x/core'], 'npm:@owner/core@2.1.0');
  assert.equal(out.publishConfig.registry, 'https://npm.pkg.github.com');
  assert.equal(out.repository.url, 'git+https://github.com/o/r.git');
  assert.deepEqual(out.bin, { tool: './dist/index.js' }, 'bin names do not change');
  assert.throws(() => rewriteManifest({ name: '@x/a', version: '2.1.0', dependencies: { '@x/core': '1.0.0' } }, { scope: '@owner', versions }), /workspace has 2.1.0/);
  const plain = rewriteManifest({ name: '@x/a', version: '1.0.0' }, { versions });
  assert.equal(plain.name, '@x/a', 'without a scope the name stays');
});

test('stage, publish to a local registry, install and run the CLI', { skip: process.env.RELEASE_E2E !== '1' && 'set RELEASE_E2E=1', timeout: 600_000 }, async () => {
  const work = mkdtempSync(join(tmpdir(), 'release-e2e-'));
  // The registry runs in its own process: the steps below use execFileSync, which blocks this event loop.
  const child = spawn(process.execPath, [join(root, 'scripts/release/local-registry.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
  const first = await new Promise((ok, bad) => { createInterface({ input: child.stdout }).once('line', ok); child.once('exit', () => bad(new Error('registry exited'))); });
  const reg = { url: JSON.parse(first).url, close: async () => { child.kill(); } };
  const docOf = async (name) => { const r = await fetch(reg.url + name.replace('/', '%2f')); return r.ok ? r.json() : undefined; };
  try {
    const scope = '@e2e-owner';
    const staged = join(work, 'staged');
    execFileSync(process.execPath, [join(root, 'scripts/release/packages.mjs'), 'stage', '--out', staged, '--scope', scope, '--registry', reg.url], { stdio: 'inherit' });
    assert.deepEqual(verifyStaged(staged), []);
    const host = new URL(reg.url).host;
    const npmrc = join(work, '.npmrc');
    writeFileSync(npmrc, `//${host}/:_authToken=test-token\n${scope}:registry=${reg.url}\nnoproxy=127.0.0.1,localhost\n`);
    const env = { ...process.env, NPM_CONFIG_USERCONFIG: npmrc, NO_PROXY: [process.env.NO_PROXY, "127.0.0.1", "localhost"].filter(Boolean).join(","), no_proxy: [process.env.no_proxy, "127.0.0.1", "localhost"].filter(Boolean).join(",") };
    execFileSync(process.execPath, [join(root, 'scripts/release/packages.mjs'), 'publish', '--dir', staged, '--registry', reg.url], { stdio: 'inherit', env });
    const list = JSON.parse(readFileSync(join(staged, 'staged.json'), 'utf8')).packages;
    for (const p of list) assert.ok((await docOf(p.name))?.versions[p.version], `${p.name}@${p.version} is on the registry`);
    // publishing again skips what is there
    const again = execFileSync(process.execPath, [join(root, 'scripts/release/packages.mjs'), 'publish', '--dir', staged, '--registry', reg.url], { encoding: 'utf8', env });
    assert.ok(JSON.parse(again).results.every((r) => r.status === 'exists'));
    const cli = list.at(-1);
    const app = join(work, 'app');
    execFileSync(npm, ['init', '-y'], { cwd: (execFileSync('mkdir', ['-p', app]), app), stdio: 'ignore', env });
    execFileSync(npm, ['install', '--no-audit', '--no-fund', `${cli.name}@${cli.version}`], { cwd: app, stdio: 'inherit', env, shell: process.platform === 'win32' });
    const cliJson = JSON.parse(readFileSync(join(app, 'node_modules', cli.name, 'package.json'), 'utf8'));
    const binName = Object.keys(cliJson.bin)[0];
    const bin = join(app, 'node_modules', '.bin', binName);
    assert.equal(execFileSync(bin, ['--version'], { encoding: 'utf8' }).trim(), cli.version);
    const sample = join(root, 'samples/ls-linux.elf');
    if (existsSync(sample)) {
      const r = spawnSync(bin, ['analyze', sample, '--json'], { encoding: 'utf8', maxBuffer: 64 << 20 });
      assert.equal(r.status, 0, r.stderr);
      const rep = JSON.parse(r.stdout);
      assert.equal(rep.format ?? rep.file?.format, 'elf');
    }
  } finally { await reg.close(); rmSync(work, { recursive: true, force: true }); }
});
