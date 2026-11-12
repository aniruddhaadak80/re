#!/usr/bin/env node
// Stage and publish every workspace package for a release.
//
//   node scripts/release/packages.mjs list
//   node scripts/release/packages.mjs stage --out .release/staged [--scope @owner] [--registry URL]
//   node scripts/release/packages.mjs publish --dir .release/staged [--registry URL] [--dry-run] [--provenance] [--tag latest]
//   node scripts/release/packages.mjs verify --dir .release/staged
//
// Nothing here names a package. Names, versions and internal dependencies are read from the
// package.json files of the root "workspaces" globs, so a product rename needs no change here.
//
// stage runs `npm pack` in each public workspace package (so the "files" list decides what ships),
// unpacks the tarball and, when --scope is given, renames the package into that scope:
//   @any/core -> @owner/core      plain-name -> @owner/plain-name
// Every dependency on another workspace package becomes an npm alias to the renamed package
// ("@any/core": "npm:@owner/core@1.2.3"), so `import '@any/core'` in the built code keeps working
// and no source file is rewritten. publishConfig.registry is set to --registry. Without --scope the
// packages are staged unchanged (the npmjs path).
//
// publish goes in dependency order and skips a version that the registry already has, so a failed
// run can be repeated.
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const [cmd, ...rest] = process.argv.slice(2);
const flag = (k) => rest.includes(`--${k}`);
const opt = (k, d) => { const i = rest.indexOf(`--${k}`); return i >= 0 && rest[i + 1] && !rest[i + 1].startsWith('--') ? rest[i + 1] : d; };
const log = (m) => process.stderr.write(`[release] ${m}\n`);
const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies'];

/** Expand the root workspaces globs. Only the "dir/*" and plain "dir" forms are used by this repo. */
export function workspaceDirs(base = root) {
  const pkg = readJson(join(base, 'package.json'));
  const globs = Array.isArray(pkg.workspaces) ? pkg.workspaces : pkg.workspaces?.packages ?? [];
  const out = [];
  for (const g of globs) {
    if (g.endsWith('/*')) {
      const d = join(base, g.slice(0, -2));
      if (!existsSync(d)) continue;
      for (const e of readdirSync(d).sort()) if (existsSync(join(d, e, 'package.json'))) out.push(join(d, e));
    } else if (existsSync(join(base, g, 'package.json'))) out.push(join(base, g));
  }
  return out;
}

/** Public workspace packages in dependency order (a package comes after everything it depends on). */
export function listPackages(base = root) {
  const all = workspaceDirs(base).map((dir) => ({ dir, json: readJson(join(dir, 'package.json')) }));
  const pub = all.filter((p) => !p.json.private && p.json.name && p.json.version);
  const names = new Set(pub.map((p) => p.json.name));
  const byName = new Map(pub.map((p) => [p.json.name, p]));
  const deps = (p) => [...new Set(DEP_FIELDS.flatMap((f) => Object.keys(p.json[f] ?? {})))].filter((n) => names.has(n));
  const order = []; const state = new Map();
  const visit = (p, chain) => {
    const s = state.get(p.json.name);
    if (s === 2) return;
    if (s === 1) throw new Error(`workspace dependency cycle: ${[...chain, p.json.name].join(' -> ')}`);
    state.set(p.json.name, 1);
    for (const d of deps(p)) visit(byName.get(d), [...chain, p.json.name]);
    state.set(p.json.name, 2); order.push(p);
  };
  for (const p of [...pub].sort((a, b) => a.json.name.localeCompare(b.json.name))) visit(p, []);
  return order.map((p) => ({ name: p.json.name, version: p.json.version, dir: relative(base, p.dir).split('\\').join('/'), internalDeps: deps(p) }));
}

/** The name a package gets inside another scope. */
export function scopedName(name, scope) {
  if (!/^@[a-z0-9][a-z0-9._-]*$/.test(scope)) throw new Error(`scope must look like @owner, got ${scope}`);
  const bare = name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
  return `${scope}/${bare}`;
}

/** Rewrite one package.json for a scope. Pure; returns a new object. */
export function rewriteManifest(json, { scope, registry, versions }) {
  const out = structuredClone(json);
  if (!scope) { if (registry) out.publishConfig = { ...(out.publishConfig ?? {}), registry }; return out; }
  out.name = scopedName(json.name, scope);
  for (const f of DEP_FIELDS) {
    if (!out[f]) continue;
    for (const [dep, spec] of Object.entries(out[f])) {
      if (!versions.has(dep)) continue;
      const v = versions.get(dep);
      const want = String(spec).replace(/^workspace:/, '');
      if (want !== '*' && want !== v && want !== `^${v}` && want !== `~${v}`) throw new Error(`${json.name} depends on ${dep}@${spec} but the workspace has ${v}`);
      out[f][dep] = `npm:${scopedName(dep, scope)}@${v}`;
    }
  }
  if (out.repository && typeof out.repository === 'object' && /^https:\/\/.*\.git$/.test(out.repository.url ?? '')) out.repository = { ...out.repository, url: `git+${out.repository.url}` };
  out.publishConfig = { ...(out.publishConfig ?? {}), ...(registry ? { registry } : {}), access: out.publishConfig?.access ?? 'public' };
  delete out.publishConfig.provenance;
  return out;
}

function stage() {
  const outDir = resolve(opt('out', join(root, '.release/staged')));
  const scope = opt('scope');
  const registry = opt('registry', scope ? 'https://npm.pkg.github.com' : undefined);
  const pkgs = listPackages();
  const versions = new Map(pkgs.map((p) => [p.name, p.version]));
  const versionSet = new Set(pkgs.map((p) => p.version));
  if (versionSet.size !== 1 && !flag('allow-mixed-versions')) throw new Error(`workspace versions differ (${[...versionSet].join(', ')}); release-please links them, so this means a manifest is out of date`);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(join(outDir, 'tgz'), { recursive: true });
  const staged = [];
  for (const p of pkgs) {
    const dir = join(root, p.dir);
    if (!existsSync(join(dir, 'dist')) && readJson(join(dir, 'package.json')).files?.includes('dist')) throw new Error(`${p.name}: dist is missing; run npm run build first`);
    const res = JSON.parse(execFileSync(npmCmd, ['pack', '--json', '--pack-destination', join(outDir, 'tgz')], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], shell: process.platform === 'win32' }));
    const tgz = join(outDir, 'tgz', res[0].filename);
    const slot = join(outDir, p.dir.split('/').join('__'));
    mkdirSync(slot, { recursive: true });
    execFileSync('tar', ['-xzf', tgz, '-C', slot]);
    const pkgDir = join(slot, 'package');
    const json = readJson(join(pkgDir, 'package.json'));
    const next = rewriteManifest(json, { scope, registry, versions });
    writeFileSync(join(pkgDir, 'package.json'), JSON.stringify(next, null, 2) + '\n');
    staged.push({ source: p.name, name: next.name, version: next.version, dir: relative(outDir, pkgDir).split('\\').join('/'), files: res[0].entryCount, bytes: res[0].size });
    log(`staged ${next.name}@${next.version} (${res[0].entryCount} files)`);
  }
  writeFileSync(join(outDir, 'staged.json'), JSON.stringify({ scope: scope ?? null, registry: registry ?? null, packages: staged }, null, 2) + '\n');
  process.stdout.write(JSON.stringify({ outDir, packages: staged.length }) + '\n');
}

/** Check a staged set: every internal dependency points at a staged name and version, and no file still names the old scope in package.json deps. */
export function verifyStaged(dir) {
  const m = readJson(join(dir, 'staged.json'));
  const have = new Map(m.packages.map((p) => [p.name, p.version]));
  const problems = [];
  for (const p of m.packages) {
    const json = readJson(join(dir, p.dir, 'package.json'));
    if (json.name !== p.name || json.version !== p.version) problems.push(`${p.dir}: manifest says ${json.name}@${json.version}`);
    for (const f of DEP_FIELDS) for (const [dep, spec] of Object.entries(json[f] ?? {})) {
      const s = String(spec);
      if (s.startsWith('workspace:') || s.startsWith('file:') || s.startsWith('link:')) problems.push(`${json.name}: ${dep} uses ${s}`);
      const alias = /^npm:(@?[^@]+)@(.+)$/.exec(s);
      if (alias && m.scope && !have.has(alias[1])) problems.push(`${json.name}: alias ${dep} -> ${alias[1]} is not staged`);
      if (alias && m.scope && have.get(alias[1]) !== alias[2]) problems.push(`${json.name}: alias ${dep} wants ${alias[2]}, staged ${have.get(alias[1])}`);
      if (!alias && m.scope && m.packages.some((q) => q.source === dep)) problems.push(`${json.name}: ${dep} was not rewritten`);
    }
    if (m.registry && json.publishConfig?.registry !== m.registry) problems.push(`${json.name}: publishConfig.registry is ${json.publishConfig?.registry}`);
    for (const b of Object.values(typeof json.bin === 'string' ? { x: json.bin } : json.bin ?? {})) if (!existsSync(join(dir, p.dir, b))) problems.push(`${json.name}: bin ${b} is not in the package`);
    const main = json.exports?.['.']?.default ?? json.main;
    if (main && !existsSync(join(dir, p.dir, main))) problems.push(`${json.name}: entry ${main} is not in the package`);
  }
  return problems;
}

function publish() {
  const dir = resolve(opt('dir', join(root, '.release/staged')));
  const m = readJson(join(dir, 'staged.json'));
  const registry = opt('registry', m.registry ?? 'https://registry.npmjs.org');
  const dry = flag('dry-run');
  const problems = verifyStaged(dir);
  if (problems.length) throw new Error(`staged packages are not consistent:\n  ${problems.join('\n  ')}`);
  const results = [];
  for (const p of m.packages) {
    const pkgDir = join(dir, p.dir);
    if (!dry) {
      const v = spawnSync(npmCmd, ['view', `${p.name}@${p.version}`, 'version', '--registry', registry], { encoding: 'utf8', shell: process.platform === 'win32' });
      if (v.status === 0 && v.stdout.trim() === p.version) { log(`${p.name}@${p.version} is already on ${registry}, skipped`); results.push({ ...p, status: 'exists' }); continue; }
    }
    const args = ['publish', pkgDir, '--registry', registry, '--access', 'public', '--tag', opt('tag', 'latest')];
    if (flag('provenance')) args.push('--provenance');
    if (dry) args.push('--dry-run');
    log(`npm ${args.join(' ')}`);
    const r = spawnSync(npmCmd, args, { stdio: ['ignore', 'inherit', 'inherit'], shell: process.platform === 'win32' });
    if (r.status !== 0) throw new Error(`npm publish failed for ${p.name}@${p.version} (exit ${r.status})`);
    results.push({ ...p, status: dry ? 'dry-run' : 'published' });
  }
  process.stdout.write(JSON.stringify({ registry, dryRun: dry, results }, null, 2) + '\n');
}

if (import.meta.url === `file://${process.argv[1]}` || fileURLToPath(import.meta.url) === resolve(process.argv[1] ?? '')) {
  try {
    if (cmd === 'list') process.stdout.write(JSON.stringify(listPackages(), null, 2) + '\n');
    else if (cmd === 'stage') stage();
    else if (cmd === 'publish') publish();
    else if (cmd === 'verify') { const pr = verifyStaged(resolve(opt('dir', join(root, '.release/staged')))); if (pr.length) { process.stderr.write(pr.join('\n') + '\n'); process.exit(1); } log('staged packages are consistent'); }
    else { process.stderr.write('usage: packages.mjs list|stage|publish|verify (see the header of this file)\n'); process.exit(2); }
  } catch (e) { process.stderr.write(`[release] ${e.message}\n`); process.exit(1); }
}
