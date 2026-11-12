// install.sh against a local release server: picks the asset for this OS and CPU from SHA256SUMS,
// checks the SHA-256 (computed independently here with node:crypto and sha256sum), refuses a
// tampered binary without installing anything, honours --version and --alias, and runs the binary.
// When REVLENS_SEA_BINARY points at a built single executable, that real binary is installed and run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, readlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SCRIPT = join(root, 'install.sh');
const posix = process.platform !== 'win32';
const os = process.platform === 'darwin' ? 'macos' : 'linux';
const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
const bin = JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8')).bin;
const binName = Object.keys(bin)[0]!;
const asset = `${binName}-${os}-${arch}`;
const sea = process.env.REVLENS_SEA_BINARY;

let server: Server;
let base = '';
let releases = '';
const hits: string[] = [];
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

function release(tag: string, files: Record<string, Buffer>, sums: string) {
  const d = join(releases, tag);
  mkdirSync(d, { recursive: true });
  for (const [n, b] of Object.entries(files)) writeFileSync(join(d, n), b);
  writeFileSync(join(d, 'SHA256SUMS'), sums);
}

before(async () => {
  releases = mkdtempSync(join(tmpdir(), 'rl-releases-'));
  server = createServer((req, res) => {
    hits.push(req.url ?? '');
    // /download/<tag>/<file> and /latest/download/<file>
    const m = /^\/(?:download\/([^/]+)|latest\/download)\/([^/]+)$/.exec(req.url ?? '');
    const p = m ? join(releases, m[1] ?? 'latest', m[2]!) : '';
    if (!p || !existsSync(p)) { res.writeHead(404); res.end('missing'); return; }
    res.writeHead(200); res.end(readFileSync(p));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const fake = Buffer.from('#!/bin/sh\necho 9.9.9\n');
  const real = sea && existsSync(sea) ? readFileSync(sea) : fake;
  const other = Buffer.from('#!/bin/sh\necho other\n');
  release('latest', { [asset]: real, [`${binName}-windows-x64.exe`]: other }, `${sha(real)}  ${asset}\n${sha(other)}  ${binName}-windows-x64.exe\n`);
  release('v1.2.3', { [asset]: fake }, `${sha(fake)}  ${asset}\n`);
  release('v6.6.6', { [asset]: Buffer.from('#!/bin/sh\necho evil\n') }, `${sha(fake)}  ${asset}\n`);
  release('v0.0.1', { 'x-plan9-mips': fake }, `${sha(fake)}  x-plan9-mips\n`);
});
after(() => server?.close());

/** Run install.sh without blocking the event loop (the release server lives in this process). */
function install(args: string[], env: Record<string, string> = {}): Promise<{ status: number | null; stderr: string; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), 'rl-install-'));
  return new Promise((ok) => {
    const c = spawn('sh', [SCRIPT, '--dir', dir, ...args], { env: { PATH: process.env.PATH!, HOME: dir, INSTALL_BASE_URL: base, ...env }, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    c.stderr.on('data', (d) => { stderr += d; });
    c.on('close', (status) => ok({ status, stderr, dir }));
  });
}

test('installs the latest binary for this platform after checking its sha256', { skip: !posix && 'POSIX shell' }, async () => {
  const r = await install(['--alias', 'rl-alias']);
  assert.equal(r.status, 0, r.stderr);
  const target = join(r.dir, binName);
  const bytes = readFileSync(target);
  const reference = execFileSync('sha256sum', [target], { encoding: 'utf8' }).split(' ')[0];
  assert.equal(sha(bytes), reference);
  assert.match(r.stderr, new RegExp(`sha256 ok: ${reference}`));
  assert.equal(readlinkSync(join(r.dir, 'rl-alias')), binName);
  const v = execFileSync(target, ['--version'], { encoding: 'utf8' }).trim();
  if (sea && existsSync(sea)) {
    assert.equal(v, JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8')).version);
    const out = execFileSync(target, ['analyze', join(root, 'samples/disasm/hello-x64.elf'), '--json'], { encoding: 'utf8', maxBuffer: 64 << 20 });
    const rep = JSON.parse(out);
    assert.equal(rep.file.format, 'elf');
    assert.equal(rep.file.hashes.sha256, sha(readFileSync(join(root, 'samples/disasm/hello-x64.elf'))));
    assert.ok(rep.meta.disasm.functions > 0);
  } else assert.equal(v, '9.9.9');
  assert.ok(hits.includes(`/latest/download/${asset}`));
});

test('--version picks the tagged release', { skip: !posix && 'POSIX shell' }, async () => {
  const r = await install(['--version', '1.2.3']);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(hits.includes(`/download/v1.2.3/${asset}`));
});

test('a binary that does not match SHA256SUMS is refused and nothing is installed', { skip: !posix && 'POSIX shell' }, async () => {
  const r = await install(['--version', 'v6.6.6']);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /sha256 mismatch/);
  assert.equal(existsSync(join(r.dir, binName)), false);
});

test('no asset for this platform, bad options and dry run', { skip: !posix && 'POSIX shell' }, async () => {
  const none = await install(['--version', '0.0.1']);
  assert.notEqual(none.status, 0);
  assert.match(none.stderr, /no binary for/);
  const bad = await install(['--version', '1;rm -rf /']);
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /version must look like/);
  const dry = await install(['--dry-run']);
  assert.equal(dry.status, 0);
  assert.match(dry.stderr, /dry run/);
  assert.equal(existsSync(join(dry.dir, binName)), false);
  const alias = await install(['--alias', '../evil']);
  assert.notEqual(alias.status, 0);
});

test('install.ps1 keeps the same contract', () => {
  const ps = readFileSync(join(root, 'install.ps1'), 'utf8');
  assert.match(ps, /Get-FileHash -Algorithm SHA256/);
  assert.match(ps, /SHA256SUMS/);
  assert.match(ps, /-windows-\$arch\\\.exe/);
  assert.doesNotMatch(ps + readFileSync(SCRIPT, 'utf8'), /revlens/i, 'the binary name comes from the release, not the script');
  chmodSync(SCRIPT, 0o755);
});
