// Cutter detection. Cutter is a GUI, so it is never started; these tests build the install
// layouts Cutter's official releases use (asset names from github.com/rizinorg/cutter releases
// v2.5.0; the Windows layout is the real top level listing of Cutter-v2.5.0-Windows-x86_64.zip in
// samples/bridges/recorded/cutter) inside a private HOME and check what detection reports.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { detect, detectCutter, cutterVersionFromName, plistVersion, appdataVersion } from '../src/detect.ts';
import { TOOLS } from '../src/tools.ts';
import { runTool } from '../src/exec.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const touch = (p: string, mode = 0o755, text = '') => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); chmodSync(p, mode); return p; };
const fresh = () => mkdtempSync(join(tmpdir(), 'rl-cutter-'));

test('version helpers: release names, Info.plist, AppStream metadata', () => {
  assert.equal(cutterVersionFromName('Cutter-v2.5.0-Linux-x86_64.AppImage'), '2.5.0');
  assert.equal(cutterVersionFromName('Cutter-v2.5.0-Linux-Qt5-x86_64.AppImage'), '2.5.0');
  assert.equal(cutterVersionFromName('C:/Cutter-v2.5.0-rc1-Windows-x86_64'), '2.5.0-rc1');
  assert.equal(cutterVersionFromName('/usr/bin/cutter'), undefined);
  assert.equal(plistVersion('<plist><dict><key>CFBundleShortVersionString</key>\n<string>2.5.0</string></dict></plist>'), '2.5.0');
  assert.equal(appdataVersion('<component><releases><release version="2.5.0" date="2026-01-01"/><release version="2.4.1"/></releases></component>'), '2.5.0');
});

test('Linux: AppImage in ~/Applications', () => {
  const h = fresh();
  const p = touch(join(h, 'Applications', 'Cutter-v2.5.0-Linux-x86_64.AppImage'));
  const d = detectCutter({ env: { HOME: h, PATH: '' }, platform: 'linux' });
  assert.equal(d.available, true);
  assert.equal(d.path, p);
  assert.equal(d.version, '2.5.0');
  assert.equal(d.details?.kind, 'appimage');
});

test('Linux: Flatpak install with AppStream metadata', () => {
  const h = fresh();
  touch(join(h, '.local', 'share', 'flatpak', 'app', 're.rizin.cutter', 'current', 'active', 'files', 'share', 'metainfo', 're.rizin.cutter.appdata.xml'), 0o644,
    '<component type="desktop"><id>re.rizin.cutter</id><releases><release version="2.5.0" date="2026-01-01"/></releases></component>');
  const d = detectCutter({ env: { HOME: h, PATH: '' }, platform: 'linux' });
  assert.equal(d.available, true);
  assert.equal(d.version, '2.5.0');
  assert.equal(d.details?.kind, 'flatpak');
  assert.equal(d.details?.launch, 'flatpak run re.rizin.cutter');
});

test('Linux: cutter on PATH is found but never run', () => {
  const h = fresh();
  const bin = join(h, 'bin-on-path');
  // a "cutter" that would leave a marker if anything executed it
  const marker = join(h, 'ran');
  touch(join(bin, 'cutter'), 0o755, `#!/bin/sh\ntouch ${marker}\n`);
  const d = detectCutter({ env: { HOME: h, PATH: bin }, platform: 'linux' });
  assert.equal(d.available, true);
  assert.equal(d.details?.kind, 'binary');
  assert.throws(() => readFileSync(marker));
});

test('macOS: Cutter.app with Info.plist', () => {
  const h = fresh();
  const app = join(h, 'Applications', 'Cutter.app');
  const exe = touch(join(app, 'Contents', 'MacOS', 'cutter'));
  touch(join(app, 'Contents', 'Info.plist'), 0o644, '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>cutter</string><key>CFBundleShortVersionString</key><string>2.5.0</string></dict></plist>');
  const d = detectCutter({ env: { HOME: h, PATH: '' }, platform: 'darwin' });
  assert.equal(d.available, true);
  assert.equal(d.path, exe);
  assert.equal(d.version, '2.5.0');
  assert.equal(d.details?.kind, 'app-bundle');
});

test('Windows: official release folder (real v2.5.0 layout) with bundled rizin.exe, also found as rizin', async () => {
  const h = fresh();
  const pf = join(h, 'Program Files');
  const listing = readFileSync(join(repo, 'samples', 'bridges', 'recorded', 'cutter', 'windows-release-v2.5.0-toplevel.txt'), 'utf8').trim().split('\n');
  assert.ok(listing.includes('Cutter-v2.5.0-Windows-x86_64/cutter.exe'));
  assert.ok(listing.includes('Cutter-v2.5.0-Windows-x86_64/rizin.exe'));
  for (const f of listing) touch(join(pf, f));
  const env = { HOME: h, USERPROFILE: h, ProgramFiles: pf, PATH: '', PATHEXT: '.EXE;.BAT;.CMD' };
  const d = detectCutter({ env, platform: 'win32' });
  assert.equal(d.available, true);
  assert.equal(d.path, join(pf, 'Cutter-v2.5.0-Windows-x86_64', 'cutter.exe'));
  assert.equal(d.version, '2.5.0');
  assert.equal(d.details?.bundledRizin, join(pf, 'Cutter-v2.5.0-Windows-x86_64', 'rizin.exe'));
  const rz = await detect('rizin', { env, platform: 'win32', skipVersion: true, refresh: true });
  assert.equal(rz.available, true);
  assert.equal(rz.path, join(pf, 'Cutter-v2.5.0-Windows-x86_64', 'rizin.exe'));
});

test('Windows: Scoop install', () => {
  const h = fresh();
  const exe = touch(join(h, 'scoop', 'apps', 'cutter', 'current', 'cutter.exe'));
  const d = detectCutter({ env: { HOME: h, USERPROFILE: h, PATH: '', ProgramFiles: join(h, 'nope') }, platform: 'win32' });
  assert.equal(d.available, true);
  assert.equal(d.path, exe);
});

test('override and missing: REVLENS_CUTTER_PATH, then nothing at all', () => {
  const h = fresh();
  const p = touch(join(h, 'tools', 'Cutter-v2.4.1-Linux-x86_64.AppImage'));
  const d = detectCutter({ env: { HOME: h, PATH: '', REVLENS_CUTTER_PATH: p }, platform: 'linux' });
  assert.deepEqual([d.available, d.via, d.version], [true, 'override', '2.4.1']);
  const none = detectCutter({ env: { HOME: fresh(), PATH: '' }, platform: 'linux' });
  assert.equal(none.available, false);
});

test('bridge_cutter_info: available:false with install commands when Cutter is missing', async () => {
  const code = `const { TOOLS } = await import(${JSON.stringify(pathToFileURL(join(repo, 'packages/bridges/src/tools.ts')).href)});
process.stdout.write(JSON.stringify(await TOOLS.find((t) => t.name === 'bridge_cutter_info').run({ path: '/tmp/x.bin' })));`;
  const h = fresh();
  const r = await runTool(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { cwd: repo, env: { ...process.env, HOME: h, PATH: dirname(process.execPath) }, timeoutMs: 60_000 });
  assert.equal(r.code, 0, r.stderr);
  const v = JSON.parse(r.stdout);
  assert.equal(v.available, false);
  assert.match(v.install.homepage, /^https:\/\/cutter\.re/);
});

test('bridge_cutter_info: reports the open command for a found AppImage', async () => {
  const h = fresh();
  touch(join(h, 'Applications', 'Cutter-v2.5.0-Linux-x86_64.AppImage'));
  const code = `const { TOOLS } = await import(${JSON.stringify(pathToFileURL(join(repo, 'packages/bridges/src/tools.ts')).href)});
process.stdout.write(JSON.stringify(await TOOLS.find((t) => t.name === 'bridge_cutter_info').run({ path: '/tmp/x.bin' })));`;
  if (process.platform !== 'linux') return;
  const r = await runTool(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { cwd: repo, env: { ...process.env, HOME: h, PATH: dirname(process.execPath) }, timeoutMs: 60_000 });
  assert.equal(r.code, 0, r.stderr);
  const v = JSON.parse(r.stdout);
  assert.equal(v.available, true);
  assert.equal(v.version, '2.5.0');
  assert.deepEqual(v.openCommand, [join(h, 'Applications', 'Cutter-v2.5.0-Linux-x86_64.AppImage'), '/tmp/x.bin']);
  assert.ok(TOOLS.some((t) => t.name === 'bridge_cutter_info'));
});
