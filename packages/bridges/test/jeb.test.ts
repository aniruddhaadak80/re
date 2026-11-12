// JEB bridge. JEB is commercial and not in CI, so these tests cover: the missing-tool answer, install
// detection on the real JEB folder layout (launchers at the top, bin/app/jeb.jar), the exact headless
// command line handed to the launcher (recorded by a stand-in launcher), result parsing, and that the
// RevLens JEB script at least compiles as Python.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import fc from 'fast-check';
import { detectJebSync, jebArgs, jebUnits, jebDecompile, jebInfo, parseJebOutput, jebScriptPath, jebVersionFromName } from '../src/jeb.ts';
import { TOOLS } from '../src/tools.ts';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const APK = join(repo, 'samples', 'mobile', 'apk', 'org.rayg.streaktracker_12.apk');
const fresh = () => mkdtempSync(join(tmpdir(), 'rl-jeb-'));
const posix = process.platform !== 'win32';

function fakeJeb(version = '5.12.0.202405301617'): string {
  const home = join(fresh(), `jeb-pro-${version}`);
  mkdirSync(join(home, 'bin', 'app'), { recursive: true });
  writeFileSync(join(home, 'bin', 'app', 'jeb.jar'), 'PK');
  // stand-in launcher: records its arguments and answers like the RevLens script would
  const launcher = `#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
print("JEB 5 headless (stand-in)")
print("@@REVLENS_JSON_BEGIN@@")
print(json.dumps({"ok": True, "action": args[3], "argv": args, "units": [{"name": "Bytecode", "type": "DexUnit", "format": "dex", "children": 3}]}))
print("@@REVLENS_JSON_END@@")
`;
  for (const n of ['jeb_linux.sh', 'jeb_macos.sh']) { writeFileSync(join(home, n), launcher); chmodSync(join(home, n), 0o755); }
  writeFileSync(join(home, 'jeb_wincli.bat'), '@echo off\r\n');
  return home;
}

test('missing JEB: every tool answers available:false with install notes', async () => {
  const old = { ...process.env };
  try {
    delete process.env.JEB_HOME; delete process.env.REVLENS_JEB_PATH;
    process.env.HOME = fresh();
    for (const name of ['bridge_jeb_info', 'bridge_jeb_units', 'bridge_jeb_decompile']) {
      const r = await TOOLS.find((t) => t.name === name)!.run({ path: APK, item: 'La/B;' }) as any;
      assert.equal(r.available, false, name);
      assert.match(r.install.homepage, /pnfsoftware/);
    }
    const bare = await TOOLS.find((t) => t.name === 'bridge_jeb_info')!.run({}) as any;
    assert.equal(bare.available, false);
  } finally { process.env = old; }
});

test('detection on the JEB folder layout, with version from the folder name', () => {
  const home = fakeJeb();
  const d = detectJebSync({ env: { JEB_HOME: home, HOME: fresh() }, platform: 'linux' });
  assert.equal(d.available, true);
  assert.equal(d.launcher, join(home, 'jeb_linux.sh'));
  assert.equal(d.version, '5.12.0');
  assert.equal(d.via, 'env');
  assert.equal(detectJebSync({ env: { JEB_HOME: home, HOME: fresh() }, platform: 'win32' }).launcher, join(home, 'jeb_wincli.bat'));
  assert.equal(detectJebSync({ env: { JEB_HOME: home, HOME: fresh() }, platform: 'darwin' }).launcher, join(home, 'jeb_macos.sh'));
  const h2 = fresh();
  const inHome = fakeJeb('4.30.0');
  execFileSync('mv', [inHome, join(h2, 'jeb-4.30.0')]);
  const found = detectJebSync({ env: { HOME: h2 }, platform: 'linux' });
  assert.equal(found.via, 'dir');
  assert.equal(found.version, '4.30.0');
  const bad = detectJebSync({ env: { JEB_HOME: fresh(), HOME: fresh() }, platform: 'linux' });
  assert.equal(bad.available, false);
  assert.match(bad.problems!.join(' '), /jeb_linux\.sh/);
  assert.equal(jebVersionFromName('JEB-Community-4.20'), '4.20');
});

test('headless command line and result parsing through the launcher', { skip: !posix && 'stand-in launcher is POSIX' }, async () => {
  const home = fakeJeb();
  const old = process.env.JEB_HOME;
  process.env.JEB_HOME = home;
  try {
    const u = await jebUnits({ path: APK }) as any;
    assert.equal(u.available, true);
    assert.equal(u.ok, true);
    assert.deepEqual(u.argv, ['-c', `--script=${jebScriptPath()}`, '--', 'units', APK]);
    assert.equal(u.units[0].type, 'DexUnit');
    const d = await jebDecompile({ path: APK, item: 'Lorg/rayg/streaktracker/MainActivity;->onCreate(Landroid/os/Bundle;)V', maxChars: 5000 }) as any;
    assert.deepEqual(d.argv.slice(3), ['decompile', APK, 'Lorg/rayg/streaktracker/MainActivity;->onCreate(Landroid/os/Bundle;)V', '5000']);
    await assert.rejects(jebDecompile({ path: APK, item: 'a b; rm -rf /' }), /item must be/);
    const i = await jebInfo({ path: APK }) as any;
    assert.equal(i.action, 'info');
  } finally { if (old === undefined) delete process.env.JEB_HOME; else process.env.JEB_HOME = old; }
});

test('the RevLens JEB script is valid Python and implements IScript', () => {
  execFileSync('python3', ['-c', 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")', jebScriptPath()]);
  const src = execFileSync('cat', [jebScriptPath()], { encoding: 'utf8' });
  assert.match(src, /class RevLensJeb\(IScript\)/);
  assert.match(src, /@@REVLENS_JSON_BEGIN@@/);
  assert.deepEqual(jebArgs('/s.py', 'units', '/f'), ['-c', '--script=/s.py', '--', 'units', '/f']);
});

test('hostile JEB output never throws', () => {
  fc.assert(fc.property(fc.string({ maxLength: 4000 }), (s) => {
    const r = parseJebOutput(s);
    assert.ok(typeof r.ok === 'boolean');
    parseJebOutput(`@@REVLENS_JSON_BEGIN@@${s}@@REVLENS_JSON_END@@`);
  }), { numRuns: 300 });
  assert.deepEqual(parseJebOutput('x\n@@REVLENS_JSON_BEGIN@@\n{"ok":true}\n@@REVLENS_JSON_END@@\n'), { ok: true, value: { ok: true } });
});
