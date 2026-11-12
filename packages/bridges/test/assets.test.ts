// Shipped scripts inside a single executable: written once to a private folder, rewritten when
// tampered with, refused when the folder is a link or someone else's. The real SEA path is checked by
// scripts/build-sea.mjs on every platform it builds (the embedded Cutter plugin must come out byte for
// byte); here the SEA API is a stand-in so the logic runs on every test machine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, symlinkSync, rmSync, existsSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bundledScriptPath, materialize, assetDir, privateDir, BUNDLED_SCRIPTS, runningAsSea } from '../src/assets.js';
import { pluginScriptPath } from '../src/cutter.js';
import { jebScriptPath } from '../src/jeb.js';

const pkg = join(dirname(fileURLToPath(import.meta.url)), '..');

test('every bundled script key points at a file in the package', () => {
  for (const rel of Object.values(BUNDLED_SCRIPTS)) assert.ok(existsSync(join(pkg, rel)), rel);
  assert.equal(pluginScriptPath(), join(pkg, BUNDLED_SCRIPTS['bridges/cutter/revlens_cutter_bridge.py']));
  assert.equal(jebScriptPath(), join(pkg, BUNDLED_SCRIPTS['bridges/jeb/RevLensJeb.py']));
  assert.equal(runningAsSea(), false);
});

test('inside a SEA the embedded script is written to a private folder, once', () => {
  const base = mkdtempSync(join(tmpdir(), 'assets-'));
  try {
    const real = readFileSync(join(pkg, BUNDLED_SCRIPTS['bridges/cutter/revlens_cutter_bridge.py']));
    let reads = 0;
    const sea = { isSea: () => true, getAsset: (k: string) => { reads++; assert.equal(k, 'bridges/cutter/revlens_cutter_bridge.py'); return real.buffer.slice(real.byteOffset, real.byteOffset + real.byteLength); } };
    const p1 = bundledScriptPath('bridges/cutter/revlens_cutter_bridge.py', [join(base, 'missing.py')], { sea, base });
    assert.ok(p1.startsWith(base));
    assert.deepEqual(readFileSync(p1), real);
    if (process.platform !== 'win32') {
      assert.equal(statSync(dirname(p1)).mode & 0o777, 0o700);
      assert.equal(statSync(p1).mode & 0o777, 0o600);
    }
    const m1 = statSync(p1).mtimeMs;
    const p2 = bundledScriptPath('bridges/cutter/revlens_cutter_bridge.py', [join(base, 'missing.py')], { sea, base });
    assert.equal(p2, p1);
    assert.equal(statSync(p2).mtimeMs, m1, 'an identical copy is reused, not rewritten');
    writeFileSync(p1, 'print("tampered")');
    const p3 = bundledScriptPath('bridges/cutter/revlens_cutter_bridge.py', [join(base, 'missing.py')], { sea, base });
    assert.deepEqual(readFileSync(p3), real, 'a changed copy is written again');
    assert.equal(reads, 3);
    // the folder name follows the content, so another build gets another folder
    assert.notEqual(assetDir(new Uint8Array([1])), assetDir(new Uint8Array([2])));
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test('an on-disk script wins over the embedded one, and a missing asset falls back to the first candidate', () => {
  const sea = { isSea: () => true, getAsset: () => { throw new Error('no such asset'); } };
  const cand = join(pkg, BUNDLED_SCRIPTS['bridges/jeb/RevLensJeb.py']);
  assert.equal(bundledScriptPath('bridges/jeb/RevLensJeb.py', [cand], { sea }), cand);
  assert.equal(bundledScriptPath('bridges/jeb/RevLensJeb.py', ['/nope/a.py', '/nope/b.py'], { sea }), '/nope/a.py');
});

test('a linked or shared asset folder is refused or tightened', { skip: process.platform === 'win32' && 'POSIX modes' }, () => {
  const base = mkdtempSync(join(tmpdir(), 'assets-'));
  try {
    const target = mkdtempSync(join(tmpdir(), 'assets-target-'));
    symlinkSync(target, join(base, 'link'));
    assert.throws(() => privateDir(join(base, 'link')), /not a plain folder/);
    assert.throws(() => materialize(join(base, 'link'), 'x.py', new Uint8Array([1])), /not a plain folder/);
    rmSync(target, { recursive: true, force: true });
    const open = join(base, 'open');
    privateDir(open);
    // loosen it, then check it is made private again
    chmodSync(open, 0o777);
    privateDir(open);
    assert.equal(statSync(open).mode & 0o777, 0o700);
  } finally { rmSync(base, { recursive: true, force: true }); }
});

