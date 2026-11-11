// PyInstaller CArchive and PYZ checked against PyInstaller's own archive readers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sample, cached, bytes, json, has } from './helpers.js';
import { parseCArchive, extractPyInstaller, parsePyz, readCArchiveEntry, parsePyc, detectPythonPackers, isPyc } from '../src/index.js';

const MINI = sample('pyinstaller', 'mini-carchive.bin');
const ONEFILE = cached('hello_revlens');

function compareToc(b: Uint8Array, ref: any) {
  const a = parseCArchive(b);
  const names = a.entries.map((e) => e.name);
  assert.deepEqual(names, Object.keys(ref.toc));
  assert.deepEqual(a.options, ref.options);
  for (const e of a.entries) {
    const [off, stored, size, flag, type] = ref.toc[e.name];
    assert.equal(e.offset - a.packageOffset, off, e.name);
    assert.equal(e.storedSize, stored, e.name);
    assert.equal(e.size, size, e.name);
    assert.equal(e.compressed, flag === 1, e.name);
    assert.equal(e.type, type, e.name);
  }
  const z = a.entries.find((e) => e.type === 'z')!;
  const pyz = parsePyz(readCArchiveEntry(b, z), a.pythonVersion);
  assert.deepEqual(pyz.entries.map((e) => e.name), Object.keys(ref.pyz));
  for (const e of pyz.entries) assert.deepEqual([e.type, e.offset, e.length], ref.pyz[e.name], e.name);
  return a;
}

test('pyinstaller: mini CArchive written by PyInstaller writers matches its reader', () => {
  const b = bytes(MINI);
  const a = compareToc(b, json(sample('pyinstaller', 'mini-carchive.ref.json')));
  assert.equal(a.pythonVersion, '3.12');
  assert.equal(a.pylibName, 'libpython3.12.so.1.0');
  assert.equal(a.format, 'pyinstaller>=2.1');
  const x = extractPyInstaller(b);
  assert.deepEqual(x.errors, []);
  const paths = x.files.map((f) => f.path).sort();
  assert.deepEqual(paths, ['PYZ.pyz', 'PYZ.pyz_extracted/fixture_pkg/__init__.pyc', 'PYZ.pyz_extracted/fixture_pkg/helper.pyc', 'data.txt', 'fixture_main.pyc', 'pyiboot_stub.pyc', 'pyimod_stub.pyc']);
  const helper = parsePyc(x.files.find((f) => f.path.endsWith('helper.pyc'))!.data);
  assert.equal(helper.version, '3.12');
  assert.equal(helper.code.consts[0], 'revlens-pyz-member');
  const main = parsePyc(x.files.find((f) => f.path === 'fixture_main.pyc')!.data);
  assert.ok(main.code.names.includes('greet'));
  assert.equal(new TextDecoder().decode(x.files.find((f) => f.path === 'data.txt')!.data), 'plain data file\n');
  assert.deepEqual(detectPythonPackers(b).map((h) => h.packer), ['pyinstaller']);
});

test('pyinstaller: real onefile build matches PyInstaller reader (needs fetch-fixtures)', { skip: !has(ONEFILE) }, () => {
  const b = bytes(ONEFILE);
  const a = compareToc(b, json(ONEFILE + '.ref.json'));
  assert.ok(a.entries.some((e) => e.name === 'hello_revlens' && e.type === 's'));
  const x = extractPyInstaller(b);
  assert.deepEqual(x.errors, []);
  const script = x.files.find((f) => f.path === 'hello_revlens.pyc')!;
  assert.ok(isPyc(script.data));
  const p = parsePyc(script.data);
  assert.deepEqual(p.code.names.slice(0, 3), ['json', 'helper_mod', 'greet']);
  const helper = parsePyc(x.files.find((f) => f.path === 'PYZ.pyz_extracted/helper_mod.pyc')!.data);
  assert.equal(helper.code.consts[0], 'revlens-pyinstaller-fixture');
  // Every module pulled from the PYZ must parse.
  let parsed = 0;
  for (const f of x.files) if (f.source === 'pyz' && f.path.endsWith('.pyc')) { parsePyc(f.data); parsed++; }
  assert.ok(parsed > 50);
});
