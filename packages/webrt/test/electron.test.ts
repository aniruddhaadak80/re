import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { readAsar, readAsarFile, auditAsar, readFuses, detectElectronVersionInBinary, FUSE_NAMES } from '../src/index.js';
import { extractAsar, auditElectronPath } from '../src/node.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/webrt');
const ASAR = join(S, 'electron/app.asar');

async function reference(): Promise<{ list?: string[]; header?: unknown }> {
  try {
    const m: any = await import('@electron/asar');
    const asar = m.listPackage ? m : m.default;
    return { list: asar.listPackage(ASAR, { isPack: false }), header: asar.getRawHeader(ASAR) };
  } catch { return {}; }
}

test('asar: entries match @electron/asar and file bytes match the packed sources', async () => {
  const bytes = new Uint8Array(readFileSync(ASAR));
  const a = readAsar(bytes);
  assert.deepEqual(a.entries.map((e) => e.path), ['main.js', 'native', 'native/addon.node', 'package.json', 'preload.js']);
  const ref = await reference();
  if (ref.list) assert.deepEqual(a.entries.map((e) => '/' + e.path).sort(), [...ref.list].map((p) => p.replace(/\\/g, '/')).sort());
  if (ref.header) assert.equal(a.headerSize, (ref.header as { headerSize: number }).headerSize);
  assert.equal(a.files, 4); assert.equal(a.dirs, 1); assert.equal(a.unpackedFiles, 1);
  for (const f of ['main.js', 'preload.js', 'package.json']) {
    const data = readAsarFile(bytes, a, f)!;
    assert.deepEqual(Buffer.from(data), readFileSync(join(S, 'electron-app', f)), `${f} bytes`);
    const e = a.entries.find((x) => x.path === f)!;
    assert.equal(e.integrity?.algorithm, 'SHA256');
    const { createHash } = await import('node:crypto');
    assert.equal(createHash('sha256').update(data).digest('hex'), e.integrity?.hash, 'integrity hash in header matches content');
  }
  assert.equal(readAsarFile(bytes, a, 'native/addon.node'), undefined, 'unpacked file is not inside the archive');
});

test('asar: extract to disk copies unpacked files and blocks traversal', async () => {
  const out = mkdtempSync(join(tmpdir(), 'webrt-asar-'));
  try {
    const r = await extractAsar(ASAR, out);
    assert.equal(r.files, 3);
    assert.equal(r.unpackedCopied, 1);
    assert.deepEqual(readFileSync(join(out, 'native/addon.node')), readFileSync(join(S, 'electron-app/native/addon.node')));
    assert.deepEqual(readFileSync(join(out, 'main.js')), readFileSync(join(S, 'electron-app/main.js')));
  } finally { rmSync(out, { recursive: true, force: true }); }
  // hostile header: a file named ../../evil must land inside the output folder
  const json = JSON.stringify({ files: { '..': { files: { '..': { files: { 'evil.txt': { size: 3, offset: '0' } } } } } } });
  const head = Buffer.alloc(16);
  head.writeUInt32LE(4, 0); head.writeUInt32LE(json.length + 8, 4); head.writeUInt32LE(json.length + 4, 8); head.writeUInt32LE(json.length, 12);
  const evil = Buffer.concat([head, Buffer.from(json), Buffer.from('bad')]);
  const dir = mkdtempSync(join(tmpdir(), 'webrt-evil-'));
  try {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(join(dir, 'evil.asar'), evil);
    const r = await extractAsar(join(dir, 'evil.asar'), join(dir, 'out'));
    assert.equal(r.files, 1);
    assert.ok(existsSync(join(dir, 'out', 'evil.txt')), 'flattened inside the output folder');
    assert.ok(!existsSync(join(dir, '..', 'evil.txt')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('electron audit: insecure window, raw ipcRenderer bridge, IPC channels, openExternal, protocols, update feed', async () => {
  const a = auditAsar(new Uint8Array(readFileSync(ASAR)));
  assert.equal(a.electronVersion, '33.2.1');
  assert.equal(a.versionSource, 'package.json');
  assert.equal(a.windows.length, 2);
  assert.deepEqual(a.windows[0]?.prefs, { nodeIntegration: true, contextIsolation: false, sandbox: false, webSecurity: false, enableRemoteModule: true, preload: 'dynamic' });
  assert.deepEqual(a.windows[0]?.loads, ['https://app.revlens-fixture.example/']);
  assert.deepEqual(a.windows[1]?.loads, []);
  assert.deepEqual(a.ipc.main.map((x) => `${x.method}:${x.channel}`), ['handle:read-file', 'on:open-link', 'handle:app-version']);
  assert.deepEqual(a.ipc.renderer.map((x) => `${x.method}:${x.channel}`), ['invoke:read-file', 'send:open-link', 'invoke:app-version']);
  assert.deepEqual(a.exposed, [{ name: 'fixtureApi', keys: ['readFile', 'openLink', 'version', 'ipcRenderer'], file: 'preload.js', line: 3 }]);
  assert.equal(a.openExternal.length, 2);
  assert.deepEqual(a.protocols.map((p) => `${p.method}:${p.scheme}`), ['registerSchemesAsPrivileged:fixture', 'registerFileProtocol:fixture']);
  assert.deepEqual(a.updateUrls.map((u) => u.url).sort(), ['https://updates.revlens-fixture.example/feed', 'https://updates.revlens-fixture.example/releases']);
  const ids = a.findings.map((f) => f.id);
  for (const id of ['node-integration', 'context-isolation', 'sandbox', 'web-security', 'remote-module', 'bridge-raw', 'open-external', 'ipc-surface']) assert.ok(ids.includes(`webrt.electron.${id}`), id);
  assert.equal(a.findings.find((f) => f.id === 'webrt.electron.node-integration')?.severity, 'critical');
  // the second window is safe: only one context-isolation finding
  assert.equal(ids.filter((x) => x === 'webrt.electron.context-isolation').length, 1);
  // app folder input gives the same result
  const fromDir = await auditElectronPath(join(S, 'electron-app'));
  assert.equal(fromDir.windows.length, 2);
  assert.equal(fromDir.electronVersion, '33.2.1');
});

const BIN = join(S, '../.cache/webrt/electron-v33.2.1-linux-x64/electron');
test('electron binary: version strings and fuse wire match @electron/fuses (needs scripts/fetch-fixtures.mjs)', { skip: !existsSync(BIN) && 'run node packages/webrt/scripts/fetch-fixtures.mjs to download Electron 33.2.1' }, async () => {
  const bin = new Uint8Array(readFileSync(BIN));
  const v = detectElectronVersionInBinary(bin);
  assert.equal(v.electron, '33.2.1');
  assert.equal(readFileSync(join(dirname(BIN), 'version'), 'utf8').trim(), '33.2.1');
  assert.match(v.chrome ?? '', /^130\./);
  const ours = readFuses(bin)!;
  assert.equal(ours.version, 1);
  let ref: Record<string, number> | undefined;
  try { const m: any = await import('@electron/fuses'); ref = await m.getCurrentFuseWire(BIN); } catch { /* reference not installed */ }
  if (ref) {
    for (const [k, v2] of Object.entries(ref)) {
      if (k === 'version' || !/^\d+$/.test(k)) continue;
      const name = FUSE_NAMES[Number(k)]!;
      const expected = v2 === 49 ? 'enabled' : v2 === 48 ? 'disabled' : v2 === 114 ? 'removed' : 'unknown';
      assert.equal(ours.fuses[name], expected, name);
    }
  }
  // stock Electron ships RunAsNode on and ASAR integrity off
  assert.equal(ours.fuses.RunAsNode, 'enabled');
  assert.equal(ours.fuses.EnableEmbeddedAsarIntegrityValidation, 'disabled');
});
