// Framework detection and IL2CPP metadata on real apps. The large fixtures come from
// `node packages/mobile/scripts/fetch-fixtures.mjs` and the tests skip when they are absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { detectFrameworks, dartSnapshotInfo, parseIl2cppMetadata, parseManifest, parseResourceTable, mobileIl2cppTypes, reactNativeBundleInfo, openZip } from '../src/node.js';
import { APKS, bytes, cached } from './helpers.js';

const listing = (id: string): string[] | undefined => {
  const f = cached(id, 'listing.json');
  return f ? (JSON.parse(readFileSync(f, 'utf8')) as { entries: { name: string }[] }).entries.map((e) => e.name) : undefined;
};

test('Kotlin app and NDK-only app from the committed F-Droid APKs', () => {
  const names = openZip(bytes('apk', APKS.screentime)).entries.map((e) => e.name);
  assert.deepEqual(detectFrameworks(names).map((f) => f.id), ['kotlin']);
  const streak = openZip(bytes('apk', APKS.streak)).entries.map((e) => e.name);
  assert.deepEqual(detectFrameworks(streak, { nativeActivity: true }).map((f) => f.id), ['native-activity']);
});

test('Flutter: LocalSend (F-Droid, Apache-2.0) member names and Dart snapshot hash', (t) => {
  const names = listing('localsend-flutter');
  const libapp = cached('localsend-flutter', 'lib__arm64-v8a__libapp.so');
  if (!names || !libapp) { t.skip('run scripts/fetch-fixtures.mjs first'); return; }
  const hits = detectFrameworks(names);
  assert.equal(hits[0]?.id, 'flutter');
  assert.ok(hits[0]?.evidence.includes('lib/arm64-v8a/libflutter.so'));
  // value cross-checked with `strings -n 32 libapp.so`
  const snap = dartSnapshotInfo(new Uint8Array(readFileSync(libapp)));
  assert.equal(snap.snapshotHash, '78da37fed6bf1489361a312568249f3f');
  assert.match(snap.features ?? '', /^product .* arm64 android compressed-pointers$/);
  const arsc = cached('localsend-flutter', 'resources.arsc');
  const man = cached('localsend-flutter', 'AndroidManifest.xml');
  if (arsc && man) {
    const m = parseManifest(new Uint8Array(readFileSync(man)), parseResourceTable(new Uint8Array(readFileSync(arsc))));
    assert.equal(m.package, 'org.localsend.localsend_app');
    assert.equal(m.versionCode, 643);
    assert.equal(m.application.label, 'LocalSend');
  }
});

test('Unity IL2CPP vs Mono: Daggerfall Unity Android (MIT) listings', (t) => {
  const il = listing('daggerfall-il2cpp-64');
  const mono = listing('daggerfall-mono-32');
  if (!il || !mono) { t.skip('run scripts/fetch-fixtures.mjs first'); return; }
  assert.deepEqual(detectFrameworks(il).map((f) => f.id), ['unity-il2cpp']);
  assert.deepEqual(detectFrameworks(mono).map((f) => f.id), ['unity-mono']);
});

test('IL2CPP global-metadata.dat v29: images, types, methods, literals', async (t) => {
  const f = cached('daggerfall-il2cpp-64', 'assets__bin__Data__Managed__Metadata__global-metadata.dat');
  if (!f) { t.skip('run scripts/fetch-fixtures.mjs first'); return; }
  const m = parseIl2cppMetadata(new Uint8Array(readFileSync(f)));
  assert.equal(m.version, 29);
  assert.deepEqual(m.warnings, []);
  assert.equal(m.images.length, 59);
  assert.deepEqual(m.images.slice(0, 2), [{ name: 'Assembly-CSharp.dll', typeStart: 0, typeCount: 2274 }, { name: 'mscorlib.dll', typeStart: 2274, typeCount: 1724 }]);
  assert.equal(m.images.reduce((n, i) => n + i.typeCount, 0), m.typeCount);
  assert.equal(m.typeCount, 12280);
  const gm = m.types(0, 5, 'DaggerfallWorkshop.Game.GameManager').items[0];
  assert.equal(gm?.fullName, 'DaggerfallWorkshop.Game.GameManager');
  assert.equal(gm?.image, 'Assembly-CSharp.dll');
  const start = m.methods(0, 5, 'GameManager::Start').items[0];
  assert.equal(start?.typeName, 'DaggerfallWorkshop.Game.GameManager');
  assert.ok(m.literals(0, 5, 'HTTP/1.0').items.length > 0);
  const tool = await mobileIl2cppTypes({ path: f, what: 'images', limit: 3 });
  assert.equal((tool as { items: unknown[] }).items.length, 3);
});

test('React Native bundle sniffing: Hermes magic vs plain JS', () => {
  const hermes = new Uint8Array([0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f, 96, 0, 0, 0]);
  assert.deepEqual(reactNativeBundleInfo(hermes), { format: 'hermes', hermesVersion: 96, size: 12 });
  assert.equal(reactNativeBundleInfo(new TextEncoder().encode('var __BUNDLE_START_TIME__')).format, 'javascript');
});
