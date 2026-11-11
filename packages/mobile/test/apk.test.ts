// Real F-Droid APKs checked against androguard 4.1.4 output (samples/mobile/reference/androguard.json).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { analyzeApk, apkSigning, axmlToXml, openZip, parseAxml, readEntry, readManifest, parseResourceTable, loadDexes, parseElfDynamic, permissionInfo } from '../src/index.js';
import { APKS, bytes, json } from './helpers.js';

const REF = json('reference', 'androguard.json');

for (const file of Object.values(APKS)) {
  const ref = REF[file];
  test(`manifest of ${file} matches androguard`, async () => {
    const zip = openZip(bytes('apk', file));
    const table = parseResourceTable(await readEntry(zip, 'resources.arsc'));
    const m = await readManifest(zip, table);
    assert.equal(m.package, ref.package);
    assert.equal(String(m.versionCode), ref.versionCode);
    assert.equal(m.versionName, ref.versionName);
    assert.equal(String(m.minSdk), ref.minSdk);
    assert.equal(String(m.targetSdk), ref.targetSdk);
    assert.equal(m.application.label, ref.label);
    assert.equal(m.launcherActivity, ref.mainActivity);
    assert.deepEqual(m.permissions.map((p) => p.name).sort(), ref.permissions);
    const names = (kind: string) => m.components.filter((c) => c.kind === kind).map((c) => c.name).sort();
    assert.deepEqual(names('activity'), ref.activities);
    assert.deepEqual(names('service'), ref.services);
    assert.deepEqual(names('receiver'), ref.receivers);
    assert.deepEqual(names('provider'), ref.providers);
  });

  test(`signing of ${file} matches androguard`, async () => {
    const s = await apkSigning(bytes('apk', file));
    assert.equal(s.v1.present, ref.signedV1);
    assert.equal(s.v2.present, ref.signedV2);
    assert.equal(s.v3.present, ref.signedV3);
    const want = ref.certificates[0];
    const got = s.v1.certificates[0];
    assert.ok(got);
    assert.equal(got.serial, want.serial);
    assert.equal(got.sha256, want.sha256);
    // androguard prints "Common Name: X, Organizational Unit: Y"; RevLens prints CN=X, OU=Y in the same order
    const short = want.subject.replace('Common Name', 'CN').replace('Organizational Unit', 'OU').replace('Organization', 'O').replace('Locality', 'L').replace('State/Province', 'ST').replace('Country', 'C').replace(/: /g, '=');
    assert.equal(got.subject, short);
    assert.deepEqual(s.v2.signers.flatMap((x) => x.certificates.map((c) => c.sha256)), ref.v2CertSha256);
    assert.deepEqual(s.v3.signers.flatMap((x) => x.certificates.map((c) => c.sha256)), ref.v3CertSha256);
    assert.deepEqual(s.warnings, []);
  });

  test(`dex tables of ${file} match androguard counts`, async () => {
    const dexes = await loadDexes(openZip(bytes('apk', file)));
    assert.equal(dexes.length, ref.dex.length);
    dexes.forEach((d, i) => {
      const r = ref.dex[i];
      assert.equal(d.name, r.name);
      assert.equal(d.classCount, r.classes);
      assert.equal(d.methodCount, r.methodIds);
      assert.equal(d.fieldCount, r.fieldIds);
      assert.equal(d.stringCount, r.strings);
    });
  });
}

test('alarm clock manifest details: exported flags, provider, allowBackup, flags', async () => {
  const m = await readManifest(openZip(bytes('apk', APKS.alarm)));
  const provider = m.components.find((c) => c.kind === 'provider');
  assert.equal(provider?.name, 'com.angrydoughnuts.android.alarmclock.AlarmClockProvider');
  assert.equal(provider?.exported, false);
  assert.equal(provider?.exportedReason, 'explicit');
  const main = m.components.find((c) => c.launcher);
  assert.equal(main?.exported, true);
  assert.equal(m.application.allowBackup, false);
  assert.equal(m.application.debuggable, false);
  const p = m.permissions.find((x) => x.name === 'android.permission.READ_MEDIA_AUDIO');
  assert.equal(p?.level, 'dangerous');
  assert.equal(permissionInfo('android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK').level, 'normal');
});

test('stopwatch: implicit export through intent filter on targetSdk 29', async () => {
  const m = await readManifest(openZip(bytes('apk', APKS.stopwatch)));
  const options = m.components.find((c) => c.name.endsWith('.Options'));
  assert.equal(options?.exported, true);
  assert.equal(options?.exportedReason, 'intent-filter-default');
});

test('AXML renders back to XML text', async () => {
  const zip = openZip(bytes('apk', APKS.alarm));
  const xml = axmlToXml(parseAxml(await readEntry(zip, 'AndroidManifest.xml')));
  assert.match(xml, /^<\?xml version="1.0" encoding="utf-8"\?>\n<manifest xmlns:android="http:\/\/schemas.android.com\/apk\/res\/android"/);
  assert.match(xml, /<uses-permission android:name="android.permission.WAKE_LOCK" \/>/);
  assert.match(xml, /<provider android:name="com.angrydoughnuts.android.alarmclock.AlarmClockProvider"/);
});

test('native-only APK: ABIs, NativeActivity framework and ELF exports match readelf', async () => {
  const rep = await analyzeApk(bytes('apk', APKS.streak));
  assert.deepEqual(rep.abis, ['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64']);
  assert.equal(rep.dex.length, 0);
  assert.equal(rep.frameworks[0]?.id, 'native-activity');
  const arm64 = rep.nativeLibs.find((l) => l.abi === 'arm64-v8a');
  assert.equal(arm64?.path, 'lib/arm64-v8a/libStreak.so');
  assert.equal(arm64?.size, 36872);
  assert.deepEqual(arm64?.elf?.entryPoints, ['ANativeActivity_onCreate']);
  // readelf -d lib/arm64-v8a/libStreak.so (binutils 2.40)
  assert.deepEqual(arm64?.elf?.needed, ['libm.so', 'libGLESv3.so', 'libEGL.so', 'libandroid.so', 'liblog.so', 'libOpenSLES.so', 'libdl.so', 'libc.so']);
  assert.equal(rep.nativeLibs.find((l) => l.abi === 'armeabi-v7a')?.elf?.machine, 'arm');
  assert.equal(rep.nativeLibs.find((l) => l.abi === 'x86')?.elf?.bits, 32);
});

test('ELF exports agree with nm -D when binutils is installed', async (t) => {
  const zip = openZip(bytes('apk', APKS.streak));
  const so = await readEntry(zip, 'lib/x86_64/libStreak.so');
  const elf = parseElfDynamic(so);
  let nm: string;
  try {
    const { writeFileSync, mkdtempSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'revlens-'));
    writeFileSync(join(dir, 'lib.so'), so);
    nm = execFileSync('nm', ['-D', '--defined-only', join(dir, 'lib.so')], { encoding: 'utf8', timeout: 10_000 });
  } catch { t.skip('nm not available'); return; }
  const want = nm.split('\n').map((l) => l.trim().split(/\s+/)).filter((p) => p.length === 3 && /[TDBRVW]/.test(p[1] as string)).map((p) => p[2]).sort();
  assert.deepEqual(elf.exports.map((e) => e.name).sort(), want);
});

test('analyzeApk produces manifest and signing findings without false alarms on clean apps', async () => {
  const rep = await analyzeApk(bytes('apk', APKS.screentime));
  assert.equal(rep.kind, 'apk');
  assert.ok(rep.findings.some((f) => f.id === 'mobile.dangerous-permissions'));
  assert.ok(!rep.findings.some((f) => f.id === 'mobile.debuggable'));
  assert.ok(rep.frameworks.some((f) => f.id === 'kotlin'));
  assert.equal(rep.obfuscation?.likelyObfuscated, true);
  for (const f of rep.findings) { assert.match(f.id, /^mobile\./); assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(f.severity)); }
  JSON.stringify(rep);
});
