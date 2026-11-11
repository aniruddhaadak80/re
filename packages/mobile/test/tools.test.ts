// Public API contract: TOOLS, CLI_COMMANDS and the core Analyzer objects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TOOLS, CLI_COMMANDS, ANALYZERS, setCliOutput, mobileManifest, mobileSigning, mobileApkReport, mobileNativeLibs } from '../src/node.js';
import type { AnalyzerContext, Report } from '@revlens/core';
import { APKS, bytes, sample } from './helpers.js';

test('TOOLS follow the contract', () => {
  const names = TOOLS.map((t) => t.name);
  for (const want of ['mobile_manifest', 'mobile_signing', 'mobile_dex_classes', 'mobile_dex_method', 'mobile_dex_search', 'mobile_dex_xrefs', 'mobile_java_class', 'mobile_ipa_info', 'mobile_app_framework', 'mobile_il2cpp_types']) {
    assert.ok(names.includes(want), want);
  }
  for (const t of TOOLS) {
    assert.match(t.name, /^mobile_[a-z0-9_]+$/);
    assert.ok(t.description.length > 20);
    for (const [k, v] of Object.entries(t.inputSchema)) {
      assert.ok(['string', 'number', 'boolean', 'array', 'object'].includes(v.type), `${t.name}.${k}`);
      assert.ok(v.description);
    }
    assert.equal(typeof t.run, 'function');
  }
  assert.equal(new Set(names).size, names.length);
});

test('tools accept base64 input as well as a path', async () => {
  const b64 = Buffer.from(bytes('apk', APKS.stopwatch)).toString('base64');
  const a = await mobileManifest({ base64: b64 });
  const b = await mobileManifest({ path: sample('apk', APKS.stopwatch), xml: true });
  assert.deepEqual(a.manifest, b.manifest);
  assert.match((b.xml as { text: string }).text, /<manifest/);
  const s = await mobileSigning({ path: sample('apk', APKS.stopwatch) });
  assert.equal(s.certificateSha256[0], '53f7c03751587546b5cff6b4e93dbae5f89a1be81e50b214cb710863fd3c94ce');
  await assert.rejects(() => mobileManifest({}), /path|base64/);
  await assert.rejects(() => mobileSigning({ path: sample('java', 'Hello.class') }), /not an APK/);
});

test('apk report and native libs tools return JSON-serializable data', async () => {
  const r = await mobileApkReport({ path: sample('apk', APKS.alarm) });
  assert.equal(r.manifest?.package, 'com.angrydoughnuts.android.alarmclock');
  JSON.parse(JSON.stringify(r));
  const n = await mobileNativeLibs({ path: sample('apk', APKS.streak) });
  assert.deepEqual(Object.keys(n.libraries ?? {}).sort(), ['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64']);
});

test('every CLI command prints JSON with --json and text by default', async () => {
  const out: string[] = [];
  const err: string[] = [];
  setCliOutput((s) => out.push(s), (s) => err.push(s));
  const apk = sample('apk', APKS.alarm);
  const runs: [string, string[]][] = [
    ['apk', [apk]], ['manifest', [apk]], ['apksig', [apk]], ['dex', [apk, '--limit', '3']],
    ['smali', [apk, '--class', 'com.angrydoughnuts.android.alarmclock.AlarmClockActivity', '--method', 'onCreate']],
    ['dex-search', [apk, '--query', 'alarm', '--kinds', 'class']], ['xrefs', [apk, '--target', 'getSystemService', '--kind', 'method']],
    ['javap', [sample('java', 'Hello.class')]], ['ipa', [sample('ipa', 'Wikipedia-fixture.ipa')]], ['app-framework', [apk]],
    ['native-libs', [sample('apk', APKS.streak)]],
  ];
  for (const [name, args] of runs) {
    const c = CLI_COMMANDS.find((x) => x.name === name);
    assert.ok(c, name);
    out.length = 0;
    assert.equal(await c.run(args), 0, `${name} text: ${err.join('\n')}`);
    assert.ok(out.join('\n').length > 0, name);
    out.length = 0;
    assert.equal(await c.run([...args, '--json']), 0, `${name} json`);
    JSON.parse(out.join('\n'));
  }
  const il = CLI_COMMANDS.find((x) => x.name === 'il2cpp');
  assert.equal(await il?.run([sample('apk', APKS.alarm)]), 1);
  assert.equal(await CLI_COMMANDS[0]?.run([]), 2);
  setCliOutput((s) => console.log(s), (s) => console.error(s));
});

function ctxFor(file: string, format: AnalyzerContext['format']): AnalyzerContext {
  const report: Report = {
    schema: 'revlens/report@1', tool: { name: 'RevLens', version: 'test' }, generatedAt: new Date(0).toISOString(),
    file: { name: file, size: 0, format, hashes: { md5: '', sha1: '', sha256: '' }, entropy: 0 },
    sections: [], imports: [], exports: [], strings: [], components: [], findings: [], capabilities: [], meta: {}, timings: {},
  };
  const b = new Uint8Array(readFileSync(file));
  return { bytes: b, name: file, format, options: { maxStrings: 1000, recurse: false, maxDepth: 1 }, depth: 0, report };
}

test('core analyzers add findings and meta.mobile', async () => {
  const byId = Object.fromEntries(ANALYZERS.map((a) => [a.id, a]));
  const apk = ctxFor(sample('apk', APKS.alarm), 'apk');
  assert.ok(byId['mobile-apk']?.applies(apk));
  await byId['mobile-apk']?.run(apk);
  const meta = apk.report.meta.mobile as { apk: { package: string; signing: { v2: boolean } } };
  assert.equal(meta.apk.package, 'com.angrydoughnuts.android.alarmclock');
  assert.equal(meta.apk.signing.v2, true);
  assert.ok(apk.report.findings.length > 0);
  JSON.stringify(apk.report);

  const dex = ctxFor(sample('java', 'hello-035.dex'), 'dex');
  assert.ok(byId['mobile-dex']?.applies(dex));
  await byId['mobile-dex']?.run(dex);
  assert.ok(dex.report.findings.some((f) => f.id === 'mobile.secret.aws-access-key'));

  const cls = ctxFor(sample('java', 'Hello.class'), 'class');
  await byId['mobile-class']?.run(cls);
  assert.equal((cls.report.meta.mobile as { javaClass: { declaration: string } }).javaClass.declaration, 'public class com.revlens.demo.Hello implements java.lang.Runnable');

  const ipa = ctxFor(sample('ipa', 'Wikipedia-fixture.ipa'), 'zip');
  assert.ok(byId['mobile-ipa']?.applies(ipa));
  assert.ok(!byId['mobile-apk']?.applies(ipa));
  await byId['mobile-ipa']?.run(ipa);
  const ids = ipa.report.findings.map((f) => f.id).sort();
  assert.deepEqual(ids, ['mobile.ios.ats-arbitrary-loads', 'mobile.ios.get-task-allow', 'mobile.ios.url-schemes']);
});
