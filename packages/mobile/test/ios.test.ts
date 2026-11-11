// IPA fixture built from MIT-licensed Wikipedia iOS plists (see samples/mobile/SOURCES.md).
// Plists are checked against Python plistlib, the code signature against rcodesign 0.29.0.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeIpa, openZip, readEntry, parsePlist, parseBinaryPlist, parseXmlPlist, parseMachoSlices, mobileIpaInfo, mobileAppFramework } from '../src/node.js';
import { bytes, json, sample } from './helpers.js';

const IPA = 'Wikipedia-fixture.ipa';
const REF = json('reference', 'wikipedia-ipa-plists.json');

function normalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    if ('$data' in o) return { $bytes: o.$length };
    return Object.fromEntries(Object.keys(o).sort().map((k) => [k, normalize(o[k])]));
  }
  return v;
}

test('binary Info.plist decodes to the same values as plistlib', async () => {
  const zip = openZip(bytes('ipa', IPA));
  const b = await readEntry(zip, 'Payload/Wikipedia.app/Info.plist');
  assert.equal(new TextDecoder().decode(b.subarray(0, 8)), 'bplist00');
  assert.deepEqual(normalize(parseBinaryPlist(b)), normalize(REF.info));
});

test('XML plist (app extension Info.plist) decodes to the same values as plistlib', async () => {
  const zip = openZip(bytes('ipa', IPA));
  const b = await readEntry(zip, 'Payload/Wikipedia.app/PlugIns/Widgets.appex/Info.plist');
  assert.deepEqual(normalize(parseXmlPlist(new TextDecoder().decode(b))), normalize(REF.widgets));
  assert.deepEqual(normalize(parsePlist(b)), normalize(REF.widgets));
});

test('analyzeIpa: bundle facts, URL schemes, ATS, privacy strings, extensions, frameworks', async () => {
  const info = await analyzeIpa(bytes('ipa', IPA));
  assert.equal(info.appPath, 'Payload/Wikipedia.app/');
  assert.equal(info.bundleId, 'org.wikimedia.wikipedia');
  assert.equal(info.executablePath, 'Payload/Wikipedia.app/Wikipedia');
  assert.equal(info.minimumOSVersion, '16.6');
  assert.deepEqual(info.deviceFamily, ['iPhone', 'iPad']);
  assert.deepEqual(info.urlSchemes.flatMap((u) => u.schemes), ['wikipedia', 'wikipedia-official']);
  assert.equal(info.ats?.allowsArbitraryLoads, true);
  assert.deepEqual(info.privacyUsage.map((p) => p.key).sort(), Object.keys(REF.info).filter((k) => /^NS\w+UsageDescription$/.test(k)).sort());
  assert.deepEqual(info.frameworks.map((f) => f.name), ['WMF.framework']);
  assert.deepEqual(info.extensions, [{ name: 'Widgets.appex', path: 'Payload/Wikipedia.app/PlugIns/Widgets.appex', bundleId: 'org.wikimedia.wikipedia.Widgets', extensionPoint: 'com.apple.widgetkit-extension' }]);
  assert.deepEqual(info.warnings, []);
});

test('code signature: identifier and entitlements match rcodesign and the signed plist', async () => {
  const info = await analyzeIpa(bytes('ipa', IPA));
  const rc = readFileSync(sample('reference', 'wikipedia-rcodesign.yaml'), 'utf8');
  const ident = /identifier: (\S+)/.exec(rc)?.[1];
  assert.equal(info.executableInfo?.identifier, ident);
  assert.equal(info.executableInfo?.encrypted, false);
  assert.deepEqual(info.executableInfo?.slices.map((s) => s.cpu), ['arm64']);
  assert.deepEqual(info.executableInfo?.slices[0]?.dylibs, ['/usr/lib/libSystem.B.dylib', '@rpath/WMF.framework/WMF']);
  assert.deepEqual(normalize(info.executableInfo?.entitlements), normalize(REF.entitlements));
  assert.deepEqual(info.associatedDomains, REF.entitlements['com.apple.developer.associated-domains']);
  const zip = openZip(bytes('ipa', IPA));
  const [slice] = parseMachoSlices(await readEntry(zip, 'Payload/Wikipedia.app/Wikipedia'));
  const sig = slice?.signature;
  assert.equal(sig?.hashType, /digest_type: (\S+)/.exec(rc)?.[1]);
  assert.equal(sig?.flags, 0x2); // CodeSignatureFlags(ADHOC)
  assert.equal(sig?.derEntitlements, true);
  assert.deepEqual(sig?.blobs.map((b) => b.type), ['CodeDirectory', 'Requirements', 'Entitlements', 'DerEntitlements', 'AlternateCodeDirectory', 'CMS']);
  const sigOff = Number(/macho_signature_start_offset: (\d+)/.exec(rc)?.[1]);
  assert.equal(sig?.offset, sigOff);
});

test('ipa tools and framework detection', async () => {
  const path = sample('ipa', IPA);
  const r = await mobileIpaInfo({ path });
  assert.equal(r.bundleId, 'org.wikimedia.wikipedia');
  assert.equal('infoPlist' in r, false);
  const f = await mobileAppFramework({ path });
  assert.equal(f.platform, 'ios');
  assert.deepEqual(f.frameworks, []);
  const m = await mobileIpaInfo({ path: sample('ipa', IPA), includeInfoPlist: true });
  assert.equal((m.infoPlist as Record<string, unknown>).CFBundleIdentifier, 'org.wikimedia.wikipedia');
});
