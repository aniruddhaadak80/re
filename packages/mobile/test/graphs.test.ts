// App graphs, JNI map and DEX member diff on real files.
// References: androguard 4.1.4 (components, exported attribute, intent filters), llvm-readelf 19
// (relocations, dynamic symbols, .data.rel.ro bytes), javap from JDK 25 (member lists), rcodesign
// and plistlib (IPA entitlements and Info.plist).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { mobileAppGraph, mobileIpaGraph, mobileJniMap, mobileCompareMembers, scanJniLibrary, compareDex, openDex, openZip, readEntry, androidAppGraph, graphToMermaid, parseManifest, CLI_COMMANDS, setCliOutput, ParseError, TOOLS } from '../src/node.js';
import { APKS, bytes, json, sample, gzJson } from './helpers.js';
import { readFileSync } from 'node:fs';

const REF = json('reference', 'androguard-graph.json');

test('mobile_app_graph: components, exported state and intent actions match androguard for all F-Droid APKs', async () => {
  for (const apk of Object.values(APKS)) {
    const g = await mobileAppGraph({ path: sample('apk', apk), limit: 1000 }) as any;
    const ref = REF[apk];
    const comps = g.nodes.items.filter((n: any) => ['activity', 'service', 'receiver', 'provider'].includes(n.kind));
    assert.deepEqual(comps.map((n: any) => n.label).sort(), Object.keys(ref.components).sort(), apk);
    for (const n of comps) {
      const r = ref.components[n.label];
      assert.equal(n.kind, r.kind, n.label);
      // exported: the explicit attribute, or the pre-Android 12 default (true when there is an intent filter, even a category-only one)
      const expect = r.exportedAttr === 'true' ? true : r.exportedAttr === 'false' ? false : r.actions.length + r.categories.length > 0;
      assert.equal(n.attrs.exported, expect, `${apk} ${n.label}`);
      const actions = g.edges.items.filter((e: any) => e.to === n.id && e.kind === 'intent').map((e: any) => e.from.slice('action:'.length)).sort();
      assert.deepEqual(actions, r.actions, `${apk} ${n.label} actions`);
      if (r.authorities) assert.ok(g.edges.items.some((e: any) => e.from === n.id && e.to === `authority:${r.authorities}`));
      if (g.stats.app && n.attrs.inDex !== undefined) assert.equal(n.attrs.inDex, true, `${n.label} class is in DEX`);
    }
    const perms = g.edges.items.filter((e: any) => e.kind === 'uses-permission').map((e: any) => e.to.slice(5)).sort();
    assert.deepEqual(perms, ref.permissions, `${apk} permissions`);
    const exported = comps.filter((n: any) => n.attrs.exported);
    assert.equal(g.edges.items.filter((e: any) => e.from === 'ext:caller').length, exported.length);
    assert.match(g.mermaid, /^flowchart LR\n/);
    assert.equal(g.mermaid.split('\n').filter((l: string) => /^ {2}n\d+[[({>]/.test(l)).length, g.nodes.total);
    if (exported.length) assert.match(g.mermaid, /classDef exported/);
  }
  // values checked by hand against the manifest XML: the alarm clock provider is not exported and serves one authority
  const a = await mobileAppGraph({ path: sample('apk', APKS.alarm), limit: 1000 }) as any;
  assert.deepEqual(a.stats, { app: 1, permission: 10, activity: 2, action: 4, service: 1, receiver: 3, provider: 1, authority: 1, external: 1, edges: 23 });
});

test('mobile_ipa_graph: executables, framework link, extension, entitlements and schemes match rcodesign and plistlib', async () => {
  const ref = json('reference', 'wikipedia-ipa-plists.json');
  const g = await mobileIpaGraph({ path: sample('ipa', 'Wikipedia-fixture.ipa'), limit: 1000 }) as any;
  const ids = new Set(g.nodes.items.map((n: any) => n.id));
  assert.ok(ids.has('app:org.wikimedia.wikipedia'));
  assert.ok(ids.has('framework:WMF.framework'));
  assert.ok(ids.has('extension:Widgets.appex'));
  const ext = g.nodes.items.find((n: any) => n.id === 'extension:Widgets.appex');
  assert.equal(ext.attrs.extensionPoint, 'com.apple.widgetkit-extension');
  const ents = g.edges.items.filter((e: any) => e.from === 'exe:Payload/Wikipedia.app/Wikipedia' && e.kind === 'entitled').map((e: any) => e.to.slice(4)).sort();
  assert.deepEqual(ents, Object.keys(ref.entitlements).sort());
  assert.ok(g.edges.items.some((e: any) => e.from === 'exe:Payload/Wikipedia.app/Wikipedia' && e.to === 'framework:WMF.framework' && e.label === '@rpath/WMF.framework/WMF'));
  assert.ok(!g.edges.items.some((e: any) => e.from === 'exe:Payload/Wikipedia.app/Frameworks/WMF.framework/WMF' && e.to === 'framework:WMF.framework'), 'no edge for the install name itself');
  assert.deepEqual(g.nodes.items.filter((n: any) => n.kind === 'url-scheme').map((n: any) => n.label), ['wikipedia://', 'wikipedia-official://']);
  assert.deepEqual(g.nodes.items.filter((n: any) => n.kind === 'associated-domain').map((n: any) => n.label), ref.entitlements['com.apple.developer.associated-domains']);
  assert.equal(g.stats['privacy-usage'], 5);
  assert.match(g.mermaid, /-->\|"links @rpath\/WMF.framework\/WMF"\|/);
});

test('mobile_jni_map: exports, long names and RegisterNatives tables match llvm-readelf on arm64 and armv7', async () => {
  const r = await mobileJniMap({ path: sample('jni', 'jnidemo.apk') }) as any;
  assert.equal(r.nativeMethods, 7);
  const lib = (abi: string) => r.libraries.find((l: any) => l.abi === abi);
  // llvm-readelf -r: R_AARCH64_RELATIVE at 0x205f0.. with addends 0x40c 0x436 0x105d8 0x400 0x432 0x105ec
  assert.deepEqual(lib('arm64-v8a').tables, [{ vaddr: '0x205f0', fileOffset: 0x5f0, section: '.data.rel.ro', entries: [
    { name: 'hash', signature: '([BI)J', fn: '0x105d8', slotVaddr: '0x205f0' },
    { name: 'reset', signature: '()V', fn: '0x105ec', slotVaddr: '0x20608' }] }]);
  // llvm-readelf -x .data.rel.ro (REL relocations, addend in place): 64760100 at 0x507e8, 7c760100 at 0x507f4
  assert.deepEqual(lib('armeabi-v7a').tables[0].entries.map((e: any) => [e.name, e.fn, e.slotVaddr]), [['hash', '0x17664', '0x507e0'], ['reset', '0x1767c', '0x507ec']]);
  assert.deepEqual(lib('arm64-v8a').classHints, ['org/revlens/jnidemo/NativeBridge']);
  const by = (m: string, sig: string) => r.methods.items.find((x: any) => x.method === m && x.signature === sig);
  // llvm-readelf --dyn-syms: add 0x1052c, greet 0x10534, overloaded__I 0x10548 (arm64); 0x175a8, 0x175b0, 0x175c8 (armv7)
  assert.deepEqual(by('add', '(II)I').bindings.map((b: any) => [b.abi, b.how, b.address]), [['arm64-v8a', 'export-short', '0x1052c'], ['armeabi-v7a', 'export-short', '0x175a8']]);
  assert.deepEqual(by('greet', '(Ljava/lang/String;)Ljava/lang/String;').bindings.map((b: any) => b.address), ['0x10534', '0x175b0']);
  assert.deepEqual(by('overloaded', '(I)I').bindings.map((b: any) => [b.how, b.symbol, b.address]), [['export-long', 'Java_org_revlens_jnidemo_NativeBridge_overloaded__I', '0x10548'], ['export-long', 'Java_org_revlens_jnidemo_NativeBridge_overloaded__I', '0x175c8']]);
  assert.deepEqual(by('hash', '([BI)J').bindings.map((b: any) => [b.how, b.address]), [['register-natives', '0x105d8'], ['register-natives', '0x17664']]);
  assert.deepEqual(by('reset', '()V').bindings.map((b: any) => b.how), ['register-natives', 'register-natives']);
  assert.deepEqual(r.unresolved.sort(), ['org.revlens.jnidemo.NativeBridge.missing()Z', 'org.revlens.jnidemo.NativeBridge.overloaded(Ljava/lang/String;)I']);
  assert.deepEqual(r.orphanExports, []);
  // a pure NativeActivity app: no DEX, libStreak.so has no Java_* exports or tables
  const s = await mobileJniMap({ path: sample('apk', APKS.streak) }) as any;
  assert.equal(s.nativeMethods, 0);
  assert.equal(s.libraries.length, 4);
  for (const l of s.libraries) { assert.equal(l.javaExports, 0); assert.deepEqual(l.tables, []); }
  // a bare .so works too
  const one = await mobileJniMap({ base64: Buffer.from(await readEntry(openZip(bytes('jni', 'jnidemo.apk')), 'lib/arm64-v8a/libjnidemo.so')).toString('base64') }) as any;
  assert.equal(one.library.javaExports.length, 3);
  assert.equal(one.library.jniOnLoad, true);
});

function javapMembers(file: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  let cls = '', pending = '';
  for (const line of readFileSync(sample('jni', file), 'utf8').split('\n')) {
    const c = /^(?:\w+ )*(?:class|interface) ([\w.$]+)/.exec(line);
    if (c) { cls = c[1]!; out.set(cls, new Set()); continue; }
    const d = /^\s+descriptor: (\S+)/.exec(line);
    if (d && pending) { out.get(cls)!.add(`${pending}${d[1]!.startsWith('(') ? '' : ':'}${d[1]}`); pending = ''; continue; }
    const m = /^ {2}(.+?);$/.exec(line);
    if (m) {
      const decl = m[1]!;
      if (decl === 'static {}') pending = '<clinit>';
      else { const p = /([\w$.]+)\(/.exec(decl); pending = p ? (p[1] === cls ? '<init>' : p[1]!) : decl.split(' ').pop()!; }
    }
  }
  return out;
}

test('mobile_compare_members: DEX member diff equals the diff of javap member lists', async () => {
  const r = await mobileCompareMembers({ path: sample('jni', 'bridge-v1.dex'), otherPath: sample('jni', 'bridge-v2.dex'), bodies: true }) as any;
  const a = javapMembers('bridge-v1.javap.txt'), b = javapMembers('bridge-v2.javap.txt');
  assert.deepEqual(r.classes.added, [...b.keys()].filter((k) => !a.has(k)));
  assert.deepEqual(r.classes.removed, []);
  const ch = r.changes.items[0];
  assert.equal(ch.class, 'org.revlens.jnidemo.NativeBridge');
  const A = a.get(ch.class)!, B = b.get(ch.class)!;
  const ours = (xs: any[], field = false) => xs.map((x) => `${x.name}${field ? ':' : ''}${x.descriptor}`).sort();
  assert.deepEqual(ours(ch.methods.added), [...B].filter((x) => !A.has(x) && !x.includes(':')).sort());
  assert.deepEqual(ours(ch.methods.removed), [...A].filter((x) => !B.has(x) && !x.includes(':')).sort());
  assert.deepEqual(ours(ch.fields.added, true), [...B].filter((x) => !A.has(x) && x.includes(':')).sort());
  assert.deepEqual(ch.methods.added.find((m: any) => m.name === 'thrice').access, 'protected');
  assert.deepEqual(ch.methods.bodyChanged, ['twice(I)I']);
  assert.deepEqual(r.methods, { added: 3, removed: 2, accessChanged: 0, bodyChanged: 1 });
  // the same file against itself: no change; two hello.dex builds (035 vs 039) have identical members
  const same = compareDex(openDex(bytes('jni', 'bridge-v1.dex')), openDex(bytes('jni', 'bridge-v1.dex')), { bodies: true });
  assert.equal(same.classes.changed, 0);
  // hello-035 vs hello-039 (two d8 builds): same members; bodies that differ are exactly those whose baksmali text differs
  const hello = compareDex(openDex(bytes('java', 'hello-035.dex')), openDex(bytes('java', 'hello-039.dex')), { bodies: true });
  const ba = gzJson('expected', 'hello-035.baksmali.json.gz'), bb = gzJson('expected', 'hello-039.baksmali.json.gz');
  const smaliChanged: string[] = [];
  for (const [cls, ms] of Object.entries<Record<string, string[]>>(ba)) for (const [k, body] of Object.entries(ms)) if (JSON.stringify(body) !== JSON.stringify(bb[cls]?.[k])) smaliChanged.push(k.split(' ').pop()!);
  assert.deepEqual(hello.changes.flatMap((c) => c.methods.bodyChanged).sort(), smaliChanged.sort());
  assert.deepEqual(smaliChanged, ['mix(JFDCBSZ)D']);
  assert.equal(hello.methods.added + hello.methods.removed + hello.fields.added + hello.fields.removed, 0);
  await assert.rejects(() => mobileCompareMembers({ path: sample('jni', 'bridge-v1.dex') }), ParseError);
});

test('graph, JNI and compare tools are registered and their CLI commands run', async () => {
  for (const n of ['mobile_app_graph', 'mobile_ipa_graph', 'mobile_jni_map', 'mobile_compare_members']) assert.ok(TOOLS.some((t) => t.name === n), n);
  const out: string[] = [];
  setCliOutput((s) => out.push(s), (s) => out.push(s));
  try {
    assert.equal(await CLI_COMMANDS.find((c) => c.name === 'jni-map')!.run([sample('jni', 'jnidemo.apk')]), 0);
    assert.match(out.join('\n'), /JNINativeMethod table at 0x205f0/);
    out.length = 0;
    assert.equal(await CLI_COMMANDS.find((c) => c.name === 'compare-members')!.run([sample('jni', 'bridge-v1.dex'), '--other', sample('jni', 'bridge-v2.dex')]), 0);
    assert.match(out.join('\n'), /\+ class org\.revlens\.jnidemo\.Extra/);
    out.length = 0;
    assert.equal(await CLI_COMMANDS.find((c) => c.name === 'app-graph')!.run([sample('apk', APKS.stopwatch)]), 0);
    assert.match(out.join('\n'), /^flowchart LR/);
    out.length = 0;
    assert.equal(await CLI_COMMANDS.find((c) => c.name === 'ipa-graph')!.run([sample('ipa', 'Wikipedia-fixture.ipa'), '--json']), 0);
    assert.equal(JSON.parse(out.join('\n')).platform, 'ios');
  } finally { setCliOutput((s) => console.log(s), (s) => console.error(s)); }
});

test('hostile: mutated libraries, manifests and DEX files end in a result or ParseError', async () => {
  const so = await readEntry(openZip(bytes('jni', 'jnidemo.apk')), 'lib/arm64-v8a/libjnidemo.so');
  const so32 = await readEntry(openZip(bytes('jni', 'jnidemo.apk')), 'lib/armeabi-v7a/libjnidemo.so');
  const dex = bytes('jni', 'bridge-v2.dex');
  const man = await readEntry(openZip(bytes('apk', APKS.alarm)), 'AndroidManifest.xml');
  const ok = (e: unknown): void => { if (!(e instanceof ParseError) && !(e instanceof RangeError)) throw e; };
  fc.assert(fc.property(fc.integer({ min: 0, max: 3 }), fc.nat(), fc.integer({ min: 0, max: 255 }), fc.nat({ max: 64 }), (w, pos, val, cut) => {
    const src = [so, so32, dex, man][w]!;
    const m = src.slice(0, Math.max(1, src.length - cut * 17));
    m[pos % m.length] = val;
    const t0 = Date.now();
    try { if (w < 2) scanJniLibrary(m); else if (w === 2) compareDex(openDex(dex), openDex(m), { bodies: true }); else graphToMermaid(androidAppGraph(parseManifest(m))); } catch (e) { ok(e); }
    assert.ok(Date.now() - t0 < 3000);
  }), { numRuns: 300 });
  fc.assert(fc.property(fc.uint8Array({ minLength: 52, maxLength: 4096 }), (b) => {
    b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1], 0);
    try { scanJniLibrary(b); } catch (e) { ok(e); }
  }), { numRuns: 300 });
  // huge declared section and relocation counts stay bounded
  const big = so.slice();
  new DataView(big.buffer, big.byteOffset).setUint16(0x3c, 9999, true);
  try { scanJniLibrary(big); } catch (e) { ok(e); }
});
