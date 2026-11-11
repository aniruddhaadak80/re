// DEX parsing and smali output checked against baksmali 2.5.2 (samples/mobile/expected/*.baksmali.json.gz).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DexFile, openDex, openZip, loadDexes, renderClass, renderMethod, findMethod, xrefIndex, searchDex, sensitiveApis, scanStrings, nativeMethods, jniNames, detectLibraries, mobileDexClasses, mobileDexMethod, mobileDexSearch, mobileDexXrefs } from '../src/node.js';
import { APKS, bytes, gzJson, normSmali, sample } from './helpers.js';

function compareAll(dex: DexFile, expectedFile: string): { methods: number } {
  const ref = gzJson<Record<string, Record<string, string[]>>>('expected', expectedFile);
  assert.equal(dex.classCount, Object.keys(ref).length, 'class count');
  let methods = 0;
  for (const cd of dex.classes) {
    const want = ref[cd.name];
    assert.ok(want, `baksmali has no class ${cd.name}`);
    const mine = normSmali(renderClass(dex, cd));
    assert.deepEqual(Object.keys(mine).sort(), Object.keys(want).sort(), `method list of ${cd.name}`);
    for (const [k, lines] of Object.entries(want)) {
      assert.deepEqual(mine[k], lines, `${cd.name} ${k}`);
      methods++;
    }
  }
  return { methods };
}

for (const [label, file] of [['alarm clock', APKS.alarm], ['screen time', APKS.screentime], ['stopwatch', APKS.stopwatch]] as const) {
  test(`every method of ${label} classes.dex disassembles identically to baksmali`, async () => {
    const [dex] = await loadDexes(openZip(bytes('apk', file)));
    assert.ok(dex);
    const { methods } = compareAll(dex, `${file.slice(0, -4)}.baksmali.json.gz`);
    assert.ok(methods > 300, `compared ${methods} methods`);
  });
}

test('d8 output for dex 035 and 039 matches baksmali, versions detected', () => {
  const d35 = openDex(bytes('java', 'hello-035.dex'))[0] as DexFile;
  const d39 = openDex(bytes('java', 'hello-039.dex'))[0] as DexFile;
  assert.equal(d35.version, 35);
  assert.equal(d39.version, 39);
  compareAll(d35, 'hello-035.baksmali.json.gz');
  compareAll(d39, 'hello-039.baksmali.json.gz');
});

test('Hello.grade smali text is exact (packed-switch, labels, payload)', () => {
  const dex = openDex(bytes('java', 'hello-035.dex'))[0] as DexFile;
  const [hit] = findMethod([dex], 'com.revlens.demo.Hello', 'grade');
  assert.ok(hit);
  assert.equal(renderMethod(dex, { classDef: hit.cd, method: hit.m, direct: hit.direct }), [
    '.method public static grade(I)Ljava/lang/String;',
    '    .registers 1',
    '    div-int/lit8 p0, p0, 0xa',
    '    packed-switch p0, :pswitch_data_12',
    '    const-string p0, "F"',
    '    return-object p0',
    '    :pswitch_8',
    '    const-string p0, "A"',
    '    return-object p0',
    '    :pswitch_b',
    '    const-string p0, "B"',
    '    return-object p0',
    '    :pswitch_e',
    '    const-string p0, "C"',
    '    return-object p0',
    '    nop',
    '    :pswitch_data_12',
    '    .packed-switch 0x7',
    '        :pswitch_e',
    '        :pswitch_b',
    '        :pswitch_8',
    '        :pswitch_8',
    '    .end packed-switch',
    '.end method',
  ].join('\n'));
  // with debug info, .line directives appear like baksmali's
  const withLines = renderMethod(dex, { classDef: hit.cd, method: hit.m, direct: hit.direct }, { lines: true });
  assert.match(withLines, /\.line 25\n {4}div-int\/lit8/);
});

test('multidex: classes.dex then classes2.dex, sensitive APIs and strings', async () => {
  const zip = openZip(bytes('java', 'multidex.zip'));
  const dexes = await loadDexes(zip);
  assert.deepEqual(dexes.map((d) => d.name), ['classes.dex', 'classes2.dex']);
  compareAll(dexes[1] as DexFile, 'multidex-classes2.baksmali.json.gz');
  const idx = xrefIndex(dexes[1] as DexFile);
  const hits = sensitiveApis(idx);
  const dcl = hits.find((h) => h.rule.id === 'dynload-dexclassloader');
  assert.equal(dcl?.callers[0]?.ref, 'Lcom/revlens/demo2/Second;->load(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Object;');
  const s = scanStrings(dexes[1] as DexFile, idx);
  assert.deepEqual(s.urls.map((u) => u.value), ['http://tracker.example.net/collect']);
  assert.equal(s.urls[0]?.users[0]?.method, 'pick');
});

test('xrefs, secrets, JNI names on the Hello dex', () => {
  const dex = openDex(bytes('java', 'hello-035.dex'))[0] as DexFile;
  const idx = xrefIndex(dex);
  assert.deepEqual(idx.calls.get('Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;')?.map((c) => c.method), ['reflect']);
  assert.deepEqual(idx.calls.get('Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')?.map((c) => c.method), ['<clinit>']);
  assert.deepEqual(idx.fields.get('Lcom/revlens/demo/Hello;->counter:I')?.map((f) => `${f.loc.method}:${f.write}`).sort(), ['<init>:true', 'add:false', 'add:true']);
  const s = scanStrings(dex, idx);
  assert.equal(s.secrets.find((x) => x.kind === 'aws-access-key')?.value, 'AKIAIOSFODNN7EXAMPLE');
  assert.ok(s.urls.some((u) => u.value === 'https://api.example.com/v1/login'));
  const nm = nativeMethods(dex);
  assert.deepEqual(nm.map((n) => n.jni), ['Java_com_revlens_demo_Hello_nativeSum']);
  assert.equal(nm[0]?.jniLong, 'Java_com_revlens_demo_Hello_nativeSum__II');
  assert.equal(jniNames('Lcom/a_b/C$D;', 'f_g', ['[I', 'Ljava/lang/String;']).long, 'Java_com_a_1b_C_00024D_f_1g___3ILjava_lang_String_2');
  const apis = sensitiveApis(idx).map((h) => h.rule.id).sort();
  assert.deepEqual(apis, ['native-loadlibrary', 'reflection-forname', 'reflection-invoke']);
});

test('search finds classes, methods, fields and strings with users', () => {
  const dex = openDex(bytes('java', 'hello-035.dex'))[0] as DexFile;
  const r = searchDex([dex], 'api.example', ['string']);
  assert.equal(r[0]?.class, 'Lcom/revlens/demo/Hello;');
  assert.equal(r[0]?.name, 'run');
  assert.deepEqual(searchDex([dex], 'Callback', ['class']).map((x) => x.class), ['Lcom/revlens/demo/Hello$Callback;']);
  assert.deepEqual(searchDex([dex], 'counter', ['field']).map((x) => x.name), ['counter']);
});

test('library detection by package prefix', () => {
  const libs = detectLibraries(['Lokhttp3/OkHttpClient;', 'Lokhttp3/Call;', 'Lcom/google/firebase/messaging/FirebaseMessagingService;', 'Lcom/google/firebase/FirebaseApp;', 'Lretrofit2/Retrofit;', 'Lcom/example/Main;']);
  const byName = Object.fromEntries(libs.map((l) => [l.name, l.classes]));
  assert.equal(byName['OkHttp 3/4'], 2);
  assert.equal(byName['Firebase Cloud Messaging'], 1);
  assert.equal(byName.Firebase, 1);
  assert.equal(byName['Retrofit 2'], 1);
});

test('dex tools on a real APK path', async () => {
  const path = sample('apk', APKS.alarm);
  const cls = await mobileDexClasses({ path, filter: 'AlarmClockActivity', limit: 5 });
  assert.equal(cls.dexFiles[0]?.version, '039');
  assert.equal(cls.totalClasses, 111);
  assert.ok(cls.classes.items.every((c) => c.class.includes('AlarmClockActivity')));
  const m = await mobileDexMethod({ path, class: 'com.angrydoughnuts.android.alarmclock.AlarmClockActivity', method: 'onCreate' });
  assert.match(m.methods?.[0]?.smali ?? '', /^\.method (public|protected) onCreate\(Landroid\/os\/Bundle;\)V\n {4}\.registers \d+/);
  const s = await mobileDexSearch({ path, query: 'notification', kinds: ['class'] });
  assert.ok(s.count > 0);
  const x = await mobileDexXrefs({ path, target: 'getSystemService', kind: 'method' });
  assert.ok(x.matches?.length && x.totalReferences > 3);
  const from = await mobileDexXrefs({ path, class: 'com.angrydoughnuts.android.alarmclock.AlarmClockActivity', target: 'onCreate', direction: 'from' });
  assert.ok(from.methods?.[0]?.references.some((r) => r.op.startsWith('invoke-super')));
});
