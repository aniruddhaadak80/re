// ADB suite tests.
// 1. Parsers against real device captures in samples/bridges/recorded/adb (sources in SOURCES.md).
//    Expected values were read off the capture files by hand and cross checked with grep counts.
// 2. Safety: device changing tools refuse without allowExecution, hostile values never reach the
//    device shell unquoted, and the quoting survives a real POSIX shell.
// 3. Real adb (when installed): no device attached gives clean errors, forward --list works.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import {
  parseGetprop, parseSettingsList, parseDumpsysPackage, launcherActivities, parseAmStart, parseInstallResult, parseTransfer, parsePs,
  parseWm, parseResolveActivity, parseForwardList, parseLsLong, pngSize, parseBackupHeader, parseAdbPackages, parseAdbPmPath, expandComponent,
} from '../src/parsers/adb.ts';
import { amStartArgs, shQuote, checkRemotePath, deviceSummary } from '../src/providers/adb.ts';
import { detect } from '../src/detect.ts';
import { runTool } from '../src/exec.ts';
import { TOOLS } from '../src/tools.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const R = (f: string) => readFileSync(join(repo, 'samples', 'bridges', 'recorded', 'adb', f), 'utf8');
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const run = async (n: string, i: Record<string, unknown>) => (await tool(n).run(i)) as any;

// ---------------- recorded real outputs ----------------

test('getprop: Android TV emulator API 28 capture', () => {
  const text = R('getprop-atv28.txt');
  const p = parseGetprop(text);
  // every line of this capture is one [key]: [value] pair
  assert.equal(Object.keys(p).length, text.split('\n').filter((l) => l.startsWith('[')).length);
  assert.equal(Object.keys(p).length, 252);
  assert.equal(p['ro.build.version.sdk'], '28');
  assert.equal(p['ro.product.model'], 'sdk_google_atv_x86');
  assert.equal(p['ro.product.cpu.abi'], 'x86');
  assert.equal(p['dalvik.vm.appimageformat'], 'lz4');
  const s = deviceSummary(p);
  assert.equal(s.sdk, 28);
  assert.equal(s.brand, 'google');
  assert.equal(s.model, 'sdk_google_atv_x86');
});

test('getprop: Mi TV capture', () => {
  const p = parseGetprop(R('getprop-mitv.txt'));
  assert.equal(p['ro.product.model'], 'MiTV-AXSO0');
  assert.equal(p['ro.build.version.sdk'], '28');
});

test('getprop: values that span lines are joined', () => {
  const p = parseGetprop('[a]: [one\ntwo]\n[b]: [x]\n');
  assert.equal(p.a, 'one\ntwo');
  assert.equal(p.b, 'x');
});

test('settings list global: API 28 capture', () => {
  const text = R('settings-list-global-atv28.txt');
  const s = parseSettingsList(text);
  assert.equal(s.adb_enabled, '1');
  assert.equal(s.add_users_when_locked, '0');
  assert.equal(s._boot_Phenotype_flags, '');
  assert.equal(Object.keys(s).length, text.split('\n').filter((l) => /^[\w.:-]+=/.test(l)).length);
});

test('dumpsys package: API 35 emulator capture (com.samruston.buzzkill)', () => {
  const info = parseDumpsysPackage(R('dumpsys-package-buzzkill-api35.txt'), 'com.samruston.buzzkill');
  assert.equal(info.package, 'com.samruston.buzzkill');
  assert.equal(info.appId, 10217);
  assert.equal(info.versionCode, 338);
  assert.equal(info.minSdk, 24);
  assert.equal(info.targetSdk, 35);
  assert.equal(info.versionName, '36.0.0');
  assert.equal(info.primaryCpuAbi, 'arm64-v8a');
  assert.equal(info.apkSigningVersion, 3);
  assert.deepEqual(info.flags, ['HAS_CODE', 'ALLOW_CLEAR_USER_DATA', 'ALLOW_BACKUP']);
  assert.equal(info.debuggable, false);
  assert.equal(info.allowBackup, true);
  assert.equal(info.firstInstallTime, '2026-08-01 13:04:46');
  assert.equal(info.lastUpdateTime, '2026-08-01 13:04:46');
  assert.equal(info.installerPackageName, null);
  assert.equal(info.installed, true);
  assert.equal(info.stopped, true);
  assert.equal(info.dataDir, '/data/user/0/com.samruston.buzzkill');
  assert.deepEqual(info.declaredPermissions, ['com.samruston.buzzkill.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION']);
  assert.equal(info.requestedPermissions.length, 25);
  assert.equal(info.requestedPermissions[0], 'android.permission.POST_NOTIFICATIONS');
  assert.equal(info.installPermissions.length, 16);
  assert.ok(info.installPermissions.every((p) => p.granted === true));
  assert.equal(info.runtimePermissions.length, 5);
  assert.deepEqual(info.runtimePermissions[4], { name: 'android.permission.ACCESS_BACKGROUND_LOCATION', granted: false, flags: ['USER_SENSITIVE_WHEN_GRANTED', 'USER_SENSITIVE_WHEN_DENIED', 'RESTRICTION_INSTALLER_EXEMPT'] });
  assert.deepEqual(launcherActivities(info), ['com.samruston.buzzkill/.ui.MainActivity']);
  assert.equal(info.activities.length, 4);
  const main = info.activities.find((a) => a.component === 'com.samruston.buzzkill/.ui.MainActivity')!;
  assert.equal(main.className, 'com.samruston.buzzkill.ui.MainActivity');
  assert.deepEqual(main.actions, ['android.intent.action.MAIN']);
  // a receiver registered under five actions is one component with five actions
  const pi = info.receivers.find((r) => r.component === 'com.samruston.buzzkill/androidx.profileinstaller.ProfileInstallReceiver')!;
  assert.equal(pi.actions.length, 4);
  assert.equal(pi.className, 'androidx.profileinstaller.ProfileInstallReceiver');
  const tile = info.services.find((s) => s.component === 'com.samruston.buzzkill/.integrations.shortcuts.TriggerTileService')!;
  assert.equal(tile.permission, 'android.permission.BIND_QUICK_SETTINGS_TILE');
  const wear = info.services.find((s) => s.component === 'com.samruston.buzzkill/.background.wear.MessageListenerService')!;
  assert.deepEqual(wear.schemes, ['wear']);
});

test('dumpsys package: older capture (a2dp.Vol, userId and restricted permissions)', () => {
  const info = parseDumpsysPackage(R('dumpsys-package-a2dp-api24.txt'), 'a2dp.Vol');
  assert.equal(info.package, 'a2dp.Vol');
  assert.equal(info.appId, 10147);
  assert.equal(info.versionCode, 133);
  assert.equal(info.minSdk, 15);
  assert.equal(info.targetSdk, 24);
  assert.equal(info.versionName, '2.12.7');
  assert.equal(info.primaryCpuAbi, null);
  assert.equal(info.requestedPermissions.length, 20);
  assert.ok(info.requestedPermissions.includes('android.permission.RECEIVE_SMS'));
  assert.equal(info.installPermissions.length, 9);
  assert.equal(info.runtimePermissions.length, 10);
  assert.deepEqual(launcherActivities(info), ['a2dp.Vol/.main']);
  const starter = info.receivers.find((r) => r.component === 'a2dp.Vol/.Starter')!;
  assert.deepEqual(starter.actions, ['android.intent.action.BOOT_COMPLETED', 'android.intent.action.MY_PACKAGE_REPLACED']);
  assert.deepEqual(starter.categories, ['android.intent.category.HOME']);
  assert.equal(info.services[0]!.permission, 'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE');
  assert.equal(info.services[0]!.className, 'a2dp.Vol.NotificationCatcher');
});

test('pm list packages -f and pm path: API 28 capture', () => {
  const text = R('pm-list-packages-f-atv28.txt');
  const pk = parseAdbPackages(text);
  assert.equal(pk.length, text.split('\n').filter((l) => l.startsWith('package:')).length);
  assert.deepEqual(pk[0], { name: 'com.android.cts.priv.ctsshim', apkPath: '/system/priv-app/CtsShimPrivPrebuilt/CtsShimPrivPrebuilt.apk' });
  assert.deepEqual(parseAdbPmPath(R('pm-path-gms-atv28.txt')), ['/system/priv-app/PrebuiltGmsCorePano/PrebuiltGmsCorePano.apk']);
});

test('resolve-activity --brief: API 28 capture', () => {
  assert.equal(parseResolveActivity(R('resolve-activity-home-atv28.txt')), 'com.google.android.tvlauncher/.HomeScreen');
  assert.equal(parseResolveActivity('No activity found\n'), undefined);
});

test('ps -A: Galaxy A30s capture', () => {
  const text = R('ps-A-galaxy-a30s.txt');
  const ps = parsePs(text);
  // reference: lines of the ps -A table that start with a user, then pid and ppid
  const expected = text.split('\n').filter((l) => /^\S+ +\d+ +\d+ /.test(l)).length;
  assert.equal(ps.length, expected);
  assert.equal(ps.length, 438);
  assert.deepEqual(ps[0], { user: 'root', pid: 1, ppid: 0, vsz: 2223728, rss: 3660, state: 'S', name: 'init' });
  const z = ps.find((p) => p.name === 'zygote64')!;
  assert.equal(z.pid, 3901);
  const ss = ps.find((p) => p.name === 'system_server')!;
  assert.equal(ss.pid, 4358);
  assert.equal(ss.ppid, 3901);
  assert.equal(ss.user, 'system');
});

test('wm size and density: TV capture', () => {
  assert.deepEqual(parseWm(R('wm-size-density-tv.txt')), { physicalSize: { width: 1280, height: 720 }, physicalDensity: 213 });
  assert.deepEqual(parseWm('Physical size: 1080x2400\nOverride size: 720x1600\n').overrideSize, { width: 720, height: 1600 });
});

test('am start -W: real capture', () => {
  const r = parseAmStart(R('am-start-W.txt'));
  assert.equal(r.ok, true);
  assert.equal(r.status, 'ok');
  assert.equal(r.launchState, 'COLD');
  assert.equal(r.component, 'io.github.eslamasabry.opencode_mobile/.MainActivity');
  assert.equal(r.totalTimeMs, 1542);
  assert.equal(r.waitTimeMs, 1544);
  const bad = parseAmStart('Starting: Intent { cmp=com.x/.Nope }\nError type 3\nError: Activity class {com.x/com.x.Nope} does not exist.\n');
  assert.equal(bad.ok, false);
  assert.match(bad.error!, /Error type 3/);
});

test('install and push lines: real capture', () => {
  const text = R('install-push.txt');
  assert.deepEqual(parseInstallResult(text), { ok: true });
  assert.deepEqual(parseTransfer(text), { files: 1, skipped: 0, rate: '16.1 MB/s', bytes: 35092106, seconds: 2.078 });
  assert.deepEqual(parseTransfer(R('pull.txt')), { files: 1, skipped: 0, rate: '26.5 MB/s', bytes: 47370, seconds: 0.002 });
  assert.deepEqual(parseInstallResult('Performing Streamed Install\nadb: failed to install x.apk: Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package com.x signatures do not match]\n'),
    { ok: false, code: 'INSTALL_FAILED_UPDATE_INCOMPATIBLE', message: 'Package com.x signatures do not match' });
});

test('forward --list, ls -la layout, PNG and backup headers', () => {
  assert.deepEqual(parseForwardList(R('forward-list-empty.txt')), []);
  assert.deepEqual(parseForwardList('emulator-5554 tcp:27042 tcp:27042\n'), [{ serial: 'emulator-5554', local: 'tcp:27042', remote: 'tcp:27042' }]);
  const ls = parseLsLong('total 12\ndrwxrwx--x 4 root sdcard_rw 3488 2024-01-01 12:00 .\ndrwxrwx--x 4 root sdcard_rw 3488 2024-01-01 12:00 Download\n-rw-rw---- 1 u0_a1 sdcard_rw 70 2024-02-03 04:05 a b.txt\nlrw-r--r-- 1 root root 11 2009-01-01 00:00 sdcard -> /storage/self/primary\n');
  assert.deepEqual(ls.map((e) => [e.type, e.name, e.size, e.target]), [['dir', 'Download', 3488, undefined], ['file', 'a b.txt', 70, undefined], ['link', 'sdcard', 11, '/storage/self/primary']]);
  const png = Buffer.from('89504e470d0a1a0a0000000d4948445200000500000002d008060000', 'hex');
  assert.deepEqual(pngSize(png), { width: 1280, height: 720 });
  assert.equal(pngSize(Buffer.from('nope')), undefined);
  assert.deepEqual(parseBackupHeader(Buffer.from('ANDROID BACKUP\n5\n1\nnone\nxx', 'latin1')), { version: 5, compressed: true, encryption: 'none' });
  assert.equal(expandComponent('a.b/.C'), 'a.b.C');
  assert.equal(expandComponent('a.b/x.y.Z'), 'x.y.Z');
});

test('ls -la parser on a real ls run in the toybox column layout', async () => {
  // GNU ls with --time-style=+%Y-%m-%d %H:%M prints the same columns as Android toybox ls -la.
  const dir = mkdtempSync(join(tmpdir(), 'rl-ls-'));
  writeFileSync(join(dir, 'file one.bin'), Buffer.alloc(1234));
  const r = await runTool('ls', ['-la', '--time-style=+%Y-%m-%d %H:%M', dir]);
  if (r.code !== 0) return; // not GNU ls (macOS, Windows): covered by the literal case above
  const e = parseLsLong(r.stdout).find((x) => x.name === 'file one.bin');
  assert.equal(e?.size, 1234);
  assert.equal(e?.type, 'file');
});

// ---------------- safety ----------------

test('shQuote survives a real POSIX shell for hostile strings', async () => {
  const sh = process.platform === 'win32' ? undefined : '/bin/sh';
  if (!sh) return;
  const cases = ["a'b", '$(touch /tmp/rl-pwn)', '`id`', 'x; rm -rf /', '"\\', "'; echo pwned; '", 'tab\there', '*'];
  for (const c of cases) {
    const r = await runTool(sh, ['-c', `printf %s ${shQuote(c)}`]);
    assert.equal(r.stdout, c);
  }
  await fc.assert(fc.asyncProperty(fc.string({ maxLength: 40 }).filter((s) => !s.includes('\0')), async (s) => {
    const r = await runTool(sh, ['-c', `printf %s ${shQuote(s)}`]);
    assert.equal(r.stdout, s);
  }), { numRuns: 60 });
});

test('am start arguments: every value is validated', () => {
  assert.deepEqual(amStartArgs({ component: 'com.x/.Main', action: 'android.intent.action.VIEW', data: 'https://example.com/a?b=1', categories: ['android.intent.category.BROWSABLE'], extras: { user: 'bob smith' } }),
    ['-W', '-n', 'com.x/.Main', '-a', 'android.intent.action.VIEW', '-d', 'https://example.com/a?b=1', '-c', 'android.intent.category.BROWSABLE', '--es', 'user', 'bob smith']);
  const bad: any[] = [
    { component: 'com.x/.Main; reboot' }, { component: 'com.x/.Main', action: 'a b' }, { component: 'com.x/.Main', data: "https://x/'$(id)" },
    { component: 'com.x/.Main', extras: { 'k;id': 'v' } }, { component: 'com.x/.Main', extras: { k: 'line\nbreak' } }, { component: '-n evil/.x' },
  ];
  for (const b of bad) assert.throws(() => amStartArgs(b), /must|bad extra/);
});

test('remote paths refuse traversal, quotes and control characters', () => {
  assert.equal(checkRemotePath('/sdcard/Download/a b.txt'), '/sdcard/Download/a b.txt');
  for (const p of ['/sdcard/../data/x', "/sdcard/a'b", '/sdcard/a\nb', 'relative/x', '/sdcard/$(id)', '/sdcard/`id`', '/sdcard/a;b']) {
    assert.throws(() => checkRemotePath(p));
  }
});

test('device changing ADB tools refuse without allowExecution (or report adb missing)', async () => {
  const apkDir = mkdtempSync(join(tmpdir(), 'rl-apk-'));
  const apk = join(apkDir, 'x.apk');
  writeFileSync(apk, Buffer.from('504b030400000000', 'hex'));
  const cases: [string, Record<string, unknown>][] = [
    ['bridge_adb_install', { path: apk }],
    ['bridge_adb_uninstall', { package: 'com.example.app' }],
    ['bridge_adb_push', { path: apk, remotePath: '/data/local/tmp/x.apk' }],
    ['bridge_adb_start_activity', { component: 'com.example.app/.Main' }],
    ['bridge_adb_stop_app', { package: 'com.example.app' }],
    ['bridge_adb_input', { kind: 'keyevent', keycode: 'KEYCODE_HOME' }],
    ['bridge_adb_forward', { action: 'add', local: 'tcp:27042', remote: 'tcp:27042' }],
    ['bridge_adb_reverse', { action: 'remove-all' }],
  ];
  const adb = await detect('adb');
  for (const [name, input] of cases) {
    for (const allow of [undefined, false, 'true', 1]) {
      const r = await run(name, { ...input, allowExecution: allow });
      if (!adb.available) { assert.equal(r.available, false, name); continue; }
      assert.equal(r.blocked, true, `${name} allow=${String(allow)}`);
      assert.match(String(r.error), /allowExecution: true/);
    }
  }
});

test('hostile ADB inputs are refused before anything runs', async () => {
  const adb = await detect('adb');
  const bad: [string, Record<string, unknown>][] = [
    ['bridge_adb_pull', { remotePath: '/sdcard/x; reboot' }],
    ['bridge_adb_push', { path: __filename_safe(), remotePath: '/system/bin/sh', allowExecution: true }],
    ['bridge_adb_settings', { namespace: 'global; reboot' }],
    ['bridge_adb_settings', { namespace: 'global', key: "x' ; reboot" }],
    ['bridge_adb_getprop', { key: 'ro.x$(id)' }],
    ['bridge_adb_input', { kind: 'text', text: 'héllo', allowExecution: true }],
    ['bridge_adb_input', { kind: 'tap', x: -1, y: 2, allowExecution: true }],
    ['bridge_adb_logcat_filtered', { specs: ['Tag:Q'] }],
    ['bridge_adb_logcat_filtered', { buffer: 'main;id' }],
    ['bridge_adb_forward', { action: 'add', local: 'tcp:99999', remote: 'tcp:1', allowExecution: true }],
    ['bridge_adb_forward', { action: 'add', local: 'tcp:1 tcp:2', remote: 'tcp:1', allowExecution: true }],
    ['bridge_adb_ls', { remotePath: '/sdcard/../../' }],
    ['bridge_adb_components', { package: 'com.x;id' }],
    ['bridge_adb_screenrecord', { size: '1x1;id' }],
  ];
  for (const [name, input] of bad) {
    const r = await run(name, input);
    if (!adb.available) { assert.equal(r.available, false, name); continue; }
    assert.equal(r.inputError, true, `${name} ${JSON.stringify(input)} -> ${JSON.stringify(r)}`);
  }
});

function __filename_safe(): string {
  return fileURLToPath(import.meta.url);
}

test('ADB parsers stay fast and never throw on random input', () => {
  fc.assert(fc.property(fc.string({ maxLength: 4000 }), (s) => {
    parseGetprop(s); parseSettingsList(s); parseDumpsysPackage(s); parseAmStart(s); parseInstallResult(s); parseTransfer(s);
    parsePs(s); parseWm(s); parseResolveActivity(s); parseForwardList(s); parseLsLong(s);
  }), { numRuns: 300 });
  const big = 'Activity Resolver Table:\n' + '  ab com.x/.A filter 1\n    Action: "' + 'a'.repeat(100_000) + '"\n';
  const t0 = Date.now();
  parseDumpsysPackage(big.repeat(20));
  parseGetprop('[' + 'k'.repeat(200_000) + ']: [' + 'v'.repeat(200_000));
  parseLsLong('-rw-r--r-- 1 a b 1 2024-01-01 00:00 ' + ' '.repeat(200_000));
  assert.ok(Date.now() - t0 < 3000);
});

// ---------------- real adb ----------------

const adbDet = await detect('adb');
const noAdb = adbDet.available ? false : 'adb not installed';

test('real adb: version and device list', { skip: noAdb }, async () => {
  assert.match(adbDet.version ?? '', /^1\.0\.\d+/);
  const r = await run('bridge_adb_devices', {});
  assert.equal(r.ok, true);
  assert.ok(Array.isArray(r.devices));
});

test('real adb: forward --list works without a device', { skip: noAdb }, async () => {
  const r = await run('bridge_adb_forward', {});
  assert.equal(r.ok, true);
  assert.ok(Array.isArray(r.rules));
});

test('real adb: read tools return a clean error when no device is attached', { skip: noAdb }, async () => {
  const devs = await run('bridge_adb_devices', {});
  if (devs.count > 0) return; // a real device is attached: these would succeed, nothing to check here
  for (const [name, input] of [['bridge_adb_getprop', {}], ['bridge_adb_ps', {}], ['bridge_adb_pm_path', { package: 'com.android.settings' }], ['bridge_adb_settings', { namespace: 'global', key: 'adb_enabled' }]] as const) {
    const r = await run(name, input);
    assert.equal(r.available, true, name);
    assert.equal(r.ok, false, name);
    assert.match(String(r.error), /no devices|device .* not found|no emulators/i, name);
  }
});
