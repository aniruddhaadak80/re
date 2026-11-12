// Round 3 desktop tests: build computer sessions, native UI tracing and scenarios, process capture,
// app state export and tasks. Live tests run on Linux with Xvfb, xdotool, xwd, dbus-daemon,
// at-spi2-registryd and Chromium (see scripts/fetch-desktop-tools.py); they skip with a reason
// when a piece is missing. File-format tests run everywhere against references recorded by
// scripts/gen-r3-fixtures.py with Python's own readers, ImageMagick and strace -C.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync, spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import fc from 'fast-check';
import {
  encodeMessage, decodeMessage, splitSignature, Variant, MSG, compareUiTrees, findNode, checkSelector, normalizeRole, decodeAtspiStates,
  parseStrace, compareCaptures, readLevelLog, decodeLocalStorage, parseXml, wholeText, parseKeyFile, viewOf, validateTask, resolvePointer, runTask,
  toEvalTasks, scoreTaskAnswers, writeZip, listZip, readZipEntry, decodeXwd, encodePng, pngInfo, parseKeyCombo, toXdotool, toYdotool, winVk, redactValue, redactLines, isSecretFile,
  TOOLS as WEB_TOOLS, InputError,
} from '../src/index.js';
import {
  startComputer, actOnComputer, checkpointComputer, closeComputer, listComputers, verifyAuditLog, traceUi, runUiScenario, captureProcess, compareCaptureFiles,
  appState, appExport, checkTaskFile, nodeViewHelpers, homeSource, DBusClient, captureUiTree, TOOLS, CLI_COMMANDS, toolsEnv,
} from '../src/node.js';
import { inflateRawSync, deflateRawSync, deflateSync } from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
const S = join(HERE, '../../../samples/desktop');
const R3 = join(S, 'r3');
const REF = JSON.parse(readFileSync(join(R3, 'reference.json'), 'utf8'));
const linux = process.platform === 'linux';
const ENV = toolsEnv();
const which = (cmd: string) => { for (const d of String(ENV.PATH ?? '').split(delimiter)) if (d && existsSync(join(d, cmd))) return join(d, cmd); return undefined; };
const chrome = process.env.REVLENS_CHROMIUM && existsSync(process.env.REVLENS_CHROMIUM) ? process.env.REVLENS_CHROMIUM : undefined;
const sha = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------- D-Bus codec ----------------

test('D-Bus messages round trip through the codec', () => {
  const body = [42, 'hi', [1, 2, 3], { a: new Variant('s', 'x'), b: new Variant('i', 7) }, [':1.2', '/org/a11y/atspi/accessible/root'], true, 2.5, -3n, new Uint8Array([1, 2, 255])];
  const m = encodeMessage({ type: MSG.call, flags: 0, serial: 9, path: '/x/y', interface: 'a.b', member: 'M', destination: 'org.d', signature: 'usaua{sv}(so)bdxay', body });
  const d = decodeMessage(m);
  assert.equal(d.serial, 9); assert.equal(d.path, '/x/y'); assert.equal(d.member, 'M'); assert.equal(d.signature, 'usaua{sv}(so)bdxay');
  assert.deepEqual(d.body.slice(0, 3), [42, 'hi', [1, 2, 3]]);
  assert.deepEqual({ ...(d.body[3] as object) }, { a: 'x', b: 7 });
  assert.deepEqual(d.body.slice(4, 8), [[':1.2', '/org/a11y/atspi/accessible/root'], true, 2.5, -3]);
  assert.deepEqual([...(d.body[8] as Uint8Array)], [1, 2, 255]);
  assert.deepEqual(splitSignature('a{sv}ia(ii)v'), ['a{sv}', 'i', 'a(ii)', 'v']);
  assert.throws(() => splitSignature('a{s}'), InputError);
});

test('the D-Bus client talks to a real dbus-daemon the same way gdbus does', { timeout: 30_000 }, async (t) => {
  const daemon = which('dbus-daemon'), gdbus = which('gdbus');
  if (!linux || !daemon || !gdbus) { t.skip('needs Linux, dbus-daemon and gdbus'); return; }
  const dir = mkdtempSync(join(tmpdir(), 'rl-dbus-'));
  writeFileSync(join(dir, 'bus.conf'), `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd"><busconfig><type>session</type><listen>unix:path=${dir}/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*" eavesdrop="true"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>`);
  const bus = spawn(daemon, [`--config-file=${dir}/bus.conf`, '--nofork', '--print-address'], { env: ENV, stdio: ['ignore', 'pipe', 'ignore'] });
  try {
    const address = await new Promise<string>((res) => bus.stdout!.once('data', (d) => res(String(d).split('\n')[0]!.trim())));
    const c = await DBusClient.connect(address);
    assert.match(c.uniqueName, /^:1\.\d+$/);
    const names = (await c.call({ destination: 'org.freedesktop.DBus', path: '/org/freedesktop/DBus', interface: 'org.freedesktop.DBus', member: 'ListNames' }))[0] as string[];
    const ref = spawnSync(gdbus, ['call', '--address', address, '--dest', 'org.freedesktop.DBus', '--object-path', '/org/freedesktop/DBus', '--method', 'org.freedesktop.DBus.GetId'], { env: ENV, encoding: 'utf8' });
    const id = (await c.call({ destination: 'org.freedesktop.DBus', path: '/org/freedesktop/DBus', interface: 'org.freedesktop.DBus', member: 'GetId' }))[0];
    assert.equal(`('${id}',)`, ref.stdout.trim());
    assert.ok(names.includes('org.freedesktop.DBus') && names.includes(c.uniqueName));
    assert.equal(await c.pidOf(c.uniqueName), process.pid);
    await assert.rejects(c.call({ destination: 'org.nope.Missing', path: '/', interface: 'x.y', member: 'Z' }), /ServiceUnknown/);
    c.close();
  } finally { bus.kill(); }
});

// ---------------- formats against Python, ImageMagick and strace references ----------------

test('XWD decoding matches ImageMagick and our PNG decodes to the same pixels in Python', (t) => {
  if (!REF.xwd) { t.skip('fixture made without ImageMagick'); return; }
  const img = decodeXwd(new Uint8Array(readFileSync(join(R3, 'gradient.xwd'))));
  assert.equal(img.width, REF.xwd.width); assert.equal(img.height, REF.xwd.height);
  assert.equal(sha(img.data), REF.xwd.rgba_sha256);
  const png = encodePng(img, (b) => new Uint8Array(deflateSync(b)));
  assert.deepEqual(pngInfo(png), { width: 48, height: 32, bitDepth: 8, colorType: 6 });
  const dir = mkdtempSync(join(tmpdir(), 'rl-png-')); writeFileSync(join(dir, 'a.png'), png);
  const py = spawnSync('python3', ['-c', 'import sys,hashlib\nfrom PIL import Image\nim=Image.open(sys.argv[1]).convert("RGBA")\nprint(hashlib.sha256(im.tobytes()).hexdigest())', join(dir, 'a.png')], { encoding: 'utf8' });
  if (py.status !== 0) { t.diagnostic('Pillow not available; PNG checked by header only'); return; }
  assert.equal(py.stdout.trim(), REF.xwd.rgba_sha256);
});

test('strace parser counts agree with strace -C for every syscall', () => {
  const s = parseStrace(readFileSync(join(R3, 'strace-sample.txt'), 'utf8'));
  const refTable = REF.strace_summary as Record<string, { calls: number; errors: number }>;
  assert.ok(Object.keys(refTable).length >= 5);
  for (const [k, v] of Object.entries(refTable)) assert.deepEqual({ calls: s.bySyscall[k]?.calls, errors: s.bySyscall[k]?.errors }, v, k);
  assert.ok(s.execs.some((e) => e.path === '/bin/true' && e.ok));
  assert.ok(s.network.some((n) => n.op === 'connect' && n.address === '127.0.0.1' && n.port === 9));
  assert.ok(s.files.some((f) => f.path === '/nonexistent/revlens' && f.failed === 1));
  assert.ok(s.processes.some((p) => p.parent !== undefined));
});

test('typed views agree with Python json, configparser, ElementTree, sqlite3, zipfile, gzip and plistlib', async () => {
  const h = await nodeViewHelpers();
  const rd = (p: string) => new Uint8Array(readFileSync(join(R3, 'task-home', p)));
  assert.deepEqual((viewOf('todo.txt', rd('Documents/todo.txt')).view as { lines: string[] }).lines, REF.todo_lines);
  assert.deepEqual(viewOf('settings.json', rd('.config/revlens-fixture/settings.json')).view, REF.settings);
  const ini = viewOf('app.ini', rd('.config/revlens-fixture/app.ini'));
  assert.equal(ini.format, 'keyfile'); assert.deepEqual(JSON.parse(JSON.stringify((ini.view as { groups: unknown }).groups)), REF.ini);
  const xml = viewOf('doc.xml', rd('Documents/doc.xml'));
  const root = (xml.view as { root: { children: unknown[] } }).root;
  assert.equal(wholeText(root.children[0] as never), REF.xml_title_text);
  assert.equal(resolvePointer(xml.view, '/root/children/[name=item][@id=two]/children/0').value, REF.xml_item_two_text);
  const db = viewOf('notes.sqlite', rd('.local/share/revlens-fixture/notes.sqlite'), h);
  assert.equal(db.format, 'sqlite');
  assert.deepEqual((db.view as { tables: Record<string, { rows: unknown[][] }> }).tables.notes!.rows, REF.notes_rows);
  const z = viewOf('flyer.zdoc', rd('Documents/flyer.zdoc'), h);
  assert.deepEqual((z.view as { entries: { name: string }[] }).entries.map((e) => e.name), REF.zip_names);
  assert.equal(resolvePointer(z.view, '/entries/[name=content.xml]/view/root/children/[name=body]/children/[name=p]/children/0').value, REF.zip_subtitle);
  assert.deepEqual(viewOf('data.json.gz', rd('Documents/data.json.gz'), h).view, REF.gz);
  assert.deepEqual(viewOf('x.plist', rd('Library/Preferences/dev.revlens.fixture.plist')).view, REF.plist);
});

test('task file: every check gives the result its construction expects, and x_eval_score scores the answers the same way', async () => {
  const task = JSON.parse(readFileSync(join(R3, 'task.json'), 'utf8'));
  assert.deepEqual(validateTask(task), []);
  const r = await checkTaskFile({ task: join(R3, 'task.json'), home: join(R3, 'task-home') });
  const got = Object.fromEntries(r.results.map((x) => [x.id, x.pass]));
  assert.deepEqual(got, REF.expected_pass, JSON.stringify(r.results.filter((x) => x.pass !== REF.expected_pass[x.id])));
  assert.equal(r.failed, 1);
  // the eval harness in @revlens/extras scores the same answers to the same totals
  const { scoreAnswers } = await import('../../extras/src/eval/harness.js');
  const ours = scoreTaskAnswers(task, r.answers, 'fixture');
  const theirs = scoreAnswers(r.answers, { tasks: toEvalTasks(task) as never, agent: 'fixture' });
  assert.equal(ours.score, theirs.score); assert.equal(ours.correct, theirs.correct); assert.equal(theirs.correct, task.checks.length - 1);
  assert.deepEqual(ours.byTag['fixture-checks'], theirs.byTag['fixture-checks']);
  // rule checks
  assert.ok(validateTask({ ...task, checks: [{ kind: 'lines_present', file: '../etc/passwd', lines: ['x'] }] }).some((p) => /relative path/.test(p)));
  assert.ok(validateTask({ ...task, checks: [{ kind: 'value_equals', file: 'a.json', pointer: '/t', value: '2026-01-02T03:04:05Z' }] }).some((p) => /date/.test(p)));
  assert.ok(validateTask({ ...task, checks: [{ kind: 'row_count', file: 'a.db', table: 't', equals: 1, at_most: 3 }] }).some((p) => /exactly one/.test(p)));
  await assert.rejects(homeSource(join(R3, 'task-home')).read('../task.json'), InputError);
});

test('app state finds config, data and preference files with formats, and export redacts secrets (checked with Python zipfile)', async () => {
  const home = join(R3, 'task-home');
  const st = await appState({ name: 'revlens-fixture', bundleId: 'dev.revlens.fixture', home, paths: [join(home, 'Library/Preferences')] });
  const rels = st.files.map((f) => f.rel);
  assert.ok(rels.includes('settings.json') && rels.includes('app.ini') && rels.includes('notes.sqlite') && rels.includes('dev.revlens.fixture.plist'), rels.join(','));
  const f = (n: string) => st.files.find((x) => x.rel === n)!;
  assert.equal(f('settings.json').format, 'json'); assert.equal(f('notes.sqlite').format, 'sqlite'); assert.deepEqual(f('notes.sqlite').summary, { tables: { notes: 3, tags: 0 } });
  assert.equal(f('Cookies').secret, true); assert.equal(f('settings.json').sha256, sha(readFileSync(join(home, '.config/revlens-fixture/settings.json'))));
  const out = join(mkdtempSync(join(tmpdir(), 'rl-exp-')), 'state.zip');
  const e = await appExport({ name: 'revlens-fixture', home, out, paths: [join(home, 'Library/Preferences')] });
  assert.ok(e.withheld >= 1 && e.redactedFiles >= 3);
  const py = spawnSync('python3', ['-c', 'import sys,zipfile,json\nz=zipfile.ZipFile(sys.argv[1])\nassert z.testzip() is None\nprint(json.dumps({"names":z.namelist(),"manifest":json.loads(z.read("manifest.json")),"settings":json.loads([z.read(n) for n in z.namelist() if n.endswith("settings.json")][0]),"ini":[z.read(n).decode() for n in z.namelist() if n.endswith("app.ini")][0],"plist":json.loads([z.read(n) for n in z.namelist() if n.endswith(".plist.redacted.json")][0])}))', out], { encoding: 'utf8' });
  assert.equal(py.status, 0, py.stderr);
  const z = JSON.parse(py.stdout);
  assert.ok(!z.names.some((n: string) => n.endsWith('/Cookies')), 'Cookies withheld');
  assert.equal(z.manifest.files.find((x: { source: string }) => x.source.endsWith('Cookies')).redacted, 'withheld');
  assert.equal(z.settings.sync.apiToken, '[redacted]'); assert.equal(z.settings.sync.password, '[redacted]'); assert.equal(z.settings.sync.server, 'example.org'); assert.equal(z.settings.theme, 'dark');
  assert.match(z.ini, /^password=\[redacted\]$/m); assert.match(z.ini, /^user=ada$/m);
  assert.equal(z.plist.AuthToken, '[redacted]'); assert.equal(z.plist.WindowWidth, 1024);
  const manifestSettings = z.manifest.files.find((x: { source: string }) => x.source.endsWith('settings.json'));
  assert.equal(manifestSettings.sha256, sha(readFileSync(join(home, '.config/revlens-fixture/settings.json'))));
  assert.deepEqual(manifestSettings.masked.sort(), ['/sync/apiToken', '/sync/password']);
});

test('Electron-style userData written by real Chromium: Local Storage keys read from its LevelDB log', { timeout: 90_000 }, async (t) => {
  if (!linux || !chrome) { t.skip('needs Linux and REVLENS_CHROMIUM'); return; }
  const home = mkdtempSync(join(tmpdir(), 'rl-home-'));
  const page = join(home, 'ls.html');
  writeFileSync(page, `<title>LS</title><script>localStorage.setItem('theme','dark');localStorage.setItem('authToken','abc123');localStorage.setItem('名前','値');localStorage.setItem('gone','x');localStorage.removeItem('gone');document.title='done'</script>`);
  const r = spawnSync(chrome, ['--headless', '--disable-gpu', `--user-data-dir=${join(home, '.config/RevLensElectronFixture')}`, '--no-first-run', '--dump-dom', `file://${page}`], { encoding: 'utf8', timeout: 60_000, env: ENV });
  assert.match(r.stdout, /<title>done<\/title>/);
  const st = await appState({ name: 'RevLensElectronFixture', home });
  assert.equal(st.electron?.length, 1);
  const ls = Object.fromEntries((st.electron![0]!.localStorage ?? []).map((x) => [x.key, x.value]));
  assert.deepEqual(ls, { theme: 'dark', authToken: '[redacted]', '名前': '値' });
  const out = join(home, 'x.zip');
  await appExport({ name: 'RevLensElectronFixture', home, out });
  const all = spawnSync('python3', ['-c', 'import sys,zipfile\nz=zipfile.ZipFile(sys.argv[1])\nprint(any(b"abc123" in z.read(n) for n in z.namelist()))', out], { encoding: 'utf8' });
  assert.equal(all.stdout.trim(), 'False', 'the token value is not in the export');
  // the raw log decodes to the same records without the app state wrapper
  const log = readdirSync(join(home, '.config/RevLensElectronFixture/Default/Local Storage/leveldb')).find((n) => n.endsWith('.log'))!;
  const recs = readLevelLog(new Uint8Array(readFileSync(join(home, '.config/RevLensElectronFixture/Default/Local Storage/leveldb', log)))).records.map((x) => ({ op: x.op, ...decodeLocalStorage(x.key, x.value) })).filter((x) => !x.meta);
  assert.ok(recs.some((x) => x.op === 'delete' && x.key === 'gone'));
});

// ---------------- live desktop: computer, trace, scenario ----------------

const HTML = `<title>RL fixture</title><body style="margin:0"><button style="position:absolute;left:40px;top:40px;width:200px;height:50px" onclick="document.getElementById('s').textContent='Clicked '+(++window.n)">Press me</button><p id=s role=status style="position:absolute;left:40px;top:100px">Idle</p><input aria-label="Search box" style="position:absolute;left:40px;top:160px;width:300px"><label style="position:absolute;left:40px;top:220px"><input type=checkbox id=c>Agree</label><div style="position:absolute;left:400px;top:40px;width:120px;height:120px;background:rgb(255,0,0)"></div><div style="height:3000px"></div></body><script>window.n=0</script>`;
let live: { id: string; auditLog: string; workDir: string; pid?: number } | undefined;
let liveSkip = '';

before(async () => {
  if (!linux) { liveSkip = 'live desktop tests need Linux'; return; }
  if (!chrome) { liveSkip = 'set REVLENS_CHROMIUM to a Chromium binary'; return; }
  for (const p of ['xdotool', 'xwd', 'dbus-daemon']) if (!which(p)) { liveSkip = `${p} not found (run scripts/fetch-desktop-tools.py and set REVLENS_DESKTOP_TOOLS)`; return; }
  if (!which('Xvfb') && !which('Xvfb-revlens')) { liveSkip = 'Xvfb not found'; return; }
  try {
    const s = await startComputer({ consent: true, allowExecution: true, width: 1024, height: 768, launch: [chrome, '--ozone-platform=x11', '--force-renderer-accessibility', '--disable-gpu', '--no-first-run', '--disable-infobars', `--user-data-dir=${mkdtempSync(join(tmpdir(), 'rl-ud-'))}`, '--window-position=0,0', '--window-size=1024,768', '--app=data:text/html,' + encodeURIComponent(HTML)] }) as { id: string; auditLog: string; workDir: string; launched?: { pid?: number } };
    live = { id: s.id, auditLog: s.auditLog, workDir: s.workDir, pid: s.launched?.pid };
    await actOnComputer(s.id, { action: 'wait', untilElement: { role: 'button', name: 'Press me' }, timeoutMs: 60_000 });
  } catch (e) { liveSkip = `could not start the session: ${(e as Error).message}`; if (live) await closeComputer(live.id).catch(() => undefined); live = undefined; }
});
after(async () => { if (live) await closeComputer(live.id).catch(() => undefined); });

async function elementBounds(name: string, role: string, retry = 0): Promise<import('../src/gvariant.js').UiNode> {
  const tree = await captureUiTree({ allowExecution: true, busAddress: (listComputers().find((x) => x.id === live!.id) as { accessibilityBus?: string }).accessibilityBus, maxNodes: 2000, maxDepth: 40, details: true });
  const n = findNode(tree.nodes, { role, name })!;
  assert.ok(n, `${role} ${name} in the tree`);
  if (!n.bounds && retry < 5) { await sleep(500); return elementBounds(name, role, retry + 1); }
  return n;
}

test('computer: screenshot pixels match ImageMagick on the same display and show the page', { timeout: 60_000 }, async (t) => {
  if (!live) { t.skip(liveSkip); return; }
  const shot = await actOnComputer(live.id, { action: 'screenshot' }) as { path: string; width: number; height: number; sha256: string };
  assert.equal(shot.width, 1024); assert.equal(shot.height, 768);
  assert.equal(sha(readFileSync(shot.path)), shot.sha256);
  // the red square: its accessible bounds are not exposed (a plain div), so locate it from the button's bounds
  const btn = await elementBounds('Press me', 'button');
  const py = spawnSync('python3', ['-c', 'import sys\nfrom PIL import Image\nim=Image.open(sys.argv[1]).convert("RGB")\nx,y=int(sys.argv[2]),int(sys.argv[3])\nprint(*im.getpixel((x,y)))', shot.path, String(btn.bounds!.x + 360 + 60), String(btn.bounds!.y + 60)], { encoding: 'utf8' });
  if (py.status === 0) assert.equal(py.stdout.trim(), '255 0 0');
  // xwd of the same display decoded by ImageMagick equals our decoder
  const display = (listComputers().find((x) => x.id === live!.id) as { display: string }).display;
  const xwd = spawnSync(which('xwd')!, ['-root', '-silent'], { env: { ...ENV, DISPLAY: display }, maxBuffer: 64 << 20 });
  const mine = decodeXwd(new Uint8Array(xwd.stdout));
  const im = spawnSync('convert', ['xwd:-', '-depth', '8', 'rgba:-'], { input: xwd.stdout, maxBuffer: 64 << 20 });
  if (im.status !== 0) { t.diagnostic('ImageMagick not available'); return; }
  assert.equal(sha(mine.data), sha(im.stdout));
});

test('computer: pointer click, typing and keys reach the app (checked through its accessibility states and text)', { timeout: 60_000 }, async (t) => {
  if (!live) { t.skip(liveSkip); return; }
  const cb = await elementBounds('Agree', 'check box');
  assert.ok(!(cb.states ?? []).includes('checked'));
  await actOnComputer(live.id, { action: 'click', x: cb.bounds!.x + 5, y: cb.bounds!.y + Math.floor(cb.bounds!.height / 2) });
  await sleep(300);
  assert.ok(((await elementBounds('Agree', 'check box')).states ?? []).includes('checked'));
  const box = await elementBounds('Search box', 'entry');
  await actOnComputer(live.id, { action: 'click', x: box.bounds!.x + 10, y: box.bounds!.y + 5 });
  await actOnComputer(live.id, { action: 'type', text: 'Hi -there' });
  await sleep(300);
  assert.equal((await elementBounds('Search box', 'entry') as { text?: string }).text, 'Hi -there');
  await actOnComputer(live.id, { action: 'key', key: 'ctrl+a' });
  await actOnComputer(live.id, { action: 'key', key: 'BackSpace' });
  await actOnComputer(live.id, { action: 'type', text: 'secret-pw', secret: true });
  await sleep(300);
  assert.equal((await elementBounds('Search box', 'entry') as { text?: string }).text, 'secret-pw');
  const moved = await actOnComputer(live.id, { action: 'move', x: 333, y: 222 });
  assert.ok(moved);
  assert.deepEqual((await actOnComputer(live.id, { action: 'cursor' }) as { cursor: unknown }).cursor, { x: 333, y: 222 });
  const w = await actOnComputer(live.id, { action: 'windows' }) as { windows: { title: string; pid?: number }[] };
  assert.ok(w.windows.some((x) => x.title === 'RL fixture'));
  await assert.rejects(actOnComputer(live.id, { action: 'key', key: 'hyper+q' }), InputError);
  const log = readFileSync(live.auditLog, 'utf8');
  assert.ok(!log.includes('secret-pw'), 'secret text is not in the audit log');
  assert.ok(log.includes(sha('secret-pw')));
});

test('computer: checkpoint saves screenshot, UI tree and process snapshots with matching digests', { timeout: 60_000 }, async (t) => {
  if (!live) { t.skip(liveSkip); return; }
  const cp = await checkpointComputer(live.id, { label: 'after typing' }) as { dir: string; files: { name: string; sha256: string }[]; uiNodes: number; processes: number };
  for (const f of cp.files) assert.equal(sha(readFileSync(join(cp.dir, f.name))), f.sha256, f.name);
  assert.ok(cp.uiNodes > 10);
  const tree = JSON.parse(readFileSync(join(cp.dir, 'ui-tree.json'), 'utf8'));
  assert.ok(tree.nodes.some((n: { role: string; name: string }) => n.role === 'button' && n.name === 'Press me'));
  const procs = JSON.parse(readFileSync(join(cp.dir, 'processes.json'), 'utf8'));
  assert.ok(procs.some((p: { process: { name: string }; modules: { path: string }[] }) => /chrom/i.test(p.process.name) && p.modules.some((m) => /libc\.so/.test(m.path))));
  const manifest = JSON.parse(readFileSync(join(cp.dir, 'manifest.json'), 'utf8'));
  assert.equal(manifest.kind, 'revlens-computer-checkpoint');
});

test('UI trace: an accessibility action during the trace shows up as events and as a tree change', { timeout: 60_000 }, async (t) => {
  if (!live) { t.skip(liveSkip); return; }
  const r = await traceUi({ allowExecution: true, session: live.id, durationMs: 2500, elementAction: { selector: { role: 'button', name: 'Press me' } } });
  assert.equal(r.backend, 'at-spi');
  assert.ok(r.actions[0]?.ok, JSON.stringify(r.actions));
  assert.ok(r.events.length > 0);
  assert.ok(r.summary.textChanges.some((x) => /Clicked/.test(x.text)) || r.events.some((e) => e.type.startsWith('object:text-changed')), JSON.stringify(r.summary.byType));
  const status = r.diff!.changed.find((c) => c.changes.some((ch) => ch.field === 'text' && /^Clicked \d+$/.test(String(ch.after))));
  assert.ok(status, JSON.stringify(r.diff!.changed.slice(0, 5)));
  // poll mode sees the same change without events
  const p = await traceUi({ allowExecution: true, session: live.id, mode: 'poll', intervalMs: 300, durationMs: 2000, elementAction: { selector: { role: 'button', name: 'Press me' } }, treeDiff: false });
  assert.ok(p.events.some((e) => e.type === 'object:text-changed:replace' && /^Clicked \d+$/.test(String(e.data))), JSON.stringify(p.events.slice(0, 5)));
});

test('UI scenario: find, accessibility click, wait, type, pointer click, asserts; a failing step stops the rest', { timeout: 90_000 }, async (t) => {
  if (!live) { t.skip(liveSkip); return; }
  const wasChecked = ((await elementBounds('Agree', 'check box')).states ?? []).includes('checked');
  const r = await runUiScenario({ allowExecution: true, session: live.id, steps: [
    { find: { role: 'button', name: 'Press me' } },
    { click: { role: 'push button', name: 'Press me' }, method: 'action' },
    { waitFor: { namePrefix: 'Clicked' }, timeoutMs: 5000 },
    { type: 'hello world', into: { role: 'entry', name: 'Search box' } },
    { assert: { role: 'entry', name: 'Search box' }, text: 'hello world' },
    { click: { role: 'checkbox', name: 'Agree' }, method: 'pointer' },
    wasChecked ? { assert: { role: 'checkbox', name: 'Agree' }, notStates: ['checked'] } : { assert: { role: 'checkbox', name: 'Agree' }, states: ['checked'] },
    { key: 'Tab' },
    { assert: { role: 'button', name: 'No such button' }, exists: false },
    { screenshot: 'end' },
  ] });
  assert.ok(r.ok, JSON.stringify(r.steps.filter((s) => !s.ok)));
  assert.equal(r.steps[1]!.how?.startsWith('accessibility action'), true);
  assert.match(r.steps[5]!.how!, /^pointer click at/);
  for (const s of r.steps) { assert.ok(s.tree && existsSync(s.tree)); assert.ok(s.screenshot && existsSync(s.screenshot)); assert.equal(sha(readFileSync(s.screenshot!)), s.screenshotSha256); }
  assert.ok(r.steps[1]!.changes!.changed > 0);
  const bad = await runUiScenario({ allowExecution: true, session: live.id, capture: false, steps: [{ assert: { role: 'button', name: 'Press me' }, states: ['checked'] }, { find: { role: 'button' } }] });
  assert.equal(bad.ok, false); assert.equal(bad.failed, 1); assert.equal(bad.skipped, 1); assert.match(bad.steps[0]!.error!, /state checked missing/);
  // compare the first and last step trees through the tool
  const cmp = await WEB_TOOLS.find((x) => x.name === 'desktop_ui_compare')!.run({ aText: readFileSync(r.steps[0]!.tree!, 'utf8'), bText: readFileSync(r.steps[r.steps.length - 1]!.tree!, 'utf8'), ignore: ['bounds'] }) as { changed: { name: string }[] };
  assert.ok(cmp.changed.some((c) => c.name === 'Search box' || c.name === 'Agree'));
});

test('computer: audit log is intact, a changed line is detected, and close stops every process', { timeout: 60_000 }, async (t) => {
  if (!live) { t.skip(liveSkip); return; }
  const pids = (listComputers().find((x) => x.id === live!.id) as { processes: { pid: number }[] }).processes.map((p) => p.pid);
  const c = await closeComputer(live.id) as { auditLog: string; auditHead: string };
  live = undefined;
  await sleep(500);
  for (const p of pids) assert.ok(!existsSync(`/proc/${p}`) || /zombie|\bZ\b/.test(readFileSync(`/proc/${p}/status`, 'utf8')), `pid ${p} stopped`);
  const v = await verifyAuditLog(c.auditLog);
  assert.ok(v.ok, JSON.stringify(v.problems)); assert.equal(v.head, c.auditHead); assert.ok(v.actions.click! >= 2 && v.actions.checkpoint === 1 && v.actions.close === 1);
  const lines = readFileSync(c.auditLog, 'utf8').split('\n');
  lines[2] = lines[2]!.replace('"ok":true', '"ok":false');
  const bad = join(mkdtempSync(join(tmpdir(), 'rl-audit-')), 'audit.jsonl'); writeFileSync(bad, lines.join('\n'));
  const v2 = await verifyAuditLog(bad);
  assert.equal(v2.ok, false); assert.equal(v2.problems[0]!.line, 3);
  await assert.rejects(actOnComputer(c.auditHead, { action: 'cursor' }), InputError);
});

// ---------------- process capture ----------------

test('process capture of a real program finds the file, connection and child it reports, plus its syscalls', { timeout: 60_000 }, async (t) => {
  const r = await captureProcess({ allowExecution: true, command: [process.execPath, join(S, 'capture-target.mjs')], durationMs: 10_000 });
  const c = r.capture;
  const truth = JSON.parse(c.stdout!.excerpt.trim().split('\n')[0]!);
  assert.equal(c.exit?.code, 7);
  if (process.platform === 'win32') { assert.ok(c.processes.some((p) => p.pid === truth.child)); return; }
  assert.ok(c.files.some((f) => f.path === truth.marker), 'marker file seen open');
  assert.ok(c.sockets.some((s) => s.key.includes(`:${truth.port}`) && s.key.includes(`:${truth.clientPort}`)), JSON.stringify(c.sockets.map((s) => s.key)));
  assert.ok(c.processes.some((p) => p.pid === truth.child && (p.cmdline ?? []).includes('-e')));
  if (!c.syscalls) { t.diagnostic(`no strace: ${c.warnings.join('; ')}`); return; }
  assert.ok(c.syscalls.files.some((f) => f.path === truth.marker && f.ops.some((o) => o.startsWith('openat'))));
  assert.ok(c.syscalls.network.some((n) => n.op === 'connect' && n.port === truth.port));
  assert.ok(c.syscalls.execs.some((e) => e.argv.includes('setTimeout(()=>{}, 1500)')));
  assert.ok(c.syscalls.processes.some((p) => p.pid === truth.child));
  // a second run with a different hold time: same shape, new ports
  const r2 = await captureProcess({ allowExecution: true, command: [process.execPath, join(S, 'capture-target.mjs'), '600'], durationMs: 10_000, strace: false });
  const d = await compareCaptureFiles(r.path, r2.path) as { modules: { same: number }; exit: { same: boolean }; syscalls?: unknown; similarity: number };
  assert.equal(d.exit.same, true); assert.ok(d.modules.same > 3); assert.equal(d.syscalls, undefined);
});

test('process capture attaches to a running pid for a bounded time', { timeout: 30_000 }, async (t) => {
  if (process.platform === 'win32') { t.skip('pid attach sampling is covered by the Windows platform test'); return; }
  const child = spawn(process.execPath, [join(S, 'proc-target.mjs'), '20000'], { stdio: ['pipe', 'pipe', 'ignore'] });
  try {
    const info = await new Promise<{ fileA: string; tcpPort: number }>((res) => child.stdout!.once('data', (d) => res(JSON.parse(String(d)))));
    const r = await captureProcess({ allowExecution: true, pid: child.pid, durationMs: 1500 });
    assert.ok(r.capture.files.some((f) => f.path === info.fileA));
    assert.ok(r.capture.sockets.some((s) => s.key.includes(`:${info.tcpPort} LISTEN`)));
    assert.equal(r.capture.exit, undefined);
  } finally { child.kill(); }
});

// ---------------- gates ----------------

test('consent and execution gates', async () => {
  await assert.rejects(startComputer({ allowExecution: true }), /consent: true/);
  await assert.rejects(startComputer({ consent: true, allowExecution: false } as never), /allowExecution/);
  await assert.rejects(startComputer({ consent: true, allowExecution: true, mode: 'attach' }), /attachCurrentDisplay/);
  if (process.platform !== 'linux') await assert.rejects(startComputer({ consent: true, allowExecution: true, mode: 'isolated' }), /need Linux/);
  const prev = process.env.REVLENS_ALLOW_EXECUTION; delete process.env.REVLENS_ALLOW_EXECUTION;
  try {
    await assert.rejects(traceUi({ durationMs: 100 }), /allowExecution/);
    await assert.rejects(runUiScenario({ steps: [{ wait: 1 }] }), /allowExecution/);
    await assert.rejects(captureProcess({ command: ['true'] }), /allowExecution/);
  } finally { if (prev !== undefined) process.env.REVLENS_ALLOW_EXECUTION = prev; }
  await assert.rejects(captureProcess({ allowExecution: true }), /exactly one/);
  await assert.rejects(runUiScenario({ allowExecution: true, steps: [{ find: { role: 'x' }, wait: 3 }] }), /exactly one/);
  await assert.rejects(actOnComputer('computer-nope', { action: 'cursor' }), /no open computer session/);
});

// ---------------- small pure pieces ----------------

test('key combos, selectors, roles, states and redaction', () => {
  assert.equal(toXdotool(parseKeyCombo('ctrl+shift+a')), 'ctrl+shift+a');
  assert.equal(toXdotool(parseKeyCombo('Enter')), 'Return');
  assert.equal(toXdotool(parseKeyCombo('cmd+PageDown')), 'super+Next');
  assert.equal(toXdotool(parseKeyCombo('ctrl++')), 'ctrl+plus');
  assert.deepEqual(toYdotool(parseKeyCombo('ctrl+c')), ['29:1', '46:1', '46:0', '29:0']);
  assert.equal(winVk('f5'), 0x74); assert.equal(winVk('a'), 0x41);
  assert.throws(() => parseKeyCombo('foo+a'), InputError);
  assert.equal(normalizeRole('push button'), 'button'); assert.equal(normalizeRole('AXButton'), 'button'); assert.equal(normalizeRole('ControlType.Edit'), 'entry'); assert.equal(normalizeRole('check box'), 'checkbox');
  assert.deepEqual(decodeAtspiStates([(1 << 4) | (1 << 8) | (1 << 30), 1 << 9]), ['checked', 'enabled', 'visible', 'checkable']);
  const nodes = [{ id: 0, parent: null, depth: 0, role: 'frame', name: 'W' }, { id: 1, parent: 0, depth: 1, role: 'push button', name: 'OK', states: ['enabled'] }, { id: 2, parent: 0, depth: 1, role: 'push button', name: 'OK', states: [] }];
  assert.equal(findNode(nodes, { role: 'button', name: 'OK', states: ['enabled'] })!.id, 1);
  assert.equal(findNode(nodes, { role: 'button', name: 'OK', index: 1 })!.id, 2);
  assert.throws(() => checkSelector({ index: 2 }), InputError);
  const d = compareUiTrees({ nodes }, { nodes: [nodes[0]!, { ...nodes[1]!, states: [] }, { id: 3, parent: 0, depth: 1, role: 'label', name: 'New' }] });
  assert.equal(d.removed.length, 1); assert.equal(d.added[0]!.name, 'New'); assert.deepEqual(d.changed[0]!.changes, [{ field: 'states', before: ['enabled'], after: [] }]);
  const masked: string[] = [];
  assert.deepEqual(redactValue({ a: 1, Password: 'x', nested: { api_key: 'k', ok: 'v' } }, '', masked), { a: 1, Password: '[redacted]', nested: { api_key: '[redacted]', ok: 'v' } });
  assert.deepEqual(masked, ['/Password', '/nested/api_key']);
  assert.equal(redactLines('user=a\nTOKEN = abc\nexport API_KEY="z"'), 'user=a\nTOKEN = [redacted]\nexport API_KEY=[redacted]');
  assert.ok(isSecretFile('/x/Default/Login Data') && isSecretFile('/x/id_ed25519') && !isSecretFile('/x/settings.json'));
  const kf = parseKeyFile('top=1\n[A]\nk = v\n');
  assert.deepEqual(JSON.parse(JSON.stringify(kf.groups)), { '': { top: '1' }, A: { k: 'v' } });
  const zip = writeZip([{ name: 'a.txt', data: new TextEncoder().encode('hello '.repeat(50)) }, { name: 'b/c.bin', data: new Uint8Array([1, 2, 3]) }], (b) => new Uint8Array(deflateRawSync(b)));
  const list = listZip(zip);
  assert.deepEqual(list.map((e) => [e.name, e.method]), [['a.txt', 8], ['b/c.bin', 0]]);
  assert.equal(new TextDecoder().decode(readZipEntry(zip, list[0]!, (b, max) => new Uint8Array(inflateRawSync(b, { maxOutputLength: max })))), 'hello '.repeat(50));
  assert.throws(() => writeZip([{ name: '../x', data: new Uint8Array(1) }]), InputError);
});

test('TOOLS and CLI commands for round 3', () => {
  const names = TOOLS.map((x) => x.name);
  for (const n of ['desktop_computer_start', 'desktop_computer_act', 'desktop_computer_checkpoint', 'desktop_computer_close', 'desktop_computer_list', 'desktop_audit_verify', 'desktop_ui_trace', 'desktop_ui_scenario', 'desktop_ui_compare', 'desktop_process_capture', 'desktop_capture_compare', 'desktop_app_state', 'desktop_app_export', 'desktop_task_check', 'desktop_task_validate', 'desktop_task_score', 'desktop_strace_parse', 'desktop_leveldb_log', 'desktop_screenshot_info']) assert.ok(names.includes(n), n);
  assert.equal(new Set(names).size, names.length);
  for (const x of TOOLS) { assert.match(x.name, /^desktop_[a-z_]+$/); for (const [k, v] of Object.entries(x.inputSchema)) assert.ok(v.description, `${x.name}.${k}`); }
  for (const n of ['ui-compare', 'ui-trace', 'ui-scenario', 'proc-capture', 'capture-compare', 'app-state', 'app-export', 'task-check', 'audit-verify', 'computer-run']) assert.ok(CLI_COMMANDS.some((c) => c.name === n), n);
  const runner = join(HERE, 'cli-runner.ts');
  const r = spawnSync(process.execPath, ['--import', 'tsx', runner, 'task-check', join(R3, 'task.json'), '--home', join(R3, 'task-home')], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^fixture-checks: FAIL \(16 passed, 1 failed\)/);
  assert.match(r.stdout, /fail wrong-theme value_equals/);
  const s = spawnSync(process.execPath, ['--import', 'tsx', runner, 'proc-capture', '--allow-execution', '--duration', '3000', '--no-strace', '--', process.execPath, '-e', 'console.log(42)'], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(s.status, 0, s.stderr); assert.match(s.stdout, /exit \{"code":0,"signal":null\}/);
});

test('hostile inputs: D-Bus messages, strace text, LevelDB logs, XML, XWD, zips, pointers and trees never hang or crash', () => {
  const opts = { numRuns: 300, interruptAfterTimeLimit: 20_000 };
  const ok = (f: () => unknown) => { try { f(); } catch (e) { if (!(e instanceof InputError) && !(e instanceof RangeError)) throw e; } };
  const good = encodeMessage({ type: MSG.signal, flags: 0, serial: 1, path: '/a', interface: 'a.b', member: 'C', signature: 'siiva{sv}', body: ['x', 1, 2, new Variant('s', 'y'), {}] });
  fc.assert(fc.property(fc.uint8Array({ maxLength: 4096 }), (b) => { ok(() => decodeMessage(b)); ok(() => readLevelLog(b)); ok(() => decodeXwd(b)); ok(() => listZip(b)); ok(() => pngInfo(b)); ok(() => viewOf('x.bin', b)); }), opts);
  fc.assert(fc.property(fc.integer({ min: 0, max: good.length - 1 }), fc.integer({ min: 0, max: 255 }), (i, v) => { const b = good.slice(); b[i] = v; ok(() => decodeMessage(b)); ok(() => decodeMessage(b.subarray(0, i))); }), opts);
  fc.assert(fc.property(fc.string({ maxLength: 3000 }), (s) => { ok(() => parseStrace(s)); ok(() => parseXml(s)); ok(() => parseKeyFile(s)); ok(() => resolvePointer({ a: [{ name: 'x' }] }, '/' + s)); ok(() => parseKeyCombo(s)); ok(() => redactLines(s)); ok(() => isSecretFile(s)); }), opts);
  const t0 = Date.now();
  parseStrace('1 openat(' + '"'.repeat(200_000) + '\n' + '('.repeat(100_000) + ') = 0\n');
  parseXml('<a>' + '<b x="1">'.repeat(200) + '</b>'.repeat(200) + '</a>');
  assert.throws(() => parseXml('<a>'.repeat(1000)), InputError);
  redactLines(('a'.repeat(119) + ' ').repeat(80) + '=x');
  assert.ok(Date.now() - t0 < 5000);
  // huge counts
  const lv = new Uint8Array(7 + 12); lv.set([0, 0, 0, 0, 12, 0, 1]); new DataView(lv.buffer).setUint32(7 + 8, 0xffffffff, true);
  assert.equal(readLevelLog(lv).records.length, 0);
  assert.throws(() => decodeMessage(new Uint8Array([0x6c, 1, 0, 1, 0xff, 0xff, 0xff, 0x7f, 1, 0, 0, 0, 0, 0, 0, 0])), InputError);
  const bigTree = { nodes: Array.from({ length: 3000 }, (_, i) => ({ id: i, parent: i ? i - 1 : null, depth: i, role: 'panel', name: '' })) };
  assert.equal(compareUiTrees(bigTree, bigTree).similarity, 1);
  assert.ok(Date.now() - t0 < 15_000);
  void runTask; void statSync; void createServer; void compareCaptures;
});
