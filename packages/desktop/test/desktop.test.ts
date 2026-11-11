import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync, mkdtempSync, writeFileSync, realpathSync } from 'node:fs';
import { spawn, spawnSync, execFileSync, type ChildProcess } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, basename, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { parsePlist, parseDesktopFile, desktopEntryToApp, splitExec, parseRegQuery, uninstallKeysToApps, parseGVariant, parseAccessibleRefs, parseLsofF, parseProcNet, parseProcMaps, compareSnapshots, ANALYZERS, TOOLS as WEB_TOOLS, InputError } from '../src/index.js';
import { listProcesses, snapshotProcess, compareProcessSnapshots, listApps, inspectApp, captureUiTree, TOOLS, CLI_COMMANDS } from '../src/node.js';

const S = join(dirname(fileURLToPath(import.meta.url)), '../../../samples/desktop');
const linux = process.platform === 'linux';
const toolsDir = process.env.REVLENS_DESKTOP_TOOLS;
if (toolsDir) {
  process.env.PATH = `${join(toolsDir, 'usr/bin')}:${process.env.PATH}`;
  process.env.LD_LIBRARY_PATH = [join(toolsDir, 'usr/lib/aarch64-linux-gnu'), join(toolsDir, 'usr/lib/x86_64-linux-gnu'), process.env.LD_LIBRARY_PATH].filter(Boolean).join(':');
}
const has = (cmd: string) => spawnSync(cmd, ['-v'], { stdio: 'ignore' }).error === undefined;

test('XML and binary plists decode to the same values as Python plistlib', () => {
  const ref = JSON.parse(readFileSync(join(S, 'plist-reference.json'), 'utf8'));
  assert.deepEqual(JSON.parse(JSON.stringify(parsePlist(readFileSync(join(S, 'Info.xml.plist'))))), ref);
  assert.deepEqual(JSON.parse(JSON.stringify(parsePlist(readFileSync(join(S, 'Info.binary.plist'))))), ref);
});

test('Info.plist app record and plist analyzer findings', async () => {
  const app = await inspectApp(join(S, 'Info.binary.plist'));
  assert.equal(app.id, 'dev.revlens.SampleApp'); assert.equal(app.name, 'Sample Ä App'); assert.equal(app.version, '2.4.1');
  assert.equal(app.extra!.urlSchemes, 'revlens-sample,rls'); assert.equal(app.extra!.ElectronAsarIntegrity, '[present]');
  const report: any = { findings: [], meta: {} };
  const bytes = new Uint8Array(readFileSync(join(S, 'Info.binary.plist')));
  const ctx: any = { bytes, name: 'Sample.app/Contents/Info.plist', format: 'unknown', report, options: {}, depth: 0 };
  const a = ANALYZERS.find((x) => x.id === 'desktop-plist')!;
  assert.ok(a.applies(ctx)); await a.run(ctx);
  assert.equal(report.meta.desktop.app.id, 'dev.revlens.SampleApp');
  assert.deepEqual(report.findings.map((f: any) => f.id), ['plist-ats-arbitrary-loads']);
});

test('.desktop parsing follows the spec quoting rules', () => {
  const e = parseDesktopFile(readFileSync(join(S, 'tricky.desktop'), 'utf8'));
  const app = desktopEntryToApp(e, '/usr/share/applications/tricky.desktop')!;
  assert.deepEqual(splitExec(app.exec!), ['env', 'GDK_BACKEND=x11', '/opt/Tricky Viewer/tricky-viewer', '--open', 'file "one".txt']);
  assert.equal(app.executable, '/opt/Tricky Viewer/tricky-viewer');
  assert.deepEqual(app.categories, ['Office', 'Viewer']);
  assert.deepEqual(app.mimeTypes, ['application/pdf', 'image/x;weird']);
  assert.equal(e.groups['Desktop Entry']!['Name[de]'], 'Kniffliger Betrachter');
  assert.equal(e.groups['Desktop Entry']!.Comment, 'Opens; files with a semicolon');
  assert.equal(e.groups['Desktop Action new-window']!.Name, 'New Window');
  assert.equal(app.extra!.StartupWMClass, 'TrickyViewer');
});

test('desktop entry analyzer flags a download-and-run autostart entry', async () => {
  const bytes = new Uint8Array(readFileSync(join(S, 'autostart-dropper.desktop')));
  const report: any = { findings: [], meta: {} };
  const ctx: any = { bytes, name: '/home/u/.config/autostart/autostart-dropper.desktop', format: 'text', report, options: {}, depth: 0 };
  const a = ANALYZERS.find((x) => x.id === 'desktop-entry')!;
  assert.ok(a.applies(ctx)); await a.run(ctx);
  assert.deepEqual(report.findings.map((f: any) => f.id).sort(), ['desktop-autostart', 'desktop-exec-download', 'desktop-exec-shell']);
});

test('real system .desktop files agree with Python configparser', (t) => {
  const dir = '/usr/share/applications';
  if (!existsSync(dir)) { t.skip('no /usr/share/applications'); return; }
  const files = readdirSync(dir).filter((f) => f.endsWith('.desktop')).slice(0, 50);
  if (!files.length) { t.skip('no desktop files'); return; }
  let ref: Record<string, { Name?: string; Exec?: string; Type?: string }>;
  try {
    ref = JSON.parse(execFileSync('python3', ['-c', 'import sys,json,configparser\nout={}\nfor f in sys.argv[1:]:\n  c=configparser.RawConfigParser(strict=False,interpolation=None);c.optionxform=str\n  c.read(f,encoding="utf-8")\n  g=c["Desktop Entry"] if c.has_section("Desktop Entry") else {}\n  out[f]={k:g.get(k) for k in ("Name","Exec","Type")}\nprint(json.dumps(out))', ...files.map((f) => join(dir, f))], { encoding: 'utf8' }));
  } catch { t.skip('python3 not available'); return; }
  for (const f of files) {
    const e = parseDesktopFile(readFileSync(join(dir, f), 'utf8')).groups['Desktop Entry'] ?? {};
    for (const k of ['Name', 'Exec', 'Type'] as const) assert.equal(e[k] ?? null, ref[join(dir, f)]![k] ?? null, `${f} ${k}`);
  }
});

test('listApps scans a folder and inspectApp resolves executables on PATH', async () => {
  const r = await listApps({ dirs: [S], includeHidden: true });
  assert.deepEqual(r.apps.map((a) => a.name), ['Tricky Viewer', 'Updater']);
  const dir = mkdtempSync(join(tmpdir(), 'rl-apps-'));
  writeFileSync(join(dir, 'node.desktop'), `[Desktop Entry]\nType=Application\nName=Node REPL\nExec=${basename(process.execPath)} %F\n`);
  const prev = process.env.PATH; process.env.PATH = `${dirname(process.execPath)}${delimiter}${prev}`;
  const norm = (p?: string) => (p && process.platform === 'win32' ? realpathSync(p).toLowerCase() : p && realpathSync(p));
  try { const a = await inspectApp(join(dir, 'node.desktop')); assert.equal(norm(a.resolvedExecutable), norm(process.execPath)); assert.equal(a.electron, false); }
  finally { process.env.PATH = prev; }
});

test('reg query uninstall output becomes app records', () => {
  const keys = parseRegQuery(readFileSync(join(S, 'reg-uninstall.txt'), 'utf8'));
  assert.equal(keys.length, 5);
  const apps = uninstallKeysToApps(keys);
  assert.deepEqual(apps.map((a) => a.name), ['7-Zip 24.08 (x64)', 'Microsoft Visual C++ 2022 X64 Runtime', 'Microsoft Visual Studio Code']);
  assert.equal(apps[0]!.executable, 'C:\\Program Files\\7-Zip\\7zFM.exe');
  assert.equal(apps[0]!.extra!.EstimatedSizeKb, '5760');
  assert.equal(apps[1]!.packaging, 'msi');
  assert.equal(apps[2]!.executable, 'C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe');
  assert.equal(apps[2]!.version, '1.96.2');
});

test('GVariant text from gdbus parses, including typed and nested values', () => {
  assert.deepEqual(parseAccessibleRefs("([(':1.3', objectpath '/org/a11y/atspi/accessible/root'), (':1.3', objectpath '/org/a11y/atspi/accessible/12')],)"), [{ bus: ':1.3', path: '/org/a11y/atspi/accessible/root' }, { bus: ':1.3', path: '/org/a11y/atspi/accessible/12' }]);
  assert.deepEqual(parseGVariant("(@a(so) [],)"), [[]]);
  assert.deepEqual(parseGVariant("(<'it\\'s'>, uint32 7, {'a': <int32 -3>}, true, \"q'd\")"), ["it's", 7, { a: -3 }, true, "q'd"]);
  assert.throws(() => parseGVariant('('.repeat(500)), InputError);
});

// ---------------- live process tests (Linux /proc, cross-checked with ps, ldd and lsof) ----------------

let child: ChildProcess | undefined;
let info: { pid: number; fileA: string; fdA: number; tcpPort: number; udpPort: number; unixPath: string; dir: string } | undefined;
const lineReader = (c: ChildProcess) => { let buf = ''; const waiters: ((l: string) => void)[] = []; c.stdout!.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); waiters.shift()?.(l); } }); return () => new Promise<string>((r, j) => { const t = setTimeout(() => j(new Error('no output')), 15_000); waiters.push((l) => { clearTimeout(t); r(l); }); }); };
let nextLine: () => Promise<string>;
const live = linux || process.platform === 'darwin' || process.platform === 'win32';
before(async () => {
  if (!live) return;
  child = spawn(process.execPath, [join(S, 'proc-target.mjs'), '120000'], { stdio: ['pipe', 'pipe', 'inherit'] });
  nextLine = lineReader(child);
  info = JSON.parse(await nextLine());
});
after(() => child?.kill());

test('process tools refuse to touch other processes without allowExecution', async () => {
  const prev = process.env.REVLENS_ALLOW_EXECUTION; delete process.env.REVLENS_ALLOW_EXECUTION;
  try {
    await assert.rejects(listProcesses(), /allowExecution/);
    await assert.rejects(snapshotProcess(1), /allowExecution/);
    await assert.rejects(captureUiTree(), /allowExecution/);
    await assert.rejects(snapshotProcess(-5, { allowExecution: true }), /bad pid/);
  } finally { if (prev !== undefined) process.env.REVLENS_ALLOW_EXECUTION = prev; }
});

test('process list matches ps for the target process', async (t) => {
  if (!linux || !info) { t.skip('Linux only'); return; }
  const r = await listProcesses({ allowExecution: true, filter: 'proc-target.mjs' });
  const p = r.processes.find((x) => x.pid === info!.pid)!;
  assert.ok(p, 'target listed');
  if (has('ps')) {
    const [ppid, comm] = execFileSync('ps', ['-o', 'ppid=,comm=', '-p', String(info.pid)], { encoding: 'utf8' }).trim().split(/\s+/);
    assert.equal(p.ppid, Number(ppid)); assert.equal(p.name, comm);
  }
  assert.equal(p.ppid, process.pid);
  assert.deepEqual(p.cmdline, [process.execPath, join(S, 'proc-target.mjs'), '120000']);
});

test('process snapshot finds the open file, TCP, UDP and Unix sockets and the libraries ldd lists', async (t) => {
  if (!linux || !info) { t.skip('Linux only'); return; }
  const s = await snapshotProcess(info.pid, { allowExecution: true });
  assert.equal(s.process.exe, realpathSync(process.execPath));
  assert.ok(s.files.some((f) => f.fd === String(info!.fdA) && f.path === info!.fileA), JSON.stringify(s.files));
  assert.ok(s.sockets.some((x) => x.proto === 'tcp' && x.localPort === info!.tcpPort && x.state === 'LISTEN' && x.local === '127.0.0.1'), JSON.stringify(s.sockets));
  assert.ok(s.sockets.some((x) => x.proto === 'udp' && x.localPort === info!.udpPort && x.local === '127.0.0.1'));
  assert.ok(s.sockets.some((x) => x.proto === 'unix' && x.path === info!.unixPath && x.state === 'LISTEN'));
  // every library ldd resolves for the node binary is mapped
  if (has('ldd')) {
    const ldd = execFileSync('ldd', [process.execPath], { encoding: 'utf8' });
    const libs = [...ldd.matchAll(/=>\s+(\/\S+)/g)].map((m) => m[1]!);
    const mods = new Set(s.modules.map((m) => m.path));
    for (const l of libs) assert.ok(mods.has(l) || mods.has(realpathSync(l)), `module ${l} missing`);
  }
  assert.equal(s.modules.find((m) => m.kind === 'executable')?.path, s.process.exe);
});

test('lsof -F agrees with the /proc snapshot on libraries, files and sockets', async (t) => {
  if (!linux || !info || !has('lsof')) { t.skip('needs Linux and lsof'); return; }
  const s = await snapshotProcess(info.pid, { allowExecution: true });
  const out = execFileSync('lsof', ['-nP', '-w', '-p', String(info.pid), '-F', 'pcuftnPT'], { encoding: 'utf8' });
  const l = parseLsofF(out)[0]!;
  assert.equal(l.pid, info.pid);
  const procLibs = s.modules.filter((m) => m.kind === 'library').map((m) => m.path).sort();
  const lsofLibs = l.modules.filter((m) => m.kind === 'library').map((m) => m.path).sort();
  assert.deepEqual(lsofLibs, procLibs);
  assert.equal(l.modules.find((m) => m.kind === 'executable')?.path, s.process.exe);
  assert.ok(l.files.some((f) => f.fd === String(info!.fdA) && f.path === info!.fileA));
  const tcp = l.sockets.find((x) => x.proto === 'tcp' && x.localPort === info!.tcpPort)!;
  assert.equal(tcp.state, 'LISTEN'); assert.equal(tcp.local, '127.0.0.1');
  assert.ok(l.sockets.some((x) => x.proto === 'udp' && x.localPort === info!.udpPort));
});

test('snapshot comparison shows the file and connection opened between two snapshots', async (t) => {
  if (!linux || !info || !child) { t.skip('Linux only'); return; }
  const dir = mkdtempSync(join(tmpdir(), 'rl-snap-'));
  const tool = TOOLS.find((x) => x.name === 'desktop_process_inspect')!;
  await tool.run({ pid: info.pid, allowExecution: true, saveTo: join(dir, 'a.json') });
  child.stdin!.write('more\n');
  const more = JSON.parse(await nextLine());
  await tool.run({ pid: info.pid, allowExecution: true, saveTo: join(dir, 'b.json') });
  const d = await compareProcessSnapshots(join(dir, 'a.json'), join(dir, 'b.json'));
  assert.ok(d.pidSame);
  assert.deepEqual(d.files.added, [`file ${more.fileB}`]);
  assert.ok(d.sockets.added.includes(`tcp 127.0.0.1:${more.clientPort} -> 127.0.0.1:${info.tcpPort} ESTABLISHED`), JSON.stringify(d.sockets));
  assert.ok(d.sockets.added.some((x) => x.startsWith(`tcp 127.0.0.1:${info!.tcpPort} -> 127.0.0.1:${more.clientPort}`)), 'server side of the connection');
  assert.deepEqual(d.modules, { added: [], removed: [], same: d.modules.same });
  assert.ok(d.similarity > 0.5 && d.similarity < 1);
  // the CLI prints the same diff
  const runner = join(dirname(fileURLToPath(import.meta.url)), 'cli-runner.ts');
  const r = spawnSync(process.execPath, ['--import', 'tsx', runner, 'proc-compare', join(dir, 'a.json'), join(dir, 'b.json')], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes(`+ file ${more.fileB}`));
});

// ---------------- live process tests on macOS (ps, lsof, vmmap) and Windows (PowerShell, CIM, reg) ----------------

const mac = process.platform === 'darwin';
const win = process.platform === 'win32';
const real = (p: string) => { const r = realpathSync(p); return win ? r.toLowerCase() : r; };

test('macOS and Windows: process list finds the target with its parent', async (t) => {
  if ((!mac && !win) || !info) { t.skip('macOS and Windows only (Linux has its own tests)'); return; }
  const r = await listProcesses({ allowExecution: true, limit: 100_000 });
  assert.ok(r.total > 5, `only ${r.total} processes`);
  const p = r.processes.find((x) => x.pid === info!.pid);
  assert.ok(p, `target pid ${info.pid} not listed`);
  assert.equal(p!.ppid, process.pid);
  assert.match(p!.name, /^node(\.exe)?$/i);
  if (win) {
    assert.ok((p!.cmdline ?? []).join(' ').includes('proc-target.mjs'), JSON.stringify(p));
    const byCmd = await listProcesses({ allowExecution: true, filter: 'proc-target.mjs' });
    assert.ok(byCmd.processes.some((x) => x.pid === info!.pid));
  }
  if (mac) {
    // ps itself agrees on the parent and the command
    const [ppid, comm] = execFileSync('ps', ['-o', 'ppid=,comm=', '-p', String(info.pid)], { encoding: 'utf8' }).trim().split(/\s+/);
    assert.equal(p!.ppid, Number(ppid));
    assert.equal(p!.name, comm!.split('/').pop());
  }
});

test('macOS and Windows: process snapshot has the executable, libraries and the TCP and UDP sockets', async (t) => {
  if ((!mac && !win) || !info) { t.skip('macOS and Windows only'); return; }
  const s = await snapshotProcess(info.pid, { allowExecution: true });
  assert.equal(s.process.pid, info.pid);
  assert.equal(s.process.ppid, process.pid);
  const exe = s.modules.find((m) => m.kind === 'executable');
  assert.ok(exe, `no executable module: ${JSON.stringify(s.modules.slice(0, 5))} ${JSON.stringify(s.warnings)}`);
  assert.equal(real(exe!.path), real(process.execPath));
  assert.ok(s.modules.some((m) => m.kind === 'library'), 'at least one library');
  if (win) {
    assert.equal(real(s.process.exe!), real(process.execPath));
    assert.ok(s.modules.some((m) => /\\ntdll\.dll$/i.test(m.path) && m.base?.startsWith('0x')), 'ntdll.dll with a base address');
  }
  if (mac) {
    assert.ok(s.modules.some((m) => /\/usr\/lib\/(dyld|libSystem\.B\.dylib)$/.test(m.path)), `dyld or libSystem: ${JSON.stringify(s.modules.map((m) => m.path).slice(0, 40))}`);
    assert.ok(s.files.some((f) => f.fd === String(info!.fdA) && real(f.path) === real(info!.fileA)), JSON.stringify(s.files));
    assert.ok(s.sockets.some((x) => x.proto === 'unix'), 'unix socket listed');
  }
  assert.ok(s.sockets.some((x) => x.proto === 'tcp' && x.localPort === info!.tcpPort && x.state === 'LISTEN' && x.local === '127.0.0.1'), JSON.stringify(s.sockets));
  assert.ok(s.sockets.some((x) => x.proto === 'udp' && x.localPort === info!.udpPort && x.local === '127.0.0.1'), JSON.stringify(s.sockets));
  const me = await snapshotProcess(process.pid, { modules: false, files: false, sockets: false });
  assert.ok(me.children?.includes(info.pid), `children of this process ${JSON.stringify(me.children)}`);
});

test('macOS and Windows: comparing two snapshots shows the new connection', async (t) => {
  if ((!mac && !win) || !info || !child) { t.skip('macOS and Windows only'); return; }
  const dir = mkdtempSync(join(tmpdir(), 'rl-snap-'));
  const tool = TOOLS.find((x) => x.name === 'desktop_process_inspect')!;
  await tool.run({ pid: info.pid, allowExecution: true, saveTo: join(dir, 'a.json') });
  child.stdin!.write('more\n');
  const more = JSON.parse(await nextLine());
  await tool.run({ pid: info.pid, allowExecution: true, saveTo: join(dir, 'b.json') });
  const d = await compareProcessSnapshots(join(dir, 'a.json'), join(dir, 'b.json'));
  assert.ok(d.pidSame);
  assert.ok(d.sockets.added.some((x) => x.includes(`:${more.clientPort}`) && x.includes(`:${info!.tcpPort}`) && /ESTABLISHED/.test(x)), JSON.stringify(d.sockets.added));
  if (mac) assert.ok(d.files.added.some((x) => x.endsWith('held-b.txt')), JSON.stringify(d.files.added));
});

test('macOS and Windows: installed apps are discovered from the system', async (t) => {
  if (!mac && !win) { t.skip('macOS and Windows only'); return; }
  const r = await listApps({ limit: 5000 });
  assert.ok(r.total > 0, `no apps found: ${JSON.stringify(r.warnings.slice(0, 5))}`);
  if (mac) {
    const safari = r.apps.find((a) => a.id === 'com.apple.Safari');
    assert.ok(safari, `Safari not found in ${r.dirs.join(', ')}`);
    assert.ok(safari!.version && /^\d+/.test(safari!.version));
  }
  if (win) assert.ok(r.apps.every((a) => a.name.length > 0));
});

test('/proc/net parsers decode IPv4 and IPv6 addresses', () => {
  const v4 = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n';
  assert.deepEqual(parseProcNet(v4, 'tcp')[0], { proto: 'tcp', local: '127.0.0.1', localPort: 8080, remote: '0.0.0.0', remotePort: 0, state: 'LISTEN', inode: 12345 });
  const v6 = '  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1\n';
  assert.equal(parseProcNet(v6, 'tcp6')[0]!.local, '::1');
  const maps = '55d0c0a00000-55d0c0a01000 r--p 00000000 08:01 131 /usr/bin/x\n55d0c0a01000-55d0c0a05000 r-xp 00001000 08:01 131 /usr/bin/x\n7f00-7f10 r-xp 00000000 08:01 77 /lib/libc.so.6\n7ffd0000-7ffd1000 rw-p 00000000 00:00 0 [stack]\n';
  assert.deepEqual(parseProcMaps(maps, '/usr/bin/x'), [{ path: '/usr/bin/x', base: '0x55d0c0a00000', size: 0x5000, kind: 'executable' }, { path: '/lib/libc.so.6', base: '0x7f00', size: 0x10, kind: 'library' }]);
});

// ---------------- AT-SPI against a real accessibility bus and Chromium ----------------

test('AT-SPI UI tree of a real Chromium window through gdbus', { timeout: 100_000 }, async (t) => {
  if (!linux || !has('gdbus')) { t.skip('needs Linux and gdbus'); return; }
  const daemon = ['dbus-daemon'].find(has);
  const registryd = [toolsDir && join(toolsDir, 'usr/libexec/at-spi2-registryd'), '/usr/libexec/at-spi2-registryd', '/usr/lib/at-spi2-core/at-spi2-registryd'].find((p): p is string => !!p && existsSync(p));
  let chrome = process.env.REVLENS_CHROMIUM;
  if (!chrome) { try { chrome = (await import('playwright' as string)).chromium.executablePath(); } catch { /* none */ } }
  if (!daemon || !registryd || !chrome || !existsSync(chrome)) { t.skip('needs dbus-daemon, at-spi2-registryd and Chromium'); return; }
  const dir = mkdtempSync(join(tmpdir(), 'rl-a11y-'));
  writeFileSync(join(dir, 'bus.conf'), `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd"><busconfig><type>session</type><listen>unix:path=${dir}/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>`);
  const procs: ChildProcess[] = [];
  try {
    const bus = spawn('dbus-daemon', [`--config-file=${dir}/bus.conf`, '--nofork', '--print-address'], { stdio: ['ignore', 'pipe', 'ignore'] });
    procs.push(bus);
    const address = (await lineReader(bus)()).trim();
    const env = { ...process.env, AT_SPI_BUS_ADDRESS: address, DBUS_SESSION_BUS_ADDRESS: address, ACCESSIBILITY_ENABLED: '1' };
    const reg = spawn(registryd, ['--use-gnome-session'], { env, stdio: ['ignore', 'ignore', 'pipe'] }); procs.push(reg); reg.stderr!.on('data', (d) => { if (process.env.RL_DEBUG) console.error('registryd:', String(d)); }); reg.on('exit', (c) => { if (process.env.RL_DEBUG) console.error('registryd exit', c); });
    await new Promise((r) => setTimeout(r, 800));
    const page = 'data:text/html,<title>RevLens a11y</title><h1>Fixture heading</h1><button>Press me</button><input aria-label="Search box">';
    procs.push(spawn(chrome, ['--no-sandbox', '--ozone-platform=headless', '--force-renderer-accessibility', '--disable-gpu', `--user-data-dir=${dir}/ud`, '--no-first-run', page], { env, stdio: 'ignore' }));
    let tree: Awaited<ReturnType<typeof captureUiTree>> | undefined;
    const t0 = Date.now();
    while (Date.now() - t0 < 60_000) {
      await new Promise((r) => setTimeout(r, 1000));
      try { tree = await captureUiTree({ allowExecution: true, busAddress: address, maxNodes: 500, maxDepth: 30 }); } catch (e) { if (process.env.RL_DEBUG) console.error(String(e)); continue; }
      if (tree.nodes.some((n) => /^(push )?button$/.test(n.role) && n.name === 'Press me')) break;
    }
    assert.equal(tree!.backend, 'at-spi');
    const app = tree!.nodes[0]!;
    assert.equal(app.role, 'application'); assert.match(app.name, /chrom/i);
    assert.ok(tree!.nodes.some((n) => /^(push )?button$/.test(n.role) && n.name === 'Press me'), JSON.stringify(tree!.nodes.map((n) => [n.role, n.name])));
    assert.ok(tree!.nodes.some((n) => n.role === 'heading' && n.name === 'Fixture heading'));
    assert.ok(tree!.nodes.some((n) => n.role === 'entry' && n.name === 'Search box'));
    for (const n of tree!.nodes.slice(1)) assert.ok(n.parent !== null && n.parent < n.id);
    // filtering by pid through the bus daemon
    const byPid = await captureUiTree({ allowExecution: true, busAddress: address, pid: procs[2]!.pid, maxNodes: 5 });
    assert.equal(byPid.nodes[0]?.role, 'application');
    const none = await captureUiTree({ allowExecution: true, busAddress: address, app: 'no-such-app' });
    assert.equal(none.nodes.length, 0);
  } finally { for (const p of procs.reverse()) p.kill(); }
});

// ---------------- tools, CLI, hostile input ----------------

test('TOOLS and CLI_COMMANDS', () => {
  assert.deepEqual(TOOLS.map((x) => x.name), ['desktop_plist_parse', 'desktop_entry_parse', 'desktop_reg_uninstall_parse', 'desktop_proc_parse', 'desktop_gvariant_parse', 'desktop_snapshot_compare', 'desktop_process_list', 'desktop_process_inspect', 'desktop_process_compare', 'desktop_apps_list', 'desktop_app_inspect', 'desktop_ui_tree']);
  assert.equal(WEB_TOOLS.length, 6);
  for (const x of TOOLS) { assert.match(x.name, /^desktop_[a-z_]+$/); for (const [k, v] of Object.entries(x.inputSchema)) assert.ok(v.description, `${x.name}.${k}`); }
  assert.deepEqual(CLI_COMMANDS.map((c) => c.name), ['ps', 'proc-inspect', 'proc-compare', 'apps', 'app-inspect', 'ui-tree']);
  const runner = join(dirname(fileURLToPath(import.meta.url)), 'cli-runner.ts');
  const r = spawnSync(process.execPath, ['--import', 'tsx', runner, 'app-inspect', join(S, 'tricky.desktop')], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^Tricky Viewer \(tricky\)/);
  const j = spawnSync(process.execPath, ['--import', 'tsx', runner, 'apps', '--dir', S, '--hidden', '--json'], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(JSON.parse(j.stdout).total, 2);
  const bad = spawnSync(process.execPath, ['--import', 'tsx', runner, 'ps'], { encoding: 'utf8', timeout: 60_000, env: { ...process.env, REVLENS_ALLOW_EXECUTION: '' } });
  assert.equal(bad.status, 2);
});

test('parse-only tools work from text in the browser entry', async () => {
  const t = WEB_TOOLS.find((x) => x.name === 'desktop_plist_parse')!;
  const r = (await t.run({ base64: readFileSync(join(S, 'Info.binary.plist')).toString('base64'), bundle: true })) as any;
  assert.equal(r.app.id, 'dev.revlens.SampleApp');
  await assert.rejects(t.run({ path: '/etc/passwd' }), /only supported in Node/);
  const sc = WEB_TOOLS.find((x) => x.name === 'desktop_snapshot_compare')!;
  const snap = { kind: 'revlens-process-snapshot', version: 1, platform: 'linux', takenAt: '', process: { pid: 1, name: 'x' }, modules: [{ path: '/a.so', kind: 'library' }], files: [], sockets: [], warnings: [] };
  const d = (await sc.run({ aText: JSON.stringify(snap), bText: JSON.stringify({ ...snap, modules: [{ path: '/b.so', kind: 'library' }] }) })) as any;
  assert.deepEqual([d.modules.added, d.modules.removed, d.similarity], [['/b.so'], ['/a.so'], 0]);
  assert.equal(compareSnapshots(snap as any, snap as any).similarity, 1);
});

test('hostile inputs never crash the parsers', () => {
  const bin = new Uint8Array(readFileSync(join(S, 'Info.binary.plist')));
  fc.assert(fc.property(fc.uint8Array({ maxLength: 3000 }), fc.integer({ min: 8, max: bin.length - 1 }), fc.integer({ min: 0, max: 255 }), (rand, pos, val) => {
    const m = bin.slice(); m[pos] = val;
    for (const input of [m, new Uint8Array([...new TextEncoder().encode('bplist00'), ...rand])]) { try { parsePlist(input); } catch (e) { assert.ok(e instanceof Error); } }
  }), { numRuns: 500 });
  fc.assert(fc.property(fc.string({ maxLength: 2000 }), (s) => {
    for (const f of [() => parseGVariant(s), () => parsePlist(new TextEncoder().encode('<plist>' + s)), () => parseDesktopFile(s), () => parseRegQuery(s), () => parseLsofF(s), () => parseProcNet(s, 'tcp6')]) { try { f(); } catch (e) { assert.ok(e instanceof InputError, String(e)); } }
  }), { numRuns: 500 });
  // a binary plist whose array points at itself is a cycle, not an infinite loop
  const cyc = new Uint8Array([...new TextEncoder().encode('bplist00'), 0xa1, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
  assert.throws(() => parsePlist(cyc), /cycle|range|out of/);
  assert.throws(() => parsePlist(new TextEncoder().encode('<plist>' + '<array>'.repeat(5000))), /deep|unterminated|end/);
});
