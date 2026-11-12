// Cutter driving: finding running Cutter windows and their open files, the RevLens Cutter plugin
// protocol (the real plugin script run by Python 3 in self test mode), and cutter_command through a
// separate radare2 or rizin. Linux process tests use real processes: a copy of tail named "cutter"
// that holds the target file open, checked against the kernel's own /proc fd links read with readlink(1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { copyFileSync, chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import fc from 'fast-check';
import {
  listCutterSessions, cutterCommand, pluginCommand, pluginScriptPath, isCutterProcess, parseCmdline, filesFromArgs,
  cutterFromProc, parsePs, parseLsof, parseWindowsProcesses, splitWindowsCommandLine, readAnnouncements,
} from '../src/cutter.ts';
import { detect } from '../src/detect.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const ELF = join(repo, 'samples', 'disasm', 'hello-x64.elf');
const linux = process.platform === 'linux';
const fresh = (p = 'rl-cutter-live-') => mkdtempSync(join(tmpdir(), p));
const which = (n: string) => { try { return execFileSync('which', [n], { encoding: 'utf8' }).trim(); } catch { return ''; } };
const python = which('python3');

function startFakeCutter(name: string, argv0?: string): { child: ChildProcess; exe: string } {
  const dir = fresh();
  const exe = join(dir, name);
  copyFileSync(which('tail'), exe);
  chmodSync(exe, 0o755);
  const child = spawn(exe, ['-f', ELF], { stdio: 'ignore', ...(argv0 ? { argv0 } : {}) });
  return { child, exe };
}
const settle = () => new Promise((r) => setTimeout(r, 300));

test('process name rules', () => {
  for (const yes of ['/usr/bin/cutter', 'cutter', 'C:\\Cutter\\cutter.exe', '/home/a/Applications/Cutter-v2.5.0-Linux-x86_64.AppImage', '/Applications/Cutter.app/Contents/MacOS/Cutter', '/var/lib/flatpak/app/re.rizin.cutter/current/active/files/bin/cutter']) assert.ok(isCutterProcess(yes), yes);
  for (const no of ['/usr/bin/cutterfish', 'rizin', '/usr/bin/tail', 'Cutter-notes.txt']) assert.ok(!isCutterProcess(no), no);
  assert.deepEqual(filesFromArgs(['cutter', '-A', '2', '-p', 'proj.rzdb', 'a.out'], '/w'), { files: ['/w/a.out'], project: '/w/proj.rzdb' });
  assert.deepEqual(filesFromArgs(['cutter', '--project=/p/x.rzdb'], null), { files: [], project: '/p/x.rzdb' });
  assert.deepEqual(filesFromArgs(['cutter', 'saved.rzdb'], '/w'), { files: [], project: '/w/saved.rzdb' });
  assert.deepEqual(splitWindowsCommandLine('"C:\\Program Files\\Cutter\\cutter.exe" -A 1 "C:\\a b\\x.exe"'), ['C:\\Program Files\\Cutter\\cutter.exe', '-A', '1', 'C:\\a b\\x.exe']);
  assert.deepEqual(parseWindowsProcesses('{"ProcessId":12,"CommandLine":"cutter.exe x.exe","ExecutablePath":"C:\\\\c\\\\cutter.exe"}'), [{ pid: 12, commandLine: 'cutter.exe x.exe', exe: 'C:\\c\\cutter.exe' }]);
  assert.deepEqual(parsePs('  101 /Applications/Cutter.app/Contents/MacOS/Cutter /tmp/a.out\n 7 bash\n'), [{ pid: 101, args: '/Applications/Cutter.app/Contents/MacOS/Cutter /tmp/a.out' }, { pid: 7, args: 'bash' }]);
  assert.deepEqual(parseLsof('p101\nfcwd\nn/Users/a\nf3\nn/Users/a/target.bin\nf4\nn/usr/lib/libz.dylib\n'), ['/Users/a', '/Users/a/target.bin']);
  assert.deepEqual(parseCmdline(Buffer.from(['cutter', '-A', '1', 'x.bin', ''].join('\0'))), ['cutter', '-A', '1', 'x.bin']);
});

test('a fake proc tree: command line, cwd and project', () => {
  const root = fresh();
  const p = join(root, '4242');
  mkdirSync(join(p, 'fd'), { recursive: true });
  writeFileSync(join(p, 'cmdline'), ['/opt/x/Cutter-v2.5.0-Linux-x86_64.AppImage', '-p', 'work.rzdb', 'bin/app'].join('\0') + '\0');
  writeFileSync(join(p, 'comm'), 'AppRun\n');
  symlinkSync('/work', join(p, 'cwd'));
  symlinkSync(ELF, join(p, 'fd', '7'));
  symlinkSync('/usr/lib/libc.so.6', join(p, 'fd', '8'));
  mkdirSync(join(root, '7'));
  writeFileSync(join(root, '7', 'cmdline'), 'bash\0');
  const s = cutterFromProc(root);
  assert.equal(s.length, 1);
  assert.equal(s[0]!.pid, 4242);
  assert.equal(s[0]!.project, '/work/work.rzdb');
  assert.deepEqual(s[0]!.files, ['/work/bin/app', ELF]);
});

test('real process: a Cutter process that holds the file open is listed with that file', { skip: !linux && 'needs /proc' }, async () => {
  const { child, exe } = startFakeCutter('cutter');
  try {
    await settle();
    const r = await listCutterSessions({ pluginDir: fresh() });
    const s = r.sessions.find((x) => x.pid === child.pid);
    assert.ok(s, JSON.stringify(r.sessions));
    assert.equal(s.exe, exe);
    assert.equal(s.source, 'proc');
    // reference: what the kernel reports for the process's descriptors
    const fdTargets = readdirSync(`/proc/${child.pid}/fd`).map((fd) => { try { return execFileSync('readlink', [`/proc/${child.pid}/fd/${fd}`], { encoding: 'utf8' }).trim(); } catch { return ''; } });
    assert.ok(fdTargets.includes(ELF), 'tail holds the file open');
    assert.deepEqual(s.files, [ELF]);
    assert.match(r.notes.join(' '), /RevLens plugin/);
  } finally { child.kill(); }
});

test('real process: an AppImage launch name is recognised from argv[0]', { skip: !linux && 'needs /proc' }, async () => {
  const { child } = startFakeCutter('AppRun', 'Cutter-v2.5.0-Linux-x86_64.AppImage');
  try {
    await settle();
    const s = (await listCutterSessions({ pluginDir: fresh() })).sessions.find((x) => x.pid === child.pid);
    assert.ok(s);
    assert.equal(s.argv[0], 'Cutter-v2.5.0-Linux-x86_64.AppImage');
  } finally { child.kill(); }
});

async function startPlugin(dir: string): Promise<{ child: ChildProcess; port: number; pid: number }> {
  const child = spawn(python, [pluginScriptPath(), '--selftest'], { env: { ...process.env, REVLENS_CUTTER_BRIDGE_DIR: dir, REVLENS_SELFTEST_FILE: ELF }, stdio: ['pipe', 'pipe', 'inherit'] });
  const line = await new Promise<string>((res, rej) => { createInterface({ input: child.stdout! }).once('line', res); child.once('error', rej); });
  const j = JSON.parse(line);
  return { child, port: j.port, pid: j.pid };
}

test('the RevLens Cutter plugin: announce, live commands, token and guards', { skip: !python && 'needs python3' }, async () => {
  const dir = fresh();
  const { child, port, pid } = await startPlugin(dir);
  try {
    const ann = readAnnouncements(dir);
    assert.equal(ann.length, 1);
    assert.equal(ann[0]!.pid, pid);
    assert.equal(ann[0]!.port, port);
    assert.equal(ann[0]!.file, ELF);
    const mode = execFileSync('stat', ['-c', '%a', join(dir, `${pid}.json`)], { encoding: 'utf8' }).trim();
    assert.equal(mode, '600', 'the token file is private');
    const list = await listCutterSessions({ pluginDir: dir });
    const s = list.sessions.find((x) => x.pid === pid)!;
    assert.equal(s.bridge?.port, port);
    assert.deepEqual(s.files, [ELF]);
    const live = await cutterCommand({ session: pid, command: 'afl', allowExecution: true }, { pluginDir: dir }) as any;
    assert.equal(live.ok, true);
    assert.equal(live.mode, 'live');
    assert.equal(live.output, 'ran: afl');
    const wrong = await pluginCommand(port, 'x'.repeat(48), 'afl');
    assert.equal(wrong.ok, false);
    assert.equal(wrong.status, 401);
    const refused = await pluginCommand(port, ann[0]!.token, '!id');
    assert.equal(refused.status, 400, 'the plugin refuses host escapes by itself');
    await assert.rejects(cutterCommand({ session: pid, command: 'pd 4; !id', allowExecution: true }, { pluginDir: dir }), /refuse/);
    const gated = await cutterCommand({ session: pid, command: 'afl' }, { pluginDir: dir }) as any;
    assert.equal(gated.needsAllowExecution, true);
  } finally { child.stdin!.end(); child.kill(); }
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(readAnnouncements(dir).length, 0, 'the announcement is removed when the plugin stops');
});

test('cutter_command through a separate radare2 or rizin on the same file', async (t) => {
  const r2 = await detect('rizin');
  const r2b = r2.available ? r2 : await detect('radare2');
  if (!r2b.available) { t.skip('neither rizin nor radare2 is installed'); return; }
  const out = await cutterCommand({ file: ELF, command: 'iIj', analysis: 'none', allowExecution: true }, { pluginDir: fresh() }) as any;
  assert.equal(out.ok, true, out.error);
  assert.equal(out.mode, 'rizin');
  const info = JSON.parse(out.output);
  // reference: readelf -h of the same file
  const hdr = execFileSync('readelf', ['-h', ELF], { encoding: 'utf8' });
  assert.match(hdr, /Class:\s+ELF64/);
  assert.equal(info.bits, 64);
  assert.match(hdr, /X86-64/);
  assert.equal(info.arch, 'x86');
  assert.equal(info.bintype, 'elf');
});

test('cutter_command with no rizin, radare2 or Cutter answers available:false', () => {
  const code = `import { cutterCommand } from ${JSON.stringify(join(repo, 'packages/bridges/src/cutter.ts'))};
process.stdout.write(JSON.stringify(await cutterCommand({ file: ${JSON.stringify(ELF)}, command: 'afl', allowExecution: true }, { pluginDir: '/nonexistent' })));`;
  const out = JSON.parse(execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { env: { ...process.env, REVLENS_BRIDGES_DISABLE: 'all' }, encoding: 'utf8' }));
  assert.equal(out.available, false);
  assert.equal(out.tool, 'rizin');
  assert.ok(out.install.homepage);
});

test('hostile process listings and command lines', () => {
  fc.assert(fc.property(fc.string({ maxLength: 5000 }), (s) => {
    parseCmdline(s); parsePs(s); parseLsof(s); parseWindowsProcesses(s);
    assert.ok(splitWindowsCommandLine(s).length <= 64);
    const f = filesFromArgs(['cutter', ...s.split(' ').slice(0, 100)], '/w');
    assert.ok(Array.isArray(f.files));
  }), { numRuns: 300 });
  const t0 = Date.now();
  splitWindowsCommandLine('"'.repeat(200_000));
  parsePs('1 '.repeat(100_000));
  assert.ok(Date.now() - t0 < 2000);
});
