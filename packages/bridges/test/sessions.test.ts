// Persistent sessions: radare2, gdb (MI), lldb and Frida kept alive across tool calls.
// - Guards: host escapes are refused for every debugger, normal commands pass.
// - MI parser on a recorded real gdb 16.3 MI transcript.
// - Manager: ids, max sessions, idle timeout, queueing, clean shutdown, cleanup on process exit.
// - Real tools (skipped with the reason when missing): values cross checked against the recorded
//   one shot outputs (r2-aflj.json) and the fixture source (crackme.c).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkGdbCommand, checkLldbCommand, checkR2Command, miQuote } from '../src/sessions/guards.ts';
import { parseMiLines, miUnquote, miFields } from '../src/parsers/mi.ts';
import { PipeProcess, SessionManager, SESSIONS } from '../src/sessions/manager.ts';
import { detectAll } from '../src/detect.ts';
import { runTool } from '../src/exec.ts';
import { TOOLS } from '../src/tools.ts';
import type { ToolId } from '../src/types.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const S = (f: string) => join(repo, 'samples', 'bridges', f);
const ELF = S('crackme-aarch64.elf');
const STATIC = process.arch === 'x64' ? S('crackme-x86_64-static.elf') : S('crackme-aarch64-static.elf');
const staticOk = process.platform === 'linux' && (process.arch === 'arm64' || process.arch === 'x64');
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;
const run = async (n: string, i: Record<string, unknown>) => (await tool(n).run(i)) as any;
const dets = await detectAll();
function skipUnless(...ids: ToolId[]): string | false {
  for (const id of ids) if (!dets.get(id)?.available) return `${id} not installed`;
  return false;
}
function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}
async function gone(pid: number, ms = 5000): Promise<boolean> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (!alive(pid)) return true; await new Promise((r) => setTimeout(r, 50)); }
  return !alive(pid);
}

// ---------------- guards ----------------

test('r2 guard: refuses shell, pipes, writes, scripts, opens and sandbox changes', () => {
  for (const ok of ['afl', 'pdf @ main', 'afn check @ 0x848', 'axtj @ sym.check_password', 'izj', 'pdgj @ main', 'CC hello @ 0x848', 'afl~check', 's 0x848; pd 4', 'e asm.bytes=false', '?e hi']) {
    assert.equal(checkR2Command(ok), undefined, ok);
  }
  for (const bad of ['!id', 'pd 1 | sh', '?e x > /tmp/f', '#!python', '`!id`', '. /tmp/x.r2', '.!id', '=!id', '$a=!id', '(m; o x)', 'o /etc/passwd', 'o+ x', 'oo+',
    'e cfg.sandbox=false', 'e cmd.hit=?e', 'e dir.projects=/tmp', 'wx 90', 'wtf /tmp/x 4', 'Ps x', 'q', 'afl;!id', 'afl\nid', '', 'x'.repeat(5000)]) {
    assert.ok(checkR2Command(bad), bad);
  }
});

test('gdb guard: refuses host escapes, file writes and target switches', () => {
  for (const ok of ['break check_password', 'b *0x101ae04', 'run', 'r', 'c', 'continue', 'stepi', 'si', 'ni', 'finish', 'info registers', 'i r x0',
    'bt', 'x/16gx $sp', 'p $x0', 'print (char*)$x0', 'disassemble', 'set var $x0 = 1', 'set $pc = 0x101ae04', 'show version', 'delete', 'kill', 'tbreak main']) {
    assert.equal(checkGdbCommand(ok), undefined, ok);
  }
  for (const bad of ['shell id', 'sh id', '!id', '|id', 'pipe bt | sh', 'python import os', 'py print(1)', 'pi', 'guile', 'source /tmp/x', 'so x',
    'compile code 1', 'dump memory /tmp/x 0 1', 'save breakpoints /tmp/b', 'gcore', 'generate-core-file', 'file /bin/sh', 'exec-file /bin/sh', 'attach 1',
    'target remote | sh', 'set logging on', 'set logging file /tmp/x', 'set startup-with-shell on', 'set exec-wrapper env', 'set auto-load safe-path /',
    'eval "shell %s", "id"', 'alias x = shell', 'define x', 'thread apply all shell id', 'frame apply all bt', 'taas shell id', 'with logging enabled -- bt',
    'print $_shell("id")', 'cd /tmp', 'make', 'commands 1', '-gdb-exit', 'interpreter-exec mi "-gdb-exit"', 'maint print raw-registers /tmp/x', 'quit']) {
    assert.ok(checkGdbCommand(bad), bad);
  }
});

test('lldb guard: refuses host escapes, file writes, scripts and target switches', () => {
  for (const ok of ['b check_password', 'breakpoint set -n main', 'run', 'r', 'c', 'continue', 'si', 'ni', 'register read x0 pc', 'bt', 'memory read -c 16 $sp',
    'x/4gx $sp', 'disassemble -n main', 'frame variable', 'image list', 'process status', 'settings show target.run-args', 'expr 1+1', 'thread list']) {
    assert.equal(checkLldbCommand(ok), undefined, ok);
  }
  for (const bad of ['platform shell id', 'plat sh id', 'script import os', 'scr', 'command script import x.py', 'command source /tmp/x', 'command alias x platform shell',
    'shell id', 'target create /bin/sh', 'file /bin/sh', 'process attach -p 1', 'breakpoint command add -o "platform shell id" 1', 'br command add 1',
    'target stop-hook add -o "platform shell id"', 'memory read -o /tmp/x -c 4 $sp', 'x -o /tmp/x $sp', 'log enable -f /tmp/x lldb api', 'settings set prompt x',
    'settings set target.launch-working-dir /', 'process launch --shell=/bin/sh', 'process launch -c /bin/sh', 'type summary add -P x', 'breakpoint set -P cls',
    'thread step-scripted -C cls', '_regexp-break main', 'quit', 'process save-core /tmp/core']) {
    assert.ok(checkLldbCommand(bad), bad);
  }
});

test('miQuote escapes for MI C strings', () => {
  assert.equal(miQuote('print "a\\b"'), '"print \\"a\\\\b\\""');
  assert.equal(miUnquote('a\\nb\\t\\"q\\"\\\\\\101'), 'a\nb\t"q"\\A');
});

// ---------------- MI parser on a recorded transcript ----------------

test('MI parser: recorded gdb 16.3 session on the static crackme', () => {
  const text = readFileSync(S('recorded/gdb-mi-session-aarch64.txt'), 'utf8');
  const blocks = text.split(/^\(gdb\) $/m);
  const brk = parseMiLines(blocks[1]!, '1');
  assert.equal(brk.result, 'done');
  assert.equal(brk.console, 'Breakpoint 1 at 0x101ae04\n');
  assert.equal(brk.notify.length, 1);
  const runStop = parseMiLines(blocks[2]! + blocks[3]!, '2');
  assert.equal(runStop.result, 'running');
  assert.equal(runStop.target, 'total=43\n');
  assert.equal(runStop.stopped?.reason, 'breakpoint-hit');
  assert.equal(runStop.stopped?.func, 'check_password');
  assert.equal(runStop.stopped?.addr, '0x000000000101ae04');
  const regs = parseMiLines(blocks[4]!, '3');
  assert.match(regs.console, /^pc\s+0x101ae04\s+0x101ae04 <check_password\+16>\n$/);
  const bt = parseMiLines(blocks[5]!, '4');
  assert.equal(bt.console, '#0  0x000000000101ae04 in check_password ()\n#1  0x000000000101af50 in main ()\n');
  const err = parseMiLines(blocks[6]!, '5');
  assert.equal(err.result, 'error');
  assert.equal(err.error, 'Undefined command: "nosuchcommand".  Try "help".');
  const cont = parseMiLines(blocks.slice(7, 9).join(''), '6');
  assert.equal(cont.target, 'checksum=379752446\naccess denied\n');
  assert.deepEqual({ reason: cont.stopped?.reason, code: cont.stopped?.['exit-code'] }, { reason: 'exited', code: '01' });
  assert.deepEqual(miFields('x,a="1",b={c="2"}'), { a: '1', c: '2' });
});

// ---------------- manager ----------------

function fakeSession(m: SessionManager, idleMs: number) {
  m.reserve();
  const proc = new PipeProcess(process.execPath, ['-e', 'process.stdin.on("data", d => process.stdout.write(d)); process.stdin.on("end", () => process.exit(0))']);
  const now = new Date().toISOString();
  const info = { id: m.newId('r2'), kind: 'r2' as const, tool: 'echo', toolVersion: null, target: 'x', pid: null, createdAt: now, lastUsedAt: now, idleTimeoutMs: m.idle(idleMs), commands: 0, busy: false, alive: true };
  return { info: m.add({ info, proc, close: async () => { await proc.shutdown(500); } }), proc };
}

test('manager: max sessions, ids, queueing, idle timeout and close', async () => {
  const prev = process.env.REVLENS_MAX_SESSIONS;
  process.env.REVLENS_MAX_SESSIONS = '2';
  const m = new SessionManager();
  try {
    const a = fakeSession(m, 60_000);
    const b = fakeSession(m, 1000);
    assert.match(a.info.id, /^r2-[0-9a-f]{12}$/);
    assert.throws(() => fakeSession(m, 60_000), /session limit reached \(2 open\)/);
    // two uses of one session run one after the other
    const order: string[] = [];
    await Promise.all([
      m.use(a.info.id, 'r2', async () => { order.push('1s'); await new Promise((r) => setTimeout(r, 100)); order.push('1e'); }),
      m.use(a.info.id, 'r2', async () => { order.push('2s'); order.push('2e'); }),
    ]);
    assert.deepEqual(order, ['1s', '1e', '2s', '2e']);
    assert.throws(() => m.get(a.info.id, 'gdb'), /is a r2 session, not gdb/);
    assert.throws(() => m.get('../etc'), /malformed/);
    // b idles out after 1 s and its process is killed
    await new Promise((r) => setTimeout(r, 1600));
    assert.equal(m.list().length, 1);
    assert.ok(await gone(b.proc.pid!));
    assert.equal(await m.close(a.info.id), true);
    assert.ok(await gone(a.proc.pid!));
    assert.equal(await m.close(a.info.id), false);
    assert.equal(m.list().length, 0);
  } finally {
    if (prev === undefined) delete process.env.REVLENS_MAX_SESSIONS; else process.env.REVLENS_MAX_SESSIONS = prev;
    await m.closeAll();
  }
});

test('session tools answer clean errors for unknown or malformed ids', async () => {
  for (const n of ['bridge_r2_session_cmd', 'bridge_gdb_session_cmd', 'bridge_lldb_session_cmd', 'bridge_frida_session_collect']) {
    const r = await run(n, { sessionId: 'r2-000000000000', command: 'afl' });
    if (r.available === false) continue;
    assert.equal(r.ok, false, n);
    assert.match(r.error, /no open session|malformed|is a/, n);
  }
});

// ---------------- radare2 ----------------

test('r2 session: analysis once, names persist across calls, refused commands never run', { skip: skipUnless('radare2') }, async () => {
  const o = await run('bridge_r2_session_open', { path: ELF, analysis: 'aa' });
  assert.equal(o.ok, true, JSON.stringify(o));
  assert.equal(o.session.sandboxed, true);
  const id = o.session.id;
  try {
    const afl = await run('bridge_r2_session_cmd', { sessionId: id, command: 'aflj', maxChars: 4_000_000 });
    const byName = new Map((afl.json as any[]).map((f) => [f.name, f.addr]));
    // same addresses as the recorded one shot run (recorded/r2-aflj.json)
    assert.equal(byName.get('sym.add_numbers'), 0x828);
    assert.equal(byName.get('sym.check_password'), 0x848);
    assert.equal(byName.get('sym.checksum'), 0x8c8);
    await run('bridge_r2_session_cmd', { sessionId: id, command: 'afn verify_secret @ 0x848' });
    const again = await run('bridge_r2_session_cmd', { sessionId: id, command: 'afij @ 0x848' });
    assert.equal(again.json[0].name, 'verify_secret');
    const pd = await run('bridge_r2_session_cmd', { sessionId: id, command: 'pdf @ main' });
    assert.match(pd.output, /verify_secret/);
    const marker = join(repo, 'samples', 'bridges', '.r2-session-pwned');
    for (const bad of [`!touch ${marker}`, `?e x > ${marker}`, 'o /etc/passwd']) {
      const r = await run('bridge_r2_session_cmd', { sessionId: id, command: bad });
      assert.equal(r.inputError, true, bad);
    }
    assert.equal(existsSync(marker), false);
    const list = await run('bridge_session_list', {});
    assert.ok(list.sessions.some((s: any) => s.id === id && s.commands >= 4));
    const pid = list.sessions.find((s: any) => s.id === id).pid;
    const c = await run('bridge_session_close', { sessionId: id });
    assert.equal(c.ok, true);
    assert.ok(await gone(pid));
  } finally {
    await SESSIONS.close(id);
  }
});

test('sessions are killed when the owning process exits without closing them', { skip: skipUnless('radare2') }, async () => {
  const code = `const { TOOLS } = await import(${JSON.stringify(pathToFileURL(join(repo, 'packages/bridges/src/tools.ts')).href)});
const o = await TOOLS.find((t) => t.name === 'bridge_r2_session_open').run({ path: ${JSON.stringify(ELF)} });
process.stdout.write(String(o.session.pid));
process.exit(0);`;
  const r = await runTool(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { cwd: repo, timeoutMs: 60_000 });
  const pid = Number(r.stdout.trim());
  assert.ok(pid > 0, r.stderr);
  assert.ok(await gone(pid), `r2 pid ${pid} still running after its owner exited`);
});

// ---------------- gdb ----------------

test('gdb session: break, run, registers, backtrace, continue across calls', { skip: skipUnless('gdb') || (!staticOk && 'static fixture is for linux arm64 or x64') }, async () => {
  const blocked = await run('bridge_gdb_session_open', { path: STATIC, args: ['hunter2'] });
  assert.equal(blocked.blocked, true);
  const o = await run('bridge_gdb_session_open', { path: STATIC, args: ['hunter2'], allowExecution: true });
  assert.equal(o.ok, true, JSON.stringify(o));
  const id = o.session.id;
  try {
    const cmd = (command: string) => run('bridge_gdb_session_cmd', { sessionId: id, command, timeoutMs: 30_000 });
    const b = await cmd('break check_password');
    assert.match(b.output, /^Breakpoint 1 at 0x[0-9a-f]+/);
    const r = await cmd('run');
    assert.equal(r.stopped.reason, 'breakpoint-hit');
    assert.equal(r.stopped.func, 'check_password');
    // add_numbers(argc=2, 41) ran before the breakpoint: crackme.c prints total=43
    assert.equal(r.programOutput, 'total=43\n');
    const pcName = process.arch === 'x64' ? 'rip' : 'pc';
    const regs = await cmd(`info registers ${pcName}`);
    assert.match(regs.output, /<check_password\+\d+>/);
    const bt = await cmd('bt');
    assert.match(bt.output, /#0 .* check_password \(\)\n#1 .* main \(\)/);
    const marker = join(repo, 'samples', 'bridges', '.gdb-session-pwned');
    const sh = await run('bridge_gdb_session_cmd', { sessionId: id, command: `shell touch ${marker}` });
    assert.equal(sh.inputError, true);
    assert.equal(existsSync(marker), false);
    const c = await cmd('continue');
    assert.equal(c.stopped.reason, 'exited');
    assert.equal(c.stopped['exit-code'], '01');
    assert.equal(c.programOutput, 'checksum=379752446\naccess denied\n');
  } finally {
    await run('bridge_session_close', { sessionId: id });
  }
});

test('gdb session: attach by pid, a continue that never stops is interrupted at the timeout', { skip: skipUnless('gdb') || (process.platform === 'win32' && 'posix ptrace attach') }, async () => {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 50)'], { stdio: 'ignore' });
  try {
    await new Promise((r) => setTimeout(r, 300));
    const o = await run('bridge_gdb_session_open', { pid: child.pid, allowExecution: true });
    if (!o.ok) return; // ptrace attach not permitted here (yama ptrace_scope); the spawn path is covered above
    const r = await run('bridge_gdb_session_cmd', { sessionId: o.session.id, command: 'continue', timeoutMs: 1500 });
    assert.equal(r.interrupted, true, JSON.stringify(r));
    assert.equal(r.stopped?.reason, 'signal-received');
    assert.equal(r.stopped?.['signal-name'], 'SIGINT');
    const bt = await run('bridge_gdb_session_cmd', { sessionId: o.session.id, command: 'bt 1' });
    assert.match(bt.output, /^#0 /);
    await run('bridge_session_close', { sessionId: o.session.id });
    // closing a session that attached detaches (gdb -gdb-exit detaches from attached processes): the target survives
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(alive(child.pid!), true);
  } finally {
    child.kill('SIGKILL');
  }
});

// ---------------- lldb ----------------

test('lldb session: break, run (waits for the stop), registers, continue', { skip: skipUnless('lldb') || (!staticOk && 'static fixture is for linux arm64 or x64') }, async () => {
  const o = await run('bridge_lldb_session_open', { path: STATIC, args: ['revlens-open-sesame'], allowExecution: true });
  assert.equal(o.ok, true, JSON.stringify(o));
  const id = o.session.id;
  try {
    const cmd = (command: string) => run('bridge_lldb_session_cmd', { sessionId: id, command, timeoutMs: 30_000 });
    const b = await cmd('b check_password');
    assert.match(b.output, /Breakpoint 1: where = .*check_password/);
    const r = await cmd('run');
    assert.match(r.output, /stop reason = breakpoint 1\.1/);
    assert.match(r.state, /stopped/);
    assert.equal(r.programOutput, 'total=43\n');
    const regs = await cmd(process.arch === 'x64' ? 'register read rip' : 'register read pc');
    assert.match(regs.output, /check_password/);
    const pl = await run('bridge_lldb_session_cmd', { sessionId: id, command: 'platform shell id' });
    assert.equal(pl.inputError, true);
    const c = await cmd('continue');
    // the right password: crackme.c prints access granted
    assert.match(c.programOutput, /access granted/);
    assert.match(c.state, /exited/);
  } finally {
    await run('bridge_session_close', { sessionId: id });
  }
});

// ---------------- Frida ----------------

test('Frida session: attach, load, post and collect, template events, unload, detach keeps the target', { skip: skipUnless('frida') || (process.platform === 'win32' && 'uses sleep') }, async () => {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  try {
    const blocked = await run('bridge_frida_session_attach', { pid: child.pid });
    assert.equal(blocked.blocked, true);
    const a = await run('bridge_frida_session_attach', { pid: child.pid, allowExecution: true });
    if (a.available === false) { assert.match(a.reason, /Python|frida/); return; }
    assert.equal(a.ok, true, JSON.stringify(a));
    const id = a.session.id;
    assert.equal(a.targetPid, child.pid);
    const src = "send({ hello: Process.id }); recv('ping', function onPing(m) { send({ pong: m.n * 2 }); recv('ping', onPing); });";
    const l = await run('bridge_frida_session_load', { sessionId: id, source: src });
    assert.equal(l.ok, true, JSON.stringify(l));
    await run('bridge_frida_session_post', { sessionId: id, script: l.script, message: { type: 'ping', n: 21 } });
    const ev = await run('bridge_frida_session_collect', { sessionId: id, script: l.script, waitMs: 5000, minEvents: 2 });
    assert.deepEqual(ev.events.map((e: any) => e.payload), [{ hello: child.pid }, { pong: 42 }]);
    const t = await run('bridge_frida_session_load', { sessionId: id, template: 'module-list' });
    const mods = await run('bridge_frida_session_collect', { sessionId: id, script: t.script, waitMs: 5000, minEvents: 2, limit: 5000 });
    const proc = mods.events.find((e: any) => e.kind === 'event' && e.event.type === 'process');
    assert.equal(proc.event.pid, child.pid);
    assert.ok(mods.events.some((e: any) => e.kind === 'event' && e.event.type === 'module' && /node/.test(e.event.name)));
    const u = await run('bridge_frida_session_unload', { sessionId: id, script: t.script });
    assert.equal(u.ok, true);
    const bad = await run('bridge_frida_session_load', { sessionId: id, template: 'trace-native-export', params: { export: 'x"); Process.kill(1); ("' } });
    assert.equal(bad.inputError, true);
    const helperPid = (await run('bridge_session_list', {})).sessions.find((s: any) => s.id === id).pid;
    await run('bridge_session_close', { sessionId: id });
    assert.ok(await gone(helperPid));
    assert.equal(alive(child.pid!), true, 'attached target must survive detach');
  } finally {
    child.kill('SIGKILL');
  }
});

test('session open tools report the program missing first', async () => {
  const code = `const { TOOLS } = await import(${JSON.stringify(pathToFileURL(join(repo, 'packages/bridges/src/tools.ts')).href)});
const out = {};
for (const n of ['bridge_r2_session_open', 'bridge_gdb_session_open', 'bridge_lldb_session_open', 'bridge_frida_session_attach', 'bridge_gdb_session_cmd', 'bridge_frida_session_load']) {
  out[n] = await TOOLS.find((t) => t.name === n).run({ path: ${JSON.stringify(ELF)}, pid: 1, allowExecution: true, sessionId: 'x', command: 'bt' });
}
process.stdout.write(JSON.stringify(out));`;
  const r = await runTool(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { cwd: repo, env: { ...process.env, REVLENS_BRIDGES_DISABLE: 'all' }, timeoutMs: 60_000 });
  assert.equal(r.code, 0, r.stderr);
  for (const [n, v] of Object.entries(JSON.parse(r.stdout) as Record<string, any>)) {
    assert.equal(v.available, false, n);
    assert.ok(v.install?.homepage, n);
  }
});

process.on('exit', () => { for (const f of ['.r2-session-pwned', '.gdb-session-pwned']) try { rmSync(join(repo, 'samples', 'bridges', f)); } catch { /* none */ } });
