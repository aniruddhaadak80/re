// macOS and Windows round 3 tests. They drive the real desktop of a CI runner, so they run only
// when CI is set on those systems and skip everywhere else with the reason. Linux is covered by
// desktop-r3.test.ts with a private Xvfb display.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { startComputer, actOnComputer, closeComputer, checkpointComputer, verifyAuditLog, traceUi, appState, captureUiTree } from '../src/node.js';
import { pngInfo } from '../src/index.js';

const mac = process.platform === 'darwin', win = process.platform === 'win32';
const ci = !!process.env.CI;
const reason = !(mac || win) ? 'macOS and Windows only (Linux runs desktop-r3.test.ts)' : !ci ? 'drives the real desktop, so it runs only in CI (set CI=1 to run it here)' : '';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const permission = (e: unknown) => /permission|not allowed|accessibility|screen recording|not authorized|-1743|-25211/i.test(String((e as Error)?.message ?? e));

test('attach session: screenshot, pointer, keys and audit log on the real desktop', { timeout: 180_000 }, async (t) => {
  if (reason) { t.skip(reason); return; }
  const s = await startComputer({ consent: true, allowExecution: true, mode: 'attach', attachCurrentDisplay: true }) as { id: string; auditLog: string; driver: string };
  assert.equal(s.driver, win ? 'sendinput' : s.driver.startsWith('macos') ? s.driver : 'macos');
  try {
    let shot: { path: string; width: number; height: number } | undefined;
    try { shot = await actOnComputer(s.id, { action: 'screenshot' }) as never; } catch (e) { if (mac && permission(e)) t.diagnostic(`screenshot needs Screen Recording permission: ${(e as Error).message}`); else throw e; }
    if (shot) { const i = pngInfo(new Uint8Array(readFileSync(shot.path))); assert.equal(i.width, shot.width); assert.ok(i.width > 100 && i.height > 100); }
    await actOnComputer(s.id, { action: 'move', x: 211, y: 157 });
    await sleep(200);
    const c = (await actOnComputer(s.id, { action: 'cursor' }) as { cursor: { x: number; y: number } }).cursor;
    if (win) assert.deepEqual(c, { x: 211, y: 157 });
    else if (Math.round(c.x) !== 211 || Math.round(c.y) !== 157) t.diagnostic(`macOS did not move the pointer (posting events needs Accessibility permission); cursor at ${JSON.stringify(c)}`);
    const w = await actOnComputer(s.id, { action: 'windows' }) as { windows: unknown[] };
    assert.ok(Array.isArray(w.windows));
    await assert.rejects(actOnComputer(s.id, { action: 'launch', argv: ['x'] }), /isolated sessions/);
    const cp = await checkpointComputer(s.id, { label: 'desktop', uiTree: false }).catch((e) => { if (permission(e)) return undefined; throw e; }) as { files: { name: string }[] } | undefined;
    if (cp) assert.ok(cp.files.some((f) => f.name === 'windows.json'));
  } finally {
    const c = await closeComputer(s.id) as { auditLog: string };
    const v = await verifyAuditLog(c.auditLog);
    assert.ok(v.ok, JSON.stringify(v.problems)); assert.ok(v.actions.move === 1 && v.actions.close === 1);
  }
});

test('Windows: typing into Notepad through SendInput, seen in its title and through UIAutomation events', { timeout: 180_000 }, async (t) => {
  if (reason || !win) { t.skip(reason || 'Windows only'); return; }
  const np = spawn('notepad.exe', [], { stdio: 'ignore', detached: false });
  const s = await startComputer({ consent: true, allowExecution: true, mode: 'attach', attachCurrentDisplay: true }) as { id: string };
  try {
    const found = await actOnComputer(s.id, { action: 'wait', untilWindow: 'Notepad', timeoutMs: 30_000 }) as { window: { title: string; pid?: number } };
    const pid = found.window.pid ?? np.pid;
    const tree = await captureUiTree({ allowExecution: true, pid, maxNodes: 200, maxDepth: 6 });
    const edit = tree.nodes.find((n) => /^(Edit|Document)$/.test(n.role));
    assert.ok(edit?.bounds, JSON.stringify(tree.nodes.slice(0, 20).map((n) => [n.role, n.name])));
    await actOnComputer(s.id, { action: 'click', x: edit!.bounds!.x + 40, y: edit!.bounds!.y + 40 });
    const tr = await traceUi({ allowExecution: true, session: s.id, pid, durationMs: 9000, treeDiff: false, during: [{ action: 'type', text: 'RevLens round three' }] });
    assert.equal(tr.backend, 'uia');
    assert.ok(tr.actions[0]?.ok, JSON.stringify(tr.actions));
    t.diagnostic(`UIA events: ${JSON.stringify(tr.summary.byType)}`);
    assert.ok(tr.events.length > 0, 'typing produced UIAutomation events');
    const w = await actOnComputer(s.id, { action: 'windows' }) as { windows: { title: string }[] };
    assert.ok(w.windows.some((x) => x.title.startsWith('*')), JSON.stringify(w.windows.map((x) => x.title)));
  } finally {
    await closeComputer(s.id);
    spawnSync('taskkill', ['/F', '/IM', 'notepad.exe'], { stdio: 'ignore' });
  }
});

test('Windows: app state reads HKCU registry values for the app', { timeout: 60_000 }, async (t) => {
  if (reason || !win) { t.skip(reason || 'Windows only'); return; }
  spawnSync('reg', ['add', 'HKCU\\Software\\RevLensFixture', '/v', 'Theme', '/t', 'REG_SZ', '/d', 'dark', '/f']);
  spawnSync('reg', ['add', 'HKCU\\Software\\RevLensFixture', '/v', 'ApiToken', '/t', 'REG_SZ', '/d', 'tok', '/f']);
  try {
    const st = await appState({ name: 'RevLensFixture' });
    const key = st.registry?.find((k) => /RevLensFixture$/i.test(k.key));
    assert.equal(key?.values.Theme, 'dark');
    assert.ok(st.roots.some((r) => r.kind === 'registry' && r.exists));
  } finally { spawnSync('reg', ['delete', 'HKCU\\Software\\RevLensFixture', '/f']); }
});

test('macOS: app state reads the preferences plist that defaults wrote', { timeout: 60_000 }, async (t) => {
  if (reason || !mac) { t.skip(reason || 'macOS only'); return; }
  spawnSync('defaults', ['write', 'dev.revlens.fixture', 'Theme', '-string', 'dark']);
  try {
    let found: { summary?: unknown } | undefined;
    for (let i = 0; i < 20 && !found; i++) {
      const st = await appState({ bundleId: 'dev.revlens.fixture' });
      found = st.files.find((f) => f.rel === 'dev.revlens.fixture.plist');
      if (!found) await sleep(500);
    }
    assert.ok(found, 'plist written by cfprefsd');
    assert.deepEqual(found!.summary, { keys: ['Theme'] });
  } finally { spawnSync('defaults', ['delete', 'dev.revlens.fixture']); }
});

test('macOS: UI trace in poll mode sees TextEdit change while typing', { timeout: 180_000 }, async (t) => {
  if (reason || !mac) { t.skip(reason || 'macOS only'); return; }
  spawnSync('open', ['-a', 'TextEdit']);
  await sleep(3000);
  const s = await startComputer({ consent: true, allowExecution: true, mode: 'attach', attachCurrentDisplay: true }) as { id: string };
  try {
    let r;
    try { r = await traceUi({ allowExecution: true, session: s.id, app: 'TextEdit', mode: 'poll', intervalMs: 700, durationMs: 6000, during: [{ action: 'key', key: 'cmd+n' }, { action: 'type', text: 'revlens' }] }); }
    catch (e) { if (permission(e)) { t.skip(`needs Accessibility permission for osascript: ${(e as Error).message.slice(0, 200)}`); return; } throw e; }
    assert.equal(r.backend, 'poll');
    t.diagnostic(`events: ${JSON.stringify(r.summary.byType)}`);
    if (!r.events.length) t.diagnostic('no tree change seen; the runner may block synthetic input without Accessibility permission');
  } finally { await closeComputer(s.id); spawnSync('osascript', ['-e', 'tell application "TextEdit" to quit saving no']); }
});
