// Child process lifetime helpers shared by sessions and captures (Node only).
import type { ChildProcess } from 'node:child_process';

/** Wait for a child to exit, at most ms. The timer is cleared either way, so nothing is left pending. */
export function waitExit(p: ChildProcess, ms: number): Promise<boolean> {
  if (p.exitCode !== null || p.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const done = (v: boolean) => { clearTimeout(t); p.off('exit', onExit); resolve(v); };
    const onExit = () => done(true);
    const t = setTimeout(() => done(false), ms);
    p.once('exit', onExit);
  });
}

/** Let go of a child for good: close our ends of its pipes and stop it holding the event loop.
 * A grandchild that inherited stdout or stderr would otherwise keep the caller alive after the
 * capture returned (seen as a test file that never exits). */
export function release(p: ChildProcess | undefined): void {
  if (!p) return;
  for (const s of [p.stdin, p.stdout, p.stderr]) { try { s?.removeAllListeners('data'); s?.destroy(); } catch { /* closed */ } }
  try { p.unref(); } catch { /* gone */ }
}

