// Windows ChangeTime settling. Windows moves a file's ChangeTime (ctime) a little after a write
// with no content change (security software adds hash and catalog attributes in the background).
// A baseline taken while that is still happening disagrees with a later look and makes an
// untouched file seem changed. settleChangeTime keeps re-reading a fresh ChangeTime until it is
// older than the drift window, at a poll interval, for at most a number of polls, and then returns
// the last reading. Other platforms read once. Same idea as rea's ChangeTimeBaseline (MIT); this
// is an original implementation. No Node imports: the stat call, clock and sleep are passed in.
import { InputError } from './proc.js';

export interface ChangeTimeLimits { driftMs: number; pollMs: number; maxPolls: number; sources: { driftMs: 'default' | 'setting'; pollMs: 'default' | 'setting'; maxPolls: 'default' | 'setting' } }

/** The three settings, their defaults and allowed ranges. Each also accepts the REA_ name for compatibility. */
export const CHANGE_TIME_SETTINGS = [
  { key: 'driftMs', setting: 'REVLENS_WINDOWS_CHANGE_TIME_DRIFT_MS', alias: 'REA_WINDOWS_CHANGE_TIME_DRIFT_MS', defaultValue: 2000, min: 1, max: 60_000, unit: 'ms', meaning: 'how long after a write a ChangeTime may still move on its own' },
  { key: 'pollMs', setting: 'REVLENS_WINDOWS_CHANGE_TIME_SETTLE_POLL_MS', alias: 'REA_WINDOWS_CHANGE_TIME_SETTLE_POLL_MS', defaultValue: 25, min: 1, max: 1000, unit: 'ms', meaning: 'wait between ChangeTime reads' },
  { key: 'maxPolls', setting: 'REVLENS_WINDOWS_CHANGE_TIME_SETTLE_MAX_POLLS', alias: 'REA_WINDOWS_CHANGE_TIME_SETTLE_MAX_POLLS', defaultValue: 40, min: 1, max: 1000, unit: 'polls', meaning: 'most re-reads before the last reading is used' },
] as const;

/** Read the limits from an environment. A set value must be a plain positive decimal integer in range; anything else is refused, never replaced by the default. */
export function changeTimeLimits(env: Record<string, string | undefined> = {}): ChangeTimeLimits {
  const out: Record<string, number> = {}, sources: Record<string, 'default' | 'setting'> = {};
  const problems: string[] = [];
  for (const s of CHANGE_TIME_SETTINGS) {
    const raw = env[s.setting] ?? env[s.alias];
    const name = env[s.setting] !== undefined ? s.setting : s.alias;
    if (raw === undefined) { out[s.key] = s.defaultValue; sources[s.key] = 'default'; continue; }
    const ok = /^[1-9]\d{0,9}$/.test(raw) && Number(raw) >= s.min && Number(raw) <= s.max;
    if (!ok) { problems.push(`${name} is ${JSON.stringify(String(raw).slice(0, 40))}; use a whole number from ${s.min} to ${s.max} ${s.unit} (default ${s.defaultValue})`); continue; }
    out[s.key] = Number(raw); sources[s.key] = 'setting';
  }
  if (problems.length) throw new InputError(problems.join('; '));
  return { driftMs: out.driftMs!, pollMs: out.pollMs!, maxPolls: out.maxPolls!, sources: sources as ChangeTimeLimits['sources'] };
}

export interface SettleSeams { platform?: string; now?: () => number; sleep?: (ms: number) => Promise<void>; env?: Record<string, string | undefined>; limits?: ChangeTimeLimits; signal?: AbortSignal }

/** Read a file's stats until its ChangeTime has left the drift window (Windows only), then return the last reading and how many reads it took. */
export async function settleChangeTime<T extends { ctimeMs: number }>(read: () => Promise<T>, seams: SettleSeams = {}): Promise<{ stats: T; reads: number; settled: boolean }> {
  const lim = seams.limits ?? changeTimeLimits(seams.env ?? {});
  const platform = seams.platform ?? 'unknown';
  const now = seams.now ?? (() => Date.now());
  const sleep = seams.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const abort = () => { if (seams.signal?.aborted) throw seams.signal.reason instanceof Error ? seams.signal.reason : new InputError('cancelled'); };
  const moving = (s: T) => platform === 'win32' && (!Number.isFinite(s.ctimeMs) || now() - s.ctimeMs < lim.driftMs);
  abort();
  let s = await read(), reads = 1;
  for (let i = 0; i < lim.maxPolls; i++) {
    if (!moving(s)) return { stats: s, reads, settled: true };
    abort(); await sleep(lim.pollMs); abort();
    s = await read(); reads++;
  }
  abort();
  return { stats: s, reads, settled: !moving(s) };
}
