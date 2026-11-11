import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
export const SAMPLES = join(here, '..', '..', '..', 'samples', 'mobile');
export const CACHE = join(here, '..', '..', '..', 'samples', '.cache', 'mobile');

export const APKS = {
  alarm: 'com.angrydoughnuts.android.alarmclock_27.apk',
  screentime: 'de.markusfisch.android.screentime_16.apk',
  stopwatch: 'omegacentauri.mobi.simplestopwatch_31.apk',
  streak: 'org.rayg.streaktracker_12.apk',
} as const;

export function sample(...p: string[]): string { return join(SAMPLES, ...p); }
export function bytes(...p: string[]): Uint8Array { return new Uint8Array(readFileSync(join(SAMPLES, ...p))); }
export function cached(...p: string[]): string | undefined { const f = join(CACHE, ...p); return existsSync(f) ? f : undefined; }
export function json<T = any>(...p: string[]): T { return JSON.parse(readFileSync(join(SAMPLES, ...p), 'utf8')) as T; }
export function gzJson<T = any>(...p: string[]): T { return JSON.parse(gunzipSync(readFileSync(join(SAMPLES, ...p))).toString('utf8')) as T; }
export function gzText(...p: string[]): string { return gunzipSync(readFileSync(join(SAMPLES, ...p))).toString('utf8'); }

const SKIP = ['.line', '.local', '.end local', '.restart local', '.prologue', '.epilogue', '.source'];

/** Same normalization as scripts/gen-expected.py: method bodies without debug info, annotations or comments. */
export function normSmali(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  let cur: string[] | null = null;
  let skip = 0;
  for (const raw of text.split('\n')) {
    const line = raw.includes('    #') ? (raw.split('    #')[0] as string).trimEnd() : raw.trimEnd();
    const t = line.trim();
    if (t.startsWith('.method')) { cur = []; out[t] = cur; continue; }
    if (!cur) continue;
    if (t.startsWith('.annotation')) { skip++; continue; }
    if (t === '.end annotation') { skip--; continue; }
    if (t.startsWith('.param') || t === '.end param' || skip > 0) continue;
    if (t === '.end method') { cur = null; continue; }
    if (!t || SKIP.some((s) => t.startsWith(s))) continue;
    cur.push(t);
  }
  return out;
}
