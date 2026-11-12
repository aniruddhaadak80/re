// Pulse detection for OOK/ASK and 2-FSK recordings. Produces packages of pulse and gap
// widths in samples, the same shape rtl_433 slicers consume, plus level estimates.

import type { Recording } from './recording.js';
import { envelope, fmDemod, otsu } from './dsp.js';

export interface PulsePackage {
  index: number;
  modulation: 'OOK' | 'FSK';
  startSample: number;
  endSample: number;
  /** Pulse widths in samples (carrier on for OOK, frequency F1 for FSK). */
  pulses: number[];
  /** Gap widths in samples after each pulse. */
  gaps: number[];
  /** Start sample of each pulse, for evidence. */
  starts: number[];
  levelDb: number;
  noiseDb: number;
  snrDb: number;
  fsk?: { f1Hz: number; f2Hz: number; deviationHz: number };
  truncated?: boolean;
}

export interface PulseOptions {
  /** Minimum SNR in dB between the on and off level clusters (default 6). */
  minSnrDb?: number;
  /** Fixed detection level in dBFS instead of the automatic Otsu split. */
  levelDb?: number;
  /** A gap longer than this ends a package (default 20000 us, at least 10x the longest pulse seen). */
  packageGapUs?: number;
  /** Pulses or gaps shorter than this many microseconds are treated as glitches (default 2 samples). */
  glitchUs?: number;
  maxPackages?: number;
  maxPulsesPerPackage?: number;
  /** Force FSK or OOK detection; default auto (FSK when the carrier holds while the frequency flips). */
  mode?: 'auto' | 'ook' | 'fsk';
}

const dbOf = (v: number): number => (v > 0 ? 20 * Math.log10(v) : -200);
const r2 = (x: number): number => Math.round(x * 100) / 100;

interface Burst { start: number; end: number; pulses: number[]; gaps: number[]; starts: number[] }

/** Threshold the envelope into on and off runs, merging glitches; returns bursts split at long gaps. */
function ookBursts(env: Float32Array, rate: number, opts: PulseOptions): { bursts: Burst[]; levelDb: number; noiseDb: number; snrDb: number; thresholdDb: number } {
  const n = env.length;
  const logv = new Float32Array(n);
  for (let k = 0; k < n; k++) logv[k] = dbOf((env[k] as number) + 1e-5);
  const o = otsu(logv);
  const thrDb = opts.levelDb ?? o.threshold;
  const snr = o.separation;
  const res = { levelDb: r2(o.high), noiseDb: r2(o.low), snrDb: r2(snr), thresholdDb: r2(thrDb), bursts: [] as Burst[] };
  if (opts.levelDb === undefined && snr < (opts.minSnrDb ?? 6)) return res;
  const hi = Math.pow(10, (thrDb + 1) / 20), lo = Math.pow(10, (thrDb - 1) / 20);
  const glitch = Math.max(1, Math.round(((opts.glitchUs ?? 0) * rate) / 1e6) || 2);
  // raw runs, then fold glitches into the run before them and coalesce
  const raw: { on: boolean; start: number; len: number }[] = [];
  let on = (env[0] as number) > hi, start = 0;
  for (let k = 1; k <= n; k++) {
    const v = k < n ? (env[k] as number) : 0;
    const next = on ? v >= lo : v > hi;
    if (k === n || next !== on) { raw.push({ on, start, len: k - start }); on = next; start = k; }
  }
  const runs: { on: boolean; start: number; len: number }[] = [];
  for (const run of raw) {
    const last = runs[runs.length - 1];
    if (last && (run.len < glitch || last.on === run.on)) { last.len += run.len; continue; }
    runs.push({ ...run });
  }
  const maxPk = Math.max(1, opts.maxPackages ?? 500);
  const maxPulses = Math.max(1, opts.maxPulsesPerPackage ?? 20000);
  const pkgGap = Math.round(((opts.packageGapUs ?? 20000) * rate) / 1e6);
  let cur: Burst | undefined;
  let maxPulse = 0;
  for (const run of runs) {
    if (run.on) {
      if (!cur) { cur = { start: run.start, end: run.start + run.len, pulses: [], gaps: [], starts: [] }; maxPulse = 0; }
      if (cur.pulses.length < maxPulses) { cur.pulses.push(run.len); cur.gaps.push(0); cur.starts.push(run.start); }
      cur.end = run.start + run.len;
      maxPulse = Math.max(maxPulse, run.len);
    } else if (cur) {
      const limit = Math.max(pkgGap, 10 * maxPulse);
      if (run.len > limit || run.start + run.len >= n) {
        cur.gaps[cur.gaps.length - 1] = run.len;
        res.bursts.push(cur);
        cur = undefined;
        if (res.bursts.length >= maxPk) break;
      } else cur.gaps[cur.gaps.length - 1] = run.len;
    }
  }
  if (cur && res.bursts.length < maxPk) { cur.gaps[cur.gaps.length - 1] = Math.max(cur.gaps[cur.gaps.length - 1] as number, n - cur.end); res.bursts.push(cur); }
  return res;
}

/** Detect pulse packages in a recording. */
export function detectPulses(r: Recording, opts: PulseOptions = {}): { packages: PulsePackage[]; levelDb: number; noiseDb: number; snrDb: number; thresholdDb: number; modulation: 'OOK' | 'FSK' | 'none'; truncated: boolean } {
  const rate = r.sampleRate;
  const env = envelope(r, Math.max(3, Math.round(rate * 4e-6)));
  const ob = ookBursts(env, rate, opts);
  const out: PulsePackage[] = [];
  const mode = opts.mode ?? 'auto';
  let fm: Float32Array | undefined;
  let anyFsk = false;
  for (const b of ob.bursts) {
    // FSK keeps the carrier on: test each long carrier pulse for two frequency levels
    const fskParts: PulsePackage[] = [];
    if (mode !== 'ook' && r.q) {
      fm ??= fmDemod(r);
      for (let k = 0; k < b.pulses.length; k++) {
        const len = b.pulses[k] as number;
        if (len < 16 && mode !== 'fsk') continue;
        const one: Burst = { start: b.starts[k] as number, end: (b.starts[k] as number) + len, pulses: [len], gaps: [b.gaps[k] as number], starts: [b.starts[k] as number] };
        const f = fskSplit(fm, one, rate, out.length + fskParts.length, mode === 'fsk', opts);
        if (f) { fskParts.push({ ...f, levelDb: ob.levelDb, noiseDb: ob.noiseDb, snrDb: ob.snrDb }); }
      }
    }
    if (fskParts.length) {
      anyFsk = true;
      out.push(...fskParts);
    } else {
      out.push({ index: out.length, modulation: 'OOK', startSample: b.start, endSample: b.end, pulses: b.pulses, gaps: b.gaps, starts: b.starts, levelDb: ob.levelDb, noiseDb: ob.noiseDb, snrDb: ob.snrDb });
    }
  }
  return { packages: out, levelDb: ob.levelDb, noiseDb: ob.noiseDb, snrDb: ob.snrDb, thresholdDb: ob.thresholdDb, modulation: out.length ? (anyFsk ? 'FSK' : 'OOK') : 'none', truncated: ob.bursts.length >= (opts.maxPackages ?? 500) };
}

/**
 * Inside one carrier burst, split the instantaneous frequency into two levels. Returns undefined
 * when the burst does not look like 2-FSK (a single long carrier with two clear frequency levels).
 */
function fskSplit(fm: Float32Array, b: Burst, rate: number, index: number, force: boolean, opts: PulseOptions): PulsePackage | undefined {
  // FSK keeps the carrier on: a burst made of one long pulse (or few) covering most of its span
  const onTotal = b.pulses.reduce((a, x) => a + x, 0);
  const span = b.end - b.start;
  if (!force && (b.pulses.length > 1 || onTotal < 0.9 * span || span < 16)) return undefined;
  // smooth the frequency a little
  const w = 3;
  const n = span;
  const f = new Float32Array(n);
  let s = 0;
  for (let k = 0; k < n; k++) {
    s += fm[b.start + k] as number;
    if (k >= w) s -= fm[b.start + k - w] as number;
    f[k] = s / Math.min(k + 1, w);
  }
  // ignore edges where the carrier ramps
  const edge = Math.min(4, Math.floor(n / 8));
  const core = f.subarray(edge, n - edge);
  const o = otsu(core);
  const sep = o.separation;
  if (!force && sep < Math.max(2000, rate * 0.01)) return undefined;
  const thr = o.threshold;
  // F1 is the frequency the burst starts on (rtl_433 convention: pulse = F1)
  let startHigh = 0;
  for (let k = edge; k < Math.min(n, edge + 8); k++) startHigh += (f[k] as number) > thr ? 1 : -1;
  const f1High = startHigh >= 0;
  const glitch = Math.max(1, Math.round(((opts.glitchUs ?? 0) * rate) / 1e6) || 2);
  const runs: { isF1: boolean; len: number; start: number }[] = [];
  for (let k = 0; k < n; k++) {
    const isF1 = ((f[k] as number) > thr) === f1High;
    const last = runs[runs.length - 1];
    if (last && last.isF1 === isF1) last.len++;
    else runs.push({ isF1, len: 1, start: b.start + k });
  }
  // merge glitches
  const merged: typeof runs = [];
  for (const run of runs) {
    const last = merged[merged.length - 1];
    if (last && (run.len < glitch || last.isF1 === run.isF1)) { last.len += run.len; continue; }
    merged.push({ ...run });
  }
  while (merged.length && !merged[0]!.isF1) merged.shift();
  const pulses: number[] = [], gaps: number[] = [], starts: number[] = [];
  for (const run of merged) {
    if (run.isF1) { pulses.push(run.len); gaps.push(0); starts.push(run.start); }
    else if (pulses.length) gaps[gaps.length - 1] = (gaps[gaps.length - 1] as number) + run.len;
  }
  if (!pulses.length) return undefined;
  const f1 = f1High ? o.high : o.low, f2 = f1High ? o.low : o.high;
  return { index, modulation: 'FSK', startSample: b.start, endSample: b.end, pulses, gaps, starts, levelDb: 0, noiseDb: 0, snrDb: 0, fsk: { f1Hz: Math.round(f1), f2Hz: Math.round(f2), deviationHz: Math.round(Math.abs(f1 - f2) / 2) } };
}

/** Convert a package's widths to microseconds. */
export function packageMicros(p: PulsePackage, rate: number): { pulsesUs: number[]; gapsUs: number[] } {
  const k = 1e6 / rate;
  return { pulsesUs: p.pulses.map((x) => Math.round(x * k)), gapsUs: p.gaps.map((x) => Math.round(x * k)) };
}
