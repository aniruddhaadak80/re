// Small DSP helpers for signal recordings: radix-2 FFT, averaged power spectrum with peak
// finding, AM envelope and FM (phase difference) demodulation. Pure TypeScript.

import type { Recording } from './recording.js';

/** In-place iterative radix-2 complex FFT. Length must be a power of two. */
export function fft(re: Float64Array, im: Float64Array): void {
  const n = re.length;
  if (n !== im.length || (n & (n - 1)) !== 0) throw new Error('fft length must be a power of two');
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      const tr = re[i] as number; re[i] = re[j] as number; re[j] = tr;
      const ti = im[i] as number; im[i] = im[j] as number; im[j] = ti;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = (-2 * Math.PI) / len;
    const wr = Math.cos(ang), wi = Math.sin(ang);
    const half = len >> 1;
    for (let i = 0; i < n; i += len) {
      let cr = 1, ci = 0;
      for (let k = 0; k < half; k++) {
        const a = i + k, b = a + half;
        const xr = (re[b] as number) * cr - (im[b] as number) * ci;
        const xi = (re[b] as number) * ci + (im[b] as number) * cr;
        re[b] = (re[a] as number) - xr; im[b] = (im[a] as number) - xi;
        re[a] = (re[a] as number) + xr; im[a] = (im[a] as number) + xi;
        const t = cr * wr - ci * wi;
        ci = cr * wi + ci * wr;
        cr = t;
      }
    }
  }
}

export interface SpectrumPeak { bin: number; offsetHz: number; frequencyHz?: number; powerDb: number; aboveFloorDb: number }
export interface SpectrumSummary {
  fftSize: number; segments: number; window: 'hann'; binHz: number; sampleRate: number; centerFreq?: number;
  noiseFloorDb: number; maxDb: number; peaks: SpectrumPeak[];
  /** Occupied bandwidth estimate around the strongest peak (bins within 20 dB of it, contiguous). */
  occupiedBandwidthHz?: number;
  /** Downsampled power spectrum for plotting: [offsetHz, dB] pairs from -fs/2 to +fs/2. */
  plot: [number, number][];
}

/**
 * Welch style averaged spectrum (Hann window, 50 percent overlap) over at most maxSegments
 * segments spread across the recording, with local maxima above the noise floor as peaks.
 */
export function spectrumSummary(r: Recording, opts: { fftSize?: number; maxSegments?: number; maxPeaks?: number; minAboveFloorDb?: number; startSample?: number; endSample?: number; plotPoints?: number } = {}): SpectrumSummary {
  let n = 1 << Math.round(Math.log2(Math.max(64, Math.min(65536, opts.fftSize ?? 4096))));
  const start = Math.max(0, Math.min(r.samples, opts.startSample ?? 0));
  const end = Math.max(start, Math.min(r.samples, opts.endSample ?? r.samples));
  const avail = end - start;
  while (n > 64 && n > avail) n >>= 1;
  const win = new Float64Array(n);
  let wsum = 0;
  for (let k = 0; k < n; k++) { win[k] = 0.5 - 0.5 * Math.cos((2 * Math.PI * k) / (n - 1)); wsum += win[k] as number; }
  const hop = n >> 1;
  const possible = avail >= n ? Math.floor((avail - n) / hop) + 1 : avail > 0 ? 1 : 0;
  const segs = Math.min(possible, Math.max(1, opts.maxSegments ?? 256));
  const step = segs > 1 ? Math.floor((avail - n) / (segs - 1)) : 0;
  const acc = new Float64Array(n);
  const re = new Float64Array(n), im = new Float64Array(n);
  for (let s = 0; s < segs; s++) {
    const base = start + s * step;
    for (let k = 0; k < n; k++) {
      const idx = base + k;
      const w = win[k] as number;
      re[k] = idx < end ? (r.i[idx] as number) * w : 0;
      im[k] = idx < end && r.q ? (r.q[idx] as number) * w : 0;
    }
    fft(re, im);
    for (let k = 0; k < n; k++) acc[k] = (acc[k] as number) + (re[k] as number) ** 2 + (im[k] as number) ** 2;
  }
  // shift so index 0 is -fs/2
  const db = new Float64Array(n);
  const norm = segs > 0 ? segs * wsum * wsum : 1;
  for (let k = 0; k < n; k++) {
    const src = (k + (n >> 1)) % n;
    const p = (acc[src] as number) / norm;
    db[k] = p > 0 ? 10 * Math.log10(p) : -200;
  }
  const binHz = r.sampleRate / n;
  const sorted = Array.from(db).sort((a, b) => a - b);
  const floor = sorted[Math.floor(sorted.length / 2)] ?? -200;
  const maxDb = sorted[sorted.length - 1] ?? -200;
  const minAbove = opts.minAboveFloorDb ?? 10;
  const cand: SpectrumPeak[] = [];
  // real recordings: only the positive half is meaningful
  const from = r.complex ? 1 : n >> 1;
  for (let k = from; k < n - 1; k++) {
    const v = db[k] as number;
    if (v - floor < minAbove) continue;
    if (v >= (db[k - 1] as number) && v > (db[k + 1] as number)) {
      // parabolic interpolation for a finer frequency
      const a = db[k - 1] as number, c = db[k + 1] as number;
      const den = a - 2 * v + c;
      const delta = den !== 0 ? Math.max(-0.5, Math.min(0.5, (0.5 * (a - c)) / den)) : 0;
      const offsetHz = (k + delta - (n >> 1)) * binHz;
      cand.push({ bin: k - (n >> 1), offsetHz: Math.round(offsetHz * 10) / 10, ...(r.centerFreq !== undefined ? { frequencyHz: Math.round(r.centerFreq + offsetHz) } : {}), powerDb: Math.round(v * 100) / 100, aboveFloorDb: Math.round((v - floor) * 100) / 100 });
    }
  }
  cand.sort((a, b) => b.powerDb - a.powerDb);
  // drop peaks within 1 percent of the band of a stronger one (window sidelobes, modulation sidebands)
  const peaks: SpectrumPeak[] = [];
  for (const p of cand) {
    if (peaks.some((q) => Math.abs(q.bin - p.bin) <= Math.max(3, Math.round(n / 100)))) continue;
    peaks.push(p);
    if (peaks.length >= (opts.maxPeaks ?? 10)) break;
  }
  let occupiedBandwidthHz: number | undefined;
  const top = peaks[0];
  if (top) {
    const idx = top.bin + (n >> 1);
    let lo = idx, hi = idx;
    while (lo > 0 && (db[lo - 1] as number) >= top.powerDb - 20) lo--;
    while (hi < n - 1 && (db[hi + 1] as number) >= top.powerDb - 20) hi++;
    occupiedBandwidthHz = Math.round((hi - lo + 1) * binHz);
  }
  const pts = Math.max(16, Math.min(1024, opts.plotPoints ?? 256));
  const plot: [number, number][] = [];
  const group = Math.max(1, Math.floor(n / pts));
  for (let k = 0; k + group <= n; k += group) {
    let m = -200;
    for (let j = k; j < k + group; j++) m = Math.max(m, db[j] as number);
    plot.push([Math.round((k + group / 2 - (n >> 1)) * binHz), Math.round(m * 10) / 10]);
  }
  return { fftSize: n, segments: segs, window: 'hann', binHz, sampleRate: r.sampleRate, ...(r.centerFreq !== undefined ? { centerFreq: r.centerFreq } : {}), noiseFloorDb: Math.round(floor * 100) / 100, maxDb: Math.round(maxDb * 100) / 100, peaks, ...(occupiedBandwidthHz !== undefined ? { occupiedBandwidthHz } : {}), plot };
}

/** AM envelope (magnitude). For real recordings the absolute value, smoothed over `smooth` samples. */
export function envelope(r: Recording, smooth = 1): Float32Array {
  const n = r.samples;
  const e = new Float32Array(n);
  for (let k = 0; k < n; k++) {
    const a = r.i[k] as number, b = r.q ? (r.q[k] as number) : 0;
    e[k] = r.q ? Math.sqrt(a * a + b * b) : Math.abs(a);
  }
  const w = Math.max(1, Math.floor(smooth));
  if (w <= 1) return e;
  const out = new Float32Array(n);
  let s = 0;
  for (let k = 0; k < n; k++) {
    s += e[k] as number;
    if (k >= w) s -= e[k - w] as number;
    out[k] = s / Math.min(k + 1, w);
  }
  return out;
}

/** Instantaneous frequency in Hz from the phase difference of consecutive IQ samples. */
export function fmDemod(r: Recording): Float32Array {
  const n = r.samples;
  const f = new Float32Array(n);
  if (!r.q) return f;
  const scale = r.sampleRate / (2 * Math.PI);
  for (let k = 1; k < n; k++) {
    const a = r.i[k] as number, b = r.q[k] as number, c = r.i[k - 1] as number, d = r.q[k - 1] as number;
    // x[k] * conj(x[k-1])
    const re = a * c + b * d, im = b * c - a * d;
    f[k] = Math.atan2(im, re) * scale;
  }
  f[0] = f[1] ?? 0;
  return f;
}

/** Otsu threshold over values (on a capped, evenly spaced subset). Returns the threshold and the class means. */
export function otsu(values: ArrayLike<number>, bins = 256, maxSamples = 400_000): { threshold: number; low: number; high: number; separation: number } {
  const n = values.length;
  if (!n) return { threshold: 0, low: 0, high: 0, separation: 0 };
  const step = Math.max(1, Math.floor(n / maxSamples));
  let mn = Infinity, mx = -Infinity;
  for (let k = 0; k < n; k += step) { const v = values[k] as number; if (v < mn) mn = v; if (v > mx) mx = v; }
  if (!(mx > mn)) return { threshold: mn, low: mn, high: mn, separation: 0 };
  const h = new Float64Array(bins);
  let total = 0;
  for (let k = 0; k < n; k += step) { const v = values[k] as number; const b = Math.min(bins - 1, Math.floor(((v - mn) / (mx - mn)) * bins)); h[b] = (h[b] as number) + 1; total++; }
  let sumAll = 0;
  for (let b = 0; b < bins; b++) sumAll += b * (h[b] as number);
  let wB = 0, sumB = 0, best = -1, bestT = 0;
  for (let t = 0; t < bins - 1; t++) {
    wB += h[t] as number;
    if (!wB) continue;
    const wF = total - wB;
    if (!wF) break;
    sumB += t * (h[t] as number);
    const mB = sumB / wB, mF = (sumAll - sumB) / wF;
    const between = wB * wF * (mB - mF) ** 2;
    if (between > best) { best = between; bestT = t; }
  }
  let lo = 0, loN = 0, hi = 0, hiN = 0;
  for (let b = 0; b < bins; b++) { if (b <= bestT) { lo += b * (h[b] as number); loN += h[b] as number; } else { hi += b * (h[b] as number); hiN += h[b] as number; } }
  const toV = (b: number) => mn + ((b + 0.5) / bins) * (mx - mn);
  const low = toV(loN ? lo / loN : 0), high = toV(hiN ? hi / hiN : bins - 1);
  return { threshold: mn + ((bestT + 1) / bins) * (mx - mn), low, high, separation: high - low };
}
