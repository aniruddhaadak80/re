// Automatic pulse analysis, in the spirit of rtl_433 -A: histogram pulse and gap widths,
// cluster them, guess the line coding (PCM, PPM, PWM, Manchester) and the timing, and emit a
// flex spec that decodes the package.

import type { PulsePackage } from './pulses.js';
import { parseFlexSpec, runFlex, type FlexEvent } from './flex.js';

export interface WidthCluster { meanUs: number; minUs: number; maxUs: number; count: number }
export interface PackageAnalysis {
  package: number; modulation: 'OOK' | 'FSK'; pulseCount: number; startSample: number; timeSec: number;
  pulses: WidthCluster[]; gaps: WidthCluster[]; periods: WidthCluster[];
  guess?: { coding: string; flex: string; reason: string };
  events: FlexEvent[];
  fsk?: { f1Hz: number; f2Hz: number; deviationHz: number };
}

/** Group sorted widths: a value joins the current cluster while it is within 20 percent (plus one sample) of the cluster start. */
export function clusterWidths(values: number[], sampleUs: number, maxClusters = 16): WidthCluster[] {
  const v = values.filter((x) => x > 0).sort((a, b) => a - b);
  const out: { vals: number[] }[] = [];
  for (const x of v) {
    const cur = out[out.length - 1];
    if (cur && x <= (cur.vals[0] as number) * 1.2 + sampleUs) cur.vals.push(x);
    else out.push({ vals: [x] });
  }
  return out.slice(0, maxClusters).map((c) => ({ meanUs: Math.round(c.vals.reduce((a, b) => a + b, 0) / c.vals.length), minUs: Math.round(c.vals[0] as number), maxUs: Math.round(c.vals[c.vals.length - 1] as number), count: c.vals.length }));
}

const near = (a: number, b: number, tol = 0.25): boolean => Math.abs(a - b) <= Math.max(tol * b, 1);

/** Guess coding and timing for one package. */
export function guessCoding(p: PulsePackage, rate: number): PackageAnalysis['guess'] {
  const us = 1e6 / rate;
  const pu = p.pulses.map((x) => x * us);
  const ga = p.gaps.slice(0, -1).map((x) => x * us);
  if (pu.length < 4) return undefined;
  const P = clusterWidths(pu, us).filter((c) => c.count >= Math.max(2, 0.05 * pu.length) || pu.length < 8);
  const Gall = clusterWidths(ga, us);
  if (!P.length) return undefined;
  // data gaps: clusters within 4x of the smallest gap; larger ones are row or message breaks
  const g0 = Gall[0]?.meanUs ?? 0;
  // FSK packages are one carrier burst, so every gap is data
  const G = p.modulation === 'FSK' ? Gall : Gall.filter((c) => c.meanUs <= Math.max(4 * g0, 4 * (P[0]?.meanUs ?? 0)) && c.count >= 2);
  const breaks = Gall.filter((c) => !G.includes(c));
  const pre = p.modulation === 'FSK' ? 'FSK_' : 'OOK_';
  const dataGapMax = Math.max(0, ...G.map((c) => c.maxUs), ...P.map((c) => c.maxUs));
  const rowGap = breaks.length ? Math.min(...breaks.map((c) => c.minUs)) : 0;
  const reset = breaks.length ? Math.round(Math.max(...breaks.map((c) => c.maxUs)) * 0.8 + dataGapMax * 0.2) : Math.round(dataGapMax * 4);
  const r = Math.max(reset, Math.round(dataGapMax * 1.5) + 1);
  const gopt = (gap: number) => (rowGap && rowGap < r ? `,g=${gap}` : '');
  const T = Math.min(P[0]!.meanUs, G[0]?.meanUs ?? Infinity);
  // NRZ bit width: pulses run long and gaps short by the same detector bias, so average them
  const Tn = G[0] ? (P[0]!.meanUs + G[0].meanUs) / 2 : T;
  const fit = (x: number) => { const m = x / Tn; return Math.round(m) >= 1 && Math.abs(m - Math.round(m)) < 0.3; };
  const multiples = (cs: WidthCluster[]) => cs.every((c) => fit(c.meanUs) || (fit(c.minUs) && fit(c.maxUs)));
  const mostlyMultiples = [...pu, ...ga.filter((x) => x <= dataGapMax)].filter(fit).length >= 0.9 * (pu.length + ga.filter((x) => x <= dataGapMax).length);
  const allIn12 = [...P, ...G].every((c) => near(c.meanUs, T) || near(c.meanUs, 2 * T));
  if (P.length >= 1 && G.length >= 1 && allIn12 && [...P, ...G].some((c) => near(c.meanUs, 2 * T)) && p.modulation === 'OOK' && P.length <= 2 && G.length <= 2) {
    return { coding: 'manchester', flex: `n=auto,m=${pre}MC_ZEROBIT,s=${Math.round(T)},l=${Math.round(T)},r=${r}`, reason: `pulses and gaps are one or two half bits of ${Math.round(T)} us` };
  }
  if (P.length === 1 && G.length === 2) {
    const s = G[0]!.meanUs, l = G[1]!.meanUs;
    return { coding: 'ppm', flex: `n=auto,m=${pre}PPM,s=${s},l=${l},g=${Math.round(l * 1.5 + s * 0.5)},r=${r}`, reason: `one pulse width (${P[0]!.meanUs} us) and two gap widths (${s}, ${l} us)` };
  }
  if (P.length >= 2 && P.length <= 3 && !(multiples(P) && multiples(G) && G.length >= 2 && P.length === 2 && near(P[1]!.meanUs, 2 * T) && near(G[1]!.meanUs, 2 * T) && p.modulation === 'FSK')) {
    const s = P[0]!.meanUs, l = P[1]!.meanUs;
    const periods = pu.map((x, k) => x + (ga[k] ?? 0)).filter((x, k) => k < ga.length);
    const per = clusterWidths(periods, us);
    if (per.filter((c) => c.count >= Math.max(2, 0.05 * periods.length)).length <= 2) {
      const sync = P.length === 3 ? `,y=${P[2]!.meanUs}` : '';
      return { coding: 'pwm', flex: `n=auto,m=${pre}PWM,s=${s},l=${l}${sync}${gopt(Math.round(dataGapMax * 1.5))},r=${r}`, reason: `two pulse widths (${s}, ${l} us)${sync ? ' plus a sync width' : ''}, steady period` };
    }
  }
  if ((multiples(P) && multiples(G)) || mostlyMultiples) {
    return { coding: 'pcm', flex: `n=auto,m=${pre}PCM,s=${Math.round(Tn)},l=${Math.round(Tn)},g=${Math.round(dataGapMax + Tn)},r=${r}`, reason: `pulses and gaps are whole multiples of ${Math.round(Tn)} us` };
  }
  if (P.length === 1) {
    const per = clusterWidths(pu.map((x, k) => x + (ga[k] ?? 0)).filter((_, k) => k < ga.length), us);
    if (per.length >= 1) return { coding: 'rz', flex: `n=auto,m=${pre}PCM,s=${P[0]!.meanUs},l=${per[0]!.meanUs},r=${r}`, reason: 'one pulse width with a fixed bit period (RZ)' };
  }
  return undefined;
}

/** Analyze packages: width histograms, coding guess and the bits the guess decodes. */
export function analyzePackages(packages: PulsePackage[], rate: number, opts: { maxPackages?: number } = {}): PackageAnalysis[] {
  const us = 1e6 / rate;
  const out: PackageAnalysis[] = [];
  for (const p of packages.slice(0, opts.maxPackages ?? 50)) {
    const pu = p.pulses.map((x) => x * us), ga = p.gaps.slice(0, -1).map((x) => x * us);
    const guess = guessCoding(p, rate);
    let events: FlexEvent[] = [];
    if (guess) { try { events = runFlex(parseFlexSpec(guess.flex), [p], rate, { maxEvents: 20 }); } catch { events = []; } }
    out.push({
      package: p.index, modulation: p.modulation, pulseCount: p.pulses.length, startSample: p.startSample, timeSec: Math.round((p.startSample / rate) * 1e6) / 1e6,
      pulses: clusterWidths(pu, us), gaps: clusterWidths(ga, us), periods: clusterWidths(pu.map((x, k) => x + (ga[k] ?? 0)).filter((_, k) => k < ga.length), us),
      ...(guess ? { guess } : {}), events, ...(p.fsk ? { fsk: p.fsk } : {}),
    });
  }
  return out;
}
