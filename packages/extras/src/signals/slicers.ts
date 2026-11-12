// Bit slicers that turn pulse packages into bit rows: PCM (NRZ and RZ), PPM, PWM, Manchester
// (zero bit start, as in rtl_433 OOK_MC_ZEROBIT) and differential Manchester. The timing rules
// follow the behaviour rtl_433 documents for its flex decoder so specs carry over; the code is
// an independent TypeScript implementation.

import type { PulsePackage } from './pulses.js';

export const MAX_ROWS = 50;
export const MAX_ROW_BITS = 4096;

/** Rows of bits, like rtl_433's bitbuffer. */
export class BitBuffer {
  rows: number[][] = [[]];
  syncs: number[] = [0];
  add(bit: number): void {
    const row = this.rows[this.rows.length - 1] as number[];
    if (row.length < MAX_ROW_BITS) row.push(bit ? 1 : 0);
  }
  newRow(): void {
    if (this.rows.length >= MAX_ROWS) return;
    if ((this.rows[this.rows.length - 1] as number[]).length === 0) return;
    this.rows.push([]);
    this.syncs.push(0);
  }
  /** Sync marks a row boundary only when the row already has bits (rtl_433 adds a row too). */
  sync(): void {
    const last = this.rows.length - 1;
    if ((this.rows[last] as number[]).length) this.newRow();
    this.syncs[this.rows.length - 1] = (this.syncs[this.rows.length - 1] as number) + 1;
  }
  clear(): void { this.rows = [[]]; this.syncs = [0]; }
  get bitCount(): number { return this.rows.reduce((a, r) => a + r.length, 0); }
  /** Rows as reported: drop a trailing empty row. */
  snapshot(): number[][] {
    const r = this.rows.map((x) => x.slice());
    while (r.length > 1 && (r[r.length - 1] as number[]).length === 0) r.pop();
    return r;
  }
}

/** Hex text for a bit row, MSB first, padded with zero bits to a whole nibble... like rtl_433 (to whole bytes). */
export function rowHex(bits: number[]): string {
  let s = '';
  for (let k = 0; k < bits.length; k += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | (bits[k + j] ?? 0);
    s += v.toString(16).padStart(2, '0');
  }
  // rtl_433 prints only the nibbles that hold bits
  return s.slice(0, Math.ceil(bits.length / 4));
}
export const rowCode = (bits: number[]): string => `{${bits.length}}${rowHex(bits)}`;

export type Modulation =
  | 'OOK_PCM' | 'OOK_RZ' | 'OOK_PPM' | 'OOK_PWM' | 'OOK_MC_ZEROBIT' | 'OOK_DMC'
  | 'FSK_PCM' | 'FSK_PWM' | 'FSK_PPM' | 'FSK_MC_ZEROBIT' | 'FSK_DMC';

export interface SlicerTiming {
  /** Short width in microseconds (PCM: bit width, PWM: 1 pulse, PPM: 0 gap, MC: half bit). */
  short: number;
  long: number;
  /** Sync width (PWM/PPM). */
  sync?: number;
  /** Gap that ends a message (microseconds). */
  reset: number;
  /** Gap that starts a new row inside a message. */
  gap?: number;
  tolerance?: number;
}

export interface SlicedEvent { rows: number[][]; startSample: number; endSample: number; package: number }

function scaled(t: SlicerTiming, rate: number) {
  const k = rate / 1e6;
  return { s: t.short * k, l: t.long * k, y: (t.sync ?? 0) * k, r: t.reset * k, g: (t.gap ?? 0) * k, tol: (t.tolerance ?? 0) * k };
}

/** Run one slicer over packages and collect events (a message ends at the package end or a gap above reset). */
export function slice(packages: PulsePackage[], mod: Modulation, t: SlicerTiming, rate: number, maxEvents = 1000): SlicedEvent[] {
  const events: SlicedEvent[] = [];
  const base = mod.replace(/^(OOK|FSK)_/, '');
  for (const p of packages) {
    if (events.length >= maxEvents) break;
    const emit = (bb: BitBuffer, from: number, to: number) => {
      if (events.length < maxEvents && bb.bitCount > 0) events.push({ rows: bb.snapshot(), startSample: p.starts[from] ?? p.startSample, endSample: (p.starts[to] ?? p.startSample) + (p.pulses[to] ?? 0), package: p.index });
    };
    if (base === 'PCM' || base === 'RZ') pcm(p, t, rate, base === 'RZ', emit);
    else if (base === 'PPM') ppm(p, t, rate, emit);
    else if (base === 'PWM') pwm(p, t, rate, emit);
    else if (base === 'MC_ZEROBIT') manchesterZero(p, t, rate, emit);
    else if (base === 'DMC') dmc(p, t, rate, emit);
  }
  return events;
}

type Emit = (bb: BitBuffer, from: number, to: number) => void;

function pcm(p: PulsePackage, t: SlicerTiming, rate: number, rzForced: boolean, emit: Emit): void {
  const { s, l, r, g, tol: tol0 } = scaled(t, rate);
  if (s <= 0 || l <= 0) return;
  const rz = rzForced || Math.abs(s - l) > 1e-9;
  const tol = tol0 > 0 ? tol0 : l / 4;
  const gapLimit = g > 0 ? g : r;
  const maxZeros = Math.floor(gapLimit / l);
  let fS = 1 / s, fL = 1 / l;
  // refine the bit period from pulses and gaps that are clearly one or two bits (NRZ) or full RZ periods
  const n = p.pulses.length;
  if (!rz) {
    let width = 0, count = 0;
    for (let k = 0; k < n; k++) {
      const pu = p.pulses[k] as number, ga = p.gaps[k] as number;
      for (const m of [1, 2]) { if (Math.abs(pu - m * s) <= tol) { width += pu; count += m; } }
      if (k < n - 1) for (const m of [1, 2]) { if (Math.abs(ga - m * l) <= tol) { width += ga; count += m; } }
    }
    if (count > 20) fS = fL = count / width;
  } else {
    let sw = 0, lw = 0, count = 0;
    for (let k = 0; k < n; k++) {
      const pu = p.pulses[k] as number, per = pu + (p.gaps[k] as number);
      if (Math.abs(pu - s) <= tol && Math.abs(per - l) <= tol) { sw += pu; lw += per; count++; }
    }
    if (count > 8) { fS = count / sw; fL = count / lw; }
  }
  let bb = new BitBuffer();
  let from = 0;
  for (let k = 0; k < n; k++) {
    const pu = p.pulses[k] as number, ga = p.gaps[k] as number;
    const highs = Math.floor(pu * fS + 0.5);
    let lows = Math.floor((rz ? ga + s - l : ga) * fL + 0.5);
    for (let i = 0; i < highs; i++) bb.add(1);
    lows = Math.min(lows, maxZeros);
    for (let i = 0; i < lows; i++) bb.add(0);
    if (rz && Math.abs(pu - s) > tol) { bb.clear(); from = k + 1; }
    else if (ga > gapLimit && ga <= r) bb.newRow();
    if (k === n - 1 || ga > r) {
      emit(bb, from, k);
      bb = new BitBuffer();
      from = k + 1;
    }
  }
}

function ppm(p: PulsePackage, t: SlicerTiming, rate: number, emit: Emit): void {
  const { s, l, y, r, g, tol } = scaled(t, rate);
  let zl: number, zu: number, ol: number, ou: number, yl = 0, yu = 0;
  if (tol > 0) { zl = s - tol; zu = s + tol; ol = l - tol; ou = l + tol; if (y > 0) { yl = y - tol; yu = y + tol; } }
  else { zl = 0; zu = (s + l) / 2 + 1; ol = zu - 1; ou = g > 0 ? g : r; }
  let bb = new BitBuffer();
  let from = 0;
  const n = p.pulses.length;
  for (let k = 0; k < n; k++) {
    const ga = p.gaps[k] as number;
    if (ga > zl && ga < zu) bb.add(0);
    else if (ga > ol && ga < ou) bb.add(1);
    else if (ga > yl && ga < yu) bb.sync();
    else if (ga < r) bb.newRow();
    if (k === n - 1 || ga >= r) { emit(bb, from, k); bb = new BitBuffer(); from = k + 1; }
  }
}

function pwm(p: PulsePackage, t: SlicerTiming, rate: number, emit: Emit): void {
  const { s, l, y, r, g, tol } = scaled(t, rate);
  let ol: number, ou: number, zl: number, zu: number, yl = 0, yu = 0;
  const INF = Number.POSITIVE_INFINITY;
  if (tol > 0) { ol = s - tol; ou = s + tol; zl = l - tol; zu = l + tol; if (y > 0) { yl = y - tol; yu = y + tol; } }
  else if (y <= 0) { ol = 0; ou = (s + l) / 2 + 1; zl = ou - 1; zu = INF; }
  else if (y < s) { yl = 0; yu = (y + s) / 2 + 1; ol = yu - 1; ou = (s + l) / 2 + 1; zl = ou - 1; zu = INF; }
  else if (y < l) { ol = 0; ou = (s + y) / 2 + 1; yl = ou - 1; yu = (y + l) / 2 + 1; zl = yu - 1; zu = INF; }
  else { ol = 0; ou = (s + l) / 2 + 1; zl = ou - 1; zu = (l + y) / 2 + 1; yl = zu - 1; yu = INF; }
  let bb = new BitBuffer();
  let from = 0;
  const n = p.pulses.length;
  for (let k = 0; k < n; k++) {
    const pu = p.pulses[k] as number, ga = p.gaps[k] as number;
    if (pu > ol && pu < ou) bb.add(1);
    else if (pu > zl && pu < zu) bb.add(0);
    else if (pu > yl && pu < yu) bb.sync();
    else if (pu <= ol) { /* spurious short pulse */ }
    else bb.newRow();
    if (k === n - 1 || ga > r) { emit(bb, from, k); bb = new BitBuffer(); from = k + 1; }
    else if (g > 0 && ga > g) bb.newRow();
  }
}

/** Manchester with an implied leading zero bit: a falling edge in mid bit is 1, a rising edge is 0. */
function manchesterZero(p: PulsePackage, t: SlicerTiming, rate: number, emit: Emit): void {
  const { s, r, tol } = scaled(t, rate);
  let bb = new BitBuffer();
  bb.add(0);
  let since = 0, from = 0;
  const n = p.pulses.length;
  for (let k = 0; k < n; k++) {
    const pu = p.pulses[k] as number, ga = p.gaps[k] as number;
    if (tol > 0 && (pu < s - tol || pu > 2 * s + tol || ga < s - tol || ga > 2 * s + tol)) {
      if (pu > s * 1.5 && pu <= 2 * s + tol) bb.add(1);
      bb.newRow();
      bb.add(0);
      since = 0;
    } else if (pu + since > s * 1.5) { bb.add(1); since = 0; }
    else since += pu;
    if (k === n - 1 || ga > r) {
      emit(bb, from, k);
      bb = new BitBuffer();
      bb.add(0);
      since = 0;
      from = k + 1;
    } else if (ga + since > s * 1.5) { bb.add(0); since = 0; }
    else since += ga;
  }
}

/** Differential Manchester: a transition in mid bit means 0, no mid bit transition means 1 (short = half bit). */
function dmc(p: PulsePackage, t: SlicerTiming, rate: number, emit: Emit): void {
  const { s, l, r, tol: tol0 } = scaled(t, rate);
  const tol = tol0 > 0 ? tol0 : s / 2;
  let bb = new BitBuffer();
  let from = 0, half = false;
  const n = p.pulses.length;
  const step = (w: number) => {
    if (Math.abs(w - s) <= tol) { if (half) { bb.add(0); half = false; } else half = true; }
    else if (Math.abs(w - l) <= tol) { if (half) { bb.newRow(); half = false; } else bb.add(1); }
    else { bb.newRow(); half = false; }
  };
  for (let k = 0; k < n; k++) {
    step(p.pulses[k] as number);
    const ga = p.gaps[k] as number;
    if (k === n - 1 || ga > r) { emit(bb, from, k); bb = new BitBuffer(); from = k + 1; half = false; }
    else step(ga);
  }
}

/** Decode Manchester pairs in a row (IEEE 802.3: 01 is 1, 10 is 0; G. E. Thomas with thomas=true). Stops at the first invalid pair. */
export function manchesterDecode(bits: number[], thomas = false): number[] {
  const out: number[] = [];
  for (let k = 0; k + 1 < bits.length; k += 2) {
    const a = bits[k], b = bits[k + 1];
    if (a === b) break;
    out.push(thomas ? (a === 1 ? 1 : 0) : (a === 0 ? 1 : 0));
  }
  return out;
}

/** Decode a differential Manchester encoded row (pairs; equal halves are invalid). */
export function dmDecode(bits: number[]): number[] {
  const out: number[] = [];
  let prev = 1;
  for (let k = 0; k + 1 < bits.length; k += 2) {
    const a = bits[k] as number, b = bits[k + 1] as number;
    if (a === b) break;
    out.push(a === prev ? 0 : 1);
    prev = b;
  }
  return out;
}

/** UART framing inside a bit row: start bit 0, 8 data bits LSB first, stop bit 1. */
export function uartDecode(bits: number[], dataBits = 8): { bytes: number[]; errors: number } {
  const bytes: number[] = [];
  let errors = 0;
  for (let k = 0; k + dataBits + 2 <= bits.length; ) {
    if (bits[k] !== 0) { k++; continue; }
    let v = 0;
    for (let j = 0; j < dataBits; j++) v |= (bits[k + 1 + j] as number) << j;
    if (bits[k + 1 + dataBits] !== 1) { errors++; k++; continue; }
    bytes.push(v);
    k += dataBits + 2;
  }
  return { bytes, errors };
}
