// Signal recording decoders: read SigMF, WAV and raw IQ, summarize the spectrum, detect OOK and
// 2-FSK pulses, slice bits with PCM/PPM/PWM/Manchester rules, and run rtl_433 style flex specs.
// Logic analyzer captures (sigrok .sr) are decoded by ./logic.ts.

import { readRecording, recordingStats, type Recording, type ReadOptions } from './recording.js';
import { spectrumSummary } from './dsp.js';
import { detectPulses, packageMicros, type PulseOptions } from './pulses.js';
import { parseFlexSpec, runFlex, MODULATIONS, type FlexEvent } from './flex.js';
import { analyzePackages } from './analyze.js';
import { LOGIC_DECODERS } from './logic.js';

export * from './recording.js';
export * from './dsp.js';
export * from './pulses.js';
export * from './slicers.js';
export * from './flex.js';
export * from './analyze.js';
export * from './logic.js';

/** What the signal decoders can read and decode (the inspect_signal_decoders catalog). */
export function inspectSignalDecoders(): {
  inputs: { container: string; formats: string[]; notes: string }[];
  modulations: { name: string; description: string }[];
  flexKeys: { key: string; description: string }[];
  logicDecoders: { id: string; description: string; options: string[] }[];
  outputs: string[];
} {
  return {
    inputs: [
      { container: 'raw IQ', formats: ['cu8', 'cs8', 'cs16', 'cu16', 'cs32', 'cf32 (.cfile, .fc32)', 'cf64', 'real u8/s8/s16/f32'], notes: 'rate and center frequency from options or an rtl_433 style name such as g001_433.92M_250k.cu8' },
      { container: 'WAV', formats: ['PCM 8/16/24/32 bit', 'float 32/64', 'stereo = I/Q, mono = real', 'auxi chunk center frequency'], notes: 'sample rate from the fmt chunk' },
      { container: 'SigMF', formats: ['.sigmf-meta + .sigmf-data', '.sigmf tar archive', 'ci/cu/cf/ri/ru/rf 8-64 bit, _le or _be'], notes: 'captures and annotations are reported' },
      { container: 'sigrok session (.sr)', formats: ['logic channels (unitsize 1-8 bytes)', 'metadata samplerate and probe names'], notes: 'decoded with the logic decoders below' },
    ],
    modulations: Object.entries(MODULATIONS).map(([name, m]) => ({ name, description: m.desc })),
    flexKeys: [
      { key: 'n=<name>', description: 'model name in the output' },
      { key: 'm=<modulation>', description: 'one of the modulations above' },
      { key: 's=<us>, l=<us>, y=<us>', description: 'short, long and sync widths in microseconds' },
      { key: 'r=<us>, g=<us>, t=<us>', description: 'reset (message end), gap (row break) and tolerance' },
      { key: 'bits>=n, bits<=n, bits=n, rows>=n, rows<=n, repeats>=n', description: 'row filters' },
      { key: 'match={n}hex, preamble={n}hex', description: 'keep rows holding a pattern; preamble also aligns the row after it' },
      { key: 'invert, reflect, unique, countonly', description: 'bit transforms and output control' },
      { key: 'decode_mc, decode_mc_thomas, decode_dm, decode_uart', description: 'second stage decoding of each row' },
      { key: 'get=@offset:{bits}:name[:[v:text ...]]', description: 'extract a field (optionally mapped to text) from each row' },
    ],
    logicDecoders: LOGIC_DECODERS,
    outputs: ['recording facts and level statistics', 'spectrum summary (Welch FFT, peaks with absolute frequency, occupied bandwidth, plot points)', 'pulse packages with widths in microseconds', 'automatic coding guess with a ready flex spec', 'bit rows as rtl_433 style codes {len}hex with sample offsets'],
  };
}

export interface DecodeSignalOptions extends ReadOptions, PulseOptions {
  data?: Uint8Array;
  /** One or more flex specs to run. */
  flex?: string | string[];
  spectrum?: boolean;
  fftSize?: number;
  analyze?: boolean;
  /** Include per-package widths (first N pulses) in the output. */
  pulseDetail?: number;
}

/** Decode an RF recording: facts, spectrum, pulses, automatic analysis and flex decoding. */
export function decodeSignalRecording(bytes: Uint8Array, opts: DecodeSignalOptions = {}): {
  recording: Omit<Recording, 'i' | 'q'> & { stats: ReturnType<typeof recordingStats> };
  spectrum?: ReturnType<typeof spectrumSummary>;
  pulses: { modulation: string; levelDb: number; noiseDb: number; snrDb: number; thresholdDb: number; packageCount: number; truncated: boolean; packages: { index: number; modulation: string; startSample: number; timeSec: number; pulses: number; durationUs: number; fsk?: { f1Hz: number; f2Hz: number; deviationHz: number }; pulsesUs?: number[]; gapsUs?: number[] }[] };
  analysis?: ReturnType<typeof analyzePackages>;
  decoded: { spec: string; model: string; events: FlexEvent[]; error?: string }[];
} {
  const rec = readRecording(bytes, opts);
  const { i: _i, q: _q, ...facts } = rec;
  void _i; void _q;
  const det = detectPulses(rec, opts);
  const us = 1e6 / rec.sampleRate;
  const detail = Math.max(0, Math.min(2000, opts.pulseDetail ?? 0));
  const packages = det.packages.slice(0, 200).map((p) => {
    const m = detail ? packageMicros(p, rec.sampleRate) : undefined;
    return {
      index: p.index, modulation: p.modulation, startSample: p.startSample, timeSec: Math.round((p.startSample / rec.sampleRate) * 1e6) / 1e6, pulses: p.pulses.length,
      durationUs: Math.round((p.endSample - p.startSample) * us), ...(p.fsk ? { fsk: p.fsk } : {}),
      ...(m ? { pulsesUs: m.pulsesUs.slice(0, detail), gapsUs: m.gapsUs.slice(0, detail) } : {}),
    };
  });
  const specs = opts.flex === undefined ? [] : Array.isArray(opts.flex) ? opts.flex.slice(0, 32) : [opts.flex];
  const decoded = specs.map((s) => {
    try {
      const spec = parseFlexSpec(String(s));
      const pk = det.packages.filter((p) => (spec.modulation.startsWith('FSK') ? p.modulation === 'FSK' : p.modulation === 'OOK'));
      return { spec: String(s), model: spec.name, events: runFlex(spec, pk, rec.sampleRate) };
    } catch (e) {
      return { spec: String(s), model: '', events: [], error: (e as Error).message };
    }
  });
  return {
    recording: { ...facts, stats: recordingStats(rec) },
    ...(opts.spectrum !== false ? { spectrum: spectrumSummary(rec, { fftSize: opts.fftSize }) } : {}),
    pulses: { modulation: det.modulation, levelDb: det.levelDb, noiseDb: det.noiseDb, snrDb: det.snrDb, thresholdDb: det.thresholdDb, packageCount: det.packages.length, truncated: det.truncated, packages },
    ...(opts.analyze !== false ? { analysis: analyzePackages(det.packages, rec.sampleRate) } : {}),
    decoded,
  };
}
