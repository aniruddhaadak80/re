// Signal recording readers: raw IQ (cu8, cs8, cs16, cf32, and a few rarer sample types),
// WAV (PCM 8/16/24/32 bit and float, mono as real samples, stereo as I/Q), and SigMF
// (a .sigmf-meta JSON next to its .sigmf-data, or a .sigmf tar archive holding both).
// Everything is browser safe; callers pass bytes. All sizes are capped.

import { ParseError, utf8, latin1 } from '../util.js';

export type SampleFormat = 'cu8' | 'cs8' | 'cs16' | 'cu16' | 'cs32' | 'cf32' | 'cf64' | 'ru8' | 'rs8' | 'rs16' | 'rf32';

export interface SigmfAnnotation { sampleStart: number; sampleCount?: number; label?: string; comment?: string; freqLower?: number; freqUpper?: number }
export interface SigmfInfo {
  version?: string; datatype: string; sampleRate?: number; description?: string; author?: string; hw?: string; license?: string; recorder?: string;
  captures: { sampleStart: number; frequency?: number; datetime?: string }[];
  annotations: SigmfAnnotation[];
  extensions?: string[];
  numChannels?: number;
}

export interface Recording {
  container: 'raw' | 'wav' | 'sigmf';
  format: SampleFormat;
  sampleRate: number;
  /** Center frequency in Hz when the container or the file name says it. */
  centerFreq?: number;
  complex: boolean;
  /** In-phase (or real) samples scaled to about -1..1. */
  i: Float32Array;
  /** Quadrature samples, absent for real recordings. */
  q?: Float32Array;
  samples: number;
  durationSec: number;
  truncated: boolean;
  sigmf?: SigmfInfo;
  wav?: { channels: number; bitsPerSample: number; audioFormat: number; dataOffset: number; dataSize: number };
  notes: string[];
}

export const MAX_SAMPLES = 20_000_000;
const BYTES_PER: Record<SampleFormat, number> = { cu8: 2, cs8: 2, cs16: 4, cu16: 4, cs32: 8, cf32: 8, cf64: 16, ru8: 1, rs8: 1, rs16: 2, rf32: 4 };

/** Sample format from a file extension (rtl_433, GNU Radio and SDR++ names). */
export function formatFromName(name: string): SampleFormat | undefined {
  const m = /\.([a-z0-9]{2,6})$/i.exec(name);
  const ext = m ? (m[1] as string).toLowerCase() : '';
  const map: Record<string, SampleFormat> = {
    cu8: 'cu8', data: 'cu8', complex16u: 'cu8', cs8: 'cs8', complex16s: 'cs16', cs16: 'cs16', cu16: 'cu16', cs32: 'cs32', cf32: 'cf32', cfile: 'cf32', fc32: 'cf32', complex: 'cf32', cf64: 'cf64',
    u8: 'ru8', s8: 'rs8', s16: 'rs16', f32: 'rf32',
  };
  return map[ext];
}

/** rtl_433 file name hints: g001_433.92M_250k.cu8 gives 433.92 MHz center and 250 kHz rate. */
export function hintsFromName(name: string): { sampleRate?: number; centerFreq?: number } {
  const base = name.split(/[\\/]/).pop() ?? name;
  const stem = base.replace(/\.[^.]*$/, '');
  const out: { sampleRate?: number; centerFreq?: number } = {};
  const big: number[] = [];
  for (const tok of stem.split('_')) {
    const m = /^(\d{1,7}(?:\.\d{1,7})?)([kKmMgG])$/.exec(tok);
    if (!m) continue;
    const unit = (m[2] as string).toLowerCase();
    const v = parseFloat(m[1] as string) * (unit === 'k' ? 1e3 : unit === 'm' ? 1e6 : 1e9);
    if (unit === 'k') { if (out.sampleRate === undefined) out.sampleRate = v; } else big.push(v);
  }
  if (big.length) out.centerFreq = big[0];
  if (big.length > 1 && out.sampleRate === undefined) out.sampleRate = big[1];
  return out;
}

/** Decode raw interleaved samples into float arrays. */
export function decodeSamples(b: Uint8Array, format: SampleFormat, opts: { maxSamples?: number; bigEndian?: boolean } = {}): { i: Float32Array; q?: Float32Array; truncated: boolean } {
  const bps = BYTES_PER[format];
  if (!bps) throw new ParseError(`unknown sample format ${format}`);
  const complex = format.startsWith('c');
  const max = Math.max(0, Math.min(opts.maxSamples ?? MAX_SAMPLES, MAX_SAMPLES));
  const total = Math.floor(b.length / bps);
  const n = Math.min(total, max);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const le = !opts.bigEndian;
  const i = new Float32Array(n);
  const q = complex ? new Float32Array(n) : undefined;
  const comp = complex ? 2 : 1;
  const cb = bps / comp;
  const read = (o: number): number => {
    switch (format) {
      case 'cu8': case 'ru8': return ((b[o] as number) - 127.5) / 127.5;
      case 'cs8': case 'rs8': return dv.getInt8(o) / 127;
      case 'cs16': case 'rs16': return dv.getInt16(o, le) / 32768;
      case 'cu16': return (dv.getUint16(o, le) - 32767.5) / 32767.5;
      case 'cs32': return dv.getInt32(o, le) / 2147483648;
      case 'cf32': case 'rf32': { const v = dv.getFloat32(o, le); return Number.isFinite(v) ? v : 0; }
      case 'cf64': { const v = dv.getFloat64(o, le); return Number.isFinite(v) ? v : 0; }
    }
  };
  for (let k = 0; k < n; k++) {
    const o = k * bps;
    i[k] = read(o);
    if (q) q[k] = read(o + cb);
  }
  return { i, ...(q ? { q } : {}), truncated: total > n };
}

/** SigMF datatype (ci16_le, cu8, cf32_le, ri16_be ...) to a sample format and byte order. */
export function sigmfDatatype(dt: string): { format: SampleFormat; bigEndian: boolean } {
  const m = /^([cr])([fiu])(8|16|32|64)(?:_(le|be))?$/.exec(dt.trim());
  if (!m) throw new ParseError(`unsupported SigMF datatype ${dt}`);
  const [, cr, kind, bits, end] = m as unknown as [string, string, string, string, string | undefined];
  const key = `${cr}${kind === 'i' ? 's' : kind}${bits}`;
  const ok: Record<string, SampleFormat> = { cu8: 'cu8', cs8: 'cs8', cs16: 'cs16', cu16: 'cu16', cs32: 'cs32', cf32: 'cf32', cf64: 'cf64', ru8: 'ru8', rs8: 'rs8', rs16: 'rs16', rf32: 'rf32' };
  const format = ok[key];
  if (!format) throw new ParseError(`unsupported SigMF datatype ${dt}`);
  return { format, bigEndian: end === 'be' };
}

const num = (x: unknown): number | undefined => (typeof x === 'number' && Number.isFinite(x) ? x : undefined);
const str = (x: unknown): string | undefined => (typeof x === 'string' ? x.slice(0, 2000) : undefined);

/** Parse a .sigmf-meta document (JSON). */
export function parseSigmfMeta(text: string): SigmfInfo {
  if (text.length > 16 << 20) throw new ParseError('SigMF metadata too large');
  let j: Record<string, unknown>;
  try { j = JSON.parse(text) as Record<string, unknown>; } catch (e) { throw new ParseError(`SigMF metadata is not JSON: ${(e as Error).message}`); }
  const g = (j.global ?? {}) as Record<string, unknown>;
  const dt = str(g['core:datatype']);
  if (!dt) throw new ParseError('SigMF metadata has no core:datatype');
  const caps = Array.isArray(j.captures) ? (j.captures as Record<string, unknown>[]).slice(0, 10000) : [];
  const anns = Array.isArray(j.annotations) ? (j.annotations as Record<string, unknown>[]).slice(0, 10000) : [];
  const ext = Array.isArray(g['core:extensions']) ? (g['core:extensions'] as Record<string, unknown>[]).slice(0, 100).map((e) => String(e?.name ?? '')).filter(Boolean) : undefined;
  return {
    version: str(g['core:version']), datatype: dt, sampleRate: num(g['core:sample_rate']), description: str(g['core:description']), author: str(g['core:author']), hw: str(g['core:hw']), license: str(g['core:license']), recorder: str(g['core:recorder']),
    numChannels: num(g['core:num_channels']),
    captures: caps.map((c) => ({ sampleStart: num(c?.['core:sample_start']) ?? 0, ...(num(c?.['core:frequency']) !== undefined ? { frequency: num(c['core:frequency']) } : {}), ...(str(c?.['core:datetime']) ? { datetime: str(c['core:datetime']) } : {}) })),
    annotations: anns.map((a) => ({ sampleStart: num(a?.['core:sample_start']) ?? 0, ...(num(a?.['core:sample_count']) !== undefined ? { sampleCount: num(a['core:sample_count']) } : {}), ...(str(a?.['core:label']) ? { label: str(a['core:label']) } : {}), ...(str(a?.['core:comment']) ? { comment: str(a['core:comment']) } : {}), ...(num(a?.['core:freq_lower_edge']) !== undefined ? { freqLower: num(a['core:freq_lower_edge']) } : {}), ...(num(a?.['core:freq_upper_edge']) !== undefined ? { freqUpper: num(a['core:freq_upper_edge']) } : {}) })),
    ...(ext ? { extensions: ext } : {}),
  };
}

/** Minimal ustar reader for .sigmf archives: returns name, offset and size of each regular file. */
export function tarEntries(b: Uint8Array, max = 10000): { name: string; offset: number; size: number }[] {
  const out: { name: string; offset: number; size: number }[] = [];
  let o = 0;
  while (o + 512 <= b.length && out.length < max) {
    const hdr = b.subarray(o, o + 512);
    if (hdr.every((x) => x === 0)) break;
    const nul = (s: Uint8Array) => { const z = s.indexOf(0); return latin1(z < 0 ? s : s.subarray(0, z)); };
    const name = nul(hdr.subarray(0, 100));
    const prefix = latin1(hdr.subarray(257, 263)).startsWith('ustar') ? nul(hdr.subarray(345, 500)) : '';
    const sizeText = nul(hdr.subarray(124, 136)).trim();
    const size = /^[0-7]+$/.test(sizeText) ? parseInt(sizeText, 8) : NaN;
    if (!Number.isFinite(size) || size < 0) throw new ParseError('bad tar header', o);
    const type = String.fromCharCode(hdr[156] as number);
    const data = o + 512;
    if (data + size > b.length) throw new ParseError('tar member runs past the end', o);
    if (type === '0' || type === '\0') out.push({ name: prefix ? `${prefix}/${name}` : name, offset: data, size });
    o = data + Math.ceil(size / 512) * 512;
  }
  return out;
}

export interface ReadOptions { name?: string; format?: SampleFormat; sampleRate?: number; centerFreq?: number; maxSamples?: number; bigEndian?: boolean; offsetSamples?: number }

/** Parse a WAV file. Stereo is read as I/Q, mono as real samples. */
export function readWav(b: Uint8Array, opts: ReadOptions = {}): Recording {
  if (b.length < 12 || latin1(b.subarray(0, 4)) !== 'RIFF' || latin1(b.subarray(8, 12)) !== 'WAVE') throw new ParseError('not a RIFF WAVE file');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 12;
  let fmt: { audioFormat: number; channels: number; rate: number; bits: number } | undefined;
  let data: { off: number; size: number } | undefined;
  let center: number | undefined;
  for (let guard = 0; o + 8 <= b.length && guard < 10000; guard++) {
    const id = latin1(b.subarray(o, o + 4));
    const size = dv.getUint32(o + 4, true);
    const body = o + 8;
    if (id === 'fmt ' && body + 16 <= b.length) {
      let af = dv.getUint16(body, true);
      if (af === 0xfffe && size >= 40 && body + 26 <= b.length) af = dv.getUint16(body + 24, true);
      fmt = { audioFormat: af, channels: dv.getUint16(body + 2, true), rate: dv.getUint32(body + 4, true), bits: dv.getUint16(body + 14, true) };
    } else if (id === 'data') {
      data = { off: body, size: Math.min(size, b.length - body) };
      break;
    } else if (id === 'auxi' && body + 40 <= b.length) {
      // SDR# / SDRuno auxi chunk: center frequency at byte 32 (uint32)
      const f = dv.getUint32(body + 32, true);
      if (f > 0) center = f;
    }
    o = body + size + (size & 1);
  }
  if (!fmt) throw new ParseError('WAV has no fmt chunk');
  if (!data) throw new ParseError('WAV has no data chunk');
  if (fmt.channels < 1 || fmt.channels > 2) throw new ParseError(`WAV with ${fmt.channels} channels is not a signal recording this reader handles`);
  const pcm = fmt.audioFormat === 1, flt = fmt.audioFormat === 3;
  if (!pcm && !flt) throw new ParseError(`WAV audio format ${fmt.audioFormat} is not PCM or float`);
  const bytesPer = fmt.bits / 8;
  if (![1, 2, 3, 4, 8].includes(bytesPer) || (flt && bytesPer !== 4 && bytesPer !== 8)) throw new ParseError(`WAV with ${fmt.bits} bit samples is not supported`);
  const frame = bytesPer * fmt.channels;
  const total = Math.floor(data.size / frame);
  const start = Math.min(total, Math.max(0, opts.offsetSamples ?? 0));
  const n = Math.min(total - start, opts.maxSamples ?? MAX_SAMPLES, MAX_SAMPLES);
  const read = (p: number): number => {
    if (flt) return bytesPer === 4 ? dv.getFloat32(p, true) : dv.getFloat64(p, true);
    if (bytesPer === 1) return ((b[p] as number) - 128) / 128;
    if (bytesPer === 2) return dv.getInt16(p, true) / 32768;
    if (bytesPer === 3) { const v = (b[p] as number) | ((b[p + 1] as number) << 8) | ((b[p + 2] as number) << 16); return ((v << 8) >> 8) / 8388608; }
    return dv.getInt32(p, true) / 2147483648;
  };
  const i = new Float32Array(n);
  const q = fmt.channels === 2 ? new Float32Array(n) : undefined;
  for (let k = 0; k < n; k++) {
    const p = data.off + (start + k) * frame;
    const a = read(p);
    i[k] = Number.isFinite(a) ? a : 0;
    if (q) { const c = read(p + bytesPer); q[k] = Number.isFinite(c) ? c : 0; }
  }
  const hints = opts.name ? hintsFromName(opts.name) : {};
  const sampleRate = opts.sampleRate ?? fmt.rate;
  const centerFreq = opts.centerFreq ?? center ?? hints.centerFreq;
  const format: SampleFormat = q ? (bytesPer === 1 ? 'cu8' : bytesPer === 2 ? 'cs16' : flt ? 'cf32' : 'cs32') : (bytesPer === 1 ? 'ru8' : bytesPer === 2 ? 'rs16' : 'rf32');
  return {
    container: 'wav', format, sampleRate, ...(centerFreq !== undefined ? { centerFreq } : {}), complex: !!q, i, ...(q ? { q } : {}), samples: n, durationSec: sampleRate > 0 ? n / sampleRate : 0, truncated: start + n < total,
    wav: { channels: fmt.channels, bitsPerSample: fmt.bits, audioFormat: fmt.audioFormat, dataOffset: data.off, dataSize: data.size },
    notes: q ? ['stereo WAV read as I (left) and Q (right)'] : ['mono WAV read as real samples'],
  };
}

/** Read a SigMF recording from its metadata text and data bytes. */
export function readSigmf(metaText: string, data: Uint8Array, opts: ReadOptions = {}): Recording {
  const sigmf = parseSigmfMeta(metaText);
  const { format, bigEndian } = sigmfDatatype(sigmf.datatype);
  const notes: string[] = [];
  if ((sigmf.numChannels ?? 1) > 1) notes.push(`recording has ${sigmf.numChannels} channels; only interleaved channel 0 framing is assumed`);
  const bps = BYTES_PER[format];
  const skip = Math.max(0, opts.offsetSamples ?? 0) * bps;
  const d = decodeSamples(data.subarray(Math.min(data.length, skip)), format, { bigEndian, maxSamples: opts.maxSamples });
  const sampleRate = opts.sampleRate ?? sigmf.sampleRate ?? 0;
  if (!sampleRate) notes.push('no core:sample_rate; times are in samples');
  const centerFreq = opts.centerFreq ?? sigmf.captures[0]?.frequency;
  return {
    container: 'sigmf', format, sampleRate: sampleRate || 1, ...(centerFreq !== undefined ? { centerFreq } : {}), complex: format.startsWith('c'), i: d.i, ...(d.q ? { q: d.q } : {}),
    samples: d.i.length, durationSec: sampleRate ? d.i.length / sampleRate : 0, truncated: d.truncated, sigmf, notes,
  };
}

/** Read a raw IQ file; the format comes from options or the file extension, the rate from options or the rtl_433 style name. */
export function readRaw(b: Uint8Array, opts: ReadOptions = {}): Recording {
  const format = opts.format ?? (opts.name ? formatFromName(opts.name) : undefined);
  if (!format) throw new ParseError('raw recording needs a format (cu8, cs8, cs16, cf32 ...) or a file extension that names one');
  const hints = opts.name ? hintsFromName(opts.name) : {};
  const sampleRate = opts.sampleRate ?? hints.sampleRate ?? 250_000;
  const notes: string[] = [];
  if (opts.sampleRate === undefined && hints.sampleRate === undefined) notes.push('sample rate not given and not in the file name; assumed 250 kHz like rtl_433');
  const bps = BYTES_PER[format];
  const skip = Math.max(0, opts.offsetSamples ?? 0) * bps;
  const d = decodeSamples(b.subarray(Math.min(b.length, skip)), format, { bigEndian: opts.bigEndian, maxSamples: opts.maxSamples });
  const centerFreq = opts.centerFreq ?? hints.centerFreq;
  return { container: 'raw', format, sampleRate, ...(centerFreq !== undefined ? { centerFreq } : {}), complex: format.startsWith('c'), i: d.i, ...(d.q ? { q: d.q } : {}), samples: d.i.length, durationSec: d.i.length / sampleRate, truncated: d.truncated, notes };
}

/**
 * Read any supported recording. For SigMF pass the metadata bytes as `bytes` and the data bytes as
 * `data`, or pass a .sigmf tar archive as `bytes`.
 */
export function readRecording(bytes: Uint8Array, opts: ReadOptions & { data?: Uint8Array } = {}): Recording {
  const name = opts.name ?? '';
  if (bytes.length >= 12 && latin1(bytes.subarray(0, 4)) === 'RIFF' && latin1(bytes.subarray(8, 12)) === 'WAVE') return readWav(bytes, opts);
  if (/\.sigmf$/i.test(name) || (bytes.length > 512 && latin1(bytes.subarray(257, 262)) === 'ustar')) {
    const ents = tarEntries(bytes);
    const meta = ents.find((e) => e.name.endsWith('.sigmf-meta'));
    const data = meta ? ents.find((e) => e.name === meta.name.replace(/\.sigmf-meta$/, '.sigmf-data')) ?? ents.find((e) => e.name.endsWith('.sigmf-data')) : undefined;
    if (!meta || !data) throw new ParseError('SigMF archive has no .sigmf-meta and .sigmf-data pair');
    return readSigmf(utf8(bytes.subarray(meta.offset, meta.offset + meta.size)), bytes.subarray(data.offset, data.offset + data.size), opts);
  }
  if (/\.sigmf-meta$/i.test(name) || (bytes[0] === 0x7b && /"core:datatype"/.test(utf8(bytes.subarray(0, Math.min(bytes.length, 1 << 16)))))) {
    if (!opts.data) throw new ParseError('SigMF metadata given without its .sigmf-data');
    return readSigmf(utf8(bytes), opts.data, opts);
  }
  return readRaw(bytes, opts);
}

/** Basic sample statistics: RMS, peak, DC offset. */
export function recordingStats(r: Recording): { rmsDbfs: number; peakDbfs: number; dcI: number; dcQ?: number; clippedFraction: number } {
  let s = 0, peak = 0, di = 0, dq = 0, clip = 0;
  const n = r.samples;
  for (let k = 0; k < n; k++) {
    const a = r.i[k] as number, c = r.q ? (r.q[k] as number) : 0;
    const m = a * a + c * c;
    s += m; di += a; dq += c;
    if (m > peak) peak = m;
    if (Math.abs(a) >= 0.999 || Math.abs(c) >= 0.999) clip++;
  }
  const db = (x: number) => (x > 0 ? Math.round(10 * Math.log10(x) * 100) / 100 : -200);
  return { rmsDbfs: db(n ? s / n : 0), peakDbfs: db(peak), dcI: n ? di / n : 0, ...(r.q ? { dcQ: n ? dq / n : 0 } : {}), clippedFraction: n ? clip / n : 0 };
}
