// Logic analyzer captures: sigrok session files (.sr, version 1 and 2) and plain packed sample
// dumps, decoded with UART, I2C and SPI protocol decoders written in TypeScript. Annotations
// carry sample numbers so an agent can cite them.

import { ParseError, utf8 } from '../util.js';
import { zipEntries, zipRead } from '../compress/zip.js';

export interface LogicCapture {
  sampleRate: number; unitSize: number; samples: number; channels: string[];
  /** Packed samples, unitSize bytes per sample, little endian. */
  data: Uint8Array;
  truncated: boolean;
  meta: Record<string, string>;
  sigrokVersion?: string;
}

export const LOGIC_DECODERS = [
  { id: 'uart', description: 'Asynchronous serial: start bit, 5-9 data bits, optional parity, stop bits', options: ['rx=<channel>', 'baudrate=<n>', 'data_bits=8', 'parity=none|even|odd', 'stop_bits=1', 'bit_order=lsb-first|msb-first', 'invert_rx=no|yes'] },
  { id: 'i2c', description: 'I2C: start, repeated start, 7 bit address with read or write, data bytes, ACK/NACK, stop', options: ['scl=<channel>', 'sda=<channel>'] },
  { id: 'spi', description: 'SPI: words on MOSI and MISO sampled on the clock edge for the chosen mode, framed by CS', options: ['clk=<channel>', 'mosi=<channel>', 'miso=<channel>', 'cs=<channel>', 'cpol=0', 'cpha=0', 'cs_polarity=active-low', 'bitorder=msb-first', 'wordsize=8'] },
];

const MAX_LOGIC_BYTES = 256 << 20;

function parseRate(v: string | undefined): number {
  if (!v) return 0;
  const m = /^\s*([\d.]+)\s*([kMG]?)(?:Hz)?\s*$/i.exec(v);
  if (!m) return 0;
  const mul = ({ '': 1, k: 1e3, K: 1e3, m: 1e6, M: 1e6, g: 1e9, G: 1e9 } as Record<string, number>)[m[2] as string] ?? 1;
  return parseFloat(m[1] as string) * mul;
}

/** Parse a sigrok .sr session (zip with metadata and logic-1-N chunks). */
export function readSigrokSession(b: Uint8Array, opts: { maxBytes?: number } = {}): LogicCapture {
  const ents = zipEntries(b, { maxEntries: 100000 });
  const get = (n: string) => ents.find((e) => e.name === n);
  const metaE = get('metadata');
  if (!metaE) throw new ParseError('sigrok session has no metadata member');
  const text = utf8(zipRead(b, metaE, 1 << 20));
  const meta: Record<string, string> = {};
  let section = '';
  for (const line of text.split(/\r?\n/).slice(0, 10000)) {
    const t = line.trim();
    if (!t || t.startsWith(';') || t.startsWith('#')) continue;
    const sm = /^\[(.{1,64})\]$/.exec(t);
    if (sm) { section = sm[1] as string; continue; }
    const k = t.indexOf('=');
    if (k > 0) meta[`${section}.${t.slice(0, k).trim()}`] = t.slice(k + 1).trim();
  }
  const dev = Object.keys(meta).find((k) => /^device \d+\.capturefile$/.test(k))?.split('.')[0] ?? 'device 1';
  const capture = meta[`${dev}.capturefile`] ?? 'logic-1';
  const unitSize = Math.max(1, Math.min(8, Number(meta[`${dev}.unitsize`] ?? '1') || 1));
  const probes = Number(meta[`${dev}.total probes`] ?? meta[`${dev}.total channels`] ?? String(unitSize * 8)) || unitSize * 8;
  const channels: string[] = [];
  for (let k = 1; k <= Math.min(64, probes); k++) channels.push(meta[`${dev}.probe${k}`] ?? `D${k - 1}`);
  // chunks: logic-1-1, logic-1-2 ... (v2) or a single logic-1 (v1)
  const chunks = ents.filter((e) => e.name === capture || e.name.startsWith(`${capture}-`)).sort((a, c) => {
    const na = Number(a.name.slice(capture.length + 1)) || 0, nc = Number(c.name.slice(capture.length + 1)) || 0;
    return na - nc;
  });
  const cap = Math.min(opts.maxBytes ?? MAX_LOGIC_BYTES, MAX_LOGIC_BYTES);
  let total = 0;
  const parts: Uint8Array[] = [];
  let truncated = false;
  for (const c of chunks) {
    if (total >= cap) { truncated = true; break; }
    const d = zipRead(b, c, cap);
    const take = Math.min(d.length, cap - total);
    parts.push(take < d.length ? d.subarray(0, take) : d);
    total += take;
    if (take < d.length) truncated = true;
  }
  const data = new Uint8Array(total - (total % unitSize));
  let o = 0;
  for (const p of parts) { const n = Math.min(p.length, data.length - o); data.set(p.subarray(0, n), o); o += n; }
  const version = get('version') ? utf8(zipRead(b, get('version')!, 64)).trim() : undefined;
  return { sampleRate: parseRate(meta[`${dev}.samplerate`]), unitSize, samples: data.length / unitSize, channels, data, truncated, meta, ...(meta['global.sigrok version'] ? { sigrokVersion: meta['global.sigrok version'] } : {}), ...(version ? { meta: { ...meta, 'file.version': version } } : {}) };
}

/** Wrap a packed binary sample dump (sigrok "binary" output) as a capture. */
export function logicFromBinary(data: Uint8Array, sampleRate: number, unitSize = 1, channels?: string[]): LogicCapture {
  const us = Math.max(1, Math.min(8, unitSize));
  const d = data.subarray(0, data.length - (data.length % us));
  return { sampleRate, unitSize: us, samples: d.length / us, channels: channels ?? Array.from({ length: us * 8 }, (_, k) => `D${k}`), data: d, truncated: false, meta: {} };
}

/** Channel index from a name (probe name, D3, or a number). */
export function channelIndex(cap: LogicCapture, ch: string | number | undefined): number | undefined {
  if (ch === undefined || ch === '') return undefined;
  if (typeof ch === 'number') return ch;
  const byName = cap.channels.findIndex((c) => c.toLowerCase() === ch.toLowerCase());
  if (byName >= 0) return byName;
  const m = /^D?(\d{1,2})$/i.exec(ch);
  if (m) return Number(m[1]);
  throw new ParseError(`unknown channel ${ch}; channels are ${cap.channels.join(', ')}`);
}

/** Edges of one channel: initial level and transition sample numbers. */
export function channelEdges(cap: LogicCapture, ch: number, maxEdges = 5_000_000): { initial: number; edges: number[]; truncated: boolean } {
  if (ch < 0 || ch >= cap.unitSize * 8) throw new ParseError(`channel ${ch} is outside the ${cap.unitSize * 8} captured channels`);
  const byte = ch >> 3, mask = 1 << (ch & 7);
  const d = cap.data, us = cap.unitSize;
  const initial = d.length ? ((d[byte] as number) & mask ? 1 : 0) : 0;
  let prev = initial;
  const edges: number[] = [];
  for (let s = 1; s < cap.samples; s++) {
    const v = (d[s * us + byte] as number) & mask ? 1 : 0;
    if (v !== prev) { edges.push(s); prev = v; if (edges.length >= maxEdges) return { initial, edges, truncated: true }; }
  }
  return { initial, edges, truncated: false };
}

const bitAt = (cap: LogicCapture, ch: number, s: number): number => ((cap.data[s * cap.unitSize + (ch >> 3)] as number) >> (ch & 7)) & 1;

export interface Annotation { decoder: string; startSample: number; endSample: number; type: string; text: string; value?: number }

/** UART decoder: finds start bits on falling edges, samples data bits at bit centers. */
export function decodeUart(cap: LogicCapture, o: { rx: string | number; baudrate: number; dataBits?: number; parity?: 'none' | 'even' | 'odd'; stopBits?: number; bitOrder?: 'lsb-first' | 'msb-first'; invert?: boolean; maxFrames?: number }): Annotation[] {
  const ch = channelIndex(cap, o.rx);
  if (ch === undefined) throw new ParseError('uart needs rx');
  if (!(o.baudrate > 0) || !(cap.sampleRate > 0)) throw new ParseError('uart needs a baud rate and a capture sample rate');
  const spb = cap.sampleRate / o.baudrate;
  if (spb < 2) throw new ParseError('sample rate too low for this baud rate');
  const nb = Math.max(5, Math.min(9, o.dataBits ?? 8));
  const parity = o.parity ?? 'none';
  const stop = o.stopBits ?? 1;
  const inv = o.invert ? 1 : 0;
  const level = (s: number) => bitAt(cap, ch, Math.min(cap.samples - 1, Math.max(0, Math.round(s)))) ^ inv;
  const out: Annotation[] = [];
  const max = o.maxFrames ?? 100000;
  let s = 0;
  // wait for idle high first
  while (s < cap.samples && level(s) === 0) s++;
  while (s < cap.samples && out.length < max) {
    if (level(s) === 1) { s++; continue; }
    const start = s;
    const frameEnd = start + spb * (1 + nb + (parity === 'none' ? 0 : 1) + stop);
    if (frameEnd > cap.samples) break;
    if (level(start + spb / 2) !== 0) { s++; continue; }
    let v = 0;
    for (let k = 0; k < nb; k++) {
      const bit = level(start + spb * (1.5 + k));
      if (o.bitOrder === 'msb-first') v = (v << 1) | bit; else v |= bit << k;
    }
    let ann: Annotation = { decoder: 'uart', startSample: start, endSample: Math.round(frameEnd), type: 'data', text: v.toString(16).padStart(2, '0'), value: v };
    let pos = 1 + nb;
    if (parity !== 'none') {
      const pb = level(start + spb * (pos + 0.5));
      let ones = pb;
      for (let k = 0; k < nb; k++) ones += (v >> k) & 1;
      if ((parity === 'even' && ones % 2 !== 0) || (parity === 'odd' && ones % 2 !== 1)) ann = { ...ann, type: 'parity-error' };
      pos++;
    }
    for (let k = 0; k < stop; k++) if (level(start + spb * (pos + k + 0.5)) !== 1) ann = { ...ann, type: 'frame-error' };
    out.push(ann);
    s = Math.round(start + spb * (pos + stop - 0.5));
    while (s < cap.samples && level(s) === 0 && ann.type === 'frame-error') s++;
  }
  return out;
}

/** I2C decoder: start/stop from SDA edges while SCL is high, bits on SCL rising edges. */
export function decodeI2c(cap: LogicCapture, o: { scl: string | number; sda: string | number; maxEvents?: number }): Annotation[] {
  const scl = channelIndex(cap, o.scl), sda = channelIndex(cap, o.sda);
  if (scl === undefined || sda === undefined) throw new ParseError('i2c needs scl and sda');
  const out: Annotation[] = [];
  const max = o.maxEvents ?? 100000;
  let inFrame = false, bitCount = 0, v = 0, byteStart = 0, isAddr = false;
  let pScl = bitAt(cap, scl, 0), pSda = bitAt(cap, sda, 0);
  for (let s = 1; s < cap.samples && out.length < max; s++) {
    const c = bitAt(cap, scl, s), d = bitAt(cap, sda, s);
    if (c === 1 && pScl === 1 && d !== pSda) {
      if (d === 0) { out.push({ decoder: 'i2c', startSample: s, endSample: s, type: inFrame ? 'repeated-start' : 'start', text: inFrame ? 'Sr' : 'S' }); inFrame = true; isAddr = true; bitCount = 0; v = 0; }
      else { out.push({ decoder: 'i2c', startSample: s, endSample: s, type: 'stop', text: 'P' }); inFrame = false; }
    } else if (inFrame && c === 1 && pScl === 0) {
      if (bitCount === 0) byteStart = s;
      if (bitCount < 8) { v = (v << 1) | d; bitCount++; }
      else {
        const ack = d === 0;
        if (isAddr) out.push({ decoder: 'i2c', startSample: byteStart, endSample: s, type: v & 1 ? 'address-read' : 'address-write', text: `${(v >> 1).toString(16).padStart(2, '0')} ${v & 1 ? 'R' : 'W'}`, value: v >> 1 });
        else out.push({ decoder: 'i2c', startSample: byteStart, endSample: s, type: 'data', text: v.toString(16).padStart(2, '0'), value: v });
        out.push({ decoder: 'i2c', startSample: s, endSample: s, type: ack ? 'ack' : 'nack', text: ack ? 'A' : 'N' });
        isAddr = false; bitCount = 0; v = 0;
      }
    }
    pScl = c; pSda = d;
  }
  return out;
}

/** SPI decoder: words on MOSI/MISO, sampled on the leading or trailing clock edge per CPOL/CPHA, framed by CS. */
export function decodeSpi(cap: LogicCapture, o: { clk: string | number; mosi?: string | number; miso?: string | number; cs?: string | number; cpol?: number; cpha?: number; csActiveHigh?: boolean; bitOrder?: 'msb-first' | 'lsb-first'; wordSize?: number; maxWords?: number }): Annotation[] {
  const clk = channelIndex(cap, o.clk);
  if (clk === undefined) throw new ParseError('spi needs clk');
  const mosi = channelIndex(cap, o.mosi), miso = channelIndex(cap, o.miso), cs = channelIndex(cap, o.cs);
  if (mosi === undefined && miso === undefined) throw new ParseError('spi needs mosi or miso');
  const cpol = o.cpol ? 1 : 0, cpha = o.cpha ? 1 : 0;
  const ws = Math.max(1, Math.min(32, o.wordSize ?? 8));
  // sample edge: mode 0 and 3 sample on rising, mode 1 and 2 on falling
  const sampleRising = (cpol ^ cpha) === 0;
  const out: Annotation[] = [];
  const max = o.maxWords ?? 100000;
  let pClk = bitAt(cap, clk, 0);
  let pCs = cs !== undefined ? bitAt(cap, cs, 0) : 0;
  const csActive = (v: number) => (o.csActiveHigh ? v === 1 : v === 0);
  let n = 0, vo = 0, vi = 0, wStart = 0;
  for (let s = 1; s < cap.samples && out.length < max; s++) {
    const c = bitAt(cap, clk, s);
    if (cs !== undefined) {
      const cv = bitAt(cap, cs, s);
      if (cv !== pCs) {
        if (csActive(cv)) { out.push({ decoder: 'spi', startSample: s, endSample: s, type: 'cs-active', text: 'CS#' }); n = 0; vo = 0; vi = 0; }
        else out.push({ decoder: 'spi', startSample: s, endSample: s, type: 'cs-inactive', text: 'CS' });
        pCs = cv;
      }
      if (!csActive(cv)) { pClk = c; continue; }
    }
    if (c !== pClk && ((sampleRising && c === 1) || (!sampleRising && c === 0))) {
      if (n === 0) wStart = s;
      const bo = mosi !== undefined ? bitAt(cap, mosi, s) : 0, bi = miso !== undefined ? bitAt(cap, miso, s) : 0;
      if (o.bitOrder === 'lsb-first') { vo |= bo << n; vi |= bi << n; } else { vo = (vo << 1) | bo; vi = (vi << 1) | bi; }
      n++;
      if (n === ws) {
        const hexw = Math.ceil(ws / 4);
        if (mosi !== undefined) out.push({ decoder: 'spi', startSample: wStart, endSample: s, type: 'mosi', text: (vo >>> 0).toString(16).padStart(hexw, '0'), value: vo >>> 0 });
        if (miso !== undefined) out.push({ decoder: 'spi', startSample: wStart, endSample: s, type: 'miso', text: (vi >>> 0).toString(16).padStart(hexw, '0'), value: vi >>> 0 });
        n = 0; vo = 0; vi = 0;
      }
    }
    pClk = c;
  }
  return out;
}

/** Run a decoder by id with sigrok style options (key=value strings or an object). */
export function decodeLogic(cap: LogicCapture, decoder: string, options: Record<string, string | number | boolean> = {}): Annotation[] {
  const o = options;
  const num = (k: string, d?: number) => (o[k] === undefined ? d : Number(o[k]));
  switch (decoder.toLowerCase()) {
    case 'uart': return decodeUart(cap, { rx: o.rx as string ?? o.tx as string, baudrate: num('baudrate', 115200)!, dataBits: num('data_bits', 8), parity: (o.parity as 'none') ?? 'none', stopBits: num('stop_bits', 1), bitOrder: (o.bit_order as 'lsb-first') ?? 'lsb-first', invert: o.invert_rx === 'yes' || o.invert_rx === true });
    case 'i2c': return decodeI2c(cap, { scl: o.scl as string, sda: o.sda as string });
    case 'spi': return decodeSpi(cap, { clk: o.clk as string, mosi: o.mosi as string | undefined, miso: o.miso as string | undefined, cs: o.cs as string | undefined, cpol: num('cpol', 0), cpha: num('cpha', 0), csActiveHigh: o.cs_polarity === 'active-high', bitOrder: (o.bitorder as 'msb-first') ?? 'msb-first', wordSize: num('wordsize', 8) });
    default: throw new ParseError(`unknown logic decoder ${decoder}; one of uart, i2c, spi`);
  }
}
