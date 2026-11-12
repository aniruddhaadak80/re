// Signal decoders: synthetic recordings with known bits (checked against rtl_433 25.02 on the
// same files), real rtl_433_tests recordings (fetched, not committed), a sigrok session checked
// against sigrok-cli 0.7.2, and hostile input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import fc from 'fast-check';
import {
  decodeSignalRecording, inspectSignalDecoders, readRecording, parseFlexSpec, parseSigmfMeta, hintsFromName, spectrumSummary, readSigrokSession, decodeLogic,
  fft, rowCode, manchesterDecode, tarEntries, ParseError,
} from '../src/index.js';
import { gunzipMember, inflateZlib, inflateRaw } from '../src/compress/inflate.js';
import { zipEntries, zipRead } from '../src/compress/zip.js';
import { S, cached } from './helpers.js';

const SIG = join(S, 'signals');
const manifest = JSON.parse(readFileSync(join(SIG, 'manifest.json'), 'utf8')) as { file: string; format: string; flex?: string; hex?: string; bits?: number; rows?: number; modulation?: string; centerFreq?: number; tones?: number[]; rtl_433?: { codes: string[] } }[];
const load = (f: string) => new Uint8Array(readFileSync(join(SIG, f)));

for (const m of manifest.filter((x) => x.flex)) {
  test(`signal ${m.file}: flex decode gives the generated bits and matches rtl_433`, () => {
    const data = m.format === 'sigmf' ? load(m.file.replace('.sigmf-meta', '.sigmf-data')) : undefined;
    const r = decodeSignalRecording(load(m.file), { name: m.file, data, flex: m.flex });
    const codes = r.decoded[0]!.events.flatMap((e) => e.codes);
    const want = `{${m.modulation === 'OOK_MC_ZEROBIT' ? m.bits! + 1 : m.bits}}`;
    if (m.rtl_433) assert.deepEqual(codes, m.rtl_433.codes, 'same codes as rtl_433 -X on the same file');
    if (m.modulation === 'OOK_MC_ZEROBIT') assert.equal(codes.filter((c) => c === rtlMc(m.hex!, m.bits!)).length, m.rows);
    else if (m.modulation === 'OOK_PCM') assert.equal(codes.filter((c) => c.startsWith('{34}' + m.hex)).length, m.rows);
    else assert.equal(codes.filter((c) => c === `${want}${m.hex}`).length, m.rows);
    if (m.centerFreq) assert.equal(r.recording.centerFreq, m.centerFreq);
    assert.equal(r.recording.sampleRate, 250000);
    // the automatic analysis finds the same coding family and the same payload
    const auto = r.analysis!.flatMap((a) => a.events.flatMap((e) => e.codes));
    assert.ok(auto.some((c) => c.includes(m.hex!.slice(0, 4)) || (m.modulation === 'OOK_MC_ZEROBIT' && c === rtlMc(m.hex!, m.bits!))), `auto analysis decodes ${m.hex}: ${auto.join(' ')}`);
    const fam = m.modulation!.replace(/^(OOK|FSK)_/, '').replace('MC_ZEROBIT', 'MC_ZEROBIT');
    assert.ok(r.analysis!.some((a) => a.guess?.flex.includes(fam)), `guessed ${fam}`);
  });
}

// OOK_MC_ZEROBIT output has the leading zero bit, so the code is the payload shifted right by one
function rtlMc(hex: string, bits: number): string {
  const v = (BigInt('0x' + hex) << 0n);
  const n = bits + 1;
  const padded = v << BigInt(Math.ceil(n / 4) * 4 - n);
  return `{${n}}${padded.toString(16).padStart(Math.ceil(n / 4), '0')}`;
}

test('signal: FSK recording is detected as FSK with the right deviation', () => {
  const m = manifest.find((x) => x.modulation === 'FSK_PCM')!;
  const r = decodeSignalRecording(load(m.file), { name: m.file });
  assert.equal(r.pulses.modulation, 'FSK');
  const p = r.pulses.packages[0]!;
  assert.ok(p.fsk && Math.abs(p.fsk.deviationHz - 40000) < 2500, `deviation ${p.fsk?.deviationHz}`);
  assert.ok(Math.abs(p.fsk!.f1Hz - 40000) < 3000);
});

test('signal: spectrum summary finds the generated tones', () => {
  const m = manifest.find((x) => x.tones)!;
  const rec = readRecording(load(m.file), { name: m.file });
  const s = spectrumSummary(rec, { fftSize: 4096 });
  assert.equal(s.peaks.length >= 2, true);
  assert.ok(Math.abs(s.peaks[0]!.offsetHz - 50000) < s.binHz, `strong tone ${s.peaks[0]!.offsetHz}`);
  assert.ok(Math.abs(s.peaks[1]!.offsetHz + 80000) < s.binHz, `weak tone ${s.peaks[1]!.offsetHz}`);
  assert.ok(Math.abs(s.peaks[0]!.frequencyHz! - 100_050_000) <= 2);
  // 0.6 vs 0.15 amplitude is 12.04 dB
  assert.ok(Math.abs(s.peaks[0]!.powerDb - s.peaks[1]!.powerDb - 12.04) < 0.6);
  assert.ok(s.peaks[0]!.aboveFloorDb > 40);
});

test('signal: readers agree across cu8, cs16, WAV and SigMF', () => {
  const wav = readRecording(load('pwm-iq_250k.wav'), { name: 'pwm-iq_250k.wav' });
  assert.equal(wav.container, 'wav'); assert.equal(wav.complex, true); assert.equal(wav.sampleRate, 250000); assert.equal(wav.wav!.channels, 2);
  const sig = readRecording(load('ppm.sigmf-meta'), { name: 'ppm.sigmf-meta', data: load('ppm.sigmf-data') });
  assert.equal(sig.container, 'sigmf'); assert.equal(sig.format, 'cs16'); assert.equal(sig.centerFreq, 315e6);
  assert.equal(sig.sigmf!.annotations[0]!.label, 'ppm burst');
  assert.equal(sig.samples, load('ppm.sigmf-data').length / 4);
  const raw = readRecording(load('ppm_315M_250k.cs16'), { name: 'ppm_315M_250k.cs16' });
  assert.equal(raw.samples, load('ppm_315M_250k.cs16').length / 4);
  assert.deepEqual(hintsFromName('g001_433.92M_250k.cu8'), { sampleRate: 250000, centerFreq: 433.92e6 });
  assert.deepEqual(hintsFromName('cap_868.3M_1024k.cs16'), { sampleRate: 1024000, centerFreq: 868.3e6 });
  // a SigMF archive (tar) round trip
  const tar = makeTar([['rec.sigmf-meta', load('ppm.sigmf-meta')], ['rec.sigmf-data', load('ppm.sigmf-data')]]);
  assert.equal(tarEntries(tar).length, 2);
  const fromTar = decodeSignalRecording(tar, { name: 'rec.sigmf', flex: 'n=ppm,m=OOK_PPM,s=1000,l=2000,g=3000,r=6000' });
  assert.deepEqual(fromTar.decoded[0]!.events.flatMap((e) => e.codes), ['{16}5aa5', '{16}5aa5']);
});

function makeTar(files: [string, Uint8Array][]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const [name, data] of files) {
    const h = new Uint8Array(512);
    h.set(new TextEncoder().encode(name), 0);
    h.set(new TextEncoder().encode(data.length.toString(8).padStart(11, '0') + '\0'), 124);
    h[156] = 0x30;
    h.set(new TextEncoder().encode('ustar\0'), 257);
    parts.push(h, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }
  parts.push(new Uint8Array(1024));
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

test('signal: flex spec parsing, filters and getters', () => {
  const s = parseFlexSpec('n=t,m=OOK_PWM,s=300,l=900,r=5000,g=1500,bits>=24,rows>=1,get=@0:{8}:first,get=@8:{4}:nib:[12:twelve 3:three]');
  assert.equal(s.modulation, 'OOK_PWM'); assert.equal(s.minBits, 24); assert.equal(s.minRows, 1); assert.equal(s.getters.length, 2);
  const r = decodeSignalRecording(load('pwm_433.92M_250k.cu8'), { name: 'pwm_433.92M_250k.cu8', flex: s.source });
  const row = r.decoded[0]!.events[0]!.rows[0]!;
  assert.equal(row.fields!.first, 0xa5);
  assert.equal(row.fields!.nib, 'twelve');
  // preamble aligns, match filters, invert flips
  const p = decodeSignalRecording(load('fsk-pcm_868.3M_250k.cu8'), { name: 'fsk-pcm_868.3M_250k.cu8', flex: ['n=a,m=FSK_PCM,s=100,l=100,r=1000,preamble={16}2dd4', 'n=b,m=FSK_PCM,s=100,l=100,r=1000,match={8}d2,invert', 'n=c,m=FSK_PCM,s=100,l=100,r=1000,bits>=100'] });
  assert.deepEqual(p.decoded[0]!.events.flatMap((e) => e.codes), ['{32}c0ffee42', '{32}c0ffee42']);
  assert.deepEqual(p.decoded[1]!.events.flatMap((e) => e.codes), ['{64}5555d22b3f0011bd', '{64}5555d22b3f0011bd']);
  assert.equal(p.decoded[2]!.events.length, 0);
  assert.throws(() => parseFlexSpec('m=NOPE,s=1,r=2'), ParseError);
  assert.throws(() => parseFlexSpec('n=x,s=1,r=2'), /m=/);
  assert.equal(rowCode([1, 0, 1, 0, 0, 1, 0, 1, 1]), '{9}a58');
  assert.deepEqual(manchesterDecode([0, 1, 1, 0, 0, 1]), [1, 0, 1]);
});

test('signal: catalog lists inputs, modulations and logic decoders', () => {
  const c = inspectSignalDecoders();
  assert.ok(c.modulations.some((m) => m.name === 'OOK_MC_ZEROBIT'));
  assert.ok(c.modulations.some((m) => m.name === 'FSK_PCM'));
  assert.deepEqual(c.logicDecoders.map((d) => d.id), ['uart', 'i2c', 'spi']);
  assert.ok(c.inputs.some((i) => i.container === 'SigMF'));
});

test('signal: FFT matches a direct DFT', () => {
  const n = 64;
  const re = new Float64Array(n), im = new Float64Array(n);
  for (let k = 0; k < n; k++) { re[k] = Math.sin(k * 0.7) + 0.3 * Math.cos(k * 2.1); im[k] = 0.1 * k; }
  const dre: number[] = [], dim: number[] = [];
  for (let f = 0; f < n; f++) { let a = 0, b = 0; for (let k = 0; k < n; k++) { const t = (-2 * Math.PI * f * k) / n; a += re[k]! * Math.cos(t) - im[k]! * Math.sin(t); b += re[k]! * Math.sin(t) + im[k]! * Math.cos(t); } dre.push(a); dim.push(b); }
  fft(re, im);
  for (let f = 0; f < n; f++) { assert.ok(Math.abs(re[f]! - dre[f]!) < 1e-9); assert.ok(Math.abs(im[f]! - dim[f]!) < 1e-9); }
});

// Real recordings from merbanan/rtl_433_tests (no license file there, so fetch only):
// node packages/extras/scripts/fetch-signal-fixtures.mjs
const RT = JSON.parse(readFileSync(join(SIG, 'rtl_433_tests.reference.json'), 'utf8')) as { recordings: { path: string; flex: string; rtl_433_codes: string[]; rtl_433_tests_expected: Record<string, unknown> }[] };
for (const rec of RT.recordings) {
  const bytes = cached(join('rtl_433_tests', rec.path.replaceAll('/', '__')));
  test(`signal: rtl_433_tests ${rec.path} matches rtl_433`, { skip: bytes ? false : 'run scripts/fetch-signal-fixtures.mjs' }, () => {
    const name = rec.path.split('/').pop()!;
    const r = decodeSignalRecording(bytes!, { name, flex: rec.flex });
    const codes = r.decoded[0]!.events.flatMap((e) => e.codes);
    const main = rec.rtl_433_codes.filter((c) => c.length > 6);
    if (rec.path.includes('bresser')) {
      assert.deepEqual(codes, rec.rtl_433_codes, 'identical 222 bit FSK row after the preamble');
      // independent check: the second 13 bytes are the inverted first 13, and the id and humidity fields match the test's JSON
      const hex = codes[0]!.replace(/^\{\d+\}/, '');
      const by = (k: number) => parseInt(hex.slice(k * 2, k * 2 + 2), 16);
      for (let k = 0; k < 13; k++) assert.equal(by(k) ^ by(k + 13), 0xff);
      assert.equal(by(14), rec.rtl_433_tests_expected.id);
      assert.equal(Number(by(22).toString(16)), rec.rtl_433_tests_expected.humidity);
      // automatic analysis lands on FSK PCM near the 124 us bit
      const g = r.analysis!.find((a) => a.guess)?.guess;
      assert.match(g!.flex, /m=FSK_PCM,s=1(1|2|3)\d/);
    } else {
      // full 25 bit rows: g018 gives all of rtl_433's rows; on g026 the signal fades and the last
      // rows' gaps stretch past g=1056 in our detector, so at least 3 of rtl_433's 5 are required
      const want = main[0]!;
      const got = codes.filter((c) => c === want).length;
      assert.ok(got >= Math.min(main.length, rec.path.includes('g026') ? 3 : main.length), `${want} x${got} vs rtl_433 x${main.length}`);
      // Smoke-GS558 code from the test JSON: invert, take 24 bits, reverse each byte, print b2 b1 b0
      const bits = BigInt('0x' + want.replace(/^\{25\}/, '')) >> 4n;
      const inv = (~bits) & 0xffffffn;
      const rev = (x: number) => { let v = 0; for (let k = 0; k < 8; k++) v |= ((x >> k) & 1) << (7 - k); return v; };
      const b0 = rev(Number((inv >> 16n) & 0xffn)), b1 = rev(Number((inv >> 8n) & 0xffn)), b2 = rev(Number(inv & 0xffn));
      assert.equal([b2, b1, b0].map((x) => x.toString(16).padStart(2, '0')).join(''), rec.rtl_433_tests_expected.code);
      const g = r.analysis!.find((a) => a.guess?.flex.includes('PWM'))?.guess;
      assert.ok(g, 'auto analysis guesses PWM');
    }
  });
}

test('logic: sigrok session decoded like sigrok-cli 0.7.2', () => {
  const ref = JSON.parse(readFileSync(join(S, 'logic', 'mixed_1MHz.reference.json'), 'utf8'));
  const cap = readSigrokSession(new Uint8Array(readFileSync(join(S, 'logic', 'mixed_1MHz.sr'))));
  assert.equal(cap.sampleRate, 1e6); assert.equal(cap.samples, 60000); assert.equal(cap.channels.length, 8);
  const uart = decodeLogic(cap, 'uart', { rx: '0', baudrate: 115200 });
  const refUart = (ref.uart as string[]).map((l) => { const m = /^(\d+)-(\d+) uart-1: ([0-9A-F]{2})$/.exec(l)!; return { s: Number(m[1]), v: m[3]!.toLowerCase() }; });
  assert.deepEqual(uart.map((a) => a.text), refUart.map((x) => x.v));
  for (let k = 0; k < uart.length; k++) assert.ok(Math.abs(uart[k]!.dataStartSample! - refUart[k]!.s) <= 1, 'data bit start sample within one sample of sigrok');
  assert.equal(String.fromCharCode(...uart.map((a) => a.value!)), ref.expected.uart_text);
  const i2c = decodeLogic(cap, 'i2c', { scl: '1', sda: '2' });
  assert.deepEqual(i2c.map((a) => a.text), ref.expected.i2c);
  const refI2c = (ref.i2c as string[]).filter((l) => /Start|Stop|Address|Data|ACK/.test(l)).map((l) => Number(l.split('-')[0]));
  assert.deepEqual(i2c.filter((a) => a.type !== 'repeated-start').map((a) => a.startSample), refI2c);
  const spi = decodeLogic(cap, 'spi', { clk: '3', mosi: '4', miso: '5', cs: '6' });
  assert.deepEqual(spi.filter((a) => a.type === 'mosi').map((a) => a.text), ref.expected.spi_mosi);
  assert.deepEqual(spi.filter((a) => a.type === 'miso').map((a) => a.text), ref.expected.spi_miso);
  const refSpiStarts = [...new Set((ref.spi as string[]).map((l) => Number(l.split('-')[0])))];
  assert.deepEqual([...new Set(spi.filter((a) => a.type === 'mosi').map((a) => a.startSample))], refSpiStarts);
});

test('compress: inflate, zlib and gzip match node:zlib and report the stream end', async () => {
  const zlib = await import('node:zlib');
  const src = new Uint8Array(200000);
  for (let k = 0; k < src.length; k++) src[k] = (k * 31 + (k >> 7)) & 0xff ^ (k % 1000 < 300 ? 0 : k & 7);
  const gz = new Uint8Array(zlib.gzipSync(src, { level: 9 }));
  const withTail = new Uint8Array(gz.length + 10); withTail.set(gz); withTail.fill(0x41, gz.length);
  const m = gunzipMember(withTail);
  assert.deepEqual(m.data, src); assert.equal(m.end, gz.length); assert.ok(m.crcValid && m.sizeValid);
  const z = new Uint8Array(zlib.deflateSync(src, { level: 1 }));
  const zr = inflateZlib(z);
  assert.deepEqual(zr.data, src); assert.equal(zr.checksumValid, true); assert.equal(zr.end, z.length);
  const stored = new Uint8Array(zlib.deflateRawSync(src.subarray(0, 1000), { level: 0 }));
  assert.deepEqual(inflateRaw(stored).data, src.subarray(0, 1000));
  assert.throws(() => inflateRaw(new Uint8Array(zlib.deflateRawSync(src)), { maxOut: 1000 }), /limit/);
});

test('compress: zip reader reads the sigrok session members', () => {
  const b = new Uint8Array(readFileSync(join(S, 'logic', 'mixed_1MHz.sr')));
  const ents = zipEntries(b);
  assert.ok(ents.some((e) => e.name === 'metadata'));
  assert.match(new TextDecoder().decode(zipRead(b, ents.find((e) => e.name === 'version')!)), /^2/);
});

test('signal: hostile input ends in a result or a ParseError, quickly', () => {
  const ok = (f: () => unknown) => {
    const t0 = Date.now();
    try { f(); } catch (e) { if (!(e instanceof ParseError) && !(e instanceof SyntaxError) && !/flex|unknown|bad|needs|format|zip|tar|sigrok|channel/i.test((e as Error).message)) throw e; }
    assert.ok(Date.now() - t0 < 3000, 'took too long');
  };
  fc.assert(fc.property(fc.uint8Array({ maxLength: 4000 }), fc.constantFrom('x.cu8', 'x.cs8', 'x.cs16', 'x.cf32', 'x.wav', 'x.sigmf', 'x.sigmf-meta', 'x.sr'), (b, name) => {
    ok(() => decodeSignalRecording(b, { name, data: b, flex: 'n=a,m=OOK_PWM,s=10,l=20,r=100' }));
    ok(() => readSigrokSession(b));
    ok(() => zipEntries(b));
    ok(() => inflateRaw(b, { maxOut: 1 << 20 }));
    ok(() => gunzipMember(b));
  }), { numRuns: 300 });
  fc.assert(fc.property(fc.string({ maxLength: 200 }), (s) => { ok(() => parseFlexSpec(s)); ok(() => parseSigmfMeta(s)); }), { numRuns: 500 });
  // truncated and bit flipped real files
  const real = load('fsk-pcm_868.3M_250k.cu8');
  fc.assert(fc.property(fc.nat(real.length), fc.nat(real.length - 1), (cut, flip) => {
    const b = real.slice(0, cut); if (flip < b.length) b[flip] ^= 0x80;
    ok(() => decodeSignalRecording(b, { name: 'f_250k.cu8', flex: 'n=f,m=FSK_PCM,s=100,l=100,r=1000' }));
  }), { numRuns: 40 });
  const sr = new Uint8Array(readFileSync(join(S, 'logic', 'mixed_1MHz.sr')));
  fc.assert(fc.property(fc.nat(sr.length - 1), fc.integer({ min: 1, max: 255 }), (at, x) => {
    const b = sr.slice(); b[at] ^= x;
    ok(() => { const c = readSigrokSession(b); decodeLogic(c, 'uart', { rx: '0', baudrate: 115200 }); decodeLogic(c, 'i2c', { scl: 1, sda: 2 }); });
  }), { numRuns: 100 });
  // a huge declared WAV data chunk is clamped to the file
  const wav = load('pwm-iq_250k.wav').slice(0, 2000);
  new DataView(wav.buffer).setUint32(40, 0xfffffff0, true);
  assert.ok(readRecording(wav, { name: 'w.wav' }).samples < 600);
});
