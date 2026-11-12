#!/usr/bin/env python3
"""Generate small synthetic RF recordings whose bits are known, for the RevLens signal decoders.

Each recording is written in a format rtl_433 can also read (file names follow the rtl_433
convention name_<freq>M_<rate>k.<fmt>), so rtl_433 -X <flex spec> is the independent reference.
Writes samples/extras/signals/*.cu8|cs8|cs16|cf32|wav|sigmf-* and manifest.json with the bits.

Usage: python3 gen-signal-fixtures.py <outdir>
Needs numpy. Deterministic (fixed seed).
"""
import json, os, struct, sys, hashlib
import numpy as np

out = sys.argv[1] if len(sys.argv) > 1 else 'samples/extras/signals'
os.makedirs(out, exist_ok=True)
rng = np.random.default_rng(433)
RATE = 250_000

def bits_of(hexs, n):
    v = int(hexs, 16)
    total = len(hexs) * 4
    return [(v >> (total - 1 - i)) & 1 for i in range(n)]

def us(n):
    return int(round(n * RATE / 1e6))

def ook_env(segments):
    """segments: list of (level 0/1, microseconds) -> amplitude array"""
    parts = [np.full(us(d), float(l), dtype=np.float64) for l, d in segments]
    return np.concatenate(parts)

def iq_from_env(env, offset_hz=20_000, noise=0.03, amp=0.7):
    n = len(env)
    t = np.arange(n) / RATE
    phase = 2 * np.pi * offset_hz * t + rng.uniform(0, 2 * np.pi)
    sig = amp * env * np.exp(1j * phase)
    sig += noise * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    return sig

def fsk_iq(symbols, sym_us, dev=40_000, noise=0.03, amp=0.7, lead_us=20000, tail_us=2000):
    # symbols 1 -> +dev (mark), 0 -> -dev (space); carrier off before and after
    freq = np.concatenate([np.full(us(sym_us), dev if s else -dev, dtype=np.float64) for s in symbols])
    env = np.concatenate([np.zeros(us(lead_us)), np.ones(len(freq)), np.zeros(us(tail_us))])
    f = np.concatenate([np.zeros(us(lead_us)), freq, np.zeros(us(tail_us))])
    phase = 2 * np.pi * np.cumsum(f) / RATE
    sig = amp * env * np.exp(1j * phase)
    n = len(sig)
    sig += noise * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    return sig

def write_cu8(path, sig):
    i = np.clip(np.round(sig.real * 127.5 + 127.5), 0, 255).astype(np.uint8)
    q = np.clip(np.round(sig.imag * 127.5 + 127.5), 0, 255).astype(np.uint8)
    a = np.empty(2 * len(sig), dtype=np.uint8); a[0::2] = i; a[1::2] = q
    a.tofile(path)

def write_cs8(path, sig):
    i = np.clip(np.round(sig.real * 127), -128, 127).astype(np.int8)
    q = np.clip(np.round(sig.imag * 127), -128, 127).astype(np.int8)
    a = np.empty(2 * len(sig), dtype=np.int8); a[0::2] = i; a[1::2] = q
    a.tofile(path)

def write_cs16(path, sig):
    i = np.clip(np.round(sig.real * 32767), -32768, 32767).astype('<i2')
    q = np.clip(np.round(sig.imag * 32767), -32768, 32767).astype('<i2')
    a = np.empty(2 * len(sig), dtype='<i2'); a[0::2] = i; a[1::2] = q
    a.tofile(path)

def write_cf32(path, sig):
    a = np.empty(2 * len(sig), dtype='<f4'); a[0::2] = sig.real; a[1::2] = sig.imag
    a.tofile(path)

def write_wav_iq(path, sig):
    i = np.clip(np.round(sig.real * 32767), -32768, 32767).astype('<i2')
    q = np.clip(np.round(sig.imag * 32767), -32768, 32767).astype('<i2')
    a = np.empty(2 * len(sig), dtype='<i2'); a[0::2] = i; a[1::2] = q
    data = a.tobytes()
    hdr = b'RIFF' + struct.pack('<I', 36 + len(data)) + b'WAVE'
    hdr += b'fmt ' + struct.pack('<IHHIIHH', 16, 1, 2, RATE, RATE * 4, 4, 16)
    hdr += b'data' + struct.pack('<I', len(data))
    open(path, 'wb').write(hdr + data)

manifest = []

def pad(segs, lead=20000, tail=6000):
    return [(0, lead)] + segs + [(0, tail)]

def repeat(rows, gap_us):
    segs = []
    for k, r in enumerate(rows):
        segs += r
        if k < len(rows) - 1:
            segs.append((0, gap_us))
    return segs

# 1. OOK PWM, EV1527 style: short pulse 1 (300 us high, 900 us low) = 1? Use rtl_433 OOK_PWM: short pulse = 1, long pulse = 0.
pwm_hex, pwm_n = 'a5c3f1', 24
pwm_bits = bits_of(pwm_hex, pwm_n)
def pwm_row(bits):
    s = []
    for b in bits:
        s += [(1, 300), (0, 900)] if b else [(1, 900), (0, 300)]
    return s
segs = pad(repeat([pwm_row(pwm_bits)] * 3, 9000))
sig = iq_from_env(ook_env(segs))
name = 'pwm_433.92M_250k.cu8'
write_cu8(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'cu8', 'sampleRate': RATE, 'centerFreq': 433.92e6, 'modulation': 'OOK_PWM', 'short': 300, 'long': 900, 'gap': 1500, 'reset': 5000, 'rows': 3, 'bits': pwm_n, 'hex': pwm_hex, 'flex': 'n=pwm,m=OOK_PWM,s=300,l=900,r=5000,g=1500'})

# 2. OOK PPM: pulse 500 us, gap 1000 = 0, gap 2000 = 1 (rtl_433 OOK_PPM: short gap = 0, long gap = 1)
ppm_hex, ppm_n = '5aa5', 16
def ppm_row(bits):
    s = []
    for b in bits:
        s += [(1, 500), (0, 2000 if b else 1000)]
    s += [(1, 500)]
    return s
segs = pad(repeat([ppm_row(bits_of(ppm_hex, ppm_n))] * 2, 9000))
sig = iq_from_env(ook_env(segs), offset_hz=-35_000)
name = 'ppm_315M_250k.cs16'
write_cs16(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'cs16', 'sampleRate': RATE, 'centerFreq': 315e6, 'modulation': 'OOK_PPM', 'short': 1000, 'long': 2000, 'gap': 3000, 'reset': 6000, 'rows': 2, 'bits': ppm_n, 'hex': ppm_hex, 'flex': 'n=ppm,m=OOK_PPM,s=1000,l=2000,g=3000,r=6000'})

# 3. OOK PCM NRZ: bit width 400 us, preamble 1010, data
pcm_hex, pcm_n = 'aaf0b7', 24
def pcm_row(bits):
    return [(b, 400) for b in bits]
row = pcm_row(bits_of(pcm_hex, pcm_n))
segs = pad(repeat([row, row], 10000))
sig = iq_from_env(ook_env(segs), offset_hz=10_000)
name = 'pcm_868.3M_250k.cf32'
write_cf32(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'cf32', 'sampleRate': RATE, 'centerFreq': 868.3e6, 'modulation': 'OOK_PCM', 'short': 400, 'long': 400, 'reset': 4000, 'rows': 2, 'bits': pcm_n, 'hex': pcm_hex, 'flex': 'n=pcm,m=OOK_PCM,s=400,l=400,r=4000'})

# 4. OOK Manchester (rtl_433 OOK_MC_ZEROBIT: leading zero bit, then IEEE 802.3: 1 = low->high? rtl_433: 0 = high-low? ) we encode G.E. Thomas: 1 = high then low
mc_hex, mc_n = '9e3d', 16
def mc_row(bits):
    s = []
    for b in [0] + bits:  # zero bit start like OOK_MC_ZEROBIT
        s += [(1, 250), (0, 250)] if b else [(0, 250), (1, 250)]
    return s
segs = pad(repeat([mc_row(bits_of(mc_hex, mc_n))] * 2, 8000))
sig = iq_from_env(ook_env(segs), offset_hz=5_000)
name = 'mc_433.92M_250k.cs8'
write_cs8(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'cs8', 'sampleRate': RATE, 'centerFreq': 433.92e6, 'modulation': 'OOK_MC_ZEROBIT', 'short': 250, 'long': 250, 'reset': 3000, 'rows': 2, 'bits': mc_n, 'hex': mc_hex, 'flex': 'n=mc,m=OOK_MC_ZEROBIT,s=250,l=250,r=3000'})

# 5. 2-FSK PCM: 100 us symbols, preamble aaaa, sync 2dd4, payload
fsk_hex = 'aaaa2dd4c0ffee42'
fsk_n = 64
sig = fsk_iq(bits_of(fsk_hex, fsk_n), 100)
sig = np.concatenate([sig, fsk_iq(bits_of(fsk_hex, fsk_n), 100)])
name = 'fsk-pcm_868.3M_250k.cu8'
write_cu8(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'cu8', 'sampleRate': RATE, 'centerFreq': 868.3e6, 'modulation': 'FSK_PCM', 'short': 100, 'long': 100, 'reset': 1000, 'rows': 2, 'bits': fsk_n, 'hex': fsk_hex, 'sync': '2dd4', 'flex': 'n=fsk,m=FSK_PCM,s=100,l=100,r=1000'})

# 6. WAV IQ (stereo 16 bit) carrying the PWM signal; SigMF pair carrying the PPM signal as ci16_le
segs = pad(repeat([pwm_row(pwm_bits)] * 2, 9000))
sig = iq_from_env(ook_env(segs), offset_hz=15_000)
name = 'pwm-iq_250k.wav'
write_wav_iq(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'wav', 'sampleRate': RATE, 'modulation': 'OOK_PWM', 'short': 300, 'long': 900, 'gap': 1500, 'reset': 5000, 'rows': 2, 'bits': pwm_n, 'hex': pwm_hex, 'flex': 'n=pwm,m=OOK_PWM,s=300,l=900,r=5000,g=1500'})

segs = pad(repeat([ppm_row(bits_of(ppm_hex, ppm_n))] * 2, 9000))
sig = iq_from_env(ook_env(segs), offset_hz=25_000)
base = 'ppm'
write_cs16(os.path.join(out, base + '.sigmf-data'), sig)
meta = {
    'global': {'core:datatype': 'ci16_le', 'core:sample_rate': RATE, 'core:version': '1.0.0', 'core:description': 'RevLens synthetic OOK PPM test recording', 'core:author': 'RevLens gen-signal-fixtures.py', 'core:recorder': 'numpy', 'core:license': 'https://creativecommons.org/publicdomain/zero/1.0/'},
    'captures': [{'core:sample_start': 0, 'core:frequency': 315e6, 'core:datetime': '2026-11-12T00:00:00Z'}],
    'annotations': [{'core:sample_start': us(20000), 'core:sample_count': us(40000), 'core:label': 'ppm burst', 'core:freq_lower_edge': 315e6 + 15e3, 'core:freq_upper_edge': 315e6 + 35e3}],
}
open(os.path.join(out, base + '.sigmf-meta'), 'w').write(json.dumps(meta, indent=2))
manifest.append({'file': base + '.sigmf-meta', 'format': 'sigmf', 'sampleRate': RATE, 'centerFreq': 315e6, 'modulation': 'OOK_PPM', 'short': 1000, 'long': 2000, 'gap': 3000, 'reset': 6000, 'rows': 2, 'bits': ppm_n, 'hex': ppm_hex, 'flex': 'n=ppm,m=OOK_PPM,s=1000,l=2000,g=3000,r=6000'})

# 7. pure tones for the spectrum summary: two complex tones at +50 kHz (strong) and -80 kHz (weaker)
n = 16384
t = np.arange(n) / RATE
sig = 0.6 * np.exp(2j * np.pi * 50_000 * t) + 0.15 * np.exp(2j * np.pi * -80_000 * t)
sig += 0.01 * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
name = 'tones_100M_250k.cf32'
write_cf32(os.path.join(out, name), sig)
manifest.append({'file': name, 'format': 'cf32', 'sampleRate': RATE, 'centerFreq': 100e6, 'tones': [50_000, -80_000]})

for m in manifest:
    p = os.path.join(out, m['file'])
    m['sha256'] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
    m['size'] = os.path.getsize(p)
open(os.path.join(out, 'manifest.json'), 'w').write(json.dumps(manifest, indent=2) + '\n')
print('wrote', len(manifest), 'recordings to', out)
