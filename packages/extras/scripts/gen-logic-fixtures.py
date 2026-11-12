#!/usr/bin/env python3
"""Generate a logic capture with UART, I2C and SPI traffic whose bytes are known, convert it to a
sigrok session with sigrok-cli, and record sigrok-cli 0.7.2 protocol decoder output as reference.

Channels (1 MHz sample rate): D0 UART TX 115200 8N1; D1 SCL, D2 SDA (I2C ~50 kHz);
D3 SCLK, D4 MOSI, D5 MISO, D6 CS# (SPI mode 0, ~100 kHz).
Usage: . tools/sigrok-env.sh; python3 gen-logic-fixtures.py <outdir>
"""
import json, os, subprocess, sys, hashlib

out = sys.argv[1] if len(sys.argv) > 1 else 'samples/extras/logic'
os.makedirs(out, exist_ok=True)
RATE = 1_000_000
lines = {k: [] for k in range(8)}  # per channel list of levels per sample

N = 60000
state = [1, 1, 1, 0, 0, 0, 1, 0]  # idle levels
samples = [list(state) for _ in range(N)]

def setr(ch, start, end, v):
    for s in range(max(0, start), min(N, end)):
        samples[s][ch] = v

# UART on D0 from sample 1000
uart_text = b'RevLens\r\n'
spb = RATE / 115200
pos = 1000.0
for byte in uart_text:
    bits = [0] + [(byte >> i) & 1 for i in range(8)] + [1]
    for b in bits:
        setr(0, int(round(pos)), int(round(pos + spb)), b)
        pos += spb
    pos += spb * 2

# I2C on D1 (SCL) D2 (SDA): write 0x3c, bytes 0x00 0xaf ; then read from 0x50 one byte 0x42 with NACK
half = 10  # 10 us half period -> 50 kHz
t = 5000
def i2c_start():
    global t
    setr(2, t, N, 1); setr(1, t, N, 1); t += half
    setr(2, t, N, 0); t += half            # SDA falls while SCL high
    setr(1, t, N, 0); t += half
def i2c_bit(b):
    global t
    setr(2, t, N, b); t += half // 2
    setr(1, t, N, 1); t += half
    setr(1, t, N, 0); t += half // 2
def i2c_byte(v, ack=0):
    for i in range(7, -1, -1):
        i2c_bit((v >> i) & 1)
    i2c_bit(ack)
def i2c_stop():
    global t
    setr(2, t, N, 0); t += half // 2
    setr(1, t, N, 1); t += half
    setr(2, t, N, 1); t += half            # SDA rises while SCL high
i2c_start(); i2c_byte(0x3c << 1); i2c_byte(0x00); i2c_byte(0xaf); i2c_stop()
t += 200
i2c_start(); i2c_byte((0x50 << 1) | 1); i2c_byte(0x42, ack=1); i2c_stop()

# SPI mode 0 on D3 SCLK, D4 MOSI, D5 MISO, D6 CS#
mosi = [0x9f, 0x00, 0x00, 0x00]
miso = [0xff, 0xef, 0x40, 0x18]
t = 20000
sh = 5  # 5 us half period -> 100 kHz
setr(6, t, N, 0); t += 20
for mo, mi in zip(mosi, miso):
    for i in range(7, -1, -1):
        setr(4, t, N, (mo >> i) & 1); setr(5, t, N, (mi >> i) & 1)
        t += sh
        setr(3, t, N, 1); t += sh
        setr(3, t, N, 0)
    t += 10
t += 20
setr(6, t, N, 1)

raw = bytes(sum(v << ch for ch, v in enumerate(s)) for s in samples)
binpath = os.path.join(out, 'mixed_1MHz.bin')
open(binpath, 'wb').write(raw)
srpath = os.path.join(out, 'mixed_1MHz.sr')
if os.path.exists(srpath): os.remove(srpath)
subprocess.run(['sigrok-cli', '-I', f'binary:numchannels=8:samplerate={RATE}', '-i', binpath, '-o', srpath], check=True, timeout=60)

def decode(args):
    r = subprocess.run(['sigrok-cli', '-i', srpath, '--protocol-decoder-samplenum'] + args, capture_output=True, text=True, timeout=60)
    return [l for l in r.stdout.splitlines() if l.strip()]

ref = {
    'sigrok-cli': subprocess.run(['sigrok-cli', '--version'], capture_output=True, text=True).stdout.splitlines()[0],
    'uart': decode(['-P', 'uart:rx=0:baudrate=115200', '-A', 'uart=rx-data']),
    'i2c': decode(['-P', 'i2c:scl=1:sda=2']),
    'spi': decode(['-P', 'spi:clk=3:mosi=4:miso=5:cs=6', '-A', 'spi=mosi-data:miso-data']),
    'expected': {'uart_text': uart_text.decode('latin1'), 'i2c': ['S', '3c W', 'A', '00', 'A', 'af', 'A', 'P', 'S', '50 R', 'A', '42', 'N', 'P'], 'spi_mosi': [f'{x:02x}' for x in mosi], 'spi_miso': [f'{x:02x}' for x in miso]},
}
os.remove(binpath)
ref['sha256'] = hashlib.sha256(open(srpath, 'rb').read()).hexdigest()
open(os.path.join(out, 'mixed_1MHz.reference.json'), 'w').write(json.dumps(ref, indent=2) + '\n')
print(json.dumps(ref, indent=1)[:3000])
