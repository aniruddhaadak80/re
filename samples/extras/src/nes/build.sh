#!/bin/sh
# Builds the iNES and NES 2.0 fixtures with ca65/ld65 (cc65 2.19) and records CRC32/SHA-1 of the
# PRG and CHR data with Python zlib/hashlib, plus the header fields as written in rom.s.
set -e
cd "$(dirname "$0")"
out=../../containers/nes
t=$(mktemp -d)
ca65 -o $t/a.o rom.s
ld65 -C rom.cfg -D PRGBASE=0x8000 -D PRGSIZE=0x8000 -D CHRSIZE=0x2000 -o $out/ines-mmc1.nes $t/a.o
ca65 -D NES2 -o $t/b.o rom.s
ld65 -C rom.cfg -D PRGBASE=0xE0000 -D PRGSIZE=0x20000 -D CHRSIZE=0 -o $out/nes2-268.nes $t/b.o
python3 - "$out" <<'PY'
import hashlib, json, sys, zlib
out = sys.argv[1]
def ref(f, trainer, prg, chr_):
    b = open(f'{out}/{f}', 'rb').read()
    p = 16 + (512 if trainer else 0)
    P, C = b[p:p + prg], b[p + prg:p + prg + chr_]
    r = {'size': len(b), 'prgCrc32': '%08x' % zlib.crc32(P), 'romCrc32': '%08x' % zlib.crc32(P + C), 'romSha1': hashlib.sha1(P + C).hexdigest()}
    if chr_: r['chrCrc32'] = '%08x' % zlib.crc32(C)
    return r
d = {'tool': 'ca65/ld65 2.19, Python zlib and hashlib', 'ines-mmc1.nes': {**ref('ines-mmc1.nes', False, 0x8000, 0x2000), 'format': 'iNES', 'mapper': 1, 'prgRomSize': 32768, 'chrRomSize': 8192, 'mirroring': 'vertical', 'battery': True, 'trainer': False},
     'nes2-268.nes': {**ref('nes2-268.nes', True, 0x20000, 0), 'format': 'NES 2.0', 'mapper': 268, 'submapper': 1, 'prgRomSize': 131072, 'chrRomSize': 0, 'chrRamSize': 8192, 'prgNvramSize': 8192, 'prgRamSize': 0, 'mirroring': 'four-screen', 'battery': True, 'trainer': True, 'timing': 'PAL (RP2C07)', 'defaultExpansion': 1}}
json.dump(d, open(f'{out}/reference.json', 'w'), indent=1)
PY
