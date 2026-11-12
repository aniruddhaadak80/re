#!/bin/sh
# Generate the compression fixtures in samples/extras/compress from a deterministic plain file.
# Needs python3 (lzma module), xz 5.8 (ARM64 and RISC-V filters), lzop 1.04 and zstd.
set -e
out=${1:-samples/extras/compress}
mkdir -p "$out"
python3 - "$out" <<'PY'
import lzma, random, sys
out = sys.argv[1]
random.seed(1)
data = bytearray()
for i in range(3000):
    data += random.choice([b'hello world ', b'RevLens ', bytes(random.randrange(256) for _ in range(5)), b'\xe8\x00\x10\x00\x00', b'\x00\x00\x00\x94'])
data = bytes(data) * 3
open(f'{out}/plain.bin','wb').write(data)
open(f'{out}/plain.lzma','wb').write(lzma.compress(data, format=lzma.FORMAT_ALONE))
open(f'{out}/plain-lc4.lzma','wb').write(lzma.compress(data, format=lzma.FORMAT_ALONE, filters=[{'id':lzma.FILTER_LZMA1,'lc':4,'lp':0,'pb':0,'dict_size':1<<16}]))
open(f'{out}/plain-crc64.xz','wb').write(lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64))
open(f'{out}/plain-crc32.xz','wb').write(lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32))
for name, fid in [('x86',lzma.FILTER_X86),('arm',lzma.FILTER_ARM),('armthumb',lzma.FILTER_ARMTHUMB),('powerpc',lzma.FILTER_POWERPC),('sparc',lzma.FILTER_SPARC)]:
    open(f'{out}/plain-{name}.xz','wb').write(lzma.compress(data, format=lzma.FORMAT_XZ, filters=[{'id':fid},{'id':lzma.FILTER_LZMA2}]))
open(f'{out}/plain-delta.xz','wb').write(lzma.compress(data, format=lzma.FORMAT_XZ, filters=[{'id':lzma.FILTER_DELTA,'dist':4},{'id':lzma.FILTER_LZMA2}]))
PY
xz -c --arm64 --lzma2 "$out/plain.bin" > "$out/plain-arm64.xz"
lzop -9 -f -o "$out/plain-9.lzo" "$out/plain.bin"
lzop -1 -f -o "$out/plain-1.lzo" "$out/plain.bin"
zstd -q -19 -f -o "$out/plain.zst" "$out/plain.bin"
gzip -9 -n -c "$out/plain.bin" > "$out/plain.gz"
# bzip2 1.0.8: one stream at -9, and two streams concatenated at -1 (bzip2 -d reads both)
bzip2 -9 -c "$out/plain.bin" > "$out/plain.bz2"
{ bzip2 -1 -c "$out/plain.bin"; printf 'second stream\n' | bzip2 -1 -c; } > "$out/plain-multi.bz2"
