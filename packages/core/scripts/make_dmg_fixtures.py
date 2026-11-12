#!/usr/bin/env python3
"""Build small UDIF disk images that exercise every chunk codec RevLens decodes.

Each image holds one partition built from real bytes (a slice of samples/ls-linux.elf, so the data
is not synthetic noise) split into chunks with the codec named in the file name, plus zero fill
and ignored chunks. The images are checked independently with 7-Zip (7zz x -tDmg), which must
extract the partition with the same CRC-32, before the reference values are written.

Run: python3 packages/core/scripts/make_dmg_fixtures.py [path/to/7zz]
"""
import base64, bz2, hashlib, json, os, struct, subprocess, sys, tempfile, zlib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
OUT = os.path.join(ROOT, 'samples', 'core', 'dmg')
SEVENZIP = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('SEVENZIP', '/workspace/work/r4c-scratch/7z/7zz')
# Apple's reference lzfse command line tool (github.com/lzfse/lzfse, BSD-3-Clause) built locally.
LZFSE = os.environ.get('LZFSE', '/workspace/work/r4c-scratch/lzfse-cli')
SECTOR = 512


def adc_compress(data: bytes) -> bytes:
    """Greedy ADC encoder: literal runs up to 128 bytes, 2 byte matches (3..18, distance < 1024),
    3 byte matches (4..67, distance < 65536)."""
    out = bytearray()
    lit = bytearray()
    i = 0
    n = len(data)
    table = {}

    def flush():
        nonlocal lit
        while lit:
            chunk = lit[:128]
            out.append(0x80 | (len(chunk) - 1))
            out.extend(chunk)
            lit = lit[128:]

    while i < n:
        best_len, best_dist = 0, 0
        if i + 3 <= n:
            key = data[i:i + 3]
            for j in reversed(table.get(key, [])[-16:]):
                dist = i - j - 1
                if dist < 0 or dist > 0xffff:
                    continue
                l = 0
                while l < 67 and i + l < n and data[j + l] == data[i + l]:
                    l += 1
                if l > best_len:
                    best_len, best_dist = l, dist
        if best_len >= 3 and (best_dist < 1024 and best_len <= 18):
            flush()
            ln = best_len
            out.append(((ln - 3) << 2) | (best_dist >> 8))
            out.append(best_dist & 0xff)
        elif best_len >= 4:
            flush()
            ln = best_len
            out.append(0x40 | (ln - 4))
            out.extend(struct.pack('>H', best_dist))
        else:
            ln = 1
            lit.append(data[i])
        for k in range(i, min(i + ln, n - 2)):
            table.setdefault(data[k:k + 3], []).append(k)
        i += ln
    flush()
    return bytes(out)


def mish(first_sector, sector_count, chunks, checksum):
    hdr = b'mish' + struct.pack('>IQQQII', 1, first_sector, sector_count, 0, 0, 0) + b'\0' * 24
    hdr += struct.pack('>II', 2, 32) + struct.pack('>I', checksum) + b'\0' * 124
    hdr += struct.pack('>I', len(chunks))
    for t, s, c, off, ln in chunks:
        hdr += struct.pack('>IIQQQQ', t, 0, s, c, off, ln)
    return hdr


def build(name, codec, data):
    assert len(data) % SECTOR == 0
    sectors = len(data) // SECTOR
    fork = bytearray()
    chunks = []
    step = 64  # sectors per chunk
    s = 0
    while s < sectors:
        cnt = min(step, sectors - s)
        raw = data[s * SECTOR:(s + cnt) * SECTOR]
        if raw.count(0) == len(raw):
            chunks.append((0x00000000, s, cnt, len(fork), 0))
        elif codec == 'zlib':
            comp = zlib.compress(raw, 9); chunks.append((0x80000005, s, cnt, len(fork), len(comp))); fork += comp
        elif codec == 'bzip2':
            comp = bz2.compress(raw, 9); chunks.append((0x80000006, s, cnt, len(fork), len(comp))); fork += comp
        elif codec == 'lzfse':
            with tempfile.TemporaryDirectory() as td:
                a, b = os.path.join(td, 'in'), os.path.join(td, 'out')
                open(a, 'wb').write(raw)
                subprocess.run([LZFSE, '-encode', '-i', a, '-o', b], check=True)
                comp = open(b, 'rb').read()
            chunks.append((0x80000007, s, cnt, len(fork), len(comp))); fork += comp
        elif codec == 'adc':
            comp = adc_compress(raw); chunks.append((0x80000004, s, cnt, len(fork), len(comp))); fork += comp
        else:
            chunks.append((0x00000001, s, cnt, len(fork), len(raw))); fork += raw
        s += cnt
    chunks.append((0xffffffff, sectors, 0, len(fork), 0))
    pcrc = zlib.crc32(data) & 0xffffffff
    blk = mish(0, sectors, chunks, pcrc)
    plist = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
             '<plist version="1.0">\n<dict>\n\t<key>resource-fork</key>\n\t<dict>\n\t\t<key>blkx</key>\n\t\t<array>\n\t\t\t<dict>\n'
             '\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n\t\t\t\t<key>CFName</key>\n\t\t\t\t<string>whole disk (Apple_HFS : 0)</string>\n'
             '\t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n\t\t\t\t' + base64.b64encode(blk).decode() + '\n\t\t\t\t</data>\n'
             '\t\t\t\t<key>ID</key>\n\t\t\t\t<string>0</string>\n\t\t\t\t<key>Name</key>\n\t\t\t\t<string>whole disk (Apple_HFS : 0)</string>\n'
             '\t\t\t</dict>\n\t\t</array>\n\t</dict>\n</dict>\n</plist>\n').encode()
    master = zlib.crc32(struct.pack('>I', pcrc)) & 0xffffffff
    xml_off = len(fork)
    koly = b'koly' + struct.pack('>III', 4, 512, 1) + struct.pack('>QQQQQ', 0, 0, len(fork), 0, 0)
    koly += struct.pack('>II', 1, 1) + hashlib.md5(name.encode()).digest()
    koly += struct.pack('>II', 2, 32) + struct.pack('>I', zlib.crc32(bytes(fork)) & 0xffffffff) + b'\0' * 124
    koly += struct.pack('>QQ', xml_off, len(plist)) + b'\0' * 120
    koly += struct.pack('>II', 2, 32) + struct.pack('>I', master) + b'\0' * 124
    koly += struct.pack('>IQ', 1, sectors) + b'\0' * 12
    assert len(koly) == 512, len(koly)
    return bytes(fork) + plist + koly, pcrc


def main():
    os.makedirs(OUT, exist_ok=True)
    src = open(os.path.join(ROOT, 'samples', 'ls-linux.elf'), 'rb').read()
    base = src[:96 * 1024] + b'\0' * (64 * SECTOR) + src[96 * 1024:128 * 1024]
    base += b'\0' * ((-len(base)) % SECTOR)
    ref = {}
    for codec in ['zlib', 'bzip2', 'adc', 'lzfse', 'raw']:
        name = f'tiny-{codec}.dmg'
        img, pcrc = build(name, codec, base)
        path = os.path.join(OUT, name)
        open(path, 'wb').write(img)
        with tempfile.TemporaryDirectory() as td:
            subprocess.run([SEVENZIP, 'x', '-y', '-tDmg', '-o' + td, path], check=True, stdout=subprocess.DEVNULL)
            files = sorted(os.listdir(td))
            got = open(os.path.join(td, files[0]), 'rb').read()
        assert zlib.crc32(got) & 0xffffffff == pcrc, (name, files)
        ref[name] = {'sha256': hashlib.sha256(img).hexdigest(), 'partitionCrc32': '%08x' % pcrc, 'partitionSize': len(base), 'sevenZipFile': files[0],
                     'sevenZipCrc32': '%08x' % (zlib.crc32(got) & 0xffffffff), 'sha256OfPartition': hashlib.sha256(got).hexdigest()}
        print(name, len(img), ref[name]['sevenZipCrc32'])
    json.dump(ref, open(os.path.join(OUT, 'reference.json'), 'w'), indent=1)


if __name__ == '__main__':
    main()
