#!/usr/bin/env python3
"""Build the UEFI, EFI/Tiano, TRX and router image fixtures and record reference values.

Compression comes from EDK2's own compressors as packaged in uefi_firmware 1.16 (pip install
uefi_firmware): EfiCompress, TianoCompress and LzmaCompress. The firmware volume is assembled
here by hand following the PI specification (FV header, FFS2 files, sections), then parsed back
with uefi_firmware's independent parser to record which files and sections it sees. The TRX image
and the router image (uImage + squashfs, the OpenWrt sysupgrade layout) are checked with
binwalk 2.4.3. Run from the repository root:
  python3 packages/extras/scripts/gen-uefi-trx-fixtures.py
"""
import hashlib, json, os, struct, subprocess, uuid, zlib, random, lzma
from uefi_firmware import efi_compressor as E
import uefi_firmware

OUT = 'samples/extras/firmware'
U = os.path.join(OUT, 'uefi')
os.makedirs(U, exist_ok=True)
sha = lambda b: hashlib.sha256(b).hexdigest()
random.seed(11)
plain = (b'RevLens EFI test ' * 400) + bytes(random.randrange(256) for _ in range(3000)) + b'\x00' * 5000 + bytes(range(256)) * 40
open(f'{U}/plain.bin', 'wb').write(plain)
open(f'{U}/plain.efi', 'wb').write(E.EfiCompress(plain, len(plain)))
open(f'{U}/plain.tiano', 'wb').write(E.TianoCompress(plain, len(plain)))

g = lambda s: uuid.UUID(s).bytes_le
FFS2 = '8C8CE578-8A3D-4F1C-9935-896185C32DD3'
LZMA_GUID = 'EE4E5898-3914-4259-9D6E-DC7BD79403CF'
TIANO_GUID = 'A31280AD-481E-41B6-95E8-127F4C984779'
pad4 = lambda b: b + b'\x00' * (-len(b) % 4)

def section(t, body):
    n = 4 + len(body)
    return struct.pack('<I', n)[:3] + bytes([t]) + body
def ui(name): return section(0x15, name.encode('utf-16-le') + b'\x00\x00')
def version(build, s): return section(0x14, struct.pack('<H', build) + s.encode('utf-16-le') + b'\x00\x00')
def sections(*secs): return b''.join(pad4(s) for s in secs[:-1]) + secs[-1]
def compressed(inner): return section(0x01, struct.pack('<IB', len(inner), 1) + E.EfiCompress(inner, len(inner)))
def guided(gs, data): return section(0x02, g(gs) + struct.pack('<HH', 24, 1) + data)
def fake_pe(tag):
    # a small MZ/PE image header followed by a tagged body (not executable; parsers only need the bytes)
    return b'MZ' + b'\x00' * 58 + struct.pack('<I', 64) + b'PE\x00\x00' + struct.pack('<HH', 0xAA64, 0) + tag * 64

def ffs(name, ftype, body, erase=0xff):
    size = 24 + len(body)
    hdr = bytearray(g(name) + b'\x00\x00' + bytes([ftype, 0]) + struct.pack('<I', size)[:3] + b'\x00')
    hdr[16] = (0x100 - (sum(hdr) & 0xff)) & 0xff
    hdr[17] = 0xaa
    hdr[23] = 0xf8 if erase == 0xff else 0x07
    return bytes(hdr) + body

def volume(files, erase=0xff, size=None):
    hlen = 72
    body = b''
    for f in files:
        body += f + bytes([erase]) * (-(hlen + len(body) + len(f)) % 8)
    total = size or (hlen + len(body) + 7) // 8 * 8 + 0x100
    hdr = bytearray(b'\x00' * 16 + g(FFS2) + struct.pack('<Q', total) + b'_FVH' + struct.pack('<IHHHBB', 0x0004FEFF if erase == 0xff else 0x0004F6FF, hlen, 0, 0, 0, 2) + struct.pack('<II', total // 0x100 if total % 0x100 == 0 else 1, 0x100 if total % 0x100 == 0 else total) + struct.pack('<II', 0, 0))
    csum = sum(struct.unpack('<%dH' % (hlen // 2), bytes(hdr))) & 0xffff
    struct.pack_into('<H', hdr, 50, (0x10000 - csum) & 0xffff)
    vol = bytes(hdr) + body
    return vol + bytes([erase]) * (total - len(vol))

pe1, pe2, raw1 = fake_pe(b'DXE1'), fake_pe(b'APP2'), plain[:4000]
inner_lz = sections(section(0x19, raw1), ui('RevLensConfig'))
lz = E.LzmaCompress(inner_lz, len(inner_lz))
inner_ti = sections(section(0x10, pe2), ui('RevLensApp'))
ti = E.TianoCompress(inner_ti, len(inner_ti))
nested = volume([ffs('5C60F367-A505-419A-859E-2A4FF6CA6FE5', 0x01, b'nested raw file ' * 32)], size=0x400)
files = [
    ffs('11111111-2222-4333-8444-555555555555', 0x07, sections(ui('RevLensDxe'), version(7, '1.0'), compressed(sections(section(0x10, pe1), section(0x13, b'\x08'))))),
    ffs('22222222-3333-4444-8555-666666666666', 0x02, guided(LZMA_GUID, lz)),
    ffs('33333333-4444-4555-8666-777777777777', 0x09, guided(TIANO_GUID, ti)),
    ffs('44444444-5555-4666-8777-888888888888', 0x0b, section(0x17, nested)),
]
fv = volume(files, size=0x4000)
blob = b'\xff' * 0x1000 + fv + b'\xff' * 0x800
open(f'{U}/revlens-fv.bin', 'wb').write(blob)

# Independent parse with uefi_firmware: walk every object and record leaf section bytes
parsed = uefi_firmware.AutoParser(blob)
fw = parsed.parse()
leaves = []
def walk(o, fguid=None):
    for c in (o.objects if getattr(o, 'objects', None) else []):
        if c is None: continue
        name = type(c).__name__
        if name == 'FirmwareFile':
            fguid = str(c.guid) if not isinstance(c.guid, bytes) else str(uuid.UUID(bytes_le=c.guid)).upper()
            if c.type == 1: leaves.append({'file': fguid.upper(), 'type': 'raw-file', 'size': len(c.data), 'sha256': sha(bytes(c.data))})
        if name == 'FirmwareFileSystemSection' and c.type not in (1, 2, 23):
            leaves.append({'file': fguid.upper() if fguid else None, 'type': c.type, 'size': len(c.data), 'sha256': sha(bytes(c.data))})
        walk(c, fguid)
walk(fw)
ref = {
  'tool': 'uefi_firmware ' + getattr(uefi_firmware, '__version__', '1.16') + ' (EDK2 compressors and its own FV parser)',
  'plain.bin': {'size': len(plain), 'sha256': sha(plain)},
  'efi': {'size': len(plain), 'sha256': sha(E.EfiDecompress(open(f'{U}/plain.efi','rb').read(), os.path.getsize(f'{U}/plain.efi')))},
  'tiano': {'size': len(plain), 'sha256': sha(E.TianoDecompress(open(f'{U}/plain.tiano','rb').read(), os.path.getsize(f'{U}/plain.tiano')))},
  'fv': {'offset': 0x1000, 'length': len(fv), 'files': 4, 'leafSections': leaves,
         'expect': {'pe1': sha(pe1), 'pe2': sha(pe2), 'raw1': sha(raw1), 'nestedRaw': sha(b'nested raw file ' * 32)}},
}

# TRX v1: an LZMA kernel and the xz squashfs, as Broadcom routers ship them
kernel = plain[:20000]
klz = lzma.compress(kernel, format=lzma.FORMAT_ALONE, filters=[{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 20}])
sq = open(f'{OUT}/rootfs-xz.squashfs', 'rb').read()
hdr_len = 28
k_off = hdr_len
fs_off = (k_off + len(klz) + 0xfff) // 0x1000 * 0x1000
body = bytearray(fs_off + len(sq))
body[k_off:k_off + len(klz)] = klz
body[fs_off:] = sq
total = (len(body) + 0xfff) // 0x1000 * 0x1000
body += b'\x00' * (total - len(body))
struct.pack_into('<4sIIHHIII', body, 0, b'HDR0', total, 0, 0, 1, k_off, fs_off, 0)
crc = (zlib.crc32(bytes(body[12:])) ^ 0xffffffff) & 0xffffffff
struct.pack_into('<I', body, 8, crc)
open(f'{OUT}/revlens.trx', 'wb').write(bytes(body))

# Router image: 0x40 vendor header, uImage with an LZMA kernel at 0x40, squashfs at the next 64 KiB
import tempfile
with tempfile.TemporaryDirectory() as d:
    open(f'{d}/k.lzma', 'wb').write(klz)
    subprocess.run(['mkimage', '-A', 'mips', '-O', 'linux', '-T', 'kernel', '-C', 'lzma', '-a', '0x80060000', '-e', '0x80060000', '-n', 'RevLens router kernel', '-d', f'{d}/k.lzma', f'{d}/u.bin'], check=True, capture_output=True, env={**os.environ, 'SOURCE_DATE_EPOCH': '1700000000'})
    uimg = open(f'{d}/u.bin', 'rb').read()
vendor = b'RVLN' + struct.pack('>I', 1) + b'RevLens test router'.ljust(56, b'\x00')
img = bytearray(vendor + uimg)
img += b'\xff' * (-len(img) % 0x10000)
sq_off = len(img)
img += sq
img += b'\xff' * (-len(img) % 0x10000)
open(f'{OUT}/router.bin', 'wb').write(bytes(img))

def binwalk(p):
    out = subprocess.run(['binwalk', p], capture_output=True, text=True, timeout=120).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            rows.append({'offset': int(parts[0]), 'description': parts[2].split(',')[0]})
    return rows
ref['trx'] = {'kernelOffset': k_off, 'kernelSha256': sha(kernel), 'rootfsOffset': fs_off, 'length': total, 'crc32': crc, 'binwalk': binwalk(f'{OUT}/revlens.trx')}
ref['router'] = {'uimageOffset': 0x40, 'squashfsOffset': sq_off, 'kernelSha256': sha(kernel), 'binwalk': binwalk(f'{OUT}/router.bin')}
json.dump(ref, open(f'{OUT}/uefi-trx.reference.json', 'w'), indent=1)
print(json.dumps({k: (v if k in ('trx', 'router') else '...') for k, v in ref.items()}, indent=1)[:3000])
print(len(leaves), 'leaf sections from uefi_firmware')
