"""Builds fw-blob.bin: a firmware-like blob with a uImage (written by the uboot package,
BSD-3), a gzip stream (Python zlib), a device tree (board.dtb) and an ELF, at known offsets.
binwalk 2.4.3 is the reference scanner used to check the offsets."""
import os, gzip, uboot
os.chdir(os.path.join(os.path.dirname(__file__), '..'))
kernel = bytes(range(256)) * 64
img = uboot.new_img(image='firmware', data=kernel, arch='arm', os='linux', compress='none', load_address=0x80008000, entry_address=0x80008000, name='RevLens test kernel')
uimg = img.export()
gz = gzip.compress(b'revlens firmware payload\n' * 200, mtime=0)
dtb = open('board.dtb', 'rb').read()
elf = open('demo-arm64-stripped.elf', 'rb').read()[:4096]
blob = bytearray(b'\xff' * 0x100)
offs = {}
for name, part in [('uimage', uimg), ('gzip', gz), ('fdt', dtb), ('elf', elf)]:
    while len(blob) % 0x100: blob.append(0xff)
    offs[name] = len(blob); blob += part
open('fw-blob.bin', 'wb').write(bytes(blob))
open('uimage.bin', 'wb').write(uimg)
print(offs, len(uimg))
