# Builds hello-fat.macho (universal binary) from the two thin Mach-O files.
# Fat header layout per Apple <mach-o/fat.h>. Run from samples/disasm.
import struct
thin = [("hello-x64.macho", 0x01000007, 3), ("hello-arm64.macho", 0x0100000c, 0)]
align = 14
blobs = [open(n, "rb").read() for n, _, _ in thin]
hdr = struct.pack(">II", 0xCAFEBABE, len(thin))
off = 1 << align
archs = b""; body = []
for (n, cpu, sub), b in zip(thin, blobs):
    archs += struct.pack(">IIIII", cpu, sub, off, len(b), align)
    body.append((off, b)); off += (len(b) + (1 << align) - 1) & ~((1 << align) - 1)
out = bytearray(off)
out[:len(hdr) + len(archs)] = hdr + archs
for o, b in body: out[o:o + len(b)] = b
open("hello-fat.macho", "wb").write(out)
