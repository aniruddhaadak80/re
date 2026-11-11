# Removes .debug_* sections from a 32/64-bit little endian ELF, keeping .symtab/.strtab.
# Usage: python3 strip-debug.py in.elf out.elf [--all]  (--all also drops .symtab/.strtab, like strip -s)
#  (used because zig objcopy crashed on aarch64 hosts)
import struct, sys
d = open(sys.argv[1], "rb").read()
is64 = d[4] == 2
if is64:
    shoff, = struct.unpack_from("<Q", d, 0x28); shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
    SH = "<IIQQQQIIQQ"
else:
    shoff, = struct.unpack_from("<I", d, 0x20); shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2e)
    SH = "<IIIIIIIIII"
shs = [list(struct.unpack_from(SH, d, shoff + i * shentsize)) for i in range(shnum)]
OFF, SIZE, TYPE, LINK, FLAGS = (4, 5, 1, 6, 2) if is64 else (4, 5, 1, 6, 2)
strtab = shs[shstrndx]
name = lambda s: d[strtab[OFF] + s[0]:].split(b"\0", 1)[0].decode()
drop_all = "--all" in sys.argv[3:]
keep = [i for i, s in enumerate(shs) if not name(s).startswith(".debug") and not (drop_all and name(s) in (".symtab", ".strtab", ".comment"))]
remap = {old: new for new, old in enumerate(keep)}
alloc_end = max((s[OFF] + (s[SIZE] if s[TYPE] != 8 else 0)) for s in shs if s[FLAGS] & 2)
out = bytearray(d[:alloc_end])
new = []
for i in keep:
    s = list(shs[i])
    if not (s[FLAGS] & 2) and s[TYPE] != 0 and s[TYPE] != 8:
        while len(out) % 8: out.append(0)
        data = d[s[OFF]:s[OFF] + s[SIZE]]
        s[OFF] = len(out); out += data
    s[LINK] = remap.get(s[LINK], 0)
    if s[TYPE] in (4, 9): s[7] = remap.get(s[7], s[7])  # sh_info of REL/RELA points at a section
    new.append(s)
while len(out) % 8: out.append(0)
new_shoff = len(out)
for s in new: out += struct.pack(SH, *s)
if is64:
    struct.pack_into("<Q", out, 0x28, new_shoff); struct.pack_into("<HHH", out, 0x3a, shentsize, len(new), remap[shstrndx])
else:
    struct.pack_into("<I", out, 0x20, new_shoff); struct.pack_into("<HHH", out, 0x2e, shentsize, len(new), remap[shstrndx])
open(sys.argv[2], "wb").write(out)
