#!/bin/sh
# Build small firmware fixtures with the real tools (squashfs-tools 4.6.1, u-boot-tools mkimage
# 2025.01, mkbootimg 34.0.5, GNU cpio 2.15, xz, lzop, zstd) and record unsquashfs listings.
set -e
out=${1:-samples/extras/firmware}
work=$(mktemp -d)
mkdir -p "$out"; out=$(cd "$out" && pwd)
root="$work/root"
mkdir -p "$root/etc/config" "$root/bin" "$root/www/cgi-bin" "$root/lib"
printf 'config system\n\toption hostname RevLens\n' > "$root/etc/config/system"
printf '#!/bin/sh\necho hello from revlens\n' > "$root/bin/hello"; chmod 755 "$root/bin/hello"
python3 -c "import random; random.seed(7); open('$root/lib/libdata.so','wb').write(bytes(random.randrange(256) for _ in range(70000)) + b'RevLens'*20000)"
head -c 300000 /dev/zero > "$root/lib/zeros.bin"
printf '<html>RevLens test</html>\n' > "$root/www/index.html"
ln -s ../bin/hello "$root/www/cgi-bin/hello"
ln -s /etc/config/system "$root/etc/system.link"
truncate -s 200000 "$root/lib/sparse.img"; printf 'tail' >> "$root/lib/sparse.img"
for c in gzip xz lzo lz4 zstd; do
  mksquashfs "$root" "$out/rootfs-$c.squashfs" -comp $c -b 65536 -noappend -all-root -mkfs-time 1700000000 -all-time 1700000000 -quiet >/dev/null
  unsquashfs -lln "$out/rootfs-$c.squashfs" | sed "s/ [0-9-]* [0-9:]* squashfs-root/ squashfs-root/" > "$out/rootfs-$c.unsquashfs.txt"
done
mksquashfs "$root" "$out/rootfs-xz-bcj.squashfs" -comp xz -Xbcj arm,x86 -noappend -all-root -mkfs-time 1700000000 -all-time 1700000000 -quiet >/dev/null
unsquashfs -lln "$out/rootfs-xz-bcj.squashfs" > "$out/rootfs-xz-bcj.unsquashfs.txt"
(cd "$root" && find . | LC_ALL=C sort | cpio -o -H newc --quiet --reproducible > "$work/initramfs.cpio")
gzip -9 -n -c "$work/initramfs.cpio" > "$out/initramfs.cpio.gz"
# uImage with a gzip payload and an lzma payload, then a FIT image holding a kernel and a ramdisk
head -c 50000 "$root/lib/libdata.so" > "$work/kernel.bin"
gzip -9 -n -c "$work/kernel.bin" > "$work/kernel.gz"
SOURCE_DATE_EPOCH=1700000000 mkimage -A arm -O linux -T kernel -C gzip -a 0x80008000 -e 0x80008000 -n "RevLens kernel" -d "$work/kernel.gz" "$out/uImage-gzip.bin" >/dev/null
xz --format=lzma -9 -c "$work/kernel.bin" > "$work/kernel.lzma"
SOURCE_DATE_EPOCH=1700000000 mkimage -A mips -O linux -T kernel -C lzma -a 0x80000000 -e 0x80000000 -n "RevLens lzma kernel" -d "$work/kernel.lzma" "$out/uImage-lzma.bin" >/dev/null
cat > "$work/fit.its" <<ITS
/dts-v1/;
/ {
  description = "RevLens FIT";
  #address-cells = <1>;
  images {
    kernel-1 { description = "kernel"; data = /incbin/("$work/kernel.gz"); type = "kernel"; arch = "arm64"; os = "linux"; compression = "gzip"; load = <0x80080000>; entry = <0x80080000>; hash-1 { algo = "sha1"; }; };
    ramdisk-1 { description = "initramfs"; data = /incbin/("$out/initramfs.cpio.gz"); type = "ramdisk"; arch = "arm64"; os = "linux"; compression = "none"; hash-1 { algo = "crc32"; }; };
  };
  configurations { default = "conf-1"; conf-1 { kernel = "kernel-1"; ramdisk = "ramdisk-1"; }; };
};
ITS
SOURCE_DATE_EPOCH=1700000000 mkimage -f "$work/fit.its" "$out/fit.itb" >/dev/null
# Android boot images v0 to v4
head -c 4096 "$root/lib/libdata.so" > "$work/second.bin"
for v in 0 1 2 3 4; do
  extra=""
  [ $v -le 2 ] && extra="--second $work/second.bin --pagesize 2048 --base 0x10000000"
  [ $v -eq 2 ] && extra="$extra --dtb $work/second.bin"
  [ $v -ge 1 ] && [ $v -le 2 ] && extra="$extra --recovery_dtbo $work/second.bin"
  mkbootimg --header_version $v --kernel "$work/kernel.gz" --ramdisk "$out/initramfs.cpio.gz" --cmdline "console=ttyS0 revlens=$v" --os_version 14.0.0 --os_patch_level 2024-06 $extra -o "$out/boot-v$v.img"
done
rm -rf "$work"
