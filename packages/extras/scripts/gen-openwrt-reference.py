#!/usr/bin/env python3
"""Reference values for the fetched OpenWrt 23.05.5 images (run scripts/fetch-openwrt.mjs first).

For each image: binwalk 2.4.3 signature offsets; every LZMA stream binwalk reports, decoded with
Python's lzma (liblzma), as size and SHA-256; and every squashfs binwalk reports, carved at its
offset and unpacked with unsquashfs 4.6.1, as a map of path to SHA-256 (files) or target
(symlinks). Output: samples/extras/firmware/openwrt/<image>.reference.json (hashes only).
"""
import hashlib, json, lzma, os, subprocess, sys, tempfile

CACHE = 'samples/.cache/extras/openwrt'
OUT = 'samples/extras/firmware/openwrt'
os.makedirs(OUT, exist_ok=True)
sha = lambda b: hashlib.sha256(b).hexdigest()
for f in sorted(os.listdir(CACHE)):
    p = os.path.join(CACHE, f)
    data = open(p, 'rb').read()
    rows = []
    for line in subprocess.run(['binwalk', p], capture_output=True, text=True, timeout=300).stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            rows.append({'offset': int(parts[0]), 'description': parts[2][:160]})
    ref = {'image': f, 'size': len(data), 'sha256': sha(data), 'binwalk': rows, 'lzma': [], 'squashfs': []}
    for r in rows:
        if r['description'].startswith('LZMA compressed data'):
            d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            try:
                out = d.decompress(data[r['offset']:], max_length=64 << 20)
                ref['lzma'].append({'offset': r['offset'], 'size': len(out), 'sha256': sha(out), 'tool': 'python3 lzma'})
            except lzma.LZMAError as e:
                ref['lzma'].append({'offset': r['offset'], 'error': str(e)})
        if r['description'].startswith('Squashfs filesystem'):
            with tempfile.TemporaryDirectory() as t:
                img = os.path.join(t, 'fs.sqsh')
                open(img, 'wb').write(data[r['offset']:])
                rc = subprocess.run(['unsquashfs', '-no-xattrs', '-q', '-d', os.path.join(t, 'r'), img], capture_output=True, timeout=300)
                assert rc.returncode in (0, 2), rc.stderr  # 2: device nodes need root, regular files are fine
                files = {}
                root = os.path.join(t, 'r')
                for base, dirs, names in os.walk(root):
                    for n in dirs + names:
                        full = os.path.join(base, n)
                        rel = os.path.relpath(full, root)
                        if os.path.islink(full): files[rel] = '->' + os.readlink(full)
                        elif os.path.isfile(full): files[rel] = sha(open(full, 'rb').read())
                        else: files[rel] = 'dir'
                ref['squashfs'].append({'offset': r['offset'], 'tool': 'unsquashfs 4.6.1', 'entries': len(files), 'files': dict(sorted(files.items()))})
    json.dump(ref, open(os.path.join(OUT, f + '.reference.json'), 'w'), separators=(',', ':'), sort_keys=True)
    print(f, len(rows), 'binwalk rows', [x.get('size') for x in ref['lzma']], [s['entries'] for s in ref['squashfs']])
