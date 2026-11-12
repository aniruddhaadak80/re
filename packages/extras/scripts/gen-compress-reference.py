#!/usr/bin/env python3
"""Record reference SHA-256 values for the compression and squashfs fixtures.

Each value comes from an independent decoder: Python's lzma module (liblzma) for .xz and .lzma,
lzop -d for .lzo, bzip2 -d for .bz2, zstd -d for .zst, gzip -d for .gz, and unsquashfs 4.6.1 for every regular file
and symlink target in the squashfs images. Run from the repository root with lzop, zstd and
unsquashfs on PATH:  python3 packages/extras/scripts/gen-compress-reference.py
"""
import hashlib, json, lzma, os, subprocess, sys, tempfile, glob

ROOT = sys.argv[1] if len(sys.argv) > 1 else 'samples/extras'
sha = lambda b: hashlib.sha256(b).hexdigest()

def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, timeout=120, **kw).stdout

comp = {}
cdir = os.path.join(ROOT, 'compress')
for f in sorted(os.listdir(cdir)):
    p = os.path.join(cdir, f)
    if f.endswith('.xz') or f.endswith('.lzma'):
        out, tool = lzma.decompress(open(p, 'rb').read()), 'python3 lzma ' + sys.version.split()[0]
    elif f.endswith('.lzo'):
        out, tool = run(['lzop', '-d', '-c', p]), run(['lzop', '--version']).decode().split('\n')[0].strip()
    elif f.endswith('.zst'):
        out, tool = run(['zstd', '-d', '-c', p]), run(['zstd', '--version']).decode().strip()
    elif f.endswith('.bz2'):
        out, tool = run(['bzip2', '-d', '-c', p]), 'bzip2 1.0.8 -d'
    elif f.endswith('.gz'):
        out, tool = run(['gzip', '-d', '-c', p]), 'gzip -d'
    else:
        continue
    comp[f] = {'size': len(out), 'sha256': sha(out), 'tool': tool}
json.dump(comp, open(os.path.join(cdir, 'reference.json'), 'w'), indent=1, sort_keys=True)

sq = {}
for p in sorted(glob.glob(os.path.join(ROOT, 'firmware', '*.squashfs'))):
    with tempfile.TemporaryDirectory() as d:
        dest = os.path.join(d, 'r')
        run(['unsquashfs', '-no-xattrs', '-d', dest, p])
        files = {}
        for base, dirs, names in os.walk(dest):
            for n in dirs + names:
                full = os.path.join(base, n)
                rel = os.path.relpath(full, dest)
                if os.path.islink(full):
                    files[rel] = {'type': 'symlink', 'target': os.readlink(full)}
                elif os.path.isdir(full):
                    files[rel] = {'type': 'dir'}
                else:
                    b = open(full, 'rb').read()
                    files[rel] = {'type': 'file', 'size': len(b), 'sha256': sha(b)}
        sq[os.path.basename(p)] = {'tool': 'unsquashfs 4.6.1', 'files': dict(sorted(files.items()))}
json.dump(sq, open(os.path.join(ROOT, 'firmware', 'squashfs.reference.json'), 'w'), indent=1, sort_keys=True)
print('ok', len(comp), 'compressed files,', len(sq), 'squashfs images')
