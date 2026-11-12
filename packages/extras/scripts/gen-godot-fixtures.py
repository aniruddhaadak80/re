#!/usr/bin/env python3
"""Export Godot .pck fixtures with the real Godot editors and check them with the real engine.

Needs the official linux.arm64 editors of Godot 3.6, 4.3, 4.4.1 and 4.5.1 in $GODOT_DIR
(default /workspace/work/tools/godot) and, for 3.6, an X display (Xvfb) in $DISPLAY.
For each pack: the export log's "Storing File" list is the reference file list, the MD5 of
each plain source file is the reference MD5, and running the engine with --main-pack (and with
the pack embedded at the end of a copy of the engine binary) must print the first line of
res://data.txt. The committed embedded fixtures append the same packs, laid out the same way,
to the small samples/extras/demo-arm64-stripped.elf host instead of the 50+ MB engine.
"""
import hashlib, json, os, re, shutil, struct, subprocess, tempfile

GD = os.environ.get('GODOT_DIR', '/workspace/work/tools/godot')
SRC = 'samples/extras/src/godot'
OUT = 'samples/extras/containers/godot'
HOST = 'samples/extras/demo-arm64-stripped.elf'
KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
os.makedirs(OUT, exist_ok=True)
env = {**os.environ, 'HOME': tempfile.mkdtemp(), 'GODOT_SCRIPT_ENCRYPTION_KEY': KEY}
md5 = lambda b: hashlib.md5(b).hexdigest()

def godot(ver): return os.path.join(GD, f'Godot_v{ver}-stable_linux.arm64')
def run_args(ver): return ['--no-window', '--audio-driver', 'Dummy'] if ver.startswith('3') else ['--headless']

def export(ver, proj, preset, out):
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(os.path.join(SRC, proj), os.path.join(d, 'p'))
        r = subprocess.run([godot(ver), *(['--no-window'] if ver.startswith('3') else ['--headless']), '--path', os.path.join(d, 'p'), '--export-pack', preset, os.path.abspath(out)], env=env, capture_output=True, text=True, timeout=300)
        files = sorted(set(re.findall(r'Storing File: (res://[^\s\x1b]+)', r.stdout)))
        assert os.path.exists(out), r.stdout[-2000:] + r.stderr[-2000:]
        return files

def runs(ver, args, cwd):
    r = subprocess.run(args + run_args(ver) + ['--script', 'res://main.gd'], env=env, capture_output=True, text=True, timeout=120, cwd=cwd)
    m = re.search(r'REVLENS-PCK (.*)', r.stdout)
    return m.group(1) if m else None

def embed(host, pck, absolute):
    h = open(host, 'rb').read()
    b = bytearray(open(pck, 'rb').read())
    start = len(h) + (-len(h)) % 8
    ver = struct.unpack_from('<I', b, 4)[0]
    if ver == 2: struct.pack_into('<I', b, 20, struct.unpack_from('<I', b, 20)[0] | 2)  # relative file base, as Godot 4 embedding does
    if ver <= 1 and absolute:  # Godot 3 embedding stores absolute offsets
        n = struct.unpack_from('<I', b, 84)[0]; p = 88
        for _ in range(n):
            sl = struct.unpack_from('<I', b, p)[0]; p += 4 + sl
            struct.pack_into('<Q', b, p, struct.unpack_from('<Q', b, p)[0] + start); p += 32
    return h + b'\0' * (start - len(h)) + bytes(b) + struct.pack('<Q', len(b)) + b'GDPC', start

plain = {f'res://{p}': md5(open(os.path.join(SRC, 'proj4', p), 'rb').read()) for p in ['data.txt', 'config.json', 'levels/level1.txt']}
ref = {'tool': 'Godot 3.6, 4.3, 4.4.1, 4.5.1 official linux.arm64 editors and engines', 'encryptionKey': KEY, 'sourceMd5': plain, 'packs': {}}
cases = [('3.6', 'proj3', 'Linux', 'godot36.pck'), ('4.3', 'proj4', 'Linux', 'godot43.pck'), ('4.5.1', 'proj4', 'Linux', 'godot451.pck'),
         ('4.3', 'proj4', 'LinuxEnc', 'godot43-enc.pck'), ('4.4.1', 'proj4', 'LinuxEncDir', 'godot441-encdir.pck')]
with tempfile.TemporaryDirectory() as w:
    for ver, proj, preset, name in cases:
        out = os.path.join(OUT, name)
        files = export(ver, proj, preset, out)
        b = open(out, 'rb').read()
        e = {'engine': ver, 'formatVersion': struct.unpack_from('<I', b, 4)[0], 'files': files, 'size': len(b)}
        if 'enc' not in name:
            e['mainPackRun'] = runs(ver, [godot(ver), '--main-pack', os.path.abspath(out)], w)
            exe, _ = embed(godot(ver), out, True)
            game = os.path.join(w, 'game'); open(game, 'wb').write(exe); os.chmod(game, 0o755)
            e['embeddedRun'] = runs(ver, [game], w)
            small, start = embed(HOST, out, True)
            open(os.path.join(OUT, name.replace('.pck', '-embedded.elf')), 'wb').write(small)
            e['embeddedStart'] = start
        ref['packs'][name] = e
        print(name, e.get('mainPackRun'), e.get('embeddedRun'), len(files))
json.dump(ref, open(os.path.join(OUT, 'reference.json'), 'w'), indent=1)
