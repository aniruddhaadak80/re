#!/usr/bin/env python3
"""Generate the round 4 desktop fixtures in samples/desktop/r4 and their reference values.

Reference values come from independent tools, never from RevLens:
  - LevelDB: a Local Storage folder written by real Chromium (two runs, so LevelDB turns the first
    log into a Snappy-compressed .ldb table on reopen). The live key set is read with plyvel (the
    LevelDB C++ library) and every compressed block is decompressed with python-snappy.
  - dconf: key files compiled into a binary GVDB database with `dconf compile`, then read back with
    `dconf dump /` through a DCONF_PROFILE that points at it.
  - app folders: game engine and .NET layouts built from real files where the sandbox can make
    them (dotnet publish for .NET; Godot, Unity, Unreal, GameMaker, Ren'Py and RPG Maker headers
    written per their public format notes and checked with Python readers here).

Run from the repository root:
  REVLENS_CHROMIUM=... REVLENS_DESKTOP_TOOLS=... python3 packages/desktop/scripts/gen-r4-fixtures.py [leveldb] [dconf] [engines]
Needs: plyvel (pip install plyvel-ci), python-snappy, Chromium, dconf (dconf-cli), dotnet.
"""
import hashlib, json, os, shutil, struct, subprocess, sys, tempfile

OUT = os.path.join('samples', 'desktop', 'r4')
REF_PATH = os.path.join(OUT, 'reference.json')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def tools_env():
    env = dict(os.environ)
    t = env.get('REVLENS_DESKTOP_TOOLS')
    if t:
        env['PATH'] = os.pathsep.join([os.path.join(t, 'usr', 'bin'), os.path.join(t, 'usr', 'sbin'), env.get('PATH', '')])
        libs = [os.path.join(t, 'usr', 'lib', d) for d in ('aarch64-linux-gnu', 'x86_64-linux-gnu')]
        env['LD_LIBRARY_PATH'] = os.pathsep.join([l for l in libs if os.path.isdir(l)] + [env.get('LD_LIBRARY_PATH', '')])
    return env


def load_ref():
    return json.load(open(REF_PATH)) if os.path.exists(REF_PATH) else {}


# ---------------- LevelDB ----------------

def varint(b, i):
    v = shift = 0
    while True:
        c = b[i]; i += 1
        v |= (c & 0x7f) << shift
        if not c & 0x80:
            return v, i
        shift += 7


def table_blocks(b):
    """Footer and index handles (format notes in leveldb/doc/table_format.md); used only to find
    block boundaries, the block bytes themselves are decompressed by python-snappy."""
    import snappy
    assert b[-8:] == bytes.fromhex('57fb808b247547db')
    i = len(b) - 48
    _, i = varint(b, i); _, i = varint(b, i)
    io_, i = varint(b, i); isz, i = varint(b, i)

    def block(off, size):
        raw, t = b[off:off + size], b[off + size]
        return (snappy.uncompress(raw) if t == 1 else raw), t

    idx, _ = block(io_, isz)
    n = struct.unpack_from('<I', idx, len(idx) - 4)[0]
    lim = len(idx) - 4 - 4 * n
    out, p, prev = [], 0, b''
    while p < lim:
        sh, p = varint(idx, p); ns, p = varint(idx, p); vl, p = varint(idx, p)
        key = prev[:sh] + idx[p:p + ns]; p += ns
        v = idx[p:p + vl]; p += vl; prev = key
        off, q = varint(v, 0); size, q = varint(v, q)
        data, t = block(off, size)
        out.append({'offset': off, 'size': size, 'type': t, 'uncompressed': len(data), 'sha256': sha(data)})
    return out


def gen_leveldb(ref):
    import plyvel
    chrome = os.environ['REVLENS_CHROMIUM']
    work = tempfile.mkdtemp(prefix='rl-r4-ldb-')
    page = os.path.join(work, 'p.html')
    open(page, 'w').write("""<title>LS</title><script>
for (let i = 0; i < 3000; i++) localStorage.setItem('item' + i, 'value ' + i + ' ' + 'abcdefgh'.repeat(25));
for (let i = 0; i < 3000; i += 3) localStorage.removeItem('item' + i);
localStorage.setItem('theme', 'dark'); localStorage.setItem('authToken', 'abc123'); localStorage.setItem('\u540d\u524d', '\u5024');
document.title = 'done'</script>""")
    ud = os.path.join(work, 'ud')
    for _ in range(2):
        r = subprocess.run([chrome, '--headless', '--disable-gpu', f'--user-data-dir={ud}', '--no-first-run', '--dump-dom', 'file://' + page], capture_output=True, text=True, timeout=120, env=tools_env())
        assert '<title>done</title>' in r.stdout, r.stderr[-500:]
    src = os.path.join(ud, 'Default', 'Local Storage', 'leveldb')
    dst = os.path.join(OUT, 'leveldb')
    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    for n in sorted(os.listdir(src)):
        if n.endswith(('.ldb', '.log')) or n == 'CURRENT' or n.startswith('MANIFEST-'):
            shutil.copy(os.path.join(src, n), os.path.join(dst, n))
    tables = [n for n in os.listdir(dst) if n.endswith('.ldb')]
    assert tables, 'Chromium did not write a table file; run again'
    # plyvel reads a scratch copy (opening a LevelDB folder may rewrite it)
    scratch = os.path.join(work, 'scratch'); shutil.copytree(dst, scratch)
    db = plyvel.DB(scratch)
    live = [(k, v) for k, v in db]
    db.close()
    ref['leveldb'] = {
        'files': {n: sha(open(os.path.join(dst, n), 'rb').read()) for n in sorted(os.listdir(dst))},
        'live_count': len(live),
        'live_sha256': sha(b''.join(struct.pack('<I', len(k)) + k + struct.pack('<I', len(v)) + v for k, v in live)),
        'first_keys_hex': [k.hex() for k, _ in live[:5]],
        'tables': {n: table_blocks(open(os.path.join(dst, n), 'rb').read()) for n in sorted(tables)},
    }
    shutil.rmtree(work, ignore_errors=True)


# ---------------- dconf GVDB ----------------

DCONF_KEYFILE = r"""[org/revlens/fixture]
theme='dark'
font-size=uint32 14
zoom=1.25
enabled=true
recent=['a.txt', 'b.txt', "it's"]
empty-list=@as []
window=(800, 600)
count=int64 -5
small=byte 0x07
map={'one': <1>, 'two': <'2'>}
label='名前'

[org/revlens/fixture/child]
nested=true
path=objectpath '/org/revlens'

[org/other]
value=-3
maybe=@mi 5
nothing=@ms nothing
pairs=[(1, 'a'), (2, 'b')]
dict={'k': 'v'}

[org/revlens/stress]
tenth=0.10000000000000001
big=1e300
tiny=-2.5e-10
whole=3.0
neg-zero=-0.0
u64=uint64 18446744073709551615
i64min=int64 -9223372036854775808
i16=int16 -32768
u16=uint16 65535
bytes=b'hello'
raw-bytes=[byte 0x00, 0x01, 0xff]
nested=<<[1, 2]>>
asv={'a': <true>, 'b': <@as ['x']>, 'c': <(1, 'two', 3.5)>}
unit=()
single=(1,)
mmi=@mmi nothing
mmi-just=@mmi just nothing
mixed=('a', [byte 0x01], 'bb', @ay [], 7)
escapes='tab\there \u00e9 \\ back \U0001f600 \u0007'
quote-both="it's \"q\""
aas=[['a', 'bb'], [], ['ccc']]
sig=signature 'a{sv}'
empty-dict=@a{sv} {}
"""


def gen_dconf(ref):
    env = tools_env()
    work = tempfile.mkdtemp(prefix='rl-r4-dconf-')
    kd = os.path.join(work, 'keyfiles'); os.makedirs(kd)
    open(os.path.join(kd, '00-fixture'), 'w').write(DCONF_KEYFILE)
    dst = os.path.join(OUT, 'dconf'); os.makedirs(dst, exist_ok=True)
    db = os.path.join(dst, 'user')
    subprocess.run(['dconf', 'compile', db, kd], check=True, env=env, timeout=60)
    # dconf dump through a profile that names this file as the user database
    cfg = os.path.join(work, 'config', 'dconf'); os.makedirs(cfg)
    shutil.copy(db, os.path.join(cfg, 'user'))
    prof = os.path.join(work, 'profile'); open(prof, 'w').write('user-db:user\n')
    e = dict(env, DCONF_PROFILE=prof, XDG_CONFIG_HOME=os.path.join(work, 'config'), XDG_RUNTIME_DIR=work, DBUS_SESSION_BUS_ADDRESS='disabled:')
    dump = subprocess.run(['dconf', 'dump', '/'], capture_output=True, text=True, env=e, timeout=60)
    assert dump.returncode == 0, dump.stderr
    sub = subprocess.run(['dconf', 'dump', '/org/revlens/'], capture_output=True, text=True, env=e, timeout=60).stdout
    listing = subprocess.run(['dconf', 'list', '/org/revlens/fixture/'], capture_output=True, text=True, env=e, timeout=60).stdout
    ref['dconf'] = {'user_sha256': sha(open(db, 'rb').read()), 'dump': dump.stdout, 'dump_org_revlens': sub, 'list_fixture': listing.split()}
    shutil.rmtree(work, ignore_errors=True)


def gen_snappy(ref):
    """Compress varied inputs with python-snappy (the C++ library) for the decoder test."""
    import base64, random, snappy
    rnd = random.Random(20261112)
    inputs = [b'', b'a', b'abc' * 1000, bytes(range(256)) * 300, bytes(rnd.getrandbits(8) for _ in range(40000)),
              b''.join(rnd.choice([b'alpha ', b'beta ', b'gamma ', bytes([rnd.getrandbits(8)])]) for _ in range(12000)),
              b'x' * 100000, (b'0123456789abcdef' * 4096) + bytes(rnd.getrandbits(8) for _ in range(5000))]
    out = []
    for raw in inputs:
        c = snappy.compress(raw)
        assert snappy.uncompress(c) == raw
        out.append({'compressed_b64': base64.b64encode(c).decode(), 'length': len(raw), 'sha256': sha(raw)})
    path = os.path.join(OUT, 'snappy-vectors.json')
    json.dump(out, open(path, 'w'))
    ref['snappy_vectors_sha256'] = sha(open(path, 'rb').read())


def main():
    os.makedirs(OUT, exist_ok=True)
    ref = load_ref()
    parts = sys.argv[1:] or ['leveldb', 'dconf', 'snappy', 'engines']
    if 'leveldb' in parts:
        gen_leveldb(ref)
    if 'dconf' in parts:
        gen_dconf(ref)
    if 'snappy' in parts:
        gen_snappy(ref)
    if 'engines' in parts:
        import importlib.util
        spec = importlib.util.spec_from_file_location('engines', os.path.join(os.path.dirname(__file__), 'gen-r4-engines.py'))
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        m.gen(ref, OUT, tools_env())
    json.dump(ref, open(REF_PATH, 'w'), indent=1, ensure_ascii=False, sort_keys=True)
    print('wrote', REF_PATH)


if __name__ == '__main__':
    main()
