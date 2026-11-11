# Build a small but real PyInstaller archive with PyInstaller's own writers (no bootloader, nothing runnable).
# Dev only, needs `pip install pyinstaller`. Usage: python gen-pyinstaller-fixture.py <workdir> <out.bin> <out.ref.json>
import sys, os, json, py_compile
from PyInstaller.archive.writers import CArchiveWriter, ZlibArchiveWriter
from PyInstaller.archive.readers import CArchiveReader
work, out, ref = sys.argv[1:4]
os.makedirs(work, exist_ok=True)
def w(name, text):
    p = os.path.join(work, name); open(p, 'w').write(text); return p
main = w('fixture_main.py', 'from fixture_pkg import helper\nprint(helper.greet("RevLens"))\n')
os.makedirs(os.path.join(work, 'fixture_pkg'), exist_ok=True)
init = w('fixture_pkg/__init__.py', 'VERSION = "1.0"\n')
helper = w('fixture_pkg/helper.py', 'MARKER = "revlens-pyz-member"\n\ndef greet(n):\n    return "hello " + n\n')
boot = w('pyiboot_stub.py', 'import sys\n')
data = w('data.txt', 'plain data file\n')
modpyc = os.path.join(work, 'pyimod_stub.pyc'); py_compile.compile(boot, cfile=modpyc, doraise=True)
pyz = os.path.join(work, 'PYZ.pyz')
codes = {'fixture_pkg': compile(open(init).read(), 'fixture_pkg/__init__.py', 'exec'), 'fixture_pkg.helper': compile(open(helper).read(), 'fixture_pkg/helper.py', 'exec')}
ZlibArchiveWriter(pyz, [('fixture_pkg', init, 'PYMODULE'), ('fixture_pkg.helper', helper, 'PYMODULE')], codes)
pkg = os.path.join(work, 'pkg.arch')
CArchiveWriter(pkg, [
    ('pyi-contents-directory _internal', '', False, 'o'),
    ('pyimod_stub', modpyc, True, 'm'),
    ('pyiboot_stub', boot, True, 's'),
    ('fixture_main', main, True, 's'),
    ('data.txt', data, True, 'x'),
    ('PYZ.pyz', pyz, False, 'z'),
], 'libpython3.12.so.1.0')
stub = b'\x7fELF' + b'REVLENS-NOT-A-BOOTLOADER'.ljust(60, b'\0')
blob = stub + open(pkg, 'rb').read() + b'TRAILER'
open(out, 'wb').write(blob)
r = CArchiveReader(out)
z = r.open_embedded_archive('PYZ.pyz')
json.dump({'toc': {k: list(v) for k, v in r.toc.items()}, 'options': r.options, 'pyz': {k: list(v) for k, v in z.toc.items()}, 'size': len(blob)}, open(ref, 'w'), indent=1)
print(out, len(blob))
