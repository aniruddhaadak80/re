#!/usr/bin/env python3
"""Generate the round 3 desktop fixtures in samples/desktop/r3 and their reference values.

Every reference value is computed here with Python's own readers (json, configparser, sqlite3,
zipfile, xml.etree, plistlib, gzip), with ImageMagick for the XWD image and with strace's own
-C summary for the syscall counts, so the TypeScript tests compare against independent tools.

Run from the repository root:  python3 packages/desktop/scripts/gen-r3-fixtures.py
Needs: ImageMagick (convert) and strace on PATH for the image and strace fixtures (skipped otherwise).
"""
import configparser, gzip, hashlib, io, json, os, plistlib, shutil, sqlite3, subprocess, sys, zipfile
import xml.etree.ElementTree as ET

OUT = os.path.join('samples', 'desktop', 'r3')
HOME = os.path.join(OUT, 'task-home')


def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def main():
    if os.path.exists(HOME):
        shutil.rmtree(HOME)
    ref = {}
    # text
    w(os.path.join(HOME, 'Documents/todo.txt'), 'buy milk\nwalk the dog\nbuy bread\n')
    ref['todo_lines'] = open(os.path.join(HOME, 'Documents/todo.txt')).read().splitlines()
    # json with a secret
    settings = {'theme': 'dark', 'fontSize': 14, 'recent': [{'name': 'a.txt', 'pinned': True}, {'name': 'b.txt', 'pinned': False}], 'sync': {'apiToken': 'tok-123', 'password': 'hunter2', 'server': 'example.org'}}
    w(os.path.join(HOME, '.config/revlens-fixture/settings.json'), json.dumps(settings, indent=2))
    ref['settings'] = json.load(open(os.path.join(HOME, '.config/revlens-fixture/settings.json')))
    # key file
    w(os.path.join(HOME, '.config/revlens-fixture/app.ini'), '[General]\nlanguage=en\nzoom=1.25\n\n[Account]\nuser=ada\npassword=s3cret\n')
    cp = configparser.ConfigParser(interpolation=None); cp.optionxform = str
    cp.read(os.path.join(HOME, '.config/revlens-fixture/app.ini'))
    ref['ini'] = {s: dict(cp[s]) for s in cp.sections()}
    # xml with namespaces and split runs
    xml = '<?xml version="1.0"?>\n<doc xmlns:t="urn:t"><t:p t:style="Title">The meeting is at <c>3</c>:<c>30</c> today.</t:p><item id="one" kind="a">First</item><item id="two" kind="b">Second &amp; more</item></doc>\n'
    w(os.path.join(HOME, 'Documents/doc.xml'), xml)
    root = ET.parse(os.path.join(HOME, 'Documents/doc.xml')).getroot()
    ref['xml_title_text'] = ''.join(root.find('{urn:t}p').itertext())
    ref['xml_item_two_text'] = root.findall('item')[1].text
    # sqlite
    db = os.path.join(HOME, '.local/share/revlens-fixture/notes.sqlite')
    os.makedirs(os.path.dirname(db), exist_ok=True)
    c = sqlite3.connect(db)
    c.execute('CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, done INTEGER)')
    c.executemany('INSERT INTO notes (title, done) VALUES (?, ?)', [('olive oil', 0), ('milk', 1), ('bread', 0)])
    c.execute('CREATE TABLE tags (name TEXT)')
    c.commit(); c.close()
    c = sqlite3.connect(db)
    ref['notes_rows'] = c.execute('SELECT id, title, done FROM notes ORDER BY id').fetchall()
    ref['notes_open'] = c.execute('SELECT count(*) FROM notes WHERE done = 0').fetchone()[0]
    c.close()
    # zip with an XML entry (like an ODF document)
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('mimetype', 'application/x-revlens', compress_type=zipfile.ZIP_STORED)
        z.writestr('content.xml', '<office><body><p style="Subtitle">Monday 24 November</p></body></office>')
        z.writestr('meta.json', json.dumps({'pages': 3}))
    w(os.path.join(HOME, 'Documents/flyer.zdoc'), zb.getvalue())
    with zipfile.ZipFile(os.path.join(HOME, 'Documents/flyer.zdoc')) as z:
        ref['zip_names'] = z.namelist()
        ref['zip_subtitle'] = ET.fromstring(z.read('content.xml')).find('body/p').text
    # gzip json
    w(os.path.join(HOME, 'Documents/data.json.gz'), gzip.compress(json.dumps({'count': 5, 'items': ['x', 'y']}).encode(), mtime=0))
    ref['gz'] = json.loads(gzip.decompress(open(os.path.join(HOME, 'Documents/data.json.gz'), 'rb').read()))
    # plist (binary)
    w(os.path.join(HOME, 'Library/Preferences/dev.revlens.fixture.plist'), plistlib.dumps({'ShowSidebar': True, 'WindowWidth': 1024, 'AuthToken': 'plist-secret'}, fmt=plistlib.FMT_BINARY))
    ref['plist'] = plistlib.load(open(os.path.join(HOME, 'Library/Preferences/dev.revlens.fixture.plist'), 'rb'))
    # a cookie jar that must be withheld from exports
    w(os.path.join(HOME, '.config/revlens-fixture/Cookies'), b'SQLite format 3\x00' + b'\x00' * 84)
    # task file in rea's format plus a RevLens ui_element check
    task = {
        'name': 'fixture-checks',
        'prompt': 'In the fixture app, add olive oil to the notes and keep the dark theme.',
        'checks': [
            {'id': 'milk', 'kind': 'lines_present', 'file': 'Documents/todo.txt', 'lines': ['buy milk']},
            {'id': 'no-eggs', 'kind': 'lines_absent', 'file': 'Documents/todo.txt', 'lines': ['buy eggs']},
            {'id': 'buys', 'kind': 'line_count', 'file': 'Documents/todo.txt', 'contains': 'buy', 'equals': 2},
            {'id': 'theme', 'kind': 'value_equals', 'file': '.config/revlens-fixture/settings.json', 'pointer': '/theme', 'value': 'dark'},
            {'id': 'pinned', 'kind': 'value_equals', 'file': '.config/revlens-fixture/settings.json', 'pointer': '/recent/[name=a.txt]/pinned', 'value': True},
            {'id': 'recent-count', 'kind': 'member_count', 'file': '.config/revlens-fixture/settings.json', 'pointer': '/recent', 'at_least': 2},
            {'id': 'zoom', 'kind': 'value_equals', 'file': '.config/revlens-fixture/app.ini', 'pointer': '/groups/General/zoom', 'value': 1.25, 'tolerance': 0.001},
            {'id': 'no-proxy', 'kind': 'value_absent', 'file': '.config/revlens-fixture/app.ini', 'pointer': '/groups/General/proxy'},
            {'id': 'title', 'kind': 'text_equals', 'file': 'Documents/doc.xml', 'pointer': '/root/children/[name=t:p]', 'value': ref['xml_title_text']},
            {'id': 'item-two', 'kind': 'text_contains', 'file': 'Documents/doc.xml', 'pointer': '/root/children/[name=item][@id=two]', 'value': 'Second &'.replace('&', '&')},
            {'id': 'olive', 'kind': 'row_present', 'file': '.local/share/revlens-fixture/notes.sqlite', 'table': 'notes', 'where': {'title': 'olive oil', 'done': 0}},
            {'id': 'open-notes', 'kind': 'row_count', 'file': '.local/share/revlens-fixture/notes.sqlite', 'table': 'notes', 'where': {'done': 0}, 'equals': ref['notes_open']},
            {'id': 'subtitle', 'kind': 'value_equals', 'file': 'Documents/flyer.zdoc', 'pointer': '/entries/[name=content.xml]/view/root/children/[name=body]/children/[name=p][@style=Subtitle]/children/0', 'value': ref['zip_subtitle']},
            {'id': 'gz-count', 'kind': 'value_equals', 'file': 'Documents/data.json.gz', 'pointer': '/count', 'value': ref['gz']['count']},
            {'id': 'sidebar', 'kind': 'value_equals', 'file': 'Library/Preferences/dev.revlens.fixture.plist', 'pointer': '/ShowSidebar', 'value': True},
            {'id': 'missing', 'kind': 'file_absent', 'file': 'Documents/missing.txt'},
            {'id': 'wrong-theme', 'kind': 'value_equals', 'file': '.config/revlens-fixture/settings.json', 'pointer': '/theme', 'value': 'light'},
        ],
    }
    w(os.path.join(OUT, 'task.json'), json.dumps(task, indent=2))
    ref['expected_pass'] = {c['id']: c['id'] != 'wrong-theme' for c in task['checks']}
    # XWD image through ImageMagick, with its RGBA as the reference
    if shutil.which('convert'):
        subprocess.run(['convert', '-size', '48x32', 'gradient:red-blue', '-fill', 'lime', '-draw', 'rectangle 10,8 20,16', '-depth', '8', 'xwd:' + os.path.join(OUT, 'gradient.xwd')], check=True)
        rgba = subprocess.run(['convert', os.path.join(OUT, 'gradient.xwd'), '-depth', '8', 'rgba:-'], check=True, capture_output=True).stdout
        ref['xwd'] = {'width': 48, 'height': 32, 'rgba_sha256': hashlib.sha256(rgba).hexdigest(), 'pixel_15_12': list(rgba[(12 * 48 + 15) * 4:(12 * 48 + 15) * 4 + 4])}
    # strace output with strace's own summary (-C) as the count reference
    if shutil.which('strace'):
        tmp = os.path.join(OUT, 'strace-sample.txt')
        subprocess.run(['strace', '-f', '-tt', '-T', '-C', '-o', tmp, '-e', 'trace=%file,%network,%process', sys.executable, '-c',
                        'import os,socket,subprocess\nopen("/etc/hostname").read() if os.path.exists("/etc/hostname") else None\ntry:\n  open("/nonexistent/revlens")\nexcept OSError: pass\ns=socket.socket(); s.settimeout(0.2)\ntry: s.connect(("127.0.0.1", 9))\nexcept OSError: pass\nsubprocess.run(["/bin/true"])\n'], check=True)
        text = open(tmp).read()
        # strace -C appends a table: "% time seconds usecs/call calls errors syscall"
        table, on = {}, False
        for line in text.splitlines():
            if line.startswith('% time'):
                on = True; continue
            if on and line.strip() and not line.startswith('-') and not line.strip().endswith('total'):
                parts = line.split()
                name = parts[-1]
                nums = parts[3:-1]
                calls = int(nums[0]); errors = int(nums[1]) if len(nums) > 1 else 0
                table[name] = {'calls': calls, 'errors': errors}
        ref['strace_summary'] = table
        # strip the absolute python path so the fixture is stable to read
    ref_path = os.path.join(OUT, 'reference.json')
    json.dump(ref, open(ref_path, 'w'), indent=1, default=str)
    print('wrote', OUT)


if __name__ == '__main__':
    main()
