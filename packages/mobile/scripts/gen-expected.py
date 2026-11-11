#!/usr/bin/env python3
"""Regenerate reference outputs in samples/mobile/expected from real tools.

Not run by the tests. Needs a JDK (javap), baksmali 2.5.2
(https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar, BSD-3-Clause) and,
for samples/mobile/reference/androguard.json, androguard 4.x in a virtualenv.

usage: gen-expected.py <java_home> <baksmali.jar>
"""
import gzip, json, os, subprocess, sys, tempfile, zipfile

ROOT = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'samples', 'mobile')
SKIP = ('.line', '.local', '.end local', '.restart local', '.prologue', '.epilogue', '.source')


def norm(text):
    """Method bodies without debug directives, annotations, params and comments (mirrors the test)."""
    out, cur, skip = {}, None, 0
    for raw in text.split('\n'):
        line = raw.split('    #')[0].rstrip() if '    #' in raw else raw.rstrip()
        t = line.strip()
        if t.startswith('.method'):
            cur = []
            out[t] = cur
            continue
        if cur is None:
            continue
        if t.startswith('.annotation'):
            skip += 1
            continue
        if t == '.end annotation':
            skip -= 1
            continue
        if t.startswith('.param') or t == '.end param' or skip > 0:
            continue
        if t == '.end method':
            cur = None
            continue
        if not t or t.startswith(SKIP):
            continue
        cur.append(t)
    return out


def baksmali(java, jar, dex_bytes, name):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'classes.dex')
        open(p, 'wb').write(dex_bytes)
        subprocess.run([java, '-jar', jar, 'd', '-o', os.path.join(d, 'out'), p], check=True)
        res = {}
        for base, _, files in os.walk(os.path.join(d, 'out')):
            for f in files:
                t = open(os.path.join(base, f), encoding='utf-8').read()
                cls = [l for l in t.split('\n') if l.startswith('.class')][0].split(' ')[-1]
                res[cls] = norm(t)
        json.dump(res, gzip.open(os.path.join(ROOT, 'expected', name + '.baksmali.json.gz'), 'wt'), sort_keys=True)


def main():
    java_home, bak = sys.argv[1], sys.argv[2]
    java = os.path.join(java_home, 'bin', 'java')
    javap = os.path.join(java_home, 'bin', 'javap')
    for f in sorted(os.listdir(os.path.join(ROOT, 'apk'))):
        z = zipfile.ZipFile(os.path.join(ROOT, 'apk', f))
        if 'classes.dex' in z.namelist():
            baksmali(java, bak, z.read('classes.dex'), f[:-4])
    for f in ('hello-035.dex', 'hello-039.dex'):
        baksmali(java, bak, open(os.path.join(ROOT, 'java', f), 'rb').read(), f[:-4])
    z = zipfile.ZipFile(os.path.join(ROOT, 'java', 'multidex.zip'))
    baksmali(java, bak, z.read('classes2.dex'), 'multidex-classes2')
    # javap -c -p for every class of commons-cli, in archive order, and for Hello.class
    jar = os.path.join(ROOT, 'java', 'commons-cli-1.6.0.jar')
    names = [n[:-6] for n in zipfile.ZipFile(jar).namelist() if n.endswith('.class') and 'module-info' not in n]
    out = subprocess.run([javap, '-c', '-p', '-cp', jar] + names, check=True, capture_output=True, text=True).stdout
    gzip.open(os.path.join(ROOT, 'expected', 'commons-cli-1.6.0.javap.txt.gz'), 'wt').write(out)
    out = subprocess.run([javap, '-c', '-p', os.path.join(ROOT, 'java', 'Hello.class')], check=True, capture_output=True, text=True).stdout
    open(os.path.join(ROOT, 'expected', 'Hello.javap.txt'), 'w').write(out)


if __name__ == '__main__':
    main()
