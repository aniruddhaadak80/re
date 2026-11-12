#!/usr/bin/env python3
"""Fetch Xvfb, xdotool, xwd, a window manager and strace from Debian .deb files without root.

Usage: fetch-desktop-tools.py <tools-dir> [packages...]

Reads the Debian Packages index next to the tools dir (Packages or Packages.xz, downloaded
from deb.debian.org for this machine's architecture when missing), resolves dependencies that
dpkg says are not installed, downloads each .deb from deb.debian.org and unpacks it with
dpkg-deb -x into <tools-dir>. Point REVLENS_DESKTOP_TOOLS at <tools-dir>.

Xvfb runs xkbcomp from a path compiled into it (/usr/bin). When /usr/bin/xkbcomp is missing,
this script writes a copy named Xvfb-revlens whose compiled path is /tmp/.xb (same length) and
the computer session links /tmp/.xb/xkbcomp to the unpacked xkbcomp before it starts Xvfb.
This is only for sandboxes without root; a normal install of the xvfb package needs none of it.
"""
import lzma, os, shutil, subprocess, sys, urllib.request

MIRROR = 'https://deb.debian.org/debian'
DEFAULT = ['xvfb', 'xdotool', 'x11-apps', 'x11-utils', 'matchbox-window-manager', 'strace', 'at-spi2-core', 'dbus-daemon', 'dbus-bin', 'libglib2.0-bin']
SKIP = {'man-db', 'bsdextrautils', 'groff-base', 'libuchardet0', 'libpipeline1', 'systemd', 'systemd-sysv', 'libpam-systemd', 'dbus', 'dbus-user-session'}


def arch():
    return subprocess.run(['dpkg', '--print-architecture'], capture_output=True, text=True).stdout.strip() or 'arm64'


def load_index(base):
    p = os.path.join(base, 'Packages')
    if not os.path.exists(p):
        url = f'{MIRROR}/dists/trixie/main/binary-{arch()}/Packages.xz'
        with urllib.request.urlopen(url, timeout=120) as r:
            open(p, 'wb').write(lzma.decompress(r.read()))
    pk, cur = {}, {}
    for line in open(p, encoding='utf8'):
        line = line.rstrip('\n')
        if not line:
            if 'Package' in cur:
                pk.setdefault(cur['Package'], cur)
            cur = {}
            continue
        if line[0] in ' \t':
            continue
        k, _, v = line.partition(': ')
        cur[k] = v
    return pk


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    tools = os.path.abspath(sys.argv[1])
    wanted = sys.argv[2:] or DEFAULT
    base = os.path.dirname(tools)
    pk = load_index(base)
    prov = {}
    for n, p in pk.items():
        for x in p.get('Provides', '').split(','):
            x = x.strip().split(' ')[0]
            if x:
                prov.setdefault(x, n)
    inst = set(subprocess.run(['dpkg-query', '-W', '-f', '${Package}\n'], capture_output=True, text=True).stdout.split())
    need, seen = [], set()

    def add(n):
        if n in seen or n in inst or n in SKIP:
            return
        seen.add(n)
        if n not in pk:
            if n in prov:
                return add(prov[n])
            print('not in index:', n, file=sys.stderr)
            return
        need.append(n)
        for alt in pk[n].get('Depends', '').split(','):
            alts = [a.strip().split(' ')[0].split(':')[0] for a in alt.split('|') if a.strip()]
            if alts and not any(a in inst or a in seen for a in alts):
                add(alts[0])

    for w in wanted:
        add(w)
    debs = os.path.join(base, 'debs')
    os.makedirs(debs, exist_ok=True)
    os.makedirs(tools, exist_ok=True)
    for n in need:
        fn = pk[n]['Filename']
        dst = os.path.join(debs, os.path.basename(fn))
        if not os.path.exists(dst):
            with urllib.request.urlopen(f'{MIRROR}/{fn}', timeout=300) as r, open(dst + '.part', 'wb') as f:
                shutil.copyfileobj(r, f)
            os.rename(dst + '.part', dst)
        subprocess.run(['dpkg-deb', '-x', dst, tools], check=True)
        print('unpacked', n)
    xvfb = os.path.join(tools, 'usr/bin/Xvfb')
    if os.path.exists(xvfb) and not os.path.exists('/usr/bin/xkbcomp'):
        d = bytearray(open(xvfb, 'rb').read())
        i = d.find(b'/usr/bin\x00')
        if i >= 0:
            d[i:i + 9] = b'/tmp/.xb\x00'
            out = os.path.join(tools, 'usr/bin/Xvfb-revlens')
            open(out, 'wb').write(d)
            os.chmod(out, 0o755)
            print('wrote', out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
