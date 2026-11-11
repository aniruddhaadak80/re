#!/usr/bin/env python3
"""Regenerate samples/extras/reference-gaps.json from independent reference tools.

Reference tools (not shipped, used only to produce expected values):
  regipy 6.5.0 (MIT)                 registry hives
  windowsprefetch 4.0.3 (Apache-2.0) prefetch, with dissect.util 3.24 (AGPL-3.0, tool only)
                                     lzxpress_huffman standing in for the Windows-only RtlDecompressBufferEx
  olefile 0.47 (BSD-2-Clause)        OLE compound files
  LnkParse3 1.6.0 (MIT)              shell links inside jump lists
Other sections are added by the same script; run from the repo root with the venv that has them:
  python3 packages/extras/scripts/gen_reference_gaps.py
"""
import gzip, hashlib, json, os, struct, sys, io

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
S = os.path.join(ROOT, 'samples', 'extras')
W = os.path.join(S, 'windows')
OUT = os.path.join(S, 'reference-gaps.json')


def load(p):
    b = open(p, 'rb').read()
    return gzip.decompress(b) if p.endswith('.gz') else b


def filetime(v):
    import datetime
    if not v:
        return None
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def registry():
    from regipy.registry import RegistryHive
    import tempfile
    out = {}
    for f in ['SAM.gz', 'BCD', 'SECURITY', 'NTUSER.DAT.gz']:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(load(os.path.join(W, f)))
        tmp.close()
        h = RegistryHive(tmp.name)
        keys = vals = 0
        for sk in h.recurse_subkeys(as_json=False):
            keys += 1
            vals += len(sk.values)
        r = h.root
        e = {'keys': keys, 'values': vals, 'root': r.name, 'rootSubkeys': [s.name for s in r.iter_subkeys()]}
        if f.startswith('NTUSER'):
            k = h.get_key('\\Environment')
            e['environment'] = {v.name: v.value for v in k.iter_values()}
            e['environmentLastWritten'] = k.header.last_modified if hasattr(k.header, 'last_modified') else None
            k = h.get_key('\\Control Panel\\Desktop')
            e['desktop'] = {v.name: [v.value_type, v.value if isinstance(v.value, (int, str)) else None] for v in k.iter_values()}
        if f == 'BCD':
            e['objects'] = [s.name for s in h.get_key('\\Objects').iter_subkeys()]
        out[f] = e
        os.unlink(tmp.name)
    return out


def prefetch():
    from dissect.util.compression import lzxpress_huffman
    import windowsprefetch.windowsprefetch as wp
    import windowsprefetch.utils as wu

    def dec(self, infile):
        b = open(infile, 'rb').read()
        sig, size = struct.unpack('<LL', b[:8])
        return bytearray(lzxpress_huffman.decompress(b[8:])[:size])
    wu.DecompressWin10.decompress = dec
    wp.DecompressWin10.decompress = dec
    out = {}
    for f in sorted(os.listdir(W)):
        if not f.endswith('.pf'):
            continue
        p = wp.Prefetch(os.path.join(W, f))
        raw = open(os.path.join(W, f), 'rb').read()
        e = {'version': p.version, 'executable': p.executableName, 'hash': p.hash.upper().rjust(8, '0'), 'runCount': p.runCount,
             'files': len([x for x in p.resources if x]), 'firstFile': p.resources[0] if p.resources else None, 'lastFile': [x for x in p.resources if x][-1],
             'volumes': [{'path': v['Volume Name'].decode('utf-16le') if isinstance(v['Volume Name'], bytes) else v['Volume Name'],
                          'serial': v['Serial Number'].upper().rjust(8, '0') if isinstance(v.get('Serial Number'), str) else v.get('Serial Number')} for v in p.volumesInformationArray],
             'timestamps': [str(t) for t in p.timestamps]}
        if raw[:3] == b'MAM':
            d = lzxpress_huffman.decompress(raw[8:])[:struct.unpack('<L', raw[4:8])[0]]
            e['decompressedSize'] = len(d)
            e['decompressedSha256'] = hashlib.sha256(d).hexdigest()
        out[f] = e
    return out


def jumplists():
    import olefile, LnkParse3
    out = {}
    for f in sorted(os.listdir(W)):
        if f.endswith('.automaticDestinations-ms'):
            ole = olefile.OleFileIO(os.path.join(W, f))
            streams = ['/'.join(s) for s in ole.listdir()]
            dl = ole.openstream('DestList').read()
            ver, n, pinned = struct.unpack('<III', dl[:12])
            entries = []
            p = 32
            for _ in range(n):
                num = struct.unpack('<I', dl[p + 88:p + 92])[0]
                mtime = struct.unpack('<Q', dl[p + 100:p + 108])[0]
                pin = struct.unpack('<i', dl[p + 108:p + 112])[0]
                host = dl[p + 72:p + 88].split(b'\0')[0].decode('latin1')
                if ver == 1:
                    plen = struct.unpack('<H', dl[p + 112:p + 114])[0]
                    path = dl[p + 114:p + 114 + plen * 2].decode('utf-16le')
                    count = None
                    p += 114 + plen * 2
                else:
                    count = struct.unpack('<I', dl[p + 116:p + 120])[0]
                    plen = struct.unpack('<H', dl[p + 128:p + 130])[0]
                    path = dl[p + 130:p + 130 + plen * 2].decode('utf-16le')
                    p += 130 + plen * 2 + 4
                lnk = None
                sname = format(num, 'x')
                if ole.exists(sname):
                    l = LnkParse3.lnk_file(io.BytesIO(ole.openstream(sname).read())).get_json()
                    lnk = {'localBasePath': (l.get('link_info') or {}).get('local_base_path'), 'size': l['header'].get('file_size')}
                entries.append({'entry': num, 'host': host, 'path': path, 'pin': pin, 'count': count, 'modified': filetime(mtime), 'lnk': lnk})
            out[f] = {'streams': sorted(streams), 'version': ver, 'entries': n, 'pinned': pinned, 'destList': entries}
        elif f.endswith('.customDestinations-ms'):
            b = open(os.path.join(W, f), 'rb').read()
            sig = bytes.fromhex('4c0000000114020000000000c000000000000046')
            offs = []
            i = b.find(sig)
            while i >= 0:
                offs.append(i)
                i = b.find(sig, i + 1)
            lnks = []
            for o in offs:
                try:
                    l = LnkParse3.lnk_file(io.BytesIO(b[o:])).get_json()
                    lnks.append({'offset': o, 'arguments': (l.get('data') or {}).get('command_line_arguments'), 'localBasePath': (l.get('link_info') or {}).get('local_base_path')})
                except Exception as ex:
                    lnks.append({'offset': o, 'error': str(ex)})
            out[f] = {'lnkOffsets': offs, 'lnks': lnks, 'footer': b[-4:].hex()}
    return out


SECTIONS = {'registry': registry, 'prefetch': prefetch, 'jumplists': jumplists}

if __name__ == '__main__':
    ref = json.load(open(OUT)) if os.path.exists(OUT) else {}
    want = sys.argv[1:] or list(SECTIONS)
    for k in want:
        ref[k] = SECTIONS[k]()
    json.dump(ref, open(OUT, 'w'), indent=1, sort_keys=True, default=str)
    print('wrote', OUT, list(ref))
