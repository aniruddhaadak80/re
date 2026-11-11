#!/usr/bin/env python3
"""Regenerate docs/showcases/*.md by running the real CLI on the repository fixtures.

Run after `npm run build`:  python3 scripts/gen-showcases.py
Every output block on those pages is pasted from this run, only trimmed to a line limit.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = ['node', os.path.join(ROOT, 'packages', 'cli', 'dist', 'index.js')]
OUT = os.path.join(ROOT, 'docs', 'showcases')


def run(args, limit=30):
    env = dict(os.environ, NO_COLOR='1', FORCE_COLOR='0')
    p = subprocess.run(CLI + args, cwd=ROOT, capture_output=True, text=True, env=env, timeout=300)
    text = (p.stdout or '') + (p.stderr if p.returncode not in (0, 2, 3) else '')
    lines = [l.rstrip() for l in text.strip().split('\n')]
    # timings change from run to run, so drop them to keep the pages stable
    lines = [__import__('re').sub(r'\s+\d+(\.\d+)? ms$', '', l) for l in lines]
    more = len(lines) - limit
    if more > 0:
        lines = lines[:limit] + [f'... ({more} more lines)']
    return '\n'.join(lines)


def block(args, limit=30, lang='text'):
    cmd = 'revlens ' + ' '.join(a if (' ' not in a and '*' not in a) else f'"{a}"' for a in args)
    return f'```console\n$ {cmd}\n{run(args, limit)}\n```\n'


def page(name, title, desc, order, body):
    os.makedirs(OUT, exist_ok=True)
    text = f'---\ntitle: "{title}"\ndescription: {desc}\norder: {order}\n---\n\n# {title}\n\n{body}'
    with open(os.path.join(OUT, name), 'w') as f:
        f.write(text)
    print('wrote', name)


ELF = 'samples/disasm/hello-x64-stripped.elf'
page('stripped-elf-password-check.md', 'Showcase: find the password check in a stripped ELF',
     'Recover main from a stripped x86-64 Linux program, read its pseudo code, follow a string to the function that uses it, and verify the answer against the bytes.', 1,
     f'''The file is `{ELF}`, a small C program built for x86-64 Linux and stripped of its symbol table. The question: what input does it accept, and where is that decided?

Everything below is real output from the RevLens CLI on that file. Nothing is installed besides Node.

## 1. Triage

{block(['analyze', ELF])}
It is a stripped, dynamically linked ELF with 11 functions found by the disassembler. There are no findings, so nothing looks packed or hostile.

## 2. Functions

{block(['disasm-functions', ELF])}
The symbol table is gone, yet `main` is named: RevLens found it from the `__libc_start_main` call in `_start`. The other functions come from the `.eh_frame` unwind table.

## 3. Strings and who uses them

{block(['refs', ELF, '--string', 'access'])}
The strings "access granted" and "access denied" are used by one function. That is our check.

## 4. Read it

{block(['decompile', ELF, 'sub_10018e0'], 40)}
The function compares its argument with the constant `revlens-secret-key` through `strcmp`, then picks the message: the compiler used a conditional move, so the light lifter prints the default `puts` argument and shows the swap on the line above it. The accepted input is `revlens-secret-key`.

## 5. Verify before you say it

{block(['verify', ELF, 'string=revlens-secret-key', 'import=strcmp', 'string=hunter2'])}
Two claims hold, with the offset or import that proves them, and the made up password is refuted. An agent using the MCP server makes the same check with `verify_claim` before it reports.

## With Ghidra installed

The same address works with the bridge: `revlens bridge ghidra_decompile {ELF} --functions 0x10018e0`. See [bridges](../bridges.md).
''')

APK = 'samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk'
page('android-apk-review.md', 'Showcase: review an Android app before you install it',
     'Read the manifest, signatures, permissions, exported components and network calls of a real F-Droid APK without Java or the Android SDK.', 2,
     f'''The file is `{APK}`, the Alarm Clock app from F-Droid. The questions: what does it ask for, who signed it, and what does its code reach out to?

## 1. The one shot report

{block(['apk', APK], 40)}

## 2. Who signed it

{block(['apksig', APK], 25)}
RevLens reads the v1 JAR signature and the APK Signing Block. It reports what is present and the certificate digests. It does not verify the signatures cryptographically.

## 3. Search the code

{block(['dex-search', APK, '--query', 'DeleteAll'], 15)}
No hardcoded URLs turned up for `http` in this app, which fits an offline alarm clock. Searching for a class name finds the confirmation dialog.

## 4. Read a class as smali

{block(['smali', APK, '--class', 'com.angrydoughnuts.android.alarmclock.AlarmClockActivity$DeleteAllConfirmation'], 40)}
The smali output matches baksmali line for line on the test corpus. For Java source, install jadx and run `revlens bridge jadx_decompile {APK}`.
''')

DLL = 'samples/managed/dotnet/System.IO.Compression.Brotli.dll'
PYC = 'samples/managed/python/sample_mod.3.12.pyc'
page('dotnet-and-python-bytecode.md', 'Showcase: read .NET and Python bytecode',
     'Identify a .NET assembly, list its types and read one method as CIL, then disassemble a Python 3.12 pyc and list a PyInstaller archive.', 3,
     f'''Two managed runtimes, no SDKs installed: `{DLL}` from .NET 8 and `{PYC}`, compiled by CPython 3.12.

## 1. What is this assembly

{block(['dotnet', DLL], 30)}

## 2. Its types

{block(['dotnet', DLL, 'types', '--filter', 'Brotli'], 20)}

## 3. One method as CIL

{block(['dotnet', DLL, 'search', 'Quality', '--kind', 'method'], 10)}

{block(['dotnet', DLL, 'il', 'System.IO.Compression.BrotliUtils::GetQualityFromCompressionLevel'], 40)}
The `switch` maps the four `CompressionLevel` values to Brotli quality 4, 1, 0 and 11. Each instruction carries its IL offset, and the header gives the file offset of the method body.

## 4. A Python module

{block(['pyc', PYC], 30)}
The opcode names and arguments match `dis.get_instructions` from CPython 3.12 for every instruction in the test corpus.

## 5. A PyInstaller archive

{block(['pyinstaller', 'samples/managed/pyinstaller/mini-carchive.bin', 'list'], 25)}
''')

OBF = 'samples/webrt/obfuscated.js'
ASAR = 'samples/webrt/electron/app.asar'
page('javascript-and-electron-audit.md', 'Showcase: deobfuscate JavaScript and audit an Electron app',
     'Recover the hidden strings of javascript-obfuscator output, list its network calls, and review an Electron ASAR for risky settings.', 4,
     f'''`{OBF}` is javascript-obfuscator output with a string array. `{ASAR}` is a small Electron app archive.

## 1. Deobfuscate

{block(['js-deobfuscate', OBF], 40)}
The string array is decoded by a small evaluator over literals. The input code is never run.

## 2. Why deobfuscate first

{block(['js-endpoints', OBF], 25)}
On the obfuscated file the endpoint search finds nothing, because the URL only exists inside the encoded string array. After deobfuscation it is plain: `https://telemetry.revlens-fixture.example/collect`, posted with a bearer token. The [JavaScript page](https://aniruddhaadak80.github.io/re/labs/javascript) runs both steps in the browser.

## 3. Electron security review

{block(['electron-audit', ASAR], 40)}

## 4. What is inside the archive

{block(['asar-list', ASAR], 20)}
''')

PCAP = 'samples/webrt/chrome-34-google.pcap'
DB = 'samples/webrt/fixture.sqlite'
page('network-capture-and-database.md', 'Showcase: a packet capture and an app database',
     'Summarize a browser packet capture with TLS SNI and JA3, then read an SQLite database with a safe SELECT.', 5,
     f'''`{PCAP}` is a capture of Chrome 34 opening Google. `{DB}` is a small app database.

## 1. The capture

{block(['pcap-summary', PCAP], 40)}
The JA3 value matches the Salesforce JA3 reference for this capture.

## 2. Flows

{block(['pcap-flows', PCAP], 15)}

## 3. The database

{block(['sqlite-tables', DB], 30)}

{block(['sqlite-query', DB, 'SELECT * FROM users LIMIT 3'], 20)}
SQLite itself never runs. RevLens reads the pages and runs one read only SELECT.
''')

with open(os.path.join(OUT, 'README.md'), 'w') as f:
    f.write('''# Showcases

Real walkthroughs on files in this repository. Every output block is pasted from the CLI by `python3 scripts/gen-showcases.py`, only trimmed.

1. [Find the password check in a stripped ELF](stripped-elf-password-check.md)
2. [Review an Android app before you install it](android-apk-review.md)
3. [Read .NET and Python bytecode](dotnet-and-python-bytecode.md)
4. [Deobfuscate JavaScript and audit an Electron app](javascript-and-electron-audit.md)
5. [A packet capture and an app database](network-capture-and-database.md)
''')
