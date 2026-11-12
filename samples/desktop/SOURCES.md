# Desktop fixtures

All files here were made for the @revlens/desktop tests and are part of this repo (MIT).

- `Info.xml.plist`, `Info.binary.plist`: one dictionary (strings, unicode, nested arrays and dicts, data,
  date, booleans, 64-bit and negative integers, a real) written with Python 3.12 `plistlib` in XML and
  binary (bplist00) form. `plist-reference.json` is what `plistlib.loads` returns, with data as base64 and
  dates as ISO strings.
- `tricky.desktop`: hand-written to exercise the Desktop Entry Specification 1.5 quoting rules (quoted Exec
  arguments with spaces and escaped quotes, field codes, `\s` and `\;` escapes, localized keys, actions).
- `autostart-dropper.desktop`: hand-written example of a malicious autostart entry (download piped to sh)
  for the analyzer findings. The URL uses the reserved `.invalid` TLD.
- `reg-uninstall.txt`: hand-written in the exact layout `reg query <key> /s` prints on Windows (CRLF,
  four-space indents, REG_SZ, REG_EXPAND_SZ and REG_DWORD values). Not captured from a real machine.
- `proc-target.mjs`: a small Node program the tests start; it holds a file open and listens on TCP, UDP and
  a Unix socket so the live process inspection can be checked against known values.

## Round 3 fixtures

Made by `packages/desktop/scripts/gen-r3-fixtures.py` (this repo, MIT) with Python 3 standard library writers, ImageMagick 7 (`convert`) and strace 6.13. `r3/reference.json` holds the values Python's readers, ImageMagick and `strace -C` report for them. `capture-target.mjs` is a small Node program written for the process capture tests.

| File | Source | SHA-256 |
|---|---|---|
| `capture-target.mjs` | hand-written test program | c6b99b4682603dbdca5cbc8d4a9ef593a88fc88ad3ecaae47e2e31c85e7c82ac |
| `r3/gradient.xwd` | ImageMagick gradient in XWD | fbf5688c1c498200df6405675037f65cf068e5f8a8bb27e292043c5754db3406 |
| `r3/reference.json` | reference values | 4651755acb48913bc549d5d6063bff27b79d2a1d970bc0d8d915679e3ff55f50 |
| `r3/strace-sample.txt` | strace -f -tt -T -C of a Python run | 01b384d7e9b2a1762836abaa28b51753dca73754713894756dc987cd1d0211b9 |
| `r3/task-home/.config/revlens-fixture/Cookies` | generated fixture home file | 485bd01eecba0fe7f1973f04260aff0a9d9bb19e68020acf0d6edb21f03f917a |
| `r3/task-home/.config/revlens-fixture/app.ini` | generated fixture home file | c46d09b52d065f545c0251fefb9b2f254d76f04213b20199c11de7e327053a98 |
| `r3/task-home/.config/revlens-fixture/settings.json` | generated fixture home file | 622755a65ada601dc78cfc673e450aefd2a168b8cb6bef6634423c26098d9939 |
| `r3/task-home/.local/share/revlens-fixture/notes.sqlite` | generated fixture home file | 9736051b8de13781beaca43d912c328c96a82c713470d9efc21249b22b561c1b |
| `r3/task-home/Documents/data.json.gz` | generated fixture home file | c667a12e3e24946366bee9f59b6ce42e1690a0c95d99723c021ff180e1b915f5 |
| `r3/task-home/Documents/doc.xml` | generated fixture home file | e62c5c2402dd3d1426daa568d234baf6f7a4f7e9c3ce57e7bfda196d13648800 |
| `r3/task-home/Documents/flyer.zdoc` | generated fixture home file | b58c70acc1acd9f533497816dea1ed76c473efb1bbb481aff0b87e33ded09454 |
| `r3/task-home/Documents/todo.txt` | generated fixture home file | 1455ea5862f22f9dfd0184a6eaabf85382f92e485b0cb02bcda4bf480d1468b0 |
| `r3/task-home/Library/Preferences/dev.revlens.fixture.plist` | generated fixture home file | 71c2858f96db026f69ca91b92fb004421b726effc5789ed7fbba41a2b874c67b |
| `r3/task.json` | task file (rea check kinds) | 516a7950371bd8c6d21074212e888168cc1cdb632a7e95a8bf7ffc934d2bc8ed |
