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
