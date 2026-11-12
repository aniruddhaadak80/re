# Python playbook

Python ships as `.pyc` files, inside PyInstaller, py2exe, Nuitka or cx_Freeze executables, or as
plain source in a ZIP.

## Recognise
- A `.pyc` starts with a 4 byte magic that names the Python version; `analyze_file` reports it.
- A PyInstaller executable ends with a `MEI` cookie; `managed_pyinstaller_list` reads its table of contents.

## First pass
1. `managed_pyinstaller_list` to see the archive members and the entry scripts.
2. `managed_pyinstaller_extract` writes members to a folder you choose. It writes files, so give a fresh output folder.
3. `managed_pyc_disasm` for the bytecode of each code object with names, constants and line numbers.

## What to look for
- Entry scripts (not starting with `pyi_`) hold the real program.
- Constants with URLs, tokens and file paths; imports of `subprocess`, `socket`, `ctypes` and `base64`.
- Marshalled or encrypted payloads loaded with `exec` or `marshal.loads`.

## Verify
- Cite the archive member name and the code object and offset from `managed_pyc_disasm`.
