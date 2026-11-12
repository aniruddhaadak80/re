#?description=RevLens headless helper: open a file, list units, decompile an item. Prints one JSON document.
#?shortcut=
# RevLens JEB script (MIT, part of RevLens). JEB runs it headless:
#   jeb_linux.sh -c --script=RevLensJeb.py -- <action> <input file> [item] [maxChars]
#   jeb_macos.sh ... and jeb_wincli.bat ... take the same arguments.
# Actions:
#   info       project and artifact facts
#   units      every unit with type, name, format and child count (capped)
#   decompile  decompile one item (a class or method signature like Lcom/a/B; or Lcom/a/B;->m()V, or a
#              native address) with the unit's decompiler and print the source text
# The JSON is printed between @@REVLENS_JSON_BEGIN@@ and @@REVLENS_JSON_END@@ so RevLens can find it in
# JEB's log output. Written for the JEB 4 and 5 Python (Jython 2.7) script API.
import json
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.util import DecompilerHelper

MAX_UNITS = 2000


def emit(obj):
    print("@@REVLENS_JSON_BEGIN@@")
    print(json.dumps(obj))
    print("@@REVLENS_JSON_END@@")


def unit_row(u):
    try:
        children = len(u.getChildren())
    except Exception:
        children = 0
    return {"name": u.getName(), "type": u.getClass().getSimpleName(), "format": u.getFormatType(), "children": children}


class RevLensJeb(IScript):
    def run(self, ctx):
        args = list(ctx.getArguments() or [])
        if len(args) < 2:
            emit({"ok": False, "error": "usage: <action> <file> [item] [maxChars]"})
            return
        action, path = args[0], args[1]
        item = args[2] if len(args) > 2 else None
        max_chars = int(args[3]) if len(args) > 3 else 200000
        prj = ctx.open(path)
        if prj is None:
            prj = ctx.getMainProject()
        if prj is None:
            emit({"ok": False, "error": "JEB could not open the file"})
            return
        units = list(RuntimeProjectUtil.getAllUnits(prj))
        if action == "info":
            emit({"ok": True, "action": "info", "file": path, "project": prj.getName(), "artifacts": [a.getArtifact().getName() for a in prj.getLiveArtifacts()], "units": len(units)})
        elif action == "units":
            emit({"ok": True, "action": "units", "file": path, "total": len(units), "units": [unit_row(u) for u in units[:MAX_UNITS]]})
        elif action == "decompile":
            if not item:
                emit({"ok": False, "error": "decompile needs an item"})
                return
            for u in units:
                dec = DecompilerHelper.getDecompiler(u)
                if dec is None:
                    continue
                try:
                    ok = dec.decompile(item)
                except Exception:
                    ok = False
                if not ok:
                    continue
                text = dec.getDecompiledText(item) or ""
                emit({"ok": True, "action": "decompile", "file": path, "item": item, "unit": u.getName(), "decompiler": dec.getClass().getSimpleName(), "text": text[:max_chars], "truncated": len(text) > max_chars})
                return
            emit({"ok": False, "action": "decompile", "item": item, "error": "no decompiler could decompile that item"})
        else:
            emit({"ok": False, "error": "unknown action " + action})
