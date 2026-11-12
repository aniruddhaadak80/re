# RevLens bridge plugin for Cutter (https://cutter.re). MIT licensed, part of RevLens.
#
# Install: copy this file into Cutter's Python plugins folder (Edit > Preferences > Plugins shows the
# path, for example ~/.local/share/rizin/cutter/plugins/python on Linux) and restart Cutter.
#
# What it does: when Cutter starts, it opens a small HTTP server on 127.0.0.1 with a random port and
# a random token, and writes {pid, port, token, file} to ~/.revlens/cutter/<pid>.json (only readable by
# you). RevLens (list_cutter_sessions, cutter_command) reads that file and sends rizin commands that run
# inside this Cutter window, so they see your renames, comments and analysis. Commands that reach the
# host (!, pipes, file writes, scripts, opening files) are refused here as well as in RevLens.
#
# The server part does not need Cutter or Qt, so it can be tested with any Python 3 and a stub command
# function: python3 revlens_cutter_bridge.py --selftest
import hmac
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL = 1
MAX_BODY = 64 * 1024
MAX_OUTPUT = 16 * 1024 * 1024


def refuse_reason(cmd):
    """Return why a command is refused, or None. Mirrors RevLens checkR2Command in spirit."""
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 4096:
        return "command must be 1 to 4096 characters"
    if any(c in cmd for c in "\0\r\n"):
        return "command must be one line"
    if any(c in cmd for c in "!`|>"):
        return "refused: ! ` | and > reach the host shell or write files"
    if "#!" in cmd:
        return "refused: #! script interpreters"
    for seg in cmd.split(";"):
        seg = seg.strip()
        if not seg:
            continue
        if seg[0] in ".=$(\"":
            return "refused: commands starting with " + seg[0]
        if seg[0] in "owPLTq" or seg.startswith(("r ", "r-", "r+")) or seg == "r":
            return "refused: open, write, project, plugin, resize and quit commands"
        if seg.startswith(("e cfg.sandbox", "e cmd.", "e dir.", "e http.", "e scr.prompt")):
            return "refused: that setting"
    return None


def announce_dir():
    base = os.environ.get("REVLENS_CUTTER_BRIDGE_DIR") or os.path.join(os.path.expanduser("~"), ".revlens", "cutter")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return base


class BridgeServer:
    """Loopback HTTP server. run_command(cmd) -> str runs a rizin command and returns its output."""

    def __init__(self, run_command, current_file=lambda: None, pid=None):
        self.run_command = run_command
        self.current_file = current_file
        self.pid = pid or os.getpid()
        self.token = secrets.token_hex(24)
        self.httpd = None
        self.path = None
        self.lock = threading.Lock()

    def start(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, obj):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def authorized(self):
                got = self.headers.get("authorization", "")
                want = "Bearer " + server.token
                return hmac.compare_digest(got.encode("utf-8"), want.encode("utf-8"))

            def do_GET(self):
                if not self.authorized():
                    return self.reply(401, {"ok": False, "error": "bad token"})
                if self.path == "/status":
                    return self.reply(200, {"ok": True, "pid": server.pid, "file": server.current_file(), "protocol": PROTOCOL})
                return self.reply(404, {"ok": False, "error": "not found"})

            def do_POST(self):
                if not self.authorized():
                    return self.reply(401, {"ok": False, "error": "bad token"})
                if self.path != "/cmd":
                    return self.reply(404, {"ok": False, "error": "not found"})
                if self.headers.get("origin"):
                    return self.reply(403, {"ok": False, "error": "browser requests are refused"})
                try:
                    n = int(self.headers.get("content-length", "0"))
                except ValueError:
                    n = -1
                if n < 0 or n > MAX_BODY:
                    return self.reply(413, {"ok": False, "error": "body too large"})
                try:
                    req = json.loads(self.rfile.read(n).decode("utf-8"))
                    cmd = req.get("command")
                except Exception:
                    return self.reply(400, {"ok": False, "error": "body must be JSON with a command"})
                why = refuse_reason(cmd)
                if why:
                    return self.reply(400, {"ok": False, "error": why})
                with server.lock:
                    try:
                        out = server.run_command(cmd.strip())
                    except Exception as e:  # report, never crash Cutter
                        return self.reply(500, {"ok": False, "error": str(e)[:2000]})
                out = out if isinstance(out, str) else str(out)
                return self.reply(200, {"ok": True, "output": out[:MAX_OUTPUT], "truncated": len(out) > MAX_OUTPUT})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, name="revlens-bridge", daemon=True).start()
        self.write_announcement()
        return self

    def port(self):
        return self.httpd.server_address[1]

    def write_announcement(self):
        self.path = os.path.join(announce_dir(), "%d.json" % self.pid)
        data = {"pid": self.pid, "port": self.port(), "token": self.token, "file": self.current_file(),
                "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "protocol": PROTOCOL}
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    def stop(self):
        try:
            if self.path and os.path.exists(self.path):
                os.remove(self.path)
        finally:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()


# ---------------- Cutter plugin glue (only when running inside Cutter) ----------------
try:
    import cutter  # type: ignore
    from PySide2.QtCore import QObject, Signal, Slot, Qt  # type: ignore
except Exception:  # not inside Cutter, or a Cutter built with PySide6
    try:
        import cutter  # type: ignore
        from PySide6.QtCore import QObject, Signal, Slot, Qt  # type: ignore
    except Exception:
        cutter = None

if cutter is not None:
    class _MainThreadRunner(QObject):
        """Runs rizin commands on Cutter's main thread; the HTTP thread waits for the answer."""
        request = Signal(str, object)

        def __init__(self):
            super().__init__()
            self.request.connect(self._run, Qt.QueuedConnection)

        @Slot(str, object)
        def _run(self, cmd, box):
            try:
                box["out"] = cutter.cmd(cmd)
            except Exception as e:
                box["err"] = str(e)
            box["done"].set()

        def run(self, cmd, timeout=120):
            box = {"done": threading.Event()}
            self.request.emit(cmd, box)
            if not box["done"].wait(timeout):
                raise RuntimeError("Cutter did not answer within %d s" % timeout)
            if "err" in box:
                raise RuntimeError(box["err"])
            return box.get("out") or ""

    def _current_file():
        try:
            info = json.loads(cutter.cmd("ij") or "{}")
            return info.get("core", {}).get("file")
        except Exception:
            return None

    class RevLensBridgePlugin(cutter.CutterPlugin):
        name = "RevLens bridge"
        description = "Lets RevLens agents run rizin commands in this Cutter window (loopback only, token protected)."
        version = "1.0"
        author = "RevLens"

        def setupPlugin(self):
            self.runner = None
            self.server = None

        def setupInterface(self, main):
            self.runner = _MainThreadRunner()
            self.server = BridgeServer(self.runner.run, _current_file).start()
            try:
                cutter.core().fileOpened.connect(lambda *_: self.server.write_announcement())
            except Exception:
                pass

        def terminate(self):
            if self.server:
                self.server.stop()

    def create_cutter_plugin():
        return RevLensBridgePlugin()


if __name__ == "__main__" and "--selftest" in sys.argv:
    # Stand alone mode for tests: echo commands back, announce in REVLENS_CUTTER_BRIDGE_DIR, print the port.
    srv = BridgeServer(lambda c: "ran: " + c, lambda: os.environ.get("REVLENS_SELFTEST_FILE")).start()
    sys.stdout.write(json.dumps({"port": srv.port(), "pid": srv.pid}) + "\n")
    sys.stdout.flush()
    try:
        sys.stdin.read()
    finally:
        srv.stop()
