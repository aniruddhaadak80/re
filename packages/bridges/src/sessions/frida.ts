// Persistent Frida sessions: attach (or spawn), load scripts, post messages, collect events,
// unload, detach. Runs a small Python helper that uses the frida bindings (installed with
// frida-tools) and talks JSON lines over stdin and stdout. Node only.
import { existsSync, readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runTool } from '../exec.js';
import { buildHookScript, HOOK_TEMPLATES, HookParamError, type HookTemplateId } from '../hooks.js';
import { FRIDA_EVENT_PREFIX } from '../parsers/frida.js';
import type { Detection } from '../types.js';
import { BridgeInputError, int, need, requireExecution, requireFile, unavailable } from '../providers/common.js';
import { PipeProcess, SESSIONS, SessionError, type SessionImpl, type SessionInfo } from './manager.js';

/** The helper. Original code, MIT licensed, part of @revlens/bridges. */
export const FRIDA_SESSION_HELPER = String.raw`# RevLens Frida session helper. Original code, MIT licensed, part of @revlens/bridges.
# Reads one JSON request per line on stdin, writes one JSON line per reply or event on stdout.
import base64, json, sys, threading
import frida

lock = threading.Lock()
def out(obj):
    line = json.dumps(obj, default=str)
    with lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

state = {"device": None, "session": None, "pid": None, "spawned": False, "scripts": {}, "next": 1, "resumed": True}

def on_message(sid):
    def handler(message, data):
        ev = {"event": "message", "script": sid, "message": message}
        if data is not None:
            ev["data"] = base64.b64encode(bytes(data[:65536])).decode("ascii")
            ev["dataSize"] = len(data)
        out(ev)
    return handler

def on_detached(reason, crash=None):
    out({"event": "detached", "reason": str(reason), "crash": None if crash is None else str(crash)})

def pick_device(sel):
    if sel in (None, "", "local"):
        return frida.get_local_device()
    if sel == "usb":
        return frida.get_usb_device(timeout=5)
    if sel == "remote":
        return frida.get_remote_device()
    return frida.get_device(sel, timeout=5)

def op_attach(req):
    dev = pick_device(req.get("device"))
    state["device"] = dev
    if req.get("spawn"):
        argv = [req["spawn"]] + list(req.get("args") or [])
        pid = dev.spawn(argv)
        state["spawned"] = True
        state["resumed"] = False
    elif req.get("pid") is not None:
        pid = int(req["pid"])
    else:
        pid = dev.get_process(req["name"]).pid
    sess = dev.attach(pid)
    sess.on("detached", on_detached)
    state["session"] = sess
    state["pid"] = pid
    return {"pid": pid, "device": dev.id, "deviceName": dev.name, "spawned": state["spawned"]}

def op_load(req):
    sess = state["session"]
    if sess is None:
        raise RuntimeError("not attached")
    sid = state["next"]
    state["next"] += 1
    sc = sess.create_script(req["source"], name="revlens-%d" % sid)
    sc.on("message", on_message(sid))
    def on_log(level, text, sid=sid):
        out({"event": "message", "script": sid, "message": {"type": "log", "level": level, "payload": text}})
    try:
        sc.set_log_handler(on_log)
    except AttributeError:
        pass  # older bindings deliver console.log as a "log" message
    sc.load()
    state["scripts"][sid] = sc
    if req.get("resume") and not state["resumed"]:
        state["device"].resume(state["pid"])
        state["resumed"] = True
    return {"script": sid}

def op_post(req):
    sc = state["scripts"][int(req["script"])]
    sc.post(req["message"])
    return {}

def op_unload(req):
    sc = state["scripts"].pop(int(req["script"]))
    sc.unload()
    return {}

def op_resume(req):
    if not state["resumed"]:
        state["device"].resume(state["pid"])
        state["resumed"] = True
    return {"resumed": True}

def op_detach(req):
    sess = state["session"]
    if sess is not None:
        for sc in list(state["scripts"].values()):
            try: sc.unload()
            except Exception: pass
        state["scripts"].clear()
        try: sess.detach()
        except Exception: pass
        if state["spawned"] and req.get("kill", True):
            try: state["device"].kill(state["pid"])
            except Exception: pass
    state["session"] = None
    return {}

OPS = {"attach": op_attach, "load": op_load, "post": op_post, "unload": op_unload, "resume": op_resume, "detach": op_detach, "ping": lambda r: {"frida": frida.__version__}}

out({"event": "ready", "frida": frida.__version__})
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except Exception as e:
        out({"id": None, "ok": False, "error": "bad json: %s" % e})
        continue
    rid = req.get("id")
    fn = OPS.get(req.get("op"))
    if fn is None:
        out({"id": rid, "ok": False, "error": "unknown op"})
        continue
    try:
        out({"id": rid, "ok": True, "result": fn(req)})
    except Exception as e:
        out({"id": rid, "ok": False, "error": "%s: %s" % (type(e).__name__, e)})
try:
    op_detach({"kill": True})
except Exception:
    pass
`;

const DEVICE_RE = /^[\w.:@-]{1,128}$/;
const PROC_NAME_RE = /^[\w .+@-]{1,255}$/;
const MAX_SOURCE = 512 * 1024;

export interface FridaEventRecord {
  seq: number;
  /** script id inside the session */
  script: number;
  kind: 'send' | 'log' | 'error' | 'event' | 'detached';
  /** RevLens template events (console.log lines starting with @@revlens) are parsed into this */
  event?: unknown;
  payload?: unknown;
  level?: string;
  text?: string;
  stack?: string;
  dataBase64?: string;
  dataSize?: number;
}

interface FridaSession extends SessionImpl {
  events: FridaEventRecord[];
  dropped: number;
  seq: number;
  maxEvents: number;
  pending: Map<number, (v: { ok: boolean; result?: any; error?: string }) => void>;
  nextId: number;
  tmp: string;
  python: string;
  detached?: string;
}

/** Find a Python interpreter that can import frida: REVLENS_FRIDA_PYTHON, the frida launcher's own interpreter, then python3 or python. */
export async function findFridaPython(det: Detection): Promise<{ python: string; env: NodeJS.ProcessEnv } | undefined> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  const cands: string[] = [];
  if (process.env.REVLENS_FRIDA_PYTHON) cands.push(process.env.REVLENS_FRIDA_PYTHON);
  // The frida launcher is a Python script (#!/path/python) or a small shell wrapper around one.
  try {
    let launcher = det.path!;
    for (let hop = 0; hop < 2; hop++) {
      const headText = readFileSync(launcher, { encoding: 'latin1' }).slice(0, 4096);
      const shebang = /^#!\s*(\S+)/.exec(headText)?.[1];
      if (shebang && /python[\d.]*$/i.test(shebang)) { cands.push(shebang); break; }
      const pp = /PYTHONPATH=("?)([^\s"]+)\1/.exec(headText)?.[2];
      if (pp) env.PYTHONPATH = pp + (env.PYTHONPATH ? `:${env.PYTHONPATH}` : '');
      const next = /exec\s+("?)([^\s"]+)\1/.exec(headText)?.[2];
      if (!next || !existsSync(next)) break;
      launcher = next;
    }
  } catch { /* binary launcher (Windows .exe) */ }
  const dir = dirname(det.path!);
  for (const n of process.platform === 'win32' ? ['python.exe'] : ['python3', 'python']) if (existsSync(join(dir, n))) cands.push(join(dir, n));
  cands.push(process.platform === 'win32' ? 'python' : 'python3');
  for (const py of [...new Set(cands)]) {
    const r = await runTool(py, ['-c', 'import frida,sys;sys.stdout.write(frida.__version__)'], { timeoutMs: 20_000, env, maxOutputBytes: 4096 });
    if (r.code === 0 && /^\d+\.\d+/.test(r.stdout.trim())) return { python: py, env };
  }
  return undefined;
}

function request(s: FridaSession, op: string, body: Record<string, unknown>, timeoutMs: number): Promise<{ ok: boolean; result?: any; error?: string }> {
  const id = s.nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => { s.pending.delete(id); resolve({ ok: false, error: `no reply to ${op} within ${timeoutMs} ms` }); }, timeoutMs);
    s.pending.set(id, (v) => { clearTimeout(timer); resolve(v); });
    try { s.proc.write(JSON.stringify({ id, op, ...body }) + '\n'); } catch (e) { clearTimeout(timer); s.pending.delete(id); resolve({ ok: false, error: (e as Error).message }); }
  });
}

function pushEvent(s: FridaSession, e: Omit<FridaEventRecord, 'seq'>): void {
  if (s.events.length >= s.maxEvents) { s.dropped++; return; }
  s.events.push({ seq: ++s.seq, ...e });
}

/** Turn one helper line into a reply or an event. */
function onLine(s: FridaSession, line: string): void {
  let v: any;
  try { v = JSON.parse(line); } catch { return; }
  if (v && typeof v.id === 'number' && s.pending.has(v.id)) { const cb = s.pending.get(v.id)!; s.pending.delete(v.id); cb(v); return; }
  if (v?.event === 'detached') { s.detached = String(v.reason); pushEvent(s, { script: 0, kind: 'detached', text: `${v.reason}${v.crash ? `: ${v.crash}` : ''}` }); return; }
  if (v?.event !== 'message') return;
  const m = v.message ?? {};
  const script = Number(v.script) || 0;
  const data = typeof v.data === 'string' ? { dataBase64: v.data, dataSize: v.dataSize } : {};
  if (m.type === 'send') pushEvent(s, { script, kind: 'send', payload: m.payload, ...data });
  else if (m.type === 'log') {
    const text = String(m.payload ?? '');
    if (text.startsWith(FRIDA_EVENT_PREFIX)) {
      try { pushEvent(s, { script, kind: 'event', event: JSON.parse(text.slice(FRIDA_EVENT_PREFIX.length)) }); return; } catch { /* plain log */ }
    }
    pushEvent(s, { script, kind: 'log', level: String(m.level ?? 'info'), text: text.slice(0, 65536) });
  } else if (m.type === 'error') pushEvent(s, { script, kind: 'error', text: String(m.description ?? 'error').slice(0, 8000), stack: String(m.stack ?? '').slice(0, 8000) });
}

/** Attach Frida to a process (pid or name) or spawn a program, keeping the session open. Needs allowExecution. */
export async function fridaSessionAttach(input: { pid?: number; name?: string; spawn?: string; args?: string[]; device?: string; maxEvents?: number; idleTimeoutMs?: number; allowExecution?: boolean }) {
  const n = await need('frida');
  if ('missing' in n) return n.missing;
  const gate = requireExecution(input, 'A Frida session');
  if (gate) return { available: true, tool: 'frida', ok: false, blocked: true, error: gate };
  const targets = [input.pid !== undefined, input.name !== undefined, input.spawn !== undefined].filter(Boolean).length;
  if (targets !== 1) throw new BridgeInputError('give exactly one of pid, name or spawn');
  const device = input.device ?? 'local';
  if (typeof device !== 'string' || !DEVICE_RE.test(device)) throw new BridgeInputError('device must be local, usb, remote or a device id');
  const body: Record<string, unknown> = { device };
  let target: string;
  if (input.pid !== undefined) {
    if (!Number.isSafeInteger(input.pid) || input.pid <= 0) throw new BridgeInputError('pid must be a positive integer');
    body.pid = input.pid; target = `pid ${input.pid}`;
  } else if (input.name !== undefined) {
    if (typeof input.name !== 'string' || !PROC_NAME_RE.test(input.name)) throw new BridgeInputError('name has characters that are not allowed');
    body.name = input.name; target = input.name;
  } else {
    const sp = input.spawn!;
    if (typeof sp !== 'string' || !sp || sp.length > 4096 || /[\0\r\n]/.test(sp)) throw new BridgeInputError('spawn must be a program path or package name');
    body.spawn = device === 'local' ? requireFile(sp, 'spawn').path : sp;
    const args = input.args ?? [];
    if (!Array.isArray(args) || args.length > 64 || !args.every((a) => typeof a === 'string' && a.length <= 4096 && !/[\0\r\n]/.test(a))) throw new BridgeInputError('args must be up to 64 strings');
    body.args = args; target = String(body.spawn);
  }
  const py = await findFridaPython(n.det);
  if (!py) return unavailable('frida', 'frida-tools is installed but no Python interpreter can import the frida module. Set REVLENS_FRIDA_PYTHON to the Python that has it (pip install frida-tools).');
  SESSIONS.reserve();
  const tmp = await mkdtemp(join(tmpdir(), 'revlens-frida-'));
  const helper = join(tmp, 'revlens_frida_session.py');
  await writeFile(helper, FRIDA_SESSION_HELPER, 'utf8');
  const proc = new PipeProcess(py.python, ['-u', helper], { env: { ...py.env, PYTHONDONTWRITEBYTECODE: '1' }, cwd: tmp });
  const now = new Date().toISOString();
  const info: SessionInfo = {
    id: SESSIONS.newId('frida'), kind: 'frida', tool: 'frida', toolVersion: n.det.version ?? null, target, pid: null, createdAt: now, lastUsedAt: now,
    idleTimeoutMs: SESSIONS.idle(input.idleTimeoutMs), commands: 0, busy: false, alive: true,
  };
  const s: FridaSession = {
    info, proc, events: [], dropped: 0, seq: 0, maxEvents: int(input.maxEvents, 10_000, 10, 200_000), pending: new Map(), nextId: 1, tmp, python: py.python,
    close: async () => {
      if (proc.alive) await request(s, 'detach', { kill: true }, 10_000);
      await proc.shutdown(3000);
      await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    },
  };
  // line pump: the helper writes complete JSON lines
  const pump = async () => {
    for (;;) {
      const w = await proc.waitFor((b) => b.indexOf('\n'), 24 * 60 * 60_000);
      if (w.status !== 'ok') break;
      onLine(s, proc.take(w.end + 1).trim());
    }
    for (const cb of s.pending.values()) cb({ ok: false, error: 'frida helper exited' });
    s.pending.clear();
  };
  const readyWait = proc.waitFor((b) => b.indexOf('"event": "ready"'), 30_000);
  const rw = await readyWait;
  if (rw.status !== 'ok') {
    proc.kill(); await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    return { available: true, tool: 'frida', ok: false, error: `frida helper did not start: ${proc.takeErr().trim().slice(-1500)}` };
  }
  void pump();
  const a = await request(s, 'attach', body, 60_000);
  if (!a.ok) {
    proc.kill(); await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    return { available: true, tool: 'frida', ok: false, error: a.error ?? 'attach failed', ...(input.spawn ? { hint: 'Spawning needs ptrace. In containers run with --cap-add=SYS_PTRACE, or start the program and attach by pid.' } : {}) };
  }
  if (input.pid === undefined) info.target = `${target} (pid ${a.result.pid})`;
  const added = SESSIONS.add(s);
  return { available: true, tool: 'frida', toolVersion: n.det.version ?? null, ok: true, session: added, targetPid: a.result.pid, device: a.result.device, spawned: a.result.spawned };
}

/** Load a script into a Frida session: a RevLens hook template or your own JavaScript. */
export async function fridaSessionLoad(input: { sessionId: string; template?: string; params?: Record<string, unknown>; source?: string; resume?: boolean; maxEvents?: number }) {
  let source: string;
  if ((input.template === undefined) === (input.source === undefined)) throw new BridgeInputError('give exactly one of template or source');
  if (input.template !== undefined) {
    const tpl = HOOK_TEMPLATES.find((t) => t.id === input.template);
    if (!tpl) throw new BridgeInputError(`template must be one of ${HOOK_TEMPLATES.map((t) => t.id).join(', ')}`);
    try { source = buildHookScript(tpl.id as HookTemplateId, input.params ?? {}, int(input.maxEvents, 2000, 1, 100_000)); } catch (e) {
      if (e instanceof HookParamError) throw new BridgeInputError(e.message);
      throw e;
    }
  } else {
    if (typeof input.source !== 'string' || input.source.length === 0 || input.source.length > MAX_SOURCE || input.source.includes('\0')) throw new BridgeInputError(`source must be 1 to ${MAX_SOURCE} characters of JavaScript`);
    source = input.source;
  }
  return SESSIONS.use(input.sessionId, 'frida', async (si) => {
    const s = si as FridaSession;
    const r = await request(s, 'load', { source, resume: input.resume !== false }, 60_000);
    return r.ok ? { ok: true, sessionId: s.info.id, script: r.result.script, ...(input.template ? { template: input.template } : {}) } : { ok: false, sessionId: s.info.id, error: r.error };
  });
}

/** Post a JSON message to a loaded script (received with recv() in the script). */
export async function fridaSessionPost(input: { sessionId: string; script: number; message: unknown }) {
  if (!Number.isSafeInteger(input.script) || input.script <= 0) throw new BridgeInputError('script must be the id returned by load');
  const text = JSON.stringify(input.message ?? null);
  if (text.length > 1024 * 1024) throw new BridgeInputError('message is larger than 1 MiB');
  return SESSIONS.use(input.sessionId, 'frida', async (si) => {
    const s = si as FridaSession;
    const r = await request(s, 'post', { script: input.script, message: input.message ?? null }, 30_000);
    return r.ok ? { ok: true, sessionId: s.info.id, script: input.script } : { ok: false, sessionId: s.info.id, error: r.error };
  });
}

/** Take collected events (send payloads, console logs, RevLens template events, errors). Optionally wait up to waitMs for minEvents of them. */
export async function fridaSessionCollect(input: { sessionId: string; limit?: number; waitMs?: number; minEvents?: number; script?: number }) {
  const limit = int(input.limit, 500, 1, 50_000);
  const waitMs = int(input.waitMs, 0, 0, 120_000);
  const minEvents = int(input.minEvents, 1, 1, 50_000);
  return SESSIONS.use(input.sessionId, 'frida', async (si) => {
    const s = si as FridaSession;
    const has = () => (input.script ? s.events.filter((e) => e.script === input.script).length : s.events.length) >= minEvents;
    const t0 = Date.now();
    while (!has() && Date.now() - t0 < waitMs && s.proc.alive) await new Promise((r) => setTimeout(r, 50));
    let picked: FridaEventRecord[];
    if (input.script) {
      picked = s.events.filter((e) => e.script === input.script).slice(0, limit);
      const take = new Set(picked.map((e) => e.seq));
      s.events = s.events.filter((e) => !take.has(e.seq));
    } else picked = s.events.splice(0, limit);
    const dropped = s.dropped;
    s.dropped = 0;
    return { ok: true, sessionId: s.info.id, count: picked.length, remaining: s.events.length, dropped, events: picked, ...(s.detached ? { detached: s.detached } : {}) };
  });
}

/** Unload one script from a Frida session. */
export async function fridaSessionUnload(input: { sessionId: string; script: number }) {
  if (!Number.isSafeInteger(input.script) || input.script <= 0) throw new BridgeInputError('script must be the id returned by load');
  return SESSIONS.use(input.sessionId, 'frida', async (si) => {
    const s = si as FridaSession;
    const r = await request(s, 'unload', { script: input.script }, 30_000);
    return r.ok ? { ok: true, sessionId: s.info.id, script: input.script } : { ok: false, sessionId: s.info.id, error: r.error };
  });
}

/** Resume a spawned program that is still suspended. */
export async function fridaSessionResume(input: { sessionId: string }) {
  return SESSIONS.use(input.sessionId, 'frida', async (si) => {
    const s = si as FridaSession;
    const r = await request(s, 'resume', {}, 30_000);
    return r.ok ? { ok: true, sessionId: s.info.id } : { ok: false, sessionId: s.info.id, error: r.error };
  });
}

export { SessionError };
