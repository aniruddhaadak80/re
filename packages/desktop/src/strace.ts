// Parser for `strace -f -tt -T` output and comparison of process captures. No Node imports.
// The argument splitter is a single linear scan (quotes, brackets and braces), no regex
// backtracking on untrusted text.
import { InputError } from './proc.js';

export interface SyscallEvent { pid: number; time?: string; name: string; args: string[]; result: string; errno?: string; durationUs?: number }
export interface StraceSummary {
  lines: number; calls: number; truncated: boolean;
  bySyscall: Record<string, { calls: number; errors: number; errnos: Record<string, number>; totalUs: number }>;
  files: { path: string; ops: string[]; ok: number; failed: number }[];
  execs: { pid: number; path: string; argv: string[]; ok: boolean }[];
  network: { op: string; family: string; address: string; port?: number; ok: boolean; pid: number }[];
  processes: { pid: number; parent?: number; exit?: string }[];
  signals: { pid: number; signal: string }[];
}

/** Split the inside of a syscall's parentheses at top-level commas. */
export function splitArgs(s: string, max = 64): string[] {
  const out: string[] = [];
  let depth = 0, cur = '', inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (inStr) { cur += c; if (c === '\\' && i + 1 < s.length) { cur += s[++i]; continue; } if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth = Math.max(0, depth - 1);
    if (c === ',' && depth === 0) { out.push(cur.trim()); cur = ''; if (out.length >= max) return out; continue; }
    cur += c;
  }
  if (cur.trim() || out.length) out.push(cur.trim());
  return out;
}

/** Decode a C string literal as strace prints it ("a\nb\x01" with an optional ... after it). */
export function unquote(s: string): string {
  const t = s.trim();
  if (!t.startsWith('"')) return t;
  let out = '';
  for (let i = 1; i < t.length; i++) {
    const c = t[i]!;
    if (c === '"') break;
    if (c === '\\' && i + 1 < t.length) {
      const n = t[++i]!;
      if (n === 'n') out += '\n'; else if (n === 't') out += '\t'; else if (n === 'r') out += '\r'; else if (n === '0') out += '\0';
      else if (n === 'x' && /^[0-9a-fA-F]{2}$/.test(t.slice(i + 1, i + 3))) { out += String.fromCharCode(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; }
      else if (/[0-7]/.test(n)) { let o = n; while (o.length < 3 && /[0-7]/.test(t[i + 1] ?? '')) o += t[++i]; out += String.fromCharCode(parseInt(o, 8)); }
      else out += n;
      continue;
    }
    out += c;
  }
  return out;
}

/** Parse one strace line into an event; unfinished calls are merged by the caller. */
function parseCall(body: string): { name: string; args: string; result: string } | undefined {
  // name(args) = result
  let i = 0;
  while (i < body.length && i < 64 && /[\w]/.test(body[i]!)) i++;
  if (!i || body[i] !== '(') return undefined;
  const name = body.slice(0, i);
  // find the matching close paren of the argument list
  let depth = 0, inStr = false, j = i;
  for (; j < body.length; j++) {
    const c = body[j]!;
    if (inStr) { if (c === '\\') j++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) break; }
  }
  if (j >= body.length) return undefined;
  const rest = body.slice(j + 1).trim();
  if (!rest.startsWith('=')) return undefined;
  return { name, args: body.slice(i + 1, j), result: rest.slice(1).trim() };
}

const FILE_ARG: Record<string, number> = { open: 0, openat: 1, openat2: 1, creat: 0, stat: 0, lstat: 0, newfstatat: 1, fstatat64: 1, statx: 1, access: 0, faccessat: 1, faccessat2: 1, readlink: 0, readlinkat: 1, unlink: 0, unlinkat: 1, mkdir: 0, mkdirat: 1, rmdir: 0, chdir: 0, chmod: 0, fchmodat: 1, chown: 0, fchownat: 1, truncate: 0, rename: 0, renameat: 1, renameat2: 1, link: 0, linkat: 1, symlink: 1, symlinkat: 2, utimensat: 1, getxattr: 0, lgetxattr: 0, setxattr: 0, inotify_add_watch: 1, statfs: 0, mknod: 0, mknodat: 1, execve: 0, execveat: 1 };

function parseSockaddr(a: string): { family: string; address: string; port?: number } | undefined {
  const fam = /sa_family=(AF_\w+)/.exec(a)?.[1];
  if (!fam) return undefined;
  const port = /htons\((\d+)\)/.exec(a)?.[1];
  if (fam === 'AF_INET') return { family: fam, address: /inet_addr\("([^"]*)"\)/.exec(a)?.[1] ?? '', port: port ? Number(port) : undefined };
  if (fam === 'AF_INET6') return { family: fam, address: /inet_pton\(AF_INET6, "([^"]*)"/.exec(a)?.[1] ?? '', port: port ? Number(port) : undefined };
  if (fam === 'AF_UNIX') { const m = /sun_path=(@?"(?:[^"\\]|\\.){0,512}")/.exec(a)?.[1]; return { family: fam, address: m ? (m.startsWith('@') ? '@' + unquote(m.slice(1)) : unquote(m)) : '(unnamed)' }; }
  if (fam === 'AF_NETLINK') return { family: fam, address: /nl_pid=(\d+)/.exec(a)?.[1] ?? '' };
  return { family: fam, address: '' };
}

/** Summarise strace -f -tt -T output (also accepts output without pids, times or durations). */
export function parseStrace(text: string, opts: { maxLines?: number; maxItems?: number } = {}): StraceSummary {
  if (typeof text !== 'string') throw new InputError('strace output must be text');
  const maxLines = Math.max(1, Math.min(opts.maxLines ?? 2_000_000, 10_000_000));
  const maxItems = Math.max(1, Math.min(opts.maxItems ?? 20_000, 200_000));
  const sum: StraceSummary = { lines: 0, calls: 0, truncated: false, bySyscall: Object.create(null), files: [], execs: [], network: [], processes: [], signals: [] };
  const files = new Map<string, { path: string; ops: Set<string>; ok: number; failed: number }>();
  const procs = new Map<number, { pid: number; parent?: number; exit?: string }>();
  const pending = new Map<number, string>();
  let pos = 0;
  while (pos < text.length) {
    if (sum.lines >= maxLines) { sum.truncated = true; break; }
    let end = text.indexOf('\n', pos); if (end < 0) end = text.length;
    let line = text.slice(pos, Math.min(end, pos + 1_000_000)); pos = end + 1; sum.lines++;
    // pid and time prefix
    let pid = 0, time: string | undefined;
    const pm = /^(?:\[pid\s+)?(\d+)\]?\s+/.exec(line);
    if (pm) { pid = Number(pm[1]); line = line.slice(pm[0].length); }
    const tm = /^(\d\d:\d\d:\d\d(?:\.\d+)?|\d+\.\d+)\s+/.exec(line);
    if (tm) { time = tm[1]; line = line.slice(tm[0].length); }
    if (!procs.has(pid) && procs.size < maxItems) procs.set(pid, { pid });
    if (line.startsWith('+++')) { const p = procs.get(pid); if (p) p.exit = line.replace(/^\+\+\+\s*|\s*\+\+\+$/g, ''); continue; }
    if (line.startsWith('---')) { const sig = /^---\s+(SIG\w+)/.exec(line)?.[1]; if (sig && sum.signals.length < maxItems) sum.signals.push({ pid, signal: sig }); continue; }
    const unf = line.indexOf(' <unfinished ...>');
    if (unf >= 0) { pending.set(pid, line.slice(0, unf)); continue; }
    const res = /^<\.\.\. (\w+) resumed>\s?/.exec(line);
    if (res) { const head = pending.get(pid); pending.delete(pid); line = (head ?? `${res[1]}(`) + line.slice(res[0].length); }
    let durationUs: number | undefined;
    const dm = /\s<(\d+\.\d+)>\s*$/.exec(line);
    if (dm) { durationUs = Math.round(Number(dm[1]) * 1e6); line = line.slice(0, dm.index); }
    const c = parseCall(line);
    if (!c) continue;
    sum.calls++;
    const failed = c.result.startsWith('-1') || c.result.startsWith('?');
    const errno = failed ? /^-1\s+(E\w+)/.exec(c.result)?.[1] : undefined;
    const st = (sum.bySyscall[c.name] ??= { calls: 0, errors: 0, errnos: Object.create(null), totalUs: 0 });
    st.calls++; if (failed) { st.errors++; if (errno) st.errnos[errno] = (st.errnos[errno] ?? 0) + 1; } if (durationUs) st.totalUs += durationUs;
    const args = splitArgs(c.args);
    const fi = FILE_ARG[c.name];
    if (fi !== undefined && args[fi]?.startsWith('"')) {
      const path = unquote(args[fi]!);
      let f = files.get(path);
      if (!f && files.size < maxItems) { f = { path, ops: new Set(), ok: 0, failed: 0 }; files.set(path, f); }
      if (f) { f.ops.add(c.name === 'openat' || c.name === 'open' ? `${c.name}:${/O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)/.test(args[fi + 1] ?? '') ? 'write' : 'read'}` : c.name); failed ? f.failed++ : f.ok++; }
      if ((c.name === 'rename' || c.name === 'renameat' || c.name === 'renameat2' || c.name === 'link' || c.name === 'linkat') && sum.files.length < maxItems) {
        const to = args.find((x, k) => k > fi && x.startsWith('"'));
        if (to) { const tp = unquote(to); let g = files.get(tp); if (!g && files.size < maxItems) { g = { path: tp, ops: new Set(), ok: 0, failed: 0 }; files.set(tp, g); } if (g) { g.ops.add(`${c.name}:target`); failed ? g.failed++ : g.ok++; } }
      }
    }
    if ((c.name === 'execve' || c.name === 'execveat') && sum.execs.length < maxItems) {
      const p = unquote(args[c.name === 'execve' ? 0 : 1] ?? '');
      const av = args[c.name === 'execve' ? 1 : 2] ?? '';
      const argv = av.startsWith('[') ? splitArgs(av.slice(1, av.lastIndexOf(']') > 0 ? av.lastIndexOf(']') : av.length), 256).filter((x) => x.startsWith('"')).map(unquote) : [];
      sum.execs.push({ pid, path: p, argv, ok: !failed });
    }
    if (['connect', 'bind', 'sendto', 'sendmsg', 'recvfrom', 'accept', 'accept4'].includes(c.name) && sum.network.length < maxItems) {
      const sa = parseSockaddr(c.args);
      if (sa && (sa.address || sa.port !== undefined)) sum.network.push({ op: c.name, family: sa.family, address: sa.address, port: sa.port, ok: !failed || errno === 'EINPROGRESS', pid });
    }
    if (['clone', 'clone3', 'fork', 'vfork'].includes(c.name) && !failed) {
      const child = Number(/^(\d+)/.exec(c.result)?.[1]);
      if (child && procs.size < maxItems) { const p = procs.get(child) ?? { pid: child }; p.parent = pid; procs.set(child, p); }
    }
  }
  sum.files = [...files.values()].map((f) => ({ path: f.path, ops: [...f.ops].sort(), ok: f.ok, failed: f.failed })).sort((a, b) => a.path.localeCompare(b.path));
  sum.processes = [...procs.values()].filter((p) => p.pid).sort((a, b) => a.pid - b.pid);
  // dedupe network endpoints
  const seen = new Set<string>();
  sum.network = sum.network.filter((n) => { const k = `${n.op} ${n.family} ${n.address} ${n.port ?? ''} ${n.ok}`; if (seen.has(k)) return false; seen.add(k); return true; });
  return sum;
}

// ---------------- capture comparison ----------------

export interface ProcessCapture {
  kind: 'revlens-process-capture'; version: 1; platform: string;
  target: { command?: string[]; pid?: number };
  startedAt: string; durationMs: number;
  exit?: { code: number | null; signal: string | null };
  processes: { pid: number; ppid?: number; name: string; exe?: string; cmdline?: string[]; firstSeenMs: number; lastSeenMs: number }[];
  modules: { path: string; firstSeenMs: number; pids: number[] }[];
  files: { path: string; type: string; firstSeenMs: number; lastSeenMs: number; pids: number[] }[];
  sockets: { key: string; proto: string; firstSeenMs: number; lastSeenMs: number; pids: number[] }[];
  timeline: { t: number; processes: number; rssKb: number; threads: number; fds: number }[];
  syscalls?: StraceSummary;
  stdout?: { bytes: number; sha256: string; excerpt: string };
  stderr?: { bytes: number; sha256: string; excerpt: string };
  samples: number; warnings: string[];
}

const setDiff = (a: string[], b: string[]) => { const sa = new Set(a), sb = new Set(b); return { added: [...sb].filter((x) => !sa.has(x)).sort(), removed: [...sa].filter((x) => !sb.has(x)).sort(), same: [...sa].filter((x) => sb.has(x)).length }; };

/** Compare two process captures: what the second run loaded, opened, connected to, started or called that the first did not, and the reverse. */
export function compareCaptures(a: ProcessCapture, b: ProcessCapture, opts: { limit?: number } = {}) {
  if (a?.kind !== 'revlens-process-capture' || b?.kind !== 'revlens-process-capture') throw new InputError('both inputs must be process captures');
  const lim = Math.max(1, Math.min(opts.limit ?? 2000, 100_000));
  const cut = (d: { added: string[]; removed: string[]; same: number }) => ({ added: d.added.slice(0, lim), removed: d.removed.slice(0, lim), same: d.same, truncated: d.added.length > lim || d.removed.length > lim });
  const procKey = (p: ProcessCapture['processes'][number]) => `${p.exe ?? p.name} ${(p.cmdline ?? []).slice(1).join(' ')}`.trim().slice(0, 500);
  const modules = setDiff(a.modules.map((m) => m.path), b.modules.map((m) => m.path));
  const files = setDiff(a.files.map((f) => `${f.type} ${f.path}`), b.files.map((f) => `${f.type} ${f.path}`));
  const sockets = setDiff(a.sockets.map((s) => s.key), b.sockets.map((s) => s.key));
  const processes = setDiff(a.processes.map(procKey), b.processes.map(procKey));
  const out: Record<string, unknown> = { modules: cut(modules), files: cut(files), sockets: cut(sockets), processes: cut(processes) };
  if (a.syscalls && b.syscalls) {
    const names = new Set([...Object.keys(a.syscalls.bySyscall), ...Object.keys(b.syscalls.bySyscall)]);
    const counts: { syscall: string; before: number; after: number; errorsBefore: number; errorsAfter: number }[] = [];
    for (const n of names) { const x = a.syscalls.bySyscall[n], y = b.syscalls.bySyscall[n]; if ((x?.calls ?? 0) !== (y?.calls ?? 0) || (x?.errors ?? 0) !== (y?.errors ?? 0)) counts.push({ syscall: n, before: x?.calls ?? 0, after: y?.calls ?? 0, errorsBefore: x?.errors ?? 0, errorsAfter: y?.errors ?? 0 }); }
    counts.sort((p, q) => Math.abs(q.after - q.before) - Math.abs(p.after - p.before));
    out.syscalls = { changed: counts.slice(0, lim), calls: { before: a.syscalls.calls, after: b.syscalls.calls } };
    out.syscallFiles = cut(setDiff(a.syscalls.files.map((f) => f.path), b.syscalls.files.map((f) => f.path)));
    out.execs = cut(setDiff(a.syscalls.execs.map((e) => `${e.path} ${e.argv.slice(1).join(' ')}`.trim()), b.syscalls.execs.map((e) => `${e.path} ${e.argv.slice(1).join(' ')}`.trim())));
    out.network = cut(setDiff(a.syscalls.network.map((n) => `${n.op} ${n.family} ${n.address}${n.port !== undefined ? ':' + n.port : ''}`), b.syscalls.network.map((n) => `${n.op} ${n.family} ${n.address}${n.port !== undefined ? ':' + n.port : ''}`)));
  }
  const peak = (c: ProcessCapture) => c.timeline.reduce((m, t) => Math.max(m, t.rssKb), 0);
  out.exit = { before: a.exit ?? null, after: b.exit ?? null, same: JSON.stringify(a.exit ?? null) === JSON.stringify(b.exit ?? null) };
  out.durationMs = { before: a.durationMs, after: b.durationMs };
  out.peakRssKb = { before: peak(a), after: peak(b) };
  out.stdoutSame = a.stdout?.sha256 === b.stdout?.sha256;
  const total = [modules, files, sockets, processes].reduce((s, d) => s + d.added.length + d.removed.length + d.same, 0);
  const same = [modules, files, sockets, processes].reduce((s, d) => s + d.same, 0);
  out.similarity = total ? Math.round((same / total) * 1000) / 1000 : 1;
  return out;
}
