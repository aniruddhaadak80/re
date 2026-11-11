// Parsers for process data from Linux /proc, lsof -F, ps and PowerShell JSON. No Node imports.

export class InputError extends Error {}

export interface ProcessInfo {
  pid: number;
  ppid?: number;
  name: string;
  exe?: string;
  cmdline?: string[];
  user?: string;
  uid?: number;
  state?: string;
  threads?: number;
  rssKb?: number;
  vszKb?: number;
  cpuPercent?: number;
  startTime?: string;
}

export interface ModuleInfo { path: string; base?: string; size?: number; kind: 'executable' | 'library' | 'file' | 'other' }
export interface OpenFile { fd: string; type: 'file' | 'dir' | 'socket' | 'pipe' | 'anon' | 'device' | 'other'; path: string; socketInode?: number }
export interface SocketInfo { proto: 'tcp' | 'tcp6' | 'udp' | 'udp6' | 'unix'; local: string; localPort?: number; remote?: string; remotePort?: number; state?: string; inode?: number; path?: string; fd?: string }

const MAX_LINES = 200_000;
const lines = (text: string) => text.split('\n', MAX_LINES);

/** Parse /proc/<pid>/status into a ProcessInfo plus the raw key map. */
export function parseProcStatus(text: string): { info: Omit<ProcessInfo, 'pid'> & { pid?: number }; fields: Record<string, string> } {
  const f: Record<string, string> = {};
  for (const l of lines(text)) {
    const i = l.indexOf(':');
    if (i > 0 && i < 64) f[l.slice(0, i)] = l.slice(i + 1).trim().slice(0, 4000);
  }
  const num = (k: string) => { const m = /^(\d+)/.exec(f[k] ?? ''); return m ? Number(m[1]) : undefined; };
  return {
    info: { pid: num('Pid'), ppid: num('PPid'), name: f.Name ?? '', state: f.State, uid: num('Uid'), threads: num('Threads'), rssKb: num('VmRSS'), vszKb: num('VmSize') },
    fields: f,
  };
}

/** Split /proc/<pid>/cmdline (NUL separated). */
export function parseCmdline(text: string): string[] {
  return text.split('\0').filter((x, i, a) => !(x === '' && i === a.length - 1)).slice(0, 1000).map((x) => x.slice(0, 4000));
}

const LINE_BREAK = /[\n\r\u2028\u2029]/;

/** Parse /proc/<pid>/maps into the list of mapped files with lowest address and total mapped size. */
export function parseProcMaps(text: string, exePath?: string): ModuleInfo[] {
  const mods = new Map<string, { lo: bigint; hi: bigint; size: bigint }>();
  for (const l of lines(text)) {
    // addr-addr perms offset dev inode path
    const m = /^([0-9a-f]+)-([0-9a-f]+)\s+\S{4}\s+[0-9a-f]+\s+[0-9a-f]+:[0-9a-f]+\s+(\d+)/i.exec(l);
    if (!m) continue;
    const rest = l.slice(m[0].length);
    if (LINE_BREAK.test(rest)) continue;
    const path = rest.trim();
    if (!path || m[3] === '0' || path.startsWith('[')) continue;
    const lo = BigInt('0x' + m[1]), hi = BigInt('0x' + m[2]);
    const cur = mods.get(path);
    if (cur) { if (lo < cur.lo) cur.lo = lo; if (hi > cur.hi) cur.hi = hi; cur.size += hi - lo; }
    else if (mods.size < 20_000) mods.set(path, { lo, hi, size: hi - lo });
  }
  return [...mods.entries()].map(([path, v]) => ({ path: path.replace(/ \(deleted\)$/, ''), base: '0x' + v.lo.toString(16), size: Number(v.size), kind: classifyModule(path, exePath) }));
}

export function classifyModule(path: string, exePath?: string): ModuleInfo['kind'] {
  if (exePath && path === exePath) return 'executable';
  if (/\.(?:so(?:\.[\d.]+)?|dylib|dll|node)$/i.test(path) || /\.framework\//.test(path)) return 'library';
  if (/^\/(?:dev|proc|sys)\//.test(path)) return 'other';
  return 'file';
}

/** Classify a /proc/<pid>/fd link target. */
export function classifyFdTarget(fd: string, target: string): OpenFile {
  const sock = /^socket:\[(\d+)\]$/.exec(target);
  if (sock) return { fd, type: 'socket', path: target, socketInode: Number(sock[1]) };
  if (/^pipe:\[/.test(target)) return { fd, type: 'pipe', path: target };
  if (/^anon_inode:/.test(target)) return { fd, type: 'anon', path: target };
  if (/^\/dev\//.test(target)) return { fd, type: 'device', path: target };
  if (target.startsWith('/')) return { fd, type: 'file', path: target };
  return { fd, type: 'other', path: target.slice(0, 4000) };
}

const TCP_STATES: Record<string, string> = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV' };

function hexIp(h: string): string {
  if (h.length === 8) {
    const n = parseInt(h, 16) >>> 0;
    return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255].join('.');
  }
  if (h.length === 32) {
    const bytes: number[] = [];
    for (let w = 0; w < 4; w++) { const n = parseInt(h.slice(w * 8, w * 8 + 8), 16) >>> 0; bytes.push(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255); }
    // IPv4-mapped
    if (bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 255 && bytes[11] === 255) return `::ffff:${bytes.slice(12).join('.')}`;
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
    const s = groups.join(':');
    // compress the longest zero run
    const runs = [...s.matchAll(/(?:^|:)0(?::0)+(?::|$)/g)].sort((a, b) => b[0].length - a[0].length);
    return runs[0] ? s.replace(runs[0][0], '::').replace(/^:::/, '::').replace(/:::$/, '::') : s;
  }
  return h;
}

/** Parse /proc/net/tcp, tcp6, udp or udp6. */
export function parseProcNet(text: string, proto: 'tcp' | 'tcp6' | 'udp' | 'udp6'): SocketInfo[] {
  const out: SocketInfo[] = [];
  for (const l of lines(text).slice(1)) {
    const p = l.trim().split(/\s+/);
    if (p.length < 10) continue;
    const [lip, lport] = p[1]!.split(':'), [rip, rport] = p[2]!.split(':');
    if (!lip || !lport || !rip || !rport) continue;
    const st = p[3]!.toUpperCase();
    out.push({ proto, local: hexIp(lip), localPort: parseInt(lport, 16), remote: hexIp(rip), remotePort: parseInt(rport, 16), state: proto.startsWith('tcp') ? TCP_STATES[st] ?? st : st === '07' ? 'UNCONN' : st === '01' ? 'ESTABLISHED' : st, inode: Number(p[9]) });
    if (out.length >= 100_000) break;
  }
  return out;
}

/** Parse /proc/net/unix. */
export function parseProcNetUnix(text: string): SocketInfo[] {
  const out: SocketInfo[] = [];
  for (const l of lines(text).slice(1)) {
    const p = l.trim().split(/\s+/);
    if (p.length < 7) continue;
    const st: Record<string, string> = { '01': 'UNCONNECTED', '02': 'CONNECTING', '03': 'CONNECTED', '04': 'DISCONNECTING' };
    out.push({ proto: 'unix', local: p[7] ?? '', path: p[7], state: (p[3] === '00010000' ? 'LISTEN' : st[p[5]!] ?? p[5]), inode: Number(p[6]) });
    if (out.length >= 100_000) break;
  }
  return out;
}

/** Parse lsof -F output (fields p c u f t n P T a) into per-process files and sockets. */
export function parseLsofF(text: string): { pid: number; command?: string; uid?: number; files: OpenFile[]; sockets: SocketInfo[]; modules: ModuleInfo[] }[] {
  const procs: ReturnType<typeof parseLsofF> = [];
  let cur: ReturnType<typeof parseLsofF>[number] | undefined;
  let file: { fd?: string; type?: string; name?: string; proto?: string; tcpState?: string } | undefined;
  const flush = () => {
    if (!cur || !file || file.fd === undefined) return;
    const name = file.name ?? '';
    const fd = file.fd;
    if (file.type === 'IPv4' || file.type === 'IPv6') {
      const proto = ((file.proto ?? 'tcp').toLowerCase() + (file.type === 'IPv6' ? '6' : '')) as SocketInfo['proto'];
      const [l, r] = name.split('->');
      const split = (s?: string) => { if (!s) return { addr: undefined, port: undefined }; const i = s.lastIndexOf(':'); return { addr: s.slice(0, i).replace(/^\[|\]$/g, ''), port: Number(s.slice(i + 1)) || undefined }; };
      const a = split(l), b = split(r);
      cur.sockets.push({ proto, local: a.addr ?? '', localPort: a.port, remote: b.addr, remotePort: b.port, state: file.tcpState ?? (proto.startsWith('udp') ? 'UNCONN' : undefined), fd });
    } else if (file.type === 'unix') {
      cur.sockets.push({ proto: 'unix', local: name, path: name.startsWith('/') ? name : undefined, fd });
    } else if ((fd === 'txt' || fd === 'mem') && file.type === 'REG') {
      // macOS lists mapped images as txt; Linux lsof lists the executable as txt and libraries as mem
      if (cur.modules.some((m) => m.path === name)) return;
      const lib = /\.(?:dylib|so(?:\.[\d.]+)?|dll|node)$|\.framework\//i.test(name);
      cur.modules.push({ path: name, kind: lib ? 'library' : fd === 'txt' ? 'executable' : 'file' });
    } else {
      const type: OpenFile['type'] = file.type === 'REG' ? 'file' : file.type === 'DIR' ? 'dir' : file.type === 'CHR' || file.type === 'BLK' ? 'device' : file.type === 'PIPE' || file.type === 'FIFO' ? 'pipe' : file.type === 'sock' ? 'socket' : 'other';
      if (/^\d+$/.test(fd) || fd === 'cwd' || fd === 'rtd') cur.files.push({ fd, type, path: name });
    }
  };
  for (const l of lines(text)) {
    if (!l) continue;
    const k = l[0], v = l.slice(1);
    if (k === 'p') { flush(); file = undefined; cur = { pid: Number(v), files: [], sockets: [], modules: [] }; if (procs.length < 100_000) procs.push(cur); }
    else if (!cur) continue;
    else if (k === 'c') cur.command = v;
    else if (k === 'u') cur.uid = Number(v);
    else if (k === 'f') { flush(); file = { fd: v }; }
    else if (file) {
      if (k === 't') file.type = v;
      else if (k === 'n') file.name = v.slice(0, 4000);
      else if (k === 'P') file.proto = v;
      else if (k === 'T' && v.startsWith('ST=')) file.tcpState = v.slice(3);
    }
  }
  flush();
  // the first txt entry is the executable
  for (const p of procs) { const first = p.modules.find((m) => m.kind === 'executable'); if (first) for (const m of p.modules) if (m !== first && m.kind === 'executable') m.kind = 'library'; }
  return procs;
}

/** Parse `ps -axo pid=,ppid=,uid=,rss=,vsz=,pcpu=,comm=` output (macOS and Linux). */
export function parsePs(text: string): ProcessInfo[] {
  const out: ProcessInfo[] = [];
  for (const l of lines(text)) {
    // fixed numeric columns by regex (no overlapping quantifiers), the command is the rest of the line
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)(\s+)/.exec(l);
    if (!m) continue;
    const rest = l.slice(m[0].length);
    const ws = m[7]!;
    if (LINE_BREAK.test(rest) || (!rest && (ws.length < 2 || LINE_BREAK.test(ws[ws.length - 1]!)))) continue;
    const comm = rest.trim();
    out.push({ pid: Number(m[1]), ppid: Number(m[2]), uid: Number(m[3]), rssKb: Number(m[4]), vszKb: Number(m[5]), cpuPercent: Number(m[6]), name: comm.split('/').pop()!.slice(0, 256), exe: comm.startsWith('/') ? comm : undefined });
    if (out.length >= 100_000) break;
  }
  return out;
}

const asArray = (v: unknown): any[] => (Array.isArray(v) ? v : v && typeof v === 'object' ? [v] : []);

/** Normalise Get-CimInstance Win32_Process JSON (ConvertTo-Json) into ProcessInfo. */
export function parseWinProcesses(json: string): ProcessInfo[] {
  let j: unknown;
  try { j = JSON.parse(json.replace(/^\uFEFF/, '')); } catch { throw new InputError('PowerShell did not return JSON'); }
  return asArray(j).slice(0, 100_000).map((p) => ({ pid: Number(p.ProcessId ?? p.Id), ppid: p.ParentProcessId !== undefined ? Number(p.ParentProcessId) : undefined, name: String(p.Name ?? p.ProcessName ?? ''), exe: p.ExecutablePath ?? p.Path ?? undefined, cmdline: typeof p.CommandLine === 'string' ? [p.CommandLine.slice(0, 8000)] : undefined, threads: p.ThreadCount !== undefined ? Number(p.ThreadCount) : undefined, rssKb: p.WorkingSetSize !== undefined ? Math.round(Number(p.WorkingSetSize) / 1024) : p.WorkingSet64 !== undefined ? Math.round(Number(p.WorkingSet64) / 1024) : undefined, user: p.UserName ?? undefined }));
}

/** Normalise the Windows process detail JSON built by the desktop PowerShell script. */
export function parseWinProcessDetail(json: string): { modules: ModuleInfo[]; sockets: SocketInfo[]; threads?: number; handles?: number } {
  let j: any;
  try { j = JSON.parse(json.replace(/^\uFEFF/, '')); } catch { throw new InputError('PowerShell did not return JSON'); }
  const TCP: Record<string, string> = { Listen: 'LISTEN', Established: 'ESTABLISHED', TimeWait: 'TIME_WAIT', CloseWait: 'CLOSE_WAIT', SynSent: 'SYN_SENT', Bound: 'BOUND', '2': 'LISTEN', '5': 'ESTABLISHED' };
  const modules: ModuleInfo[] = asArray(j?.Modules).slice(0, 20_000).map((m: any, i: number) => ({ path: String(m.FileName ?? m.ModuleName ?? ''), base: m.BaseAddress !== undefined ? '0x' + BigInt(m.BaseAddress).toString(16) : undefined, size: m.ModuleMemorySize !== undefined ? Number(m.ModuleMemorySize) : undefined, kind: i === 0 ? 'executable' : 'library' }));
  const sockets: SocketInfo[] = [
    ...asArray(j?.Tcp).slice(0, 50_000).map((c: any) => ({ proto: (String(c.LocalAddress).includes(':') ? 'tcp6' : 'tcp') as SocketInfo['proto'], local: String(c.LocalAddress), localPort: Number(c.LocalPort), remote: String(c.RemoteAddress), remotePort: Number(c.RemotePort), state: TCP[String(c.State)] ?? String(c.State) })),
    ...asArray(j?.Udp).slice(0, 50_000).map((c: any) => ({ proto: (String(c.LocalAddress).includes(':') ? 'udp6' : 'udp') as SocketInfo['proto'], local: String(c.LocalAddress), localPort: Number(c.LocalPort), state: 'UNCONN' })),
  ];
  return { modules, sockets, threads: j?.Threads !== undefined ? Number(j.Threads) : undefined, handles: j?.Handles !== undefined ? Number(j.Handles) : undefined };
}
