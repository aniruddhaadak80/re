// Input and screenshot drivers for a desktop computer session: xdotool (X11), ydotool (Wayland),
// cliclick or a CoreGraphics JXA helper (macOS) and SendInput through PowerShell (Windows).
// Every program runs through execFile with an argument array; text is passed as one argument.
import { access, readFile, rm, mkdtemp } from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import { join, delimiter, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { deflateSync } from 'node:zlib';
import { run, runBuffer, powershell, psQuote } from './exec.js';
import { InputError } from './proc.js';
import { parseKeyCombo, toXdotool, toYdotool, MAC_KEYCODE, winVk, type KeyCombo } from './keys.js';
import { decodeXwd, encodePng, pngInfo } from './image.js';

export type Button = 'left' | 'right' | 'middle';
export interface WindowInfo { id: string; title: string; pid?: number; x?: number; y?: number; width?: number; height?: number }
export interface Shot { png: Uint8Array; width: number; height: number }
export interface Driver {
  kind: string;
  move(x: number, y: number): Promise<void>;
  click(o: { x?: number; y?: number; button: Button; count: number }): Promise<void>;
  drag(from: { x: number; y: number }, to: { x: number; y: number }, button: Button): Promise<void>;
  type(text: string, delayMs: number): Promise<void>;
  key(combo: KeyCombo): Promise<void>;
  scroll(dx: number, dy: number, at?: { x: number; y: number }): Promise<void>;
  cursor(): Promise<{ x: number; y: number }>;
  screenshot(): Promise<Shot>;
  windows(): Promise<WindowInfo[]>;
}

/** Folders that hold the extra desktop programs (REVLENS_DESKTOP_TOOLS unpacked .deb tree). */
export function toolsEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env = { ...base };
  const t = base.REVLENS_DESKTOP_TOOLS;
  if (t) {
    const bins = [join(t, 'usr/bin'), join(t, 'usr/libexec')];
    const libs = [join(t, 'usr/lib/aarch64-linux-gnu'), join(t, 'usr/lib/x86_64-linux-gnu')];
    env.PATH = [...bins, base.PATH].filter(Boolean).join(delimiter);
    if (!String(base.LD_LIBRARY_PATH ?? '').includes(libs[0]!)) env.LD_LIBRARY_PATH = [...libs, base.LD_LIBRARY_PATH].filter(Boolean).join(delimiter);
  }
  return env;
}

/** Find a program on PATH (after toolsEnv) or at one of the extra paths. */
export async function findProgram(name: string, env: NodeJS.ProcessEnv = toolsEnv(), extra: string[] = []): Promise<string | undefined> {
  const tryOne = async (p: string) => { try { await access(p, FS.X_OK); return p; } catch { return undefined; } };
  if (isAbsolute(name)) return tryOne(name);
  for (const p of extra) { const f = await tryOne(p); if (f) return f; }
  const exts = process.platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  for (const d of String(env.PATH ?? '').split(delimiter).slice(0, 200)) { if (!d) continue; for (const e of exts) { const f = await tryOne(join(d, name + e)); if (f) return f; } }
  return undefined;
}

const clampCoord = (v: number, what: string) => { if (!Number.isFinite(v) || Math.abs(v) > 100_000) throw new InputError(`bad ${what}`); return Math.round(v); };
const BTN_X: Record<Button, string> = { left: '1', middle: '2', right: '3' };

// ---------------- X11 through xdotool and xwd ----------------

export class XdotoolDriver implements Driver {
  kind = 'xdotool';
  constructor(private env: NodeJS.ProcessEnv, private xdotool = 'xdotool', private xwd = 'xwd') {}
  private async x(args: string[], timeoutMs = 15_000) {
    const r = await run(this.xdotool, args, { env: this.env, timeoutMs });
    if (r.code !== 0) throw new InputError(`xdotool ${args[0]} failed: ${r.stderr.trim().slice(0, 300)}`);
    return r.stdout;
  }
  async move(x: number, y: number) { await this.x(['mousemove', '--sync', String(clampCoord(x, 'x')), String(clampCoord(y, 'y'))]); }
  async click(o: { x?: number; y?: number; button: Button; count: number }) {
    if (o.x !== undefined && o.y !== undefined) await this.move(o.x, o.y);
    await this.x(['click', '--repeat', String(Math.max(1, Math.min(o.count, 5))), '--delay', '80', BTN_X[o.button]]);
  }
  async drag(from: { x: number; y: number }, to: { x: number; y: number }, button: Button) {
    await this.move(from.x, from.y);
    await this.x(['mousedown', BTN_X[button]]);
    const steps = 8;
    for (let i = 1; i <= steps; i++) await this.move(from.x + ((to.x - from.x) * i) / steps, from.y + ((to.y - from.y) * i) / steps);
    await this.x(['mouseup', BTN_X[button]]);
  }
  async type(text: string, delayMs: number) {
    // xdotool type treats its argument as literal text; -- stops option parsing for text that starts with a dash
    for (let i = 0; i < text.length; i += 400) await this.x(['type', '--delay', String(Math.max(0, Math.min(delayMs, 500))), '--', text.slice(i, i + 400)], 120_000);
  }
  async key(c: KeyCombo) { await this.x(['key', '--clearmodifiers', toXdotool(c)]); }
  async scroll(dx: number, dy: number, at?: { x: number; y: number }) {
    if (at) await this.move(at.x, at.y);
    if (dy) await this.x(['click', '--repeat', String(Math.min(Math.abs(Math.round(dy)), 100)), '--delay', '30', dy > 0 ? '5' : '4']);
    if (dx) await this.x(['click', '--repeat', String(Math.min(Math.abs(Math.round(dx)), 100)), '--delay', '30', dx > 0 ? '7' : '6']);
  }
  async cursor() {
    const out = await this.x(['getmouselocation', '--shell']);
    const g = (k: string) => Number((new RegExp(`^${k}=(-?\\d+)`, 'm').exec(out) ?? [])[1]);
    return { x: g('X'), y: g('Y') };
  }
  async screenshot(): Promise<Shot> {
    const r = await runBuffer(this.xwd, ['-root', '-silent'], { env: this.env, timeoutMs: 30_000 });
    if (r.code !== 0 || r.stdout.length < 100) throw new InputError(`xwd failed: ${r.stderr.trim().slice(0, 300)}`);
    const img = decodeXwd(r.stdout);
    return { png: encodePng(img, (b) => new Uint8Array(deflateSync(b, { level: 6 }))), width: img.width, height: img.height };
  }
  async windows(): Promise<WindowInfo[]> {
    const r = await run(this.xdotool, ['search', '--onlyvisible', '--name', ''], { env: this.env, timeoutMs: 10_000 });
    const ids = r.stdout.split('\n').map((s) => s.trim()).filter((s) => /^\d+$/.test(s)).slice(0, 100);
    const out: WindowInfo[] = [];
    for (const id of ids) {
      const [name, geo, pid] = await Promise.all([
        run(this.xdotool, ['getwindowname', id], { env: this.env, timeoutMs: 5000 }).then((x) => x.stdout.trim()).catch(() => ''),
        run(this.xdotool, ['getwindowgeometry', '--shell', id], { env: this.env, timeoutMs: 5000 }).then((x) => x.stdout).catch(() => ''),
        run(this.xdotool, ['getwindowpid', id], { env: this.env, timeoutMs: 5000 }).then((x) => Number(x.stdout.trim()) || undefined).catch(() => undefined),
      ]);
      const g = (k: string) => { const m = new RegExp(`^${k}=(-?\\d+)`, 'm').exec(geo); return m ? Number(m[1]) : undefined; };
      out.push({ id, title: name, pid, x: g('X'), y: g('Y'), width: g('WIDTH'), height: g('HEIGHT') });
    }
    return out;
  }
}

// ---------------- Wayland through ydotool ----------------

export class YdotoolDriver implements Driver {
  kind = 'ydotool';
  constructor(private env: NodeJS.ProcessEnv, private ydotool = 'ydotool') {}
  private async y(args: string[]) { const r = await run(this.ydotool, args, { env: this.env, timeoutMs: 30_000 }); if (r.code !== 0) throw new InputError(`ydotool ${args[0]} failed: ${r.stderr.trim().slice(0, 300)}`); }
  async move(x: number, y: number) { await this.y(['mousemove', '--absolute', '-x', String(clampCoord(x, 'x')), '-y', String(clampCoord(y, 'y'))]); }
  async click(o: { x?: number; y?: number; button: Button; count: number }) {
    if (o.x !== undefined && o.y !== undefined) await this.move(o.x, o.y);
    const code = { left: '0xC0', right: '0xC1', middle: '0xC2' }[o.button];
    await this.y(['click', '--repeat', String(Math.max(1, Math.min(o.count, 5))), '--next-delay', '80', code]);
  }
  async drag(from: { x: number; y: number }, to: { x: number; y: number }, button: Button) {
    const down = { left: '0x40', right: '0x41', middle: '0x42' }[button], up = { left: '0x80', right: '0x81', middle: '0x82' }[button];
    await this.move(from.x, from.y); await this.y(['click', down]); await this.move(to.x, to.y); await this.y(['click', up]);
  }
  async type(text: string, delayMs: number) { await this.y(['type', '--key-delay', String(Math.max(0, Math.min(delayMs, 500))), '--', text]); }
  async key(c: KeyCombo) { await this.y(['key', ...toYdotool(c)]); }
  async scroll(dx: number, dy: number, at?: { x: number; y: number }) { if (at) await this.move(at.x, at.y); await this.y(['mousemove', '--wheel', '-x', String(Math.round(dx)), '-y', String(Math.round(-dy))]); }
  async cursor(): Promise<{ x: number; y: number }> { throw new InputError('ydotool cannot read the pointer position'); }
  async screenshot(): Promise<Shot> {
    const grim = await findProgram('grim', this.env);
    if (!grim) throw new InputError('screenshots on Wayland need grim');
    const r = await runBuffer(grim, ['-t', 'png', '-'], { env: this.env, timeoutMs: 30_000 });
    if (r.code !== 0) throw new InputError(`grim failed: ${r.stderr.slice(0, 300)}`);
    const i = pngInfo(r.stdout); return { png: r.stdout, width: i.width, height: i.height };
  }
  async windows(): Promise<WindowInfo[]> { return []; }
}

// ---------------- macOS: cliclick when present, otherwise CoreGraphics through JXA ----------------

const MAC_JXA = `ObjC.import('CoreGraphics');
function run(argv) {
  var a = JSON.parse(argv[0]);
  function mouse(type, x, y, btn, clicks) { var e = $.CGEventCreateMouseEvent(null, type, { x: x, y: y }, btn); if (clicks) $.CGEventSetIntegerValueField(e, 1, clicks); $.CGEventPost(0, e); }
  var DOWN = { left: [1, 2, 0], right: [3, 4, 1], middle: [25, 26, 2] };
  if (a.op === 'cursor') { var p = $.CGEventGetLocation($.CGEventCreate(null)); return JSON.stringify({ x: p.x, y: p.y }); }
  if (a.op === 'move') { mouse(5, a.x, a.y, 0, 0); return 'ok'; }
  if (a.op === 'click') {
    var p2 = a.x === undefined ? $.CGEventGetLocation($.CGEventCreate(null)) : { x: a.x, y: a.y }; var d = DOWN[a.button];
    mouse(5, p2.x, p2.y, 0, 0);
    for (var i = 1; i <= a.count; i++) { mouse(d[0], p2.x, p2.y, d[2], i); mouse(d[1], p2.x, p2.y, d[2], i); delay(0.05); }
    return 'ok';
  }
  if (a.op === 'drag') { var b = DOWN[a.button]; mouse(5, a.x, a.y, 0, 0); mouse(b[0], a.x, a.y, b[2], 1); for (var s = 1; s <= 8; s++) mouse(b[0] === 1 ? 6 : 7, a.x + (a.x2 - a.x) * s / 8, a.y + (a.y2 - a.y) * s / 8, b[2], 0); mouse(b[1], a.x2, a.y2, b[2], 1); return 'ok'; }
  if (a.op === 'key') {
    var flags = 0; a.mods.forEach(function (m) { flags |= { shift: 0x20000, ctrl: 0x40000, alt: 0x80000, super: 0x100000 }[m]; });
    var dn = $.CGEventCreateKeyboardEvent(null, a.code, true); $.CGEventSetFlags(dn, flags); $.CGEventPost(0, dn);
    var up = $.CGEventCreateKeyboardEvent(null, a.code, false); $.CGEventSetFlags(up, flags); $.CGEventPost(0, up);
    return 'ok';
  }
  if (a.op === 'type') { var se = Application('System Events'); se.keystroke(a.text); return 'ok'; }
  if (a.op === 'scroll') { var e2 = $.CGEventCreateScrollWheelEvent2(null, 1, 2, a.dy, a.dx, 0); $.CGEventPost(0, e2); return 'ok'; }
  return 'unknown op';
}`;

export class MacDriver implements Driver {
  kind = 'macos';
  constructor(private cliclick?: string) { if (cliclick) this.kind = 'macos-cliclick'; }
  private async jxa(a: Record<string, unknown>) {
    const r = await run('osascript', ['-l', 'JavaScript', '-e', MAC_JXA, JSON.stringify(a)], { timeoutMs: 60_000 });
    if (r.code !== 0) throw new InputError(`osascript failed (grant Accessibility access to the app running RevLens): ${r.stderr.trim().slice(0, 300)}`);
    return r.stdout.trim();
  }
  private async cc(args: string[]) { const r = await run(this.cliclick!, args, { timeoutMs: 60_000 }); if (r.code !== 0) throw new InputError(`cliclick failed: ${r.stderr.slice(0, 300)}`); }
  async move(x: number, y: number) { if (this.cliclick) await this.cc([`m:${clampCoord(x, 'x')},${clampCoord(y, 'y')}`]); else await this.jxa({ op: 'move', x: clampCoord(x, 'x'), y: clampCoord(y, 'y') }); }
  async click(o: { x?: number; y?: number; button: Button; count: number }) {
    if (this.cliclick && o.button !== 'middle') {
      const at = o.x !== undefined && o.y !== undefined ? `${clampCoord(o.x, 'x')},${clampCoord(o.y, 'y')}` : '.';
      const verb = o.button === 'right' ? 'rc' : o.count >= 3 ? 'tc' : o.count === 2 ? 'dc' : 'c';
      await this.cc([`${verb}:${at}`]); return;
    }
    await this.jxa({ op: 'click', x: o.x, y: o.y, button: o.button, count: Math.max(1, Math.min(o.count, 5)) });
  }
  async drag(from: { x: number; y: number }, to: { x: number; y: number }, button: Button) {
    if (this.cliclick && button === 'left') { await this.cc([`dd:${Math.round(from.x)},${Math.round(from.y)}`, `dm:${Math.round(to.x)},${Math.round(to.y)}`, `du:${Math.round(to.x)},${Math.round(to.y)}`]); return; }
    await this.jxa({ op: 'drag', x: from.x, y: from.y, x2: to.x, y2: to.y, button });
  }
  async type(text: string) { if (this.cliclick) await this.cc([`t:${text}`]); else await this.jxa({ op: 'type', text }); }
  async key(c: KeyCombo) {
    const code = MAC_KEYCODE[c.key.toLowerCase()];
    if (code === undefined) throw new InputError(`no macOS key code for ${c.key}`);
    await this.jxa({ op: 'key', code, mods: c.mods });
  }
  async scroll(dx: number, dy: number, at?: { x: number; y: number }) { if (at) await this.move(at.x, at.y); await this.jxa({ op: 'scroll', dx: Math.round(dx), dy: Math.round(-dy) }); }
  async cursor() { if (this.cliclick) { const r = await run(this.cliclick, ['p:.'], { timeoutMs: 10_000 }); const m = /(-?\d+),(-?\d+)/.exec(r.stdout); if (m) return { x: Number(m[1]), y: Number(m[2]) }; } return JSON.parse(await this.jxa({ op: 'cursor' })) as { x: number; y: number }; }
  async screenshot(): Promise<Shot> {
    const dir = await mkdtemp(join(tmpdir(), 'rl-shot-'));
    try {
      const f = join(dir, 'shot.png');
      const r = await run('screencapture', ['-x', '-t', 'png', f], { timeoutMs: 30_000 });
      if (r.code !== 0) throw new InputError(`screencapture failed (grant Screen Recording permission): ${r.stderr.slice(0, 300)}`);
      const png = new Uint8Array(await readFile(f)); const i = pngInfo(png);
      return { png, width: i.width, height: i.height };
    } finally { await rm(dir, { recursive: true, force: true }); }
  }
  async windows(): Promise<WindowInfo[]> {
    const r = await run('osascript', ['-l', 'JavaScript', '-e', 'var se=Application("System Events");var out=[];se.processes.whose({visible:true})().forEach(function(p){try{p.windows().forEach(function(w){var pos=w.position(),s=w.size();out.push({id:p.name()+"/"+w.name(),title:String(w.name()),pid:p.unixId(),x:pos[0],y:pos[1],width:s[0],height:s[1]})})}catch(e){}});JSON.stringify(out.slice(0,100))'], { timeoutMs: 60_000 });
    try { return JSON.parse(r.stdout) as WindowInfo[]; } catch { return []; }
  }
}

// ---------------- Windows through SendInput ----------------

const WIN_CS = `using System; using System.Runtime.InteropServices;
public static class RevLensInput {
  [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Explicit)] public struct UNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public UNION u; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint n, INPUT[] inputs, int size);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  static uint Send(INPUT i) { return SendInput(1, new INPUT[] { i }, Marshal.SizeOf(typeof(INPUT))); }
  public static uint Mouse(uint flags, int data) { var i = new INPUT(); i.type = 0; i.u.mi.dwFlags = flags; i.u.mi.mouseData = unchecked((uint)data); return Send(i); }
  public static uint Key(ushort vk, bool up) { var i = new INPUT(); i.type = 1; i.u.ki.wVk = vk; i.u.ki.dwFlags = up ? 2u : 0u; return Send(i); }
  public static void Text(string s) { foreach (char c in s) { var i = new INPUT(); i.type = 1; i.u.ki.wScan = c; i.u.ki.dwFlags = 4; Send(i); i.u.ki.dwFlags = 6; Send(i); System.Threading.Thread.Sleep(5); } }
}`;

export class WindowsDriver implements Driver {
  kind = 'sendinput';
  private async ps(body: string, timeoutMs = 60_000) {
    const r = await powershell(`$ErrorActionPreference='Stop'; if (-not ('RevLensInput' -as [type])) { Add-Type -TypeDefinition @'\n${WIN_CS}\n'@ }; [void][RevLensInput]::SetProcessDPIAware(); ${body}`, timeoutMs);
    if (r.code !== 0) throw new InputError(`PowerShell input failed: ${r.stderr.trim().slice(0, 300)}`);
    return r.stdout.trim();
  }
  async move(x: number, y: number) { await this.ps(`[void][RevLensInput]::SetCursorPos(${clampCoord(x, 'x')}, ${clampCoord(y, 'y')})`); }
  async click(o: { x?: number; y?: number; button: Button; count: number }) {
    const [d, u] = { left: [2, 4], right: [8, 16], middle: [32, 64] }[o.button];
    const pos = o.x !== undefined && o.y !== undefined ? `[void][RevLensInput]::SetCursorPos(${clampCoord(o.x, 'x')}, ${clampCoord(o.y, 'y')}); ` : '';
    await this.ps(`${pos}for ($i = 0; $i -lt ${Math.max(1, Math.min(o.count, 5))}; $i++) { [void][RevLensInput]::Mouse(${d}, 0); [void][RevLensInput]::Mouse(${u}, 0); Start-Sleep -Milliseconds 60 }`);
  }
  async drag(from: { x: number; y: number }, to: { x: number; y: number }, button: Button) {
    const [d, u] = { left: [2, 4], right: [8, 16], middle: [32, 64] }[button];
    await this.ps(`[void][RevLensInput]::SetCursorPos(${clampCoord(from.x, 'x')}, ${clampCoord(from.y, 'y')}); [void][RevLensInput]::Mouse(${d}, 0); for ($s = 1; $s -le 8; $s++) { [void][RevLensInput]::SetCursorPos([int](${from.x} + (${to.x - from.x}) * $s / 8), [int](${from.y} + (${to.y - from.y}) * $s / 8)); Start-Sleep -Milliseconds 20 }; [void][RevLensInput]::Mouse(${u}, 0)`);
  }
  async type(text: string) { await this.ps(`[RevLensInput]::Text(${psQuote(text.slice(0, 500))})`); if (text.length > 500) await this.type(text.slice(500)); }
  async key(c: KeyCombo) {
    const vks = [...c.mods.map(winVk), winVk(c.key)];
    await this.ps([...vks.map((v) => `[void][RevLensInput]::Key(${v}, $false)`), ...[...vks].reverse().map((v) => `[void][RevLensInput]::Key(${v}, $true)`)].join('; '));
  }
  async scroll(dx: number, dy: number, at?: { x: number; y: number }) {
    const pos = at ? `[void][RevLensInput]::SetCursorPos(${clampCoord(at.x, 'x')}, ${clampCoord(at.y, 'y')}); ` : '';
    await this.ps(`${pos}${dy ? `[void][RevLensInput]::Mouse(2048, ${Math.round(-dy * 120)}); ` : ''}${dx ? `[void][RevLensInput]::Mouse(4096, ${Math.round(dx * 120)})` : ''}`);
  }
  async cursor() { const o = await this.ps('$p = New-Object RevLensInput+POINT; [void][RevLensInput]::GetCursorPos([ref]$p); "$($p.X),$($p.Y)"'); const [x, y] = o.split(',').map(Number); return { x: x!, y: y! }; }
  async screenshot(): Promise<Shot> {
    const dir = await mkdtemp(join(tmpdir(), 'rl-shot-'));
    try {
      const f = join(dir, 'shot.png');
      await this.ps(`Add-Type -AssemblyName System.Windows.Forms, System.Drawing; $b = [System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height; $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size); $bmp.Save(${psQuote(f)}, [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()`);
      const png = new Uint8Array(await readFile(f)); const i = pngInfo(png);
      return { png, width: i.width, height: i.height };
    } finally { await rm(dir, { recursive: true, force: true }); }
  }
  async windows(): Promise<WindowInfo[]> {
    const r = await powershell('Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 100 @{n="id";e={[string]$_.MainWindowHandle}},@{n="title";e={$_.MainWindowTitle}},@{n="pid";e={$_.Id}} | ConvertTo-Json -Compress', 60_000);
    try { const j = JSON.parse(r.stdout.replace(/^\uFEFF/, '')); return (Array.isArray(j) ? j : [j]) as WindowInfo[]; } catch { return []; }
  }
}

export { parseKeyCombo };
