// Finds external tools on PATH, in well known install folders, and through env vars,
// and reads their versions. Node only.
import { accessSync, closeSync, constants, existsSync, fstatSync, openSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { runTool } from './exec.js';
import { TOOL_META, TOOL_IDS } from './catalog.js';
import type { Detection, ToolId } from './types.js';

export interface DetectOptions {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  /** skip running `--version` style probes */
  skipVersion?: boolean;
  /** ignore the in-process cache */
  refresh?: boolean;
}

const MAX_PATTERN_MATCHES = 32;

function isFile(p: string): boolean {
  try { return statSync(p).isFile(); } catch { return false; }
}
function isDir(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}
function isExecutable(p: string, platform: NodeJS.Platform): boolean {
  if (!isFile(p)) return false;
  if (platform === 'win32') return true;
  try { accessSync(p, constants.X_OK); return true; } catch { return false; }
}

/** Expand a path whose segments may contain one `*` wildcard each. Bounded and sorted newest name first. */
export function expandPattern(pattern: string): string[] {
  const norm = pattern.replace(/\\/g, '/');
  const parts = norm.split('/');
  let bases: string[] = [parts[0] === '' ? '/' : parts[0] + (parts[0]!.endsWith(':') ? '/' : '')];
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i]!;
    if (!seg) continue;
    const next: string[] = [];
    for (const b of bases) {
      if (!seg.includes('*')) { next.push(join(b, seg)); continue; }
      const [pre, post] = seg.split('*', 2) as [string, string];
      let names: string[] = [];
      try { names = readdirSync(b); } catch { continue; }
      names = names.filter((n) => n.startsWith(pre) && n.endsWith(post ?? '') && n.length >= pre.length + (post ?? '').length)
        .sort().reverse().slice(0, MAX_PATTERN_MATCHES);
      for (const n of names) next.push(join(b, n));
    }
    bases = next.slice(0, MAX_PATTERN_MATCHES);
    if (bases.length === 0) break;
  }
  return bases.filter((b) => existsSync(b));
}

function exeNames(name: string, platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string[] {
  if (platform !== 'win32') return [name];
  if (/\.(exe|bat|cmd|com)$/i.test(name)) return [name];
  const exts = (env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean).map((e) => e.toLowerCase());
  return exts.map((e) => name + e);
}

/** Search PATH, then the given extra folders, for the first executable with one of the names. */
export function findExecutable(names: string[], extraDirs: string[] = [], opts: DetectOptions = {}): { path: string; via: 'path' | 'dir' } | undefined {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const pathDirs = (env.PATH ?? env.Path ?? '').split(platform === 'win32' ? ';' : delimiter).filter(Boolean);
  for (const n of names) {
    for (const d of pathDirs) {
      for (const f of exeNames(n, platform, env)) {
        const p = join(d, f);
        if (isExecutable(p, platform)) return { path: p, via: 'path' };
      }
    }
  }
  for (const pattern of extraDirs) {
    for (const d of expandPattern(pattern)) {
      for (const n of names) {
        for (const f of exeNames(n, platform, env)) {
          const p = join(d, f);
          if (isExecutable(p, platform)) return { path: p, via: 'dir' };
        }
      }
    }
  }
  return undefined;
}

function overrideVar(id: ToolId): string {
  return `REVLENS_${id.toUpperCase().replace(/-/g, '_')}_PATH`;
}

function home(env: NodeJS.ProcessEnv): string {
  return env.HOME || env.USERPROFILE || homedir();
}

/** Well known install folders per tool and OS. Globs with `*` are expanded. */
function wellKnownDirs(id: ToolId, platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string[] {
  const h = home(env);
  const local = env.LOCALAPPDATA || join(h, 'AppData', 'Local');
  const pf = env.ProgramFiles || 'C:/Program Files';
  const common = platform === 'win32'
    ? [join(h, 'scoop', 'shims'), 'C:/ProgramData/chocolatey/bin']
    : ['/usr/local/bin', '/opt/homebrew/bin', '/usr/bin', join(h, '.local', 'bin'), join(h, 'bin')];
  switch (id) {
    case 'radare2':
      return platform === 'win32' ? [...common, 'C:/radare2/bin', join(local, 'Programs', 'radare2', 'bin'), 'C:/radare2-*/bin'] : common;
    case 'rizin':
      // Cutter's Windows release ships rizin.exe next to cutter.exe
      return platform === 'win32' ? [...common, join(pf, 'rizin', 'bin'), 'C:/rizin*/bin', join(h, 'scoop', 'apps', 'cutter', 'current'), join(pf, 'Cutter*'), 'C:/Cutter*'] : common;
    case 'cutter':
      return platform === 'darwin' ? ['/Applications/Cutter.app/Contents/MacOS'] : platform === 'win32' ? [...common, 'C:/Cutter*'] : [...common, '/opt/cutter*'];
    case 'java':
      return platform === 'darwin'
        ? ['/Library/Java/JavaVirtualMachines/*/Contents/Home/bin', '/opt/homebrew/opt/openjdk/bin', '/opt/homebrew/opt/openjdk@25/bin', '/opt/homebrew/opt/openjdk@21/bin']
        : platform === 'win32' ? [join(pf, 'Eclipse Adoptium', 'jdk-*', 'bin'), join(pf, 'Java', 'jdk-*', 'bin'), join(pf, 'Microsoft', 'jdk-*', 'bin')]
          : ['/usr/lib/jvm/*/bin', '/opt/java/*/bin', '/opt/jdk*/bin'];
    case 'jadx':
      return [...common, join(h, 'jadx', 'bin'), join(h, 'tools', 'jadx*', 'bin'), '/opt/jadx*/bin', 'C:/jadx*/bin'];
    case 'apktool':
      return common;
    case 'ilspy':
      return [join(h, '.dotnet', 'tools'), ...common];
    case 'dotnet':
      return platform === 'win32' ? [join(pf, 'dotnet'), join(h, '.dotnet')] : [join(h, '.dotnet'), '/usr/share/dotnet', '/usr/local/share/dotnet', '/usr/lib/dotnet'];
    case 'frida':
      return platform === 'win32'
        ? [join(local, 'Programs', 'Python', 'Python3*', 'Scripts'), join(h, 'AppData', 'Roaming', 'Python', 'Python3*', 'Scripts'), join(h, '.local', 'bin')]
        : [...common, join(h, 'Library', 'Python', '3.*', 'bin')];
    case 'gdb':
    case 'lldb':
      return platform === 'win32' ? [...common, 'C:/msys64/mingw64/bin', 'C:/msys64/ucrt64/bin', join(pf, 'LLVM', 'bin')] : [...common, '/usr/lib/llvm-*/bin', '/opt/homebrew/opt/llvm/bin'];
    case 'objdump':
      return platform === 'win32' ? [...common, 'C:/msys64/mingw64/bin', 'C:/msys64/ucrt64/bin'] : [...common, '/opt/homebrew/opt/binutils/bin', '/usr/local/opt/binutils/bin'];
    case 'llvm-objdump':
      return platform === 'win32' ? [join(pf, 'LLVM', 'bin'), ...common] : [...common, '/usr/lib/llvm-*/bin', '/opt/homebrew/opt/llvm/bin', '/usr/local/opt/llvm/bin', '/Library/Developer/CommandLineTools/usr/bin'];
    case 'binwalk':
      return [...common, join(h, '.cargo', 'bin')];
    case 'adb': {
      const sdk = [env.ANDROID_HOME, env.ANDROID_SDK_ROOT].filter(Boolean).map((s) => join(s!, 'platform-tools'));
      return [...sdk, ...common, join(h, 'Library', 'Android', 'sdk', 'platform-tools'), join(h, 'Android', 'Sdk', 'platform-tools'), join(local, 'Android', 'Sdk', 'platform-tools')];
    }
    case 'hopper':
      return ['/opt/hopper-v4/bin', '/opt/hopper-v5/bin', '/Applications/Hopper Disassembler v4.app/Contents/MacOS', '/Applications/Hopper Disassembler.app/Contents/MacOS'];
    default:
      return common;
  }
}

const BINARIES: Partial<Record<ToolId, string[]>> = {
  radare2: ['r2', 'radare2'],
  rizin: ['rizin'],
  cutter: ['cutter', 'Cutter'],
  java: ['java'],
  jadx: ['jadx'],
  apktool: ['apktool'],
  ilspy: ['ilspycmd'],
  dotnet: ['dotnet'],
  frida: ['frida'],
  gdb: ['gdb'],
  lldb: ['lldb'],
  objdump: ['objdump', 'gobjdump'],
  'llvm-objdump': ['llvm-objdump', 'llvm-objdump-20', 'llvm-objdump-19', 'llvm-objdump-18', 'llvm-objdump-17'],
  binwalk: ['binwalk'],
  adb: ['adb'],
  hopper: ['hopper', 'Hopper'],
};

/** Programs that are GUIs or need a license prompt: never run them to read a version. */
const NO_VERSION_PROBE = new Set<ToolId>(['cutter', 'hopper']);

const VERSION_ARGS: Partial<Record<ToolId, string[]>> = {
  radare2: ['-v'], rizin: ['-v'], java: ['-version'], jadx: ['--version'], apktool: ['--version'], ilspy: ['--version'],
  dotnet: ['--version'], frida: ['--version'], gdb: ['--version'], lldb: ['--version'], objdump: ['--version'],
  'llvm-objdump': ['--version'], binwalk: ['--version'], adb: ['version'],
};

/** Second try when the first version probe prints nothing useful (binwalk v2 treats --version as a file name). */
const VERSION_FALLBACK: Partial<Record<ToolId, string[]>> = { binwalk: ['--help'] };

/** Last whitespace separated token that looks like a version, on the first line containing `marker`. */
function lastVersionToken(text: string, marker: string): string | undefined {
  const line = text.split(/\r?\n/).find((l) => l.includes(marker));
  if (!line) return undefined;
  const toks = line.trim().split(/\s+/).reverse();
  return toks.find((x) => /^[0-9]+\.[0-9]+/.test(x))?.replace(/[^0-9.].*$/, '');
}

/** Pull a version number out of a tool's version banner. Exported for tests. */
export function parseVersion(id: ToolId, text: string): string | undefined {
  const t = text.slice(0, 4000);
  const pick = (re: RegExp) => re.exec(t)?.[1];
  switch (id) {
    case 'java': return pick(/version "([0-9][0-9._+a-z-]*)"/i) ?? pick(/(?:openjdk|java) ([0-9]+(?:\.[0-9]+)*)/i);
    case 'radare2': return pick(/radare2 ([0-9]+\.[0-9]+\.[0-9]+)/);
    case 'rizin': return pick(/rizin ([0-9]+\.[0-9]+\.[0-9]+)/);
    case 'gdb': return lastVersionToken(t, 'GNU gdb') ?? pick(/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
    case 'lldb': return pick(/lldb(?:-|\s+version\s+)([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
    case 'objdump': return lastVersionToken(t, 'GNU objdump') ?? pick(/LLVM version ([0-9]+\.[0-9]+\.[0-9]+)/);
    case 'llvm-objdump': return pick(/LLVM version ([0-9]+\.[0-9]+\.[0-9]+)/);
    case 'binwalk': return pick(/binwalk v?([0-9]+\.[0-9]+\.[0-9]+)/i);
    case 'adb': return pick(/Android Debug Bridge version ([0-9.]+)/);
    case 'ilspy': return pick(/([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
    default: return pick(/([0-9]+\.[0-9]+(?:\.[0-9]+)*)/);
  }
}

/** Major Java version from a version string like 25.0.5, 21, or 1.8.0_402. */
export function javaMajor(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const m = /^([0-9]+)(?:\.([0-9]+))?/.exec(v);
  if (!m) return undefined;
  const a = Number(m[1]);
  return a === 1 && m[2] ? Number(m[2]) : a;
}

async function probeVersion(id: ToolId, path: string, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  const args = VERSION_ARGS[id];
  if (!args) return undefined;
  const r = await runTool(path, args, { timeoutMs: 20_000, maxOutputBytes: 64 * 1024, env });
  const v = parseVersion(id, `${r.stdout}\n${r.stderr}`);
  if (v || !VERSION_FALLBACK[id]) return v;
  const r2 = await runTool(path, VERSION_FALLBACK[id]!, { timeoutMs: 20_000, maxOutputBytes: 64 * 1024, env });
  return parseVersion(id, `${r2.stdout}\n${r2.stderr}`);
}

// ---------- special detectors ----------

/** Read a Java style .properties file into a map. Bounded to 256 KiB. */
export function readProperties(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  let text = '';
  try { text = readFileSync(path, 'utf8').slice(0, 256 * 1024); } catch { return out; }
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('!')) continue;
    const i = t.search(/[=:]/);
    if (i <= 0) continue;
    out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  }
  return out;
}

/** Ghidra's native decompiler folder name for this OS and CPU. */
export function ghidraOsDir(platform: NodeJS.Platform = process.platform, arch: string = process.arch): string {
  const cpu = arch === 'arm64' ? 'arm_64' : 'x86_64';
  return platform === 'win32' ? `win_${cpu}` : platform === 'darwin' ? `mac_${cpu}` : `linux_${cpu}`;
}

function ghidraRoots(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): { root: string; via: Detection['via'] }[] {
  const h = home(env);
  const out: { root: string; via: Detection['via'] }[] = [];
  for (const k of ['REVLENS_GHIDRA_PATH', 'GHIDRA_INSTALL_DIR', 'GHIDRA_HOME']) {
    const v = env[k];
    if (v) out.push({ root: v, via: k.startsWith('REVLENS') ? 'override' : 'env' });
  }
  const pats = platform === 'win32'
    ? ['C:/ghidra*', 'C:/Program Files/ghidra*', 'C:/tools/ghidra*', join(h, 'ghidra*'), join(h, 'Downloads', 'ghidra*'), join(h, 'scoop', 'apps', 'ghidra', 'current')]
    : ['/opt/homebrew/opt/ghidra/libexec', '/usr/local/opt/ghidra/libexec', '/usr/share/ghidra', '/opt/ghidra*', '/opt/ghidra/ghidra*',
      join(h, 'ghidra*'), join(h, 'tools', 'ghidra*'), join(h, 'Downloads', 'ghidra*'), '/Applications/ghidra*'];
  for (const p of pats) for (const r of expandPattern(p)) out.push({ root: r, via: 'dir' });
  return out;
}

async function detectJava(opts: DetectOptions): Promise<Detection> {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const exe = platform === 'win32' ? 'java.exe' : 'java';
  let found: { path: string; via: Detection['via'] } | undefined;
  if (env.REVLENS_JAVA_PATH && isFile(env.REVLENS_JAVA_PATH)) found = { path: env.REVLENS_JAVA_PATH, via: 'override' };
  else if (env.JAVA_HOME && isExecutable(join(env.JAVA_HOME, 'bin', exe), platform)) found = { path: join(env.JAVA_HOME, 'bin', exe), via: 'env' };
  else found = findExecutable(['java'], wellKnownDirs('java', platform, env), opts);
  const base: Detection = { id: 'java', name: TOOL_META.java.name, available: false };
  if (!found) return base;
  const det: Detection = { ...base, available: true, path: found.path, via: found.via };
  if (!opts.skipVersion) det.version = await probeVersion('java', found.path, env);
  let javaHome: string | undefined;
  try { javaHome = dirname(dirname(realpathSync(found.path))); } catch { javaHome = dirname(dirname(found.path)); }
  const major = javaMajor(det.version);
  det.details = { javaHome, major: major ?? null, compiler: isFile(join(javaHome, 'bin', platform === 'win32' ? 'javac.exe' : 'javac')) };
  return det;
}

async function detectGhidra(opts: DetectOptions, java: Detection): Promise<Detection> {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const base: Detection = { id: 'ghidra', name: TOOL_META.ghidra.name, available: false };
  const script = platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless';
  for (const { root, via } of ghidraRoots(env, platform)) {
    const headless = join(root, 'support', script);
    const propsPath = join(root, 'Ghidra', 'application.properties');
    if (!isFile(headless) || !isFile(propsPath)) continue;
    const props = readProperties(propsPath);
    const javaMin = Number(props['application.java.min'] || 0) || undefined;
    const osDir = ghidraOsDir(platform);
    const decompiler = join(root, 'Ghidra', 'Features', 'Decompiler', 'os', osDir, platform === 'win32' ? 'decompile.exe' : 'decompile');
    const problems: string[] = [];
    const jMajor = typeof java.details?.major === 'number' ? java.details.major : undefined;
    if (!java.available) problems.push('Java not found. Ghidra needs a JDK.');
    else if (javaMin && jMajor && jMajor < javaMin) problems.push(`Ghidra ${props['application.version']} needs JDK ${javaMin} or newer, found ${java.version}.`);
    else if (java.details?.compiler === false) problems.push('Found a JRE without javac. Ghidra scripts need a full JDK.');
    if (!isFile(decompiler)) problems.push(`No native decompiler for ${osDir}. Listing works, decompiling does not. Build it with: make -C "${join(root, 'Ghidra', 'Features', 'Decompiler', 'src', 'decompile', 'cpp')}" ghidra_opt, then copy ghidra_opt to ${decompiler}.`);
    const fatal = problems.some((p) => p.startsWith('Java') || p.includes('needs JDK') || p.includes('JRE'));
    return {
      ...base,
      available: !fatal,
      path: root,
      via,
      version: props['application.version'],
      details: {
        analyzeHeadless: headless,
        releaseName: props['application.release.name'] ?? null,
        javaMin: javaMin ?? null,
        decompiler: isFile(decompiler),
        javaHome: (java.details?.javaHome as string | undefined) ?? null,
      },
      ...(problems.length ? { problems } : {}),
    };
  }
  return base;
}

function idaRoots(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): { root: string; via: Detection['via'] }[] {
  const h = home(env);
  const out: { root: string; via: Detection['via'] }[] = [];
  if (env.REVLENS_IDA_PATH) out.push({ root: env.REVLENS_IDA_PATH, via: 'override' });
  if (env.IDADIR) out.push({ root: env.IDADIR, via: 'env' });
  const pats = platform === 'win32'
    ? ['C:/Program Files/IDA*', 'C:/Program Files/IDA Pro*', 'C:/Program Files/IDA Free*']
    : platform === 'darwin'
      ? ['/Applications/IDA*.app/Contents/MacOS', join(h, 'Applications', 'IDA*.app', 'Contents', 'MacOS')]
      : ['/opt/ida*', '/opt/idapro*', join(h, 'ida*'), join(h, 'idapro*'), join(h, 'idafree*')];
  for (const p of pats) for (const r of expandPattern(p)) out.push({ root: r, via: 'dir' });
  return out;
}

/**
 * Version from an IDA install folder name, such as "IDA Professional 9.1" or "ida-pro-9.0": the first
 * dotted number after an "ida" (any case) with only non digits between. A plain scan, linear in the path.
 */
function idaVersionFromPath(root: string): string | undefined {
  const lower = root.toLowerCase();
  for (let i = lower.indexOf('ida'); i >= 0; i = lower.indexOf('ida', i + 1)) {
    let j = i + 3;
    while (j < root.length && !isDigit(root.charCodeAt(j))) j++;
    let k = j;
    let dots = 0;
    for (;;) {
      const s = k;
      while (k < root.length && isDigit(root.charCodeAt(k))) k++;
      if (k === s) { if (dots > 0) k--; break; }
      if (root[k] === '.' && k + 1 < root.length && isDigit(root.charCodeAt(k + 1))) { dots++; k++; continue; }
      break;
    }
    if (dots > 0) return root.slice(j, k);
  }
  return undefined;
}

function isDigit(c: number): boolean { return c >= 48 && c <= 57; }

function detectIda(opts: DetectOptions): Detection {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const base: Detection = { id: 'ida', name: TOOL_META.ida.name, available: false };
  for (const { root, via } of idaRoots(env, platform)) {
    for (const n of ['idat', 'idat64']) {
      const p = join(root, platform === 'win32' ? `${n}.exe` : n);
      if (isExecutable(p, platform)) {
        const ver = idaVersionFromPath(root);
        const hexrays = ['hexx64', 'hexarm64', 'hexrays'].some((x) => {
          try { return readdirSync(join(root, 'plugins')).some((f) => f.startsWith(x)); } catch { return false; }
        });
        return { ...base, available: true, path: p, via, ...(ver ? { version: ver } : {}), details: { root, batchBinary: n, hexrays, idalib: isDir(join(root, 'idalib')) } };
      }
    }
  }
  return base;
}

function detectBinja(opts: DetectOptions): Detection {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const h = home(env);
  const base: Detection = { id: 'binja', name: TOOL_META.binja.name, available: false };
  const roots: { root: string; via: Detection['via'] }[] = [];
  if (env.REVLENS_BINJA_PATH) roots.push({ root: env.REVLENS_BINJA_PATH, via: 'override' });
  if (env.BN_INSTALL_DIR) roots.push({ root: env.BN_INSTALL_DIR, via: 'env' });
  const pats = platform === 'win32'
    ? [join(env.ProgramFiles || 'C:/Program Files', 'Vector35', 'BinaryNinja'), join(env.LOCALAPPDATA || join(h, 'AppData', 'Local'), 'Vector35', 'BinaryNinja')]
    : platform === 'darwin' ? ['/Applications/Binary Ninja*.app/Contents/MacOS'] : ['/opt/binaryninja', join(h, 'binaryninja')];
  for (const p of pats) for (const r of expandPattern(p)) roots.push({ root: r, via: 'dir' });
  for (const { root, via } of roots) {
    const py = platform === 'darwin' ? join(root, '..', 'Resources', 'python') : join(root, 'python');
    if (isDir(join(py, 'binaryninja'))) {
      return { ...base, available: true, path: root, via, details: { pythonPath: py } };
    }
  }
  return base;
}

// ---------- Cutter ----------

/** Version from a Cutter release name: Cutter-v2.5.0-Linux-x86_64.AppImage, Cutter-v2.5.0-Windows-x86_64, cutter-2.3.4. */
export function cutterVersionFromName(name: string): string | undefined {
  return /cutter[-_ ]?v?(\d+\.\d+\.\d+(?:-rc\d+)?)/i.exec(name)?.[1];
}

/** CFBundleShortVersionString (or CFBundleVersion) from an XML Info.plist. */
export function plistVersion(xml: string): string | undefined {
  const t = xml.slice(0, 256 * 1024);
  return /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]{1,64})<\/string>/.exec(t)?.[1]
    ?? /<key>CFBundleVersion<\/key>\s*<string>([^<]{1,64})<\/string>/.exec(t)?.[1];
}

/** Newest <release version="..."> in an AppStream metainfo file (distro and Flatpak installs). */
export function appdataVersion(xml: string): string | undefined {
  return /<release\b[^>]*\bversion="([0-9][^"]{0,63})"/.exec(xml.slice(0, 512 * 1024))?.[1];
}

function readText(p: string, max = 512 * 1024): string | undefined {
  let fd: number | undefined;
  try {
    // one descriptor for the checks and the read
    fd = openSync(p, 'r');
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > max) return undefined;
    return readFileSync(fd, 'utf8');
  } catch { return undefined; } finally { if (fd !== undefined) closeSync(fd); }
}

/**
 * Find Cutter without starting it (it is a GUI): override, PATH, AppImage downloads, the macOS app
 * bundle, the Windows release folder or Scoop, distro packages and Flatpak. The version comes
 * from the release name, Info.plist or AppStream metadata. A rizin shipped next to Cutter (the
 * Windows release has rizin.exe beside cutter.exe) is reported as details.bundledRizin.
 */
export function detectCutter(opts: DetectOptions = {}): Detection {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const h = home(env);
  const base: Detection = { id: 'cutter', name: TOOL_META.cutter.name, available: false };
  const done = (path: string, via: Detection['via'], kind: string, version: string | undefined, extra: Record<string, string | boolean | null> = {}): Detection => {
    const dir = dirname(path);
    const rz = ['rizin', 'rizin.exe'].map((n) => join(dir, n)).find((p) => isFile(p)) ?? null;
    return { ...base, available: true, path, via, ...(version ? { version } : {}), details: { kind, bundledRizin: rz, ...extra } };
  };
  const appimageIn = (dir: string): string | undefined => {
    let names: string[] = [];
    try { names = readdirSync(dir); } catch { return undefined; }
    const hits = names.filter((n) => /^cutter.*\.appimage$/i.test(n)).sort().reverse();
    for (const n of hits) { const p = join(dir, n); if (isFile(p)) return p; }
    return undefined;
  };
  const ov = env.REVLENS_CUTTER_PATH;
  if (ov && isFile(ov)) return done(ov, 'override', /\.appimage$/i.test(ov) ? 'appimage' : 'binary', cutterVersionFromName(ov) ?? cutterVersionFromName(dirname(ov)));
  if (platform === 'darwin') {
    for (const app of ['/Applications/Cutter.app', join(h, 'Applications', 'Cutter.app')]) {
      const exe = ['cutter', 'Cutter'].map((n) => join(app, 'Contents', 'MacOS', n)).find((p) => isFile(p));
      if (!exe) continue;
      const plist = readText(join(app, 'Contents', 'Info.plist'));
      return done(exe, 'dir', 'app-bundle', plist ? plistVersion(plist) : undefined);
    }
  }
  const onPath = findExecutable(['cutter', 'Cutter'], [], opts);
  if (onPath) {
    let real = onPath.path;
    try { real = realpathSync(onPath.path); } catch { /* keep */ }
    let version = cutterVersionFromName(real) ?? cutterVersionFromName(dirname(real));
    if (!version && platform === 'linux') {
      for (const m of ['/usr/share/metainfo/re.rizin.cutter.appdata.xml', '/usr/share/metainfo/re.rizin.cutter.metainfo.xml', '/usr/local/share/metainfo/re.rizin.cutter.appdata.xml']) {
        const x = readText(m);
        if (x) { version = appdataVersion(x); break; }
      }
    }
    return done(onPath.path, 'path', /\.appimage$/i.test(real) ? 'appimage' : 'binary', version);
  }
  if (platform === 'win32') {
    const pf = env.ProgramFiles || 'C:/Program Files';
    const pats = [join(h, 'scoop', 'apps', 'cutter', 'current'), join(pf, 'Cutter*'), 'C:/Cutter*', 'C:/tools/cutter*', join(h, 'Downloads', 'Cutter*'), join(env.LOCALAPPDATA || join(h, 'AppData', 'Local'), 'Programs', 'Cutter*')];
    for (const pat of pats) {
      for (const d of expandPattern(pat)) {
        for (const sub of [d, ...expandPattern(join(d, 'Cutter*'))]) {
          const exe = join(sub, 'cutter.exe');
          if (isFile(exe)) {
            let real = sub;
            try { real = realpathSync(sub); } catch { /* keep */ }
            return done(exe, 'dir', 'binary', cutterVersionFromName(real) ?? cutterVersionFromName(sub));
          }
        }
      }
    }
    return base;
  }
  // Linux and other POSIX: AppImage downloads, /opt, then Flatpak.
  for (const d of [join(h, 'Applications'), join(h, 'Downloads'), join(h, '.local', 'bin'), join(h, 'bin'), join(h, 'Apps'), '/opt', ...expandPattern('/opt/cutter*')]) {
    const p = appimageIn(d);
    if (p) return done(p, 'dir', 'appimage', cutterVersionFromName(p));
    const exe = join(d, 'cutter');
    if (d.includes('cutter') && isFile(exe)) return done(exe, 'dir', 'binary', cutterVersionFromName(d));
  }
  for (const root of [join(h, '.local', 'share', 'flatpak'), '/var/lib/flatpak']) {
    const app = join(root, 'app', 're.rizin.cutter', 'current', 'active');
    if (!isDir(app)) continue;
    const x = readText(join(app, 'files', 'share', 'metainfo', 're.rizin.cutter.appdata.xml')) ?? readText(join(app, 'files', 'share', 'metainfo', 're.rizin.cutter.metainfo.xml'));
    return { ...base, available: true, path: app, via: 'dir', ...(x && appdataVersion(x) ? { version: appdataVersion(x)! } : {}), details: { kind: 'flatpak', launch: 'flatpak run re.rizin.cutter', bundledRizin: null } };
  }
  return base;
}

async function detectGeneric(id: ToolId, opts: DetectOptions): Promise<Detection> {
  const env = opts.env ?? process.env;
  const platform = opts.platform ?? process.platform;
  const base: Detection = { id, name: TOOL_META[id].name, available: false };
  let found: { path: string; via: Detection['via'] } | undefined;
  const ov = env[overrideVar(id)];
  if (ov && isFile(ov)) found = { path: ov, via: 'override' };
  if (!found && id === 'jadx' && env.JADX_HOME) {
    const p = join(env.JADX_HOME, 'bin', platform === 'win32' ? 'jadx.bat' : 'jadx');
    if (isFile(p)) found = { path: p, via: 'env' };
  }
  if (!found && id === 'dotnet' && env.DOTNET_ROOT) {
    const p = join(env.DOTNET_ROOT, platform === 'win32' ? 'dotnet.exe' : 'dotnet');
    if (isFile(p)) found = { path: p, via: 'env' };
  }
  if (!found) found = findExecutable(BINARIES[id] ?? [id], wellKnownDirs(id, platform, env), opts);
  if (!found && id === 'apktool' && env.APKTOOL_JAR && isFile(env.APKTOOL_JAR)) found = { path: env.APKTOOL_JAR, via: 'env' };
  if (!found) return base;
  const det: Detection = { ...base, available: true, path: found.path, via: found.via };
  if (!opts.skipVersion && !NO_VERSION_PROBE.has(id) && !found.path.endsWith('.jar')) det.version = await probeVersion(id, found.path, env);
  if (id === 'frida') {
    const dir = dirname(found.path);
    const comp = (n: string) => findExecutable([n], [dir], opts)?.path ?? null;
    det.details = { fridaPs: comp('frida-ps'), fridaLsDevices: comp('frida-ls-devices'), fridaTrace: comp('frida-trace') };
  }
  if (id === 'radare2' || id === 'rizin') det.details = await decompilerPlugin(id, found.path, env, opts.skipVersion === true);
  return det;
}

/** Look for r2ghidra or rz-ghidra in the plugin folders the tool reports. */
async function decompilerPlugin(id: 'radare2' | 'rizin', exe: string, env: NodeJS.ProcessEnv, skip: boolean): Promise<Record<string, string | boolean | null>> {
  if (skip) return { ghidraPlugin: null };
  const r = await runTool(exe, ['-H'], { timeoutMs: 15_000, maxOutputBytes: 64 * 1024, env });
  const dirs: string[] = [];
  for (const line of r.stdout.split(/\r?\n/)) {
    const m = /^(R2|RZ)_(USER_PLUGINS|LIBR_PLUGINS|LIB_PLUGINS|EXTRA_PLUGINS|PLUGINS)=(.+)$/.exec(line.trim());
    if (m) dirs.push(m[3]!.trim().replace(/^"|"$/g, ''));
  }
  for (const d of dirs) {
    try {
      const hit = readdirSync(d).find((f) => /^core_ghidra\.(so|dylib|dll)$/.test(f));
      if (hit) return { ghidraPlugin: true, pluginPath: join(d, hit) };
    } catch { /* missing dir */ }
  }
  return { ghidraPlugin: false };
}

let cache: Map<ToolId, Detection> | undefined;

/** REVLENS_BRIDGES_DISABLE=all or a comma list of tool ids hides tools, for tests and locked down hosts. */
export function disabledTools(env: NodeJS.ProcessEnv = process.env): Set<string> {
  const v = (env.REVLENS_BRIDGES_DISABLE ?? '').trim().toLowerCase();
  if (!v) return new Set();
  return new Set(v === 'all' || v === '1' ? TOOL_IDS : v.split(',').map((x) => x.trim()).filter(Boolean));
}

function disabled(id: ToolId): Detection {
  return { id, name: TOOL_META[id].name, available: false, problems: ['disabled by REVLENS_BRIDGES_DISABLE'] };
}

/** Detect every tool (cached for the life of the process unless `refresh` is set). */
export async function detectAll(opts: DetectOptions = {}): Promise<Map<ToolId, Detection>> {
  if (cache && !opts.refresh && !opts.env) return cache;
  const out = new Map<ToolId, Detection>();
  const off = disabledTools(opts.env ?? process.env);
  const java = off.has('java') ? disabled('java') : await detectJava(opts);
  out.set('java', java);
  const rest = TOOL_IDS.filter((id) => id !== 'java');
  const results = await Promise.all(rest.map(async (id) => {
    if (off.has(id)) return disabled(id);
    if (id === 'ghidra') return detectGhidra(opts, java);
    if (id === 'ida') return detectIda(opts);
    if (id === 'binja') return detectBinja(opts);
    if (id === 'cutter') return detectCutter(opts);
    return detectGeneric(id, opts);
  }));
  for (const d of results) out.set(d.id, d);
  if (!opts.env) cache = out;
  return out;
}

/** Detect one tool. */
export async function detect(id: ToolId, opts: DetectOptions = {}): Promise<Detection> {
  if (cache && !opts.refresh && !opts.env) return cache.get(id)!;
  if (disabledTools(opts.env ?? process.env).has(id)) return disabled(id);
  if (id === 'java') return detectJava(opts);
  if (id === 'ghidra') return detectGhidra(opts, await detectJava(opts));
  if (id === 'ida') return detectIda(opts);
  if (id === 'binja') return detectBinja(opts);
  if (id === 'cutter') return detectCutter(opts);
  return detectGeneric(id, opts);
}

/** Forget cached detections, for example after installing a tool. */
export function clearDetectionCache(): void {
  cache = undefined;
}
