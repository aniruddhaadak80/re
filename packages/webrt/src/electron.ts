// Electron security review: version detection, fuses, BrowserWindow webPreferences, preload bridges,
// IPC channels, shell.openExternal, custom protocols, auto-update feeds and risky command line switches.
import type { Finding, Severity } from '@revlens/core';
import { parseJs, walk, staticString, templateShape, memberName, propKey, t } from './js/ast.js';
import { readAsar, readAsarFile, type AsarArchive } from './asar.js';
import { decodeUtf8, decodeLatin1 } from './util.js';

export const FUSE_SENTINEL = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX';
export const FUSE_NAMES = ['RunAsNode', 'EnableCookieEncryption', 'EnableNodeOptionsEnvironmentVariable', 'EnableNodeCliInspectArguments', 'EnableEmbeddedAsarIntegrityValidation', 'OnlyLoadAppFromAsar', 'LoadBrowserProcessSpecificV8Snapshot', 'GrantFileProtocolExtraPrivileges', 'WasmTrapHandlers'];

export interface FuseWire { offset: number; version: number; fuses: Record<string, 'enabled' | 'disabled' | 'removed' | 'unknown'> }

export interface WindowPrefs { file: string; line: number; ctor: string; variable?: string; prefs: Record<string, boolean | string>; loads: string[] }

export interface ElectronAudit {
  electronVersion?: string;
  versionSource?: string;
  chromeVersion?: string;
  app?: { name?: string; version?: string; main?: string };
  filesScanned: number;
  windows: WindowPrefs[];
  ipc: { main: { channel: string; method: string; file: string; line: number }[]; renderer: { channel: string; method: string; file: string; line: number }[] };
  exposed: { name: string; keys: string[]; file: string; line: number }[];
  openExternal: { file: string; line: number; argument: string; literal: boolean }[];
  protocols: { scheme: string; method: string; file: string; line: number }[];
  updateUrls: { url: string; source: string }[];
  switches: { name: string; file: string; line: number }[];
  fuses?: FuseWire;
  findings: Finding[];
}

const ID = 'webrt.electron';

function finding(id: string, title: string, severity: Severity, detail: string, evidence: { path?: string; offset?: number; snippet?: string }[], tags: string[] = []): Finding {
  return { id: `${ID}.${id}`, analyzer: ID, title, severity, detail, evidence, tags: ['electron', ...tags] };
}

/** Read the fuse wire from an Electron executable (Electron 12 and later). */
export function readFuses(bin: Uint8Array): FuseWire | undefined {
  const sent = new TextEncoder().encode(FUSE_SENTINEL);
  const first = sent[0] as number;
  outer: for (let i = bin.indexOf(first); i >= 0 && i + sent.length + 2 <= bin.length; i = bin.indexOf(first, i + 1)) {
    for (let j = 1; j < sent.length; j++) if (bin[i + j] !== sent[j]) continue outer;
    const p = i + sent.length;
    const version = bin[p] as number;
    const len = Math.min(bin[p + 1] as number, bin.length - p - 2);
    const fuses: FuseWire['fuses'] = {};
    for (let k = 0; k < len; k++) {
      const b = bin[p + 2 + k];
      const name = FUSE_NAMES[k] ?? `Fuse${k}`;
      fuses[name] = b === 0x31 ? 'enabled' : b === 0x30 ? 'disabled' : b === 0x72 ? 'removed' : 'unknown';
    }
    return { offset: i, version: version >= 0x30 ? version - 0x30 : version, fuses };
  }
  return undefined;
}

/** Electron and Chrome versions from strings inside an Electron executable or framework. */
export function detectElectronVersionInBinary(bin: Uint8Array): { electron?: string; chrome?: string } {
  const out: { electron?: string; chrome?: string } = {};
  const CH = 8 * 1024 * 1024;
  for (let off = 0; off < bin.length && !(out.electron && out.chrome); off += CH - 64) {
    const s = decodeLatin1(bin.subarray(off, Math.min(bin.length, off + CH)));
    if (!out.electron) { const m = /Electron\/(\d{1,3}\.\d{1,3}\.\d{1,3}(?:-[\w.]{1,20})?)/.exec(s); if (m) out.electron = m[1]; }
    if (!out.chrome) { const m = /Chrome\/(\d{2,3}\.\d+\.\d+\.\d+)/.exec(s); if (m) out.chrome = m[1]; }
  }
  return out;
}

function boolOrDyn(n: t.Node): boolean | string {
  if (n.type === 'BooleanLiteral') return n.value;
  if (n.type === 'UnaryExpression' && n.operator === '!' && n.argument.type === 'NumericLiteral') return !n.argument.value;
  const s = staticString(n);
  if (s !== undefined) return s;
  return 'dynamic';
}

function majorOf(v?: string): number | undefined {
  const m = v ? /^(\d+)/.exec(v.replace(/^[\^~>=<v ]+/, '')) : null;
  return m ? Number(m[1]) : undefined;
}

export interface ElectronSources {
  /** path -> JavaScript source for main, preload and renderer files */
  files: { path: string; code: string }[];
  packageJson?: Record<string, unknown>;
  /** optional Electron executable bytes for version and fuses */
  binary?: Uint8Array;
}

/** Audit an Electron app from its JavaScript files, package.json and optionally the Electron binary. */
export function auditElectron(src: ElectronSources): ElectronAudit {
  const a: ElectronAudit = { filesScanned: 0, windows: [], ipc: { main: [], renderer: [] }, exposed: [], openExternal: [], protocols: [], updateUrls: [], switches: [], findings: [] };
  const pkg = src.packageJson ?? {};
  a.app = { name: typeof pkg.name === 'string' ? pkg.name : undefined, version: typeof pkg.version === 'string' ? pkg.version : undefined, main: typeof pkg.main === 'string' ? pkg.main : undefined };
  const deps = { ...(pkg.dependencies as Record<string, string> | undefined), ...(pkg.devDependencies as Record<string, string> | undefined) };
  if (deps.electron) { a.electronVersion = deps.electron.replace(/^[\^~>=<v ]+/, ''); a.versionSource = 'package.json'; }
  if (src.binary) {
    const v = detectElectronVersionInBinary(src.binary);
    if (v.electron) { a.electronVersion = v.electron; a.versionSource = 'binary'; }
    if (v.chrome) a.chromeVersion = v.chrome;
    a.fuses = readFuses(src.binary);
  }
  const build = pkg.build as Record<string, unknown> | undefined;
  const pubs = build?.publish ? (Array.isArray(build.publish) ? build.publish : [build.publish]) : [];
  for (const p of pubs as Record<string, unknown>[]) if (p && typeof p.url === 'string') a.updateUrls.push({ url: p.url, source: 'package.json build.publish' });
  const major = majorOf(a.electronVersion);

  for (const f of src.files.slice(0, 5000)) {
    let ast: t.File;
    try { ast = parseJs(f.code).ast; } catch { continue; }
    a.filesScanned++;
    const loads: { line: number; url: string; target?: string }[] = [];
    walk(ast, ({ node, parent }) => {
      if (node.type !== 'NewExpression' && node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression') return;
      const name = memberName(node.callee as t.Node) ?? '';
      const last = name.split('.').pop() ?? '';
      const args = node.arguments as t.Node[];
      const line = node.loc?.start.line ?? 0;
      if (node.type === 'NewExpression' && /(?:^|\.)(BrowserWindow|BrowserView|WebContentsView)$/.test(name)) {
        const prefs: Record<string, boolean | string> = {};
        const o = args[0];
        if (o?.type === 'ObjectExpression') {
          for (const p of o.properties) {
            if (p.type !== 'ObjectProperty' || propKey(p) !== 'webPreferences') continue;
            if (p.value.type === 'ObjectExpression') {
              for (const q of p.value.properties) {
                if (q.type !== 'ObjectProperty') continue;
                const k = propKey(q);
                if (k) prefs[k] = k === 'preload' ? (templateShape(q.value) ?? memberName(q.value) ?? 'dynamic') : boolOrDyn(q.value);
              }
            } else prefs.__dynamic = true;
          }
        }
        const variable = parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier' ? parent.id.name : parent?.type === 'AssignmentExpression' ? memberName(parent.left as t.Node) : undefined;
        a.windows.push({ file: f.path, line, ctor: last, variable, prefs, loads: [] });
        return;
      }
      if ((last === 'loadURL' || last === 'loadFile') && args[0]) {
        const u = templateShape(args[0]) ?? 'dynamic';
        const callee = node.callee as t.Node;
        let target = callee.type === 'MemberExpression' ? memberName(callee.object) : undefined;
        if (target?.endsWith('.webContents')) target = target.slice(0, -'.webContents'.length);
        loads.push({ line, url: u, target });
      }
      if (/^ipcMain\.(handle|handleOnce|on|once|removeHandler)$/.test(name) || /\.ipc\.(handle|on)$/.test(name)) {
        a.ipc.main.push({ channel: staticString(args[0]) ?? 'dynamic', method: last, file: f.path, line });
      }
      if (/^ipcRenderer\.(send|sendSync|invoke|on|once|postMessage|sendToHost)$/.test(name)) {
        a.ipc.renderer.push({ channel: staticString(args[0]) ?? 'dynamic', method: last, file: f.path, line });
      }
      if (name === 'contextBridge.exposeInMainWorld' || name === 'contextBridge.exposeInIsolatedWorld') {
        const nameArg = name.endsWith('IsolatedWorld') ? args[1] : args[0];
        const obj = name.endsWith('IsolatedWorld') ? args[2] : args[1];
        const keys: string[] = [];
        let rawIpc = false, passthrough = false;
        if (obj?.type === 'ObjectExpression') {
          for (const p of obj.properties) {
            if (p.type === 'SpreadElement') { keys.push('...spread'); continue; }
            const k = propKey(p) ?? 'computed';
            keys.push(k);
            const v = p.type === 'ObjectProperty' ? p.value : p;
            if (v.type === 'Identifier' && /^(ipcRenderer|require|process|shell|fs|child_process)$/.test(v.name)) rawIpc = true;
            if ((v.type === 'ArrowFunctionExpression' || v.type === 'FunctionExpression' || v.type === 'ObjectMethod') && v.params[0]?.type === 'Identifier') {
              const ch = (v.params[0] as t.Identifier).name;
              walk(v.body, ({ node: m }) => {
                if (m.type === 'CallExpression' && /^ipcRenderer\.(send|invoke|sendSync|on)$/.test(memberName(m.callee) ?? '') && m.arguments[0]?.type === 'Identifier' && m.arguments[0].name === ch) passthrough = true;
              });
            }
          }
        } else if (obj?.type === 'Identifier') { keys.push(`(${obj.name})`); if (obj.name === 'ipcRenderer') rawIpc = true; }
        const exposedName = staticString(nameArg) ?? 'dynamic';
        a.exposed.push({ name: exposedName, keys, file: f.path, line });
        if (rawIpc) a.findings.push(finding('bridge-raw', `Preload exposes a raw Node or IPC object as window.${exposedName}`, 'high', 'contextBridge hands the page a raw ipcRenderer, require, process, fs or shell object. Any script in the page (including injected ones) can then send arbitrary IPC messages or reach Node APIs. Expose narrow functions with fixed channels instead.', [{ path: f.path, offset: node.start ?? undefined, snippet: `line ${line}` }], ['contextBridge']));
        if (passthrough) a.findings.push(finding('bridge-passthrough', `Preload bridge window.${exposedName} forwards caller-chosen IPC channels`, 'high', 'A bridged function passes its first argument straight through as the IPC channel name, so the page can reach every ipcMain handler. Allow-list channels in the preload.', [{ path: f.path, snippet: `line ${line}` }], ['contextBridge', 'ipc']));
      }
      if (name === 'shell.openExternal' || name.endsWith('.shell.openExternal')) {
        const lit = staticString(args[0]);
        a.openExternal.push({ file: f.path, line, argument: lit ?? (args[0] ? (memberName(args[0]) ?? templateShape(args[0]) ?? args[0].type) : 'none'), literal: lit !== undefined });
        if (lit === undefined) a.findings.push(finding('open-external', 'shell.openExternal called with a non-constant URL', 'medium', 'shell.openExternal opens any URL scheme with the OS handler (file:, smb:, custom protocols). If the URL comes from the page, an IPC message or a window.open handler, an attacker can launch local programs. Validate the scheme (https only) and host before calling it.', [{ path: f.path, offset: node.start ?? undefined, snippet: `line ${line}` }], ['shell']));
      }
      if (/^protocol\.(registerFileProtocol|registerHttpProtocol|registerStringProtocol|registerBufferProtocol|registerStreamProtocol|interceptFileProtocol|interceptHttpProtocol|handle)$/.test(name) || /\.protocol\.(handle|register\w*Protocol)$/.test(name)) {
        a.protocols.push({ scheme: staticString(args[0]) ?? 'dynamic', method: last, file: f.path, line });
      }
      if (name === 'protocol.registerSchemesAsPrivileged' && args[0]?.type === 'ArrayExpression') {
        for (const el of args[0].elements) {
          if (el?.type !== 'ObjectExpression') continue;
          for (const p of el.properties) if (p.type === 'ObjectProperty' && propKey(p) === 'scheme') a.protocols.push({ scheme: staticString(p.value) ?? 'dynamic', method: 'registerSchemesAsPrivileged', file: f.path, line });
        }
      }
      if (/(?:^|\.)autoUpdater\.setFeedURL$/.test(name) && args[0]) {
        let u = staticString(args[0]);
        if (u === undefined && args[0].type === 'ObjectExpression') for (const p of args[0].properties) if (p.type === 'ObjectProperty' && propKey(p) === 'url') u = staticString(p.value);
        if (u) a.updateUrls.push({ url: u, source: `${f.path}:${line}` });
      }
      if (/commandLine\.appendSwitch$/.test(name)) {
        const sw = staticString(args[0]);
        if (sw) {
          a.switches.push({ name: sw, file: f.path, line });
          if (/^(ignore-certificate-errors|disable-web-security|allow-running-insecure-content|no-sandbox|disable-site-isolation-trials|remote-debugging-port|inspect)$/.test(sw)) a.findings.push(finding('switch', `Risky Chromium switch --${sw}`, sw === 'remote-debugging-port' || sw === 'inspect' ? 'high' : 'high', `The app turns on --${sw} at startup, which removes a browser security boundary for every window.`, [{ path: f.path, snippet: `line ${line}` }], ['switch']));
        }
      }
      if (last === 'on' && staticString(args[0]) === 'certificate-error') {
        const h = args[1];
        if (h && (h.type === 'ArrowFunctionExpression' || h.type === 'FunctionExpression')) {
          const cbName = h.params[h.params.length - 1];
          let trusts = false;
          walk(h.body, ({ node: m }) => { if (m.type === 'CallExpression' && m.callee.type === 'Identifier' && cbName?.type === 'Identifier' && m.callee.name === cbName.name && m.arguments[0]?.type === 'BooleanLiteral' && m.arguments[0].value) trusts = true; });
          if (trusts) a.findings.push(finding('cert-bypass', 'certificate-error handler accepts invalid certificates', 'high', 'The certificate-error handler calls back with true, so TLS errors are ignored and traffic can be intercepted.', [{ path: f.path, snippet: `line ${line}` }], ['tls']));
        }
      }
    });
    // attach loads in the same file to windows created there
    const here = a.windows.filter((w) => w.file === f.path);
    for (const w of here) w.loads = loads.filter((l) => (w.variable ? l.target === w.variable : here.length === 1)).map((l) => l.url).slice(0, 20);
  }

  // window findings
  for (const w of a.windows) {
    const ev = [{ path: w.file, snippet: `line ${w.line}: new ${w.ctor}(${JSON.stringify(w.prefs)})` }];
    const remote = w.loads.some((u) => /^https?:/i.test(u));
    const p = w.prefs;
    if (p.nodeIntegration === true) a.findings.push(finding('node-integration', `nodeIntegration enabled in ${w.ctor}${remote ? ' that loads remote content' : ''}`, remote ? 'critical' : 'high', 'Pages in this window can call require() and reach Node. Any XSS becomes remote code execution on the user machine.', ev, ['webPreferences']));
    if (p.nodeIntegrationInWorker === true || p.nodeIntegrationInSubFrames === true) a.findings.push(finding('node-integration-sub', 'Node integration enabled in workers or subframes', 'high', 'Workers or iframes get Node access, which widens the XSS to RCE path.', ev, ['webPreferences']));
    if (p.contextIsolation === false || (p.contextIsolation === undefined && major !== undefined && major < 12)) a.findings.push(finding('context-isolation', `contextIsolation ${p.contextIsolation === false ? 'disabled' : 'not set (off by default before Electron 12)'}`, 'high', 'Without context isolation the preload script and the page share one JavaScript world, so the page can tamper with preload globals and reach privileged APIs.', ev, ['webPreferences']));
    if (p.sandbox === false || (p.sandbox === undefined && major !== undefined && major < 20)) a.findings.push(finding('sandbox', `Renderer sandbox ${p.sandbox === false ? 'disabled' : 'not set (off by default before Electron 20)'}`, 'medium', 'The renderer runs without the Chromium sandbox, so a renderer exploit gets the full user privileges.', ev, ['webPreferences']));
    if (p.webSecurity === false) a.findings.push(finding('web-security', 'webSecurity disabled', 'high', 'Same-origin policy is off for this window: any page can read any origin and load file: URLs.', ev, ['webPreferences']));
    if (p.allowRunningInsecureContent === true) a.findings.push(finding('insecure-content', 'allowRunningInsecureContent enabled', 'high', 'HTTPS pages may run scripts fetched over plain HTTP, which a network attacker can replace.', ev, ['webPreferences']));
    if (p.enableRemoteModule === true) a.findings.push(finding('remote-module', 'Deprecated remote module enabled', 'medium', 'The remote module lets renderers call main-process objects directly. It was removed in Electron 14 and is a common privilege escalation path.', ev, ['webPreferences']));
    if (p.experimentalFeatures === true || p.enableBlinkFeatures) a.findings.push(finding('experimental', 'Experimental Blink features enabled', 'low', 'Experimental web platform features are less tested and may weaken security.', ev, ['webPreferences']));
    if (p.webviewTag === true) a.findings.push(finding('webview', '<webview> tag enabled', 'medium', 'Pages can embed <webview> guests with their own preferences. Lock them down with will-attach-webview.', ev, ['webPreferences']));
    for (const u of w.loads) if (/^http:\/\//i.test(u) && !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(u)) a.findings.push(finding('http-load', `Window loads content over plain HTTP: ${u}`, 'medium', 'Content loaded over HTTP can be replaced by a network attacker.', [{ path: w.file, snippet: u }], ['transport']));
  }
  for (const u of a.updateUrls) if (/^http:\/\//i.test(u.url)) a.findings.push(finding('update-http', `Auto-update feed over plain HTTP: ${u.url}`, 'high', 'Update metadata fetched over HTTP can be swapped by a network attacker to push a malicious update.', [{ snippet: u.url, path: u.source }], ['update']));
  if (a.ipc.main.length) a.findings.push(finding('ipc-surface', `${a.ipc.main.length} IPC handlers in the main process`, 'info', `Main-process IPC channels: ${[...new Set(a.ipc.main.map((x) => x.channel))].slice(0, 40).join(', ')}. Each is reachable from any renderer that can send IPC; check that handlers validate sender and arguments.`, a.ipc.main.slice(0, 20).map((x) => ({ path: x.file, snippet: `line ${x.line}: ${x.method}('${x.channel}')` })), ['ipc']));
  if (a.fuses) {
    const fz = a.fuses.fuses;
    if (fz.RunAsNode === 'enabled') a.findings.push(finding('fuse-runasnode', 'RunAsNode fuse enabled', 'medium', 'ELECTRON_RUN_AS_NODE turns the signed app binary into a general Node interpreter, a known living-off-the-land technique.', [{ offset: a.fuses.offset, snippet: 'fuse wire' }], ['fuses']));
    if (fz.EnableNodeOptionsEnvironmentVariable === 'enabled') a.findings.push(finding('fuse-nodeoptions', 'NODE_OPTIONS fuse enabled', 'low', 'NODE_OPTIONS can inject code into the app at launch.', [{ offset: a.fuses.offset }], ['fuses']));
    if (fz.EnableNodeCliInspectArguments === 'enabled') a.findings.push(finding('fuse-inspect', 'Node inspector CLI arguments fuse enabled', 'low', '--inspect arguments can attach a debugger to the main process.', [{ offset: a.fuses.offset }], ['fuses']));
    if (fz.EnableEmbeddedAsarIntegrityValidation !== 'enabled') a.findings.push(finding('fuse-integrity', 'ASAR integrity validation fuse not enabled', 'low', 'The app does not verify app.asar against an embedded hash, so the archive can be modified after install.', [{ offset: a.fuses.offset }], ['fuses']));
  }
  if (major !== undefined && major < 30) a.findings.push(finding('outdated', `Electron ${a.electronVersion} is out of support`, 'medium', 'Electron supports only the latest three major versions. Older versions ship an old Chromium with known exploitable bugs.', [{ snippet: `${a.versionSource}: ${a.electronVersion}` }], ['version']));
  return a;
}

/** Collect the JavaScript files and package.json from an ASAR archive and audit them. */
export function auditAsar(bytes: Uint8Array, opts: { binary?: Uint8Array; maxFiles?: number; maxFileBytes?: number } = {}): ElectronAudit & { archive: Pick<AsarArchive, 'files' | 'dirs' | 'unpackedFiles' | 'totalSize'> } {
  const arc = readAsar(bytes);
  const files: { path: string; code: string }[] = [];
  let pkg: Record<string, unknown> | undefined;
  const maxBytes = opts.maxFileBytes ?? 4 * 1024 * 1024;
  for (const e of arc.entries) {
    if (e.type !== 'file' || e.unpacked) continue;
    if (e.path === 'package.json') {
      try { pkg = JSON.parse(decodeUtf8(readAsarFile(bytes, arc, e.path) ?? new Uint8Array())) as Record<string, unknown>; } catch { /* bad json */ }
      continue;
    }
    if (!/\.(?:c|m)?js$/.test(e.path) || e.size > maxBytes || /(^|\/)node_modules\//.test(e.path)) continue;
    if (files.length >= (opts.maxFiles ?? 2000)) break;
    const b = readAsarFile(bytes, arc, e.path);
    if (b) files.push({ path: e.path, code: decodeUtf8(b) });
  }
  const audit = auditElectron({ files, packageJson: pkg, binary: opts.binary });
  return { ...audit, archive: { files: arc.files, dirs: arc.dirs, unpackedFiles: arc.unpackedFiles, totalSize: arc.totalSize } };
}
