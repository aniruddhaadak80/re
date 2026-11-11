// Frida hook templates. Original code, MIT licensed. Each template turns a small typed
// parameter object into a self-contained Frida script. Parameters are embedded with
// JSON.stringify only, never pasted as code. Every script reports through
// console.log lines that start with "@@revlens " followed by one JSON object.
import { FRIDA_EVENT_PREFIX } from './parsers/frida.js';

export type HookTemplateId = 'module-list' | 'trace-native-export' | 'java-method-log' | 'ssl-pinning-bypass' | 'electron-net-observe';

export interface HookTemplate {
  id: HookTemplateId;
  title: string;
  description: string;
  params: Record<string, { type: 'string' | 'number' | 'boolean'; description: string; optional?: boolean }>;
  /** platforms the hooks target */
  targets: string[];
}

export const HOOK_TEMPLATES: HookTemplate[] = [
  {
    id: 'module-list', title: 'List loaded modules',
    description: 'Reports the process id, architecture, platform and every loaded module with base, size and path. Read only.',
    params: {}, targets: ['native'],
  },
  {
    id: 'trace-native-export', title: 'Trace a native export',
    description: 'Attaches to an exported function and logs each call with its first arguments, the return value and optionally a backtrace.',
    params: {
      export: { type: 'string', description: 'export name, for example open or SSL_write' },
      module: { type: 'string', description: 'module name, for example libc.so.6; omit to search all modules', optional: true },
      args: { type: 'number', description: 'how many arguments to log, 0 to 8 (default 4)', optional: true },
      backtrace: { type: 'boolean', description: 'log a short backtrace for each call', optional: true },
    },
    targets: ['native'],
  },
  {
    id: 'java-method-log', title: 'Log Java method calls (Android)',
    description: 'Hooks every overload of a Java method and logs arguments and return values as strings.',
    params: {
      className: { type: 'string', description: 'fully qualified class, for example okhttp3.OkHttpClient' },
      method: { type: 'string', description: 'method name, $init for constructors' },
    },
    targets: ['android'],
  },
  {
    id: 'ssl-pinning-bypass', title: 'Disable certificate pinning in your own Android app (testing only)',
    description: 'For testing apps you own or are authorized to test. Swaps in a trust-all TrustManager for SSLContext.init and turns OkHttp3 CertificatePinner checks into no-ops, so traffic can be inspected through your proxy. Logs each bypass.',
    params: {},
    targets: ['android'],
  },
  {
    id: 'electron-net-observe', title: 'Observe network connections (Electron and other desktop apps)',
    description: 'Logs DNS lookups (getaddrinfo, GetAddrInfoW) and outgoing TCP connects with host and port, which is how an Electron app\'s fetch and XHR traffic shows up at the native level. It does not decrypt TLS; for request bodies use the Electron inspector.',
    params: {},
    targets: ['native'],
  },
];

export class HookParamError extends Error {}

const IDENT = /^[A-Za-z_$?][\w$.@?+-]{0,255}$/;

function reqString(p: Record<string, unknown>, k: string, re: RegExp): string {
  const v = p[k];
  if (typeof v !== 'string' || !re.test(v)) throw new HookParamError(`parameter "${k}" is missing or has characters that are not allowed`);
  return v;
}

function prelude(maxEvents: number): string {
  return `'use strict';
const __rl_t0 = Date.now();
let __rl_n = 0;
const __rl_max = ${JSON.stringify(maxEvents)};
function __rl_emit(o) {
  if (__rl_n >= __rl_max) return;
  __rl_n++;
  o.t = Date.now() - __rl_t0;
  let s;
  try { s = JSON.stringify(o); } catch (e) { s = JSON.stringify({ type: 'error', message: String(e) }); }
  console.log(${JSON.stringify(FRIDA_EVENT_PREFIX)} + s);
}
function __rl_str(v, n) {
  let s;
  try { s = String(v); } catch (e) { s = '<unprintable>'; }
  return s.length > n ? s.slice(0, n) + '...' : s;
}
function __rl_export(mod, name) {
  try {
    if (mod) {
      const m = Process.findModuleByName(mod);
      if (!m) return null;
      if (typeof m.findExportByName === 'function') return m.findExportByName(name);
      return Module.findExportByName(mod, name);
    }
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
    return Module.findExportByName(null, name);
  } catch (e) { return null; }
}
`;
}

/** Build the Frida script source for a template. Throws HookParamError on bad parameters. */
export function buildHookScript(id: HookTemplateId, params: Record<string, unknown> = {}, maxEvents = 1000): string {
  const max = Math.max(1, Math.min(Math.floor(Number(maxEvents) || 1000), 100_000));
  const head = prelude(max);
  switch (id) {
    case 'module-list':
      return head + `
__rl_emit({ type: 'process', pid: Process.id, arch: Process.arch, platform: Process.platform, pointerSize: Process.pointerSize });
for (const m of Process.enumerateModules().slice(0, 2000)) {
  __rl_emit({ type: 'module', name: m.name, base: m.base.toString(), size: m.size, path: m.path });
}
`;
    case 'trace-native-export': {
      const exp = reqString(params, 'export', IDENT);
      const mod = params.module === undefined || params.module === null || params.module === '' ? null : reqString(params, 'module', /^[\w.+@-]{1,255}$/);
      const nargs = Math.max(0, Math.min(Math.floor(Number(params.args ?? 4)) || 0, 8));
      const bt = params.backtrace === true;
      return head + `
const __rl_target = __rl_export(${JSON.stringify(mod)}, ${JSON.stringify(exp)});
if (__rl_target === null) {
  __rl_emit({ type: 'error', message: 'export not found', export: ${JSON.stringify(exp)}, module: ${JSON.stringify(mod)} });
} else {
  __rl_emit({ type: 'hooked', export: ${JSON.stringify(exp)}, module: ${JSON.stringify(mod)}, address: __rl_target.toString() });
  Interceptor.attach(__rl_target, {
    onEnter(args) {
      const a = [];
      for (let i = 0; i < ${nargs}; i++) a.push(args[i].toString());
      this.__rl = { type: 'call', export: ${JSON.stringify(exp)}, thread: this.threadId, args: a };
      ${bt ? "this.__rl.backtrace = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 8).map((p) => DebugSymbol.fromAddress(p).toString());" : ''}
    },
    onLeave(ret) {
      if (!this.__rl) return;
      this.__rl.ret = ret.toString();
      __rl_emit(this.__rl);
    }
  });
}
`;
    }
    case 'java-method-log': {
      const cls = reqString(params, 'className', /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/);
      const method = reqString(params, 'method', /^(\$init|[A-Za-z_$][\w$]{0,255})$/);
      if (cls.length > 512) throw new HookParamError('className too long');
      return head + `
if (typeof Java === 'undefined' || !Java.available) {
  __rl_emit({ type: 'error', message: 'Java runtime not available in this process' });
} else {
  Java.perform(function () {
    let C;
    try { C = Java.use(${JSON.stringify(cls)}); } catch (e) { __rl_emit({ type: 'error', message: 'class not found: ' + e }); return; }
    const m = C[${JSON.stringify(method)}];
    if (!m || !m.overloads) { __rl_emit({ type: 'error', message: 'method not found' }); return; }
    m.overloads.forEach(function (ov) {
      const sig = ov.argumentTypes.map(function (t) { return t.className; }).join(', ');
      __rl_emit({ type: 'hooked', className: ${JSON.stringify(cls)}, method: ${JSON.stringify(method)}, signature: sig });
      ov.implementation = function () {
        const args = [];
        for (let i = 0; i < arguments.length && i < 8; i++) args.push(__rl_str(arguments[i], 512));
        const ret = ov.apply(this, arguments);
        __rl_emit({ type: 'call', className: ${JSON.stringify(cls)}, method: ${JSON.stringify(method)}, signature: sig, args: args, ret: __rl_str(ret, 512) });
        return ret;
      };
    });
  });
}
`;
    }
    case 'ssl-pinning-bypass':
      return head + `
// Testing aid for apps you own or are authorized to test.
if (typeof Java === 'undefined' || !Java.available) {
  __rl_emit({ type: 'error', message: 'Java runtime not available in this process' });
} else {
  Java.perform(function () {
    try {
      const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      const TrustAll = Java.registerClass({
        name: 'dev.revlens.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function (chain, authType) {},
          checkServerTrusted: function (chain, authType) {},
          getAcceptedIssuers: function () { return []; }
        }
      });
      const init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) {
        __rl_emit({ type: 'bypass', where: 'SSLContext.init' });
        return init.call(this, km, [TrustAll.$new()], sr);
      };
      __rl_emit({ type: 'hooked', where: 'SSLContext.init' });
    } catch (e) { __rl_emit({ type: 'error', where: 'SSLContext.init', message: String(e) }); }
    try {
      const Pinner = Java.use('okhttp3.CertificatePinner');
      Pinner.check.overloads.forEach(function (ov) {
        ov.implementation = function (host) { __rl_emit({ type: 'bypass', where: 'okhttp3.CertificatePinner.check', host: __rl_str(host, 256) }); };
      });
      __rl_emit({ type: 'hooked', where: 'okhttp3.CertificatePinner.check' });
    } catch (e) { __rl_emit({ type: 'info', where: 'okhttp3.CertificatePinner', message: 'not present' }); }
  });
}
`;
    case 'electron-net-observe':
      return head + `
function __rl_sockaddr(p) {
  try {
    if (p.isNull()) return null;
    const fam = Process.platform === 'darwin' ? p.add(1).readU8() : p.readU16();
    if (fam === 2) {
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      const b = p.add(4).readByteArray(4);
      const ip = Array.from(new Uint8Array(b)).join('.');
      return { family: 'ipv4', ip: ip, port: port };
    }
    if (fam === 10 || fam === 23 || fam === 30) {
      const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
      const raw = new Uint8Array(p.add(8).readByteArray(16));
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(((raw[i] << 8) | raw[i + 1]).toString(16));
      return { family: 'ipv6', ip: parts.join(':'), port: port };
    }
    return { family: String(fam) };
  } catch (e) { return null; }
}
const __rl_win = Process.platform === 'windows';
const __rl_gai = __rl_win ? __rl_export('ws2_32.dll', 'GetAddrInfoW') : __rl_export(null, 'getaddrinfo');
if (__rl_gai) {
  Interceptor.attach(__rl_gai, {
    onEnter(args) {
      let host = null;
      try { host = __rl_win ? args[0].readUtf16String() : args[0].readUtf8String(); } catch (e) {}
      __rl_emit({ type: 'dns', host: host ? __rl_str(host, 256) : null });
    }
  });
  __rl_emit({ type: 'hooked', where: __rl_win ? 'GetAddrInfoW' : 'getaddrinfo' });
}
const __rl_conn = __rl_win ? __rl_export('ws2_32.dll', 'connect') : __rl_export(null, 'connect');
if (__rl_conn) {
  Interceptor.attach(__rl_conn, {
    onEnter(args) {
      const a = __rl_sockaddr(args[1]);
      if (a && a.ip) __rl_emit({ type: 'connect', ip: a.ip, port: a.port, family: a.family });
    }
  });
  __rl_emit({ type: 'hooked', where: 'connect' });
}
if (!__rl_gai && !__rl_conn) __rl_emit({ type: 'error', message: 'no network functions found to hook' });
`;
    default:
      throw new HookParamError(`unknown template ${String(id)}`);
  }
}
