import type { Analyzer, Finding, Severity } from '../types.js';
import { membersOf } from './archive.js';
import { decodeUtf8 } from '../bytes.js';

const RISKY_PERMS: Record<string, Severity> = {
  '<all_urls>': 'high', debugger: 'high', nativeMessaging: 'high', proxy: 'high', webRequestBlocking: 'medium',
  webRequest: 'medium', cookies: 'medium', history: 'medium', tabs: 'low', management: 'high', downloads: 'low',
  clipboardRead: 'medium', declarativeNetRequest: 'low', scripting: 'medium', privacy: 'medium', 'file:///*': 'high',
};
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];

export const extAuditAnalyzer: Analyzer = {
  id: 'extaudit',
  title: 'Extension and package audit',
  description: 'Audits browser extensions (CRX, XPI), VS Code extensions (VSIX) and npm tarballs for risky permissions, remote code and install scripts.',
  applies: (ctx) => ['crx', 'xpi', 'vsix', 'npm-tgz', 'zip'].includes(ctx.format),
  async run(ctx) {
    const { report } = ctx;
    const { entries } = await membersOf(ctx);
    const find = (re: RegExp) => entries.filter((e) => re.test(e.name)).sort((a, b) => a.name.split('/').length - b.name.split('/').length)[0];
    const push = (f: Omit<Finding, 'analyzer'>) => report.findings.push({ analyzer: 'extaudit', ...f });

    // Browser extension manifest.
    const mf = find(/(^|\/)manifest\.json$/);
    if (mf && ctx.format !== 'npm-tgz') {
      let m: Record<string, unknown> = {};
      try { m = JSON.parse(decodeUtf8(await mf.read())) as Record<string, unknown>; } catch { /* not json */ }
      if (m.manifest_version) {
        const perms = [...((m.permissions as string[]) ?? []), ...((m.optional_permissions as string[]) ?? [])].filter((p) => typeof p === 'string');
        const hostPerms = [...((m.host_permissions as string[]) ?? []), ...perms.filter((p) => p.includes('://') || p === '<all_urls>')];
        report.meta.extension = { name: m.name, version: m.version, manifestVersion: m.manifest_version, permissions: perms, hostPermissions: hostPerms };
        for (const p of perms) {
          const sev = RISKY_PERMS[p];
          if (sev) push({ id: `ext.perm.${p}`, title: `Extension asks for "${p}"`, severity: sev,
            detail: `The "${p}" permission gives the extension broad power. Check that its purpose needs it.`, evidence: [{ path: mf.name, snippet: p }], tags: ['permissions'] });
        }
        if (hostPerms.some((h) => h === '<all_urls>' || /^\*:\/\/\*\/\*$|^https?:\/\/\*\/\*$/.test(h))) {
          push({ id: 'ext.hosts.all', title: 'Extension can read and change every site', severity: 'high',
            detail: 'Host permissions cover all URLs. The extension can see and modify the content of every page you visit.', evidence: [{ path: mf.name }], tags: ['permissions'] });
        }
        const csp = JSON.stringify(m.content_security_policy ?? '');
        if (/unsafe-eval|unsafe-inline|https?:\/\//.test(csp)) {
          push({ id: 'ext.csp.weak', title: 'Weak extension content security policy', severity: 'medium',
            detail: `The CSP allows ${/unsafe-eval/.test(csp) ? 'eval' : 'remote or inline script'}, which lets code arrive after review.`, evidence: [{ path: mf.name, snippet: csp.slice(0, 120) }], tags: ['csp'] });
        }
        if (m.manifest_version === 2) push({ id: 'ext.mv2', title: 'Manifest V2 extension', severity: 'low',
          detail: 'Manifest V2 is retired in Chrome. MV2 allows remote code and blocking web requests that MV3 does not.', evidence: [{ path: mf.name }], tags: ['mv2'] });
      }
    }

    // VS Code extension.
    const pkg = find(/(^|\/)package\.json$/);
    if (pkg) {
      let p: Record<string, unknown> = {};
      try { p = JSON.parse(decodeUtf8(await pkg.read())) as Record<string, unknown>; } catch { /* ignore */ }
      const scripts = (p.scripts ?? {}) as Record<string, string>;
      const engines = (p.engines ?? {}) as Record<string, string>;
      if (engines.vscode || ctx.format === 'vsix') {
        const events = (p.activationEvents as string[]) ?? [];
        report.meta.vscode = { name: p.name, publisher: p.publisher, version: p.version, activationEvents: events };
        if (events.includes('*') || events.includes('onStartupFinished')) push({ id: 'vsix.activate.always', title: 'VS Code extension starts on every launch', severity: 'medium',
          detail: `Activation event ${events.includes('*') ? '"*"' : '"onStartupFinished"'} runs the extension in every window, even when you do not use it.`, evidence: [{ path: pkg.name }], tags: ['activation'] });
      }
      if (p.name && ctx.format === 'npm-tgz') report.meta.npm = { name: p.name, version: p.version, license: p.license };
      for (const s of INSTALL_SCRIPTS) {
        if (scripts[s]) push({ id: `npm.script.${s}`, title: `Runs a "${s}" script on install`, severity: /curl|wget|https?:|node -e|eval|base64/.test(scripts[s] as string) ? 'high' : 'medium',
          detail: `npm runs "${scripts[s]}" automatically during install. Install scripts are the most common way malicious packages execute.`,
          evidence: [{ path: pkg.name, snippet: (scripts[s] as string).slice(0, 160) }], tags: ['install-script'], attack: ['T1195.002'] });
      }
    }

    // Remote code loading inside the package's own scripts.
    for (const child of report.children ?? []) {
      if (child.file.format !== 'js') continue;
      const remote = child.strings.find((s) => /^https?:\/\/[^\s"']+\.js(\?|$)/.test(s.value));
      if (remote) {
        push({ id: `ext.remote.${child.file.name}`, title: 'Loads remote JavaScript', severity: 'medium',
          detail: `${child.file.name} references a remote script at ${remote.value}. Code fetched at run time escapes store review.`,
          evidence: [{ path: child.file.name, offset: remote.offset, snippet: remote.value }], tags: ['remote-code'], attack: ['T1105'] });
        break;
      }
    }
  },
};
