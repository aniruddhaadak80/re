// @revlens/desktop: process, installed app and native UI reverse engineering. This entry only parses data
// and is safe in a browser Web Worker. Live inspection is in '@revlens/desktop/node'.
import type { Analyzer, AnalyzerContext, Finding } from '@revlens/core';
import { parsePlist, isBinaryPlist } from './plist.js';
import { parseDesktopFile, desktopEntryToApp, infoPlistToApp } from './apps.js';
import { BROWSER_TOOLS } from './tools.js';

export { parseProcStatus, parseCmdline, parseProcMaps, classifyFdTarget, classifyModule, parseProcNet, parseProcNetUnix, parseLsofF, parsePs, parseWinProcesses, parseWinProcessDetail, InputError, type ProcessInfo, type ModuleInfo, type OpenFile, type SocketInfo } from './proc.js';
export { parsePlist, parseBinaryPlist, parseXmlPlist, isBinaryPlist, type PlistValue } from './plist.js';
export { parseDesktopFile, splitExec, desktopEntryToApp, infoPlistToApp, parseRegQuery, uninstallKeysToApps, type AppRecord, type DesktopEntry } from './apps.js';
export { parseGVariant, replyValue, parseAccessibleRefs, type GValue, type UiNode } from './gvariant.js';
export { compareSnapshots, socketKey, type ProcessSnapshot, type SnapshotDiff } from './compare.js';
export { BROWSER_TOOLS, type ToolDef } from './tools.js';

/** Parse-only tools (bytes or text input). The Node entry adds live process, app and UI tools. */
export const TOOLS = BROWSER_TOOLS();

function meta(ctx: AnalyzerContext): Record<string, unknown> { return (ctx.report.meta.desktop ??= {}) as Record<string, unknown>; }
const finding = (ctx: AnalyzerContext, f: Omit<Finding, 'analyzer'>) => ctx.report.findings.push({ analyzer: 'desktop', ...f });

/** Linux .desktop entries: app record, Exec command and risky launch patterns. */
export const desktopEntryAnalyzer: Analyzer = {
  id: 'desktop-entry',
  title: 'Linux desktop entry',
  description: 'Parses freedesktop .desktop files into an app record (executable, packaging, categories, MIME types) and flags shell launchers and downloads in Exec.',
  applies: (ctx) => ctx.bytes.length < 1024 * 1024 && /\.desktop$/i.test(ctx.name) && /\[Desktop Entry\]/.test(ctx.text ?? new TextDecoder().decode(ctx.bytes.subarray(0, 65536))),
  run(ctx) {
    const text = ctx.text ?? new TextDecoder().decode(ctx.bytes);
    const e = parseDesktopFile(text);
    const app = desktopEntryToApp(e, ctx.name);
    meta(ctx).desktopEntry = { app, groups: Object.keys(e.groups), errors: e.errors };
    const exec = app?.exec ?? '';
    const off = text.indexOf('Exec=');
    if (/\b(?:sh|bash|zsh|dash)\s+-c\b/.test(exec)) finding(ctx, { id: 'desktop-exec-shell', title: 'Desktop entry launches through a shell', severity: 'medium', detail: 'Exec runs a shell command string, which can hide what actually starts.', evidence: [{ offset: off, length: exec.length + 5, snippet: exec.slice(0, 200) }], attack: ['T1547.013'] });
    if (/\b(?:curl|wget)\b.*\|\s*(?:sh|bash)/.test(exec)) finding(ctx, { id: 'desktop-exec-download', title: 'Desktop entry downloads and runs code', severity: 'high', detail: 'Exec pipes a download into a shell.', evidence: [{ offset: off, length: exec.length + 5, snippet: exec.slice(0, 200) }], attack: ['T1105', 'T1547.013'] });
    if (/\/autostart\//.test(ctx.name) || e.groups['Desktop Entry']?.['X-GNOME-Autostart-enabled'] === 'true') finding(ctx, { id: 'desktop-autostart', title: 'Autostart desktop entry', severity: 'low', detail: 'This entry starts with the user session.', evidence: [{ path: ctx.name }], attack: ['T1547.013'] });
  },
};

/** Property lists (XML or binary): parsed value, and an app summary for Info.plist. */
export const plistAnalyzer: Analyzer = {
  id: 'desktop-plist',
  title: 'Property list',
  description: 'Parses XML and binary plists. Info.plist files also get an app summary (bundle id, version, executable, URL schemes) and findings for weakened App Transport Security.',
  applies: (ctx) => ctx.bytes.length < 64 * 1024 * 1024 && (isBinaryPlist(ctx.bytes) || (/\.plist$/i.test(ctx.name) && /<plist|<dict/.test(new TextDecoder().decode(ctx.bytes.subarray(0, 4096))))),
  run(ctx) {
    let v;
    try { v = parsePlist(ctx.bytes); } catch (e) { meta(ctx).plistError = (e as Error).message; return; }
    const m = meta(ctx);
    const json = JSON.stringify(v);
    m.plist = json.length > 2_000_000 ? { truncated: true, size: json.length } : v;
    if (v && typeof v === 'object' && !Array.isArray(v) && 'CFBundleIdentifier' in v) {
      m.app = infoPlistToApp(v, ctx.name.replace(/\/Contents\/Info\.plist$/, ''));
      const ats = (v as Record<string, any>).NSAppTransportSecurity;
      if (ats && ats.NSAllowsArbitraryLoads === true) finding(ctx, { id: 'plist-ats-arbitrary-loads', title: 'App Transport Security allows arbitrary loads', severity: 'medium', detail: 'NSAllowsArbitraryLoads is true, so the app may use plain HTTP.', evidence: [{ path: ctx.name, snippet: 'NSAppTransportSecurity.NSAllowsArbitraryLoads = true' }] });
    }
  },
};

export const ANALYZERS: Analyzer[] = [desktopEntryAnalyzer, plistAnalyzer];
