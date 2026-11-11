// Application graphs: Android components, intent filters, deep links, providers and permissions;
// iOS executables, extensions, frameworks, entitlements and URL schemes. Nodes and edges carry
// evidence (manifest line, archive path) and render to Mermaid flowcharts.

import type { ManifestInfo } from './manifest.js';
import type { DexFile } from './dex/parse.js';
import { toDescriptor } from './dex/parse.js';
import { analyzeIpa, findAppRoot } from './ios/ipa.js';
import { isMacho, parseMachoSlices } from './ios/macho.js';
import { parsePlist, type PlistValue } from './ios/plist.js';
import { readEntry, type ZipArchive } from './zip.js';

export interface GraphNode { id: string; kind: string; label: string; attrs?: Record<string, unknown> }
export interface GraphEdge { from: string; to: string; kind: string; label?: string }
export interface AppGraph { platform: 'android' | 'ios'; app: string; nodes: GraphNode[]; edges: GraphEdge[]; stats: Record<string, number>; truncated: boolean }

class Builder {
  nodes = new Map<string, GraphNode>();
  edges: GraphEdge[] = [];
  edgeKeys = new Set<string>();
  truncated = false;
  constructor(readonly maxNodes: number, readonly maxEdges: number) {}
  node(id: string, kind: string, label: string, attrs?: Record<string, unknown>): string {
    const n = this.nodes.get(id);
    if (n) { if (attrs) n.attrs = { ...n.attrs, ...attrs }; return id; }
    if (this.nodes.size >= this.maxNodes) { this.truncated = true; return id; }
    this.nodes.set(id, attrs && Object.keys(attrs).length ? { id, kind, label, attrs } : { id, kind, label });
    return id;
  }
  edge(from: string, to: string, kind: string, label?: string): void {
    if (!this.nodes.has(from) || !this.nodes.has(to)) return;
    const k = `${from}\u0000${to}\u0000${kind}\u0000${label ?? ''}`;
    if (this.edgeKeys.has(k)) return;
    if (this.edges.length >= this.maxEdges) { this.truncated = true; return; }
    this.edgeKeys.add(k);
    this.edges.push(label ? { from, to, kind, label } : { from, to, kind });
  }
  done(platform: AppGraph['platform'], app: string): AppGraph {
    const stats: Record<string, number> = {};
    for (const n of this.nodes.values()) stats[n.kind] = (stats[n.kind] ?? 0) + 1;
    stats.edges = this.edges.length;
    return { platform, app, nodes: [...this.nodes.values()], edges: this.edges, stats, truncated: this.truncated };
  }
}

/** Build the Android component graph from a decoded manifest (and optionally the DEX files). */
export function androidAppGraph(m: ManifestInfo, dexes: DexFile[] = [], opts: { maxNodes?: number; maxEdges?: number } = {}): AppGraph {
  const g = new Builder(opts.maxNodes ?? 5000, opts.maxEdges ?? 20000);
  const app = g.node(`app:${m.package}`, 'app', m.package, { versionName: m.versionName, versionCode: m.versionCode, minSdk: m.minSdk, targetSdk: m.targetSdk, debuggable: m.application.debuggable, allowBackup: m.application.allowBackup, application: m.application.name });
  const classes = new Set<string>();
  for (const d of dexes) for (const c of d.classes) classes.add(c.name);
  for (const p of m.permissions) { const id = g.node(`perm:${p.name}`, 'permission', p.name, { level: p.level, maxSdkVersion: p.maxSdkVersion }); g.edge(app, id, 'uses-permission'); }
  for (const p of m.definedPermissions) { const id = g.node(`perm:${p.name}`, 'permission', p.name, { defined: true, protectionLevel: p.protectionLevel }); g.edge(app, id, 'defines-permission'); }
  for (const c of m.components) {
    const id = g.node(`${c.kind}:${c.name}`, c.kind, c.name, {
      exported: c.exported, exportedReason: c.exportedReason, launcher: c.launcher || undefined, enabled: c.enabled, process: c.process,
      authorities: c.authorities, grantUriPermissions: c.grantUriPermissions, line: c.line,
      inDex: dexes.length ? classes.has(toDescriptor(c.name)) : undefined,
    });
    g.edge(app, id, 'declares');
    for (const [k, p] of [['requires', c.permission], ['read-permission', c.readPermission], ['write-permission', c.writePermission]] as const) {
      if (!p) continue;
      const pid = g.node(`perm:${p}`, 'permission', p);
      g.edge(id, pid, k);
    }
    if (c.targetActivity) { const t = m.components.find((x) => x.name === c.targetActivity && x.kind === 'activity'); if (t) g.edge(id, `activity:${t.name}`, 'alias-of'); }
    if (c.authorities) for (const a of c.authorities.split(';').filter(Boolean)) { const aid = g.node(`authority:${a}`, 'authority', `content://${a}`); g.edge(id, aid, 'serves'); }
    for (const f of c.intentFilters) {
      for (const a of f.actions) { const aid = g.node(`action:${a}`, 'action', a); g.edge(aid, id, 'intent', f.categories.length ? f.categories.map((x) => x.replace(/^android\.intent\.category\./, '')).join(',') : undefined); }
    }
  }
  for (const d of m.deepLinks) { const id = g.node(`link:${d.url}`, 'deeplink', d.url, { scheme: d.scheme, host: d.host, path: d.path, autoVerify: d.autoVerify || undefined }); g.edge(id, `activity:${d.component}`, 'opens'); g.edge(id, `activity-alias:${d.component}`, 'opens'); }
  // an external caller node only when something is exported, so the graph shows the attack surface
  if (m.components.some((c) => c.exported)) {
    g.node('ext:caller', 'external', 'other apps');
    for (const c of m.components) if (c.exported) g.edge('ext:caller', `${c.kind}:${c.name}`, 'reachable');
  }
  return g.done('android', m.package);
}

const dict = (v: PlistValue | undefined): Record<string, PlistValue> | undefined => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, PlistValue>) : undefined);
const short = (v: PlistValue, max = 80): string => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > max ? s.slice(0, max) + '...' : s; };

/** Build the iOS bundle graph from an IPA archive. */
export async function iosAppGraph(zip: ZipArchive, opts: { maxNodes?: number; maxEdges?: number } = {}): Promise<AppGraph> {
  const info = await analyzeIpa(zip);
  const root = findAppRoot(zip)!;
  const g = new Builder(opts.maxNodes ?? 5000, opts.maxEdges ?? 20000);
  const appId = info.bundleId ?? info.name ?? root;
  const app = g.node(`app:${appId}`, 'app', appId, { name: info.displayName ?? info.name, version: info.version, build: info.build, minimumOSVersion: info.minimumOSVersion, path: root });
  // every Mach-O executable in the bundle: main, frameworks, extensions, loose dylibs
  const bundles: { id: string; kind: string; label: string; plist: string; dir: string; attrs: Record<string, unknown> }[] = [];
  for (const f of info.frameworks) bundles.push({ id: `framework:${f.name}`, kind: 'framework', label: f.name, plist: `${f.path}/Info.plist`, dir: f.path, attrs: { path: f.path } });
  for (const e of info.extensions) bundles.push({ id: `extension:${e.name}`, kind: 'extension', label: e.name, plist: `${e.path}/Info.plist`, dir: e.path, attrs: { path: e.path, bundleId: e.bundleId, extensionPoint: e.extensionPoint } });
  for (const b of bundles) { g.node(b.id, b.kind, b.label, b.attrs); g.edge(app, b.id, b.kind === 'framework' ? 'embeds' : 'contains'); }
  for (const d of info.dylibs) { const id = g.node(`dylib:${d}`, 'dylib', d, { path: root + d }); g.edge(app, id, 'embeds'); }
  const execs: { owner: string; path: string }[] = [];
  if (info.executablePath) execs.push({ owner: app, path: info.executablePath });
  for (const b of bundles) {
    let exe: string | undefined;
    try { const p = dict(parsePlist(await readEntry(zip, b.plist, 4 << 20))); exe = typeof p?.CFBundleExecutable === 'string' ? p.CFBundleExecutable : undefined; } catch { /* missing plist */ }
    exe ??= b.label.replace(/\.(framework|appex)$/, '');
    execs.push({ owner: b.id, path: `${b.dir}/${exe}` });
  }
  const installName = (p: string): string | undefined => {
    const m = /(?:^|\/)([^/]+\.framework)\/[^/]+$/.exec(p);
    if (m) return `framework:${m[1]}`;
    const d = /(?:^|\/)([^/]+\.dylib)$/.exec(p);
    if (d && info.dylibs.some((x) => x.endsWith(d[1]!))) return `dylib:${info.dylibs.find((x) => x.endsWith(d[1]!))}`;
    return undefined;
  };
  for (const e of execs) {
    if (!zip.byName.has(e.path)) continue;
    let bytes: Uint8Array;
    try { bytes = await readEntry(zip, e.path, 256 << 20); } catch { continue; }
    if (!isMacho(bytes)) continue;
    const slices = parseMachoSlices(bytes);
    const xid = g.node(`exe:${e.path}`, 'executable', e.path.slice(root.length) || e.path, { cpus: slices.map((s) => s.cpu), encrypted: slices.some((s) => s.encrypted) || undefined, teamId: slices.find((s) => s.signature?.teamId)?.signature?.teamId, identifier: slices.find((s) => s.signature?.identifier)?.signature?.identifier });
    g.edge(e.owner, xid, 'executable');
    const dylibs = new Set(slices.flatMap((s) => s.dylibs));
    for (const d of dylibs) {
      const target = installName(d);
      if (target && target === e.owner) continue; // the library's own install name
      if (target && g.nodes.has(target)) g.edge(xid, target, 'links', d);
      else if (/^\/(System|usr)\//.test(d)) { const sid = g.node(`sys:${d}`, 'system-library', d.replace(/^.*\//, '')); g.edge(xid, sid, 'links', d); }
    }
    const ents = dict(slices.find((s) => s.signature?.entitlements)?.signature?.entitlements);
    for (const [k, v] of Object.entries(ents ?? {})) { const nid = g.node(`ent:${k}`, 'entitlement', k); g.edge(xid, nid, 'entitled', short(v)); }
  }
  for (const u of info.urlSchemes) for (const s of u.schemes) { const id = g.node(`scheme:${s}`, 'url-scheme', `${s}://`, { name: u.name }); g.edge(id, app, 'opens'); }
  for (const s of info.queriesSchemes) { const id = g.node(`query:${s}`, 'queried-scheme', `${s}://`); g.edge(app, id, 'queries'); }
  for (const d of info.associatedDomains) { const id = g.node(`domain:${d}`, 'associated-domain', d); g.edge(id, app, 'opens'); }
  for (const p of info.privacyUsage) { const id = g.node(`privacy:${p.key}`, 'privacy-usage', p.key, { text: p.text }); g.edge(app, id, 'asks'); }
  if (info.ats?.allowsArbitraryLoads) { const id = g.node('ats:arbitrary', 'ats', 'NSAllowsArbitraryLoads'); g.edge(app, id, 'allows'); }
  for (const d of info.ats?.exceptionDomains ?? []) { const id = g.node(`ats:${d.domain}`, 'ats', d.domain, { insecureHttp: d.insecureHttp, includesSubdomains: d.includesSubdomains }); g.edge(app, id, 'ats-exception'); }
  return g.done('ios', appId);
}

const SHAPES: Record<string, [string, string]> = {
  app: ['[[', ']]'], activity: ['[', ']'], 'activity-alias': ['[/', '/]'], service: ['([', '])'], receiver: ['>', ']'], provider: ['[(', ')]'],
  permission: ['{{', '}}'], action: ['(', ')'], deeplink: ['>', ']'], authority: ['[(', ')]'], external: ['((', '))'],
  executable: ['[', ']'], framework: ['[[', ']]'], extension: ['[/', '/]'], dylib: ['[[', ']]'], entitlement: ['{{', '}}'], 'url-scheme': ['>', ']'],
  'queried-scheme': ['(', ')'], 'associated-domain': ['>', ']'], 'privacy-usage': ['{{', '}}'], ats: ['{{', '}}'], 'system-library': ['(', ')'],
};

/** Render a graph as a Mermaid flowchart. Exported Android components are highlighted. */
export function graphToMermaid(gr: AppGraph, opts: { maxNodes?: number; direction?: 'LR' | 'TB' } = {}): string {
  const max = opts.maxNodes ?? 300;
  const ids = new Map<string, string>();
  const nodes = gr.nodes.slice(0, max);
  nodes.forEach((n, i) => ids.set(n.id, `n${i}`));
  const esc = (s: string): string => s.replace(/"/g, '#quot;').replace(/[<>]/g, (c) => (c === '<' ? '#lt;' : '#gt;')).slice(0, 120);
  const out = [`flowchart ${opts.direction ?? 'LR'}`];
  for (const n of nodes) { const [a, b] = SHAPES[n.kind] ?? ['[', ']']; out.push(`  ${ids.get(n.id)}${a}"${esc(n.kind === 'app' || n.kind === 'external' ? n.label : `${n.kind}: ${n.label}`)}"${b}`); }
  for (const e of gr.edges) {
    const a = ids.get(e.from), b = ids.get(e.to);
    if (!a || !b) continue;
    const lbl = e.label ? `${e.kind} ${e.label}` : e.kind;
    out.push(`  ${a} -->|"${esc(lbl)}"| ${b}`);
  }
  const exported = nodes.filter((n) => n.attrs?.exported === true).map((n) => ids.get(n.id)!);
  if (exported.length) out.push('  classDef exported stroke:#c00,stroke-width:2px', `  class ${exported.join(',')} exported`);
  if (gr.nodes.length > max) out.push(`  %% ${gr.nodes.length - max} more nodes not shown`);
  return out.join('\n');
}
