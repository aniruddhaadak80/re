// Turn a decoded AndroidManifest.xml tree into a structured, security-oriented summary.

import { attr, attrValue, parseAxml, resolveRef, resourceName, type AxmlDocument, type ResourceTable, type XmlNode } from './axml.js';
import { permissionInfo, type ProtectionLevel } from './permissions.js';
import { ParseError } from './bytes.js';

export interface IntentFilter {
  actions: string[];
  categories: string[];
  data: { scheme?: string; host?: string; port?: string; path?: string; pathPrefix?: string; pathPattern?: string; mimeType?: string }[];
  autoVerify?: boolean;
  priority?: number;
}

export type ComponentKind = 'activity' | 'activity-alias' | 'service' | 'receiver' | 'provider';

export interface Component {
  kind: ComponentKind;
  name: string;
  /** effective exported state after Android defaults */
  exported: boolean;
  /** how exported was decided: explicit attribute or a platform default */
  exportedReason: 'explicit' | 'intent-filter-default' | 'provider-legacy-default' | 'default-false';
  permission?: string;
  readPermission?: string;
  writePermission?: string;
  authorities?: string;
  grantUriPermissions?: boolean;
  enabled?: boolean;
  process?: string;
  targetActivity?: string;
  launcher: boolean;
  intentFilters: IntentFilter[];
  /** line in the original XML, from the AXML chunk */
  line: number;
}

export interface UsesPermission {
  name: string;
  maxSdkVersion?: number;
  level: ProtectionLevel;
  group?: string;
  note: string;
}

export interface DeepLink {
  component: string;
  url: string;
  scheme: string;
  host?: string;
  path?: string;
  autoVerify: boolean;
}

export interface ManifestInfo {
  package: string;
  versionCode?: number;
  versionName?: string;
  minSdk?: number;
  targetSdk?: number;
  maxSdk?: number;
  compileSdk?: number;
  compileSdkCodename?: string;
  platformBuildVersionName?: string;
  sharedUserId?: string;
  installLocation?: string;
  application: {
    name?: string;
    label?: string;
    labelRes?: string;
    icon?: string;
    debuggable: boolean;
    allowBackup: boolean;
    /** true when allowBackup was not written and the platform default (true) applies */
    allowBackupDefault: boolean;
    usesCleartextTraffic?: boolean;
    networkSecurityConfig?: string;
    networkSecurityConfigPath?: string;
    testOnly: boolean;
    extractNativeLibs?: boolean;
    largeHeap?: boolean;
    appComponentFactory?: string;
    requestLegacyExternalStorage?: boolean;
  };
  permissions: UsesPermission[];
  /** <permission> elements the app defines */
  definedPermissions: { name: string; protectionLevel?: string }[];
  features: { name: string; required: boolean }[];
  components: Component[];
  deepLinks: DeepLink[];
  metaData: { name: string; value?: string; resource?: string }[];
  queries: { packages: string[]; intents: number; providers: string[] };
  launcherActivity?: string;
  libraries: string[];
}

function bool(n: XmlNode, name: string): boolean | undefined {
  const v = attrValue(n, name);
  if (!v) return undefined;
  if (v.type === 0x12) return v.data !== 0;
  const t = attr(n, name);
  if (t === 'true') return true;
  if (t === 'false') return false;
  return undefined;
}

function int(n: XmlNode, name: string): number | undefined {
  const v = attrValue(n, name);
  if (!v) return undefined;
  if (v.type === 0x10 || v.type === 0x11) return v.data | 0;
  const t = attr(n, name);
  if (t !== undefined && /^-?\d+$/.test(t)) return parseInt(t, 10);
  return undefined;
}

function fqcn(pkg: string, name: string | undefined): string {
  if (!name) return '';
  if (name.startsWith('.')) return pkg + name;
  if (!name.includes('.')) return `${pkg}.${name}`;
  return name;
}

function parseFilter(n: XmlNode): IntentFilter {
  const f: IntentFilter = { actions: [], categories: [], data: [] };
  const av = bool(n, 'autoVerify');
  if (av !== undefined) f.autoVerify = av;
  const pr = int(n, 'priority');
  if (pr !== undefined) f.priority = pr;
  for (const c of n.children) {
    const nm = attr(c, 'name');
    if (c.tag === 'action' && nm) f.actions.push(nm);
    else if (c.tag === 'category' && nm) f.categories.push(nm);
    else if (c.tag === 'data') {
      const d: IntentFilter['data'][number] = {};
      for (const k of ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType'] as const) {
        const v = attr(c, k);
        if (v !== undefined) d[k] = v;
      }
      f.data.push(d);
    }
  }
  return f;
}

/** Deep links for a VIEW + BROWSABLE filter, combining every scheme with every host like the platform does. */
function deepLinksOf(component: string, f: IntentFilter): DeepLink[] {
  if (!f.actions.includes('android.intent.action.VIEW') || !f.categories.includes('android.intent.category.BROWSABLE')) return [];
  const schemes = [...new Set(f.data.map((d) => d.scheme).filter((s): s is string => !!s))];
  const hosts = [...new Set(f.data.map((d) => (d.host ? d.host + (d.port ? `:${d.port}` : '') : undefined)).filter((s): s is string => !!s))];
  const paths = [...new Set(f.data.map((d) => d.path ?? d.pathPrefix ?? d.pathPattern).filter((s): s is string => !!s))];
  const out: DeepLink[] = [];
  for (const scheme of schemes) {
    for (const host of hosts.length ? hosts : [undefined]) {
      for (const path of paths.length ? paths : [undefined]) {
        const url = `${scheme}://${host ?? '*'}${path ? (path.startsWith('/') ? path : `/${path}`) : ''}`;
        const dl: DeepLink = { component, url, scheme, autoVerify: f.autoVerify === true };
        if (host) dl.host = host;
        if (path) dl.path = path;
        out.push(dl);
        if (out.length > 200) return out;
      }
    }
  }
  return out;
}

/** Interpret an AndroidManifest AXML document. Pass the resource table to resolve labels and xml paths. */
export function interpretManifest(doc: AxmlDocument, table?: ResourceTable): ManifestInfo {
  const root = doc.root;
  if (!root || root.tag !== 'manifest') throw new ParseError('AXML root is not <manifest>');
  const pkg = attr(root, 'package') ?? '';
  const info: ManifestInfo = {
    package: pkg,
    application: { debuggable: false, allowBackup: true, allowBackupDefault: true, testOnly: false },
    permissions: [], definedPermissions: [], features: [], components: [], deepLinks: [], metaData: [],
    queries: { packages: [], intents: 0, providers: [] }, libraries: [],
  };
  const vc = int(root, 'versionCode'); if (vc !== undefined) info.versionCode = vc >>> 0;
  const vn = attr(root, 'versionName'); if (vn !== undefined) info.versionName = resolveRef(table, vn);
  const cs = int(root, 'compileSdkVersion'); if (cs !== undefined) info.compileSdk = cs;
  const csc = attr(root, 'compileSdkVersionCodename'); if (csc !== undefined) info.compileSdkCodename = csc;
  const pbv = attr(root, 'platformBuildVersionName'); if (pbv !== undefined) info.platformBuildVersionName = pbv;
  const su = attr(root, 'sharedUserId'); if (su !== undefined) info.sharedUserId = su;
  const il = attr(root, 'installLocation'); if (il !== undefined) info.installLocation = ({ '0': 'auto', '1': 'internalOnly', '2': 'preferExternal' } as Record<string, string>)[il] ?? il;

  let app: XmlNode | undefined;
  for (const c of root.children) {
    if (c.tag === 'uses-sdk') {
      const mn = int(c, 'minSdkVersion'); if (mn !== undefined) info.minSdk = mn;
      const tg = int(c, 'targetSdkVersion'); if (tg !== undefined) info.targetSdk = tg;
      const mx = int(c, 'maxSdkVersion'); if (mx !== undefined) info.maxSdk = mx;
    } else if (c.tag === 'uses-permission' || c.tag === 'uses-permission-sdk-23' || c.tag === 'uses-permission-sdk-m') {
      const name = attr(c, 'name');
      if (!name) continue;
      const p = permissionInfo(name);
      const up: UsesPermission = { name, level: p.level, note: p.note };
      if (p.group) up.group = p.group;
      const mx = int(c, 'maxSdkVersion'); if (mx !== undefined) up.maxSdkVersion = mx;
      if (!info.permissions.some((x) => x.name === name)) info.permissions.push(up);
    } else if (c.tag === 'permission') {
      const name = attr(c, 'name');
      if (name) {
        const pl = attrValue(c, 'protectionLevel');
        const levels = ['normal', 'dangerous', 'signature', 'signatureOrSystem'];
        const dp: { name: string; protectionLevel?: string } = { name };
        if (pl) dp.protectionLevel = levels[pl.data & 0xf] ?? `0x${pl.data.toString(16)}`;
        info.definedPermissions.push(dp);
      }
    } else if (c.tag === 'uses-feature') {
      const name = attr(c, 'name');
      if (name) info.features.push({ name, required: bool(c, 'required') ?? true });
    } else if (c.tag === 'queries') {
      for (const q of c.children) {
        if (q.tag === 'package') { const n = attr(q, 'name'); if (n) info.queries.packages.push(n); }
        else if (q.tag === 'intent') info.queries.intents++;
        else if (q.tag === 'provider') { const a = attr(q, 'authorities'); if (a) info.queries.providers.push(a); }
      }
    } else if (c.tag === 'application' && !app) app = c;
  }

  const target = info.targetSdk ?? info.minSdk ?? 1;
  if (app) {
    const a = info.application;
    const nm = attr(app, 'name'); if (nm) a.name = fqcn(pkg, nm);
    const lbl = attr(app, 'label');
    if (lbl !== undefined) { a.label = resolveRef(table, lbl); const rn = resourceName(table, lbl); if (rn) a.labelRes = rn; }
    const icon = attr(app, 'icon'); if (icon !== undefined) a.icon = resourceName(table, icon) ?? icon;
    a.debuggable = bool(app, 'debuggable') ?? false;
    const ab = bool(app, 'allowBackup');
    if (ab !== undefined) { a.allowBackup = ab; a.allowBackupDefault = false; }
    const ct = bool(app, 'usesCleartextTraffic'); if (ct !== undefined) a.usesCleartextTraffic = ct;
    const nsc = attr(app, 'networkSecurityConfig');
    if (nsc !== undefined) {
      a.networkSecurityConfig = resourceName(table, nsc) ?? nsc;
      const path = resolveRef(table, nsc);
      if (path.startsWith('res/')) a.networkSecurityConfigPath = path;
    }
    a.testOnly = bool(app, 'testOnly') ?? false;
    const enl = bool(app, 'extractNativeLibs'); if (enl !== undefined) a.extractNativeLibs = enl;
    const lh = bool(app, 'largeHeap'); if (lh !== undefined) a.largeHeap = lh;
    const acf = attr(app, 'appComponentFactory'); if (acf) a.appComponentFactory = acf;
    const rles = bool(app, 'requestLegacyExternalStorage'); if (rles !== undefined) a.requestLegacyExternalStorage = rles;

    for (const c of app.children) {
      if (c.tag === 'meta-data') {
        const n = attr(c, 'name');
        if (n) {
          const md: { name: string; value?: string; resource?: string } = { name: n };
          const v = attr(c, 'value'); if (v !== undefined) md.value = resolveRef(table, v);
          const rs = attr(c, 'resource'); if (rs !== undefined) md.resource = resourceName(table, rs) ?? rs;
          info.metaData.push(md);
        }
        continue;
      }
      if (c.tag === 'uses-library') { const n = attr(c, 'name'); if (n) info.libraries.push(n); continue; }
      if (!['activity', 'activity-alias', 'service', 'receiver', 'provider'].includes(c.tag)) continue;
      const kind = c.tag as ComponentKind;
      const name = fqcn(pkg, attr(c, 'name'));
      const filters = c.children.filter((x) => x.tag === 'intent-filter').map(parseFilter);
      const exp = bool(c, 'exported');
      let exported: boolean;
      let reason: Component['exportedReason'];
      if (exp !== undefined) { exported = exp; reason = 'explicit'; }
      else if (kind === 'provider' && target <= 16) { exported = true; reason = 'provider-legacy-default'; }
      else if (kind !== 'provider' && filters.length > 0) { exported = true; reason = 'intent-filter-default'; }
      else { exported = false; reason = 'default-false'; }
      const comp: Component = {
        kind, name, exported, exportedReason: reason,
        launcher: filters.some((f) => f.actions.includes('android.intent.action.MAIN') && f.categories.includes('android.intent.category.LAUNCHER')),
        intentFilters: filters, line: c.line,
      };
      for (const k of ['permission', 'readPermission', 'writePermission', 'authorities', 'process'] as const) {
        const v = attr(c, k); if (v !== undefined) comp[k] = v;
      }
      const ta = attr(c, 'targetActivity'); if (ta) comp.targetActivity = fqcn(pkg, ta);
      const gup = bool(c, 'grantUriPermissions'); if (gup !== undefined) comp.grantUriPermissions = gup;
      const en = bool(c, 'enabled'); if (en !== undefined) comp.enabled = en;
      info.components.push(comp);
      if (comp.launcher && !info.launcherActivity) info.launcherActivity = comp.targetActivity ?? name;
      for (const f of filters) info.deepLinks.push(...deepLinksOf(name, f));
    }
  }
  return info;
}

/** Decode and interpret AndroidManifest.xml bytes in one call. */
export function parseManifest(bytes: Uint8Array, table?: ResourceTable): ManifestInfo {
  return interpretManifest(parseAxml(bytes), table);
}

export interface NetworkSecurityConfig {
  baseCleartextPermitted?: boolean;
  trustsUserCerts: boolean;
  debugOverrides: boolean;
  domains: { domains: string[]; includeSubdomains: boolean; cleartextPermitted?: boolean; pins: number; trustsUserCerts: boolean }[];
}

/** Summarize a decoded res/xml network security config. */
export function interpretNetworkSecurityConfig(doc: AxmlDocument): NetworkSecurityConfig {
  const out: NetworkSecurityConfig = { trustsUserCerts: false, debugOverrides: false, domains: [] };
  const userCerts = (n: XmlNode): boolean => {
    const ta = n.children.find((c) => c.tag === 'trust-anchors');
    return !!ta?.children.some((c) => c.tag === 'certificates' && attr(c, 'src') === 'user');
  };
  const walkDomain = (n: XmlNode, depth: number): void => {
    if (depth > 32) return;
    const ds = n.children.filter((c) => c.tag === 'domain');
    const pinSet = n.children.find((c) => c.tag === 'pin-set');
    const entry: NetworkSecurityConfig['domains'][number] = {
      domains: ds.map((d) => d.text?.trim() ?? '').filter(Boolean),
      includeSubdomains: ds.some((d) => attr(d, 'includeSubdomains') === 'true'),
      pins: pinSet ? pinSet.children.filter((c) => c.tag === 'pin').length : 0,
      trustsUserCerts: userCerts(n),
    };
    const ct = attr(n, 'cleartextTrafficPermitted');
    if (ct !== undefined) entry.cleartextPermitted = ct === 'true';
    out.domains.push(entry);
    for (const c of n.children) if (c.tag === 'domain-config') walkDomain(c, depth + 1);
  };
  for (const c of doc.root?.children ?? []) {
    if (c.tag === 'base-config') {
      const ct = attr(c, 'cleartextTrafficPermitted');
      if (ct !== undefined) out.baseCleartextPermitted = ct === 'true';
      if (userCerts(c)) out.trustsUserCerts = true;
    } else if (c.tag === 'domain-config') walkDomain(c, 0);
    else if (c.tag === 'debug-overrides') out.debugOverrides = true;
  }
  return out;
}
