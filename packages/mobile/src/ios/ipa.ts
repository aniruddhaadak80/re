// IPA inspection: Info.plist, URL schemes, ATS, privacy usage strings, embedded frameworks,
// app extensions, provisioning profile, and the main executable's signature and entitlements.

import { ParseError, indexOfBytes, ascii, utf8 } from '../bytes.js';
import { detectFrameworks, type FrameworkHit } from '../framework.js';
import { openZip, readEntry, type ZipArchive } from '../zip.js';
import { isMacho, parseMachoSlices, type MachoSlice } from './macho.js';
import { parsePlist, type PlistValue } from './plist.js';

export interface IpaInfo {
  appPath: string;
  bundleId?: string;
  name?: string;
  displayName?: string;
  version?: string;
  build?: string;
  minimumOSVersion?: string;
  platforms: string[];
  deviceFamily: string[];
  executable?: string;
  /** archive path of the main executable, for @revlens/core Mach-O analysis */
  executablePath?: string;
  urlSchemes: { name?: string; schemes: string[] }[];
  queriesSchemes: string[];
  ats: { allowsArbitraryLoads: boolean; allowsArbitraryLoadsInWebContent?: boolean; allowsLocalNetworking?: boolean; exceptionDomains: { domain: string; insecureHttp: boolean; includesSubdomains: boolean; minTls?: string }[] } | undefined;
  privacyUsage: { key: string; text: string }[];
  backgroundModes: string[];
  frameworks: { name: string; path: string }[];
  dylibs: string[];
  extensions: { name: string; path: string; bundleId?: string; extensionPoint?: string }[];
  appFrameworks: FrameworkHit[];
  executableInfo?: { slices: Pick<MachoSlice, 'cpu' | 'bits' | 'encrypted' | 'dylibs'>[]; identifier?: string; teamId?: string; entitlements?: PlistValue; encrypted: boolean };
  provisioning?: { name?: string; teamName?: string; teamIds?: string[]; expirationDate?: string; provisionsAllDevices?: boolean; deviceCount: number; entitlements?: PlistValue };
  associatedDomains: string[];
  infoPlist: PlistValue;
  warnings: string[];
}

function str(v: PlistValue | undefined): string | undefined { return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : undefined; }
function dict(v: PlistValue | undefined): Record<string, PlistValue> | undefined { return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, PlistValue> : undefined; }
function arr(v: PlistValue | undefined): PlistValue[] { return Array.isArray(v) ? v : []; }

/** Find Payload/<Name>.app/ in an IPA. */
export function findAppRoot(zip: ZipArchive): string | undefined {
  for (const e of zip.entries) {
    const m = /^Payload\/([^/]+\.app)\/Info\.plist$/.exec(e.name);
    if (m) return `Payload/${m[1]}/`;
  }
  return undefined;
}

export function isIpa(zip: ZipArchive): boolean { return findAppRoot(zip) !== undefined; }

/** Extract the XML plist embedded in a CMS-signed embedded.mobileprovision. */
export function provisioningPlist(b: Uint8Array): PlistValue | undefined {
  const s = indexOfBytes(b, ascii('<?xml'));
  const e = indexOfBytes(b, ascii('</plist>'), Math.max(0, s));
  if (s < 0 || e < 0) return undefined;
  return parsePlist(b.subarray(s, e + 8));
}

export async function analyzeIpa(input: Uint8Array | ZipArchive): Promise<IpaInfo> {
  const zip = input instanceof Uint8Array ? openZip(input) : input;
  const root = findAppRoot(zip);
  if (!root) throw new ParseError('not an IPA: no Payload/<Name>.app/Info.plist');
  const warnings: string[] = [];
  const info = dict(parsePlist(await readEntry(zip, `${root}Info.plist`, 16 * 1024 * 1024))) ?? {};
  const out: IpaInfo = {
    appPath: root, platforms: arr(info.CFBundleSupportedPlatforms).map(String),
    deviceFamily: arr(info.UIDeviceFamily).map((x) => ({ 1: 'iPhone', 2: 'iPad', 3: 'Apple TV', 4: 'Apple Watch', 6: 'Mac Catalyst', 7: 'Apple Vision' } as Record<number, string>)[Number(x)] ?? String(x)),
    urlSchemes: [], queriesSchemes: arr(info.LSApplicationQueriesSchemes).map(String),
    ats: undefined, privacyUsage: [], backgroundModes: arr(info.UIBackgroundModes).map(String),
    frameworks: [], dylibs: [], extensions: [], appFrameworks: [], associatedDomains: [], infoPlist: info, warnings,
  };
  const set = <K extends keyof IpaInfo>(k: K, v: IpaInfo[K] | undefined): void => { if (v !== undefined) out[k] = v; };
  set('bundleId', str(info.CFBundleIdentifier));
  set('name', str(info.CFBundleName));
  set('displayName', str(info.CFBundleDisplayName));
  set('version', str(info.CFBundleShortVersionString));
  set('build', str(info.CFBundleVersion));
  set('minimumOSVersion', str(info.MinimumOSVersion) ?? str(info.LSMinimumSystemVersion));
  set('executable', str(info.CFBundleExecutable));
  if (out.executable) out.executablePath = `${root}${out.executable}`;
  for (const t of arr(info.CFBundleURLTypes)) {
    const d = dict(t);
    if (!d) continue;
    const u: { name?: string; schemes: string[] } = { schemes: arr(d.CFBundleURLSchemes).map(String) };
    const n = str(d.CFBundleURLName); if (n) u.name = n;
    out.urlSchemes.push(u);
  }
  const ats = dict(info.NSAppTransportSecurity);
  if (ats) {
    out.ats = { allowsArbitraryLoads: ats.NSAllowsArbitraryLoads === true, exceptionDomains: [] };
    if (ats.NSAllowsArbitraryLoadsInWebContent !== undefined) out.ats.allowsArbitraryLoadsInWebContent = ats.NSAllowsArbitraryLoadsInWebContent === true;
    if (ats.NSAllowsLocalNetworking !== undefined) out.ats.allowsLocalNetworking = ats.NSAllowsLocalNetworking === true;
    for (const [domain, v] of Object.entries(dict(ats.NSExceptionDomains) ?? {})) {
      const d = dict(v) ?? {};
      const e: { domain: string; insecureHttp: boolean; includesSubdomains: boolean; minTls?: string } = {
        domain,
        insecureHttp: d.NSExceptionAllowsInsecureHTTPLoads === true || d.NSTemporaryExceptionAllowsInsecureHTTPLoads === true,
        includesSubdomains: d.NSIncludesSubdomains === true,
      };
      const tls = str(d.NSExceptionMinimumTLSVersion) ?? str(d.NSTemporaryExceptionMinimumTLSVersion);
      if (tls) e.minTls = tls;
      out.ats.exceptionDomains.push(e);
    }
  }
  for (const [k, v] of Object.entries(info)) if (/^NS[A-Za-z]+UsageDescription$/.test(k)) out.privacyUsage.push({ key: k, text: str(v) ?? '' });

  const names = zip.entries.map((e) => e.name);
  const fwSeen = new Set<string>();
  for (const n of names) {
    if (!n.startsWith(root)) continue;
    const rel = n.slice(root.length);
    const fm = /^Frameworks\/([^/]+\.framework)\//.exec(rel);
    if (fm && !fwSeen.has(fm[1] as string)) { fwSeen.add(fm[1] as string); out.frameworks.push({ name: fm[1] as string, path: `${root}Frameworks/${fm[1]}` }); }
    if (/^Frameworks\/[^/]+\.dylib$/.test(rel)) out.dylibs.push(rel);
    const pm = /^PlugIns\/([^/]+\.appex)\/Info\.plist$/.exec(rel);
    if (pm) {
      const ext: IpaInfo['extensions'][number] = { name: pm[1] as string, path: `${root}PlugIns/${pm[1]}` };
      try {
        const p = dict(parsePlist(await readEntry(zip, n, 4 * 1024 * 1024))) ?? {};
        const id = str(p.CFBundleIdentifier); if (id) ext.bundleId = id;
        const ep = str(dict(p.NSExtension)?.NSExtensionPointIdentifier); if (ep) ext.extensionPoint = ep;
      } catch (err) { warnings.push(`${n}: ${(err as Error).message}`); }
      out.extensions.push(ext);
    }
  }
  out.appFrameworks = detectFrameworks(names.filter((n) => n.startsWith(root)));

  const prov = zip.byName.get(`${root}embedded.mobileprovision`);
  if (prov) {
    try {
      const p = dict(provisioningPlist(await readEntry(zip, prov, 4 * 1024 * 1024)));
      if (p) {
        out.provisioning = { deviceCount: arr(p.ProvisionedDevices).length };
        const pn = str(p.Name); if (pn) out.provisioning.name = pn;
        const tn = str(p.TeamName); if (tn) out.provisioning.teamName = tn;
        if (Array.isArray(p.TeamIdentifier)) out.provisioning.teamIds = p.TeamIdentifier.map(String);
        const ex = str(p.ExpirationDate); if (ex) out.provisioning.expirationDate = ex;
        if (p.ProvisionsAllDevices === true) out.provisioning.provisionsAllDevices = true;
        if (p.Entitlements) out.provisioning.entitlements = p.Entitlements;
      }
    } catch (err) { warnings.push(`embedded.mobileprovision: ${(err as Error).message}`); }
  }

  if (out.executablePath && zip.byName.has(out.executablePath)) {
    try {
      const exe = await readEntry(zip, out.executablePath, 512 * 1024 * 1024);
      if (isMacho(exe)) {
        const slices = parseMachoSlices(exe);
        const sig = slices.find((s) => s.signature)?.signature;
        out.executableInfo = {
          slices: slices.map((s) => ({ cpu: s.cpu, bits: s.bits, ...(s.encrypted !== undefined ? { encrypted: s.encrypted } : {}), dylibs: s.dylibs })),
          encrypted: slices.some((s) => s.encrypted),
        };
        if (sig?.identifier) out.executableInfo.identifier = sig.identifier;
        if (sig?.teamId) out.executableInfo.teamId = sig.teamId;
        if (sig?.entitlements) out.executableInfo.entitlements = sig.entitlements;
      } else warnings.push('main executable is not a Mach-O file');
    } catch (err) { warnings.push(`main executable: ${(err as Error).message}`); }
  } else if (out.executablePath) warnings.push(`main executable ${out.executablePath} is missing from the archive`);

  const ents = dict(out.executableInfo?.entitlements) ?? dict(out.provisioning?.entitlements);
  for (const d of arr(ents?.['com.apple.developer.associated-domains'])) out.associatedDomains.push(String(d));
  void utf8;
  return out;
}

/** Entitlements of a bare Mach-O (outside an IPA). */
export function machoEntitlements(b: Uint8Array): { identifier?: string; teamId?: string; entitlements?: PlistValue; entitlementsXml?: string }[] {
  return parseMachoSlices(b).map((s) => ({
    ...(s.signature?.identifier ? { identifier: s.signature.identifier } : {}),
    ...(s.signature?.teamId ? { teamId: s.signature.teamId } : {}),
    ...(s.signature?.entitlements ? { entitlements: s.signature.entitlements } : {}),
    ...(s.signature?.entitlementsXml ? { entitlementsXml: s.signature.entitlementsXml } : {}),
  }));
}
