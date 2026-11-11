// High level APK / AAB / XAPK analysis that ties manifest, signatures, DEX, native libs and frameworks together.

import type { Finding, Severity } from '@revlens/core';
import { ParseError } from './bytes.js';
import { axmlToXml, isAxml, parseAxml, parseResourceTable, type ResourceTable } from './axml.js';
import { detectFrameworks, dartSnapshotInfo, reactNativeBundleInfo, type FrameworkHit } from './framework.js';
import { interpretManifest, interpretNetworkSecurityConfig, type ManifestInfo, type NetworkSecurityConfig } from './manifest.js';
import { ABIS, parseElfDynamic, type ElfSummary } from './native.js';
import { apkSigning, type SigningInfo } from './signing.js';
import { detectLibraries, nativeMethods, obfuscationHints, scanStrings, sensitiveApis, xrefIndex, type LibraryHit, type ObfuscationHints, type NativeMethod, type StringHit } from './dex/analysis.js';
import { isDex, openDex, type DexFile } from './dex/parse.js';
import { findEntries, openZip, readEntry, type ZipArchive } from './zip.js';

export const APK_LIMITS = { maxDexFiles: 128, maxDexBytes: 256 * 1024 * 1024, maxNativeLibBytes: 128 * 1024 * 1024, maxNativeLibs: 400 };

export interface DexSummary { name: string; version: number; size: number; classes: number; methods: number; fields: number; strings: number; types: number }

export interface NativeLib { path: string; abi: string; name: string; size: number; elf?: Pick<ElfSummary, 'machine' | 'bits' | 'soname' | 'needed' | 'jniOnLoad' | 'jniExports' | 'entryPoints' | 'registersNativesDynamically' | 'buildId'> & { exportCount: number }; error?: string }

export interface ApkReport {
  kind: 'apk' | 'aab' | 'xapk' | 'apks';
  manifest?: ManifestInfo;
  manifestError?: string;
  networkSecurityConfig?: NetworkSecurityConfig;
  signing?: SigningInfo;
  dex: DexSummary[];
  nativeLibs: NativeLib[];
  abis: string[];
  frameworks: FrameworkHit[];
  libraries: LibraryHit[];
  obfuscation?: ObfuscationHints;
  apis: { id: string; title: string; category: string; severity: string; target: string; callers: string[] }[];
  urls: StringHit[];
  secrets: StringHit[];
  nativeMethods: NativeMethod[];
  /** native methods declared in DEX with no matching Java_* export in any bundled .so */
  unresolvedNativeMethods: number;
  memberCount: number;
  warnings: string[];
  findings: Finding[];
}

export interface ApkOptions {
  /** decode every DEX and build cross references (slower) */
  deep?: boolean;
  /** inspect lib/<abi>/*.so ELF exports */
  nativeExports?: boolean;
}

/** Path prefix for AAB modules (base/), empty for APKs. */
function modulePrefix(zip: ZipArchive): string {
  if (zip.byName.has('AndroidManifest.xml')) return '';
  if (zip.byName.has('base/manifest/AndroidManifest.xml')) return 'base/';
  return '';
}

export function kindOf(zip: ZipArchive): ApkReport['kind'] {
  if (zip.byName.has('BundleConfig.pb') || zip.byName.has('base/manifest/AndroidManifest.xml')) return 'aab';
  if (zip.byName.has('manifest.json') && zip.entries.some((e) => e.name.endsWith('.apk'))) return 'xapk';
  if (zip.byName.has('toc.pb') && zip.entries.some((e) => e.name.endsWith('.apk'))) return 'apks';
  return 'apk';
}

export async function readResources(zip: ZipArchive): Promise<ResourceTable | undefined> {
  const e = zip.byName.get('resources.arsc');
  if (!e) return undefined;
  try { return parseResourceTable(await readEntry(zip, e, 128 * 1024 * 1024)); } catch { return undefined; }
}

/** Decode AndroidManifest.xml from an APK (binary AXML) and interpret it. */
export async function readManifest(zip: ZipArchive, table?: ResourceTable): Promise<ManifestInfo> {
  const e = zip.byName.get('AndroidManifest.xml');
  if (!e) {
    if (zip.byName.has('base/manifest/AndroidManifest.xml')) throw new ParseError('AAB manifests are protobuf encoded (aapt2 proto format), which this version does not decode');
    throw new ParseError('AndroidManifest.xml not found');
  }
  const bytes = await readEntry(zip, e, 32 * 1024 * 1024);
  if (!isAxml(bytes)) throw new ParseError('AndroidManifest.xml is not binary XML');
  return interpretManifest(parseAxml(bytes), table);
}

/** Decoded manifest as readable XML text. */
export async function manifestXml(zip: ZipArchive): Promise<string> {
  const bytes = await readEntry(zip, 'AndroidManifest.xml', 32 * 1024 * 1024);
  return axmlToXml(parseAxml(bytes));
}

/** classes.dex, classes2.dex ... in load order, plus AAB base/dex and other module dex files. */
export function dexEntries(zip: ZipArchive): string[] {
  const names = zip.entries.map((e) => e.name).filter((n) => /^(?:[^/]+\/dex\/)?classes\d*\.dex$/.test(n));
  const num = (n: string): number => { const m = /classes(\d*)\.dex$/.exec(n); return m && m[1] ? Number(m[1]) : 1; };
  return names.sort((a, b) => (a.includes('/') ? 1 : 0) - (b.includes('/') ? 1 : 0) || num(a) - num(b)).slice(0, APK_LIMITS.maxDexFiles);
}

export async function loadDexes(zip: ZipArchive): Promise<DexFile[]> {
  const out: DexFile[] = [];
  let total = 0;
  for (const name of dexEntries(zip)) {
    const b = await readEntry(zip, name, APK_LIMITS.maxDexBytes);
    total += b.length;
    if (total > APK_LIMITS.maxDexBytes * 2) break;
    if (!isDex(b)) continue;
    out.push(...openDex(b, name));
  }
  return out;
}

function finding(id: string, title: string, severity: Severity, detail: string, path?: string, tags: string[] = [], attack?: string[]): Finding {
  const f: Finding = { id: `mobile.${id}`, analyzer: 'mobile-apk', title, severity, detail, evidence: path ? [{ path }] : [], tags: ['android', ...tags] };
  if (attack) f.attack = attack;
  return f;
}

/** Security findings from the manifest alone. */
export function manifestFindings(m: ManifestInfo, nsc?: NetworkSecurityConfig): Finding[] {
  const out: Finding[] = [];
  const P = 'AndroidManifest.xml';
  const a = m.application;
  if (a.debuggable) out.push(finding('debuggable', 'App is debuggable', 'high', 'android:debuggable="true" lets anyone attach a debugger and run code as the app through run-as.', P, ['manifest']));
  if (a.testOnly) out.push(finding('test-only', 'App is marked testOnly', 'medium', 'android:testOnly="true" means this is a test build, not a release build.', P, ['manifest']));
  if (a.allowBackup && (m.targetSdk ?? 0) < 31) out.push(finding('allow-backup', 'App data can be backed up with adb', 'low', a.allowBackupDefault ? 'android:allowBackup is not set and the default is true, so adb backup can copy private app data.' : 'android:allowBackup="true" lets adb backup copy private app data.', P, ['manifest']));
  if (a.usesCleartextTraffic === true) out.push(finding('cleartext', 'Cleartext HTTP traffic is allowed', 'medium', 'android:usesCleartextTraffic="true" permits unencrypted HTTP.', P, ['manifest', 'network']));
  else if (a.usesCleartextTraffic === undefined && (m.targetSdk ?? 0) < 28 && !nsc) out.push(finding('cleartext-default', 'Cleartext HTTP allowed by default (targetSdk below 28)', 'low', 'Apps targeting API 27 or lower allow cleartext traffic unless a network security config says otherwise.', P, ['manifest', 'network']));
  if (nsc) {
    if (nsc.baseCleartextPermitted) out.push(finding('nsc-cleartext', 'Network security config permits cleartext by default', 'medium', 'base-config cleartextTrafficPermitted="true".', a.networkSecurityConfigPath, ['network']));
    if (nsc.trustsUserCerts) out.push(finding('nsc-user-ca', 'Network security config trusts user-installed CAs', 'medium', 'base-config trust-anchors include user certificates, which makes TLS interception easy.', a.networkSecurityConfigPath, ['network']));
    const pins = nsc.domains.reduce((s, d) => s + d.pins, 0);
    if (pins) out.push(finding('nsc-pinning', 'Certificate pinning configured', 'info', `${pins} pin(s) across ${nsc.domains.length} domain config(s).`, a.networkSecurityConfigPath, ['network']));
  }
  if (m.sharedUserId) out.push(finding('shared-uid', 'Uses android:sharedUserId', 'low', `sharedUserId=${m.sharedUserId} shares a Linux UID with other apps from the same signer.`, P, ['manifest']));
  for (const c of m.components) {
    if (!c.exported || c.launcher || c.enabled === false) continue;
    const guarded = !!(c.permission || (c.kind === 'provider' && c.readPermission && c.writePermission));
    if (guarded) continue;
    const sev: Severity = c.kind === 'provider' ? 'medium' : 'low';
    out.push(finding(`exported-${c.kind}`, `Exported ${c.kind} without a permission: ${c.name}`, sev, `${c.kind} ${c.name} is exported (${c.exportedReason}) and not protected by a permission, so any app can reach it.`, P, ['manifest', 'attack-surface']));
  }
  const dangerous = m.permissions.filter((p) => p.level === 'dangerous' || p.level === 'special' || p.level === 'signature');
  if (dangerous.length) out.push(finding('dangerous-permissions', `${dangerous.length} sensitive permission(s) requested`, 'info', dangerous.map((p) => `${p.name} (${p.level}): ${p.note}`).join('; '), P, ['manifest', 'permissions']));
  for (const d of m.deepLinks.filter((x) => (x.scheme === 'http' || x.scheme === 'https') && !x.autoVerify).slice(0, 20)) {
    out.push(finding('unverified-app-link', `Web link not auto-verified: ${d.url}`, 'low', `${d.component} handles ${d.url} without android:autoVerify, so other apps can claim the same links.`, P, ['manifest', 'deeplink']));
  }
  if (m.targetSdk !== undefined && m.targetSdk < 28) out.push(finding('old-target-sdk', `Old targetSdkVersion ${m.targetSdk}`, 'low', 'Old target SDK levels opt out of newer platform protections.', P, ['manifest']));
  return out;
}

export function signingFindings(s: SigningInfo, minSdk?: number): Finding[] {
  const out: Finding[] = [];
  if (!s.v1.present && !s.v2.present && !s.v3.present && !s.v31.present) out.push(finding('unsigned', 'APK is not signed', 'medium', 'No v1 signature files and no APK Signing Block were found.', undefined, ['signing']));
  if (s.v1.present && !s.v2.present && !s.v3.present && (minSdk ?? 1) < 24) out.push(finding('janus', 'Only v1 (JAR) signing on a minSdk below 24', 'medium', 'Without v2 or v3 signatures, devices on Android 7.0 and older are open to the Janus issue (CVE-2017-13156).', undefined, ['signing']));
  const certs = [...s.v1.certificates, ...s.v2.signers.flatMap((x) => x.certificates), ...s.v3.signers.flatMap((x) => x.certificates)];
  if (certs.some((c) => /CN=Android Debug/.test(c.subject))) out.push(finding('debug-cert', 'Signed with the Android debug certificate', 'medium', 'The signer subject is CN=Android Debug, a build machine debug key.', undefined, ['signing']));
  return out;
}

/** Full APK analysis. */
export async function analyzeApk(input: Uint8Array | ZipArchive, opts: ApkOptions = {}): Promise<ApkReport> {
  const zip = input instanceof Uint8Array ? openZip(input) : input;
  const report: ApkReport = {
    kind: kindOf(zip), dex: [], nativeLibs: [], abis: [], frameworks: [], libraries: [], apis: [], urls: [], secrets: [],
    nativeMethods: [], unresolvedNativeMethods: 0, memberCount: zip.entries.length, warnings: [], findings: [],
  };
  const table = await readResources(zip);
  try {
    report.manifest = await readManifest(zip, table);
    const nscPath = report.manifest.application.networkSecurityConfigPath;
    if (nscPath && zip.byName.has(nscPath)) {
      try { report.networkSecurityConfig = interpretNetworkSecurityConfig(parseAxml(await readEntry(zip, nscPath, 4 * 1024 * 1024))); }
      catch (err) { report.warnings.push(`${nscPath}: ${(err as Error).message}`); }
    }
    report.findings.push(...manifestFindings(report.manifest, report.networkSecurityConfig));
  } catch (err) { report.manifestError = (err as Error).message; }

  try {
    report.signing = await apkSigning(zip);
    report.findings.push(...signingFindings(report.signing, report.manifest?.minSdk));
  } catch (err) { report.warnings.push(`signing: ${(err as Error).message}`); }

  // native libraries
  const prefix = modulePrefix(zip);
  const libs = findEntries(zip, (n) => /^(?:[^/]+\/)?lib\/[^/]+\/[^/]+\.so$/.test(n), APK_LIMITS.maxNativeLibs);
  const abis = new Set<string>();
  for (const e of libs) {
    const parts = e.name.split('/');
    const abi = parts[parts.length - 2] as string;
    abis.add(abi);
    const lib: NativeLib = { path: e.name, abi, name: parts[parts.length - 1] as string, size: e.size };
    if (opts.nativeExports !== false && e.size <= APK_LIMITS.maxNativeLibBytes) {
      try {
        const elf = parseElfDynamic(await readEntry(zip, e, APK_LIMITS.maxNativeLibBytes));
        lib.elf = { machine: elf.machine, bits: elf.bits, needed: elf.needed, jniOnLoad: elf.jniOnLoad, jniExports: elf.jniExports.slice(0, 500), entryPoints: elf.entryPoints, registersNativesDynamically: elf.registersNativesDynamically, exportCount: elf.exports.length };
        if (elf.soname) lib.elf.soname = elf.soname;
        if (elf.buildId) lib.elf.buildId = elf.buildId;
      } catch (err) { lib.error = (err as Error).message; }
    }
    report.nativeLibs.push(lib);
  }
  report.abis = [...abis].sort((a, b) => (ABIS.indexOf(a) + 1 || 99) - (ABIS.indexOf(b) + 1 || 99));
  void prefix;

  // frameworks
  const names = zip.entries.map((e) => e.name);
  report.frameworks = detectFrameworks(names, { nativeActivity: report.manifest?.components.some((c) => c.name === 'android.app.NativeActivity') && dexEntries(zip).length === 0 });
  const fl = report.frameworks.find((f) => f.id === 'flutter');
  if (fl) {
    const libapp = libs.find((l) => l.name.endsWith('/libapp.so'));
    if (libapp && libapp.size <= APK_LIMITS.maxNativeLibBytes) {
      try { fl.details = { ...dartSnapshotInfo(await readEntry(zip, libapp, APK_LIMITS.maxNativeLibBytes)), libapp: libapp.name }; } catch { /* optional */ }
    }
  }
  const rn = report.frameworks.find((f) => f.id === 'react-native');
  if (rn && zip.byName.has('assets/index.android.bundle')) {
    try { rn.details = { bundle: 'assets/index.android.bundle', ...reactNativeBundleInfo(await readEntry(zip, 'assets/index.android.bundle', 256 * 1024 * 1024)) }; } catch { /* optional */ }
  }

  // DEX
  let dexes: DexFile[] = [];
  try { dexes = await loadDexes(zip); } catch (err) { report.warnings.push(`dex: ${(err as Error).message}`); }
  const allClasses: string[] = [];
  for (const d of dexes) {
    report.dex.push({ name: d.name, version: d.version, size: d.header.fileSize, classes: d.classCount, methods: d.methodCount, fields: d.fieldCount, strings: d.stringCount, types: d.typeCount });
    for (const c of d.classes) allClasses.push(c.name);
  }
  report.libraries = detectLibraries(allClasses);
  const markerStrings: string[] = [];
  for (const d of dexes) for (let i = 0; i < Math.min(d.stringCount, 64); i++) markerStrings.push(d.string(i));
  if (dexes.length) report.obfuscation = obfuscationHints(allClasses, markerStrings);
  const jniExports = new Set(report.nativeLibs.flatMap((l) => l.elf?.jniExports ?? []));
  for (const d of dexes) report.nativeMethods.push(...nativeMethods(d, 2000));
  report.unresolvedNativeMethods = report.nativeMethods.filter((n) => !jniExports.has(n.jni) && !jniExports.has(n.jniLong)).length;
  if (opts.deep !== false) {
    for (const d of dexes) {
      const idx = xrefIndex(d);
      for (const hit of sensitiveApis(idx)) {
        report.apis.push({ id: hit.rule.id, title: hit.rule.title, category: hit.rule.category, severity: hit.rule.severity, target: hit.target, callers: hit.callers.map((c) => c.ref) });
      }
      const s = scanStrings(d, idx, 500);
      report.urls.push(...s.urls);
      report.secrets.push(...s.secrets);
    }
    const byRule = new Map<string, typeof report.apis>();
    for (const a of report.apis) { const l = byRule.get(a.id) ?? []; l.push(a); byRule.set(a.id, l); }
    for (const [id, hits] of byRule) {
      const first = hits[0] as (typeof report.apis)[number];
      if (first.severity === 'info') continue;
      const callers = hits.flatMap((h) => h.callers).slice(0, 10);
      report.findings.push(finding(`api.${id}`, first.title, first.severity as Severity, `Called from ${callers.length} place(s): ${callers.join(', ')}`, undefined, ['dex', first.category]));
    }
    for (const s of report.secrets.slice(0, 50)) {
      report.findings.push(finding(`secret.${s.kind}`, `Hardcoded ${s.title}`, s.severity as Severity, `${s.value.slice(0, 12)}... used in ${s.users.map((u) => u.ref).slice(0, 5).join(', ') || 'no method found'}`, undefined, ['dex', 'secret']));
    }
  }
  for (const lib of report.libraries.filter((l) => l.category === 'packer')) {
    report.findings.push(finding('packer', `Packer or protector: ${lib.name}`, 'medium', `${lib.classes} class(es) under ${lib.prefix}. The real code is probably encrypted and loaded at runtime.`, undefined, ['dex', 'packer'], ['T1406']));
  }
  if (report.obfuscation?.likelyObfuscated) report.findings.push(finding('obfuscated', 'Code looks obfuscated', 'info', report.obfuscation.notes.join('; '), undefined, ['dex']));
  if (report.unresolvedNativeMethods > 0 && report.nativeLibs.length > 0) {
    report.findings.push(finding('jni-dynamic', 'Native methods without matching Java_* exports', 'info', `${report.unresolvedNativeMethods} native method(s) have no static JNI export, so they are probably bound with RegisterNatives in JNI_OnLoad.`, undefined, ['native']));
  }
  return report;
}
