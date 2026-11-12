// MSIX and APPX packages (and their bundles): AppxManifest identity, dependencies, capabilities and
// applications, the AppxBlockMap with every 64 KiB block hash recomputed, the signature and code
// integrity catalog, and the content types file. Nothing is installed.

import { readZip, readZipMember, type ZipMember } from './zip.js';
import { parseXml, child, childrenNamed, findAll, findFirst, type XmlNode } from './xml.js';
import { base64Decode, toHex } from './util.js';
import { sha256 } from '../hash.js';
import { decodeUtf8 } from '../bytes.js';

/** Capabilities that need Microsoft approval for Store apps or grant broad access. */
const RESTRICTED = new Set(['runFullTrust', 'allowElevation', 'broadFileSystemAccess', 'packageManagement', 'packageQuery', 'confirmAppClose', 'unvirtualizedResources', 'localSystemServices', 'inputInjectionBrokered', 'inputObservation', 'inputSuppression', 'appDiagnostics', 'deviceUnlock', 'enterpriseAuthentication', 'sharedUserCertificates', 'documentsLibrary', 'userDataTasks', 'extendedExecutionUnconstrained', 'smbios', 'cellularDeviceControl', 'networkingVpnProvider', 'protectedApp', 'previewStore', 'customInstallActions', 'packagedServices', 'modifiableApp', 'uiAutomation', 'unvirtualizedResourcesForNonAdminUsers']);

export interface MsixReport {
  format: 'msix' | 'appx' | 'msixbundle' | 'appxbundle';
  bundle: boolean;
  zip64: boolean;
  memberCount: number;
  identity?: { name?: string; publisher?: string; version?: string; processorArchitecture?: string; resourceId?: string; publisherId?: string };
  properties?: { displayName?: string; publisherDisplayName?: string; description?: string; logo?: string; framework?: boolean; resourcePackage?: boolean };
  targetDeviceFamilies: { name?: string; minVersion?: string; maxVersionTested?: string }[];
  packageDependencies: { name?: string; minVersion?: string; publisher?: string }[];
  capabilities: { name: string; namespace: string; restricted: boolean }[];
  applications: { id?: string; executable?: string; entryPoint?: string; displayName?: string; trustLevel?: string; runtimeBehavior?: string; extensions: string[] }[];
  /** packages listed by a bundle manifest */
  bundlePackages?: { type?: string; architecture?: string; fileName?: string; version?: string; size?: number; offset?: number; resourceId?: string }[];
  blockMap?: { hashMethod: string; files: number; blocks: number; verifiedFiles: number; verifiedBlocks: number; mismatches: { file: string; block: number; reason: string }[]; sizeMismatches: string[]; missing: string[]; unlisted: string[]; skippedBytes: number };
  signature: { present: boolean; size?: number; magicOk?: boolean; sha256?: string };
  codeIntegrity: boolean;
  contentTypes: boolean;
  findings: { id: string; severity: 'info' | 'low' | 'medium' | 'high'; title: string; detail: string; path?: string }[];
  warnings: string[];
}

const BLOCK = 65536;

function blockMapPath(name: string): string { return name.replace(/\//g, '\\'); }

/** True when a ZIP holds an APPX style manifest. */
export function isMsixZip(names: string[]): 'package' | 'bundle' | null {
  if (names.includes('AppxManifest.xml')) return 'package';
  if (names.includes('AppxMetadata/AppxBundleManifest.xml')) return 'bundle';
  return null;
}

/** Inspect an MSIX, APPX or bundle. verifyBytes caps how many uncompressed bytes are hashed. */
export async function inspectMsix(bytes: Uint8Array, opts: { name?: string; verifyBlocks?: boolean; verifyBytes?: number } = {}): Promise<MsixReport> {
  const zip = readZip(bytes);
  const names = zip.members.map((m) => m.name);
  const kind = isMsixZip(names);
  const lower = (opts.name ?? '').toLowerCase();
  const bundle = kind === 'bundle';
  const format: MsixReport['format'] = bundle ? (lower.endsWith('.appxbundle') ? 'appxbundle' : 'msixbundle') : lower.endsWith('.appx') ? 'appx' : 'msix';
  const byName = new Map<string, ZipMember>(zip.members.map((m) => [m.name, m]));
  const rep: MsixReport = { format, bundle, zip64: zip.zip64, memberCount: zip.members.length, targetDeviceFamilies: [], packageDependencies: [], capabilities: [], applications: [], signature: { present: false }, codeIntegrity: byName.has('AppxMetadata/CodeIntegrity.cat'), contentTypes: byName.has('[Content_Types].xml'), findings: [], warnings: [] };
  const xmlOf = async (n: string): Promise<XmlNode | undefined> => { const m = byName.get(n); if (!m) return undefined; try { return parseXml(decodeUtf8(await readZipMember(bytes, m, 32 * 1024 * 1024)).replace(/^\uFEFF/, '')); } catch (e) { rep.warnings.push(`${n}: ${(e as Error).message}`); return undefined; } };
  const doc = await xmlOf(bundle ? 'AppxMetadata/AppxBundleManifest.xml' : 'AppxManifest.xml');
  if (!doc) rep.warnings.push('no AppxManifest.xml or AppxBundleManifest.xml');
  if (doc) {
    const id = findFirst(doc, 'Identity');
    if (id) rep.identity = { name: id.attrs.Name, publisher: id.attrs.Publisher, version: id.attrs.Version, processorArchitecture: id.attrs.ProcessorArchitecture, resourceId: id.attrs.ResourceId };
    if (bundle) {
      rep.bundlePackages = findAll(doc, 'Package').filter((p) => p.attrs.FileName).map((p) => ({ type: p.attrs.Type, architecture: p.attrs.Architecture, fileName: p.attrs.FileName, version: p.attrs.Version, size: p.attrs.Size ? Number(p.attrs.Size) : undefined, offset: p.attrs.Offset ? Number(p.attrs.Offset) : undefined, resourceId: p.attrs.ResourceId }));
    } else {
      const props = findFirst(doc, 'Properties');
      if (props) rep.properties = { displayName: child(props, 'DisplayName')?.text.trim(), publisherDisplayName: child(props, 'PublisherDisplayName')?.text.trim(), description: child(props, 'Description')?.text.trim(), logo: child(props, 'Logo')?.text.trim(), framework: child(props, 'Framework')?.text.trim() === 'true', resourcePackage: child(props, 'ResourcePackage')?.text.trim() === 'true' };
      const deps = findFirst(doc, 'Dependencies');
      rep.targetDeviceFamilies = childrenNamed(deps, 'TargetDeviceFamily').map((t) => ({ name: t.attrs.Name, minVersion: t.attrs.MinVersion, maxVersionTested: t.attrs.MaxVersionTested }));
      rep.packageDependencies = childrenNamed(deps, 'PackageDependency').map((t) => ({ name: t.attrs.Name, minVersion: t.attrs.MinVersion, publisher: t.attrs.Publisher }));
      const caps = findFirst(doc, 'Capabilities');
      for (const c of caps?.children ?? []) {
        const name = c.attrs.Name ?? '';
        if (!name) continue;
        const ns = c.name.includes(':') ? c.name.slice(0, c.name.indexOf(':')) : '';
        const restricted = ns === 'rescap' || RESTRICTED.has(name);
        rep.capabilities.push({ name, namespace: ns || 'default', restricted });
      }
      for (const a of findAll(doc, 'Application')) {
        const ve = findFirst(a, 'VisualElements');
        rep.applications.push({ id: a.attrs.Id, executable: a.attrs.Executable, entryPoint: a.attrs.EntryPoint, displayName: ve?.attrs.DisplayName, trustLevel: a.attrs['uap10:TrustLevel'], runtimeBehavior: a.attrs['uap10:RuntimeBehavior'], extensions: [...new Set(findAll(a, 'Extension').map((e) => e.attrs.Category ?? '').filter(Boolean))] });
      }
      const rc = rep.capabilities.filter((c) => c.restricted).map((c) => c.name);
      if (rc.includes('runFullTrust')) rep.findings.push({ id: 'msix.full-trust', severity: 'low', title: 'Runs with full trust', detail: 'runFullTrust: the app is a desktop app with the user\'s full rights, not sandboxed in an app container.', path: 'AppxManifest.xml' });
      if (rc.includes('allowElevation')) rep.findings.push({ id: 'msix.elevation', severity: 'medium', title: 'May elevate to administrator', detail: 'allowElevation lets the app request administrator rights.', path: 'AppxManifest.xml' });
      const other = rc.filter((x) => x !== 'runFullTrust' && x !== 'allowElevation');
      if (other.length) rep.findings.push({ id: 'msix.restricted-capabilities', severity: 'low', title: 'Restricted capabilities', detail: other.join(', '), path: 'AppxManifest.xml' });
    }
  }
  const sig = byName.get('AppxSignature.p7x');
  if (sig) {
    const s = await readZipMember(bytes, sig, 16 * 1024 * 1024).catch(() => undefined);
    rep.signature = { present: true, size: sig.size, ...(s ? { magicOk: s.length > 4 && s[0] === 0x50 && s[1] === 0x4b && s[2] === 0x43 && s[3] === 0x58, sha256: sha256(s) } : {}) };
  } else rep.findings.push({ id: 'msix.unsigned', severity: 'low', title: 'Package is not signed', detail: 'No AppxSignature.p7x; Windows installs it only in developer mode or after signing.' });
  // Block map
  const bmDoc = await xmlOf('AppxBlockMap.xml');
  if (bmDoc) {
    const bm = findFirst(bmDoc, 'BlockMap');
    const files = childrenNamed(bm, 'File');
    const zipByBm = new Map<string, ZipMember>(zip.members.map((m) => [blockMapPath(m.name), m]));
    const summary = { hashMethod: bm?.attrs.HashMethod ?? '', files: files.length, blocks: 0, verifiedFiles: 0, verifiedBlocks: 0, mismatches: [] as { file: string; block: number; reason: string }[], sizeMismatches: [] as string[], missing: [] as string[], unlisted: [] as string[], skippedBytes: 0 };
    let budget = opts.verifyBytes ?? 512 * 1024 * 1024;
    const listed = new Set<string>();
    const sha = summary.hashMethod.toLowerCase().includes('sha256');
    for (const f of files) {
      const name = f.attrs.Name ?? '';
      listed.add(name);
      const blocks = childrenNamed(f, 'Block');
      summary.blocks += blocks.length;
      const m = zipByBm.get(name);
      if (!m) { summary.missing.push(name); continue; }
      const size = Number(f.attrs.Size ?? -1);
      if (size !== m.size) summary.sizeMismatches.push(`${name}: block map ${size}, zip ${m.size}`);
      if (f.attrs.LfhSize && Number(f.attrs.LfhSize) !== m.localHeaderSize) summary.sizeMismatches.push(`${name}: LfhSize ${f.attrs.LfhSize}, local header ${m.localHeaderSize}`);
      if (opts.verifyBlocks === false || !sha) continue;
      if (m.size > budget) { summary.skippedBytes += m.size; continue; }
      let data: Uint8Array;
      try { data = await readZipMember(bytes, m, budget); } catch (e) { summary.mismatches.push({ file: name, block: -1, reason: (e as Error).message }); continue; }
      budget -= data.length;
      const want = Math.ceil(data.length / BLOCK);
      if (want !== blocks.length) summary.mismatches.push({ file: name, block: -1, reason: `${blocks.length} blocks listed, ${want} expected` });
      let ok = true;
      for (let i = 0; i < blocks.length && i * BLOCK < Math.max(1, data.length); i++) {
        const expect = toHex(base64Decode((blocks[i] as XmlNode).attrs.Hash ?? ''));
        const got = sha256(data.subarray(i * BLOCK, Math.min(data.length, (i + 1) * BLOCK)));
        if (expect !== got) { ok = false; summary.mismatches.push({ file: name, block: i, reason: 'hash differs' }); }
        else summary.verifiedBlocks++;
      }
      if (ok) summary.verifiedFiles++;
    }
    const meta = new Set(['AppxBlockMap.xml', 'AppxSignature.p7x', '[Content_Types].xml', 'AppxMetadata/CodeIntegrity.cat']);
    for (const m of zip.members) if (!m.name.endsWith('/') && !meta.has(m.name) && !listed.has(blockMapPath(m.name))) summary.unlisted.push(m.name);
    rep.blockMap = summary;
    if (summary.mismatches.length || summary.missing.length || summary.unlisted.length || summary.sizeMismatches.length) rep.findings.push({ id: 'msix.blockmap', severity: 'high', title: 'Block map does not match the package', detail: `${summary.mismatches.length} hash problems, ${summary.missing.length} missing, ${summary.unlisted.length} unlisted and ${summary.sizeMismatches.length} size problems. The package was changed after it was built.`, path: 'AppxBlockMap.xml' });
  } else if (!bundle) rep.warnings.push('no AppxBlockMap.xml');
  return rep;
}
