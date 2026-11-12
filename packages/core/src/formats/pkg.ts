// macOS flat installer packages (.pkg): a xar archive holding a Distribution file (product archives),
// and per component PackageInfo, Bom, Scripts and Payload. Scripts and Payload are gzip or pbzx
// compressed cpio streams. Nothing is installed or run.

import { parseXar, readXarFile, type XarArchive, type XarFile } from './xar.js';
import { parseXml, child, childrenNamed, findAll, findFirst } from './xml.js';
import { parseBom, type BomEntry } from './bom.js';
import { listCpio, isCpio, type CpioEntry } from './cpio.js';
import { decompress } from '../archive/inflate.js';
import { bunzip2 } from './bzip2.js';
import { decodeUtf8 } from '../bytes.js';
import { sha256 } from '../hash.js';

export interface PkgScript { name: string; size: number; mode: string; sha256: string; interpreter: string; indicators: string[]; preview: string }
export interface PkgComponent {
  /** folder inside the xar, empty for a component package at the top level */
  prefix: string;
  packageInfo?: { identifier?: string; version?: string; installLocation?: string; auth?: string; formatVersion?: string; relocatable?: boolean; payload?: { numberOfFiles?: number; installKBytes?: number }; scripts: Record<string, string>; bundles: { id?: string; path?: string; version?: string }[] };
  bom?: { pathCount: number; files: number; dirs: number; links: number; totalSize: number; entries: BomEntry[]; truncated: boolean; warnings: string[] };
  scripts?: { encoding: string; entries: PkgScript[]; error?: string };
  payload?: { size: number; storedSize: number; container: string; entries?: CpioEntry[]; truncated?: boolean; error?: string };
}
export interface PkgReport {
  format: 'pkg';
  kind: 'product' | 'component' | 'unknown';
  xar: Omit<XarArchive, 'files' | 'toc'> & { fileCount: number };
  files: { path: string; type: string; size: number; length: number; encoding: string; archivedMatches: boolean | null; extractedMatches: boolean | null }[];
  distribution?: { title?: string; minSpecVersion?: string; hostArchitectures?: string; pkgRefs: { id?: string; version?: string; installKBytes?: string; href?: string }[]; choices: number; scripts: number; scriptPreview?: string; installationCheck?: string; volumeCheck?: string; allowExternalScripts: boolean };
  components: PkgComponent[];
  findings: { id: string; severity: 'info' | 'low' | 'medium' | 'high'; title: string; detail: string; path?: string }[];
  warnings: string[];
}

/** Risky shell patterns in install scripts. Plain substring tests, no regex on untrusted text. */
const INDICATORS: [string, string][] = [
  ['curl ', 'downloads with curl'], ['wget ', 'downloads with wget'], ['| sh', 'pipes into a shell'], ['| bash', 'pipes into a shell'],
  ['launchctl', 'loads launchd jobs'], ['LaunchDaemons', 'installs a launch daemon'], ['LaunchAgents', 'installs a launch agent'],
  ['chmod +s', 'sets a setuid bit'], ['chmod 4', 'sets a setuid bit'], ['xattr -d com.apple.quarantine', 'removes quarantine'],
  ['spctl', 'changes Gatekeeper'], ['csrutil', 'touches System Integrity Protection'], ['osascript', 'runs AppleScript'],
  ['sudoers', 'edits sudoers'], ['kextload', 'loads a kernel extension'], ['systemextensionsctl', 'manages system extensions'],
  ['base64 -d', 'decodes base64'], ['base64 --decode', 'decodes base64'], ['eval ', 'uses eval'], ['rm -rf /', 'removes from the root'],
  ['tccutil', 'resets privacy permissions'], ['security add-trusted-cert', 'adds a trusted certificate'], ['/tmp/', 'uses /tmp'],
];

function scriptInfo(name: string, mode: number, data: Uint8Array): PkgScript {
  const text = decodeUtf8(data.subarray(0, Math.min(data.length, 1 << 20)));
  const first = text.slice(0, text.indexOf('\n') < 0 ? Math.min(text.length, 200) : Math.min(text.indexOf('\n'), 200));
  const interpreter = first.startsWith('#!') ? first.slice(2).trim() : '';
  const indicators: string[] = [];
  for (const [needle, label] of INDICATORS) if (text.includes(needle) && !indicators.includes(label)) indicators.push(label);
  return { name, size: data.length, mode: (mode & 0o7777).toString(8), sha256: sha256(data), interpreter, indicators, preview: text.slice(0, 600) };
}

async function unwrap(data: Uint8Array, maxBytes: number): Promise<{ bytes: Uint8Array; container: string }> {
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) return { bytes: await decompress(data, 'gzip', maxBytes), container: 'gzip+cpio' };
  if (data.length >= 3 && data[0] === 0x42 && data[1] === 0x5a && data[2] === 0x68) return { bytes: bunzip2(data, maxBytes), container: 'bzip2+cpio' };
  if (data.length >= 4 && data[0] === 0x70 && data[1] === 0x62 && data[2] === 0x7a && data[3] === 0x78) return { bytes: new Uint8Array(0), container: 'pbzx' };
  if (data.length >= 6 && data[0] === 0xfd && data[1] === 0x37) return { bytes: new Uint8Array(0), container: 'xz' };
  return { bytes: data, container: isCpio(data) ? 'cpio' : 'unknown' };
}

/** Inspect a flat package. maxEntries caps the Bom and payload listings. */
export async function inspectPkg(bytes: Uint8Array, opts: { maxEntries?: number; maxMemberBytes?: number; listPayload?: boolean } = {}): Promise<PkgReport> {
  const maxEntries = opts.maxEntries ?? 5000, maxMember = opts.maxMemberBytes ?? 64 * 1024 * 1024;
  const xar = await parseXar(bytes);
  const { files, toc: _toc, ...xrest } = xar;
  const report: PkgReport = { format: 'pkg', kind: 'unknown', xar: { ...xrest, fileCount: files.length }, files: [], components: [], findings: [], warnings: [...xar.warnings] };
  const byPath = new Map<string, XarFile>(files.map((f) => [f.path, f]));
  const cache = new Map<string, { data: Uint8Array; a: boolean | null; e: boolean | null }>();
  const read = async (f: XarFile): Promise<Uint8Array | undefined> => {
    if (cache.has(f.path)) return cache.get(f.path)?.data;
    if (f.size > maxMember) { report.warnings.push(`${f.path} is ${f.size} bytes, over the member limit; not read`); return undefined; }
    try { const r = await readXarFile(bytes, f, { maxBytes: maxMember }); cache.set(f.path, { data: r.data, a: r.archivedMatches, e: r.extractedMatches }); return r.data; } catch (e) { report.warnings.push(`${f.path}: ${(e as Error).message}`); return undefined; }
  };
  if (xar.tocChecksum?.matches === false) report.findings.push({ id: 'pkg.toc-checksum', severity: 'high', title: 'Table of contents checksum does not match', detail: 'The xar TOC hash stored in the heap differs from the hash of the TOC; the package was altered after it was built.' });
  if (!xar.signatures.length) report.findings.push({ id: 'pkg.unsigned', severity: 'low', title: 'Package is not signed', detail: 'No xar signature or x-signature element; macOS Gatekeeper will warn before installing it.' });
  // Distribution
  const dist = byPath.get('Distribution');
  if (dist) {
    report.kind = 'product';
    const d = await read(dist);
    if (d) {
      const doc = parseXml(decodeUtf8(d));
      const gi = findFirst(doc, 'installer-gui-script') ?? findFirst(doc, 'installer-script');
      const scripts = findAll(doc, 'script');
      const opt = findFirst(doc, 'options');
      const scriptText = scripts.map((s) => s.text).join('\n');
      report.distribution = {
        title: findFirst(doc, 'title')?.text.trim(), minSpecVersion: gi?.attrs.minSpecVersion, hostArchitectures: opt?.attrs.hostArchitectures,
        pkgRefs: findAll(doc, 'pkg-ref').map((r) => ({ id: r.attrs.id, version: r.attrs.version, installKBytes: r.attrs.installKBytes, href: r.text.trim() || undefined })),
        choices: findAll(doc, 'choice').length, scripts: scripts.length, scriptPreview: scriptText ? scriptText.slice(0, 600) : undefined,
        installationCheck: findFirst(doc, 'installation-check')?.attrs.script, volumeCheck: findFirst(doc, 'volume-check')?.attrs.script,
        allowExternalScripts: opt?.attrs['allow-external-scripts'] === 'true' || opt?.attrs['allow-external-scripts'] === 'yes',
      };
      if (report.distribution.allowExternalScripts) report.findings.push({ id: 'pkg.external-scripts', severity: 'medium', title: 'Distribution allows external scripts', detail: 'allow-external-scripts lets the installer JavaScript run system.run with helper tools.', path: 'Distribution' });
      if (scriptText.includes('system.run')) report.findings.push({ id: 'pkg.distribution-system-run', severity: 'medium', title: 'Installer JavaScript calls system.run', detail: 'The Distribution script runs a command while the installer evaluates checks.', path: 'Distribution' });
    }
  }
  // Components: every folder (or the top level) holding PackageInfo.
  const prefixes = files.filter((f) => f.name === 'PackageInfo').map((f) => (f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : ''));
  if (!dist && prefixes.length) report.kind = 'component';
  for (const prefix of prefixes) {
    const at = (n: string): XarFile | undefined => byPath.get(prefix ? `${prefix}/${n}` : n);
    const comp: PkgComponent = { prefix };
    const pi = at('PackageInfo');
    if (pi) {
      const d = await read(pi);
      if (d) {
        const doc = parseXml(decodeUtf8(d));
        const p = findFirst(doc, 'pkg-info');
        const pay = child(p, 'payload');
        const sc = child(p, 'scripts');
        const scripts: Record<string, string> = {};
        for (const s of sc?.children ?? []) if (s.attrs.file) scripts[s.local] = s.attrs.file;
        comp.packageInfo = {
          identifier: p?.attrs.identifier, version: p?.attrs.version, installLocation: p?.attrs['install-location'], auth: p?.attrs.auth, formatVersion: p?.attrs['format-version'],
          relocatable: child(p, 'relocate') !== undefined,
          payload: pay ? { numberOfFiles: pay.attrs.numberOfFiles ? Number(pay.attrs.numberOfFiles) : undefined, installKBytes: pay.attrs.installKBytes ? Number(pay.attrs.installKBytes) : undefined } : undefined,
          scripts, bundles: findAll(doc, 'bundle').map((b) => ({ id: b.attrs.id, path: b.attrs.path, version: b.attrs.CFBundleShortVersionString ?? b.attrs.CFBundleVersion })),
        };
        if (p?.attrs.auth?.toLowerCase() === 'root') report.findings.push({ id: `pkg.root-auth@${prefix || '.'}`, severity: 'info', title: 'Component installs as root', detail: 'auth="root": its scripts and payload run and land with root rights.', path: pi.path });
      }
    }
    const bomF = at('Bom');
    if (bomF) {
      const d = await read(bomF);
      if (d) {
        try {
          const b = parseBom(d, { maxEntries });
          comp.bom = { pathCount: b.pathCount, files: b.entries.filter((e) => e.type === 'file').length, dirs: b.entries.filter((e) => e.type === 'dir').length, links: b.entries.filter((e) => e.type === 'link').length, totalSize: b.entries.reduce((a, e) => a + (e.type === 'file' ? e.size : 0), 0), entries: b.entries, truncated: b.truncated, warnings: b.warnings };
          for (const e of b.entries) {
            if (e.type === 'file' && (e.mode & 0o4000)) { report.findings.push({ id: `pkg.setuid@${e.path}`, severity: 'medium', title: 'Installs a setuid file', detail: `${e.path} has mode ${(e.mode & 0o7777).toString(8)} owned by uid ${e.uid}.`, path: bomF.path }); break; }
          }
          if (b.entries.some((e) => e.path.includes('/LaunchDaemons/'))) report.findings.push({ id: `pkg.launchdaemon@${prefix || '.'}`, severity: 'low', title: 'Installs a launch daemon', detail: 'The Bom lists a file under LaunchDaemons, which runs as root at boot.', path: bomF.path });
        } catch (e) { report.warnings.push(`${bomF.path}: ${(e as Error).message}`); }
      }
    }
    const scF = at('Scripts');
    if (scF) {
      const d = await read(scF);
      if (d) {
        try {
          const u = await unwrap(d, maxMember);
          const list = listCpio(u.bytes, maxEntries);
          const entries: PkgScript[] = [];
          for (const e of list.entries) if (e.kind === 'file') entries.push(scriptInfo(e.name, e.mode, u.bytes.subarray(e.offset, e.offset + e.size)));
          comp.scripts = { encoding: u.container, entries, ...(list.error ? { error: list.error } : {}) };
          for (const s of entries) if (s.indicators.length) report.findings.push({ id: `pkg.script@${prefix ? prefix + '/' : ''}${s.name}`, severity: s.indicators.some((x) => /shell|setuid|quarantine|Gatekeeper|Integrity|sudoers|kernel/.test(x)) ? 'medium' : 'low', title: `Install script ${s.name} ${s.indicators[0]}`, detail: `Indicators: ${s.indicators.join(', ')}.`, path: scF.path });
        } catch (e) { comp.scripts = { encoding: 'unknown', entries: [], error: (e as Error).message }; }
      }
    }
    const plF = at('Payload');
    if (plF) {
      comp.payload = { size: plF.size, storedSize: plF.length, container: 'unknown' };
      if (opts.listPayload !== false) {
        const d = await read(plF);
        if (d) {
          try {
            const u = await unwrap(d, maxMember);
            comp.payload.container = u.container;
            if (u.bytes.length && isCpio(u.bytes)) { const l = listCpio(u.bytes, maxEntries); comp.payload.entries = l.entries; comp.payload.truncated = l.truncated; if (l.error) comp.payload.error = l.error; }
          } catch (e) { comp.payload.error = (e as Error).message; }
        }
      }
    }
    report.components.push(comp);
  }
  for (const f of files) {
    const c = cache.get(f.path);
    report.files.push({ path: f.path, type: f.type, size: f.size, length: f.length, encoding: f.encoding, archivedMatches: c ? c.a : null, extractedMatches: c ? c.e : null });
    if (c && (c.a === false || c.e === false)) report.findings.push({ id: `pkg.member-checksum@${f.path}`, severity: 'high', title: 'Member checksum does not match', detail: `${f.path}: the stored ${c.a === false ? 'archived' : 'extracted'} checksum differs from the bytes.`, path: f.path });
  }
  return report;
}
