import type { Analyzer, AnalyzerContext, Finding, Severity } from '../types.js';
import { inspectDmg } from '../formats/dmg.js';
import { inspectPkg } from '../formats/pkg.js';
import { parseXar } from '../formats/xar.js';
import { inspectMsix } from '../formats/msix.js';
import { parseDosMz } from '../formats/dosmz.js';

function push(ctx: AnalyzerContext, f: { id: string; severity: Severity; title: string; detail: string; path?: string }, tags: string[]): void {
  const finding: Finding = { id: f.id, analyzer: 'installers', title: f.title, severity: f.severity, detail: f.detail, evidence: f.path ? [{ path: f.path }] : [], tags };
  ctx.report.findings.push(finding);
}

/**
 * Apple disk images, flat installer packages and xar archives, Windows MSIX and APPX packages, and
 * plain DOS MZ programs. Rich output lands in report.meta.dmg, .pkg, .xar, .msix and .dosmz.
 */
export const installersAnalyzer: Analyzer = {
  id: 'installers',
  title: 'Disk images, installers and app packages',
  description: 'Reads UDIF disk images (partitions, chunk codecs, CRC checks, HFS+ file list, APFS volumes), macOS flat packages (Distribution, PackageInfo, Bom, scripts, payload), MSIX and APPX packages (manifest, capabilities, block map hashes, signature) and plain DOS MZ programs (relocations, entry, overlay).',
  applies: (ctx) => ['dmg', 'pkg', 'xar', 'msix', 'appx', 'dos-mz'].includes(ctx.format),
  async run(ctx) {
    const { bytes, report } = ctx;
    if (ctx.format === 'dmg') {
      const d = await inspectDmg(bytes, { maxEntries: 5000 });
      report.meta.dmg = d;
      report.file.mime = 'application/x-apple-diskimage';
      for (const p of d.partitions) report.sections.push({ name: p.name || `partition ${p.index}`, offset: p.firstSector * 512, size: p.size, entropy: 0, flags: Object.keys(p.methods).join(',') });
      if (d.dataChecksumMatches === false) push(ctx, { id: 'dmg.data-checksum', severity: 'high', title: 'Disk image data checksum does not match', detail: `The koly trailer stores CRC-32 ${d.dataChecksum.value.slice(0, 8)} for the data fork, the bytes hash to ${d.dataForkCrc32}.` }, ['dmg', 'integrity']);
      for (const p of d.partitions) {
        if (p.decoded?.checksumMatches === false) push(ctx, { id: `dmg.partition-checksum.${p.index}`, severity: 'high', title: `Partition ${p.index} checksum does not match`, detail: `${p.name}: stored CRC-32 ${p.checksum.value.slice(0, 8)}, decoded data ${p.decoded.crc32}.` }, ['dmg', 'integrity']);
        const apps = p.decoded?.hfs?.entries.filter((e) => e.kind === 'folder' && e.name.endsWith('.app') && !e.path.slice(0, -e.name.length).includes('.app/')) ?? [];
        if (apps.length) push(ctx, { id: `dmg.apps.${p.index}`, severity: 'info', title: `Disk image holds ${apps.map((a) => a.name).join(', ')}`, detail: `Volume "${p.decoded?.hfs?.volumeName}" lists ${p.decoded?.hfs?.entries.length} entries.` }, ['dmg']);
        if (p.decoded?.unsupported.length) push(ctx, { id: `dmg.codec.${p.index}`, severity: 'info', title: 'Some chunks use a codec RevLens does not decode', detail: `${p.name}: ${p.decoded.unsupported.join(', ')}.` }, ['dmg']);
      }
    } else if (ctx.format === 'pkg') {
      const r = await inspectPkg(bytes, { maxEntries: 2000 });
      report.meta.pkg = r;
      for (const f of r.findings) push(ctx, f, ['pkg', 'installer']);
      for (const c of r.components) if (c.packageInfo?.identifier) report.components.push({ name: c.packageInfo.identifier, version: c.packageInfo.version, ecosystem: 'unknown', confidence: 0.9, evidence: [{ path: `${c.prefix ? c.prefix + '/' : ''}PackageInfo` }] });
    } else if (ctx.format === 'xar') {
      const x = await parseXar(bytes);
      const { toc: _t, ...rest } = x;
      report.meta.xar = { ...rest, files: x.files.slice(0, 2000) };
    } else if (ctx.format === 'msix' || ctx.format === 'appx') {
      const m = await inspectMsix(bytes, { name: ctx.name, verifyBytes: 256 * 1024 * 1024 });
      report.meta.msix = m;
      for (const f of m.findings) push(ctx, f, ['msix']);
      if (m.identity?.name) report.components.push({ name: m.identity.name, version: m.identity.version, ecosystem: 'unknown', confidence: 0.9, evidence: [{ path: m.bundle ? 'AppxMetadata/AppxBundleManifest.xml' : 'AppxManifest.xml' }] });
    } else if (ctx.format === 'dos-mz') {
      const d = parseDosMz(bytes);
      report.meta.dosmz = { ...d, relocations: d.relocations.slice(0, 5000) };
      report.file.arch = 'x86-16';
      report.file.bits = undefined;
      report.file.endian = 'le';
      report.sections.push({ name: 'MZ header', offset: 0, size: d.headerSize, entropy: 0 }, { name: 'load module', offset: d.headerSize, size: d.loadModuleSize, entropy: 0 });
      if (d.overlay) report.sections.push({ name: 'overlay', offset: d.overlay.offset, size: d.overlay.size, entropy: 0 });
      for (const m of d.markers) if (/packer/.test(m.name)) push(ctx, { id: `dosmz.packer.${m.name.split(' ')[0]!.toLowerCase()}`, severity: 'medium', title: `Packed with ${m.name.replace(/ packer$/, '')}`, detail: `Marker at offset ${m.offset}. Unpack before reading the code.` }, ['packer']);
      if (d.newHeader) push(ctx, { id: 'dosmz.new-header', severity: 'info', title: `DOS stub in front of an ${d.newHeader.kind} image`, detail: `e_lfanew points to ${d.newHeader.kind} at offset ${d.newHeader.offset}.` }, ['dos']);
    }
  },
};
