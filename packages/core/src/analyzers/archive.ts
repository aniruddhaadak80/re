import type { Analyzer, AnalyzerContext, Report } from '../types.js';
import { listZip, listTar, listAsar, crxZipOffset, type Entry } from '../archive/containers.js';
import { decompress } from '../archive/inflate.js';
import { startsWith } from '../bytes.js';

const ARCHIVES = new Set(['zip', 'jar', 'apk', 'crx', 'xpi', 'vsix', 'npm-tgz', 'gzip', 'tar', 'asar', 'ipa']);
/** Members worth analyzing, by priority. Everything else is only listed. */
const INTERESTING = /(manifest\.json|package\.json|extension\.vsixmanifest|AndroidManifest\.xml|\.(m?js|cjs|map|wasm|node|so|dll|exe|dylib|dex|json)$)/i;
const MAX_CHILDREN = 60;
const MAX_MEMBER = 24 * 1024 * 1024;

export async function membersOf(ctx: Pick<AnalyzerContext, 'bytes' | 'format'>): Promise<{ entries: Entry[]; inner?: Uint8Array }> {
  const { bytes, format } = ctx;
  if (format === 'crx') {
    const off = crxZipOffset(bytes);
    if (off < 0) return { entries: [] };
    const inner = bytes.subarray(off);
    return { entries: listZip(inner), inner };
  }
  if (format === 'asar') return { entries: listAsar(bytes) };
  if (format === 'tar') return { entries: listTar(bytes) };
  if (format === 'gzip' || format === 'npm-tgz') {
    const inner = await decompress(bytes, 'gzip');
    if (inner.length > 262 && startsWith(inner, [0x75, 0x73, 0x74, 0x61, 0x72], 257)) return { entries: listTar(inner), inner };
    return { entries: [{ name: 'payload', size: inner.length, compressedSize: bytes.length, offset: 0, read: async () => inner }], inner };
  }
  return { entries: listZip(bytes) };
}

export const archiveAnalyzer: Analyzer = {
  id: 'archive',
  title: 'Archives and packages',
  description: 'Lists ZIP, JAR, APK, CRX, XPI, VSIX, npm tarball, gzip, tar and Electron ASAR members and analyzes the important ones recursively.',
  applies: (ctx) => ARCHIVES.has(ctx.format),
  async run(ctx) {
    const { report } = ctx;
    const { entries } = await membersOf(ctx);
    report.meta.members = entries.slice(0, 2000).map((e) => ({ name: e.name, size: e.size, compressedSize: e.compressedSize }));
    report.meta.memberCount = entries.length;

    // Zip bomb guard: compression ratio and total size.
    const totalU = entries.reduce((a, e) => a + e.size, 0);
    const totalC = entries.reduce((a, e) => a + e.compressedSize, 0) || 1;
    if (totalU / totalC > 100 && totalU > 50 * 1024 * 1024) {
      report.findings.push({ id: 'archive.bomb', analyzer: 'archive', title: 'Possible decompression bomb', severity: 'high',
        detail: `Members expand to ${totalU} bytes from ${totalC} compressed bytes, a ratio over 100 to 1.`, evidence: [], tags: ['dos'] });
    }
    // Path traversal (zip slip).
    for (const e of entries) {
      if (e.name.startsWith('/') || e.name.split(/[\\/]/).includes('..')) {
        report.findings.push({ id: 'archive.zipslip', analyzer: 'archive', title: 'Path traversal member name', severity: 'high',
          detail: `The member "${e.name}" would be written outside the target folder by a naive extractor (zip slip).`,
          evidence: [{ path: e.name, offset: e.offset }], tags: ['zip-slip'], attack: ['T1222'] });
        break;
      }
    }

    if (!ctx.options.recurse || ctx.depth >= ctx.options.maxDepth || !ctx.analyzeChild) return;
    const picks = entries
      .filter((e) => INTERESTING.test(e.name) && e.size <= MAX_MEMBER && !/node_modules\/.*\/(test|tests|docs?)\//.test(e.name))
      .sort((a, b) => score(b.name) - score(a.name))
      .slice(0, MAX_CHILDREN);
    const children: Report[] = [];
    for (const e of picks) {
      try {
        const data = await e.read();
        const child = await ctx.analyzeChild(data, e.name);
        child.meta.memberPath = e.name;
        children.push(child);
        for (const c of child.components) if (!report.components.some((x) => x.name === c.name && x.version === c.version)) {
          report.components.push({ ...c, evidence: c.evidence.map((ev) => ({ ...ev, path: e.name })) });
        }
        for (const f of child.findings) {
          if (f.severity === 'info' && f.analyzer !== 'extaudit') continue;
          const stem = f.id.replace(/\.\d+$/, '');
          if (report.findings.some((x) => x.id.split('@')[0]!.replace(/\.\d+$/, '') === stem && x.analyzer === f.analyzer)) continue;
          report.findings.push({ ...f, id: `${f.id}@${e.name}`, evidence: f.evidence.map((ev) => ({ ...ev, path: e.name })) });
        }
        for (const cap of child.capabilities) if (!report.capabilities.some((x) => x.name === cap.name)) report.capabilities.push(cap);
      } catch (err) {
        report.findings.push({ id: `archive.read@${e.name}`, analyzer: 'archive', title: 'Member could not be read', severity: 'info',
          detail: `${e.name}: ${(err as Error).message}`, evidence: [{ path: e.name }] });
      }
    }
    report.children = children;
  },
};

function score(n: string): number {
  if (/(^|\/)(manifest\.json|package\.json|extension\.vsixmanifest|AndroidManifest\.xml)$/i.test(n)) return 100 - n.split('/').length;
  if (/\.(dll|exe|so|dylib|node|wasm|dex)$/i.test(n)) return 60;
  if (/\.(m?js|cjs)$/i.test(n)) return 40 - n.split('/').length;
  return 10;
}
