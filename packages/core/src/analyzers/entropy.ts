import type { Analyzer } from '../types.js';
import { entropy, indexOf, asciiBytes } from '../bytes.js';

/** Known packer and protector markers. Each entry is a byte string seen in packed files. */
const PACKERS: { name: string; markers: string[]; attack: string }[] = [
  { name: 'UPX', markers: ['UPX!', 'UPX0', 'UPX1'], attack: 'T1027.002' },
  { name: 'ASPack', markers: ['.aspack', '.adata'], attack: 'T1027.002' },
  { name: 'MPRESS', markers: ['.MPRESS1', '.MPRESS2'], attack: 'T1027.002' },
  { name: 'Themida or WinLicense', markers: ['.themida', '.winlice'], attack: 'T1027.002' },
  { name: 'VMProtect', markers: ['.vmp0', '.vmp1'], attack: 'T1027.002' },
  { name: 'Enigma Protector', markers: ['.enigma1', '.enigma2'], attack: 'T1027.002' },
  { name: 'PECompact', markers: ['PEC2', 'PECompact2'], attack: 'T1027.002' },
  { name: 'Petite', markers: ['.petite'], attack: 'T1027.002' },
];

/** Fingerprints of common JavaScript obfuscators, matched on text. */
const JS_OBFUSCATORS: { name: string; re: RegExp; min?: number }[] = [
  { name: 'javascript-obfuscator (string array)', re: /var _0x[a-f0-9]{4,6}\s*=\s*\[|function _0x[a-f0-9]{4,6}\(\)\{/ },
  // Counted with a global search instead of /(?:_0x....*){40}/s, which backtracks exponentially
  // on text with fewer than 40 identifiers.
  { name: 'javascript-obfuscator (hex identifiers)', re: /_0x[a-f0-9]{4,6}/g, min: 40 },
  { name: 'JSFuck', re: /^[\[\]\(\)!+\s]{200,}$/m },
  { name: 'Dean Edwards packer', re: /eval\(function\(p,a,c,k,e,(?:r|d)\)/ },
  { name: 'JJencode or AAencode', re: /\$=~\[\];|ﾟωﾟ/ },
  { name: 'eval of decoded payload', re: /eval\((?:atob|unescape|decodeURIComponent)\(/ },
];

export const entropyAnalyzer: Analyzer = {
  id: 'entropy',
  title: 'Entropy and packers',
  description: 'Builds an entropy map of the file and looks for packers, protectors and JavaScript obfuscators.',
  applies: () => true,
  run(ctx) {
    const { bytes, report } = ctx;
    const blocks = 64;
    const step = Math.max(256, Math.ceil(bytes.length / blocks));
    const map: number[] = [];
    for (let i = 0; i < bytes.length; i += step) map.push(Number(entropy(bytes, i, Math.min(bytes.length, i + step)).toFixed(3)));
    report.meta.entropyMap = { blockSize: step, values: map };

    const high = map.filter((v) => v > 7.2).length;
    const isBinary = !ctx.text && !['zip', 'jar', 'apk', 'crx', 'xpi', 'vsix', 'npm-tgz', 'gzip', 'pdf', 'ipa', 'sqlite', 'pcap', 'pcapng'].includes(ctx.format);
    if (isBinary && bytes.length > 4096 && report.file.entropy > 7.2) {
      report.findings.push({
        id: 'entropy.high', analyzer: 'entropy', title: 'Very high overall entropy', severity: 'medium',
        detail: `Overall entropy is ${report.file.entropy.toFixed(2)} bits per byte. Most of the file looks compressed or encrypted, which often means packing, an embedded archive, or encrypted payloads.`,
        evidence: [], tags: ['packed'], attack: ['T1027'],
      });
    } else if (isBinary && high >= Math.max(3, map.length / 4)) {
      report.findings.push({
        id: 'entropy.regions', analyzer: 'entropy', title: 'Large high entropy regions', severity: 'low',
        detail: `${high} of ${map.length} blocks are above 7.2 bits per byte. This is normal for resources and compressed data, and worth a look if code sections are among them.`,
        evidence: [], tags: ['entropy'],
      });
    }

    for (const p of PACKERS) {
      for (const m of p.markers) {
        const off = indexOf(bytes, asciiBytes(m));
        if (off >= 0 && off < Math.max(4096, bytes.length)) {
          report.findings.push({
            id: `packer.${p.name.toLowerCase().replace(/[^a-z]+/g, '-')}`, analyzer: 'entropy',
            title: `Packed with ${p.name}`, severity: 'medium',
            detail: `Found the ${p.name} marker "${m}". Packed code hides its real logic until run time. Unpack it before deeper static analysis.`,
            evidence: [{ offset: off, length: m.length, snippet: m }], tags: ['packer'], attack: [p.attack],
          });
          report.meta.packer = p.name;
          break;
        }
      }
      if (report.meta.packer) break;
    }

    if (ctx.text) {
      const sample = ctx.text.length > 2_000_000 ? ctx.text.slice(0, 2_000_000) : ctx.text;
      for (const o of JS_OBFUSCATORS) {
        let m: RegExpExecArray | null;
        if (o.min) {
          o.re.lastIndex = 0;
          let first: RegExpExecArray | null = null;
          let n = 0;
          while (n < o.min && (m = o.re.exec(sample))) { first ??= m; n++; }
          m = n >= o.min ? first : null;
        } else m = o.re.exec(sample);
        if (m) {
          report.findings.push({
            id: `obfuscator.${o.name.toLowerCase().replace(/[^a-z]+/g, '-')}`, analyzer: 'entropy',
            title: `Obfuscated JavaScript: ${o.name}`, severity: o.name.startsWith('eval') ? 'high' : 'medium',
            detail: 'The code matches a known obfuscation pattern. Run a deobfuscator such as webcrack before reading it, and treat any eval of decoded data with care.',
            evidence: [{ offset: m.index, length: Math.min(80, m[0].length), snippet: m[0].slice(0, 80) }],
            tags: ['obfuscation'], attack: ['T1027'],
          });
        }
      }
    }
  },
};
