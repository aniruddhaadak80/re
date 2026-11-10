import type { Analyzer, AnalyzerContext, ExtractedString } from '../types.js';

const RE = {
  url: /\bhttps?:\/\/[^\s"'<>)\]]{4,}/,
  ip: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  path: /(?:[A-Za-z]:\\|\/)(?:[\w .$+-]+[\\/])+[\w .$+-]+/,
  guid: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/,
  registry: /\bHKEY_[A-Z_]+\\[^\s"']+/,
  command: /\b(?:cmd\.exe|powershell|\/bin\/sh|\/bin\/bash|CreateProcess|ShellExecute|system\()\b/,
  version: /\b\d+\.\d+\.\d+(?:[-+][\w.]+)?\b/,
};

function tagOf(s: string): string | undefined {
  if (RE.url.test(s)) return 'url';
  if (RE.email.test(s)) return 'email';
  if (RE.registry.test(s)) return 'registry';
  if (RE.guid.test(s)) return 'guid';
  if (RE.command.test(s)) return 'command';
  if (RE.ip.test(s)) return 'ip';
  if (RE.path.test(s)) return 'path';
  if (RE.version.test(s)) return 'version';
  return undefined;
}

/** Extract printable ASCII and UTF-16LE strings, like GNU strings plus wide. */
export function extractStrings(bytes: Uint8Array, min = 5, limit = 5000): ExtractedString[] {
  const out: ExtractedString[] = [];
  // ASCII
  let start = -1;
  for (let i = 0; i <= bytes.length; i++) {
    const b = i < bytes.length ? (bytes[i] as number) : 0;
    const printable = b >= 32 && b < 127;
    if (printable) { if (start < 0) start = i; }
    else {
      if (start >= 0 && i - start >= min) {
        out.push({ value: asc(bytes, start, i), offset: start, kind: 'ascii' });
        if (out.length >= limit) return out;
      }
      start = -1;
    }
  }
  // UTF-16LE: printable ASCII followed by 0x00
  start = -1;
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const lo = bytes[i] as number, hi = bytes[i + 1] as number;
    const printable = hi === 0 && lo >= 32 && lo < 127;
    if (printable) { if (start < 0) start = i; }
    else {
      if (start >= 0 && (i - start) / 2 >= min) {
        let v = '';
        for (let j = start; j < i; j += 2) v += String.fromCharCode(bytes[j] as number);
        out.push({ value: v, offset: start, kind: 'utf16' });
        if (out.length >= limit) return out;
      }
      start = -1;
    }
  }
  return out;
}

function asc(b: Uint8Array, s: number, e: number): string {
  let v = '';
  for (let i = s; i < e; i++) v += String.fromCharCode(b[i] as number);
  return v;
}

export const stringsAnalyzer: Analyzer = {
  id: 'strings',
  title: 'Strings',
  description: 'Extracts printable ASCII and UTF-16 strings and tags the interesting ones (urls, ips, paths, commands).',
  applies: () => true,
  run(ctx: AnalyzerContext) {
    const all = extractStrings(ctx.bytes, 5, 20000);
    for (const s of all) s.tag = tagOf(s.value);
    // Keep tagged strings first, then longest, capped to maxStrings.
    const sorted = all.slice().sort((a, b) => {
      const at = a.tag ? 1 : 0, bt = b.tag ? 1 : 0;
      if (at !== bt) return bt - at;
      return b.value.length - a.value.length;
    });
    ctx.report.strings = sorted.slice(0, ctx.options.maxStrings);
    ctx.report.meta.stringsTotal = all.length;
    ctx.report.meta.stringsTagged = all.filter((s) => s.tag).length;
  },
};
