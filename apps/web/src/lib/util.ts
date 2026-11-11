import type { Finding, Report, Severity } from '@revlens/core';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Tailwind classes per severity. Red, orange, amber, sky, neutral. */
export const SEV_STYLE: Record<Severity, { badge: string; dot: string; bar: string }> = {
  critical: { badge: 'border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-300', dot: 'bg-red-500', bar: '#EF4444' },
  high: { badge: 'border-orange-500/40 bg-orange-500/15 text-orange-700 dark:text-orange-300', dot: 'bg-orange-500', bar: '#F97316' },
  medium: { badge: 'border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300', dot: 'bg-amber-500', bar: '#F59E0B' },
  low: { badge: 'border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300', dot: 'bg-sky-500', bar: '#0EA5E9' },
  info: { badge: 'border-line bg-surface2 text-muted', dot: 'bg-zinc-400', bar: '#A1A1AA' },
};

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${u[i]}`;
}

export const hex = (n: number, pad = 8): string => '0x' + n.toString(16).toUpperCase().padStart(pad, '0');

export function attackUrl(id: string): string {
  const [t, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${t}/${sub ? sub + '/' : ''}`;
}

export function allReports(r: Report): Report[] { return [r, ...(r.children ?? []).flatMap(allReports)]; }
export function allFindings(r: Report): Finding[] { return allReports(r).flatMap((x) => x.findings); }

/** 0 to 100. Weighted by severity with diminishing returns so one bad file is not "100" by default. */
export function riskScore(r: Report): number {
  const w: Record<Severity, number> = { critical: 45, high: 22, medium: 9, low: 3, info: 0 };
  const raw = allFindings(r).reduce((s, f) => s + w[f.severity], 0) + Math.min(10, r.capabilities.length * 2);
  return Math.round(100 * (1 - Math.exp(-raw / 45)));
}
export function riskLabel(score: number): { label: string; color: string } {
  if (score >= 75) return { label: 'High risk', color: '#EF4444' };
  if (score >= 45) return { label: 'Elevated', color: '#F97316' };
  if (score >= 15) return { label: 'Some concerns', color: '#F5B301' };
  return { label: 'Low risk', color: '#14B8A6' };
}
export function maxSeverity(r: Report): Severity | undefined {
  return allFindings(r).sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])[0]?.severity;
}

export function download(name: string, content: string | object, type = 'application/json'): void {
  const body = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/** Removes <...> spans the way /<[^>]+>/g would, without a regex replace, in linear time. */
function stripTags(s: string): string {
  let out = '';
  let i = 0;
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    if (lt < 0) { out += s.slice(i); break; }
    const gt = s.indexOf('>', lt + 2);
    if (gt < 0 || s[lt + 1] === '>') { out += s.slice(i, lt + 1); i = lt + 1; if (gt < 0) { out += s.slice(i); break; } continue; }
    out += s.slice(i, lt);
    i = gt + 1;
  }
  return out;
}

export function slugify(s: string): string {
  return stripTags(s.toLowerCase()).replace(/[`*_~]/g, '').replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-').replace(/-+/g, '-');
}

export const cx = (...c: (string | false | null | undefined)[]): string => c.filter(Boolean).join(' ');

export const FORMAT_LABEL: Record<string, string> = {
  elf: 'ELF', pe: 'PE', macho: 'Mach-O', 'macho-fat': 'Mach-O universal', wasm: 'WebAssembly', zip: 'ZIP', jar: 'JAR', apk: 'APK',
  crx: 'Chrome extension', xpi: 'Firefox add-on', vsix: 'VS Code extension', 'npm-tgz': 'npm package', gzip: 'gzip', tar: 'tar',
  asar: 'Electron ASAR', js: 'JavaScript', sourcemap: 'Source map', json: 'JSON', pdf: 'PDF', pyc: 'Python bytecode', dex: 'Android DEX',
  class: 'Java class', text: 'Text', unknown: 'Unknown',
  dotnet: '.NET assembly', ipa: 'iOS app (IPA)', pcap: 'Packet capture', pcapng: 'Packet capture (pcapng)', sqlite: 'SQLite database',
  har: 'HAR network log', lua: 'Lua bytecode', beam: 'Erlang BEAM', 'il2cpp-metadata': 'IL2CPP metadata',
};
