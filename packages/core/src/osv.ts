import type { Component, Finding, Severity } from './types.js';

const ECOSYSTEM: Record<string, string> = { npm: 'npm', go: 'Go', cargo: 'crates.io', pypi: 'PyPI', maven: 'Maven' };

interface OsvVuln { id: string; summary?: string; aliases?: string[]; database_specific?: { severity?: string }; severity?: { type: string; score: string }[] }

function sevOf(v: OsvVuln): Severity {
  const s = (v.database_specific?.severity ?? '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'moderate' || s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'medium';
}

/**
 * Look up known vulnerabilities for components with a version, using the free
 * OSV.dev batch API. This is the only network call in RevLens and it is opt in.
 */
export async function lookupOSV(components: Component[], fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const list = components.filter((c) => c.version && ECOSYSTEM[c.ecosystem] && /^\d/.test(c.version.replace(/^v/, '')));
  const uniq = [...new Map(list.map((c) => [`${c.ecosystem}:${c.name}@${c.version}`, c])).values()].slice(0, 1000);
  if (!uniq.length) return [];
  const body = { queries: uniq.map((c) => ({ package: { name: c.name, ecosystem: ECOSYSTEM[c.ecosystem] }, version: (c.version as string).replace(/^v(?=\d)/, c.ecosystem === 'go' ? 'v' : '') })) };
  const r = await fetchImpl('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`OSV returned HTTP ${r.status}`);
  const data = (await r.json()) as { results: { vulns?: { id: string }[] }[] };
  const findings: Finding[] = [];
  const ids = new Set<string>();
  data.results.forEach((res, i) => { for (const v of res.vulns ?? []) ids.add(`${i}|${v.id}`); });
  // Fetch details for up to 60 vulns to get summaries and severity.
  const detail = new Map<string, OsvVuln>();
  await Promise.all([...new Set([...ids].map((x) => x.split('|')[1] as string))].slice(0, 60).map(async (id) => {
    try { const d = await fetchImpl(`https://api.osv.dev/v1/vulns/${id}`); if (d.ok) detail.set(id, (await d.json()) as OsvVuln); } catch { /* ignore */ }
  }));
  for (const key of ids) {
    const [i, id] = key.split('|') as [string, string];
    const c = uniq[Number(i)] as Component;
    const v = detail.get(id) ?? { id };
    const cve = v.aliases?.find((a) => a.startsWith('CVE-'));
    findings.push({
      id: `osv.${id}.${c.name}`, analyzer: 'osv', title: `${c.name} ${c.version} is affected by ${cve ?? id}`, severity: sevOf(v),
      detail: `${v.summary ?? 'A known vulnerability affects this version.'} See https://osv.dev/vulnerability/${id}`,
      evidence: c.evidence.slice(0, 2), tags: ['vulnerability', c.ecosystem],
    });
  }
  return findings;
}
