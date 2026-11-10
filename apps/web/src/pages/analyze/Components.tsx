import { useState } from 'react';
import { Boxes, Globe, Loader2 } from 'lucide-react';
import { lookupOSV, type Component, type Finding } from '@revlens/core';
import { CopyButton, Empty, SeverityBadge } from '../../components/ui';
import { allReports } from '../../lib/util';
import type { TabProps } from './shared';

export function Components({ report }: TabProps) {
  const comps: (Component & { from?: string })[] = allReports(report).flatMap((r, i) => r.components.map((c) => ({ ...c, from: i === 0 ? undefined : String(r.meta.memberPath ?? r.file.name) })));
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [vulns, setVulns] = useState<Finding[]>([]);
  const [err, setErr] = useState('');
  if (!comps.length) return <Empty title="No components found" icon={<Boxes size={28} />}>RevLens looks for bundler banners, license comments, package.json files, Go build info and cargo-auditable data.</Empty>;
  const check = async () => {
    setState('loading'); setErr('');
    try { setVulns(await lookupOSV(comps)); setState('done'); } catch (e) { setErr((e as Error).message); setState('error'); }
  };
  return (
    <div className="space-y-4">
      <div className="card overflow-x-auto" data-testid="components-table">
        <table className="w-full min-w-[680px] text-sm">
          <thead><tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
            <th className="px-4 py-3">Component</th><th className="px-4 py-3">Version</th><th className="px-4 py-3">Ecosystem</th><th className="px-4 py-3">Package URL</th><th className="px-4 py-3">Confidence</th>
          </tr></thead>
          <tbody>
            {comps.map((c, i) => (
              <tr key={`${c.name}-${c.version}-${i}`} className="border-b border-line/50 last:border-0 hover:bg-surface2/60" data-testid="component-row">
                <td className="px-4 py-2"><span className="font-medium">{c.name}</span>{c.from && <span className="block text-xs text-muted">in {c.from}</span>}</td>
                <td className="px-4 py-2 font-mono text-xs">{c.version ?? 'unknown'}</td>
                <td className="px-4 py-2"><span className="chip">{c.ecosystem}</span></td>
                <td className="px-4 py-2">{c.purl ? <span className="flex items-center gap-2"><span className="max-w-[260px] truncate font-mono text-xs" title={c.purl}>{c.purl}</span><CopyButton text={c.purl} /></span> : ''}</td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2"><span className="h-1.5 w-16 overflow-hidden rounded-full bg-surface2"><span className="block h-full rounded-full bg-teal" style={{ width: `${Math.round(c.confidence * 100)}%` }} /></span><span className="font-mono text-xs">{Math.round(c.confidence * 100)}%</span></div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="max-w-2xl">
            <p className="flex items-center gap-2 font-semibold"><Globe size={16} className="text-ink" />Known vulnerabilities</p>
            <p className="mt-1 text-sm text-muted">This is the only network request RevLens can make, and only when you press the button. It sends component names and versions to the free OSV.dev API. The file itself is never sent.</p>
          </div>
          <button type="button" className="btn-primary" onClick={check} disabled={state === 'loading'} data-testid="osv-button">
            {state === 'loading' ? <Loader2 size={16} className="animate-spin" /> : <Globe size={16} />}Check vulnerabilities on OSV.dev
          </button>
        </div>
        {state === 'error' && <p className="mt-3 text-sm text-red-500">The lookup failed: {err}</p>}
        {state === 'done' && (vulns.length ? (
          <ul className="mt-4 space-y-2">{vulns.map((v) => <li key={v.id} className="flex flex-wrap items-center gap-2 text-sm"><SeverityBadge s={v.severity} /><span className="font-medium">{v.title}</span><span className="w-full text-xs text-muted">{v.detail}</span></li>)}</ul>
        ) : <p className="mt-4 text-sm text-teal-700 dark:text-teal-300">OSV.dev has no known vulnerabilities for these versions.</p>)}
      </div>
    </div>
  );
}
