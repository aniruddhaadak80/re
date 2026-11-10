import { useMemo, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import type { Finding, Report, Severity } from '@revlens/core';
import { AttackBadge, Empty, SeverityBadge } from '../../components/ui';
import { SEVERITIES, cx } from '../../lib/util';
import { EvidenceRow, SearchBox, type TabProps } from './shared';

interface Row { f: Finding; from?: string; local: boolean }
const collect = (r: Report, from?: string): Row[] => [
  ...r.findings.map((f) => ({ f, from, local: !from })),
  ...(r.children ?? []).flatMap((c) => collect(c, String(c.meta.memberPath ?? c.file.name))),
];

export function Findings({ report, jump }: TabProps) {
  const rows = useMemo(() => collect(report), [report]);
  const [sev, setSev] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [an, setAn] = useState('all');
  const [q, setQ] = useState('');
  const analyzers = [...new Set(rows.map((r) => r.f.analyzer))].sort();
  const shown = rows.filter((r) => sev.has(r.f.severity) && (an === 'all' || r.f.analyzer === an) &&
    (!q || `${r.f.title} ${r.f.detail} ${(r.f.tags ?? []).join(' ')}`.toLowerCase().includes(q.toLowerCase())));
  if (!rows.length) return <Empty title="No findings" icon={<ShieldCheck size={28} />}>Nothing stood out. The other tabs still show sections, strings and components.</Empty>;
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {SEVERITIES.map((s) => {
          const n = rows.filter((r) => r.f.severity === s).length;
          const on = sev.has(s);
          return (
            <button key={s} type="button" aria-pressed={on} onClick={() => setSev((old) => { const x = new Set(old); if (x.has(s)) x.delete(s); else x.add(s); return x; })}
              className={cx('rounded-full border px-3 py-1 text-xs capitalize transition', on ? 'border-accent/60 bg-accent/10 text-fg' : 'border-line text-muted opacity-60')}>
              {s} <span className="ml-1 font-mono">{n}</span>
            </button>
          );
        })}
        <select className="input !w-auto" value={an} onChange={(e) => setAn(e.target.value)} aria-label="Filter by analyzer">
          <option value="all">All analyzers</option>
          {analyzers.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <SearchBox value={q} onChange={setQ} placeholder="Search findings" />
      </div>
      <ul className="space-y-3" data-testid="findings-list">
        {shown.map(({ f, from, local }, i) => (
          <li key={`${f.id}-${i}`} className="card p-4 transition hover:border-accent/40" data-testid="finding" data-severity={f.severity}>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge s={f.severity} />
              <span className="font-medium">{f.title}</span>
              <span className="chip font-mono">{f.analyzer}</span>
              {from && <span className="chip">in {from}</span>}
            </div>
            <p className="mt-2 text-sm leading-6 text-muted">{f.detail}</p>
            {(f.attack?.length || f.tags?.length) ? (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {f.attack?.map((a) => <AttackBadge key={a} id={a} />)}
                {f.tags?.map((t) => <span key={t} className="chip">{t}</span>)}
              </div>
            ) : null}
            {f.evidence.length > 0 && <div className="mt-3 space-y-1.5">{f.evidence.slice(0, 6).map((e, k) => <EvidenceRow key={k} e={e} jump={jump} local={local} />)}</div>}
          </li>
        ))}
        {!shown.length && <li className="text-sm text-muted">No findings match these filters.</li>}
      </ul>
    </div>
  );
}
