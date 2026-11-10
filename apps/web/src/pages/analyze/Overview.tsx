import { ANALYZERS } from '@revlens/core';
import { CopyButton, SeverityBadge } from '../../components/ui';
import { FORMAT_LABEL, SEVERITIES, allFindings, formatBytes, riskLabel, riskScore } from '../../lib/util';
import { Stat, type TabProps } from './shared';

function Gauge({ score }: { score: number }) {
  const { label, color } = riskLabel(score);
  const r = 70, c = Math.PI * r;
  return (
    <div className="flex flex-col items-center" data-testid="risk-gauge" data-score={score}>
      <svg viewBox="0 0 180 104" className="w-full max-w-[220px]" role="img" aria-label={`Risk score ${score} of 100, ${label}`}>
        <path d={`M 20 92 A ${r} ${r} 0 0 1 160 92`} fill="none" stroke="rgb(var(--line))" strokeWidth="14" strokeLinecap="round" />
        <path d={`M 20 92 A ${r} ${r} 0 0 1 160 92`} fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${(score / 100) * c} ${c}`} style={{ transition: 'stroke-dasharray 0.8s ease' }} />
        <text x="90" y="80" textAnchor="middle" fontSize="34" fontWeight="700" fill="rgb(var(--fg))">{score}</text>
        <text x="90" y="100" textAnchor="middle" fontSize="11" fill="rgb(var(--muted))">out of 100</text>
      </svg>
      <p className="mt-1 text-sm font-semibold" style={{ color }}>{label}</p>
    </div>
  );
}

export function Overview({ file, report }: TabProps) {
  const r = report;
  const findings = allFindings(r);
  const score = riskScore(r);
  const counts = SEVERITIES.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }));
  const hashes = Object.entries(r.file.hashes).filter(([, v]) => v) as [string, string][];
  const titles = Object.fromEntries(ANALYZERS.map((a) => [a.id, a.title]));
  const timings = Object.entries(file.timings).length ? file.timings : r.timings;
  const timingRows = Object.entries(timings).filter(([k]) => k !== 'total').sort((a, b) => b[1] - a[1]);
  const maxT = Math.max(1, ...timingRows.map(([, v]) => v));
  const highlights: [string, string][] = [];
  const m = r.meta as Record<string, unknown>;
  if (typeof m.bundler === 'string') highlights.push(['Bundler', m.bundler]);
  if (typeof m.packer === 'string') highlights.push(['Packer', m.packer]);
  if (typeof m.goVersion === 'string') highlights.push(['Go', m.goVersion]);
  if (typeof m.rust === 'string') highlights.push(['Rust', m.rust]);
  if (typeof m.memberCount === 'number') highlights.push(['Archive members', String(m.memberCount)]);
  if (typeof m.stringsTotal === 'number') highlights.push(['Strings found', String(m.stringsTotal)]);
  const npm = m.npm as { name?: string; version?: string } | undefined;
  if (npm?.name) highlights.push(['npm package', `${npm.name} ${npm.version ?? ''}`]);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="card p-5 lg:col-span-2">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-wider text-muted">File</p>
            <p className="mt-1 break-all text-xl font-semibold" data-testid="file-name">{r.file.name}</p>
          </div>
          <span className="rounded-lg border border-accent/50 bg-accent/10 px-2.5 py-1 font-mono text-sm font-semibold text-ink" data-testid="file-format">{FORMAT_LABEL[r.file.format] ?? r.file.format}</span>
        </div>
        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Size" value={formatBytes(r.file.size)} sub={`${r.file.size.toLocaleString()} bytes`} />
          <Stat label="Architecture" value={r.file.arch ?? 'Not native'} sub={[r.file.bits && `${r.file.bits} bit`, r.file.endian && (r.file.endian === 'le' ? 'little endian' : 'big endian')].filter(Boolean).join(', ') || undefined} />
          <Stat label="Entropy" value={`${r.file.entropy.toFixed(2)} bits`} sub="per byte, 8 is random" />
          <Stat label="MIME" value={r.file.mime ?? 'unknown'} />
        </div>
        <div className="mt-5 space-y-2">
          {hashes.map(([k, v]) => (
            <div key={k} className="flex min-w-0 items-center gap-3 rounded-lg border border-line/70 bg-surface2/50 px-3 py-2">
              <span className="w-14 shrink-0 font-mono text-xs uppercase text-muted">{k}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-xs" title={v}>{v}</span>
              <CopyButton text={v} />
            </div>
          ))}
        </div>
        {highlights.length > 0 && (
          <div className="mt-5 flex flex-wrap gap-2">
            {highlights.map(([k, v]) => <span key={k} className="chip"><span className="text-fg">{k}</span>{v}</span>)}
          </div>
        )}
      </div>
      <div className="card flex flex-col p-5">
        <p className="text-xs uppercase tracking-wider text-muted">Risk score</p>
        <div className="mt-2 flex-1"><Gauge score={score} /></div>
        <div className="mt-4 grid grid-cols-5 gap-1 text-center">
          {counts.map(({ s, n }) => (
            <div key={s} className="rounded-lg border border-line/70 py-2"><p className="text-lg font-semibold">{n}</p><p className="text-[10px] uppercase text-muted">{s}</p></div>
          ))}
        </div>
        <p className="mt-3 text-xs leading-5 text-muted">The score weighs findings by severity across the file and its archive members. It is a triage hint, not a verdict.</p>
      </div>
      {findings.length > 0 && (
        <div className="card p-5 lg:col-span-2">
          <p className="mb-3 text-sm font-semibold">Top findings</p>
          <ul className="space-y-2">
            {findings.slice(0, 5).map((f) => (
              <li key={f.id} className="flex min-w-0 items-center gap-3"><SeverityBadge s={f.severity} /><span className="truncate text-sm">{f.title}</span></li>
            ))}
          </ul>
        </div>
      )}
      <div className={`card p-5 ${findings.length ? '' : 'lg:col-span-3'}`} data-testid="timings">
        <p className="mb-3 text-sm font-semibold">Analyzer timings <span className="font-normal text-muted">({(timings.total ?? r.timings.total ?? 0).toFixed(1)} ms total)</span></p>
        <ul className="space-y-1.5">
          {timingRows.map(([k, v]) => (
            <li key={k} className="grid grid-cols-[110px_1fr_56px] items-center gap-2 text-xs">
              <span className="truncate text-muted" title={titles[k] ?? k}>{titles[k] ?? k}</span>
              <span className="h-1.5 overflow-hidden rounded-full bg-surface2"><span className="block h-full rounded-full bg-gradient-to-r from-teal to-accent" style={{ width: `${Math.max(3, (v / maxT) * 100)}%` }} /></span>
              <span className="text-right font-mono">{v.toFixed(1)} ms</span>
            </li>
          ))}
        </ul>
      </div>
      {r.hardening && Object.keys(r.hardening).length > 0 && (
        <div className="card p-5 lg:col-span-3">
          <p className="mb-3 text-sm font-semibold">Hardening</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(r.hardening).map(([k, v]) => (
              <span key={k} className={`chip ${v === true ? 'border-teal/50 text-teal-700 dark:text-teal-300' : v === false ? 'border-red-500/40 text-red-600 dark:text-red-300' : ''}`}>{k}: {String(v)}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
