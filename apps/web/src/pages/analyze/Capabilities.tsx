import { Radar } from 'lucide-react';
import { AttackBadge, Empty } from '../../components/ui';
import { allReports } from '../../lib/util';
import { EvidenceRow, type TabProps } from './shared';

export function Capabilities({ report, jump }: TabProps) {
  const caps = allReports(report).flatMap((r, i) => r.capabilities.map((c) => ({ ...c, local: i === 0 })));
  if (!caps.length) return <Empty title="No capabilities matched" icon={<Radar size={28} />}>Capabilities come from imports, strings and crypto constants, mapped to MITRE ATT&amp;CK where possible.</Empty>;
  const groups = new Map<string, typeof caps>();
  for (const c of caps) {
    const k = c.attack ? c.attack.split('.')[0]! : c.namespace ?? 'Other';
    groups.set(k, [...(groups.get(k) ?? []), c]);
  }
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2" data-testid="capabilities">
      {[...groups].map(([k, list]) => (
        <div key={k} className="card p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <p className="font-semibold">{/^T\d/.test(k) ? `Technique ${k}` : k}</p>
            {/^T\d/.test(k) && <AttackBadge id={k} />}
          </div>
          <ul className="space-y-3">
            {list.map((c, i) => (
              <li key={`${c.name}-${i}`}>
                <div className="flex flex-wrap items-center gap-2 text-sm"><span>{c.name}</span>{c.attack && c.attack !== k && <AttackBadge id={c.attack} />}{c.namespace && <span className="chip">{c.namespace}</span>}</div>
                {c.evidence.length > 0 && <div className="mt-1.5 space-y-1">{c.evidence.slice(0, 3).map((e, j) => <EvidenceRow key={j} e={e} jump={jump} local={c.local} />)}</div>}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
