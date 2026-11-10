import { Layers } from 'lucide-react';
import { Empty } from '../../components/ui';
import { formatBytes, hex } from '../../lib/util';
import type { TabProps } from './shared';

export function Sections({ report, jump }: TabProps) {
  if (!report.sections.length) return <Empty title="No sections" icon={<Layers size={28} />}>This format has no section table. Archives list members under Archive instead.</Empty>;
  return (
    <div className="card overflow-x-auto" data-testid="sections-table">
      <table className="w-full min-w-[640px] text-sm">
        <thead><tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
          <th className="px-4 py-3">Name</th><th className="px-4 py-3">Offset</th><th className="px-4 py-3">Size</th><th className="px-4 py-3">Virtual address</th><th className="px-4 py-3">Entropy</th><th className="px-4 py-3">Flags</th>
        </tr></thead>
        <tbody>
          {report.sections.map((s, i) => (
            <tr key={`${s.name}-${i}`} className="border-b border-line/50 transition last:border-0 hover:bg-surface2/60">
              <td className="px-4 py-2 font-mono font-medium">{s.name || '(unnamed)'}</td>
              <td className="px-4 py-2"><button type="button" className="font-mono text-xs text-ink hover:underline" onClick={() => jump(s.offset, Math.min(s.size, 4096))}>{hex(s.offset)}</button></td>
              <td className="px-4 py-2 font-mono text-xs">{formatBytes(s.size)}</td>
              <td className="px-4 py-2 font-mono text-xs text-muted">{s.vaddr != null ? hex(s.vaddr) : ''}</td>
              <td className="px-4 py-2">
                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-20 overflow-hidden rounded-full bg-surface2"><span className="block h-full rounded-full" style={{ width: `${(s.entropy / 8) * 100}%`, background: s.entropy > 7.2 ? '#EF4444' : s.entropy > 6 ? '#F97316' : '#14B8A6' }} /></span>
                  <span className="font-mono text-xs">{s.entropy.toFixed(2)}</span>
                </div>
              </td>
              <td className="px-4 py-2 font-mono text-xs text-muted">{s.flags ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
