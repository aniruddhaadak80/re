import { useMemo, useState } from 'react';
import { FileSearch } from 'lucide-react';
import { Empty } from '../../components/ui';
import { VirtualList } from '../../components/VirtualList';
import { cx, hex } from '../../lib/util';
import { SearchBox, type TabProps } from './shared';

export function Strings({ report, jump }: TabProps) {
  const [q, setQ] = useState('');
  const [tag, setTag] = useState<string>('all');
  const tags = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of report.strings) if (s.tag) m.set(s.tag, (m.get(s.tag) ?? 0) + 1);
    return [...m].sort((a, b) => b[1] - a[1]);
  }, [report]);
  const shown = useMemo(() => {
    const t = q.toLowerCase();
    return report.strings.filter((s) => (tag === 'all' || s.tag === tag) && (!t || s.value.toLowerCase().includes(t)));
  }, [report, q, tag]);
  if (!report.strings.length) return <Empty title="No strings" icon={<FileSearch size={28} />}>No printable strings long enough to be interesting were found.</Empty>;
  const total = report.meta.stringsTotal as number | undefined;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={q} onChange={setQ} placeholder="Search strings" testId="strings-search" />
        <span className="text-xs text-muted">{shown.length} shown of {report.strings.length} kept{total ? `, ${total.toLocaleString()} found` : ''}</span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {[['all', report.strings.length] as [string, number], ...tags].map(([t, n]) => (
          <button key={t} type="button" onClick={() => setTag(t)} aria-pressed={tag === t}
            className={cx('rounded-full border px-2.5 py-0.5 text-xs transition', tag === t ? 'border-accent/60 bg-accent/10 text-fg' : 'border-line text-muted hover:text-fg')}>{t} <span className="font-mono">{n}</span></button>
        ))}
      </div>
      <div className="card overflow-hidden">
        <VirtualList items={shown} rowHeight={34} height={Math.min(560, Math.max(120, shown.length * 34))} testId="strings-list"
          render={(s) => (
            <div className="flex h-full items-center gap-3 border-b border-line/40 px-3 text-xs">
              <button type="button" className="shrink-0 font-mono text-ink hover:underline" onClick={() => jump(s.offset, s.kind === 'utf16' ? s.value.length * 2 : s.value.length)}>{hex(s.offset, 6)}</button>
              <span className="w-12 shrink-0 text-muted">{s.kind}</span>
              {s.tag ? <span className="w-20 shrink-0 truncate rounded-md bg-teal/10 px-1.5 py-0.5 text-center text-teal-700 dark:text-teal-300">{s.tag}</span> : <span className="w-20 shrink-0" />}
              <span className="min-w-0 truncate font-mono" title={s.value}>{s.value}</span>
            </div>
          )} />
      </div>
    </div>
  );
}
