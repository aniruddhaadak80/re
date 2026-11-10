import { useState } from 'react';
import { ChevronRight, Network } from 'lucide-react';
import { Empty } from '../../components/ui';
import { SearchBox, type TabProps } from './shared';

export function Imports({ report }: TabProps) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<Set<string>>(() => new Set(report.imports.length <= 3 ? report.imports.map((i) => i.library) : []));
  const t = q.toLowerCase();
  const libs = report.imports.map((i) => ({ ...i, symbols: i.symbols.filter((s) => !t || s.toLowerCase().includes(t) || i.library.toLowerCase().includes(t)) })).filter((i) => i.symbols.length || i.library.toLowerCase().includes(t));
  const exps = report.exports.filter((e) => !t || e.toLowerCase().includes(t));
  if (!report.imports.length && !report.exports.length) return <Empty title="No imports or exports" icon={<Network size={28} />}>Native binaries and WebAssembly modules list them here.</Empty>;
  const total = report.imports.reduce((n, i) => n + i.symbols.length, 0);
  return (
    <div className="space-y-4">
      <SearchBox value={q} onChange={setQ} placeholder="Search libraries and symbols" testId="imports-search" />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card p-4">
          <p className="mb-3 text-sm font-semibold">Imports <span className="font-normal text-muted">{report.imports.length} libraries, {total} symbols</span></p>
          <ul className="space-y-1">
            {libs.map((l) => {
              const isOpen = open.has(l.library) || !!t;
              return (
                <li key={l.library}>
                  <button type="button" className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm transition hover:bg-surface2"
                    onClick={() => setOpen((o) => { const x = new Set(o); if (x.has(l.library)) x.delete(l.library); else x.add(l.library); return x; })} aria-expanded={isOpen}>
                    <ChevronRight size={14} className={`transition ${isOpen ? 'rotate-90 text-ink' : 'text-muted'}`} />
                    <span className="min-w-0 flex-1 truncate font-mono">{l.library || '(unknown library)'}</span>
                    <span className="chip font-mono">{l.symbols.length}</span>
                  </button>
                  {isOpen && <div className="ml-7 flex flex-wrap gap-1 py-1">{l.symbols.slice(0, 600).map((s) => <span key={s} className="rounded-md border border-line bg-surface2/60 px-1.5 py-0.5 font-mono text-[11px]">{s}</span>)}</div>}
                </li>
              );
            })}
            {!libs.length && <li className="text-sm text-muted">No imports match.</li>}
          </ul>
        </div>
        <div className="card p-4">
          <p className="mb-3 text-sm font-semibold">Exports <span className="font-normal text-muted">{report.exports.length}</span></p>
          <div className="flex max-h-[520px] flex-wrap gap-1 overflow-auto">
            {exps.slice(0, 2000).map((e) => <span key={e} className="rounded-md border border-line bg-surface2/60 px-1.5 py-0.5 font-mono text-[11px]">{e}</span>)}
            {!exps.length && <p className="text-sm text-muted">No exports{t ? ' match' : ''}.</p>}
          </div>
        </div>
      </div>
    </div>
  );
}
