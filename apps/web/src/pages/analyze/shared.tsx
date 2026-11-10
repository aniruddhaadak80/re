import type { Evidence, Report } from '@revlens/core';
import type { ReactNode } from 'react';
import type { OpenFile } from '../../lib/store';
import { hex } from '../../lib/util';

export interface TabProps { file: OpenFile; report: Report; jump: (offset: number, length?: number) => void }

/** An evidence line. Offsets are clickable and open the hex view when the bytes belong to this file. */
export function EvidenceRow({ e, jump, local = true }: { e: Evidence; jump?: TabProps['jump']; local?: boolean }) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border border-line/70 bg-surface2/60 px-2.5 py-1.5 font-mono text-xs">
      {e.offset != null && (local && jump ? (
        <button type="button" onClick={() => jump(e.offset!, e.length)} className="rounded bg-accent/15 px-1.5 py-0.5 text-ink transition hover:bg-accent/30" title="Show in hex view" data-testid="evidence-offset">
          {hex(e.offset, 6)}
        </button>
      ) : <span className="rounded bg-surface px-1.5 py-0.5 text-muted">{hex(e.offset, 6)}</span>)}
      {e.length != null && <span className="text-muted">{e.length} B</span>}
      {e.path && <span className="truncate text-teal-700 dark:text-teal-300">{e.path}</span>}
      {e.snippet && <span className="min-w-0 break-all text-fg">{e.snippet}</span>}
    </div>
  );
}

export function SearchBox({ value, onChange, placeholder, testId }: { value: string; onChange: (v: string) => void; placeholder: string; testId?: string }) {
  return <input className="input max-w-md" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} data-testid={testId} aria-label={placeholder} />;
}

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="min-w-0 rounded-xl border border-line bg-surface2/50 p-3">
      <p className="text-[11px] uppercase tracking-wider text-muted">{label}</p>
      <p className="mt-1 truncate font-semibold">{value}</p>
      {sub && <p className="truncate text-xs text-muted">{sub}</p>}
    </div>
  );
}
