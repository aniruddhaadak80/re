import { useMemo, useState } from 'react';
import { AlertTriangle, ArrowRightLeft, CheckCircle2, Loader2, Minus, Plus, RefreshCw } from 'lucide-react';
import { diff, type ChangeSet, type Component, type DiffReport, type Finding, type Report, type Section } from '@revlens/core';
import { DropZone } from '../components/DropZone';
import { Empty, PageHeader } from '../components/ui';
import { analyzeInWorker, forgetInWorker, newId } from '../lib/engine';
import { SAMPLES, loadSample } from '../lib/samples';
import { useRouteSeo } from '../lib/seo';
import { FORMAT_LABEL, cx, download, formatBytes } from '../lib/util';

interface Slot { name: string; status: 'running' | 'done' | 'error'; report?: Report; error?: string }

function SlotCard({ label, slot, onBytes, testId }: { label: string; slot: Slot | null; onBytes: (name: string, b: Uint8Array) => void; testId: string }) {
  return (
    <div className="card p-4">
      <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-ink">{label}</p>
      {slot ? (
        <div className="flex min-w-0 items-center gap-3 rounded-xl border border-line bg-surface2/60 p-3">
          {slot.status === 'running' ? <Loader2 className="animate-spin text-ink" size={18} /> : slot.status === 'error' ? <AlertTriangle className="text-red-500" size={18} /> : <CheckCircle2 className="text-teal" size={18} />}
          <div className="min-w-0 flex-1">
            <p className="truncate font-medium">{slot.name}</p>
            <p className="text-xs text-muted">{slot.report ? `${FORMAT_LABEL[slot.report.file.format] ?? slot.report.file.format}, ${formatBytes(slot.report.file.size)}` : slot.error ?? 'Analyzing'}</p>
          </div>
        </div>
      ) : null}
      <div className="mt-3"><DropZone compact multiple={false} title={slot ? 'Replace with another file' : 'Drop or choose a file'} testId={testId} onFiles={async (f) => { const file = f[0]!; onBytes(file.name, new Uint8Array(await file.arrayBuffer())); }} /></div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {SAMPLES.map((s) => <button key={s.id} type="button" className="chip transition hover:border-accent/60 hover:text-fg" data-testid={`${testId}-sample-${s.id}`} onClick={async () => onBytes(s.file, await loadSample(s))}>{s.label}</button>)}
      </div>
    </div>
  );
}

function Changes<T>({ title, set, fmt }: { title: string; set: ChangeSet<T>; fmt: (x: T) => string }) {
  const n = set.added.length + set.removed.length + (set.changed?.length ?? 0);
  return (
    <div className="card p-4" data-testid={`diff-${title.toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="font-semibold">{title}</p>
        <div className="flex gap-1.5 font-mono text-[11px]">
          <span className="rounded-md bg-teal/15 px-1.5 py-0.5 text-teal-700 dark:text-teal-300">+{set.added.length}</span>
          <span className="rounded-md bg-red-500/15 px-1.5 py-0.5 text-red-600 dark:text-red-300">-{set.removed.length}</span>
          {set.changed && <span className="rounded-md bg-accent/15 px-1.5 py-0.5 text-ink">~{set.changed.length}</span>}
        </div>
      </div>
      {n === 0 ? <p className="text-sm text-muted">No changes.</p> : (
        <ul className="max-h-72 space-y-1 overflow-auto font-mono text-xs">
          {set.added.slice(0, 200).map((x, i) => <li key={`a${i}`} className="flex min-w-0 gap-2 rounded bg-teal/5 px-2 py-1"><Plus size={12} className="mt-0.5 shrink-0 text-teal" /><span className="min-w-0 break-all">{fmt(x)}</span></li>)}
          {set.removed.slice(0, 200).map((x, i) => <li key={`r${i}`} className="flex min-w-0 gap-2 rounded bg-red-500/5 px-2 py-1"><Minus size={12} className="mt-0.5 shrink-0 text-red-500" /><span className="min-w-0 break-all">{fmt(x)}</span></li>)}
          {set.changed?.slice(0, 200).map((c, i) => <li key={`c${i}`} className="flex min-w-0 gap-2 rounded bg-accent/5 px-2 py-1"><ArrowRightLeft size={12} className="mt-0.5 shrink-0 text-ink" /><span className="min-w-0 break-all">{fmt(c.before)} <span className="text-muted">to</span> {fmt(c.after)}</span></li>)}
        </ul>
      )}
    </div>
  );
}

export default function Diff() {
  useRouteSeo('/diff');
  const [a, setA] = useState<Slot | null>(null);
  const [b, setB] = useState<Slot | null>(null);
  const run = (set: (s: Slot | null) => void) => (name: string, bytes: Uint8Array) => {
    const id = newId('d');
    set({ name, status: 'running' });
    analyzeInWorker(id, name, bytes).then((report) => set({ name, status: 'done', report })).catch((e: Error) => set({ name, status: 'error', error: e.message })).finally(() => forgetInWorker(id));
  };
  const d: DiffReport | null = useMemo(() => (a?.report && b?.report ? diff(a.report, b.report) : null), [a, b]);
  const comp = (c: Component) => `${c.name}${c.version ? '@' + c.version : ''}`;
  const sec = (s: Section) => `${s.name} ${s.size} B, entropy ${s.entropy.toFixed(2)}`;
  const fin = (f: Finding) => `[${f.severity}] ${f.title}`;
  return (
    <div>
      <PageHeader eyebrow="Release diff" title="Compare two files">
        Pick an older and a newer build of the same thing. RevLens analyzes both on your device and shows what was added, removed or changed.
      </PageHeader>
      <div className="container-x space-y-6">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <SlotCard label="Before (A)" slot={a} onBytes={run(setA)} testId="diff-a" />
          <SlotCard label="After (B)" slot={b} onBytes={run(setB)} testId="diff-b" />
        </div>
        {d ? (
          <div className="space-y-4" data-testid="diff-result">
            <div className="card flex flex-wrap items-center gap-3 border-accent/40 p-5">
              <RefreshCw size={18} className="text-ink" />
              <p className="min-w-0 flex-1 font-medium" data-testid="diff-summary">{d.summary}</p>
              <button type="button" className="btn-ghost btn-sm" onClick={() => download('revlens-diff.json', d)}>Download diff JSON</button>
            </div>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Changes title="Components" set={d.components} fmt={comp} />
              <Changes title="Endpoints" set={d.endpoints} fmt={(x) => (x.length > 180 ? `${x.slice(0, 180)} ...` : x)} />
              <Changes title="Imports" set={d.imports} fmt={(x) => x} />
              <Changes title="Exports" set={d.exports} fmt={(x) => x} />
              <Changes title="Capabilities" set={d.capabilities} fmt={(x) => x} />
              <Changes title="Findings" set={d.findings} fmt={fin} />
              <Changes title="Sections" set={d.sections} fmt={sec} />
              <Changes title="Tagged strings" set={d.strings} fmt={(x) => (x.length > 180 ? `${x.slice(0, 180)} ...` : x)} />
            </div>
          </div>
        ) : (
          <Empty title={a || b ? 'Waiting for both files' : 'Pick two files to compare'}>
            <span className={cx(a?.status === 'running' || b?.status === 'running' ? 'animate-pulse' : '')}>Try two samples, for example jquery.min.js against react-dom, to see how the view works.</span>
          </Empty>
        )}
      </div>
    </div>
  );
}
