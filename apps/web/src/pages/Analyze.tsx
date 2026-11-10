import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { AlertTriangle, CheckCircle2, Clock, Loader2, Plus, Trash2, X } from 'lucide-react';
import { ANALYZERS } from '@revlens/core';
import { DropZone } from '../components/DropZone';
import { PageHeader, SeverityBadge } from '../components/ui';
import { SAMPLES } from '../lib/samples';
import { openFiles, openSample } from '../lib/actions';
import { clearHistory, closeFile, setActive, useWorkspace, type OpenFile } from '../lib/store';
import { useRouteSeo } from '../lib/seo';
import { FORMAT_LABEL, allFindings, cx, formatBytes } from '../lib/util';
import { Overview } from './analyze/Overview';
import { Findings } from './analyze/Findings';
import { Entropy } from './analyze/Entropy';
import { Sections } from './analyze/Sections';
import { Imports } from './analyze/Imports';
import { Strings } from './analyze/Strings';
import { Components } from './analyze/Components';
import { Capabilities } from './analyze/Capabilities';
import { Archive } from './analyze/Archive';
import { Surface } from './analyze/Surface';
import { Rules } from './analyze/Rules';
import { Hex } from './analyze/Hex';
import { Export } from './analyze/Export';
import type { TabProps } from './analyze/shared';

const TABS = [
  ['overview', 'Overview'], ['findings', 'Findings'], ['entropy', 'Entropy'], ['sections', 'Sections'], ['imports', 'Imports and exports'],
  ['strings', 'Strings'], ['components', 'Components'], ['capabilities', 'Capabilities'], ['archive', 'Archive'], ['surface', 'Surface'],
  ['rules', 'Rules'], ['hex', 'Hex'], ['export', 'Export'],
] as const;
type TabId = (typeof TABS)[number][0];

function count(f: OpenFile, t: TabId): number | undefined {
  const r = f.report;
  if (!r) return undefined;
  switch (t) {
    case 'findings': return allFindings(r).length;
    case 'sections': return r.sections.length;
    case 'imports': return r.imports.reduce((n, i) => n + i.symbols.length, 0) + r.exports.length;
    case 'strings': return r.strings.length;
    case 'components': return r.components.length + (r.children ?? []).reduce((n, c) => n + c.components.length, 0);
    case 'capabilities': return r.capabilities.length;
    case 'archive': return (r.meta.memberCount as number | undefined) ?? 0;
    default: return undefined;
  }
}

function Progress({ f }: { f: OpenFile }) {
  const done = Object.keys(f.timings);
  return (
    <div className="card p-6" data-testid="analysis-progress">
      <div className="flex items-center gap-3">
        {f.status === 'error' ? <AlertTriangle className="text-red-500" /> : <Loader2 className="animate-spin text-ink" />}
        <div className="min-w-0">
          <p className="truncate font-semibold">{f.status === 'error' ? `Could not analyze ${f.name}` : `Analyzing ${f.name}`}</p>
          <p className="text-sm text-muted">{f.status === 'error' ? f.error : f.current ? `Running ${ANALYZERS.find((a) => a.id === f.current)?.title ?? f.current}` : 'Hashing and detecting the format'}</p>
        </div>
      </div>
      {f.status !== 'error' && (
        <>
          <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-surface2"><div className="h-full rounded-full bg-gradient-to-r from-teal to-accent transition-all" style={{ width: `${Math.max(6, (done.length / ANALYZERS.length) * 100)}%` }} /></div>
          <ul className="mt-4 grid grid-cols-1 gap-1.5 text-xs sm:grid-cols-2 lg:grid-cols-3">
            {ANALYZERS.map((a) => (
              <li key={a.id} className="flex items-center gap-2">
                {f.timings[a.id] != null ? <CheckCircle2 size={13} className="text-teal" /> : f.current === a.id ? <Loader2 size={13} className="animate-spin text-ink" /> : <Clock size={13} className="text-muted/60" />}
                <span className={f.timings[a.id] != null ? '' : 'text-muted'}>{a.title}</span>
                {f.timings[a.id] != null && <span className="ml-auto font-mono text-muted">{f.timings[a.id]!.toFixed(1)} ms</span>}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function Start() {
  const ws = useWorkspace();
  const [busy, setBusy] = useState<string | null>(null);
  return (
    <div className="container-x grid grid-cols-1 gap-6 pb-10 lg:grid-cols-[1.4fr_1fr]">
      <div className="space-y-4">
        <DropZone onFiles={(f) => void openFiles(f)} />
        <div className="card p-4">
          <p className="mb-3 text-sm font-semibold">Or try a sample</p>
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((s) => (
              <button key={s.id} type="button" className={cx('btn-ghost btn-sm', busy === s.id && 'animate-pulse')} data-testid={`sample-${s.id}`}
                onClick={async () => { setBusy(s.id); try { await openSample(s); } finally { setBusy(null); } }}>{s.label}</button>
            ))}
          </div>
        </div>
      </div>
      <div className="card p-4">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-sm font-semibold">Recent analyses</p>
          {ws.history.length > 0 && <button type="button" className="btn-ghost btn-sm" onClick={clearHistory}><Trash2 size={13} />Clear</button>}
        </div>
        {ws.history.length === 0 ? <p className="text-sm text-muted">Nothing yet. Only names, sizes, hashes and finding counts are kept here, in this browser. File contents are never stored.</p> : (
          <ul className="space-y-2" data-testid="history">
            {ws.history.map((h) => (
              <li key={h.sha256 + h.at} className="rounded-lg border border-line/70 p-2.5">
                <div className="flex min-w-0 items-center gap-2"><span className="min-w-0 flex-1 truncate text-sm font-medium">{h.name}</span>{h.max && <SeverityBadge s={h.max} />}</div>
                <p className="mt-0.5 truncate font-mono text-[11px] text-muted">{FORMAT_LABEL[h.format] ?? h.format}, {formatBytes(h.size)}, {h.findings} findings, {h.sha256.slice(0, 12)}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default function Analyze() {
  useRouteSeo('/analyze');
  const ws = useWorkspace();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = (TABS.find(([id]) => id === params.get('tab'))?.[0] ?? 'overview') as TabId;
  const setTab = (t: TabId) => setParams((p) => { p.set('tab', t); return p; }, { replace: true });
  const [target, setTarget] = useState<{ offset: number; length: number; nonce: number } | null>(null);
  const active = ws.files.find((f) => f.id === ws.activeId) ?? ws.files[ws.files.length - 1];
  useEffect(() => setTarget(null), [active?.id]);

  const jump = (offset: number, length = 1) => { setTarget({ offset, length, nonce: Date.now() }); setTab('hex'); window.scrollTo({ top: 0, behavior: 'smooth' }); };

  return (
    <div>
      <PageHeader eyebrow="Workspace" title="Analyze">
        Drop any number of files. Each one opens as a tab and is analyzed in a background worker on your device.
      </PageHeader>
      {ws.files.length > 0 && (
        <div className="container-x mb-4">
          <div className="flex items-center gap-2 overflow-x-auto pb-1" role="tablist" aria-label="Open files">
            {ws.files.map((f) => (
              <div key={f.id} className={cx('group flex shrink-0 items-center gap-2 rounded-xl border px-3 py-2 text-sm transition', f.id === active?.id ? 'border-accent/60 bg-accent/10' : 'border-line bg-surface hover:border-accent/40')}>
                <button type="button" role="tab" aria-selected={f.id === active?.id} className="flex max-w-[220px] items-center gap-2" onClick={() => setActive(f.id)}>
                  {f.status === 'running' ? <Loader2 size={13} className="animate-spin text-ink" /> : f.status === 'error' ? <AlertTriangle size={13} className="text-red-500" /> : <CheckCircle2 size={13} className="text-teal" />}
                  <span className="truncate">{f.name}</span>
                </button>
                <button type="button" onClick={() => closeFile(f.id)} className="rounded p-0.5 text-muted hover:text-fg" aria-label={`Close ${f.name}`}><X size={13} /></button>
              </div>
            ))}
            <button type="button" className="btn-ghost btn-sm shrink-0" onClick={() => { setActive(''); nav('/analyze'); }} aria-label="Open another file"><Plus size={14} />Open</button>
          </div>
        </div>
      )}
      {!active || ws.activeId === '' ? <Start /> : (
        <div className="container-x">
          {active.status !== 'done' || !active.report ? <Progress f={active} /> : (
            <>
              <div className="sticky top-16 z-30 -mx-4 mb-5 border-b border-line bg-bg/85 px-4 backdrop-blur-xl sm:mx-0 sm:rounded-xl sm:border sm:px-2">
                <div className="flex gap-1 overflow-x-auto py-2" role="tablist" aria-label="Report sections">
                  {TABS.map(([id, label]) => {
                    const n = count(active, id);
                    return (
                      <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)} data-testid={`tab-${id}`}
                        className={cx('relative shrink-0 rounded-lg px-3 py-1.5 text-sm transition', tab === id ? 'text-fg' : 'text-muted hover:text-fg')}>
                        {tab === id && <motion.span layoutId="tab-pill" className="absolute inset-0 rounded-lg border border-accent/50 bg-accent/10" transition={{ type: 'spring', stiffness: 400, damping: 34 }} />}
                        <span className="relative">{label}{n != null && n > 0 && <span className="ml-1.5 font-mono text-[11px] text-muted">{n}</span>}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
              <AnimatePresence mode="wait">
                <motion.div key={`${active.id}-${tab}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }} transition={{ duration: 0.15 }} data-testid={`panel-${tab}`}>
                  <TabBody tab={tab} file={active} report={active.report} jump={jump} target={target} />
                </motion.div>
              </AnimatePresence>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function TabBody({ tab, target, ...p }: TabProps & { tab: TabId; target: { offset: number; length: number; nonce: number } | null }) {
  switch (tab) {
    case 'overview': return <Overview {...p} />;
    case 'findings': return <Findings {...p} />;
    case 'entropy': return <Entropy {...p} />;
    case 'sections': return <Sections {...p} />;
    case 'imports': return <Imports {...p} />;
    case 'strings': return <Strings {...p} />;
    case 'components': return <Components {...p} />;
    case 'capabilities': return <Capabilities {...p} />;
    case 'archive': return <Archive {...p} />;
    case 'surface': return <Surface {...p} />;
    case 'rules': return <Rules {...p} />;
    case 'hex': return <Hex {...p} target={target} />;
    case 'export': return <Export {...p} />;
  }
}
