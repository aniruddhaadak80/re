import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Loader2, Play } from 'lucide-react';
import { PageHeader } from '../../components/ui';
import { ToolResult } from '../../components/ToolResult';
import { argsFrom, type Lab, type LabTool } from '../../lib/labs';
import { useSeo } from '../../lib/seo';
import { cx } from '../../lib/util';
import { FilePicker, LAB_ICONS, useLabFile, useTool } from './shared';

function Field({ f, value, onChange }: { f: NonNullable<LabTool['fields']>[number]; value: string; onChange: (v: string) => void }) {
  if (f.kind === 'bool') {
    return (
      <label className="flex items-center gap-2 text-sm text-fg">
        <input type="checkbox" className="h-4 w-4 accent-[rgb(var(--accent))]" checked={value === 'true'} onChange={(e) => onChange(e.target.checked ? 'true' : 'false')} data-testid={`field-${f.key}`} />{f.label}
      </label>
    );
  }
  if (f.kind === 'select') {
    return (
      <label className="block min-w-0 flex-1"><span className="label">{f.label}</span>
        <select className="input" value={value} onChange={(e) => onChange(e.target.value)} data-testid={`field-${f.key}`}>{f.options?.map((o) => <option key={o} value={o}>{o || 'any'}</option>)}</select>
      </label>
    );
  }
  return (
    <label className={cx('block min-w-0', f.key === 'sql' ? 'w-full' : 'flex-1')}><span className="label">{f.label}</span>
      <input className="input font-mono" inputMode={f.kind === 'number' ? 'numeric' : undefined} value={value} placeholder={f.placeholder} onChange={(e) => onChange(e.target.value)} data-testid={`field-${f.key}`} />
    </label>
  );
}

/** A tool page for one package: pick a file or a sample, pick a tool, read the result. */
export default function LabPage({ lab }: { lab: Lab }) {
  useSeo(`${lab.title} | RevLens`, lab.summary);
  const { file, loading, error, load, loadSample } = useLabFile();
  const tool = useTool();
  const [active, setActive] = useState<string>(lab.tools[0]?.tool ?? '');
  const [values, setValues] = useState<Record<string, Record<string, string>>>({});
  const Icon = LAB_ICONS[lab.icon];
  const current = lab.tools.find((t) => t.tool === active) ?? lab.tools[0];
  const vals = (t: LabTool) => Object.fromEntries((t.fields ?? []).map((f) => [f.key, values[t.tool]?.[f.key] ?? f.def ?? '']));

  const runTool = (t: LabTool | undefined, fileId = file?.id) => {
    if (!t || !fileId) return;
    setActive(t.tool);
    void tool.run(fileId, t.tool, argsFrom(t.fields, vals(t)));
  };

  return (
    <div>
      <PageHeader eyebrow={lab.eyebrow} title={lab.title}>
        <p>{lab.summary}</p>
        <p className="mt-2 flex flex-wrap items-center gap-3 text-xs"><span className="chip"><Icon size={12} />{lab.pkg}</span><Link to="/labs" className="inline-flex items-center gap-1 text-muted hover:text-ink"><ArrowLeft size={12} />All tools</Link></p>
      </PageHeader>
      <div className="container-x grid grid-cols-1 gap-6 pb-16 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <FilePicker lab={lab} file={file} loading={loading} error={error}
            onFile={async (name, bytes) => { const f = await load(name, bytes); if (f) runTool(lab.tools.find((t) => t.auto) ?? lab.tools[0], f.id); }}
            onSample={async (s) => { const f = await loadSample(s); if (f) runTool(lab.tools.find((t) => t.tool === s.tool) ?? lab.tools[0], f.id); }} />
        </div>
        <div className="min-w-0 space-y-4">
          <div className="card p-4">
            <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Tools">
              {lab.tools.map((t) => (
                <button key={t.tool} type="button" role="tab" aria-selected={t.tool === current?.tool} data-testid={`tool-${t.tool}`}
                  className={cx('rounded-lg border px-3 py-1.5 text-sm transition', t.tool === current?.tool ? 'border-accent/70 bg-accent/10 text-ink' : 'border-line text-muted hover:border-accent/50 hover:text-fg')}
                  onClick={() => setActive(t.tool)}>{t.label}</button>
              ))}
            </div>
            {current && (
              <div className="mt-4">
                <p className="text-sm text-muted">{current.help} <span className="font-mono text-xs text-muted/80">{current.tool}</span></p>
                {current.fields && current.fields.length > 0 && (
                  <div className="mt-3 flex flex-wrap items-end gap-3">
                    {current.fields.map((f) => <Field key={f.key} f={f} value={vals(current)[f.key] ?? ''} onChange={(v) => setValues((o) => ({ ...o, [current.tool]: { ...o[current.tool], [f.key]: v } }))} />)}
                  </div>
                )}
                <button type="button" className="btn-primary mt-4" disabled={!file || tool.busy} onClick={() => runTool(current)} data-testid="run-tool">
                  {tool.busy ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}Run {current.label}
                </button>
                {!file && <p className="mt-2 text-xs text-muted">Open a file or try a sample first.</p>}
              </div>
            )}
          </div>
          {tool.busy && <div className="card flex items-center gap-2 p-4 text-sm text-muted"><Loader2 size={16} className="animate-spin text-ink" />Running {tool.tool} in the worker</div>}
          {tool.error && !tool.busy && <div className="card border-red-500/50 p-4 text-sm text-red-500" role="alert" data-testid="tool-error">{tool.error}</div>}
          {tool.result !== undefined && !tool.busy && <ToolResult result={tool.result} ms={tool.ms} />}
        </div>
      </div>
    </div>
  );
}
