import { Check, Monitor, Moon, Sun, Trash2 } from 'lucide-react';
import { PageHeader } from '../components/ui';
import { ACCENTS, THEMES, setSettings, useSettings, type Motion } from '../lib/settings';
import { clearHistory, useWorkspace } from '../lib/store';
import { useRouteSeo } from '../lib/seo';
import { cx } from '../lib/util';

const PREVIEW: Record<string, { bg: string; card: string; fg: string }> = {
  black: { bg: '#0A0A0B', card: '#18181A', fg: '#F2EFE6' }, dark: { bg: '#16171A', card: '#26272C', fg: '#F0EEE8' },
  sun: { bg: '#FAF9F5', card: '#FFFFFF', fg: '#1A1814' }, system: { bg: 'linear-gradient(135deg,#0A0A0B 50%,#FAF9F5 50%)', card: '#7F7F7F', fg: '#F2EFE6' },
};

export default function Settings() {
  useRouteSeo('/settings');
  const s = useSettings();
  const ws = useWorkspace();
  return (
    <div>
      <PageHeader eyebrow="Settings" title="Make it yours">These settings are saved in this browser only.</PageHeader>
      <div className="container-x max-w-4xl space-y-6">
        <section className="card p-5">
          <h2 className="font-semibold">Theme</h2>
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {THEMES.map((t) => {
              const Icon = t.id === 'sun' ? Sun : t.id === 'system' ? Monitor : Moon;
              const p = PREVIEW[t.id]!;
              return (
                <button key={t.id} type="button" onClick={() => setSettings({ theme: t.id })} aria-pressed={s.theme === t.id} data-testid={`theme-${t.id}`}
                  className={cx('rounded-xl border p-2 text-left transition hover:border-accent/60', s.theme === t.id ? 'border-accent ring-2 ring-accent/30' : 'border-line')}>
                  <div className="h-16 rounded-lg p-2" style={{ background: p.bg }}><div className="h-3 w-2/3 rounded" style={{ background: p.card }} /><div className="mt-2 h-2 w-1/3 rounded bg-accent" /></div>
                  <p className="mt-2 flex items-center gap-1.5 text-sm"><Icon size={14} />{t.label}{s.theme === t.id && <Check size={14} className="ml-auto text-ink" />}</p>
                </button>
              );
            })}
          </div>
        </section>
        <section className="card p-5">
          <h2 className="font-semibold">Accent</h2>
          <div className="mt-4 flex flex-wrap gap-3">
            {ACCENTS.map((a) => (
              <button key={a.id} type="button" onClick={() => setSettings({ accent: a.id })} aria-pressed={s.accent === a.id} data-testid={`accent-${a.id}`}
                className={cx('flex items-center gap-2 rounded-xl border px-3 py-2 text-sm transition hover:border-accent/60', s.accent === a.id ? 'border-accent ring-2 ring-accent/30' : 'border-line')}>
                <span className="h-4 w-4 rounded-full" style={{ background: a.hex }} />{a.label}
              </button>
            ))}
          </div>
        </section>
        <section className="card p-5">
          <h2 className="font-semibold">Motion</h2>
          <p className="mt-1 text-sm text-muted">System follows your device setting for reduced motion.</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {(['system', 'full', 'reduced'] as Motion[]).map((m) => (
              <button key={m} type="button" onClick={() => setSettings({ motion: m })} aria-pressed={s.motion === m} data-testid={`motion-${m}`}
                className={cx('rounded-xl border px-4 py-2 text-sm capitalize transition hover:border-accent/60', s.motion === m ? 'border-accent bg-accent/10' : 'border-line')}>{m === 'full' ? 'Full motion' : m === 'reduced' ? 'Reduced motion' : 'System'}</button>
            ))}
          </div>
        </section>
        <section className="card p-5">
          <h2 className="font-semibold">Local history</h2>
          <p className="mt-1 text-sm text-muted">{ws.history.length} recent analyses are listed in this browser. Only names, sizes, hashes and finding counts are kept, never file contents.</p>
          <button type="button" className="btn-ghost mt-4" onClick={clearHistory} disabled={!ws.history.length} data-testid="clear-history"><Trash2 size={15} />Clear history</button>
        </section>
      </div>
    </div>
  );
}
