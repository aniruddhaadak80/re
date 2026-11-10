import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Loader2, RotateCcw } from 'lucide-react';
import { STARTER_RULES, type RuleMatch } from '@revlens/core';
import { rulesInWorker } from '../../lib/engine';
import { hex } from '../../lib/util';
import type { TabProps } from './shared';

const KEY = 'revlens.rules';
const initial = () => { try { return localStorage.getItem(KEY) ?? STARTER_RULES.trim(); } catch { return STARTER_RULES.trim(); } };

export function Rules({ file, jump }: TabProps) {
  const [text, setText] = useState(initial);
  const [matches, setMatches] = useState<RuleMatch[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ms, setMs] = useState(0);
  const gutter = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let alive = true;
    setBusy(true);
    const t = setTimeout(async () => {
      const t0 = performance.now();
      try { const m = await rulesInWorker(file.id, text); if (alive) { setMatches(m); setError(null); } }
      catch (e) { if (alive) { setError((e as Error).message); setMatches(null); } }
      finally { if (alive) { setBusy(false); setMs(performance.now() - t0); } }
    }, 280);
    try { localStorage.setItem(KEY, text); } catch { /* ignore */ }
    return () => { alive = false; clearTimeout(t); };
  }, [text, file.id]);
  const lines = text.split('\n').length;
  const ruleCount = (text.match(/\brule\s+\w+/g) ?? []).length;
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.25fr_1fr]">
      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
          <p className="text-sm font-semibold">yara-lite rules <span className="font-normal text-muted">{ruleCount} rules</span></p>
          <button type="button" className="btn-ghost btn-sm" onClick={() => setText(STARTER_RULES.trim())}><RotateCcw size={13} />Reset to starter pack</button>
        </div>
        <div className="flex h-[520px]">
          <div ref={gutter} className="select-none overflow-hidden border-r border-line bg-surface2/60 px-2 py-3 text-right font-mono text-[12px] leading-5 text-muted" aria-hidden>
            {Array.from({ length: lines }, (_, i) => <div key={i}>{i + 1}</div>)}
          </div>
          <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="Rule editor" data-testid="rules-editor"
            onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop; }}
            className="h-full flex-1 resize-none bg-transparent p-3 font-mono text-[12px] leading-5 text-fg outline-none" />
        </div>
      </div>
      <div className="space-y-3" data-testid="rules-results">
        <div className="card flex items-center gap-2 p-3 text-sm">
          {busy ? <Loader2 size={16} className="animate-spin text-ink" /> : error ? <AlertTriangle size={16} className="text-red-500" /> : <CheckCircle2 size={16} className="text-teal" />}
          {error ? <span className="text-red-600 dark:text-red-300" data-testid="rules-error">Syntax or rule error: {error}</span>
            : <span><span data-testid="rules-match-count">{matches?.length ?? 0}</span> rules matched {file.name} <span className="text-muted">in {ms.toFixed(0)} ms</span></span>}
        </div>
        {matches?.map((m) => (
          <div key={m.rule} className="card p-4" data-testid="rule-match">
            <div className="flex flex-wrap items-center gap-2"><span className="font-mono font-semibold text-ink">{m.rule}</span>{m.tags.map((t) => <span key={t} className="chip">{t}</span>)}{m.meta.severity && <span className="chip">{m.meta.severity}</span>}</div>
            {m.meta.description && <p className="mt-1 text-sm text-muted">{m.meta.description}</p>}
            <ul className="mt-2 space-y-1">
              {m.strings.map((s, i) => (
                <li key={i} className="flex min-w-0 items-center gap-2 font-mono text-xs">
                  <span className="text-muted">{s.id}</span>
                  <button type="button" className="rounded bg-accent/15 px-1.5 text-ink hover:bg-accent/30" onClick={() => jump(s.offset, s.length)}>{hex(s.offset, 6)}</button>
                  <span className="min-w-0 truncate">{s.snippet}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {matches && !matches.length && !error && <p className="text-sm text-muted">No rule matched. Edit a rule on the left and the results update as you type.</p>}
      </div>
    </div>
  );
}
