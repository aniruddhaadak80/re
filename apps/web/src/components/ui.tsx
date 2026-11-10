import { useState, type ReactNode } from 'react';
import { Check, Copy } from 'lucide-react';
import type { Severity } from '@revlens/core';
import { SEV_STYLE, attackUrl, cx } from '../lib/util';

export function CopyButton({ text, label = 'Copy', className = '' }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={cx('inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface2 px-2 py-1 text-xs text-muted transition hover:border-accent/60 hover:text-ink', className)}
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); } catch {
          const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove();
        }
        setDone(true); setTimeout(() => setDone(false), 1400);
      }}
      aria-label={`${label}: ${text.slice(0, 40)}`}
    >
      {done ? <Check size={13} className="text-teal" /> : <Copy size={13} />}
      <span>{done ? 'Copied' : label}</span>
    </button>
  );
}

export function SeverityBadge({ s }: { s: Severity }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide', SEV_STYLE[s].badge)} data-severity={s}>
      <span className={cx('h-1.5 w-1.5 rounded-full', SEV_STYLE[s].dot)} />{s}
    </span>
  );
}

export function AttackBadge({ id }: { id: string }) {
  return (
    <a href={attackUrl(id)} target="_blank" rel="noreferrer" title={`MITRE ATT&CK ${id}`}
      className="inline-flex items-center rounded-md border border-teal/40 bg-teal/10 px-1.5 py-0.5 font-mono text-[11px] text-teal-700 transition hover:bg-teal/20 dark:text-teal-300">
      ATT&amp;CK {id}
    </a>
  );
}

export function Section({ id, eyebrow, title, children, intro }: { id?: string; eyebrow?: string; title: string; intro?: ReactNode; children: ReactNode }) {
  return (
    <section id={id} className="container-x py-16 sm:py-24">
      {eyebrow && <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-ink">{eyebrow}</p>}
      <h2 className="max-w-3xl text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h2>
      {intro && <div className="mt-4 max-w-3xl text-base leading-7 text-muted">{intro}</div>}
      <div className="mt-10">{children}</div>
    </section>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="card flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      {icon && <div className="mb-2 text-ink">{icon}</div>}
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function PageHeader({ eyebrow, title, children }: { eyebrow?: string; title: string; children?: ReactNode }) {
  return (
    <div className="container-x pb-6 pt-10 sm:pt-14">
      {eyebrow && <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-ink">{eyebrow}</p>}
      <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
      {children && <div className="mt-3 max-w-3xl text-muted">{children}</div>}
    </div>
  );
}
