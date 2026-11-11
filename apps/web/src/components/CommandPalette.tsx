import { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { BookOpen, FileSearch, FlaskConical, Monitor, Moon, Newspaper, Palette, Search, Sun } from 'lucide-react';
import { DOCS, POSTS } from '../lib/content';
import { SAMPLES } from '../lib/samples';
import { openSample } from '../lib/actions';
import { setSettings, ACCENTS } from '../lib/settings';
import { cx } from '../lib/util';

interface Item { id: string; group: string; label: string; hint?: string; icon: JSX.Element; run: () => void }

export const PAGES = [
  { to: '/', label: 'Home' }, { to: '/analyze', label: 'Analyze' }, { to: '/labs', label: 'Tools' }, { to: '/labs/disassembler', label: 'Disassembler' }, { to: '/diff', label: 'Diff' }, { to: '/verify', label: 'Verify' },
  { to: '/docs', label: 'Docs' }, { to: '/blog', label: 'Blog' }, { to: '/about', label: 'About' }, { to: '/changelog', label: 'Changelog' }, { to: '/settings', label: 'Settings' },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const items = useMemo<Item[]>(() => {
    const go = (to: string) => () => nav(to);
    return [
      ...PAGES.map((p) => ({ id: `p${p.to}`, group: 'Pages', label: p.label, hint: p.to, icon: <FileSearch size={16} />, run: go(p.to) })),
      ...SAMPLES.map((s) => ({ id: `s${s.id}`, group: 'Samples', label: `Analyze ${s.label}`, hint: s.kind, icon: <FlaskConical size={16} />, run: () => { void openSample(s); nav('/analyze'); } })),
      ...DOCS.map((d) => ({ id: `d${d.slug}`, group: 'Docs', label: d.title, hint: 'docs', icon: <BookOpen size={16} />, run: go(`/docs/${d.slug}`) })),
      ...POSTS.map((p) => ({ id: `b${p.slug}`, group: 'Blog', label: p.title, hint: 'blog', icon: <Newspaper size={16} />, run: go(`/blog/${p.slug}`) })),
      { id: 't-black', group: 'Theme', label: 'Theme: Black', icon: <Moon size={16} />, run: () => setSettings({ theme: 'black' }) },
      { id: 't-dark', group: 'Theme', label: 'Theme: Dark', icon: <Moon size={16} />, run: () => setSettings({ theme: 'dark' }) },
      { id: 't-sun', group: 'Theme', label: 'Theme: Sun', icon: <Sun size={16} />, run: () => setSettings({ theme: 'sun' }) },
      { id: 't-system', group: 'Theme', label: 'Theme: System', icon: <Monitor size={16} />, run: () => setSettings({ theme: 'system' }) },
      ...ACCENTS.map((a) => ({ id: `a${a.id}`, group: 'Theme', label: `Accent: ${a.label}`, icon: <Palette size={16} />, run: () => setSettings({ accent: a.id }) })),
    ];
  }, [nav]);
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return items;
    return items.filter((i) => `${i.group} ${i.label} ${i.hint ?? ''}`.toLowerCase().includes(t));
  }, [items, q]);
  useEffect(() => { if (open) { setQ(''); setSel(0); setTimeout(() => input.current?.focus(), 20); } }, [open]);
  useEffect(() => setSel(0), [q]);
  const pick = (i: Item | undefined) => { if (!i) return; onClose(); i.run(); };

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[70] flex items-start justify-center bg-black/60 px-3 pt-[12vh] backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
          <motion.div role="dialog" aria-modal="true" aria-label="Command palette" className="card w-full max-w-xl overflow-hidden shadow-2xl"
            initial={{ y: -12, scale: 0.98 }} animate={{ y: 0, scale: 1 }} exit={{ y: -8, scale: 0.98 }} transition={{ duration: 0.16 }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 border-b border-line px-4">
              <Search size={18} className="text-muted" />
              <input ref={input} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Jump to a page, doc or sample"
                className="h-14 w-full bg-transparent text-base outline-none placeholder:text-muted/70"
                onKeyDown={(e) => {
                  if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(shown.length - 1, s + 1)); }
                  else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
                  else if (e.key === 'Enter') { e.preventDefault(); pick(shown[sel]); }
                  else if (e.key === 'Escape') onClose();
                }} />
              <span className="kbd">Esc</span>
            </div>
            <ul className="max-h-[55vh] overflow-y-auto p-2">
              {shown.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted">Nothing matches that.</li>}
              {shown.map((i, n) => (
                <li key={i.id}>
                  {(n === 0 || shown[n - 1]?.group !== i.group) && <p className="px-3 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-widest text-muted">{i.group}</p>}
                  <button type="button" onMouseEnter={() => setSel(n)} onClick={() => pick(i)}
                    className={cx('flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition', n === sel ? 'bg-accent/15 text-fg' : 'text-muted hover:text-fg')}>
                    <span className={n === sel ? 'text-ink' : ''}>{i.icon}</span>
                    <span className="flex-1 truncate">{i.label}</span>
                    {i.hint && <span className="font-mono text-[11px] text-muted">{i.hint}</span>}
                  </button>
                </li>
              ))}
            </ul>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
