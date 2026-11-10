import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { BookOpen, Command, FlaskConical, GitCompare, Menu, Monitor, Moon, ScanSearch, Search, Sun, Upload, X } from 'lucide-react';
import { CommandPalette } from './CommandPalette';
import { DevIcon, GithubIcon, LensMark, LinkedinIcon, NpmIcon, XIcon } from './icons';
import { ANALYZERS } from '@revlens/core';
import { DOCS, POSTS } from '../lib/content';
import { openFiles } from '../lib/actions';
import { setSettings, useSettings, type Theme } from '../lib/settings';
import { cx } from '../lib/util';

const NAV = [
  { to: '/analyze', label: 'Analyze' }, { to: '/diff', label: 'Diff' }, { to: '/verify', label: 'Verify' },
  { to: '/docs', label: 'Docs' }, { to: '/blog', label: 'Blog' }, { to: '/about', label: 'About' },
];
export const REPO = 'https://github.com/aniruddhaadak80/re';

function ThemeCycle() {
  const s = useSettings();
  const order: Theme[] = ['black', 'dark', 'sun', 'system'];
  const next = order[(order.indexOf(s.theme) + 1) % order.length] as Theme;
  const Icon = s.theme === 'sun' ? Sun : s.theme === 'system' ? Monitor : Moon;
  return (
    <button type="button" onClick={() => setSettings({ theme: next })} className="grid grid-cols-1 h-9 w-9 place-items-center rounded-lg border border-line bg-surface text-muted transition hover:border-accent/60 hover:text-ink"
      aria-label={`Theme is ${s.theme}. Switch to ${next}`} title={`Theme: ${s.theme}`} data-testid="theme-cycle">
      <Icon size={16} />
    </button>
  );
}

function Header({ onPalette }: { onPalette: () => void }) {
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  useEffect(() => setOpen(false), [loc.pathname]);
  return (
    <header className="sticky top-0 z-50 border-b border-line/70 bg-bg/80 backdrop-blur-xl">
      <div className="container-x flex h-16 items-center gap-3">
        <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight" aria-label="RevLens home">
          <LensMark size={28} /><span className="text-lg">Rev<span className="text-ink">Lens</span></span>
        </Link>
        <nav className="ml-6 hidden items-center gap-1 lg:flex" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} className={({ isActive }) => cx('relative rounded-lg px-3 py-2 text-sm transition hover:text-fg', isActive ? 'text-fg' : 'text-muted')}>
              {({ isActive }) => (<>{n.label}{isActive && <motion.span layoutId="nav-underline" className="absolute inset-x-3 -bottom-[13px] h-0.5 rounded bg-accent" />}</>)}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <button type="button" onClick={onPalette} className="hidden h-9 items-center gap-2 rounded-lg border border-line bg-surface px-3 text-sm text-muted transition hover:border-accent/60 hover:text-fg sm:flex" aria-label="Open command palette">
            <Search size={15} /><span>Search</span><span className="kbd ml-2">Ctrl K</span>
          </button>
          <button type="button" onClick={onPalette} className="grid grid-cols-1 h-9 w-9 place-items-center rounded-lg border border-line bg-surface text-muted sm:hidden" aria-label="Open command palette"><Command size={16} /></button>
          <ThemeCycle />
          <a href={REPO} target="_blank" rel="noreferrer" className="hidden h-9 w-9 place-items-center rounded-lg border border-line bg-surface text-muted transition hover:border-accent/60 hover:text-ink sm:grid" aria-label="RevLens on GitHub"><GithubIcon size={16} /></a>
          <button type="button" className="grid grid-cols-1 h-9 w-9 place-items-center rounded-lg border border-line bg-surface text-muted lg:hidden" onClick={() => setOpen((o) => !o)} aria-label="Menu" aria-expanded={open}>
            {open ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>
      </div>
      <AnimatePresence>
        {open && (
          <motion.nav initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden border-t border-line lg:hidden" aria-label="Mobile">
            <div className="container-x grid grid-cols-2 gap-2 py-3">
              {[...NAV, { to: '/settings', label: 'Settings' }, { to: '/changelog', label: 'Changelog' }].map((n) => (
                <NavLink key={n.to} to={n.to} className={({ isActive }) => cx('rounded-lg border border-line px-3 py-2 text-sm', isActive ? 'border-accent/60 text-ink' : 'text-muted')}>{n.label}</NavLink>
              ))}
            </div>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  );
}

function FooterCol({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-fg">{title}</p>
      <ul className="space-y-2 text-sm text-muted">{children}</ul>
    </div>
  );
}
const FL = ({ to, children }: { to: string; children: ReactNode }) => (
  <li>{to.startsWith('http') ? <a href={to} target="_blank" rel="noreferrer" className="transition hover:text-ink">{children}</a> : <Link to={to} className="transition hover:text-ink">{children}</Link>}</li>
);

export const SOCIALS = [
  { href: 'https://github.com/aniruddhaadak80', label: 'GitHub', Icon: GithubIcon },
  { href: 'https://www.linkedin.com/in/aniruddha-adak', label: 'LinkedIn', Icon: LinkedinIcon },
  { href: 'https://x.com/asi369_', label: 'X', Icon: XIcon },
  { href: 'https://dev.to/aniruddhaadak', label: 'DEV', Icon: DevIcon },
];

function Footer() {
  const base = import.meta.env.BASE_URL;
  return (
    <footer className="mt-24 border-t border-line bg-surface/60">
      <div className="mx-auto w-full max-w-[1400px] px-4 py-14 sm:px-6 lg:px-10">
        <div className="grid grid-cols-1 gap-10 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-[minmax(280px,1.4fr)_repeat(5,minmax(0,1fr))]">
          <div className="card h-fit self-start p-5 sm:col-span-2 lg:col-span-3 xl:col-span-1">
            <div className="flex items-center gap-3">
              <img src={`${base}author/aniruddha-adak.webp`} alt="Aniruddha Adak" width={48} height={48} className="h-12 w-12 shrink-0 rounded-full border border-accent/50 object-cover"
                onError={(e) => { e.currentTarget.style.visibility = 'hidden'; }} />
              <div className="min-w-0">
                <p className="whitespace-nowrap font-semibold">Aniruddha Adak</p>
                <p className="text-xs text-muted">AI Agent Engineer, Kolkata</p>
              </div>
            </div>
            <p className="mt-4 text-sm leading-6 text-muted">RevLens is a zero-install lens for binaries, bundles and packages. It runs in your browser, your terminal and your agent, and your files stay on your device.</p>
            <div className="mt-4 flex gap-2">
              {SOCIALS.map(({ href, label, Icon }) => (
                <a key={label} href={href} target="_blank" rel="noreferrer" aria-label={label} className="grid grid-cols-1 h-9 w-9 place-items-center rounded-lg border border-line text-muted transition hover:border-accent/60 hover:text-ink"><Icon size={15} /></a>
              ))}
            </div>
          </div>
          <FooterCol title="Analyzers">
            {ANALYZERS.slice(0, 7).map((a) => <FL key={a.id} to={`/#analyzer-${a.id}`}>{a.title}</FL>)}
          </FooterCol>
          <FooterCol title="Tools">
            <FL to="/analyze">Analyze</FL><FL to="/diff">Diff</FL><FL to="/verify">Verify</FL><FL to="/analyze?tab=rules">Rules</FL><FL to="/settings">Settings</FL>
          </FooterCol>
          <FooterCol title="Docs">
            {DOCS.length ? DOCS.slice(0, 6).map((d) => <FL key={d.slug} to={`/docs/${d.slug}`}>{d.title}</FL>) : <FL to="/docs">Documentation</FL>}
          </FooterCol>
          <FooterCol title="Blog">
            {POSTS.length ? POSTS.slice(0, 4).map((p) => <FL key={p.slug} to={`/blog/${p.slug}`}><span className="line-clamp-2">{p.title.split(':')[0]}</span></FL>) : <FL to="/blog">All posts</FL>}
            <FL to="/changelog">Changelog</FL>
          </FooterCol>
          <FooterCol title="Resources">
            <FL to={REPO}>GitHub</FL>
            <FL to="https://www.npmjs.com/package/revlens">npm</FL>
            <FL to={DOCS.find((d) => /mcp/.test(d.slug)) ? `/docs/${DOCS.find((d) => /mcp/.test(d.slug))!.slug}` : '/docs'}>MCP setup</FL>
            <FL to={DOCS.find((d) => /sarif|ci/.test(d.slug)) ? `/docs/${DOCS.find((d) => /sarif|ci/.test(d.slug))!.slug}` : '/docs'}>SARIF guide</FL>
            <FL to="/about">About and credits</FL>
          </FooterCol>
        </div>
        <div className="mt-12 flex flex-col gap-3 border-t border-line pt-6 text-xs text-muted sm:flex-row sm:items-center sm:justify-between">
          <p>MIT License. Copyright 2026 Aniruddha Adak. Inspired by morluto/rea (MIT), not affiliated with it.</p>
          <p className="flex items-center gap-2"><NpmIcon size={16} /> Built with TypeScript, zero native dependencies.</p>
        </div>
      </div>
    </footer>
  );
}

function MobileBar({ onPalette }: { onPalette: () => void }) {
  const nav = useNavigate();
  const input = useRef<HTMLInputElement>(null);
  const item = 'flex flex-1 flex-col items-center gap-1 py-2 text-[11px] text-muted transition active:text-ink';
  return (
    <div className="fixed inset-x-0 bottom-0 z-40 border-t border-line bg-bg/90 pb-[env(safe-area-inset-bottom)] backdrop-blur-xl lg:hidden" data-testid="mobile-bar">
      <input ref={input} type="file" multiple className="hidden" onChange={async (e) => { const f = [...(e.target.files ?? [])]; e.target.value = ''; if (f.length) { await openFiles(f); nav('/analyze'); } }} />
      <div className="mx-auto flex max-w-lg">
        <button type="button" className={item} onClick={() => input.current?.click()}><Upload size={18} className="text-ink" />Open</button>
        <button type="button" className={item} onClick={() => nav('/analyze')}><ScanSearch size={18} />Workspace</button>
        <button type="button" className={item} onClick={onPalette}><FlaskConical size={18} />Samples</button>
        <button type="button" className={item} onClick={() => nav('/diff')}><GitCompare size={18} />Diff</button>
        <button type="button" className={item} onClick={() => nav('/docs')}><BookOpen size={18} />Docs</button>
      </div>
    </div>
  );
}

/** Drop a file anywhere on the site to analyze it. Local drop zones handle their own drops. */
function useGlobalDrop(): boolean {
  const [over, setOver] = useState(false);
  const nav = useNavigate();
  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => [...(e.dataTransfer?.types ?? [])].includes('Files');
    const enter = (e: DragEvent) => { if (!hasFiles(e)) return; depth++; setOver(true); };
    const leave = () => { depth = Math.max(0, depth - 1); if (!depth) setOver(false); };
    const overH = (e: DragEvent) => { if (hasFiles(e)) e.preventDefault(); };
    const drop = async (e: DragEvent) => {
      depth = 0; setOver(false);
      if ((e as DragEvent & { revlensHandled?: boolean }).revlensHandled || !hasFiles(e)) return;
      e.preventDefault();
      const files = [...(e.dataTransfer?.files ?? [])];
      if (files.length) { await openFiles(files); nav('/analyze'); }
    };
    window.addEventListener('dragenter', enter); window.addEventListener('dragleave', leave);
    window.addEventListener('dragover', overH); window.addEventListener('drop', drop);
    return () => { window.removeEventListener('dragenter', enter); window.removeEventListener('dragleave', leave); window.removeEventListener('dragover', overH); window.removeEventListener('drop', drop); };
  }, [nav]);
  return over;
}

export function Layout({ children }: { children: ReactNode }) {
  const [palette, setPalette] = useState(false);
  const over = useGlobalDrop();
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p); }
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, []);
  return (
    <div className="flex min-h-screen flex-col pb-16 lg:pb-0">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[80] focus:rounded-lg focus:bg-accent focus:px-3 focus:py-2 focus:text-night">Skip to content</a>
      <Header onPalette={() => setPalette(true)} />
      <main id="main" className="flex-1">{children}</main>
      <Footer />
      <MobileBar onPalette={() => setPalette(true)} />
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
      <AnimatePresence>
        {over && (
          <motion.div className="pointer-events-none fixed inset-0 z-[60] grid grid-cols-1 place-items-center bg-bg/80 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <div className="rounded-3xl border-2 border-dashed border-accent bg-surface px-10 py-12 text-center shadow-glow">
              <LensMark size={56} className="mx-auto" />
              <p className="mt-4 text-xl font-semibold">Drop to analyze</p>
              <p className="mt-1 text-sm text-muted">The file stays on your device.</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
