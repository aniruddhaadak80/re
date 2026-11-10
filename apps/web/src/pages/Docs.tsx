import { useMemo, useState } from 'react';
import { Link, NavLink, useParams } from 'react-router-dom';
import { BookOpen, ChevronLeft, ChevronRight, Search } from 'lucide-react';
import { Markdown } from '../components/Markdown';
import { Empty } from '../components/ui';
import { DOCS, type Heading } from '../lib/content';
import { useSeo, ROUTE_META } from '../lib/seo';
import { cx } from '../lib/util';
import NotFound from './NotFound';

export function Toc({ headings }: { headings: Heading[] }) {
  if (!headings.length) return null;
  return (
    <nav aria-label="On this page" className="sticky top-24 hidden max-h-[calc(100vh-8rem)] overflow-auto xl:block">
      <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-muted">On this page</p>
      <ul className="space-y-1.5 border-l border-line text-sm">
        {headings.map((h, i) => <li key={`${h.id}-${i}`}><a href={`#${h.id}`} className={cx('-ml-px block border-l border-transparent pl-3 text-muted transition hover:border-accent hover:text-fg', h.depth === 3 && 'pl-6 text-xs')}>{h.text}</a></li>)}
      </ul>
    </nav>
  );
}

export default function Docs() {
  const { slug } = useParams();
  const [q, setQ] = useState('');
  const doc = slug ? DOCS.find((d) => d.slug === slug) : DOCS[0];
  const meta = ROUTE_META['/docs']!;
  useSeo(slug && doc ? `${doc.title} | RevLens docs` : meta.title, slug && doc ? doc.description || meta.description : meta.description);
  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return DOCS.map((d) => ({ d, hit: '' }));
    return DOCS.flatMap((d) => {
      const i = d.body.toLowerCase().indexOf(t);
      if (!d.title.toLowerCase().includes(t) && i < 0) return [];
      return [{ d, hit: i >= 0 ? d.body.slice(Math.max(0, i - 40), i + 80).replace(/[#`*\n]/g, ' ') : '' }];
    });
  }, [q]);
  if (slug && !doc) return <NotFound />;
  const idx = doc ? DOCS.indexOf(doc) : -1;
  const prev = DOCS[idx - 1], next = DOCS[idx + 1];

  return (
    <div className="container-x py-8 sm:py-10">
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[240px_minmax(0,1fr)] xl:grid-cols-[240px_minmax(0,1fr)_200px]">
        <aside className="lg:sticky lg:top-24 lg:max-h-[calc(100vh-8rem)] lg:self-start lg:overflow-auto">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input className="input pl-9" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search the docs" aria-label="Search the docs" data-testid="docs-search" />
          </div>
          <nav aria-label="Docs" className="mt-4">
            <ul className="space-y-0.5">
              {results.map(({ d, hit }) => (
                <li key={d.slug}>
                  <NavLink to={`/docs/${d.slug}`} className={({ isActive }) => cx('block rounded-lg px-3 py-1.5 text-sm transition', isActive || (!slug && d === DOCS[0]) ? 'bg-accent/10 text-ink' : 'text-muted hover:bg-surface2 hover:text-fg')}>
                    {d.title}{hit && <span className="mt-0.5 block truncate text-[11px] text-muted">{hit}</span>}
                  </NavLink>
                </li>
              ))}
              {!results.length && <li className="px-3 text-sm text-muted">No page mentions that.</li>}
            </ul>
          </nav>
        </aside>
        <article className="min-w-0">
          {!doc ? (
            <>
              <h1 className="mb-6 text-3xl font-semibold tracking-tight sm:text-4xl">Docs</h1>
              <Empty title="The docs are on their way" icon={<BookOpen size={28} />}>No documentation pages are published yet. The <Link to="/" className="text-ink underline">home page</Link> has the CLI and MCP setup in the meantime.</Empty>
            </>
          ) : (
            <>
              <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-ink">Docs</p>
              {!/^#\s/m.test(doc.body) && <h1 className="mb-4 text-3xl font-semibold tracking-tight sm:text-4xl">{doc.title}</h1>}
              <Markdown source={doc.body} from="docs" />
              <div className="mt-12 grid grid-cols-1 gap-3 border-t border-line pt-6 sm:grid-cols-2">
                {prev ? <Link to={`/docs/${prev.slug}`} className="card card-hover flex items-center gap-2 p-4 text-sm"><ChevronLeft size={16} className="text-ink" /><span><span className="block text-xs text-muted">Previous</span>{prev.title}</span></Link> : <span />}
                {next && <Link to={`/docs/${next.slug}`} className="card card-hover flex items-center justify-end gap-2 p-4 text-right text-sm"><span><span className="block text-xs text-muted">Next</span>{next.title}</span><ChevronRight size={16} className="text-ink" /></Link>}
              </div>
            </>
          )}
        </article>
        {doc && <Toc headings={doc.headings} />}
      </div>
    </div>
  );
}
