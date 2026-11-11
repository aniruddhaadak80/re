import { Link, useParams } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { PageHeader } from '../../components/ui';
import { LABS, labBySlug } from '../../lib/labs';
import { useRouteSeo } from '../../lib/seo';
import { LAB_ICONS } from './shared';
import LabPage from './LabPage';
import NotFound from '../NotFound';

/** The tools index: one card per area, each with real samples to try. */
export default function Labs() {
  useRouteSeo('/labs');
  return (
    <div>
      <PageHeader eyebrow="Tools" title="Deep tools for every kind of file">
        Each page runs one RevLens package in your browser: native disassembly, mobile apps, managed runtimes, JavaScript, Electron, network captures and SQLite. Every page has real samples to try, and the same tools are in the CLI and the MCP server.
      </PageHeader>
      <div className="container-x grid grid-cols-1 gap-4 pb-16 sm:grid-cols-2 lg:grid-cols-3">
        {LABS.map((l) => {
          const I = LAB_ICONS[l.icon];
          return (
            <Link key={l.slug} to={`/labs/${l.slug}`} className="card card-hover group flex flex-col p-5" data-testid={`lab-card-${l.slug}`}>
              <div className="flex items-center gap-3"><span className="grid h-10 w-10 place-items-center rounded-xl border border-line bg-surface2 text-ink"><I size={18} /></span>
                <div className="min-w-0"><p className="text-xs uppercase tracking-widest text-muted">{l.eyebrow}</p><h2 className="font-semibold">{l.title}</h2></div></div>
              <p className="mt-3 flex-1 text-sm text-muted">{l.summary}</p>
              <p className="mt-4 flex items-center justify-between text-xs text-muted"><span className="font-mono">{l.accepts}</span><ArrowRight size={14} className="text-ink transition group-hover:translate-x-0.5" /></p>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

/** /labs/:slug for every lab except the disassembler, which has its own page. */
export function LabRoute() {
  const { slug } = useParams();
  const lab = labBySlug(slug);
  if (!lab || lab.slug === 'disassembler') return <NotFound />;
  return <LabPage key={lab.slug} lab={lab} />;
}
