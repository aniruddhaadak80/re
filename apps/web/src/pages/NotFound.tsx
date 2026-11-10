import { Link } from 'react-router-dom';
import { LensMark } from '../components/icons';
import { useSeo } from '../lib/seo';

export default function NotFound() {
  useSeo('Page not found | RevLens', 'This page does not exist. Try the analyzer, the docs or the blog.');
  return (
    <div className="container-x grid grid-cols-1 min-h-[60vh] place-items-center py-16 text-center">
      <div>
        <LensMark size={72} className="mx-auto opacity-80" />
        <p className="mt-6 font-mono text-sm text-ink">404</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">This page is not here</h1>
        <p className="mx-auto mt-3 max-w-md text-muted">The lens looked everywhere. The link may be old or mistyped. These places are real, though.</p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link to="/" className="btn-primary">Go home</Link>
          <Link to="/analyze" className="btn-ghost">Analyze a file</Link>
          <Link to="/docs" className="btn-ghost">Read the docs</Link>
        </div>
      </div>
    </div>
  );
}
