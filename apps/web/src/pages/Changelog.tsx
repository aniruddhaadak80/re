import { History } from 'lucide-react';
import { Markdown } from '../components/Markdown';
import { Empty, PageHeader } from '../components/ui';
import { CHANGELOG } from '../lib/content';
import { useRouteSeo } from '../lib/seo';

export default function Changelog() {
  useRouteSeo('/changelog');
  const body = CHANGELOG?.replace(/^#\s+.+\n/, '') ?? null;
  return (
    <div>
      <PageHeader eyebrow="Releases" title="Changelog">Every release, newest first.</PageHeader>
      <div className="container-x max-w-4xl">
        {body ? <div className="card p-6 sm:p-8"><Markdown source={body} from="root" /></div> : <Empty title="No releases written up yet" icon={<History size={28} />}>The first release notes will appear here.</Empty>}
      </div>
    </div>
  );
}
