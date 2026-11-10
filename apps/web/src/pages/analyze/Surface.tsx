import { Globe } from 'lucide-react';
import { CopyButton, Empty } from '../../components/ui';
import type { TabProps } from './shared';

const GROUPS: [string, string, string][] = [
  ['urls', 'URLs', 'Full URLs found in the file.'], ['hosts', 'Hosts', 'Distinct hostnames.'], ['apiPaths', 'API paths', 'Endpoints that look like REST routes.'],
  ['graphql', 'GraphQL operations', 'Named queries and mutations.'], ['ipc', 'IPC channels', 'Electron and extension message channels.'],
  ['flags', 'Feature flags', 'Flag names that gate behavior.'], ['storage', 'Storage keys', 'Local storage and cookie keys.'],
];

export function Surface({ report }: TabProps) {
  const s = (report.meta.surface ?? {}) as Record<string, string[] | undefined>;
  const groups = GROUPS.map(([k, t, d]) => ({ k, t, d, items: s[k] ?? [] })).filter((g) => g.items.length);
  if (!groups.length) return <Empty title="No network or IPC surface" icon={<Globe size={28} />}>No URLs, endpoints, GraphQL operations, IPC channels or feature flags were found.</Empty>;
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2" data-testid="surface">
      {groups.map((g) => (
        <div key={g.k} className="card p-4">
          <p className="font-semibold">{g.t} <span className="font-normal text-muted">{g.items.length}</span></p>
          <p className="mb-3 text-xs text-muted">{g.d}</p>
          <ul className="max-h-72 space-y-1 overflow-auto">
            {g.items.map((v) => <li key={v} className="group flex min-w-0 items-center gap-2 rounded-md px-1 py-0.5 hover:bg-surface2"><span className="min-w-0 flex-1 truncate font-mono text-xs" title={v}>{v}</span><span className="opacity-0 transition group-hover:opacity-100"><CopyButton text={v} /></span></li>)}
          </ul>
        </div>
      ))}
    </div>
  );
}
