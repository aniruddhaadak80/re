import { useMemo, useState } from 'react';
import { ChevronRight, File, FileArchive, Folder } from 'lucide-react';
import type { Report } from '@revlens/core';
import { Empty, SeverityBadge } from '../../components/ui';
import { FORMAT_LABEL, formatBytes } from '../../lib/util';
import type { TabProps } from './shared';

interface Member { name: string; size: number; compressedSize?: number }
interface Node { name: string; path: string; size: number; children: Map<string, Node>; file?: Member }

function build(members: Member[]): Node {
  const root: Node = { name: '', path: '', size: 0, children: new Map() };
  for (const m of members) {
    const parts = m.name.split('/').filter(Boolean);
    let cur = root;
    parts.forEach((p, i) => {
      const path = parts.slice(0, i + 1).join('/');
      if (!cur.children.has(p)) cur.children.set(p, { name: p, path, size: 0, children: new Map() });
      cur = cur.children.get(p)!;
      cur.size += m.size;
      if (i === parts.length - 1) cur.file = m;
    });
  }
  return root;
}

function Tree({ node, depth, childFor, onPick }: { node: Node; depth: number; childFor: (p: string) => Report | undefined; onPick: (r: Report) => void }) {
  const [open, setOpen] = useState(depth < 1);
  const kids = [...node.children.values()].sort((a, b) => Number(!!a.file) - Number(!!b.file) || a.name.localeCompare(b.name));
  const child = node.file ? childFor(node.path) : undefined;
  const isDir = kids.length > 0;
  return (
    <li>
      <button type="button" onClick={() => (isDir ? setOpen((o) => !o) : child && onPick(child))}
        className="flex w-full min-w-0 items-center gap-2 rounded-lg px-2 py-1 text-left text-sm transition hover:bg-surface2" style={{ paddingLeft: 8 + depth * 16 }}>
        {isDir ? <ChevronRight size={13} className={`shrink-0 transition ${open ? 'rotate-90' : ''}`} /> : <span className="w-[13px] shrink-0" />}
        {isDir ? <Folder size={14} className="shrink-0 text-ink" /> : <File size={14} className="shrink-0 text-muted" />}
        <span className="min-w-0 flex-1 truncate font-mono text-xs">{node.name}</span>
        {child && <span className="chip shrink-0 border-teal/40 text-teal-700 dark:text-teal-300">{child.findings.length} findings</span>}
        <span className="shrink-0 font-mono text-[11px] text-muted">{formatBytes(node.size)}</span>
      </button>
      {isDir && open && <ul>{kids.map((k) => <Tree key={k.path} node={k} depth={depth + 1} childFor={childFor} onPick={onPick} />)}</ul>}
    </li>
  );
}

function ChildReport({ r, onBack, onPick }: { r: Report; onBack: () => void; onPick: (r: Report) => void }) {
  return (
    <div className="card p-4" data-testid="child-report">
      <button type="button" className="btn-ghost btn-sm mb-3" onClick={onBack}>Back to the tree</button>
      <p className="break-all font-semibold">{String(r.meta.memberPath ?? r.file.name)}</p>
      <p className="text-xs text-muted">{FORMAT_LABEL[r.file.format] ?? r.file.format}, {formatBytes(r.file.size)}, sha256 {r.file.hashes.sha256.slice(0, 16)}</p>
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div><p className="label">Findings</p>{r.findings.length ? r.findings.map((f) => <p key={f.id} className="flex items-center gap-2 py-0.5 text-sm"><SeverityBadge s={f.severity} />{f.title}</p>) : <p className="text-sm text-muted">None</p>}</div>
        <div><p className="label">Components</p>{r.components.length ? r.components.map((c) => <p key={c.name} className="text-sm">{c.name} {c.version}</p>) : <p className="text-sm text-muted">None</p>}</div>
        <div><p className="label">Strings kept</p><p className="text-sm">{r.strings.length}</p></div>
      </div>
      {r.children?.length ? <div className="mt-4"><p className="label">Nested members</p><ul>{r.children.map((c, i) => <li key={i}><button type="button" className="text-sm text-ink hover:underline" onClick={() => onPick(c)}>{String(c.meta.memberPath ?? c.file.name)}</button></li>)}</ul></div> : null}
    </div>
  );
}

export function Archive({ report }: TabProps) {
  const members = (report.meta.members as Member[] | undefined) ?? [];
  const tree = useMemo(() => build(members), [members]);
  const [picked, setPicked] = useState<Report[]>([]);
  if (!members.length) return <Empty title="Not an archive" icon={<FileArchive size={28} />}>ZIP, JAR, APK, CRX, XPI, VSIX, npm tarballs and ASAR files list their members here, and each member is analyzed too.</Empty>;
  const childFor = (p: string) => report.children?.find((c) => c.meta.memberPath === p || c.file.name === p);
  const top = picked[picked.length - 1];
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.2fr_1fr]">
      <div className="card p-3" data-testid="archive-tree">
        <p className="px-2 pb-2 text-sm font-semibold">{members.length} members <span className="font-normal text-muted">{report.children?.length ?? 0} analyzed</span></p>
        <ul>{[...tree.children.values()].map((n) => <Tree key={n.path} node={n} depth={0} childFor={childFor} onPick={(r) => setPicked([r])} />)}</ul>
      </div>
      <div>{top ? <ChildReport r={top} onBack={() => setPicked((p) => p.slice(0, -1))} onPick={(r) => setPicked((p) => [...p, r])} /> : <Empty title="Pick a member">Members with a findings badge were analyzed on their own. Click one to see its report.</Empty>}</div>
    </div>
  );
}
