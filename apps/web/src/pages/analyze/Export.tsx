import { Download, FileCode2, FileJson, FileText, Package, ShieldCheck } from 'lucide-react';
import { toCycloneDX, toHTML, toMarkdown, toSARIF } from '@revlens/core';
import { download } from '../../lib/util';
import type { TabProps } from './shared';

export function Export({ report }: TabProps) {
  const base = report.file.name.replace(/[^\w.-]+/g, '_');
  const items = [
    { id: 'json', icon: FileJson, title: 'Report JSON', text: 'The full revlens/report@1 document, with every section, string and finding.', run: () => download(`${base}.revlens.json`, report) },
    { id: 'sarif', icon: ShieldCheck, title: 'SARIF 2.1.0', text: 'Upload to GitHub code scanning or any SARIF viewer.', run: () => download(`${base}.sarif`, toSARIF(report), 'application/sarif+json') },
    { id: 'md', icon: FileText, title: 'Markdown', text: 'A readable summary for issues, pull requests and chats with your agent.', run: () => download(`${base}.md`, toMarkdown(report), 'text/markdown') },
    { id: 'html', icon: FileCode2, title: 'HTML', text: 'A single self contained page you can share or archive.', run: () => download(`${base}.html`, toHTML(report), 'text/html') },
    { id: 'cyclonedx', icon: Package, title: 'CycloneDX 1.5 SBOM', text: 'Every detected component with its package URL.', run: () => download(`${base}.cdx.json`, toCycloneDX(report)) },
  ];
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {items.map((it) => (
        <div key={it.id} className="card card-hover flex flex-col p-5">
          <it.icon size={22} className="text-ink" />
          <p className="mt-3 font-semibold">{it.title}</p>
          <p className="mt-1 flex-1 text-sm text-muted">{it.text}</p>
          <button type="button" className="btn-ghost mt-4" onClick={it.run} data-testid={`export-${it.id}`}><Download size={15} />Download</button>
        </div>
      ))}
      <p className="text-xs text-muted sm:col-span-2 lg:col-span-3">Exports are generated in your browser from the report already on screen.</p>
    </div>
  );
}
